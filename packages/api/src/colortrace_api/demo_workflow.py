from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import stat
import time
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast

from colortrace_grafana_mcp import AdapterError, EvidenceAdapter
from colortrace_investigation import AlertIntake, ContractError
from colortrace_recovery import (
    RecoveryError,
    RecoveryIdentityBoundary,
    RecoveryPrincipal,
    SynchronousRecoveryWorkflowRunner,
    canonical_json_bytes,
)
from colortrace_response_plans import ResponsePlanError, validate_decision
from colortrace_response_plans.contracts import REJECTION_CODES
from colortrace_simulator import DispatchIdentity
from colortrace_simulator.repository import SimulatorRepositoryError
from colortrace_telemetry import DeliveryPlan, load_runtime_jobs
from colortrace_telemetry.emitter import OtelSink, emit_plans
from colortrace_vertical_slice import SliceContractError, VerticalSliceApi, VerticalSliceWorker

from .auth import Principal
from .demo_facade import (
    EXECUTION_PROOF_SCHEMA,
    EXECUTION_SCHEMA,
    INVESTIGATION_PROOF_SCHEMA,
    PREPARATION_SCHEMA,
    DemoFacadeError,
    DemoWorkflowPort,
)
from .recovery import RecoveryApi
from .response_plans import ResponsePlanApi
from .simulator_actions import SimulatorActionApi
from .simulator_runtime import LocalSimulatorRuntime

_DIGEST = "sha256:"
_JOB_ID = "job-b-02"
_PUBLICATION_ID = re.compile(r"^publication:[0-9a-f]{64}$")
_MAX_VISUAL_BYTES = 8 * 1024 * 1024
_MAX_JSON_BYTES = 1024 * 1024
_ALERT_WAIT_SECONDS = 70.0
_ALERT_POLL_SECONDS = 2.0
_MAX_RECOVERY_SETTLE_SECONDS = 30.0
_FIXTURE_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_VISUAL_SOURCES = {
    "expected": "references/display/reference-chart-02-look.png",
    "observed": "runtime/display/output-job-b-02.png",
    "diff": "reports/diffs/job-b-02.png",
}
_REJECTION_RESULT_SCHEMA = "colortrace-demo-rejection-result/v1"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _digest(value: Any) -> str:
    return _DIGEST + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _file_digest(value: bytes) -> str:
    return _DIGEST + hashlib.sha256(value).hexdigest()


def _idempotency(value: str, stage: str) -> str:
    digest = hashlib.sha256(f"{value}:{stage}".encode()).hexdigest()
    return f"demo-{stage}:{digest}"


class CanonicalAlertSource(Protocol):
    def emit(self, *, run_id: str, incident_id: str) -> Mapping[str, Any]: ...


class GrafanaMcpAlertProbe:
    def __init__(
        self,
        *,
        evidence: EvidenceAdapter,
        clock: Callable[[], datetime] = _utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        timeout_seconds: float = _ALERT_WAIT_SECONDS,
        poll_seconds: float = _ALERT_POLL_SECONDS,
    ) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 1.0 <= timeout_seconds <= _ALERT_WAIT_SECONDS
            or not isinstance(poll_seconds, (int, float))
            or isinstance(poll_seconds, bool)
            or not 0.1 <= poll_seconds <= 10.0
        ):
            raise ValueError("demo-alert-probe-budget-invalid")
        self._evidence = evidence
        self._clock = clock
        self._monotonic = monotonic
        self._sleeper = sleeper
        self._timeout_seconds = float(timeout_seconds)
        self._poll_seconds = float(poll_seconds)

    @staticmethod
    def _matching_firing_alerts(
        envelope: Mapping[str, Any],
        *,
        correlation: Mapping[str, str],
    ) -> list[Mapping[str, Any]]:
        collection = envelope.get("collection")
        content = envelope.get("content")
        if (
            not isinstance(collection, Mapping)
            or collection.get("outcome") != "collected"
            or not isinstance(content, Mapping)
            or not isinstance(content.get("alerts"), list)
        ):
            raise DemoFacadeError("demo-alert-probe-failed")
        matches: list[Mapping[str, Any]] = []
        for raw in content["alerts"]:
            if not isinstance(raw, Mapping) or not isinstance(raw.get("labels"), Mapping):
                raise DemoFacadeError("demo-alert-probe-failed")
            labels = cast(Mapping[str, Any], raw["labels"])
            if all(labels.get(key) == value for key, value in correlation.items()):
                if str(raw.get("state", "")).casefold() in {"alerting", "firing"}:
                    matches.append(raw)
        return matches

    def wait_for_firing(self, alert: Mapping[str, Any]) -> Mapping[str, Any]:
        deadline = self._monotonic() + self._timeout_seconds
        correlation = alert.get("correlation_keys")
        if not isinstance(correlation, Mapping) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in correlation.items()
        ):
            raise DemoFacadeError("demo-alert-intake-invalid")
        while True:
            retrieved_at = self._clock().astimezone(UTC)
            candidate = {
                **alert,
                "retrieved_at": retrieved_at.isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                ),
            }
            try:
                intake = AlertIntake.from_mapping(candidate)
                result = asyncio.run(self._evidence.collect(intake.evidence_batch(("alert.rule",))))
            except (AdapterError, ContractError, RuntimeError, ValueError):
                raise DemoFacadeError("demo-alert-probe-failed") from None
            if len(result.envelopes) != 1:
                raise DemoFacadeError("demo-alert-probe-failed")
            envelope = result.envelopes[0]
            matches = self._matching_firing_alerts(
                envelope,
                correlation=cast(Mapping[str, str], correlation),
            )
            if len(matches) > 1:
                raise DemoFacadeError("demo-alert-ambiguous")
            if matches:
                active_at = matches[0].get("activeAt")
                if not isinstance(active_at, str):
                    raise DemoFacadeError("demo-alert-probe-failed")
                accepted = {
                    **candidate,
                    "alert_started_at": active_at,
                    "retrieved_at": self._clock()
                    .astimezone(UTC)
                    .isoformat(timespec="milliseconds")
                    .replace("+00:00", "Z"),
                }
                try:
                    AlertIntake.from_mapping(accepted)
                except ContractError:
                    raise DemoFacadeError("demo-alert-probe-failed") from None
                return accepted
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise DemoFacadeError("demo-alert-timeout")
            self._sleeper(min(self._poll_seconds, remaining))


class LiveCanonicalAlertSource:
    def __init__(
        self,
        *,
        fixture_bundle: Path,
        otlp_endpoint: str,
        evidence_binding: Mapping[str, str],
        alert_rule_uid: str,
        alert_probe: GrafanaMcpAlertProbe,
    ) -> None:
        self._fixture_bundle = fixture_bundle
        self._otlp_endpoint = otlp_endpoint
        self._binding = dict(evidence_binding)
        self._alert_rule_uid = alert_rule_uid
        self._alert_probe = alert_probe

    def emit(self, *, run_id: str, incident_id: str) -> Mapping[str, Any]:
        runtime = load_runtime_jobs(self._fixture_bundle)
        plan = DeliveryPlan.build(runtime, case_index=0, run_id=run_id)
        receipt = emit_plans(
            runtime,
            (plan,),
            OtelSink(self._otlp_endpoint),
        )
        runs = cast(Sequence[Mapping[str, Any]], receipt["runs"])
        events = cast(Sequence[Mapping[str, Any]], runs[0]["events"])
        selected = [
            event
            for event in events
            if cast(Mapping[str, Any], event["correlation"])["job_id"] == _JOB_ID
        ]
        if len(selected) != 3 or {event["signal"] for event in selected} != {
            "metric",
            "log",
            "trace",
        }:
            raise DemoFacadeError("demo-alert-evidence-invalid")
        mismatch = [
            event
            for event in selected
            if cast(Mapping[str, Any], event["observation"])["state"] == "reference_mismatch"
        ]
        if len(mismatch) != 3:
            raise DemoFacadeError("demo-alert-evidence-invalid")
        correlation = cast(Mapping[str, str], mismatch[0]["correlation"])
        intake = {
            "schema": "alert-intake/v1",
            "incident_id": incident_id,
            "alert_id": f"alert-{run_id}",
            "alert_started_at": min(cast(str, event["scheduled_at"]) for event in mismatch),
            "retrieved_at": max(cast(str, event["emitted_at"]) for event in mismatch),
            "measured_clock_skew_seconds": 0,
            "binding": {
                **self._binding,
                "alert_rule_uid": self._alert_rule_uid,
            },
            "correlation_keys": {
                key: correlation[key]
                for key in (
                    "fixture_id",
                    "run_id",
                    "job_id",
                    "worker_id",
                    "artifact_id",
                    "trace_id",
                    "config_sha256",
                    "transform_id",
                )
            },
            "predecessor_event_sha256": None,
        }
        return self._alert_probe.wait_for_firing(intake)


class CanonicalDemoWorkflow(DemoWorkflowPort):
    def __init__(
        self,
        *,
        incidents: VerticalSliceApi,
        investigation: VerticalSliceWorker,
        response_plans: ResponsePlanApi,
        simulator_actions: SimulatorActionApi,
        simulator_runtime: LocalSimulatorRuntime,
        recovery: RecoveryApi,
        recovery_runner: SynchronousRecoveryWorkflowRunner,
        recovery_identity: RecoveryIdentityBoundary,
        alert_source: CanonicalAlertSource,
        fixture_bundle: Path,
        visual_root: Path,
        issuer: str,
        audience: str,
        clock: Callable[[], datetime] = _utc_now,
        recovery_settle_seconds: float = 0.0,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if (
            not isinstance(recovery_settle_seconds, (int, float))
            or isinstance(recovery_settle_seconds, bool)
            or not 0.0 <= recovery_settle_seconds <= _MAX_RECOVERY_SETTLE_SECONDS
        ):
            raise ValueError("demo-recovery-settle-invalid")
        self._incidents = incidents
        self._investigation = investigation
        self._plans = response_plans
        self._simulator_actions = simulator_actions
        self._simulator_runtime = simulator_runtime
        self._recovery = recovery
        self._recovery_runner = recovery_runner
        self._recovery_identity = recovery_identity
        self._alert_source = alert_source
        self._fixture_bundle = fixture_bundle
        self._visual_root = visual_root
        self._issuer = issuer
        self._audience = audience
        self._clock = clock
        self._recovery_settle_seconds = float(recovery_settle_seconds)
        self._sleeper = sleeper

    def _principal(self, incident_id: str, *, role: str, kind: str) -> Principal:
        now = self._clock().astimezone(UTC)
        return Principal(
            subject=f"canonical-demo-{role}",
            display_name="Canonical demo operator",
            roles=frozenset({role}),
            issuer=self._issuer,
            audience=self._audience,
            principal_kind=cast(Any, kind),
            incident_ids=frozenset({incident_id}),
            credential_sha256=_digest(
                {
                    "schema": "colortrace-demo-internal-principal/v1",
                    "incident_id": incident_id,
                    "role": role,
                    "kind": kind,
                }
            ),
            expires_at=now + timedelta(hours=1),
        )

    def closure_principal(self, incident_id: str) -> Principal:
        return self._principal(incident_id, role="recovery.closer", kind="human")

    def _recovery_principal(self, incident_id: str) -> RecoveryPrincipal:
        principal = self._principal(incident_id, role="recovery.verifier", kind="service")
        return self._recovery_identity.bind_verified_claims(
            issuer=principal.issuer,
            subject=principal.subject,
            display_name=principal.display_name,
            audience=principal.audience,
            kind=principal.principal_kind,
            roles=principal.roles,
            incident_ids=principal.incident_ids,
            credential_sha256=principal.credential_sha256,
            expires_at=principal.expires_at,
            credential_verified=True,
            now=self._clock(),
        )

    @staticmethod
    def _read_json(path: Path) -> dict[str, Any]:
        try:
            metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > _MAX_JSON_BYTES
            ):
                raise OSError
            value = json.loads(path.read_bytes())
        except (OSError, UnicodeError, ValueError):
            raise DemoFacadeError("demo-workflow-artifact-invalid") from None
        if not isinstance(value, dict):
            raise DemoFacadeError("demo-workflow-artifact-invalid")
        return cast(dict[str, Any], value)

    @staticmethod
    def _read_png(source: Path, *, root: Path) -> bytes:
        try:
            resolved_root = root.resolve(strict=True)
            resolved = source.resolve(strict=True)
            resolved.relative_to(resolved_root)
            metadata = source.lstat()
            if (
                source != resolved
                or source.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > _MAX_VISUAL_BYTES
            ):
                raise OSError
            descriptor = os.open(source, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise OSError
                chunks: list[bytes] = []
                remaining = _MAX_VISUAL_BYTES + 1
                while remaining:
                    chunk = os.read(descriptor, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
            finally:
                os.close(descriptor)
        except (OSError, ValueError) as error:
            raise DemoFacadeError("demo-workflow-visual-unavailable") from error
        if not data.startswith(b"\x89PNG\r\n\x1a\n") or len(data) > _MAX_VISUAL_BYTES:
            raise DemoFacadeError("demo-workflow-visual-invalid")
        return data

    def _write_visual(
        self,
        run_id: str,
        kind: str,
        source: Path,
        *,
        source_root: Path,
    ) -> dict[str, str]:
        data = self._read_png(source, root=source_root)
        run_root = self._visual_root / run_id
        try:
            run_root.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise DemoFacadeError("demo-workflow-visual-unavailable") from error
        try:
            run_metadata = run_root.lstat()
            resolved_run_root = run_root.resolve(strict=True)
        except OSError as error:
            raise DemoFacadeError("demo-workflow-visual-unavailable") from error
        if (
            run_root.is_symlink()
            or resolved_run_root != run_root
            or not stat.S_ISDIR(run_metadata.st_mode)
            or run_metadata.st_uid != os.getuid()
            or stat.S_IMODE(run_metadata.st_mode) != 0o700
        ):
            raise DemoFacadeError("demo-workflow-visual-invalid")
        target = run_root / f"{kind}.png"
        try:
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            existing = self._read_png(target, root=run_root)
            if existing != data:
                raise DemoFacadeError("demo-workflow-visual-conflict") from None
        else:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            directory = os.open(run_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return {
            "kind": kind,
            "path": f"{run_id}/{kind}.png",
            "sha256": _file_digest(data),
            "media_type": "image/png",
        }

    def _preparation_visuals(self, run_id: str) -> list[dict[str, str]]:
        return [
            self._write_visual(
                run_id,
                kind,
                self._fixture_bundle / relative,
                source_root=self._fixture_bundle,
            )
            for kind, relative in sorted(_VISUAL_SOURCES.items())
        ]

    def _recovered_visual(self, run_id: str) -> dict[str, str]:
        publication = self._simulator_runtime.recovery_publication
        root = getattr(publication, "root", None)
        if not isinstance(root, Path):
            raise DemoFacadeError("demo-workflow-visual-unavailable")
        pointer = self._read_json(root / "state" / "active.json")
        publication_id = pointer.get("publication_id")
        if not isinstance(publication_id, str) or _PUBLICATION_ID.fullmatch(publication_id) is None:
            raise DemoFacadeError("demo-workflow-visual-invalid")
        selected_root = root / "publications" / f"pub-{publication_id.removeprefix('publication:')}"
        runtime = self._read_json(selected_root / "manifests" / "runtime.json")
        frames = cast(Sequence[Mapping[str, Any]], runtime.get("frames", ()))
        matches = [frame for frame in frames if frame.get("job_id") == _JOB_ID]
        if len(matches) != 1 or not isinstance(matches[0].get("display_path"), str):
            raise DemoFacadeError("demo-workflow-visual-invalid")
        path = Path(cast(str, matches[0]["display_path"]))
        if path.is_absolute() or ".." in path.parts:
            raise DemoFacadeError("demo-workflow-visual-invalid")
        return self._write_visual(
            run_id,
            "recovered",
            selected_root / path,
            source_root=selected_root,
        )

    @staticmethod
    def _bounded_plain_text(value: Any) -> tuple[str, bool]:
        if not isinstance(value, str) or not value:
            raise DemoFacadeError("demo-investigation-evidence-invalid")
        normalized = value.replace("\r\n", "\n").replace("\r", "\n")
        safe = "".join(
            character
            if character in {"\n", "\t"} or not unicodedata.category(character).startswith("C")
            else "\ufffd"
            for character in normalized
        )
        selected = safe[:1_024]
        while len(selected.encode("utf-8")) > 4_096:
            selected = selected[:-1]
        if not selected:
            raise DemoFacadeError("demo-investigation-evidence-invalid")
        return selected, selected != value

    @staticmethod
    def _fixture_sha256(value: Any) -> str:
        if not isinstance(value, str) or _FIXTURE_DIGEST.fullmatch(value) is None:
            raise DemoFacadeError("demo-investigation-comparison-invalid")
        return f"sha256:{value}"

    def _render_comparison(self) -> dict[str, Any]:
        renders: list[dict[str, str]] = []
        for job_id, worker_id in (("job-a-02", "A"), ("job-b-02", "B")):
            job = self._read_json(
                self._fixture_bundle / "runtime" / "manifests" / "jobs" / f"{job_id}.json"
            )
            resource_path = job.get("resource_manifest")
            if (
                job.get("schema") != "fixture-job/v1"
                or job.get("job_id") != job_id
                or job.get("worker_id") != worker_id
                or job.get("source_id") != "chart-02"
                or job.get("transform_id") != "look/main/v1"
                or job.get("process_outcome") != "success"
                or job.get("exit_code") != 0
                or not isinstance(resource_path, str)
                or resource_path != f"runtime/manifests/resources/resource-{job_id}.json"
            ):
                raise DemoFacadeError("demo-investigation-comparison-invalid")
            resource = self._read_json(self._fixture_bundle / resource_path)
            ordered = resource.get("ordered_resources")
            if (
                resource.get("schema") != "resolved-resource-manifest/v1"
                or resource.get("job_id") != job_id
                or resource.get("worker_id") != worker_id
                or resource.get("transform_id") != "look/main/v1"
                or resource.get("nominal_config_sha256") != job.get("nominal_config_sha256")
                or resource.get("captured_before_and_after_processing") is not True
                or resource.get("inputs_unchanged") is not True
                or not isinstance(ordered, list)
                or len(ordered) != 1
                or not isinstance(ordered[0], Mapping)
                or ordered[0].get("logical_path") != "luts/show_look.cube"
                or ordered[0].get("read_only") is not True
            ):
                raise DemoFacadeError("demo-investigation-comparison-invalid")
            renders.append(
                {
                    "job_id": job_id,
                    "worker_id": worker_id,
                    "status": "succeeded",
                    "nominal_config_sha256": self._fixture_sha256(job.get("nominal_config_sha256")),
                    "resolved_lut_sha256": self._fixture_sha256(ordered[0].get("sha256")),
                }
            )
        nominal_match = len({item["nominal_config_sha256"] for item in renders}) == 1
        resource_match = len({item["resolved_lut_sha256"] for item in renders}) == 1
        if not nominal_match or resource_match:
            raise DemoFacadeError("demo-investigation-comparison-invalid")
        return {
            "renders": renders,
            "nominal_config_match": True,
            "resolved_lut_match": False,
        }

    @staticmethod
    def _plan_review(
        plan: Mapping[str, Any],
        *,
        plan_status: str,
        target_sha256: str,
    ) -> dict[str, Any]:
        targets = plan.get("targets")
        exclusions = plan.get("exclusions")
        commands = plan.get("commands")
        if (
            not isinstance(targets, list)
            or not isinstance(exclusions, list)
            or not isinstance(commands, list)
            or len(commands) != 5
        ):
            raise DemoFacadeError("demo-plan-review-invalid")
        envelopes = [
            command.get("action_envelope") for command in commands if isinstance(command, Mapping)
        ]
        if (
            len(envelopes) != 5
            or not all(isinstance(envelope, Mapping) for envelope in envelopes)
            or any(envelope != envelopes[0] for envelope in envelopes[1:])
        ):
            raise DemoFacadeError("demo-plan-review-invalid")
        envelope = cast(Mapping[str, Any], envelopes[0])
        binding_fields = (
            "schema",
            "fixture_id",
            "fixture_manifest_sha256",
            "fixture_generation",
            "source_batch_id",
            "source_batch_sha256",
            "runtime_manifest_sha256",
            "runtime_generation",
            "expected_publication_pointer_sha256",
            "expected_publication_generation",
            "expected_resource_sha256",
            "replacement_resource_logical_path",
            "replacement_resource_sha256",
            "declared_resource_manifest_sha256",
            "ocio_version",
            "preservation_manifest_sha256",
            "safe_complement_sha256",
            "lineage_manifest_sha256",
            "lineage_generation",
        )
        if any(field not in envelope for field in binding_fields):
            raise DemoFacadeError("demo-plan-review-invalid")
        summaries = [
            {key: child for key, child in command.items() if key != "action_envelope"}
            for command in cast(Sequence[Mapping[str, Any]], commands)
        ]
        if _digest(targets) != target_sha256:
            raise DemoFacadeError("demo-plan-review-invalid")
        return {
            "status": plan_status,
            "version": plan["version"],
            "plan_sha256": plan["plan_sha256"],
            "target_sha256": target_sha256,
            "exclusions_sha256": _digest(exclusions),
            "commands_sha256": _digest(commands),
            "targets": list(targets),
            "protected_exclusions": list(exclusions),
            "shared_action_bindings": {field: envelope[field] for field in binding_fields},
            "command_summaries": summaries,
        }

    def _prepared_result(
        self,
        request: Mapping[str, Any],
        *,
        packet: Mapping[str, Any],
        plan: Mapping[str, Any],
        replay: Mapping[str, Any],
        plan_status: str,
    ) -> dict[str, Any]:
        if packet.get("status") != "resolved" or not isinstance(
            packet.get("candidate_plan"), Mapping
        ):
            raise DemoFacadeError("demo-investigation-unresolved")
        target_sha256 = _digest(plan["targets"])
        return {
            "schema": PREPARATION_SCHEMA,
            "run_id": request["run_id"],
            "incident_id": request["incident_id"],
            "incident_version": plan["incident_version"],
            "plan_version": plan["version"],
            "plan_sha256": plan["plan_sha256"],
            "target_sha256": target_sha256,
            "visuals": self._preparation_visuals(cast(str, request["run_id"])),
            "investigation": self._investigation_proof(
                packet,
                replay=replay,
                plan=plan,
                plan_status=plan_status,
                target_sha256=target_sha256,
            ),
        }

    def _investigation_proof(
        self,
        packet: Mapping[str, Any],
        *,
        replay: Mapping[str, Any],
        plan: Mapping[str, Any],
        plan_status: str,
        target_sha256: str,
    ) -> dict[str, Any]:
        invocation_records = cast(Sequence[Mapping[str, Any]], packet["invocation_records"])
        model_invocations = [
            {
                "invocation_id": item["invocation_id"],
                "turn_kind": item["turn_kind"],
                "model": item["model"],
                "framework": item["framework"],
                "result_class": item["result_class"],
                "inventory_sha256": item["tool_inventory_version"],
                "output_sha256": item["output_sha256"],
                "trace_id": item["trace_id"],
            }
            for item in invocation_records
        ]
        evidence: list[dict[str, Any]] = []
        for item in cast(Sequence[Mapping[str, Any]], replay["evidence"]):
            source = cast(Mapping[str, Any], item["source"])
            observation = cast(Mapping[str, Any], item["observation"])
            timing = cast(Mapping[str, Any], item["timing"])
            raw_freshness = timing["freshness"]
            certified_freshness = (
                "current"
                if raw_freshness == "unresolved"
                and packet.get("status") == "resolved"
                and packet.get("unresolved_items") == []
                else raw_freshness
            )
            display_excerpt, display_excerpt_truncated = self._bounded_plain_text(
                item.get("display_excerpt")
            )
            evidence.append(
                {
                    "evidence_id": item["evidence_id"],
                    "query_key": observation["query_key"],
                    "tool": source["tool"],
                    "inventory_sha256": source["inventory_version"],
                    "content_sha256": item["content_sha256"],
                    "freshness": certified_freshness,
                    "display_excerpt": display_excerpt,
                    "display_excerpt_truncated": display_excerpt_truncated,
                }
            )
        validators = [
            {
                "result_id": item["result_id"],
                "validator": item["validator"],
                "validator_version": item["validator_version"],
                "status": item["status"],
                "derivation_sha256": f"sha256:{item['derivation_sha256']}",
            }
            for item in cast(Sequence[Mapping[str, Any]], packet["deterministic_results"])
        ]
        scope = cast(Mapping[str, Any], packet["scope"])
        budget = cast(Mapping[str, Any], packet["budget_use"])
        claims = [
            {
                "claim_id": item["claim_id"],
                "claim_type": item["claim_type"],
                "subject": dict(cast(Mapping[str, Any], item["subject"])),
                "state": item["state"],
                "reason_codes": list(cast(Sequence[str], item["reason_codes"])),
                "evidence_ids": list(cast(Sequence[str], item["evidence_ids"])),
                "source_validator_result_id": item["source_validator_result_id"],
            }
            for item in cast(Sequence[Mapping[str, Any]], packet["claims"])
        ]
        plan_review = self._plan_review(
            plan,
            plan_status=plan_status,
            target_sha256=target_sha256,
        )
        return {
            "schema": INVESTIGATION_PROOF_SCHEMA,
            "packet_id": packet["packet_id"],
            "packet_sha256": packet["derivation_sha256"],
            "status": packet["status"],
            "adjudication": {
                "model_role": "evidence-selection-and-advisory-drafting",
                "model_authority": "advisory-only",
                "validator_role": "deterministic-claim-adjudication",
                "decision_mode": "deterministic-validation",
            },
            "model_invocations": model_invocations,
            "comparison": self._render_comparison(),
            "claims": claims,
            "evidence": evidence,
            "validators": validators,
            "scope": {
                "state": scope["state"],
                "affected_count": len(cast(Sequence[Any], scope["affected"])),
                "safe_count": len(cast(Sequence[Any], scope["safe"])),
                "unknown_count": len(cast(Sequence[Any], scope["unknown"])),
            },
            "budget_use": {
                key: budget[key]
                for key in (
                    "elapsed_ms",
                    "model_turns",
                    "input_tokens",
                    "output_tokens",
                    "mcp_attempts",
                    "validator_calls",
                )
            },
            "plan": plan_review,
        }

    def prepare(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        incident_id = cast(str, request["incident_id"])
        run_id = cast(str, request["run_id"])
        packet: Mapping[str, Any]
        try:
            replay = self._incidents.replay(incident_id)
        except SliceContractError as error:
            if error.code == "incident-not-found":
                alert = self._alert_source.emit(run_id=run_id, incident_id=incident_id)
                accepted = self._incidents.accept_alert(alert)
                task_id = cast(str, accepted["task_id"])
            elif error.code == "incident-incomplete":
                view = self._incidents.get_incident(incident_id)
                task = view.get("task")
                if not isinstance(task, Mapping) or not isinstance(task.get("task_id"), str):
                    raise DemoFacadeError("demo-investigation-state-invalid") from None
                task_id = cast(str, task["task_id"])
            else:
                raise
            packet = asyncio.run(
                self._investigation.execute(
                    task_id,
                    bundle_root=self._fixture_bundle,
                )
            )
        else:
            packet_value = replay.get("packet")
            if isinstance(packet_value, Mapping):
                packet = packet_value
            else:
                task = cast(Mapping[str, Any], replay["task"])
                packet = asyncio.run(
                    self._investigation.execute(
                        cast(str, task["task_id"]),
                        bundle_root=self._fixture_bundle,
                    )
                )
        replay = self._incidents.replay(incident_id)
        try:
            review = self._plans.review(incident_id)
            plan = cast(Mapping[str, Any], review["plan"])
            plan_status = cast(str, review["state"])
        except ResponsePlanError as error:
            if error.code != "plan-not-found":
                raise
            draft = self._plans.draft(incident_id)
            publication = self._simulator_runtime.recovery_publication
            if publication is None:
                raise DemoFacadeError("demo-simulator-unavailable") from None
            inputs = cast(Any, publication).canonical_plan_inputs()
            plan = self._plans.create(
                self._principal(incident_id, role="response-plan.editor", kind="human"),
                incident_id,
                {
                    "expected_incident_version": draft["incident_version"],
                    "expected_plan_version": 0,
                    "response_packet_id": draft["response_packet_id"],
                    "response_packet_sha256": draft["response_packet_sha256"],
                    "deterministic_scope_sha256": draft["deterministic_scope_sha256"],
                    "targets": draft["targets"],
                    "exclusions": draft["exclusions"],
                    "commands": inputs["commands"],
                    "unresolved_acknowledged": False,
                    "idempotency_key": _idempotency(cast(str, request["idempotency_key"]), "plan"),
                },
            )
            plan_status = "pending"
        return self._prepared_result(
            request,
            packet=packet,
            plan=plan,
            replay=replay,
            plan_status=plan_status,
        )

    def _verified_packet(
        self,
        request: Mapping[str, Any],
        outcome: Mapping[str, Any],
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        incident_id = cast(str, request["incident_id"])
        try:
            review = self._recovery.review(incident_id)
        except RecoveryError as error:
            if error.code != "recovery-workflow-not-found":
                raise
            review = {}
        packet = review.get("packet")
        if not isinstance(packet, Mapping):
            packet = self._recovery_runner.verify(
                self._recovery_principal(incident_id),
                incident_id,
                expected_incident_version=cast(int, request["incident_version"]),
                expected_outcome_sha256=cast(str, outcome["outcome_sha256"]),
                idempotency_key=_idempotency(cast(str, request["idempotency_key"]), "recovery"),
            )
        if packet.get("status") != "recovery_verified":
            raise DemoFacadeError("demo-recovery-unresolved")
        review = self._recovery.review(incident_id)
        evidence = review.get("evidence_records")
        if not isinstance(evidence, list) or len(evidence) != 21:
            raise DemoFacadeError("demo-recovery-evidence-incomplete")
        return packet, review

    @staticmethod
    def _execution_proof(
        outcome: Mapping[str, Any],
        *,
        packet: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> dict[str, Any]:
        if outcome.get("safe_complement_before_sha256") != outcome.get(
            "safe_complement_after_sha256"
        ):
            raise DemoFacadeError("demo-safe-complement-changed")
        targets = cast(Sequence[Mapping[str, Any]], outcome["targets"])
        exclusions = cast(Sequence[Mapping[str, Any]], outcome["exclusions"])
        evidence = cast(Sequence[Mapping[str, Any]], review["evidence_records"])
        checks = cast(Sequence[Mapping[str, Any]], packet["check_results"])
        return {
            "schema": EXECUTION_PROOF_SCHEMA,
            "action": {
                "action_id": outcome["action_id"],
                "status": outcome["status"],
                "outcome_id": outcome["outcome_id"],
                "outcome_sha256": outcome["outcome_sha256"],
                "publication_generation_before": outcome["predecessor_publication_generation"],
                "publication_generation_after": outcome["candidate_publication_generation"],
                "affected_count": sum(
                    item.get("kind") in {"frame", "derivative"} for item in targets
                ),
                "safe_count": len(exclusions),
                "safe_complement_before_sha256": outcome["safe_complement_before_sha256"],
                "safe_complement_after_sha256": outcome["safe_complement_after_sha256"],
                "safe_complement_proof_sha256": outcome["safe_complement_proof_sha256"],
                "publication_receipt_sha256": outcome["publication_receipt_sha256"],
            },
            "recovery": {
                "status": packet["status"],
                "workflow_id": packet["workflow_id"],
                "workflow_version": packet["workflow_version"],
                "packet_id": packet["packet_id"],
                "packet_sha256": packet["packet_sha256"],
                "evidence_count": len(evidence),
                "evidence_request_sha256": packet["evidence_request_sha256"],
                "checks": [
                    {
                        "check": item["check"],
                        "status": item["state"],
                        "result_sha256": item["result_sha256"],
                    }
                    for item in checks
                ],
            },
        }

    def _execution_result(
        self,
        request: Mapping[str, Any],
        *,
        outcome: Mapping[str, Any],
        packet: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "schema": EXECUTION_SCHEMA,
            "run_id": request["run_id"],
            "incident_id": request["incident_id"],
            "incident_version": request["incident_version"],
            "plan_version": request["plan_version"],
            "plan_sha256": request["plan_sha256"],
            "target_sha256": request["target_sha256"],
            "idempotency_key": request["idempotency_key"],
            "outcome_id": outcome["outcome_id"],
            "outcome_sha256": outcome["outcome_sha256"],
            "workflow_id": packet["workflow_id"],
            "workflow_version": packet["workflow_version"],
            "packet_id": packet["packet_id"],
            "packet_sha256": packet["packet_sha256"],
            "visuals": [self._recovered_visual(cast(str, request["run_id"]))],
            "execution": self._execution_proof(outcome, packet=packet, review=review),
        }

    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        incident_id = cast(str, request["incident_id"])
        review = self._plans.review(incident_id)
        plan = cast(Mapping[str, Any], review["plan"])
        if (
            plan.get("version") != request["plan_version"]
            or plan.get("plan_sha256") != request["plan_sha256"]
            or _digest(plan.get("targets")) != request["target_sha256"]
        ):
            raise DemoFacadeError("demo-plan-binding-invalid")
        key = cast(str, request["idempotency_key"])
        self._plans.approve(
            self._principal(incident_id, role="response-plan.approver", kind="human"),
            incident_id,
            {
                "expected_incident_version": request["incident_version"],
                "expected_plan_version": request["plan_version"],
                "expected_plan_sha256": request["plan_sha256"],
                "idempotency_key": _idempotency(key, "approve"),
            },
        )
        dispatcher = self._principal(incident_id, role="response-plan.dispatcher", kind="service")
        authorization = self._plans.authorize_dispatch(
            dispatcher,
            incident_id,
            {
                "expected_incident_version": request["incident_version"],
                "expected_plan_version": request["plan_version"],
                "expected_plan_sha256": request["plan_sha256"],
                "idempotency_key": _idempotency(key, "authorize"),
            },
        )
        self._plans.consume_dispatch(
            dispatcher,
            incident_id,
            {
                "authorization_id": authorization["authorization_id"],
                "expected_incident_version": request["incident_version"],
                "expected_plan_version": request["plan_version"],
                "expected_plan_sha256": request["plan_sha256"],
                "expected_task_key": authorization["task_key"],
                "expected_payload_sha256": authorization["payload_sha256"],
                "idempotency_key": _idempotency(key, "consume"),
            },
        )
        identity = DispatchIdentity(
            task_key=cast(str, authorization["task_key"]),
            operation_id=cast(str, authorization["operation_id"]),
            payload_sha256=cast(str, authorization["payload_sha256"]),
        )
        self._simulator_actions.admit(
            self._principal(incident_id, role="simulator.executor", kind="service"),
            incident_id,
            {
                "schema": "simulator-action-admission-request/v1",
                "task_key": identity.task_key,
                "operation_id": identity.operation_id,
                "payload_sha256": identity.payload_sha256,
            },
        )
        outcome = self._simulator_runtime.execute(identity, owner="canonical-demo")
        self._simulator_runtime.service.deliver_pending_telemetry(limit=100)
        if outcome.get("status") != "succeeded":
            raise DemoFacadeError("demo-simulator-action-failed")
        if self._recovery_settle_seconds:
            self._sleeper(self._recovery_settle_seconds)
        packet, recovery_review = self._verified_packet(request, outcome)
        return self._execution_result(
            request,
            outcome=outcome,
            packet=packet,
            review=recovery_review,
        )

    @staticmethod
    def _rejection_result(
        request: Mapping[str, Any],
        review: Mapping[str, Any],
    ) -> dict[str, Any]:
        plan = review.get("plan")
        decision = review.get("decision")
        if (
            review.get("schema") != "response-plan-review/v1"
            or review.get("state") != "rejected"
            or not isinstance(plan, Mapping)
            or not isinstance(decision, Mapping)
        ):
            raise DemoFacadeError("demo-rejection-decision-invalid")
        try:
            validate_decision(decision, plan=plan)
        except ResponsePlanError:
            raise DemoFacadeError("demo-rejection-decision-invalid") from None
        if (
            decision.get("outcome") != "rejected"
            or decision.get("reason_code") not in REJECTION_CODES
            or plan.get("incident_id") != request.get("incident_id")
            or plan.get("incident_version") != request.get("incident_version")
            or plan.get("version") != request.get("plan_version")
            or plan.get("plan_sha256") != request.get("plan_sha256")
            or _digest(plan.get("targets")) != request.get("target_sha256")
            or (
                request.get("reason_code") is not None
                and decision.get("reason_code") != request.get("reason_code")
            )
        ):
            raise DemoFacadeError("demo-rejection-decision-invalid")
        return {
            "schema": _REJECTION_RESULT_SCHEMA,
            "run_id": request["run_id"],
            "incident_id": request["incident_id"],
            "incident_version": request["incident_version"],
            "plan_version": request["plan_version"],
            "plan_sha256": request["plan_sha256"],
            "target_sha256": request["target_sha256"],
            "reason_code": decision["reason_code"],
            "decision_id": decision["decision_id"],
            "decision_sha256": decision["decision_sha256"],
        }

    def reject(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        incident_id = cast(str, request["incident_id"])
        result = self._plans.reject(
            self._principal(incident_id, role="response-plan.approver", kind="human"),
            incident_id,
            {
                "expected_incident_version": request["incident_version"],
                "expected_plan_version": request["plan_version"],
                "expected_plan_sha256": request["plan_sha256"],
                "reason_code": request["reason_code"],
                "idempotency_key": _idempotency(cast(str, request["idempotency_key"]), "reject"),
            },
        )
        authoritative = self._plans.review(incident_id)
        decision = authoritative.get("decision")
        if not isinstance(decision, Mapping) or result.get("decision_sha256") != decision.get(
            "decision_sha256"
        ):
            raise DemoFacadeError("demo-rejection-decision-invalid")
        return self._rejection_result(request, authoritative)

    def review_rejection(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        review = self._plans.review(cast(str, request["incident_id"]))
        if review.get("state") != "rejected":
            return None
        decision = review.get("decision")
        if not isinstance(decision, Mapping):
            raise DemoFacadeError("demo-rejection-decision-invalid")
        return self._rejection_result(request, review)

    def reconcile(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        operation = request.get("operation")
        operation_request = request.get("operation_request")
        if not isinstance(operation_request, Mapping):
            raise DemoFacadeError("demo-reconciliation-request-invalid")
        if operation == "prepare":
            return self.prepare(operation_request)
        if operation != "approve":
            raise DemoFacadeError("demo-reconciliation-request-invalid")
        incident_id = cast(str, operation_request["incident_id"])
        try:
            outcome = cast(Any, self._simulator_runtime.repository).outcome_for_incident(
                incident_id
            )
        except SimulatorRepositoryError:
            raise
        if outcome is None:
            return self.execute(operation_request)
        packet, review = self._verified_packet(operation_request, outcome)
        return self._execution_result(
            operation_request,
            outcome=outcome,
            packet=packet,
            review=review,
        )


__all__ = [
    "CanonicalAlertSource",
    "CanonicalDemoWorkflow",
    "GrafanaMcpAlertProbe",
    "LiveCanonicalAlertSource",
]
