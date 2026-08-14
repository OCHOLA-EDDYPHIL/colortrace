from __future__ import annotations

import asyncio
import math
import sys
from array import array
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast

from colortrace_fixture.fixture import (
    CHANNELS,
    FLOAT_HEADER,
    PIXELS,
    compare_buffers,
)
from colortrace_grafana_mcp import (
    NormalizedActionObservation,
    SimulatorActionEvidenceBatch,
    SimulatorActionEvidenceProjection,
)
from colortrace_simulator import (
    RecoveryArtifact,
    RecoveryPublicationPort,
    RecoverySnapshot,
)

from .authority import RecoveryPrincipal
from .contracts import (
    ARTIFACT_ROLE_COUNTS,
    ARTIFACT_SCHEMA,
    CHECK_NAMES,
    RecoveryError,
    assess_post_action_observations,
    build_check_result,
    build_evidence_record,
    build_evidence_request,
    build_recovery_packet,
    build_verification_snapshot,
    canonical_json_bytes,
    document_sha256,
    parse_timestamp,
    prefixed_sha256,
    require_digest,
    require_idempotency_key,
    require_identifier,
    strict_json_bytes,
    validate_evidence_request,
    validate_verification_snapshot,
    verification_state_sha256,
)
from .service import RecoveryReadService, RecoveryVerificationService

CheckState = Literal["passed", "failed", "unresolved"]


class DurableSimulatorOutcomeSource(Protocol):
    """Narrow authority required from the durable simulator repository."""

    def outcome_for_incident(
        self,
        incident_id: str,
        *,
        expected_outcome_sha256: str | None = None,
    ) -> dict[str, Any] | None: ...


class SimulatorActionEvidenceCollector(Protocol):
    @property
    def simulator_action_catalog_sha256(self) -> str: ...

    async def collect_simulator_action_projection(
        self,
        batch: SimulatorActionEvidenceBatch,
    ) -> SimulatorActionEvidenceProjection: ...


class DeterministicRecoveryVerifierError(RecoveryError):
    def __init__(self, code: str, classification: Literal["failed", "unresolved"]) -> None:
        self.classification = classification
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _TranslatedSnapshot:
    core: dict[str, Any]
    artifact_ids: Mapping[tuple[str, str, str, str, str], str]


@dataclass(frozen=True, slots=True)
class _ArtifactRead:
    artifact: RecoveryArtifact
    artifact_id: str
    value: bytes | None
    state: Literal["failed", "unresolved"] | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class _Assessment:
    state: CheckState
    reasons: tuple[str, ...]
    artifact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()


class _CheckProblem(RuntimeError):
    def __init__(self, state: Literal["failed", "unresolved"], reason: str) -> None:
        self.state = state
        self.reason = reason
        super().__init__(reason)


def _artifact_key(artifact: RecoveryArtifact) -> tuple[str, str, str, str, str]:
    return (
        artifact.role,
        artifact.target_kind,
        artifact.target_id,
        artifact.root,
        artifact.logical_path,
    )


def _target_key(value: Mapping[str, Any]) -> tuple[str, str, str]:
    if (
        value.get("schema") != "simulator-target/v1"
        or value.get("namespace") != "colortrace-simulator"
        or value.get("kind") not in {"color-resource", "frame", "derivative"}
        or not isinstance(value.get("id"), str)
    ):
        raise _CheckProblem("failed", "recovery-scope-invalid")
    return (
        cast(str, value["namespace"]),
        cast(str, value["kind"]),
        cast(str, value["id"]),
    )


def _ordered_targets(values: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(values, key=_target_key)


def _mapping(value: Any, *, reason: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise _CheckProblem("failed", reason)
    selected = strict_json_bytes(canonical_json_bytes(value))
    if not isinstance(selected, dict):
        raise _CheckProblem("failed", reason)
    return selected


def _sequence(value: Any, *, reason: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(child, Mapping) for child in value):
        raise _CheckProblem("failed", reason)
    return [_mapping(child, reason=reason) for child in value]


def _float_buffer(value: bytes) -> array[float]:
    if not value.startswith(FLOAT_HEADER):
        raise _CheckProblem("failed", "float-buffer-invalid")
    payload = value[len(FLOAT_HEADER) :]
    if len(payload) != PIXELS * CHANNELS * 4:
        raise _CheckProblem("failed", "float-buffer-invalid")
    result = array("f")
    result.frombytes(payload)
    if sys.byteorder == "little":
        result.byteswap()
    if any(not math.isfinite(child) for child in result):
        raise _CheckProblem("failed", "float-buffer-invalid")
    return result


def _now(clock: Callable[[], datetime]) -> datetime:
    selected = clock()
    if selected.tzinfo is None or selected.utcoffset() is None:
        raise DeterministicRecoveryVerifierError("time-invalid", "unresolved")
    return selected.astimezone(UTC)


def _artifact_identifier(artifact: RecoveryArtifact) -> str:
    identity = {
        "schema": "recovery-verification-artifact-identity/v1",
        "root": artifact.root,
        "logical_path": artifact.logical_path,
        "sha256": artifact.sha256,
        "role": artifact.role,
        "target_kind": artifact.target_kind,
        "target_id": artifact.target_id,
    }
    digest = prefixed_sha256(canonical_json_bytes(identity))
    return f"recovery-artifact:{digest.removeprefix('sha256:')}"


def _translate_snapshot(
    outcome: Mapping[str, Any],
    snapshot: RecoverySnapshot,
) -> _TranslatedSnapshot:
    document = snapshot.to_dict()
    if (
        document.get("schema") != "simulator-recovery-snapshot/v1"
        or document.get("outcome_id") != outcome.get("outcome_id")
        or document.get("outcome_sha256") != outcome.get("outcome_sha256")
        or document.get("incident_id") != outcome.get("incident_id")
        or document.get("incident_version") != outcome.get("incident_version")
        or document.get("action_id") != outcome.get("action_id")
        or document.get("operation_id") != outcome.get("operation_id")
    ):
        raise DeterministicRecoveryVerifierError("simulator-snapshot-binding-invalid", "failed")
    body = {
        key: child
        for key, child in document.items()
        if key not in {"snapshot_id", "snapshot_sha256"}
    }
    digest = document_sha256(body)
    if (
        document.get("snapshot_sha256") != digest
        or document.get("snapshot_id")
        != f"simulator-recovery-snapshot:{digest.removeprefix('sha256:')}"
    ):
        raise DeterministicRecoveryVerifierError("simulator-snapshot-digest-invalid", "failed")
    listed = document.get("artifacts")
    if not isinstance(listed, list) or len(listed) != 15:
        raise DeterministicRecoveryVerifierError("recovery-artifact-profile-invalid", "failed")
    object_documents = [
        {
            "root": artifact.root,
            "logical_path": artifact.logical_path,
            "sha256": artifact.sha256,
            "size": artifact.size,
            "kind": artifact.kind,
            "role": artifact.role,
            "target_kind": artifact.target_kind,
            "target_id": artifact.target_id,
        }
        for artifact in snapshot.artifacts
    ]
    role_counts = Counter(artifact.role for artifact in snapshot.artifacts)
    if object_documents != listed or role_counts != Counter(ARTIFACT_ROLE_COUNTS):
        raise DeterministicRecoveryVerifierError("recovery-artifact-profile-invalid", "failed")
    active = _mapping(document.get("active_publication"), reason="active-publication-invalid")
    active_core = {
        "schema": "recovery-active-publication/v1",
        "publication_id": active["publication_id"],
        "observed_at": document["observed_at"],
        "generation": active["generation"],
        "pointer_sha256": active["pointer_sha256"],
        "runtime_manifest_sha256": active["runtime_manifest_sha256"],
        "fixture_manifest_sha256": active["fixture_manifest_sha256"],
        "lineage_manifest_sha256": active["lineage_manifest_sha256"],
        "declared_resource_manifest_sha256": active["declared_resource_manifest_sha256"],
        "preservation_manifest_sha256": active["preservation_manifest_sha256"],
        "safe_complement_sha256": active["safe_complement_after_sha256"],
        "safe_complement_proof_sha256": active["safe_complement_proof_sha256"],
        "candidate_seal_sha256": active["candidate_seal_sha256"],
        "candidate_tree_sha256": active["candidate_tree_sha256"],
    }
    artifact_ids: dict[tuple[str, str, str, str, str], str] = {}
    artifacts: list[dict[str, Any]] = []
    for artifact in snapshot.artifacts:
        identifier = _artifact_identifier(artifact)
        key = _artifact_key(artifact)
        if key in artifact_ids:
            raise DeterministicRecoveryVerifierError("recovery-artifact-duplicate", "failed")
        artifact_ids[key] = identifier
        selected_target = (
            None
            if artifact.target_kind == "publication"
            else {
                "schema": "simulator-target/v1",
                "namespace": "colortrace-simulator",
                "kind": artifact.target_kind,
                "id": artifact.target_id,
            }
        )
        artifacts.append(
            {
                "schema": ARTIFACT_SCHEMA,
                "artifact_id": identifier,
                "role": artifact.role,
                "target": selected_target,
                "sha256": artifact.sha256,
                "size": artifact.size,
                "publication_pointer_sha256": active["pointer_sha256"],
            }
        )
    artifacts.sort(key=lambda child: (cast(str, child["role"]), cast(str, child["artifact_id"])))
    created_at = parse_timestamp(document["observed_at"])
    core = build_verification_snapshot(
        outcome,
        active_core,
        artifacts,
        created_at=created_at,
    )
    return _TranslatedSnapshot(core, artifact_ids)


def project_recovery_verification_snapshot(
    outcome: Mapping[str, Any],
    snapshot: RecoverySnapshot,
) -> dict[str, Any]:
    """Project a trusted simulator re-observation into the validated recovery core."""

    return _translate_snapshot(outcome, snapshot).core


class DeterministicRecoveryVerifier:
    """Runs the fixed #24 verification without accepting caller-authored facts."""

    def __init__(
        self,
        *,
        outcomes: DurableSimulatorOutcomeSource,
        publication: RecoveryPublicationPort,
        collector: SimulatorActionEvidenceCollector,
        verification: RecoveryVerificationService,
        reads: RecoveryReadService,
        evidence_binding: Mapping[str, str],
        evidence_catalog_sha256: str,
        claim_owner: str = "recovery-verifier",
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        heartbeat_seconds: float = 10.0,
        collection_timeout_seconds: float = 60.0,
    ) -> None:
        if not 0.1 <= heartbeat_seconds <= 20.0:
            raise RecoveryError("recovery-heartbeat-invalid")
        if not 0.01 <= collection_timeout_seconds <= 60.0:
            raise RecoveryError("recovery-collection-timeout-invalid")
        if set(evidence_binding) != {
            "prometheus_datasource_uid",
            "loki_datasource_uid",
            "tempo_datasource_uid",
        }:
            raise RecoveryError("evidence-binding-invalid")
        for value in evidence_binding.values():
            require_identifier(value, code="evidence-binding-invalid")
        require_digest(evidence_catalog_sha256, code="evidence-catalog-invalid")
        try:
            collector_catalog_sha256 = collector.simulator_action_catalog_sha256
            require_digest(
                collector_catalog_sha256,
                code="evidence-catalog-binding-invalid",
            )
        except Exception as error:
            raise RecoveryError("evidence-catalog-binding-invalid") from error
        if collector_catalog_sha256 != evidence_catalog_sha256:
            raise RecoveryError("evidence-catalog-binding-invalid")
        require_identifier(claim_owner, code="claim-owner-invalid")
        self._outcomes = outcomes
        self._publication = publication
        self._collector = collector
        self._verification = verification
        self._reads = reads
        self._binding = dict(evidence_binding)
        self._catalog_sha256 = evidence_catalog_sha256
        self._claim_owner = claim_owner
        self._clock = clock
        self._heartbeat_seconds = heartbeat_seconds
        self._collection_timeout_seconds = collection_timeout_seconds

    def _load_outcome(
        self,
        incident_id: str,
        *,
        expected_outcome_sha256: str,
    ) -> dict[str, Any]:
        require_digest(expected_outcome_sha256, code="expected-outcome-digest-invalid")
        try:
            outcome = self._outcomes.outcome_for_incident(
                incident_id,
                expected_outcome_sha256=expected_outcome_sha256,
            )
        except Exception as error:
            code = cast(str, getattr(error, "code", "simulator-outcome-unavailable"))
            raise DeterministicRecoveryVerifierError(code, "unresolved") from error
        if outcome is None:
            raise DeterministicRecoveryVerifierError("simulator-outcome-not-found", "unresolved")
        if outcome.get("outcome_sha256") != expected_outcome_sha256:
            raise DeterministicRecoveryVerifierError(
                "simulator-outcome-binding-invalid",
                "failed",
            )
        try:
            # The frozen snapshot builder invokes the complete telemetry outcome validator.
            # This probe uses no caller-provided publication facts and fails before mutation.
            return cast(dict[str, Any], strict_json_bytes(canonical_json_bytes(outcome)))
        except (RecoveryError, TypeError, ValueError) as error:
            raise DeterministicRecoveryVerifierError(
                "simulator-outcome-invalid", "failed"
            ) from error

    def _simulator_snapshot(self, outcome: Mapping[str, Any]) -> RecoverySnapshot:
        try:
            return self._publication.snapshot_for_recovery(outcome)
        except Exception as error:
            classification = getattr(error, "classification", "unresolved")
            selected: Literal["failed", "unresolved"] = (
                "failed" if classification == "failed" else "unresolved"
            )
            code = cast(str, getattr(error, "code", "recovery-snapshot-unavailable"))
            raise DeterministicRecoveryVerifierError(code, selected) from error

    def _existing(self, incident_id: str) -> dict[str, Any] | None:
        try:
            return self._reads.durable_aggregate_for_incident(incident_id)
        except RecoveryError as error:
            if error.code == "recovery-workflow-not-found":
                return None
            raise

    async def _collect_with_heartbeat(
        self,
        principal: RecoveryPrincipal,
        claim: Any,
        batch: SimulatorActionEvidenceBatch,
        deadline: datetime,
    ) -> tuple[SimulatorActionEvidenceProjection | None, Any]:
        task = asyncio.create_task(self._collector.collect_simulator_action_projection(batch))
        current_claim = claim
        loop = asyncio.get_running_loop()
        authoritative_remaining = max(0.0, (deadline - _now(self._clock)).total_seconds())
        wall_deadline = loop.time() + min(
            authoritative_remaining,
            self._collection_timeout_seconds,
        )
        try:
            while True:
                wall_remaining = wall_deadline - loop.time()
                clock_remaining = (deadline - _now(self._clock)).total_seconds()
                remaining = min(wall_remaining, clock_remaining)
                if remaining <= 0:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    return None, current_claim
                done, _pending = await asyncio.wait(
                    {task},
                    timeout=min(self._heartbeat_seconds, remaining),
                )
                if done:
                    try:
                        return await task, current_claim
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        return None, current_claim
                current_claim = self._verification.renew_claim(principal, current_claim)
        except BaseException:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            raise

    def _read_artifacts(
        self,
        snapshot: RecoverySnapshot,
        translated: _TranslatedSnapshot,
    ) -> tuple[_ArtifactRead, ...]:
        values: list[_ArtifactRead] = []
        for artifact in snapshot.artifacts:
            identifier = translated.artifact_ids[_artifact_key(artifact)]
            try:
                raw = self._publication.read_recovery_artifact(snapshot, artifact)
                if len(raw) != artifact.size or prefixed_sha256(raw) != artifact.sha256:
                    raise _CheckProblem("failed", "artifact-binding-mismatch")
            except _CheckProblem as error:
                values.append(_ArtifactRead(artifact, identifier, None, error.state, error.reason))
            except Exception as error:
                classification = getattr(error, "classification", "unresolved")
                state: Literal["failed", "unresolved"] = (
                    "failed" if classification == "failed" else "unresolved"
                )
                code = cast(str, getattr(error, "code", "artifact-unreadable"))
                values.append(_ArtifactRead(artifact, identifier, None, state, code))
            else:
                values.append(_ArtifactRead(artifact, identifier, raw, None, None))
        return tuple(values)

    @staticmethod
    def _selected(
        reads: Sequence[_ArtifactRead],
        *roles: str,
    ) -> tuple[_ArtifactRead, ...]:
        selected = tuple(value for value in reads if value.artifact.role in roles)
        expected = sum(ARTIFACT_ROLE_COUNTS[role] for role in roles)
        if len(selected) != expected:
            raise _CheckProblem("failed", "artifact-role-profile-invalid")
        failures = [value for value in selected if value.state == "failed"]
        unresolved = [value for value in selected if value.state == "unresolved"]
        if failures:
            raise _CheckProblem("failed", cast(str, failures[0].reason))
        if unresolved:
            raise _CheckProblem("unresolved", cast(str, unresolved[0].reason))
        return selected

    @staticmethod
    def _single(reads: Sequence[_ArtifactRead], role: str) -> _ArtifactRead:
        selected = DeterministicRecoveryVerifier._selected(reads, role)
        if len(selected) != 1:
            raise _CheckProblem("failed", "artifact-role-profile-invalid")
        return selected[0]

    @staticmethod
    def _json(read: _ArtifactRead, schema: str) -> dict[str, Any]:
        if read.value is None:
            raise _CheckProblem(read.state or "unresolved", read.reason or "artifact-unreadable")
        try:
            value = strict_json_bytes(read.value)
        except RecoveryError as error:
            raise _CheckProblem("failed", "artifact-document-invalid") from error
        if not isinstance(value, dict) or value.get("schema") != schema:
            raise _CheckProblem("failed", "artifact-document-invalid")
        return value

    @staticmethod
    def _assessment(
        state: CheckState,
        reasons: Sequence[str],
        reads: Sequence[_ArtifactRead],
        evidence_ids: Sequence[str] = (),
    ) -> _Assessment:
        return _Assessment(
            state,
            tuple(sorted(set(reasons))),
            tuple(sorted(value.artifact_id for value in reads)),
            tuple(sorted(set(evidence_ids))),
        )

    def _run_check(
        self,
        reads: Sequence[_ArtifactRead],
        roles: Sequence[str],
        operation: Callable[[tuple[_ArtifactRead, ...]], _Assessment],
    ) -> _Assessment:
        selected = tuple(value for value in reads if value.artifact.role in roles)
        try:
            self._selected(reads, *roles)
            return operation(selected)
        except _CheckProblem as error:
            return self._assessment(error.state, (error.reason,), selected)
        except (IndexError, KeyError, RecoveryError, StopIteration, TypeError, ValueError):
            return self._assessment(
                "failed",
                ("authoritative-artifact-invalid",),
                selected,
            )

    def _active_check(
        self,
        outcome: Mapping[str, Any],
        simulator: Mapping[str, Any],
        reads: Sequence[_ArtifactRead],
    ) -> _Assessment:
        roles = ("fixture-manifest", "runtime-manifest", "lineage-manifest")

        def execute(selected: tuple[_ArtifactRead, ...]) -> _Assessment:
            active = _mapping(
                simulator.get("active_publication"), reason="active-publication-invalid"
            )
            documents = _mapping(simulator.get("documents"), reason="active-publication-invalid")
            pointer = _mapping(
                documents.get("publication_pointer"), reason="active-publication-invalid"
            )
            bindings = {
                "pointer_sha256": "active_publication_pointer_sha256",
                "generation": "candidate_publication_generation",
                "runtime_manifest_sha256": "active_runtime_manifest_sha256",
                "fixture_manifest_sha256": "candidate_fixture_manifest_sha256",
                "lineage_manifest_sha256": "candidate_lineage_manifest_sha256",
                "declared_resource_manifest_sha256": "declared_resource_manifest_sha256",
                "preservation_manifest_sha256": "preservation_manifest_sha256",
                "safe_complement_after_sha256": "safe_complement_after_sha256",
                "safe_complement_proof_sha256": "safe_complement_proof_sha256",
                "candidate_seal_sha256": "candidate_seal_sha256",
                "candidate_tree_sha256": "candidate_tree_sha256",
            }
            if any(active.get(left) != outcome.get(right) for left, right in bindings.items()):
                raise _CheckProblem("failed", "active-publication-binding-mismatch")
            if (
                prefixed_sha256(canonical_json_bytes(pointer)) != active["pointer_sha256"]
                or pointer.get("publication_id") != active.get("publication_id")
                or pointer.get("operation_id") != outcome.get("operation_id")
            ):
                raise _CheckProblem("failed", "active-publication-pointer-mismatch")
            role_digests = {value.artifact.role: value.artifact.sha256 for value in selected}
            if (
                role_digests["fixture-manifest"] != active["fixture_manifest_sha256"]
                or role_digests["runtime-manifest"] != active["runtime_manifest_sha256"]
                or role_digests["lineage-manifest"] != active["lineage_manifest_sha256"]
                or parse_timestamp(simulator["observed_at"])
                <= parse_timestamp(outcome["action_started_at"])
            ):
                raise _CheckProblem("failed", "active-publication-binding-mismatch")
            return self._assessment("passed", (), selected)

        return self._run_check(reads, roles, execute)

    def _resource_check(
        self,
        outcome: Mapping[str, Any],
        reads: Sequence[_ArtifactRead],
    ) -> _Assessment:
        roles = ("active-resource", "runtime-manifest")

        def execute(selected: tuple[_ArtifactRead, ...]) -> _Assessment:
            resource = next(value for value in selected if value.artifact.role == "active-resource")
            runtime_read = next(
                value for value in selected if value.artifact.role == "runtime-manifest"
            )
            runtime = self._json(runtime_read, "simulator-runtime-manifest/v1")
            results = _sequence(outcome.get("command_outcomes"), reason="resource-state-invalid")
            quarantines = [value for value in results if value.get("result_kind") == "quarantine"]
            if len(quarantines) != 1:
                raise _CheckProblem("failed", "resource-state-invalid")
            result = quarantines[0]
            target = _mapping(result.get("target"), reason="resource-state-invalid")
            before = _mapping(result.get("before"), reason="resource-state-invalid")
            after = _mapping(result.get("after"), reason="resource-state-invalid")
            if (
                target.get("kind") != "color-resource"
                or target.get("id") != before.get("resource_sha256")
                or resource.artifact.target_kind != "color-resource"
                or resource.artifact.target_id != target.get("id")
                or resource.artifact.sha256 != after.get("resource_sha256")
            ):
                raise _CheckProblem("failed", "approved-resource-state-mismatch")
            target_frames = {
                cast(str, value["id"])
                for value in cast(list[Mapping[str, Any]], outcome["targets"])
                if value.get("kind") == "frame"
            }
            frames = _sequence(runtime.get("frames"), reason="resource-state-invalid")
            workers = {
                cast(str, frame["worker_id"])
                for frame in frames
                if frame.get("frame_id") in target_frames
            }
            resources = _sequence(runtime.get("resources"), reason="resource-state-invalid")
            matches = [
                value
                for value in resources
                if value.get("worker_id") in workers
                and value.get("resource_sha256") == resource.artifact.sha256
                and value.get("resource_path") == resource.artifact.logical_path
                and value.get("resource_size") == resource.artifact.size
                and value.get("last_operation_id") == outcome.get("operation_id")
                and value.get("trace_id") == result.get("trace_id")
            ]
            if len(workers) != 1 or len(matches) != 1:
                raise _CheckProblem("failed", "approved-resource-state-mismatch")
            return self._assessment("passed", (), selected)

        return self._run_check(reads, roles, execute)

    def _reference_check(
        self,
        outcome: Mapping[str, Any],
        reads: Sequence[_ArtifactRead],
    ) -> _Assessment:
        roles = ("affected-output", "declared-reference", "runtime-manifest")

        def execute(selected: tuple[_ArtifactRead, ...]) -> _Assessment:
            runtime_read = next(
                value for value in selected if value.artifact.role == "runtime-manifest"
            )
            runtime = self._json(runtime_read, "simulator-runtime-manifest/v1")
            outputs = {
                value.artifact.target_id: value
                for value in selected
                if value.artifact.role == "affected-output"
            }
            references = {
                value.artifact.target_id: value
                for value in selected
                if value.artifact.role == "declared-reference"
            }
            target_ids = {
                cast(str, value["id"])
                for value in cast(list[Mapping[str, Any]], outcome["targets"])
                if value.get("kind") == "frame"
            }
            if set(outputs) != target_ids or set(references) != target_ids:
                raise _CheckProblem("failed", "declared-reference-profile-mismatch")
            frames = {
                cast(str, value["frame_id"]): value
                for value in _sequence(runtime.get("frames"), reason="runtime-manifest-invalid")
            }
            frame_results = {
                cast(str, cast(Mapping[str, Any], value["target"])["id"]): value
                for value in _sequence(
                    outcome.get("command_outcomes"), reason="action-results-invalid"
                )
                if value.get("result_kind") == "frame"
            }
            indeterminate = False
            for frame_id in sorted(target_ids):
                frame = frames.get(frame_id)
                result = frame_results.get(frame_id)
                output = outputs[frame_id]
                reference = references[frame_id]
                if frame is None or result is None:
                    raise _CheckProblem("failed", "declared-reference-binding-mismatch")
                after = _mapping(result.get("after"), reason="action-results-invalid")
                if (
                    frame.get("output_path") != output.artifact.logical_path
                    or frame.get("output_sha256") != output.artifact.sha256
                    or frame.get("output_size") != output.artifact.size
                    or frame.get("reference_buffer_path") != reference.artifact.logical_path
                    or frame.get("reference_buffer_sha256") != reference.artifact.sha256
                    or after.get("output_sha256") != output.artifact.sha256
                    or frame.get("last_operation_id") != outcome.get("operation_id")
                    or frame.get("trace_id") != result.get("trace_id")
                    or output.value is None
                    or reference.value is None
                ):
                    raise _CheckProblem("failed", "declared-reference-binding-mismatch")
                comparison = compare_buffers(
                    _float_buffer(output.value),
                    _float_buffer(reference.value),
                )
                state = comparison.get("state")
                if state == "reference_mismatch":
                    raise _CheckProblem("failed", "declared-reference-threshold-mismatch")
                if state != "reference_match":
                    indeterminate = True
            if indeterminate:
                raise _CheckProblem("unresolved", "reference-threshold-indeterminate")
            return self._assessment("passed", (), selected)

        return self._run_check(reads, roles, execute)

    def _lineage_check(
        self,
        outcome: Mapping[str, Any],
        reads: Sequence[_ArtifactRead],
    ) -> _Assessment:
        roles = (
            "derivative-output",
            "derivative-parent",
            "lineage-manifest",
            "runtime-manifest",
        )

        def execute(selected: tuple[_ArtifactRead, ...]) -> _Assessment:
            derivative = next(
                value for value in selected if value.artifact.role == "derivative-output"
            )
            parent = next(value for value in selected if value.artifact.role == "derivative-parent")
            lineage = self._json(
                next(value for value in selected if value.artifact.role == "lineage-manifest"),
                "artifact-lineage/v1",
            )
            runtime = self._json(
                next(value for value in selected if value.artifact.role == "runtime-manifest"),
                "simulator-runtime-manifest/v1",
            )
            derivatives = _sequence(runtime.get("derivatives"), reason="lineage-invalid")
            records = [
                value
                for value in derivatives
                if value.get("artifact_id") == derivative.artifact.target_id
            ]
            frames = _sequence(runtime.get("frames"), reason="lineage-invalid")
            if len(records) != 1:
                raise _CheckProblem("failed", "typed-lineage-mismatch")
            record = records[0]
            parents = [
                value
                for value in frames
                if value.get("frame_id") == parent.artifact.target_id
                and value.get("output_id") == record.get("parent_artifact_id")
            ]
            edges = [
                value
                for value in _sequence(lineage.get("edges"), reason="lineage-invalid")
                if value.get("edge_type") == "lossless-derivative/v1"
                and value.get("child_artifact_id") == record.get("artifact_id")
            ]
            manifest_artifacts = [
                value
                for value in _sequence(lineage.get("artifacts"), reason="lineage-invalid")
                if value.get("artifact_id") == record.get("artifact_id")
                and value.get("artifact_type") == "lossless-derivative"
            ]
            results = [
                value
                for value in _sequence(
                    outcome.get("command_outcomes"), reason="action-results-invalid"
                )
                if value.get("result_kind") == "derivative"
            ]
            profiles = (parents, edges, manifest_artifacts, results)
            if any(len(value) != 1 for value in profiles):
                raise _CheckProblem("failed", "typed-lineage-mismatch")
            result = results[0]
            after = _mapping(result.get("after"), reason="action-results-invalid")
            if (
                edges[0].get("parent_artifact_id") != record.get("parent_artifact_id")
                or manifest_artifacts[0].get("sha256")
                != derivative.artifact.sha256.removeprefix("sha256:")
                or record.get("buffer_path") != derivative.artifact.logical_path
                or record.get("buffer_sha256") != derivative.artifact.sha256
                or record.get("buffer_size") != derivative.artifact.size
                or record.get("last_operation_id") != outcome.get("operation_id")
                or record.get("trace_id") != result.get("trace_id")
                or after.get("derivative_sha256") != derivative.artifact.sha256
                or parents[0].get("output_path") != parent.artifact.logical_path
                or parents[0].get("output_sha256") != parent.artifact.sha256
                or derivative.value is None
                or parent.value is None
                or derivative.value != parent.value
            ):
                raise _CheckProblem("failed", "typed-lineage-mismatch")
            return self._assessment("passed", (), selected)

        return self._run_check(reads, roles, execute)

    def _scope_check(
        self,
        outcome: Mapping[str, Any],
        reads: Sequence[_ArtifactRead],
    ) -> _Assessment:
        roles = ("preservation-manifest", "runtime-manifest")

        def execute(selected: tuple[_ArtifactRead, ...]) -> _Assessment:
            preservation = self._json(
                next(value for value in selected if value.artifact.role == "preservation-manifest"),
                "simulator-preservation-manifest/v1",
            )
            runtime = self._json(
                next(value for value in selected if value.artifact.role == "runtime-manifest"),
                "simulator-runtime-manifest/v1",
            )
            targets = cast(list[Mapping[str, Any]], outcome["targets"])
            exclusions = cast(list[Mapping[str, Any]], outcome["exclusions"])
            target_keys = {_target_key(value) for value in targets}
            exclusion_keys = {_target_key(value) for value in exclusions}
            kinds = Counter(value[1] for value in target_keys)
            command_targets = {
                _target_key(cast(Mapping[str, Any], value["target"]))
                for value in _sequence(
                    outcome.get("command_outcomes"), reason="recovery-scope-invalid"
                )
            }
            frame_ids = {
                cast(str, value["frame_id"])
                for value in _sequence(runtime.get("frames"), reason="runtime-manifest-invalid")
            }
            target_frames = {value[2] for value in target_keys if value[1] == "frame"}
            expected_exclusions = {
                ("colortrace-simulator", "frame", value) for value in frame_ids - target_frames
            }
            if (
                kinds != Counter({"color-resource": 1, "frame": 3, "derivative": 1})
                or target_keys != command_targets
                or target_keys & exclusion_keys
                or exclusion_keys != expected_exclusions
            ):
                raise _CheckProblem("failed", "approved-recovery-scope-mismatch")
            if preservation.get("targets_sha256") != prefixed_sha256(
                canonical_json_bytes(_ordered_targets(targets))
            ) or preservation.get("exclusions_sha256") != prefixed_sha256(
                canonical_json_bytes(_ordered_targets(exclusions))
            ):
                raise _CheckProblem("failed", "approved-recovery-scope-mismatch")
            derivative_id = next(value[2] for value in target_keys if value[1] == "derivative")
            resource_id = next(value[2] for value in target_keys if value[1] == "color-resource")
            expected_mutable = {
                ("resource", resource_id),
                ("derivative-output", derivative_id),
                ("derivative-display", derivative_id),
                *(
                    (kind, frame_id)
                    for frame_id in target_frames
                    for kind in ("frame-output", "frame-display")
                ),
            }
            mutable = _sequence(
                preservation.get("mutable_entries"), reason="preservation-manifest-invalid"
            )
            identities = {
                (cast(str, value.get("kind")), cast(str, value.get("id"))) for value in mutable
            }
            if len(mutable) != 9 or identities != expected_mutable:
                raise _CheckProblem("failed", "approved-recovery-scope-mismatch")
            return self._assessment("passed", (), selected)

        return self._run_check(reads, roles, execute)

    def _safe_check(
        self,
        outcome: Mapping[str, Any],
        simulator: Mapping[str, Any],
        reads: Sequence[_ArtifactRead],
    ) -> _Assessment:
        roles = (
            "runtime-manifest",
            "preservation-manifest",
            "safe-complement",
            "safe-complement-proof",
        )

        def execute(selected: tuple[_ArtifactRead, ...]) -> _Assessment:
            by_role = {value.artifact.role: value for value in selected}
            runtime = self._json(by_role["runtime-manifest"], "simulator-runtime-manifest/v1")
            preservation = self._json(
                by_role["preservation-manifest"], "simulator-preservation-manifest/v1"
            )
            stored = self._json(by_role["safe-complement"], "simulator-safe-complement/v1")
            proof = self._json(
                by_role["safe-complement-proof"],
                "simulator-safe-complement-proof/v1",
            )
            mutable = _sequence(
                preservation.get("mutable_entries"), reason="preservation-manifest-invalid"
            )
            mutable_paths = {cast(str, value.get("path")) for value in mutable}
            additions = _sequence(
                preservation.get("allowed_additions"), reason="preservation-manifest-invalid"
            )
            if len(mutable_paths) != len(mutable) or len(additions) != 1:
                raise _CheckProblem("failed", "safe-complement-mismatch")
            excluded_paths = {
                *mutable_paths,
                cast(str, cast(Mapping[str, Any], runtime["lineage"])["path"]),
                cast(str, additions[0].get("path")),
            }
            files = [
                {
                    "kind": value["kind"],
                    "id": value["path"],
                    "path": value["path"],
                    "sha256": value["sha256"],
                    "size": value["size"],
                }
                for value in _sequence(runtime.get("files"), reason="runtime-manifest-invalid")
                if value.get("path") not in excluded_paths
            ]
            targets = cast(list[Mapping[str, Any]], outcome["targets"])
            target_frames = {
                cast(str, value["id"]) for value in targets if value.get("kind") == "frame"
            }
            frames = _sequence(runtime.get("frames"), reason="runtime-manifest-invalid")
            frame_by_id = {cast(str, value["frame_id"]): value for value in frames}
            workers = {
                cast(str, frame_by_id[value]["worker_id"])
                for value in target_frames
                if value in frame_by_id
            }
            if len(workers) != 1 or len(frame_by_id) != len(frames):
                raise _CheckProblem("failed", "safe-complement-mismatch")
            target_worker = next(iter(workers))
            records = [
                {
                    "kind": "resource",
                    "id": value["worker_id"],
                    "record_sha256": prefixed_sha256(canonical_json_bytes(value)),
                }
                for value in _sequence(runtime.get("resources"), reason="runtime-manifest-invalid")
                if value.get("worker_id") != target_worker
            ]
            records.extend(
                {
                    "kind": "frame",
                    "id": value["frame_id"],
                    "record_sha256": prefixed_sha256(canonical_json_bytes(value)),
                }
                for value in frames
                if value.get("frame_id") not in target_frames
            )
            recomputed = {
                "schema": "simulator-safe-complement/v1",
                "fixture_id": runtime["fixture_id"],
                "source_batch_id": runtime["source_batch_id"],
                "source_batch_sha256": runtime["source_batch_sha256"],
                "files": sorted(files, key=lambda value: cast(str, value["path"])),
                "records": sorted(
                    records,
                    key=lambda value: (cast(str, value["kind"]), cast(str, value["id"])),
                ),
            }
            digest = document_sha256(recomputed)
            if (
                recomputed != stored
                or digest != by_role["safe-complement"].artifact.sha256
                or digest != outcome.get("safe_complement_before_sha256")
                or digest != outcome.get("safe_complement_after_sha256")
                or digest != preservation.get("safe_complement_sha256")
                or digest != simulator.get("recomputed_safe_complement_sha256")
                or recomputed != simulator.get("recomputed_safe_complement")
                or proof.get("before_sha256") != digest
                or proof.get("after_sha256") != digest
                or proof.get("byte_identical") is not True
                or proof.get("preservation_manifest_sha256")
                != by_role["preservation-manifest"].artifact.sha256
            ):
                raise _CheckProblem("failed", "safe-complement-mismatch")
            return self._assessment("passed", (), selected)

        return self._run_check(reads, roles, execute)

    @staticmethod
    def _observation_records(
        projection: SimulatorActionEvidenceProjection | None,
        batch: SimulatorActionEvidenceBatch,
    ) -> tuple[dict[str, Any], ...]:
        if projection is None:
            return ()
        if (
            projection.request_id != batch.request_id
            or projection.evidence_request_id != batch.evidence_request_id
            or projection.evidence_request_sha256 != batch.evidence_request_sha256
            or projection.catalog_sha256 != batch.catalog_sha256
            or projection.incident_id != batch.incident_id
            or projection.outcome_id != batch.outcome_id
            or projection.outcome_sha256 != batch.outcome_sha256
            or projection.snapshot_id != batch.snapshot_id
            or projection.snapshot_sha256 != batch.snapshot_sha256
            or projection.action_id != batch.action_id
            or projection.operation_id != batch.operation_id
            or projection.completed_at.tzinfo is None
            or projection.completed_at.utcoffset() is None
        ):
            return ()
        records: list[dict[str, Any]] = []
        for value in projection.observations:
            try:
                records.append(
                    build_evidence_record(
                        event_id=value.event_id,
                        signal=value.signal,
                        subject_kind=value.subject_kind,
                        subject_id=value.subject_id,
                        trace_id=value.trace_id,
                        outcome_id=value.outcome_id,
                        outcome_sha256=value.outcome_sha256,
                        action_id=value.action_id,
                        operation_id=value.operation_id,
                        observed_at=value.observed_at,
                        emitted_at=value.emitted_at,
                        retrieved_at=value.retrieved_at,
                        clock_provenance=value.clock_provenance,
                        clock_skew_milliseconds=value.clock_skew_milliseconds,
                        truncated=value.truncated,
                        source_label=value.source_label,
                        source_envelope=value.source_envelope,
                    )
                )
            except (RecoveryError, TypeError, ValueError):
                continue
        return tuple(records)

    @staticmethod
    def _check_documents(
        snapshot: Mapping[str, Any],
        assessments: Mapping[str, _Assessment],
    ) -> list[dict[str, Any]]:
        documents: list[dict[str, Any]] = []
        for name in CHECK_NAMES:
            assessment = assessments[name]
            normalized = document_sha256(
                {
                    "schema": "recovery-check-normalized-input/v1",
                    "check": name,
                    "snapshot_sha256": snapshot["snapshot_sha256"],
                    "artifact_ids": list(assessment.artifact_ids),
                    "evidence_ids": list(assessment.evidence_ids),
                    "state": assessment.state,
                    "reason_codes": list(assessment.reasons),
                }
            )
            documents.append(
                build_check_result(
                    name,
                    assessment.state,
                    normalized_inputs_sha256=normalized,
                    evidence_ids=assessment.evidence_ids,
                    artifact_ids=assessment.artifact_ids,
                    reason_codes=assessment.reasons,
                )
            )
        return documents

    def _unresolved_packet_after_claim(
        self,
        claim: Any,
        existing: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        snapshot = validate_verification_snapshot(claim.snapshot)
        request = validate_evidence_request(claim.evidence_request, snapshot=snapshot)
        request_start = parse_timestamp(request["evaluation_started_at"])
        deadline = parse_timestamp(request["evaluation_deadline_at"])
        evaluation_completed = min(max(request_start, _now(self._clock)), deadline)
        telemetry_state, telemetry_reasons, telemetry_ids = assess_post_action_observations(
            snapshot,
            (),
            evaluation_started_at=request_start,
            evaluation_completed_at=evaluation_completed,
        )
        assessments = {
            name: _Assessment(
                "unresolved",
                ("verification-setup-unresolved",),
                (),
            )
            for name in CHECK_NAMES
            if name != "post-action-telemetry-correlation"
        }
        assessments["post-action-telemetry-correlation"] = _Assessment(
            telemetry_state,
            telemetry_reasons,
            (),
            telemetry_ids,
        )
        previous = None if existing is None else existing.get("packet")
        return build_recovery_packet(
            snapshot,
            request,
            self._check_documents(snapshot, assessments),
            workflow_id=claim.workflow_id,
            workflow_version=claim.workflow_version + 1,
            attempt_id=claim.attempt_id,
            attempt_number=claim.attempt_number,
            evaluation_completed_at=evaluation_completed,
            supersedes_packet_id=(
                None if not isinstance(previous, Mapping) else cast(str, previous["packet_id"])
            ),
            supersedes_packet_sha256=(
                None if not isinstance(previous, Mapping) else cast(str, previous["packet_sha256"])
            ),
        )

    async def _evaluate_claim(
        self,
        principal: RecoveryPrincipal,
        claim: Any,
        batch: SimulatorActionEvidenceBatch,
        *,
        outcome: Mapping[str, Any],
        simulator_document: Mapping[str, Any],
        simulator_snapshot: RecoverySnapshot,
        translated: _TranslatedSnapshot,
        core_snapshot: Mapping[str, Any],
        request: Mapping[str, Any],
        existing: Mapping[str, Any] | None,
    ) -> tuple[dict[str, Any], tuple[dict[str, Any], ...], Any]:
        projection, current_claim = await self._collect_with_heartbeat(
            principal,
            claim,
            batch,
            parse_timestamp(request["evaluation_deadline_at"]),
        )
        records = self._observation_records(projection, batch)
        reads = self._read_artifacts(simulator_snapshot, translated)
        assessments: dict[str, _Assessment] = {
            "active-publication": self._active_check(outcome, simulator_document, reads),
            "approved-resource-state": self._resource_check(outcome, reads),
            "declared-reference-recovery": self._reference_check(outcome, reads),
            "exact-typed-lineage": self._lineage_check(outcome, reads),
            "approved-recovery-scope": self._scope_check(outcome, reads),
            "safe-complement-preservation": self._safe_check(
                outcome,
                simulator_document,
                reads,
            ),
        }
        request_start = parse_timestamp(request["evaluation_started_at"])
        deadline = parse_timestamp(request["evaluation_deadline_at"])
        projected_end = (
            request_start if projection is None else projection.completed_at.astimezone(UTC)
        )
        if projected_end > deadline:
            records = ()
        evaluation_completed = min(max(request_start, projected_end, _now(self._clock)), deadline)
        telemetry_state, telemetry_reasons, telemetry_ids = assess_post_action_observations(
            core_snapshot,
            records,
            evaluation_started_at=request_start,
            evaluation_completed_at=evaluation_completed,
        )
        assessments["post-action-telemetry-correlation"] = self._assessment(
            telemetry_state,
            telemetry_reasons,
            (),
            telemetry_ids,
        )
        try:
            self._publication.assert_recovery_snapshot_current(simulator_snapshot)
        except Exception as error:
            classification = getattr(error, "classification", None)
            code = cast(str, getattr(error, "code", "active-publication-recheck-unavailable"))
            state: Literal["failed", "unresolved"] = (
                "unresolved" if classification == "unresolved" else "failed"
            )
            current_active = assessments["active-publication"]
            if current_active.state != "failed":
                assessments["active-publication"] = _Assessment(
                    state,
                    tuple(sorted({*current_active.reasons, code})),
                    current_active.artifact_ids,
                )
        previous = None if existing is None else existing.get("packet")
        packet = build_recovery_packet(
            core_snapshot,
            request,
            self._check_documents(core_snapshot, assessments),
            workflow_id=current_claim.workflow_id,
            workflow_version=current_claim.workflow_version + 1,
            attempt_id=current_claim.attempt_id,
            attempt_number=current_claim.attempt_number,
            evaluation_completed_at=evaluation_completed,
            supersedes_packet_id=(
                None if not isinstance(previous, Mapping) else cast(str, previous["packet_id"])
            ),
            supersedes_packet_sha256=(
                None if not isinstance(previous, Mapping) else cast(str, previous["packet_sha256"])
            ),
        )
        return packet, records, current_claim

    async def verify(
        self,
        principal: RecoveryPrincipal,
        incident_id: str,
        *,
        idempotency_key: str,
        expected_incident_version: int,
        expected_outcome_sha256: str,
    ) -> dict[str, Any]:
        require_idempotency_key(idempotency_key)
        if (
            not isinstance(expected_incident_version, int)
            or isinstance(expected_incident_version, bool)
            or expected_incident_version < 1
        ):
            raise RecoveryError("expected-incident-version-invalid")
        outcome = self._load_outcome(
            incident_id,
            expected_outcome_sha256=expected_outcome_sha256,
        )
        if outcome.get("incident_version") != expected_incident_version:
            raise DeterministicRecoveryVerifierError(
                "recovery-incident-version-conflict",
                "failed",
            )
        replay = self._reads.verification_packet_for_idempotency(
            incident_id,
            idempotency_key,
            expected_outcome_sha256,
        )
        if replay is not None:
            return replay
        simulator_snapshot = self._simulator_snapshot(outcome)
        simulator_document = simulator_snapshot.to_dict()
        translated = _translate_snapshot(outcome, simulator_snapshot)
        existing = self._existing(incident_id)
        if existing is not None:
            review = cast(Mapping[str, Any], existing["review"])
            existing_snapshot = validate_verification_snapshot(
                cast(Mapping[str, Any], existing["snapshot"])
            )
            existing_outcome = cast(Mapping[str, Any], existing_snapshot["action_outcome"])
            if existing_outcome["outcome_sha256"] == outcome["outcome_sha256"]:
                packet = existing.get("packet")
                if review["status"] in {"recovery_verified", "recovery_failed", "closed"}:
                    if not isinstance(packet, Mapping):
                        raise RecoveryError("stored-recovery-packet-missing")
                    self._publication.assert_recovery_snapshot_current(simulator_snapshot)
                    return cast(dict[str, Any], strict_json_bytes(canonical_json_bytes(packet)))
                core_snapshot = existing_snapshot
            else:
                core_snapshot = translated.core
        else:
            core_snapshot = translated.core

        current = _now(self._clock)
        observed = parse_timestamp(simulator_document["observed_at"])
        evaluation_started = max(current, observed)
        if existing is not None and cast(Mapping[str, Any], existing["review"])["status"] in {
            "verification_pending",
            "verification_running",
        }:
            request = cast(dict[str, Any], existing["evidence_request"])
        else:
            request = build_evidence_request(
                core_snapshot,
                binding=self._binding,
                catalog_sha256=self._catalog_sha256,
                evaluation_started_at=evaluation_started,
            )
        if (
            request.get("catalog_sha256") != self._catalog_sha256
            or request.get("binding") != self._binding
            or request.get("state_equivalence_sha256") != verification_state_sha256(translated.core)
        ):
            raise DeterministicRecoveryVerifierError(
                "recovery-evidence-authorization-mismatch",
                "failed",
            )
        attempt = self._verification.request_verification(
            principal,
            core_snapshot,
            request,
            idempotency_key=idempotency_key,
        )
        claim = self._verification.claim_verification(
            principal,
            attempt.workflow_id,
            owner=self._claim_owner,
        )
        try:
            batch = SimulatorActionEvidenceBatch.from_documents(
                outcome=outcome,
                snapshot=simulator_document,
                binding=self._binding,
                evidence_request_id=cast(str, request["request_id"]),
                evidence_request_sha256=cast(str, request["request_sha256"]),
                catalog_sha256=cast(str, request["catalog_sha256"]),
                predecessor_event_sha256=cast(
                    str | None,
                    request["predecessor_event_sha256"],
                ),
            )
            packet, records, claim = await self._evaluate_claim(
                principal,
                claim,
                batch,
                outcome=outcome,
                simulator_document=simulator_document,
                simulator_snapshot=simulator_snapshot,
                translated=translated,
                core_snapshot=core_snapshot,
                request=request,
                existing=existing,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            packet = self._unresolved_packet_after_claim(claim, existing)
            records = ()
        return self._verification.complete_verification(
            principal,
            claim,
            packet,
            evidence_records=records,
        )


class SynchronousRecoveryWorkflowRunner:
    """Sync API boundary for the async evidence workflow in FastAPI worker threads."""

    def __init__(self, verifier: DeterministicRecoveryVerifier) -> None:
        self._verifier = verifier

    def verify(
        self,
        principal: RecoveryPrincipal,
        incident_id: str,
        *,
        idempotency_key: str,
        expected_incident_version: int,
        expected_outcome_sha256: str,
    ) -> dict[str, Any]:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(
                self._verifier.verify(
                    principal,
                    incident_id,
                    idempotency_key=idempotency_key,
                    expected_incident_version=expected_incident_version,
                    expected_outcome_sha256=expected_outcome_sha256,
                )
            )
        raise RecoveryError("recovery-sync-runner-event-loop-conflict")


__all__ = [
    "DeterministicRecoveryVerifier",
    "DeterministicRecoveryVerifierError",
    "DurableSimulatorOutcomeSource",
    "NormalizedActionObservation",
    "SimulatorActionEvidenceCollector",
    "SimulatorActionEvidenceProjection",
    "SynchronousRecoveryWorkflowRunner",
    "project_recovery_verification_snapshot",
]
