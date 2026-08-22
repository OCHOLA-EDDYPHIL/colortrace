from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, TextIO, cast

from colortrace_fixture import CANONICAL_SEED, FIXTURE_ID, build_scenario
from colortrace_response_plans import (
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    ResponsePlanError,
    SQLiteResponsePlanRepository,
)
from colortrace_response_plans.contracts import canonical_json_bytes, prefixed_sha256
from colortrace_simulator import DispatchIdentity, SimulatorActionService
from colortrace_simulator.authority import SimulatorAuthorityBoundary, SimulatorExecutorBoundary
from colortrace_simulator.bundle import LocalPublicationPort
from colortrace_simulator.repository import SQLiteSimulatorRepository

from .auth import Principal
from .response_plans import ResponsePlanCoordinator
from .simulator_actions import SimulatorActionCoordinator

_CONFIG_KEYS = frozenset(
    {
        "schema",
        "incident_id",
        "incident_version",
        "fixture_variant",
        "fixture_seed",
        "issuer",
        "audience",
        "approval_phrase",
    }
)
_CONFIG_VALUES: Mapping[str, str | int] = {
    "schema": "colortrace-local-demo-config/v1",
    "incident_id": "incident-local-demo-001",
    "incident_version": 1,
    "fixture_variant": "canonical",
    "fixture_seed": CANONICAL_SEED,
    "issuer": "https://identity.colortrace.invalid",
    "audience": "colortrace-local-demo",
    "approval_phrase": "APPROVE_COLORTRACE_SIMULATOR_ACTION",
}
_OBJECT_ID = re.compile(r"[0-9a-f]{40}")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DEMO_TIME = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


class DemoError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class _StepClock:
    value: datetime

    def __call__(self) -> datetime:
        observed = self.value
        self.value += timedelta(milliseconds=1)
        return observed


class _RecordedIncident:
    def __init__(self, replay: Mapping[str, Any]) -> None:
        self._replay = replay

    def replay(self, incident_id: str) -> dict[str, Any]:
        incident = cast(Mapping[str, Any], self._replay["incident"])
        if incident.get("incident_id") != incident_id:
            raise DemoError("incident-binding-invalid")
        return dict(self._replay)


ApprovalProvider = Callable[[str, str], str]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise DemoError("config-invalid")
        document[key] = value
    return document


def _reject_float(_value: str) -> NoReturn:
    raise DemoError("config-invalid")


def _load_config(path: Path) -> tuple[dict[str, str | int], str, str]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise DemoError("config-file-unsafe")
        if metadata.st_mode & 0o022:
            raise DemoError("config-file-unsafe")
        raw = path.read_bytes()
    except DemoError:
        raise
    except OSError as error:
        raise DemoError("config-unavailable") from error
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except DemoError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise DemoError("config-invalid") from error
    if not isinstance(value, dict) or set(value) != _CONFIG_KEYS:
        raise DemoError("config-invalid")
    if type(value.get("incident_version")) is not int:
        raise DemoError("config-invalid")
    if any(not isinstance(value.get(key), str) for key in _CONFIG_KEYS - {"incident_version"}):
        raise DemoError("config-invalid")
    if value != _CONFIG_VALUES:
        raise DemoError("config-invalid")
    resolved = path.resolve(strict=True)
    try:
        label = resolved.relative_to(Path.cwd().resolve(strict=True)).as_posix()
    except ValueError:
        label = resolved.name
    if not label or label.startswith("/") or ".." in Path(label).parts:
        raise DemoError("config-path-unsafe")
    return cast(dict[str, str | int], value), prefixed_sha256(raw), label


def _workspace_path(path: Path) -> Path:
    if ".." in path.parts:
        raise DemoError("workspace-unsafe")
    absolute = path if path.is_absolute() else Path.cwd() / path
    for parent in reversed((absolute, *absolute.parents)):
        if not parent.exists() and not parent.is_symlink():
            continue
        if parent.is_symlink():
            raise DemoError("workspace-unsafe")
    resolved = absolute.resolve(strict=False)
    if resolved == Path(resolved.anchor) or len(resolved.parts) < 3:
        raise DemoError("workspace-unsafe")
    try:
        metadata = resolved.lstat()
    except FileNotFoundError:
        try:
            parent = resolved.parent.resolve(strict=True)
            if not parent.is_dir():
                raise DemoError("workspace-unsafe")
            resolved.mkdir(mode=0o700)
            metadata = resolved.lstat()
        except DemoError:
            raise
        except OSError as error:
            raise DemoError("workspace-unavailable") from error
    except OSError as error:
        raise DemoError("workspace-unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
    ):
        raise DemoError("workspace-unsafe")
    try:
        if next(resolved.iterdir(), None) is not None:
            raise DemoError("workspace-not-empty")
    except OSError as error:
        raise DemoError("workspace-unavailable") from error
    return resolved


def _binding(
    *,
    config_path: str,
    config_sha256: str,
    source_commit: str,
    source_tree: str,
    image_digest: str,
) -> dict[str, str]:
    if _OBJECT_ID.fullmatch(source_commit) is None:
        raise DemoError("source-commit-invalid")
    if _OBJECT_ID.fullmatch(source_tree) is None:
        raise DemoError("source-tree-invalid")
    if _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise DemoError("image-digest-invalid")
    return {
        "config_path": config_path,
        "config_sha256": config_sha256,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "image_digest": image_digest,
    }


def _principal(
    *,
    subject: str,
    role: str,
    kind: str,
    config: Mapping[str, str | int],
) -> Principal:
    credential_sha256 = prefixed_sha256(f"local-demo-identity:{subject}".encode())
    return Principal(
        subject=subject,
        display_name=subject,
        roles=frozenset({role}),
        issuer=cast(str, config["issuer"]),
        audience=cast(str, config["audience"]),
        principal_kind=cast(Any, kind),
        incident_ids=frozenset({cast(str, config["incident_id"])}),
        credential_sha256=credential_sha256,
        expires_at=_DEMO_TIME + timedelta(days=1),
    )


def _recommendation(inputs: Mapping[str, Any]) -> str:
    targets = cast(Sequence[Mapping[str, Any]], inputs["targets"])
    exclusions = cast(Sequence[Mapping[str, Any]], inputs["exclusions"])
    counts = {
        kind: sum(target.get("kind") == kind for target in targets)
        for kind in ("color-resource", "frame", "derivative")
    }
    if counts != {"color-resource": 1, "frame": 3, "derivative": 1}:
        raise DemoError("fixture-topology-invalid")
    if not exclusions or any(target.get("kind") != "frame" for target in exclusions):
        raise DemoError("fixture-safe-scope-invalid")
    return (
        "Quarantine the mismatched color resource, install the approved replacement, "
        f"and rerender {counts['frame']} affected frames plus {counts['derivative']} "
        f"derivative; preserve {len(exclusions)} safe frames."
    )


def _incident_replay(
    *,
    config: Mapping[str, str | int],
    inputs: Mapping[str, Any],
    binding: Mapping[str, str],
    recommendation: str,
) -> dict[str, Any]:
    targets = cast(Sequence[Mapping[str, Any]], inputs["targets"])
    affected = [
        {"kind": target["kind"], "id": target["id"]}
        for target in targets
        if target["kind"] != "color-resource"
    ]
    safe = [
        {"kind": target["kind"], "id": target["id"]}
        for target in cast(Sequence[Mapping[str, Any]], inputs["exclusions"])
    ]
    causal = next(
        cast(str, target["id"]) for target in targets if target["kind"] == "color-resource"
    ).removeprefix("sha256:")
    scope = {
        "state": "resolved",
        "policy": "single-causal-resource-scope/v1",
        "affected": affected,
        "safe": safe,
        "unknown": [],
        "reason_codes": [],
    }
    packet_source = {
        "schema": "colortrace-local-demo-inspection/v1",
        "incident_id": config["incident_id"],
        "incident_version": config["incident_version"],
        "binding": dict(binding),
        "fixture_id": FIXTURE_ID,
        "fixture_seed": config["fixture_seed"],
        "fixture_variant": config["fixture_variant"],
        "recommendation": recommendation,
        "scope": scope,
        "causal_resource_sha256": causal,
    }
    packet_sha256 = prefixed_sha256(canonical_json_bytes(packet_source))
    incident_id = cast(str, config["incident_id"])
    return {
        "schema": "incident-replay/v1",
        "incident": {
            "incident_id": incident_id,
            "status": "resolved",
            "version": config["incident_version"],
        },
        "packet": {
            "packet_id": f"response-packet:{packet_sha256.removeprefix('sha256:')}",
            "incident_id": incident_id,
            "status": "resolved",
            "derivation_sha256": packet_sha256,
            "candidate_plan": {"targets": affected},
            "scope": scope,
            "unresolved_items": [],
        },
        "validator_results": [{"scope": {"causal_resource_sha256": causal}}],
    }


def _active_publication_state(root: Path) -> tuple[str, int]:
    path = root / "state" / "active.json"
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise DemoError("publication-state-invalid")
        raw = path.read_bytes()
        value = json.loads(raw)
    except DemoError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DemoError("publication-state-invalid") from error
    if (
        not isinstance(value, dict)
        or value.get("schema") != "simulator-publication-pointer/v1"
        or type(value.get("generation")) is not int
    ):
        raise DemoError("publication-state-invalid")
    return prefixed_sha256(raw), cast(int, value["generation"])


def _idempotency(binding_sha256: str, operation: str) -> str:
    return f"local-demo-{operation}:{binding_sha256.removeprefix('sha256:')}"


def run_demo(
    *,
    config_path: Path,
    workspace: Path,
    source_commit: str,
    source_tree: str,
    image_digest: str,
    approval_provider: ApprovalProvider,
) -> dict[str, Any]:
    config, config_sha256, config_label = _load_config(config_path)
    exact_binding = _binding(
        config_path=config_label,
        config_sha256=config_sha256,
        source_commit=source_commit,
        source_tree=source_tree,
        image_digest=image_digest,
    )
    binding_sha256 = prefixed_sha256(canonical_json_bytes(exact_binding))
    root = _workspace_path(workspace)
    fixture = root / "fixture"
    build_scenario(
        fixture,
        oracle_root=root / "fixture-oracle",
        variant_id=cast(str, config["fixture_variant"]),
        seed=cast(str, config["fixture_seed"]),
    )

    clock = _StepClock(_DEMO_TIME)
    publication_root = root / "publication"
    publication = LocalPublicationPort.bootstrap(
        root=publication_root,
        fixture_bundle=fixture,
        clock=clock,
    )
    inputs = publication.canonical_plan_inputs()
    recommendation = _recommendation(inputs)
    replay = _incident_replay(
        config=config,
        inputs=inputs,
        binding=exact_binding,
        recommendation=recommendation,
    )
    incident_id = cast(str, config["incident_id"])
    incident_version = cast(int, config["incident_version"])
    identity_boundary = OIDCTrustBoundary(
        trusted_issuers=frozenset({cast(str, config["issuer"])}),
        audience=cast(str, config["audience"]),
    )
    authority_boundary = CanonicalAuthorityBoundary()
    response_repository = SQLiteResponsePlanRepository(
        root / "response-plans.sqlite3",
        authority_boundary=authority_boundary,
    )
    simulator_repository: SQLiteSimulatorRepository | None = None
    try:
        plans = ResponsePlanCoordinator(
            incident_reader=_RecordedIncident(replay),
            repository=response_repository,
            authority_boundary=authority_boundary,
            identity_boundary=identity_boundary,
            clock=clock,
        )
        draft = plans.draft(incident_id)
        editor = _principal(
            subject="local-demo-editor",
            role="response-plan.editor",
            kind="human",
            config=config,
        )
        created = plans.create(
            editor,
            incident_id,
            {
                "expected_incident_version": incident_version,
                "expected_plan_version": 0,
                "response_packet_id": draft["response_packet_id"],
                "response_packet_sha256": draft["response_packet_sha256"],
                "deterministic_scope_sha256": draft["deterministic_scope_sha256"],
                "targets": draft["targets"],
                "exclusions": draft["exclusions"],
                "commands": inputs["commands"],
                "unresolved_acknowledged": False,
                "idempotency_key": _idempotency(binding_sha256, "create"),
            },
        )
        dispatcher = _principal(
            subject="local-demo-dispatcher",
            role="response-plan.dispatcher",
            kind="service",
            config=config,
        )
        preapproval_before = _active_publication_state(publication_root)
        try:
            plans.authorize_dispatch(
                dispatcher,
                incident_id,
                {
                    "expected_incident_version": incident_version,
                    "expected_plan_version": created["version"],
                    "expected_plan_sha256": created["plan_sha256"],
                    "idempotency_key": _idempotency(binding_sha256, "preapproval"),
                },
            )
        except ResponsePlanError as error:
            if error.code != "plan-not-approved":
                raise
            preapproval_reason = error.code
        else:
            raise DemoError("preapproval-dispatch-accepted")
        preapproval_after = _active_publication_state(publication_root)
        if preapproval_after != preapproval_before:
            raise DemoError("preapproval-publication-mutated")

        approval_value = approval_provider(
            recommendation,
            cast(str, config["approval_phrase"]),
        )
        if not approval_value:
            raise DemoError("approval-input-missing")
        if approval_value != config["approval_phrase"]:
            raise DemoError("approval-phrase-invalid")
        approval = plans.approve(
            _principal(
                subject="local-demo-approver",
                role="response-plan.approver",
                kind="human",
                config=config,
            ),
            incident_id,
            {
                "expected_incident_version": incident_version,
                "expected_plan_version": created["version"],
                "expected_plan_sha256": created["plan_sha256"],
                "idempotency_key": _idempotency(binding_sha256, "approve"),
            },
        )
        authorization = plans.authorize_dispatch(
            dispatcher,
            incident_id,
            {
                "expected_incident_version": incident_version,
                "expected_plan_version": created["version"],
                "expected_plan_sha256": created["plan_sha256"],
                "idempotency_key": _idempotency(binding_sha256, "authorize"),
            },
        )
        consumption = plans.consume_dispatch(
            dispatcher,
            incident_id,
            {
                "authorization_id": authorization["authorization_id"],
                "expected_incident_version": incident_version,
                "expected_plan_version": created["version"],
                "expected_plan_sha256": created["plan_sha256"],
                "expected_task_key": authorization["task_key"],
                "expected_payload_sha256": authorization["payload_sha256"],
                "idempotency_key": _idempotency(binding_sha256, "consume"),
            },
        )
        identity = DispatchIdentity(
            task_key=cast(str, authorization["task_key"]),
            operation_id=cast(str, authorization["operation_id"]),
            payload_sha256=cast(str, authorization["payload_sha256"]),
        )
        simulator_repository = SQLiteSimulatorRepository(root / "simulator.sqlite3")
        executor_boundary = SimulatorExecutorBoundary()
        trace_values = iter(
            hashlib.sha256(
                canonical_json_bytes(
                    {
                        "binding_sha256": binding_sha256,
                        "index": index,
                        "operation_id": identity.operation_id,
                    }
                )
            ).hexdigest()[:32]
            for index in range(5)
        )
        actions = SimulatorActionService(
            repository=simulator_repository,
            dispatch_source=plans,
            authority_boundary=SimulatorAuthorityBoundary(),
            executor_boundary=executor_boundary,
            publication=publication,
            clock=clock,
            trace_id_factory=trace_values.__next__,
        )
        admission = SimulatorActionCoordinator(
            service=actions,
            executor_boundary=executor_boundary,
            identity_boundary=identity_boundary,
            clock=clock,
        ).admit(
            _principal(
                subject="local-demo-executor",
                role="simulator.executor",
                kind="service",
                config=config,
            ),
            incident_id,
            {
                "schema": "simulator-action-admission-request/v1",
                "task_key": identity.task_key,
                "operation_id": identity.operation_id,
                "payload_sha256": identity.payload_sha256,
            },
        )
        execution_before = _active_publication_state(publication_root)
        primary = actions.execute(identity, owner="local-demo-worker")
        execution_after = _active_publication_state(publication_root)
        replayed = actions.execute(identity, owner="local-demo-worker-replay")
        replay_after = _active_publication_state(publication_root)

        if primary.get("status") != "succeeded":
            raise DemoError("simulator-action-failed")
        if canonical_json_bytes(primary) != canonical_json_bytes(replayed):
            raise DemoError("simulator-replay-outcome-changed")
        if execution_before[1] + 1 != execution_after[1]:
            raise DemoError("simulator-generation-invalid")
        if execution_after != replay_after:
            raise DemoError("simulator-replay-mutated-publication")
        safe_before = primary.get("safe_complement_before_sha256")
        safe_after = primary.get("safe_complement_after_sha256")
        if (
            safe_before != safe_after
            or safe_before != cast(Mapping[str, Any], inputs["envelope"])["safe_complement_sha256"]
        ):
            raise DemoError("safe-frame-equality-failed")
        if cast(Mapping[str, Any], approval["actor"])["kind"] != "human":
            raise DemoError("approval-actor-invalid")
        if cast(Mapping[str, Any], authorization["actor"])["kind"] != "service":
            raise DemoError("dispatcher-actor-invalid")
        if cast(Mapping[str, Any], consumption["actor"])["kind"] != "service":
            raise DemoError("consumer-actor-invalid")
        if cast(Mapping[str, Any], admission["executor_actor"])["kind"] != "service":
            raise DemoError("executor-actor-invalid")

        receipt: dict[str, Any] = {
            "schema": "colortrace-local-demo-receipt/v1",
            "binding": {**exact_binding, "binding_sha256": binding_sha256},
            "fixture": {
                "fixture_id": FIXTURE_ID,
                "seed": config["fixture_seed"],
                "variant": config["fixture_variant"],
            },
            "inspection": {
                "incident_id": incident_id,
                "incident_version": incident_version,
                "recommendation": recommendation,
                "response_packet_sha256": draft["response_packet_sha256"],
                "affected_target_count": len(draft["targets"]),
                "safe_frame_count": len(draft["exclusions"]),
            },
            "authority": {
                "preapproval_dispatch": "rejected",
                "preapproval_reason": preapproval_reason,
                "preapproval_publication_unchanged": True,
                "approval_actor_kind": "human",
                "dispatcher_actor_kind": "service",
                "executor_actor_kind": "service",
                "plan_sha256": created["plan_sha256"],
                "approval_sha256": approval["decision_sha256"],
                "authorization_sha256": authorization["authorization_sha256"],
                "consumption_sha256": consumption["consumption_sha256"],
                "admission_sha256": admission["admission_sha256"],
            },
            "action": {
                "action_count": 1,
                "action_id": primary["action_id"],
                "command_count": len(cast(Sequence[Any], primary["command_outcomes"])),
                "generation_before": execution_before[1],
                "generation_after": execution_after[1],
                "outcome_sha256": primary["outcome_sha256"],
                "status": primary["status"],
            },
            "replay": {
                "same_execution_path": True,
                "identical_outcome": True,
                "generation_unchanged": True,
            },
            "safety": {
                "safe_frame_before_sha256": safe_before,
                "safe_frame_after_sha256": safe_after,
                "safe_frame_digest_equal": True,
            },
        }
        return cast(dict[str, Any], json.loads(canonical_json_bytes(receipt)))
    finally:
        if simulator_repository is not None:
            simulator_repository.close()
        response_repository.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="colortrace-demo")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--approval")
    return parser


def _interactive_approval(
    recommendation: str,
    phrase: str,
    *,
    stdin: TextIO,
    stderr: TextIO,
) -> str:
    stderr.write(f"Recommendation: {recommendation}\n")
    stderr.write(f"Type {phrase} to approve this simulator action: ")
    stderr.flush()
    return stdin.readline().rstrip("\r\n")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    error_stream = sys.stderr if stderr is None else stderr
    arguments = _parser().parse_args(argv)
    provider: ApprovalProvider
    if arguments.approval is None:

        def provider(recommendation: str, phrase: str) -> str:
            return _interactive_approval(
                recommendation,
                phrase,
                stdin=input_stream,
                stderr=error_stream,
            )
    else:

        def provider(_recommendation: str, _phrase: str) -> str:
            return cast(str, arguments.approval)

    try:
        receipt = run_demo(
            config_path=cast(Path, arguments.config),
            workspace=cast(Path, arguments.workspace),
            source_commit=cast(str, arguments.source_commit),
            source_tree=cast(str, arguments.source_tree),
            image_digest=cast(str, arguments.image_digest),
            approval_provider=provider,
        )
    except DemoError as error:
        error_stream.write(f"colortrace-demo: {error.code}\n")
        return 2
    output_stream.write(canonical_json_bytes(receipt).decode("utf-8") + "\n")
    output_stream.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
