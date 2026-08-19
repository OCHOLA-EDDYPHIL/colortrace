from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast

from colortrace_fixture import (  # type: ignore[import-untyped, unused-ignore]
    build_scenario,
    validate_existing,
)
from colortrace_investigation import (  # type: ignore[import-untyped, unused-ignore]
    AlertIntake,
    validate_response_packet,
)
from colortrace_recovery import (  # type: ignore[import-untyped, unused-ignore]
    validate_audit_history as validate_recovery_audit_history,
)
from colortrace_recovery import (
    validate_evidence_record,
    validate_evidence_request,
    validate_recovery_packet,
    validate_verification_snapshot,
)
from colortrace_response_plans import (  # type: ignore[import-untyped, unused-ignore]
    validate_audit_chain as validate_plan_audit_chain,
)
from colortrace_response_plans import (
    validate_decision,
    validate_dispatch_authorization,
    validate_dispatch_consumption,
    validate_plan,
)
from colortrace_simulator.authority import (  # type: ignore[import-untyped, unused-ignore]
    canonical_json_bytes as simulator_canonical_json_bytes,
)
from colortrace_simulator.authority import (
    prefixed_sha256 as simulator_prefixed_sha256,
)
from colortrace_simulator.authority import (
    validate_schema as validate_simulator_schema,
)
from colortrace_telemetry.contract import (  # type: ignore[import-untyped, unused-ignore]
    validate_schema as validate_telemetry_schema,
)
from colortrace_vertical_slice import (  # type: ignore[import-untyped, unused-ignore]
    validate_replay,
)

from .contracts import prefixed_sha256, sha256_file, strict_json_file, validate_schema

PLAN_SCHEMA = "reliability-campaign-plan-v1.schema.json"
RUN_SCHEMA = "reliability-run-record-v1.schema.json"
CONTROL_SCHEMA = "reliability-control-record-v1.schema.json"
REPORT_SCHEMA = "reliability-report-v1.schema.json"
OBSERVATION_SCHEMA = "reliability-run-observation-v1.schema.json"
ACTION_EVIDENCE_SCHEMA = "reliability-action-recovery-evidence-v1.schema.json"
MANUAL_CONTROL_SCHEMA = "manual-no-gemini-observation-v1.schema.json"


class EvaluationError(ValueError):
    pass


def _identifier(value: str, *, code: str) -> str:
    if not value or len(value) > 128 or any(character.isspace() for character in value):
        raise EvaluationError(code)
    return value


def _sealed(body: Mapping[str, Any], *, id_key: str, prefix: str) -> dict[str, Any]:
    digest = prefixed_sha256(body)
    return {**body, id_key: f"{prefix}:{digest.removeprefix('sha256:')}", "sha256": digest}


def _case_rows(seed: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    definitions = (
        ("canonical", 10, "canonical", "resolved", "canonical-repeat"),
        ("hidden", 20, "hidden-permuted", "resolved", "fresh-hidden"),
        ("missing-resource", 8, "hidden-permuted", "unresolved", "missing-resource"),
        ("missing-reference", 6, "hidden-permuted", "unresolved", "missing-reference"),
        ("recovery-failure", 6, "hidden-permuted", "unresolved", "recovery-failure"),
    )
    ordinal = 0
    for family, count, variant, expected, coverage in definitions:
        for sample in range(count):
            case_seed = (
                "ct-shadowed-lut-v1:canonical"
                if family == "canonical"
                else f"ct-evaluation:{seed}:{family}:{sample:02d}"
            )
            identity = f"{family}:{sample:02d}:{case_seed}"
            rows.append(
                {
                    "spec_id": f"eval-{ordinal + 1:02d}",
                    "family": family,
                    "variant": variant,
                    "seed": case_seed,
                    "sample_index": sample + 1,
                    "expected_outcome": expected,
                    "evidence_case": (
                        "missing-resource"
                        if family == "missing-resource"
                        else "missing-reference"
                        if family == "missing-reference"
                        else "complete"
                    ),
                    "recovery_case": (
                        "verification-failure" if family == "recovery-failure" else "success"
                    ),
                    "coverage": [coverage, "model-sampled", "order-randomized"],
                    "order_key": hashlib.sha256(f"{seed}:{identity}".encode()).hexdigest(),
                }
            )
            ordinal += 1
    ordered = sorted(rows, key=lambda row: cast(str, row["order_key"]))
    return [{**row, "execution_order": index} for index, row in enumerate(ordered, start=1)]


def build_campaign_plan(
    *, candidate_commit: str, candidate_tree: str, campaign_seed: str, created_at: str
) -> dict[str, Any]:
    if len(candidate_commit) != 40 or len(candidate_tree) != 40:
        raise EvaluationError("candidate-binding-invalid")
    body = {
        "schema": "reliability-campaign-plan/v1",
        "candidate": {"commit": candidate_commit, "tree": candidate_tree},
        "campaign_seed": _identifier(campaign_seed, code="campaign-seed-invalid"),
        "created_at": created_at,
        "attempt_policy": {"attempts_per_spec": 1, "hidden_retries": False},
        "thresholds": {
            "root_cause_accuracy_numerator": 1,
            "root_cause_accuracy_denominator": 1,
            "affected_precision_numerator": 1,
            "affected_precision_denominator": 1,
            "affected_recall_numerator": 1,
            "affected_recall_denominator": 1,
            "safe_precision_numerator": 1,
            "safe_precision_denominator": 1,
            "safe_recall_numerator": 1,
            "safe_recall_denominator": 1,
            "maximum_trace_correlation_failures": 1,
            "maximum_unsupported_diagnoses": 0,
            "maximum_unauthorized_actions": 0,
            "maximum_duplicate_actions": 0,
        },
        "specs": _case_rows(campaign_seed),
    }
    plan = _sealed(body, id_key="plan_id", prefix="reliability-plan")
    validate_schema(PLAN_SCHEMA, plan)
    return plan


def prepare_fixture(
    *, plan: Mapping[str, Any], spec_id: str, campaign_root: Path
) -> dict[str, Any]:
    _verify_plan(plan)
    spec = next(
        (
            item
            for item in cast(Sequence[Mapping[str, Any]], plan["specs"])
            if item["spec_id"] == spec_id
        ),
        None,
    )
    if spec is None:
        raise EvaluationError("spec-not-in-plan")
    root = campaign_root.resolve()
    run_root = root / "runs" / f"{cast(int, spec['execution_order']):02d}-{spec_id}"
    bundle = run_root / "runtime-bundle"
    oracle = run_root / "offline-oracle"
    telemetry_bundle = bundle
    evidence_case = spec["evidence_case"]
    if evidence_case != "complete":
        telemetry_bundle = run_root / "telemetry-bundle"
        build_scenario(
            telemetry_bundle,
            oracle_root=run_root / "telemetry-offline-oracle",
            variant_id=f"evaluation-{spec_id}",
            seed=cast(str, spec["seed"]),
            permuted=spec["variant"] == "hidden-permuted",
        )
        validate_existing(telemetry_bundle)
    build_scenario(
        bundle,
        oracle_root=oracle,
        variant_id=f"evaluation-{spec_id}",
        seed=cast(str, spec["seed"]),
        permuted=spec["variant"] == "hidden-permuted",
        omit_resource_role="b2" if evidence_case == "missing-resource" else None,
        omit_reference_role="b2" if evidence_case == "missing-reference" else None,
    )
    validate_existing(bundle)
    return {
        "schema": "reliability-fixture-preparation/v1",
        "plan_sha256": plan["sha256"],
        "spec_id": spec_id,
        "execution_order": spec["execution_order"],
        "bundle": bundle.relative_to(root).as_posix(),
        "telemetry_bundle": telemetry_bundle.relative_to(root).as_posix(),
        "oracle": oracle.relative_to(root).as_posix(),
        "artifacts": [
            _artifact_reference(
                bundle / "reports" / "generation-receipt.json",
                root,
            ),
            _artifact_reference(
                bundle / "runtime" / "manifests" / "fixture-runtime-manifest.json",
                root,
            ),
            _artifact_reference(oracle / "fixture-oracle.json", root),
            _artifact_reference(bundle / "reports" / "validator-report.json", root),
            _artifact_reference(bundle / "reports" / "validator-receipt.json", root),
            *(
                [
                    _artifact_reference(
                        telemetry_bundle / "reports" / "generation-receipt.json", root
                    ),
                    _artifact_reference(
                        telemetry_bundle
                        / "runtime"
                        / "manifests"
                        / "fixture-runtime-manifest.json",
                        root,
                    ),
                    _artifact_reference(
                        telemetry_bundle / "reports" / "validator-report.json", root
                    ),
                    _artifact_reference(
                        telemetry_bundle / "reports" / "validator-receipt.json", root
                    ),
                ]
                if telemetry_bundle != bundle
                else []
            ),
        ],
    }


def build_alert(
    *,
    plan: Mapping[str, Any],
    spec_id: str,
    emission_receipt: Mapping[str, Any],
    binding: Mapping[str, str],
) -> dict[str, Any]:
    _verify_plan(plan)
    validate_telemetry_schema("telemetry-emission-receipt-v1.schema.json", emission_receipt)
    if len(cast(Sequence[Any], emission_receipt["runs"])) != 1:
        raise EvaluationError("slot-emission-run-count-invalid")
    spec_ids = {item["spec_id"] for item in cast(Sequence[Mapping[str, Any]], plan["specs"])}
    if spec_id not in spec_ids:
        raise EvaluationError("spec-not-in-plan")
    run = cast(Mapping[str, Any], cast(Sequence[Any], emission_receipt["runs"])[0])
    events = cast(Sequence[Mapping[str, Any]], run["events"])
    mismatch = [
        event
        for event in events
        if cast(Mapping[str, Any], event["observation"])["state"] == "reference_mismatch"
    ]
    if not mismatch:
        raise EvaluationError("slot-emission-lacks-mismatch")
    grouped: dict[tuple[tuple[str, str], ...], list[Mapping[str, Any]]] = defaultdict(list)
    for event in mismatch:
        correlation = cast(Mapping[str, str], event["correlation"])
        alert_correlation = {
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
        }
        grouped[tuple(sorted(alert_correlation.items()))].append(event)
    complete = [
        (identity, values)
        for identity, values in grouped.items()
        if {value["signal"] for value in values} == {"metric", "log", "trace"}
    ]
    if not complete:
        raise EvaluationError("slot-emission-correlation-incomplete")
    identity, selected = min(complete, key=lambda item: item[0])
    started_at = min(cast(str, event["scheduled_at"]) for event in selected)
    retrieved_at = max(cast(str, event["emitted_at"]) for event in selected)
    alert = {
        "schema": "alert-intake/v1",
        "incident_id": f"phase3-{spec_id}",
        "alert_id": f"phase3-{spec_id}-alert",
        "alert_started_at": started_at,
        "retrieved_at": retrieved_at,
        "measured_clock_skew_seconds": 0,
        "binding": dict(binding),
        "correlation_keys": dict(identity),
        "predecessor_event_sha256": None,
    }
    AlertIntake.from_mapping(alert)
    return alert


def derive_investigation_observation(
    *,
    plan: Mapping[str, Any],
    spec_id: str,
    packet: Mapping[str, Any],
    execution: Mapping[str, Any],
    replay: Mapping[str, Any],
) -> dict[str, Any]:
    _verify_plan(plan)
    validate_response_packet(packet)
    validate_schema("reliability-slot-execution-v1.schema.json", execution)
    validate_replay(replay)
    spec = next(
        (
            item
            for item in cast(Sequence[Mapping[str, Any]], plan["specs"])
            if item["spec_id"] == spec_id
        ),
        None,
    )
    if spec is None:
        raise EvaluationError("spec-not-in-plan")
    if spec["recovery_case"] != "success" and packet["status"] != "unresolved":
        raise EvaluationError("recovery-evidence-required")
    if (
        execution["outcome"] != "complete"
        or execution["plan_sha256"] != plan["sha256"]
        or execution["spec_id"] != spec_id
        or execution["candidate"] != plan["candidate"]
        or replay["packet"] != packet
        or replay["alert"]["incident_id"] != packet["incident_id"]
    ):
        raise EvaluationError("investigation-evidence-binding-invalid")
    retries = cast(int, cast(Mapping[str, Any], packet["budget_use"])["trusted_transient_retries"])
    observation = {
        "schema": "reliability-run-observation/v1",
        "plan_sha256": plan["sha256"],
        "spec_id": spec_id,
        "candidate": plan["candidate"],
        "outcome": packet["status"],
        "attempt": 1,
        "retry_count": retries,
        "trace_correlation_failure": False,
        "unsupported_diagnoses": [],
        "unauthorized_actions": 0,
        "duplicate_actions": 0,
        "primary_action_count": 0,
        "replay_action_count": 0,
        "sources": {
            "execution_sha256": prefixed_sha256(execution),
            "replay_sha256": prefixed_sha256(replay),
            "action_evidence_sha256": None,
            "recovery_aggregate_sha256": None,
        },
    }
    validate_schema(OBSERVATION_SCHEMA, observation)
    return observation


def _validate_plan_proof(proof: Mapping[str, Any]) -> None:
    plan = cast(Mapping[str, Any], proof["plan"])
    approval = cast(Mapping[str, Any], proof["approval"])
    authorization = cast(Mapping[str, Any], proof["authorization"])
    consumption = cast(Mapping[str, Any], proof["consumption"])
    validate_plan(plan)
    validate_decision(approval, plan=plan)
    validate_dispatch_authorization(authorization, plan=plan, approval=approval)
    validate_dispatch_consumption(
        consumption,
        authorization=authorization,
        plan=plan,
        approval=approval,
    )
    validate_plan_audit_chain(
        cast(Sequence[Mapping[str, Any]], proof["audit_events"]),
        trusted_head_sha256=cast(str, proof["trusted_audit_head_sha256"]),
        records=cast(Mapping[str, Mapping[str, Any]], proof["records"]),
    )
    body = {key: value for key, value in proof.items() if key != "proof_sha256"}
    if proof["proof_sha256"] != prefixed_sha256(body):
        raise EvaluationError("response-plan-proof-digest-invalid")
    if (
        approval["outcome"] != "approved"
        or consumption["authorization_id"] != (authorization["authorization_id"])
    ):
        raise EvaluationError("response-plan-proof-authority-invalid")


def _validate_simulator_audit(events: Sequence[Mapping[str, Any]], *, action_id: str) -> None:
    if not events:
        raise EvaluationError("simulator-audit-empty")
    predecessor: str | None = None
    for sequence, event in enumerate(events, start=1):
        validate_simulator_schema("simulator-action-audit-event-v1.schema.json", event)
        body = {
            key: value for key, value in event.items() if key not in {"event_id", "event_sha256"}
        }
        digest = simulator_prefixed_sha256(simulator_canonical_json_bytes(body))
        if (
            event["action_id"] != action_id
            or event["sequence"] != sequence
            or event["predecessor_event_sha256"] != predecessor
            or event["event_sha256"] != digest
        ):
            raise EvaluationError("simulator-audit-binding-invalid")
        predecessor = digest


def validate_action_recovery_evidence(
    evidence: Mapping[str, Any], *, plan: Mapping[str, Any], spec_id: str
) -> None:
    _verify_plan(plan)
    validate_schema(ACTION_EVIDENCE_SCHEMA, evidence)
    body = {key: value for key, value in evidence.items() if key not in {"evidence_id", "sha256"}}
    digest = prefixed_sha256(body)
    if evidence["sha256"] != digest or evidence["evidence_id"] != (
        f"reliability-action-recovery:{digest.removeprefix('sha256:')}"
    ):
        raise EvaluationError("action-recovery-evidence-digest-invalid")
    if (
        evidence["plan_sha256"] != plan["sha256"]
        or evidence["spec_id"] != spec_id
        or evidence["candidate"] != plan["candidate"]
    ):
        raise EvaluationError("action-recovery-evidence-binding-invalid")

    _validate_plan_proof(cast(Mapping[str, Any], evidence["response_plan_proof"]))
    simulator = cast(Mapping[str, Any], evidence["simulator"])
    identity = cast(Mapping[str, str], simulator["identity"])
    admission = cast(Mapping[str, Any], simulator["admission"])
    primary = cast(Mapping[str, Any], simulator["primary_outcome"])
    replay = cast(Mapping[str, Any], simulator["replay_outcome"])
    before = cast(Sequence[Mapping[str, Any]], simulator["audit_before_replay"])
    after = cast(Sequence[Mapping[str, Any]], simulator["audit_after_replay"])
    validate_simulator_schema("simulator-action-admission-v1.schema.json", admission)
    validate_simulator_schema("simulator-action-outcome-v1.schema.json", primary)
    validate_simulator_schema("simulator-action-outcome-v1.schema.json", replay)
    action_id = cast(str, primary["action_id"])
    _validate_simulator_audit(before, action_id=action_id)
    _validate_simulator_audit(after, action_id=action_id)
    for key in ("task_key", "operation_id", "payload_sha256"):
        if admission[key] != identity[key] or primary[key] != identity[key]:
            raise EvaluationError("simulator-identity-binding-invalid")
    if (
        primary != replay
        or list(before) != list(after)
        or admission["action_id"] != action_id
        or primary["status"] not in {"succeeded", "failed"}
    ):
        raise EvaluationError("simulator-replay-not-side-effect-free")
    terminal = [
        event for event in after if event["event_type"] in {"action.succeeded", "action.failed"}
    ]
    if len(terminal) != 1:
        raise EvaluationError("simulator-terminal-action-count-invalid")

    aggregate = cast(Mapping[str, Any], evidence["recovery_aggregate"])
    snapshot = validate_verification_snapshot(cast(Mapping[str, Any], aggregate["snapshot"]))
    request = validate_evidence_request(
        cast(Mapping[str, Any], aggregate["evidence_request"]), snapshot=snapshot
    )
    recovery_packet = validate_recovery_packet(
        cast(Mapping[str, Any], aggregate["packet"]),
        snapshot=snapshot,
        evidence_request=request,
    )
    for record in cast(Sequence[Mapping[str, Any]], aggregate["evidence"]):
        validate_evidence_record(record)
    validate_recovery_audit_history(
        cast(Sequence[Mapping[str, Any]], aggregate["audit_events"]),
        workflow_id=cast(str, recovery_packet["workflow_id"]),
    )
    if (
        recovery_packet["outcome_sha256"] != primary["outcome_sha256"]
        or recovery_packet["action_id"] != action_id
        or recovery_packet["status"] not in {"recovery_failed", "recovery_unresolved"}
        or cast(Mapping[str, Any], aggregate["review"])["status"] != recovery_packet["status"]
    ):
        raise EvaluationError("recovery-evidence-binding-invalid")


def derive_recovery_observation(
    *,
    plan: Mapping[str, Any],
    spec_id: str,
    packet: Mapping[str, Any],
    execution: Mapping[str, Any],
    replay: Mapping[str, Any],
    action_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    _verify_plan(plan)
    validate_response_packet(packet)
    validate_schema("reliability-slot-execution-v1.schema.json", execution)
    validate_replay(replay)
    spec = next(
        (
            item
            for item in cast(Sequence[Mapping[str, Any]], plan["specs"])
            if item["spec_id"] == spec_id
        ),
        None,
    )
    if spec is None or spec["recovery_case"] != "verification-failure":
        raise EvaluationError("recovery-spec-required")
    if (
        execution["outcome"] != "complete"
        or execution["plan_sha256"] != plan["sha256"]
        or execution["spec_id"] != spec_id
        or execution["candidate"] != plan["candidate"]
        or replay["packet"] != packet
    ):
        raise EvaluationError("investigation-evidence-binding-invalid")
    validate_action_recovery_evidence(action_evidence, plan=plan, spec_id=spec_id)
    response_plan = cast(
        Mapping[str, Any],
        cast(Mapping[str, Any], action_evidence["response_plan_proof"])["plan"],
    )
    if (
        response_plan["incident_id"] != packet["incident_id"]
        or response_plan["response_packet_sha256"] != packet["derivation_sha256"]
    ):
        raise EvaluationError("action-investigation-packet-binding-invalid")
    simulator = cast(Mapping[str, Any], action_evidence["simulator"])
    events = cast(Sequence[Mapping[str, Any]], simulator["audit_after_replay"])
    admission = cast(Mapping[str, Any], simulator["admission"])
    executor = cast(Mapping[str, Any], admission["executor_actor"])
    terminal_count = sum(
        event["event_type"] in {"action.succeeded", "action.failed"} for event in events
    )
    retries = cast(int, cast(Mapping[str, Any], packet["budget_use"])["trusted_transient_retries"])
    aggregate = cast(Mapping[str, Any], action_evidence["recovery_aggregate"])
    observation = {
        "schema": "reliability-run-observation/v1",
        "plan_sha256": plan["sha256"],
        "spec_id": spec_id,
        "candidate": plan["candidate"],
        "outcome": "unresolved",
        "attempt": 1,
        "retry_count": retries,
        "trace_correlation_failure": False,
        "unsupported_diagnoses": [],
        "unauthorized_actions": 0 if executor["kind"] == "service" else 1,
        "duplicate_actions": max(0, terminal_count - 1),
        "primary_action_count": terminal_count,
        "replay_action_count": 0,
        "sources": {
            "execution_sha256": prefixed_sha256(execution),
            "replay_sha256": prefixed_sha256(replay),
            "action_evidence_sha256": action_evidence["sha256"],
            "recovery_aggregate_sha256": prefixed_sha256(aggregate),
        },
    }
    validate_schema(OBSERVATION_SCHEMA, observation)
    return observation


def _verify_plan(plan: Mapping[str, Any]) -> None:
    validate_schema(PLAN_SCHEMA, plan)
    body = {key: value for key, value in plan.items() if key not in {"plan_id", "sha256"}}
    digest = prefixed_sha256(body)
    if plan["sha256"] != digest or plan["plan_id"] != (
        f"reliability-plan:{digest.removeprefix('sha256:')}"
    ):
        raise EvaluationError("plan-digest-invalid")
    specs = cast(Sequence[Mapping[str, Any]], plan["specs"])
    if (
        len({item["spec_id"] for item in specs}) != 50
        or {item["execution_order"] for item in specs} != set(range(1, 51))
        or list(specs) != _case_rows(cast(str, plan["campaign_seed"]))
    ):
        raise EvaluationError("plan-spec-set-invalid")


def _artifact_reference(path: Path, root: Path) -> dict[str, str]:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    try:
        relative = resolved.relative_to(resolved_root)
    except ValueError as error:
        raise EvaluationError("artifact-outside-run-root") from error
    logical = PurePosixPath(relative.as_posix())
    if not logical.parts or any(part in {"", ".", ".."} for part in logical.parts):
        raise EvaluationError("artifact-path-invalid")
    return {"path": logical.as_posix(), "sha256": sha256_file(resolved)}


def _scope_set(packet: Mapping[str, Any], key: str) -> set[tuple[str, str]]:
    scope = cast(Mapping[str, Any], packet["scope"])
    return {
        (cast(str, item["kind"]), cast(str, item["id"]))
        for item in cast(Sequence[Mapping[str, Any]], scope[key])
    }


def _fraction(correct: int, total: int) -> dict[str, int]:
    return {"numerator": correct, "denominator": total}


def _classification_metrics(
    observed: set[Any], expected: set[Any]
) -> tuple[dict[str, int], dict[str, int]]:
    matches = len(observed & expected)
    return _fraction(matches, len(observed)), _fraction(matches, len(expected))


def _causal_value(packet: Mapping[str, Any]) -> str | None:
    values = {
        cast(str, cast(Mapping[str, Any], claim["subject"])["value"])
        for claim in cast(Sequence[Mapping[str, Any]], packet["claims"])
        if claim.get("claim_type") == "causal-resource" and claim.get("state") == "confirmed"
    }
    return next(iter(values)) if len(values) == 1 else None


def _unsupported_diagnoses(packet: Mapping[str, Any], causal_expected: str) -> set[str]:
    unsupported: set[str] = set()
    for claim in cast(Sequence[Mapping[str, Any]], packet["claims"]):
        if claim.get("state") != "confirmed":
            continue
        claim_type = cast(str, claim.get("claim_type"))
        subject = cast(Mapping[str, Any], claim.get("subject", {}))
        if claim_type == "causal-resource":
            if subject.get("value") != causal_expected:
                unsupported.add(f"causal-resource:{subject.get('value')}")
        elif claim_type in {"nominal-config", "worker-alone", "distractor"}:
            unsupported.add(claim_type)
    return unsupported


def _structured_facts(packet: Mapping[str, Any]) -> str:
    facts = {
        "claims": [
            {
                key: claim[key]
                for key in ("claim_type", "subject", "state", "policy", "reason_codes")
            }
            for claim in cast(Sequence[Mapping[str, Any]], packet["claims"])
            if claim["state"] in {"confirmed", "rejected"}
        ],
        "scope": packet["scope"],
    }
    return prefixed_sha256(facts)


def build_run_record(
    *,
    plan: Mapping[str, Any],
    spec_id: str,
    packet: Mapping[str, Any],
    oracle: Mapping[str, Any],
    observation: Mapping[str, Any],
    run_root: Path,
    packet_path: Path,
    oracle_path: Path,
    observation_path: Path,
    action_evidence_path: Path | None,
    artifact_paths: Sequence[Path],
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    _verify_plan(plan)
    validate_response_packet(packet)
    validate_schema(OBSERVATION_SCHEMA, observation)
    specs = {item["spec_id"]: item for item in cast(Sequence[Mapping[str, Any]], plan["specs"])}
    if spec_id not in specs:
        raise EvaluationError("spec-not-in-plan")
    spec = specs[spec_id]
    if (
        observation["plan_sha256"] != plan["sha256"]
        or observation["spec_id"] != spec_id
        or observation["candidate"] != plan["candidate"]
    ):
        raise EvaluationError("observation-binding-invalid")
    sources = cast(Mapping[str, Any], observation["sources"])
    recovery_case = spec["recovery_case"] == "verification-failure"
    unresolved_without_action = recovery_case and (
        packet["status"] == "unresolved"
        and sources["action_evidence_sha256"] is None
        and sources["recovery_aggregate_sha256"] is None
        and action_evidence_path is None
        and observation["primary_action_count"] == 0
        and observation["replay_action_count"] == 0
        and observation["unauthorized_actions"] == 0
        and observation["duplicate_actions"] == 0
    )
    if (
        recovery_case
        and not unresolved_without_action
        and (
            sources["action_evidence_sha256"] is None
            or sources["recovery_aggregate_sha256"] is None
        )
    ):
        raise EvaluationError("recovery-evidence-required")
    action_evidence: Mapping[str, Any] | None = None
    if action_evidence_path is not None:
        action_evidence = strict_json_file(action_evidence_path.resolve(strict=True))
        validate_action_recovery_evidence(action_evidence, plan=plan, spec_id=spec_id)
        if action_evidence["sha256"] != sources["action_evidence_sha256"]:
            raise EvaluationError("action-evidence-observation-mismatch")
    if recovery_case and not unresolved_without_action and action_evidence is None:
        raise EvaluationError("recovery-evidence-required")
    if spec["recovery_case"] == "success" and action_evidence is not None:
        raise EvaluationError("unexpected-action-evidence")
    expected_outcome = spec["expected_outcome"]
    observed_outcome = observation.get("outcome")
    if observed_outcome not in {"resolved", "unresolved", "recovery-failed"}:
        raise EvaluationError("outcome-invalid")
    if observation.get("attempt") != 1:
        raise EvaluationError("attempt-policy-violated")
    for path, value in (
        (packet_path, packet),
        (oracle_path, oracle),
        (observation_path, observation),
    ):
        if strict_json_file(path.resolve(strict=True)) != value:
            raise EvaluationError("source-artifact-content-mismatch")
    recorded_retries = cast(Mapping[str, Any], packet["budget_use"])["trusted_transient_retries"]
    if observation.get("retry_count") != recorded_retries:
        raise EvaluationError("retry-observation-mismatch")
    causal_expected = cast(str, oracle["causal_resource_sha256"])
    causal_observed = _causal_value(packet)
    expected_affected = {
        *(("frame", item) for item in cast(Sequence[str], oracle["directly_affected_jobs"])),
        *(("derivative", item) for item in cast(Sequence[str], oracle["affected_derivatives"])),
    }
    expected_safe = {("frame", item) for item in cast(Sequence[str], oracle["safe_jobs"])}
    observed_affected = _scope_set(packet, "affected")
    observed_safe = _scope_set(packet, "safe")
    affected_precision, affected_recall = _classification_metrics(
        observed_affected, expected_affected
    )
    safe_precision, safe_recall = _classification_metrics(observed_safe, expected_safe)
    diagnosis_values = observation.get("unsupported_diagnoses")
    if not isinstance(diagnosis_values, list) or any(
        not isinstance(item, str) for item in diagnosis_values
    ):
        raise EvaluationError("unsupported-diagnosis-observation-invalid")
    artifacts = sorted(
        (_artifact_reference(path, run_root) for path in artifact_paths),
        key=lambda item: item["path"],
    )
    if len({item["path"] for item in artifacts}) != len(artifacts) or not artifacts:
        raise EvaluationError("artifact-set-invalid")
    unsupported_diagnoses = _unsupported_diagnoses(packet, causal_expected) | set(
        cast(list[str], diagnosis_values)
    )
    body = {
        "schema": "reliability-run-record/v1",
        "plan_sha256": plan["sha256"],
        "spec_id": spec_id,
        "execution_order": spec["execution_order"],
        "candidate": plan["candidate"],
        "attempt": 1,
        "retry_count": recorded_retries,
        "started_at": started_at,
        "finished_at": finished_at,
        "expected_outcome": expected_outcome,
        "observed_outcome": observed_outcome,
        "outcome_matches": observed_outcome == expected_outcome,
        "metrics": {
            "root_cause": {
                "expected": causal_expected,
                "observed": causal_observed,
                "correct": causal_observed == causal_expected,
            },
            "affected_precision": affected_precision,
            "affected_recall": affected_recall,
            "safe_precision": safe_precision,
            "safe_recall": safe_recall,
            "trace_correlation_failure": observation.get("trace_correlation_failure"),
            "unsupported_diagnoses": sorted(unsupported_diagnoses),
            "unauthorized_actions": observation.get("unauthorized_actions"),
            "duplicate_actions": observation.get("duplicate_actions"),
            "primary_action_count": observation.get("primary_action_count"),
            "replay_action_count": observation.get("replay_action_count"),
            "confirmed_facts_sha256": _structured_facts(packet),
        },
        "packet_sha256": prefixed_sha256(packet),
        "oracle_sha256": prefixed_sha256(oracle),
        "observation_sha256": prefixed_sha256(observation),
        "action_evidence_sha256": (
            None if action_evidence is None else prefixed_sha256(action_evidence)
        ),
        "source_artifacts": {
            "packet": _artifact_reference(packet_path, run_root),
            "oracle": _artifact_reference(oracle_path, run_root),
            "observation": _artifact_reference(observation_path, run_root),
            "action_evidence": (
                None
                if action_evidence_path is None
                else _artifact_reference(action_evidence_path, run_root)
            ),
        },
        "artifacts": artifacts,
    }
    record = _sealed(body, id_key="record_id", prefix="reliability-run")
    validate_schema(RUN_SCHEMA, record)
    return record


def _elapsed_milliseconds(started_at: str, finished_at: str) -> int:
    try:
        started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        finished = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvaluationError("control-time-invalid") from error
    if started.tzinfo is None or finished.tzinfo is None or finished < started:
        raise EvaluationError("control-time-invalid")
    elapsed = finished - started
    return elapsed.days * 86_400_000 + elapsed.seconds * 1_000 + elapsed.microseconds // 1_000


def _seal_control(body: Mapping[str, Any]) -> dict[str, Any]:
    digest = prefixed_sha256(body)
    control = {
        **body,
        "control_id": f"reliability-control:{digest.removeprefix('sha256:')}",
        "sha256": digest,
    }
    verify_control_record(control)
    return control


def build_no_grafana_control(
    *,
    plan: Mapping[str, Any],
    observation: Mapping[str, Any],
    observation_path: Path,
    artifact_root: Path,
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    _verify_plan(plan)
    validate_telemetry_schema("no-grafana-observation-v1.schema.json", observation)
    if strict_json_file(observation_path.resolve(strict=True)) != observation:
        raise EvaluationError("control-source-artifact-content-mismatch")
    body = {
        "schema": "reliability-control-record/v1",
        "kind": "no-grafana",
        "candidate": plan["candidate"],
        "operator_kind": "automation-assisted",
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_ms": _elapsed_milliseconds(started_at, finished_at),
        "outcome": observation["outcome"],
        "quality": {
            "root_cause_correct": False,
            "affected_scope_exact": False,
            "safe_scope_exact": False,
            "decisive_operational_facts": len(
                cast(Sequence[Any], observation["decisive_operational_facts"])
            ),
        },
        "provider_calls": {"vertex": 0, "grafana": 0},
        "limitations": [
            "The isolated no-Grafana counterfactual proves fail-closed unavailability; "
            "it does not measure human diagnosis time."
        ],
        "artifacts": [_artifact_reference(observation_path, artifact_root)],
    }
    return _seal_control(body)


def _target_set(values: Sequence[Mapping[str, Any]]) -> set[tuple[str, str]]:
    return {(cast(str, value["kind"]), cast(str, value["id"])) for value in values}


def build_manual_no_gemini_control(
    *,
    plan: Mapping[str, Any],
    observation: Mapping[str, Any],
    observation_path: Path,
    artifact_root: Path,
) -> dict[str, Any]:
    _verify_plan(plan)
    validate_schema(MANUAL_CONTROL_SCHEMA, observation)
    if strict_json_file(observation_path.resolve(strict=True)) != observation:
        raise EvaluationError("control-source-artifact-content-mismatch")
    if observation["candidate"] != plan["candidate"]:
        raise EvaluationError("control-candidate-binding-invalid")
    expected = cast(Mapping[str, Any], observation["expected"])
    observed = cast(Mapping[str, Any], observation["observed"])
    root_correct = observed["causal_resource_sha256"] == expected["causal_resource_sha256"]
    affected_exact = _target_set(
        cast(Sequence[Mapping[str, Any]], observed["affected"])
    ) == _target_set(cast(Sequence[Mapping[str, Any]], expected["affected"]))
    safe_exact = _target_set(cast(Sequence[Mapping[str, Any]], observed["safe"])) == _target_set(
        cast(Sequence[Mapping[str, Any]], expected["safe"])
    )
    decisive = cast(Sequence[Any], observation["decisive_operational_facts"])
    outcome = "resolved" if root_correct and affected_exact and safe_exact else "unresolved"
    body = {
        "schema": "reliability-control-record/v1",
        "kind": "manual-no-gemini",
        "candidate": plan["candidate"],
        "operator_kind": "human",
        "started_at": observation["started_at"],
        "finished_at": observation["finished_at"],
        "elapsed_ms": _elapsed_milliseconds(
            cast(str, observation["started_at"]), cast(str, observation["finished_at"])
        ),
        "outcome": outcome,
        "quality": {
            "root_cause_correct": root_correct,
            "affected_scope_exact": affected_exact,
            "safe_scope_exact": safe_exact,
            "decisive_operational_facts": len(decisive),
        },
        "provider_calls": {
            "vertex": 0,
            "grafana": cast(int, observation["grafana_read_calls"]),
        },
        "limitations": observation["limitations"],
        "artifacts": [_artifact_reference(observation_path, artifact_root)],
    }
    return _seal_control(body)


def verify_control_record(control: Mapping[str, Any]) -> None:
    validate_schema(CONTROL_SCHEMA, control)
    body = {key: value for key, value in control.items() if key not in {"control_id", "sha256"}}
    digest = prefixed_sha256(body)
    if control["sha256"] != digest or control["control_id"] != (
        f"reliability-control:{digest.removeprefix('sha256:')}"
    ):
        raise EvaluationError("control-digest-invalid")
    calls = cast(Mapping[str, int], control["provider_calls"])
    if calls["vertex"] != 0:
        raise EvaluationError("control-vertex-call-prohibited")
    if control["kind"] == "no-grafana" and (
        calls["grafana"] != 0
        or control["outcome"] != "unavailable"
        or control["quality"]["decisive_operational_facts"] != 0
    ):
        raise EvaluationError("no-grafana-control-invalid")


def _exact(value: Mapping[str, Any]) -> bool:
    return value.get("numerator") == value.get("denominator") and value.get("denominator", 0) > 0


def _verify_record(record: Mapping[str, Any], plan: Mapping[str, Any]) -> None:
    validate_schema(RUN_SCHEMA, record)
    body = {key: value for key, value in record.items() if key not in {"record_id", "sha256"}}
    digest = prefixed_sha256(body)
    if record["sha256"] != digest or record["record_id"] != (
        f"reliability-run:{digest.removeprefix('sha256:')}"
    ):
        raise EvaluationError("record-digest-invalid")
    if record["plan_sha256"] != plan["sha256"] or record["candidate"] != plan["candidate"]:
        raise EvaluationError("record-binding-invalid")


def _verify_artifact_set(references: Sequence[Mapping[str, Any]], root: Path) -> None:
    resolved_root = root.resolve(strict=True)
    if not references:
        raise EvaluationError("artifact-set-invalid")
    for reference in references:
        logical = PurePosixPath(cast(str, reference["path"]))
        if logical.is_absolute() or any(part in {"", ".", ".."} for part in logical.parts):
            raise EvaluationError("artifact-path-invalid")
        path = resolved_root.joinpath(*logical.parts)
        if path.is_symlink():
            raise EvaluationError("artifact-symlink-prohibited")
        resolved = path.resolve(strict=True)
        try:
            resolved.relative_to(resolved_root)
        except ValueError as error:
            raise EvaluationError("artifact-outside-root") from error
        if sha256_file(resolved) != reference["sha256"]:
            raise EvaluationError("artifact-digest-invalid")


def _resolve_artifact(reference: Mapping[str, Any], root: Path) -> Path:
    logical = PurePosixPath(cast(str, reference["path"]))
    return root.resolve(strict=True).joinpath(*logical.parts).resolve(strict=True)


def _verify_record_sources(record: Mapping[str, Any], root: Path) -> None:
    sources = cast(Mapping[str, Mapping[str, Any] | None], record["source_artifacts"])
    for key in ("packet", "oracle", "observation"):
        reference = sources[key]
        if reference is None:
            raise EvaluationError(f"{key}-artifact-missing")
        value = strict_json_file(_resolve_artifact(reference, root))
        if prefixed_sha256(value) != record[f"{key}_sha256"]:
            raise EvaluationError(f"{key}-semantic-digest-invalid")
    action_reference = sources["action_evidence"]
    if action_reference is None:
        if record["action_evidence_sha256"] is not None:
            raise EvaluationError("action-evidence-semantic-digest-invalid")
    else:
        value = strict_json_file(_resolve_artifact(action_reference, root))
        if prefixed_sha256(value) != record["action_evidence_sha256"]:
            raise EvaluationError("action-evidence-semantic-digest-invalid")


def aggregate_campaign(
    *,
    plan: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    controls: Sequence[Mapping[str, Any]],
    artifact_root: Path,
) -> dict[str, Any]:
    _verify_plan(plan)
    for record in records:
        _verify_record(record, plan)
        _verify_artifact_set(cast(Sequence[Mapping[str, Any]], record["artifacts"]), artifact_root)
        _verify_artifact_set(
            [
                item
                for item in cast(
                    Mapping[str, Mapping[str, Any] | None], record["source_artifacts"]
                ).values()
                if item is not None
            ],
            artifact_root,
        )
        _verify_record_sources(record, artifact_root)
    for control in controls:
        verify_control_record(control)
        if control["candidate"] != plan["candidate"]:
            raise EvaluationError("control-candidate-binding-invalid")
        _verify_artifact_set(cast(Sequence[Mapping[str, Any]], control["artifacts"]), artifact_root)
    expected_specs = {item["spec_id"] for item in cast(Sequence[Mapping[str, Any]], plan["specs"])}
    observed_specs = [cast(str, record["spec_id"]) for record in records]
    if (
        len(records) != 50
        or set(observed_specs) != expected_specs
        or len(set(observed_specs)) != 50
    ):
        raise EvaluationError("campaign-record-set-incomplete")
    if {control["kind"] for control in controls} != {"manual-no-gemini", "no-grafana"}:
        raise EvaluationError("control-set-incomplete")
    metrics = [cast(Mapping[str, Any], record["metrics"]) for record in records]
    thresholds = cast(Mapping[str, Any], plan["thresholds"])
    trace_failures = sum(item["trace_correlation_failure"] is True for item in metrics)
    unsupported = sum(len(cast(Sequence[Any], item["unsupported_diagnoses"])) for item in metrics)
    unauthorized = sum(cast(int, item["unauthorized_actions"]) for item in metrics)
    duplicates = sum(cast(int, item["duplicate_actions"]) for item in metrics)
    transparent_retries = sum(cast(int, record["retry_count"]) for record in records)
    resolved = [record for record in records if record["expected_outcome"] == "resolved"]
    exact_scope = all(
        _exact(cast(Mapping[str, Any], metric[name]))
        for record in resolved
        for metric in [cast(Mapping[str, Any], record["metrics"])]
        for name in ("affected_precision", "affected_recall", "safe_precision", "safe_recall")
    )
    exact_root = all(
        cast(Mapping[str, Any], record["metrics"])["root_cause"]["correct"] for record in resolved
    )
    stable: dict[str, set[str]] = defaultdict(set)
    for record in records:
        family = next(
            item["family"]
            for item in cast(Sequence[Mapping[str, Any]], plan["specs"])
            if item["spec_id"] == record["spec_id"]
        )
        if family == "canonical":
            stable[cast(str, family)].add(cast(str, record["metrics"]["confirmed_facts_sha256"]))
    facts_stable = (
        stable == {"canonical": next(iter(stable.values()))} and len(stable["canonical"]) == 1
    )
    outcomes_match = all(record["outcome_matches"] is True for record in records)
    no_action_violations = all(
        metric["primary_action_count"] in {0, 1} and metric["replay_action_count"] == 0
        for metric in metrics
    )
    checks = {
        "root_cause_exact": exact_root,
        "affected_and_safe_scope_exact": exact_scope,
        "trace_correlation_within_limit": trace_failures
        <= thresholds["maximum_trace_correlation_failures"],
        "unsupported_diagnoses_zero": unsupported == thresholds["maximum_unsupported_diagnoses"],
        "unauthorized_actions_zero": unauthorized == thresholds["maximum_unauthorized_actions"],
        "duplicate_actions_zero": duplicates == thresholds["maximum_duplicate_actions"],
        "replay_side_effects_zero": no_action_violations,
        "confirmed_facts_stable": facts_stable,
        "expected_outcomes_match": outcomes_match,
        "controls_complete": True,
        "every_run_inspectable": all(record["artifacts"] for record in records),
    }
    body = {
        "schema": "reliability-report/v1",
        "plan_sha256": plan["sha256"],
        "candidate": plan["candidate"],
        "run_count": len(records),
        "family_counts": dict(
            sorted(Counter(record["expected_outcome"] for record in records).items())
        ),
        "observations": {
            "trace_correlation_failures": trace_failures,
            "unsupported_diagnoses": unsupported,
            "unauthorized_actions": unauthorized,
            "duplicate_actions": duplicates,
            "transparent_transient_retries": transparent_retries,
        },
        "checks": checks,
        "control_sha256s": sorted(cast(str, control["sha256"]) for control in controls),
        "record_sha256s": sorted(cast(str, record["sha256"]) for record in records),
        "pass": all(checks.values()),
    }
    report = _sealed(body, id_key="report_id", prefix="reliability-report")
    validate_schema(REPORT_SCHEMA, report)
    return report


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
