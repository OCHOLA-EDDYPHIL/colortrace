"""Strict telemetry projection of immutable terminal simulator actions."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from colortrace_telemetry.contract import canonical_json_bytes, sha256_bytes, validate_schema

ACTION_OUTCOME_VERSION = "simulator-action-outcome/v1"
ACTION_CORRELATION_VERSION = "simulator-action-correlation/v1"
ACTION_PUBLICATION_VERSION = "simulator-action-publication-binding/v1"
ACTION_EVENT_VERSION = "simulator-action-telemetry-event/v1"
ACTION_RECEIPT_VERSION = "simulator-action-telemetry-receipt/v1"
COMMAND_OBSERVATION_VERSION = "simulator-command-observation/v1"
SAFE_OBSERVATION_VERSION = "simulator-safe-preservation-observation/v1"
FAILURE_OBSERVATION_VERSION = "simulator-action-failure-observation/v1"

COMMAND_SIGNALS = ("metric", "log", "trace")
NON_TRACE_SIGNALS = ("metric", "log")

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_REASON_CODE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_TASK_KEY = re.compile(r"^dispatch-task:[0-9a-f]{64}$")
_OPERATION_ID = re.compile(r"^dispatch-operation:[0-9a-f]{64}$")

_OUTCOME_KEYS = frozenset(
    {
        "schema",
        "outcome_id",
        "outcome_sha256",
        "admission_id",
        "admission_sha256",
        "action_id",
        "task_key",
        "operation_id",
        "payload_sha256",
        "status",
        "reason_codes",
        "fixture_id",
        "incident_id",
        "incident_version",
        "plan_id",
        "plan_version",
        "plan_sha256",
        "approval_id",
        "approval_sha256",
        "authorization_id",
        "authorization_sha256",
        "consumption_id",
        "consumption_sha256",
        "dispatch_bundle_sha256",
        "action_envelope_sha256",
        "action_started_at",
        "publication_intent_id",
        "publication_intent_sha256",
        "publication_receipt_id",
        "publication_receipt_sha256",
        "publication_promoted_at",
        "completed_at",
        "predecessor_publication_pointer_sha256",
        "predecessor_publication_generation",
        "candidate_publication_pointer_sha256",
        "candidate_publication_generation",
        "source_generation",
        "candidate_generation",
        "source_batch_id",
        "source_batch_sha256",
        "candidate_fixture_manifest_sha256",
        "candidate_runtime_manifest_sha256",
        "candidate_lineage_manifest_sha256",
        "declared_resource_manifest_sha256",
        "active_publication_pointer_sha256",
        "active_runtime_manifest_sha256",
        "preservation_manifest_sha256",
        "safe_complement_before_sha256",
        "safe_complement_after_sha256",
        "safe_complement_proof_sha256",
        "candidate_seal_sha256",
        "candidate_tree_sha256",
        "targets",
        "exclusions",
        "command_outcomes",
        "new_trace_ids",
    }
)

_REQUIRED_IDENTIFIERS = (
    "admission_id",
    "action_id",
    "incident_id",
    "plan_id",
    "approval_id",
    "authorization_id",
    "consumption_id",
)
_REQUIRED_DIGESTS = (
    "outcome_sha256",
    "admission_sha256",
    "payload_sha256",
    "plan_sha256",
    "approval_sha256",
    "authorization_sha256",
    "consumption_sha256",
    "dispatch_bundle_sha256",
    "action_envelope_sha256",
)
_ACTIVE_PUBLICATION_DIGESTS = (
    "predecessor_publication_pointer_sha256",
    "candidate_publication_pointer_sha256",
    "source_batch_sha256",
    "candidate_fixture_manifest_sha256",
    "candidate_runtime_manifest_sha256",
    "candidate_lineage_manifest_sha256",
    "declared_resource_manifest_sha256",
    "active_publication_pointer_sha256",
    "active_runtime_manifest_sha256",
    "preservation_manifest_sha256",
    "safe_complement_before_sha256",
    "safe_complement_after_sha256",
    "safe_complement_proof_sha256",
    "candidate_seal_sha256",
    "candidate_tree_sha256",
)


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("action telemetry keys must be strings")
            result[key] = _plain_json(child)
        return result
    if isinstance(value, (list, tuple)):
        return [_plain_json(child) for child in value]
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise ValueError("action telemetry values must be canonical JSON")


def _mapping(value: Any, *, label: str) -> dict[str, Any]:
    selected = _plain_json(value)
    if not isinstance(selected, dict):
        raise ValueError(f"{label} must be an object")
    return selected


def _exact(value: Mapping[str, Any], keys: frozenset[str], *, label: str) -> None:
    if set(value) != keys:
        raise ValueError(f"{label} fields are invalid")


def _identifier(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _digest(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _trace_id(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _TRACE_ID.fullmatch(value) is None or value == "0" * 32:
        raise ValueError(f"{label} is invalid")
    return value


def _positive_integer(value: Any, *, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"{label} is invalid")
    return value


def parse_action_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise ValueError(f"{label} is invalid")
    try:
        selected = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise ValueError(f"{label} is invalid") from None
    if selected.tzinfo is None or selected.utcoffset() != timedelta(0):
        raise ValueError(f"{label} is invalid")
    return selected.astimezone(UTC)


def _target(value: Any) -> dict[str, Any]:
    selected = _mapping(value, label="simulator target")
    validate_schema("simulator-action-target-v1.schema.json", selected)
    return selected


def _target_key(value: Mapping[str, Any]) -> tuple[str, str, str]:
    return cast(str, value["namespace"]), cast(str, value["kind"]), cast(str, value["id"])


def _ordered_targets(value: Any, *, label: str, minimum: int) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= 64:
        raise ValueError(f"{label} count is invalid")
    selected = tuple(_target(child) for child in value)
    identities = tuple(_target_key(child) for child in selected)
    if tuple(sorted(identities)) != identities or len(set(identities)) != len(identities):
        raise ValueError(f"{label} must be sorted and unique")
    return selected


def _command_result(value: Any) -> dict[str, Any]:
    selected = _mapping(value, label="simulator command result")
    validate_schema(
        "simulator-command-observation-v1.schema.json",
        {
            "schema": COMMAND_OBSERVATION_VERSION,
            "scope": "affected",
            "result": selected,
        },
    )
    return selected


def _optional_binding(
    value: Mapping[str, Any], identifier_name: str, digest_name: str
) -> tuple[str | None, str | None]:
    identifier = value[identifier_name]
    digest = value[digest_name]
    if identifier is None and digest is None:
        return None, None
    if identifier is None or digest is None:
        raise ValueError(f"{identifier_name} binding is incomplete")
    return (
        _identifier(identifier, label=identifier_name),
        _digest(digest, label=digest_name),
    )


@dataclass(frozen=True, slots=True)
class ValidatedActionOutcome:
    document: dict[str, Any]
    targets: tuple[dict[str, Any], ...]
    exclusions: tuple[dict[str, Any], ...]
    command_outcomes: tuple[dict[str, Any], ...]
    action_started_at: datetime
    completed_at: datetime
    publication_promoted_at: datetime | None


def validate_action_outcome(value: Mapping[str, Any]) -> ValidatedActionOutcome:
    outcome = _mapping(value, label="simulator action outcome")
    _exact(outcome, _OUTCOME_KEYS, label="simulator action outcome")
    if outcome["schema"] != ACTION_OUTCOME_VERSION:
        raise ValueError("simulator action outcome schema is invalid")

    for name in _REQUIRED_IDENTIFIERS:
        _identifier(outcome[name], label=name)
    for name in _REQUIRED_DIGESTS:
        _digest(outcome[name], label=name)
    _positive_integer(outcome["plan_version"], label="plan_version")
    _positive_integer(outcome["incident_version"], label="incident_version")
    if not isinstance(outcome["task_key"], str) or _TASK_KEY.fullmatch(outcome["task_key"]) is None:
        raise ValueError("task_key is invalid")
    if (
        not isinstance(outcome["operation_id"], str)
        or _OPERATION_ID.fullmatch(outcome["operation_id"]) is None
    ):
        raise ValueError("operation_id is invalid")

    _optional_binding(outcome, "publication_intent_id", "publication_intent_sha256")
    _optional_binding(outcome, "publication_receipt_id", "publication_receipt_sha256")

    status = outcome["status"]
    if status not in {"succeeded", "failed"}:
        raise ValueError("simulator action status is invalid")
    reasons = outcome["reason_codes"]
    if not isinstance(reasons, list) or len(reasons) > 32:
        raise ValueError("action reason codes are invalid")
    if any(not isinstance(code, str) or _REASON_CODE.fullmatch(code) is None for code in reasons):
        raise ValueError("action reason codes are invalid")
    if reasons != sorted(set(reasons)):
        raise ValueError("action reason codes must be sorted and unique")
    if (status == "succeeded" and reasons) or (status == "failed" and not reasons):
        raise ValueError("action status and reason codes conflict")

    started_at = parse_action_timestamp(outcome["action_started_at"], label="action_started_at")
    completed_at = parse_action_timestamp(outcome["completed_at"], label="completed_at")
    if completed_at < started_at:
        raise ValueError("action timestamps are out of order")

    targets = _ordered_targets(outcome["targets"], label="action targets", minimum=5)
    if len(targets) != 5:
        raise ValueError("successful action contract requires exactly five targets")
    exclusions = _ordered_targets(outcome["exclusions"], label="action exclusions", minimum=1)
    target_identities = {_target_key(target) for target in targets}
    exclusion_identities = {_target_key(target) for target in exclusions}
    if target_identities & exclusion_identities:
        raise ValueError("action targets and exclusions overlap")

    command_values = outcome["command_outcomes"]
    trace_values = outcome["new_trace_ids"]
    if not isinstance(command_values, list) or not isinstance(trace_values, list):
        raise ValueError("action result collections are invalid")
    commands = tuple(_command_result(child) for child in command_values)
    command_ids = tuple(cast(str, child["command_id"]) for child in commands)
    command_targets = {_target_key(cast(Mapping[str, Any], child["target"])) for child in commands}
    traces = tuple(_trace_id(child, label="new_trace_id") for child in trace_values)

    promoted_value = outcome["publication_promoted_at"]
    promoted_at: datetime | None = None
    if status == "succeeded":
        if len(commands) != 5 or command_ids != tuple(sorted(set(command_ids))):
            raise ValueError("successful command results must be five sorted unique records")
        if Counter(child["result_kind"] for child in commands) != Counter(
            {"quarantine": 1, "frame": 3, "derivative": 1}
        ):
            raise ValueError("successful command result kinds are invalid")
        if command_targets != target_identities:
            raise ValueError("command result targets differ from approved targets")
        result_traces = tuple(sorted(cast(str, child["trace_id"]) for child in commands))
        if traces != result_traces or len(set(traces)) != 5:
            raise ValueError("new trace IDs differ from command results")
        if reasons:
            raise ValueError("successful action cannot carry failure reasons")
        _identifier(outcome["fixture_id"], label="fixture_id")
        if outcome["publication_intent_id"] is None or outcome["publication_receipt_id"] is None:
            raise ValueError("successful action lacks publication authority")
        source_generation = _positive_integer(
            outcome["source_generation"], label="source_generation"
        )
        candidate_generation = _positive_integer(
            outcome["candidate_generation"], label="candidate_generation"
        )
        predecessor_generation = _positive_integer(
            outcome["predecessor_publication_generation"],
            label="predecessor_publication_generation",
        )
        candidate_publication_generation = _positive_integer(
            outcome["candidate_publication_generation"],
            label="candidate_publication_generation",
        )
        _identifier(outcome["source_batch_id"], label="source_batch_id")
        if (
            source_generation != predecessor_generation
            or candidate_generation != candidate_publication_generation
            or candidate_generation <= source_generation
        ):
            raise ValueError("candidate generation does not advance source generation")
        for name in _ACTIVE_PUBLICATION_DIGESTS:
            _digest(outcome[name], label=name)
        if outcome["safe_complement_before_sha256"] != outcome["safe_complement_after_sha256"]:
            raise ValueError("safe complement changed")
        if (
            outcome["candidate_publication_pointer_sha256"]
            != outcome["active_publication_pointer_sha256"]
            or outcome["candidate_runtime_manifest_sha256"]
            != outcome["active_runtime_manifest_sha256"]
        ):
            raise ValueError("active publication aliases differ from candidate publication")
        promoted_at = parse_action_timestamp(promoted_value, label="publication_promoted_at")
        if not started_at <= promoted_at <= completed_at:
            raise ValueError("publication timestamps are out of order")
    else:
        if commands or traces:
            raise ValueError("failed action cannot carry successful command evidence")
        absent = (
            "fixture_id",
            "publication_promoted_at",
            "predecessor_publication_generation",
            "candidate_publication_generation",
            "source_generation",
            "candidate_generation",
            "source_batch_id",
            *_ACTIVE_PUBLICATION_DIGESTS,
        )
        if any(outcome[name] is not None for name in absent):
            raise ValueError("failed action cannot carry promoted publication evidence")

    body = {
        key: child for key, child in outcome.items() if key not in {"outcome_id", "outcome_sha256"}
    }
    expected_digest = f"sha256:{sha256_bytes(canonical_json_bytes(body))}"
    expected_id = f"simulator-action-outcome:{expected_digest.removeprefix('sha256:')}"
    if outcome["outcome_sha256"] != expected_digest or outcome["outcome_id"] != expected_id:
        raise ValueError("simulator action outcome digest is invalid")

    return ValidatedActionOutcome(
        document=outcome,
        targets=targets,
        exclusions=exclusions,
        command_outcomes=commands,
        action_started_at=started_at,
        completed_at=completed_at,
        publication_promoted_at=promoted_at,
    )


def action_correlation(outcome: ValidatedActionOutcome, *, trace_id: str | None) -> dict[str, Any]:
    document = outcome.document
    if trace_id is not None:
        _trace_id(trace_id, label="trace_id")
    correlation = {
        "schema": ACTION_CORRELATION_VERSION,
        "outcome_id": document["outcome_id"],
        "outcome_sha256": document["outcome_sha256"],
        "admission_id": document["admission_id"],
        "admission_sha256": document["admission_sha256"],
        "action_id": document["action_id"],
        "task_key": document["task_key"],
        "operation_id": document["operation_id"],
        "payload_sha256": document["payload_sha256"],
        "fixture_id": document["fixture_id"],
        "incident_id": document["incident_id"],
        "incident_version": document["incident_version"],
        "plan_id": document["plan_id"],
        "plan_version": document["plan_version"],
        "plan_sha256": document["plan_sha256"],
        "approval_id": document["approval_id"],
        "approval_sha256": document["approval_sha256"],
        "authorization_id": document["authorization_id"],
        "authorization_sha256": document["authorization_sha256"],
        "consumption_id": document["consumption_id"],
        "consumption_sha256": document["consumption_sha256"],
        "dispatch_bundle_sha256": document["dispatch_bundle_sha256"],
        "action_envelope_sha256": document["action_envelope_sha256"],
        "publication_intent_id": document["publication_intent_id"],
        "publication_intent_sha256": document["publication_intent_sha256"],
        "publication_receipt_id": document["publication_receipt_id"],
        "publication_receipt_sha256": document["publication_receipt_sha256"],
        "trace_id": trace_id,
    }
    validate_schema("simulator-action-correlation-v1.schema.json", correlation)
    return correlation


def action_publication(outcome: ValidatedActionOutcome) -> dict[str, Any] | None:
    if outcome.document["status"] != "succeeded":
        return None
    document = outcome.document
    publication = {
        "schema": ACTION_PUBLICATION_VERSION,
        "publication_intent_id": document["publication_intent_id"],
        "publication_intent_sha256": document["publication_intent_sha256"],
        "publication_receipt_id": document["publication_receipt_id"],
        "publication_receipt_sha256": document["publication_receipt_sha256"],
        "predecessor_publication_pointer_sha256": document[
            "predecessor_publication_pointer_sha256"
        ],
        "predecessor_publication_generation": document["predecessor_publication_generation"],
        "candidate_publication_pointer_sha256": document["candidate_publication_pointer_sha256"],
        "candidate_publication_generation": document["candidate_publication_generation"],
        "source_generation": document["source_generation"],
        "candidate_generation": document["candidate_generation"],
        "source_batch_id": document["source_batch_id"],
        "source_batch_sha256": document["source_batch_sha256"],
        "candidate_fixture_manifest_sha256": document["candidate_fixture_manifest_sha256"],
        "candidate_runtime_manifest_sha256": document["candidate_runtime_manifest_sha256"],
        "candidate_lineage_manifest_sha256": document["candidate_lineage_manifest_sha256"],
        "declared_resource_manifest_sha256": document["declared_resource_manifest_sha256"],
        "active_publication_pointer_sha256": document["active_publication_pointer_sha256"],
        "active_runtime_manifest_sha256": document["active_runtime_manifest_sha256"],
        "preservation_manifest_sha256": document["preservation_manifest_sha256"],
        "safe_complement_before_sha256": document["safe_complement_before_sha256"],
        "safe_complement_after_sha256": document["safe_complement_after_sha256"],
        "safe_complement_proof_sha256": document["safe_complement_proof_sha256"],
        "candidate_seal_sha256": document["candidate_seal_sha256"],
        "candidate_tree_sha256": document["candidate_tree_sha256"],
        "publication_promoted_at": document["publication_promoted_at"],
    }
    validate_schema("simulator-action-publication-binding-v1.schema.json", publication)
    return publication


def stable_action_event_id(
    *, outcome_sha256: str, signal: str, observation: Mapping[str, Any]
) -> str:
    _digest(outcome_sha256, label="outcome_sha256")
    if signal not in COMMAND_SIGNALS:
        raise ValueError("action telemetry signal is invalid")
    schema = observation.get("schema")
    if schema == COMMAND_OBSERVATION_VERSION:
        result = cast(Mapping[str, Any], observation["result"])
        subject: Any = {"command_id": result["command_id"]}
    elif schema == SAFE_OBSERVATION_VERSION:
        subject = {"target": observation["target"]}
    elif schema == FAILURE_OBSERVATION_VERSION:
        subject = {"status": "failed"}
    else:
        raise ValueError("action telemetry observation schema is invalid")
    identity = {
        "schema": "simulator-action-telemetry-event-identity/v1",
        "outcome_sha256": outcome_sha256,
        "signal": signal,
        "subject": subject,
    }
    return f"simulator-action-event:{sha256_bytes(canonical_json_bytes(identity))}"


def validate_action_event(value: Mapping[str, Any]) -> dict[str, Any]:
    event = _mapping(value, label="simulator action telemetry event")
    validate_schema("simulator-action-telemetry-event-v1.schema.json", event)
    started_at = parse_action_timestamp(event["action_started_at"], label="action_started_at")
    completed_at = parse_action_timestamp(event["action_completed_at"], label="action_completed_at")
    observed_at = parse_action_timestamp(event["observed_at"], label="observed_at")
    emitted_at = parse_action_timestamp(event["emitted_at"], label="emitted_at")
    if completed_at < started_at or observed_at != completed_at or emitted_at < observed_at:
        raise ValueError("action telemetry timestamps are out of order")

    correlation = cast(dict[str, Any], event["correlation"])
    observation = cast(dict[str, Any], event["observation"])
    publication = cast(dict[str, Any] | None, event["publication"])
    if correlation["trace_id"] is not None:
        _trace_id(correlation["trace_id"], label="trace_id")
    promoted_value = event["publication_promoted_at"]
    if promoted_value is not None:
        promoted_at = parse_action_timestamp(promoted_value, label="publication_promoted_at")
        if not started_at <= promoted_at <= completed_at:
            raise ValueError("action telemetry publication time is out of order")
    if publication is not None and (
        publication["safe_complement_before_sha256"] != publication["safe_complement_after_sha256"]
        or publication["candidate_publication_pointer_sha256"]
        != publication["active_publication_pointer_sha256"]
        or publication["candidate_runtime_manifest_sha256"]
        != publication["active_runtime_manifest_sha256"]
        or publication["predecessor_publication_generation"] != publication["source_generation"]
        or publication["candidate_publication_generation"] != publication["candidate_generation"]
        or publication["candidate_generation"] <= publication["source_generation"]
        or publication["publication_intent_id"] != correlation["publication_intent_id"]
        or publication["publication_intent_sha256"] != correlation["publication_intent_sha256"]
        or publication["publication_receipt_id"] != correlation["publication_receipt_id"]
        or publication["publication_receipt_sha256"] != correlation["publication_receipt_sha256"]
    ):
        raise ValueError("action telemetry publication binding is invalid")
    signal = cast(str, event["signal"])
    observation_schema = observation["schema"]
    if observation_schema == COMMAND_OBSERVATION_VERSION:
        result = cast(dict[str, Any], observation["result"])
        expected_name = (
            "colortrace.simulator.action.quarantined"
            if result["result_kind"] == "quarantine"
            else "colortrace.simulator.action.rerendered"
        )
        if (
            publication is None
            or promoted_value != publication["publication_promoted_at"]
            or correlation["trace_id"] != result["trace_id"]
            or event["event_name"] != expected_name
        ):
            raise ValueError("command telemetry binding is invalid")
    elif observation_schema == SAFE_OBSERVATION_VERSION:
        if (
            publication is None
            or signal not in NON_TRACE_SIGNALS
            or correlation["trace_id"] is not None
            or event["event_name"] != "colortrace.simulator.safe.preserved"
            or observation["safe_complement_before_sha256"]
            != observation["safe_complement_after_sha256"]
            or observation["safe_complement_before_sha256"]
            != publication["safe_complement_before_sha256"]
            or observation["preservation_manifest_sha256"]
            != publication["preservation_manifest_sha256"]
            or observation["safe_complement_proof_sha256"]
            != publication["safe_complement_proof_sha256"]
        ):
            raise ValueError("safe preservation telemetry binding is invalid")
    elif observation_schema == FAILURE_OBSERVATION_VERSION:
        if (
            publication is not None
            or promoted_value is not None
            or signal not in NON_TRACE_SIGNALS
            or correlation["trace_id"] is not None
            or event["event_name"] != "colortrace.simulator.action.failed"
        ):
            raise ValueError("failure telemetry binding is invalid")
    else:  # pragma: no cover - schema validation rejects this
        raise ValueError("action telemetry observation schema is invalid")

    expected_event_id = stable_action_event_id(
        outcome_sha256=cast(str, correlation["outcome_sha256"]),
        signal=signal,
        observation=observation,
    )
    if event["event_id"] != expected_event_id:
        raise ValueError("action telemetry event ID is invalid")
    return event


def build_action_receipt(
    outcome: ValidatedActionOutcome,
    *,
    attempted_at: str,
    event_ids: tuple[str, ...],
    emitted_event_ids: tuple[str, ...],
    error_code: str | None,
) -> dict[str, Any]:
    parse_action_timestamp(attempted_at, label="attempted_at")
    if parse_action_timestamp(attempted_at, label="attempted_at") < outcome.completed_at:
        raise ValueError("telemetry attempt predates action completion")
    body = {
        "schema": ACTION_RECEIPT_VERSION,
        "outcome_id": outcome.document["outcome_id"],
        "outcome_sha256": outcome.document["outcome_sha256"],
        "action_id": outcome.document["action_id"],
        "attempted_at": attempted_at,
        "event_ids": list(event_ids),
        "emitted_event_ids": list(emitted_event_ids),
        "status": "emitted" if error_code is None else "failed",
        "error_code": error_code,
    }
    receipt = {
        **body,
        "receipt_sha256": f"sha256:{sha256_bytes(canonical_json_bytes(body))}",
    }
    return validate_action_receipt(receipt)


def validate_action_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    receipt = _mapping(value, label="simulator action telemetry receipt")
    validate_schema("simulator-action-telemetry-receipt-v1.schema.json", receipt)
    parse_action_timestamp(receipt["attempted_at"], label="attempted_at")
    event_ids = cast(list[str], receipt["event_ids"])
    emitted_ids = cast(list[str], receipt["emitted_event_ids"])
    if event_ids[: len(emitted_ids)] != emitted_ids:
        raise ValueError("emitted action telemetry IDs are not an event prefix")
    if receipt["status"] == "emitted":
        if receipt["error_code"] is not None or emitted_ids != event_ids:
            raise ValueError("successful action telemetry receipt is incomplete")
    elif receipt["error_code"] is None:
        raise ValueError("failed action telemetry receipt lacks an error code")
    body = {key: child for key, child in receipt.items() if key != "receipt_sha256"}
    expected = f"sha256:{sha256_bytes(canonical_json_bytes(body))}"
    if receipt["receipt_sha256"] != expected:
        raise ValueError("action telemetry receipt digest is invalid")
    return receipt


__all__ = [
    "ACTION_CORRELATION_VERSION",
    "ACTION_EVENT_VERSION",
    "ACTION_OUTCOME_VERSION",
    "ACTION_PUBLICATION_VERSION",
    "ACTION_RECEIPT_VERSION",
    "COMMAND_OBSERVATION_VERSION",
    "COMMAND_SIGNALS",
    "FAILURE_OBSERVATION_VERSION",
    "NON_TRACE_SIGNALS",
    "SAFE_OBSERVATION_VERSION",
    "ValidatedActionOutcome",
    "action_correlation",
    "action_publication",
    "build_action_receipt",
    "parse_action_timestamp",
    "stable_action_event_id",
    "validate_action_event",
    "validate_action_outcome",
    "validate_action_receipt",
]
