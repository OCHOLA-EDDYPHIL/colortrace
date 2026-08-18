from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from typing import Any, Literal, cast

from colortrace_telemetry.action_contract import stable_action_event_id, validate_action_outcome
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from referencing import Registry, Resource

SCHEMA_ROOT = Path(__file__).parent / "schemas"

SNAPSHOT_SCHEMA = "recovery-verification-snapshot/v1"
ACTIVE_PUBLICATION_SCHEMA = "recovery-active-publication/v1"
ARTIFACT_SCHEMA = "recovery-verification-artifact/v1"
EVIDENCE_REQUEST_SCHEMA = "recovery-evidence-request/v1"
EVIDENCE_RECORD_SCHEMA = "recovery-evidence-record/v1"
CHECK_RESULT_SCHEMA = "recovery-check-result/v1"
PACKET_SCHEMA = "recovery-packet/v1"
AUDIT_EVENT_SCHEMA = "recovery-audit-event/v1"
CLOSURE_REQUEST_SCHEMA = "recovery-closure-request/v1"
CLOSURE_RESULT_SCHEMA = "recovery-closure-result/v1"

RECOVERY_STATUSES = (
    "recovery_verified",
    "recovery_failed",
    "recovery_unresolved",
)
WORKFLOW_STATUSES = (
    "verification_pending",
    "verification_running",
    *RECOVERY_STATUSES,
    "closed",
)
CHECK_NAMES = (
    "active-publication",
    "approved-resource-state",
    "declared-reference-recovery",
    "exact-typed-lineage",
    "approved-recovery-scope",
    "safe-complement-preservation",
    "post-action-telemetry-correlation",
)
CHECK_POLICIES = {name: f"{name}/v1" for name in CHECK_NAMES}
ARTIFACT_ROLE_COUNTS = {
    "active-resource": 1,
    "affected-output": 3,
    "declared-reference": 3,
    "derivative-output": 1,
    "derivative-parent": 1,
    "lineage-manifest": 1,
    "runtime-manifest": 1,
    "fixture-manifest": 1,
    "preservation-manifest": 1,
    "safe-complement": 1,
    "safe-complement-proof": 1,
}
AUDIT_EVENT_TYPES = (
    "verification.requested",
    "verification.claimed",
    "verification.reclaimed",
    "verification.renewed",
    "verification.completed",
    "recovery.closed",
)

_SCHEMA_FILES = (
    "recovery-verification-snapshot-v1.schema.json",
    "recovery-evidence-request-v1.schema.json",
    "recovery-evidence-record-v1.schema.json",
    "recovery-check-result-v1.schema.json",
    "recovery-packet-v1.schema.json",
    "recovery-audit-event-v1.schema.json",
    "recovery-closure-request-v1.schema.json",
    "recovery-closure-result-v1.schema.json",
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^(?!0{32}$)[0-9a-f]{32}$")
_REASON = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class RecoveryError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def strict_json_bytes(value: bytes) -> Any:
    try:
        return json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("floating-point value")),
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise RecoveryError("malformed-json") from error


def canonical_json_bytes(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, float):
            raise TypeError("floating-point values are not canonical")
        if isinstance(item, Mapping):
            selected: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("canonical object keys must be strings")
                selected[key] = normalize(child)
            return selected
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if item is None or isinstance(item, (str, int, bool)):
            return item
        raise TypeError("value is not canonical JSON")

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def plain_json(value: Any) -> Any:
    return strict_json_bytes(canonical_json_bytes(value))


def prefixed_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def document_sha256(value: Mapping[str, Any]) -> str:
    return prefixed_sha256(canonical_json_bytes(value))


def require_identifier(value: Any, *, code: str = "identifier-invalid") -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RecoveryError(code)
    return value


def require_digest(value: Any, *, code: str = "digest-invalid") -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RecoveryError(code)
    return value


def require_idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or _IDEMPOTENCY.fullmatch(value) is None:
        raise RecoveryError("idempotency-key-invalid")
    return value


def parse_timestamp(value: Any, *, code: str = "time-invalid") -> datetime:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 64:
        raise RecoveryError(code)
    try:
        selected = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise RecoveryError(code) from None
    if selected.tzinfo is None or selected.utcoffset() != timedelta(0):
        raise RecoveryError(code)
    return selected.astimezone(UTC)


def timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RecoveryError("time-invalid")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _mapping(value: Any, *, code: str) -> dict[str, Any]:
    selected = plain_json(value)
    if not isinstance(selected, dict):
        raise RecoveryError(code)
    return selected


def _exact(value: Mapping[str, Any], fields: set[str], *, code: str) -> None:
    if set(value) != fields:
        raise RecoveryError(code)


def _positive(value: Any, *, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RecoveryError(code)
    return value


def _sorted_unique_strings(
    value: Any,
    *,
    code: str,
    maximum: int = 256,
    allow_empty: bool = True,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum or (not allow_empty and not value):
        raise RecoveryError(code)
    if any(not isinstance(child, str) for child in value):
        raise RecoveryError(code)
    selected = cast(list[str], value)
    if selected != sorted(set(selected)):
        raise RecoveryError(code)
    return selected


@cache
def _validators() -> Mapping[str, Draft202012Validator]:
    resources: list[tuple[str, Resource[Any]]] = []
    documents: dict[str, dict[str, Any]] = {}
    for name in _SCHEMA_FILES:
        document = cast(dict[str, Any], strict_json_bytes((SCHEMA_ROOT / name).read_bytes()))
        identifier = cast(str, document["$id"])
        resources.append((identifier, Resource.from_contents(document)))
        documents[name] = document
    registry = Registry().with_resources(resources)
    return {
        name: Draft202012Validator(
            document,
            registry=registry,
            format_checker=FormatChecker(),
        )
        for name, document in documents.items()
    }


def validate_schema(name: str, value: Mapping[str, Any]) -> None:
    try:
        validator = _validators()[name]
    except KeyError as error:
        raise RecoveryError("schema-unknown") from error
    errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
    if errors:
        raise RecoveryError("schema-validation")


def _validate_action_outcome(value: Any) -> dict[str, Any]:
    outcome = _mapping(value, code="action-outcome-invalid")
    try:
        # The telemetry contract is the exact consumer of the complete merged #23
        # outcome. Reusing it prevents recovery from accepting a digest-valid but
        # structurally or semantically weakened action record.
        outcome = validate_action_outcome(outcome).document
    except (TypeError, ValueError) as error:
        raise RecoveryError("action-outcome-invalid") from error
    required = {
        "schema",
        "outcome_id",
        "outcome_sha256",
        "status",
        "incident_id",
        "incident_version",
        "action_id",
        "task_key",
        "operation_id",
        "payload_sha256",
        "plan_id",
        "plan_version",
        "plan_sha256",
        "approval_id",
        "approval_sha256",
        "authorization_id",
        "authorization_sha256",
        "consumption_id",
        "consumption_sha256",
        "admission_id",
        "admission_sha256",
        "action_started_at",
        "completed_at",
        "publication_promoted_at",
        "publication_intent_id",
        "publication_intent_sha256",
        "publication_receipt_id",
        "publication_receipt_sha256",
        "candidate_publication_pointer_sha256",
        "candidate_publication_generation",
        "active_publication_pointer_sha256",
        "active_runtime_manifest_sha256",
        "candidate_fixture_manifest_sha256",
        "candidate_lineage_manifest_sha256",
        "declared_resource_manifest_sha256",
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
    if not required.issubset(outcome) or outcome.get("schema") != "simulator-action-outcome/v1":
        raise RecoveryError("action-outcome-invalid")
    if outcome["status"] != "succeeded":
        raise RecoveryError("action-outcome-not-successful")
    for name in (
        "incident_id",
        "action_id",
        "task_key",
        "operation_id",
        "plan_id",
        "approval_id",
        "authorization_id",
        "consumption_id",
        "admission_id",
        "publication_intent_id",
        "publication_receipt_id",
    ):
        require_identifier(outcome[name], code="action-outcome-invalid")
    for name in (
        "outcome_sha256",
        "payload_sha256",
        "plan_sha256",
        "approval_sha256",
        "authorization_sha256",
        "consumption_sha256",
        "admission_sha256",
        "publication_intent_sha256",
        "publication_receipt_sha256",
        "candidate_publication_pointer_sha256",
        "active_publication_pointer_sha256",
        "active_runtime_manifest_sha256",
        "candidate_fixture_manifest_sha256",
        "candidate_lineage_manifest_sha256",
        "declared_resource_manifest_sha256",
        "preservation_manifest_sha256",
        "safe_complement_before_sha256",
        "safe_complement_after_sha256",
        "safe_complement_proof_sha256",
        "candidate_seal_sha256",
        "candidate_tree_sha256",
    ):
        require_digest(outcome[name], code="action-outcome-invalid")
    _positive(outcome["incident_version"], code="action-outcome-invalid")
    _positive(outcome["plan_version"], code="action-outcome-invalid")
    _positive(outcome["candidate_publication_generation"], code="action-outcome-invalid")
    started = parse_timestamp(outcome["action_started_at"], code="action-outcome-invalid")
    completed = parse_timestamp(outcome["completed_at"], code="action-outcome-invalid")
    promoted = parse_timestamp(outcome["publication_promoted_at"], code="action-outcome-invalid")
    if not started < promoted <= completed:
        raise RecoveryError("action-outcome-not-fresh")
    if outcome["safe_complement_before_sha256"] != outcome["safe_complement_after_sha256"]:
        raise RecoveryError("action-safe-complement-changed")
    if (
        outcome["candidate_publication_pointer_sha256"]
        != outcome["active_publication_pointer_sha256"]
    ):
        raise RecoveryError("action-publication-binding-invalid")
    targets = outcome["targets"]
    exclusions = outcome["exclusions"]
    commands = outcome["command_outcomes"]
    traces = outcome["new_trace_ids"]
    if (
        not isinstance(targets, list)
        or len(targets) != 5
        or not isinstance(exclusions, list)
        or not exclusions
        or not isinstance(commands, list)
        or len(commands) != 5
        or not isinstance(traces, list)
        or len(traces) != 5
        or any(not isinstance(trace, str) or _TRACE_ID.fullmatch(trace) is None for trace in traces)
        or cast(list[str], traces) != sorted(set(cast(list[str], traces)))
    ):
        raise RecoveryError("action-outcome-invalid")
    body = {
        key: child for key, child in outcome.items() if key not in {"outcome_id", "outcome_sha256"}
    }
    digest = document_sha256(body)
    identifier = f"simulator-action-outcome:{digest.removeprefix('sha256:')}"
    if outcome["outcome_sha256"] != digest or outcome["outcome_id"] != identifier:
        raise RecoveryError("action-outcome-digest-invalid")
    return outcome


_ACTIVE_FIELDS = {
    "schema",
    "publication_id",
    "observed_at",
    "generation",
    "pointer_sha256",
    "runtime_manifest_sha256",
    "fixture_manifest_sha256",
    "lineage_manifest_sha256",
    "declared_resource_manifest_sha256",
    "preservation_manifest_sha256",
    "safe_complement_sha256",
    "safe_complement_proof_sha256",
    "candidate_seal_sha256",
    "candidate_tree_sha256",
}


def _validate_active_publication(value: Any, outcome: Mapping[str, Any]) -> dict[str, Any]:
    active = _mapping(value, code="active-publication-invalid")
    _exact(active, _ACTIVE_FIELDS, code="active-publication-invalid")
    if active["schema"] != ACTIVE_PUBLICATION_SCHEMA:
        raise RecoveryError("active-publication-invalid")
    require_identifier(active["publication_id"], code="active-publication-invalid")
    _positive(active["generation"], code="active-publication-invalid")
    observed = parse_timestamp(active["observed_at"], code="active-publication-invalid")
    if observed <= parse_timestamp(outcome["action_started_at"]):
        raise RecoveryError("active-publication-not-fresh")
    bindings = {
        "generation": "candidate_publication_generation",
        "pointer_sha256": "active_publication_pointer_sha256",
        "runtime_manifest_sha256": "active_runtime_manifest_sha256",
        "fixture_manifest_sha256": "candidate_fixture_manifest_sha256",
        "lineage_manifest_sha256": "candidate_lineage_manifest_sha256",
        "declared_resource_manifest_sha256": "declared_resource_manifest_sha256",
        "preservation_manifest_sha256": "preservation_manifest_sha256",
        "safe_complement_sha256": "safe_complement_after_sha256",
        "safe_complement_proof_sha256": "safe_complement_proof_sha256",
        "candidate_seal_sha256": "candidate_seal_sha256",
        "candidate_tree_sha256": "candidate_tree_sha256",
    }
    for active_name, outcome_name in bindings.items():
        if active[active_name] != outcome[outcome_name]:
            raise RecoveryError("active-publication-binding-invalid")
    for name in bindings:
        if name != "generation":
            require_digest(active[name], code="active-publication-invalid")
    return active


_ARTIFACT_FIELDS = {
    "schema",
    "artifact_id",
    "role",
    "target",
    "sha256",
    "size",
    "publication_pointer_sha256",
}


def _validate_artifacts(value: Any, pointer_sha256: str) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        raise RecoveryError("verification-artifacts-invalid")
    artifacts = [_mapping(child, code="verification-artifact-invalid") for child in value]
    for artifact in artifacts:
        _exact(artifact, _ARTIFACT_FIELDS, code="verification-artifact-invalid")
        if artifact["schema"] != ARTIFACT_SCHEMA or artifact["role"] not in ARTIFACT_ROLE_COUNTS:
            raise RecoveryError("verification-artifact-invalid")
        require_identifier(artifact["artifact_id"], code="verification-artifact-invalid")
        require_digest(artifact["sha256"], code="verification-artifact-invalid")
        if (
            not isinstance(artifact["size"], int)
            or isinstance(artifact["size"], bool)
            or artifact["size"] < 0
            or artifact["publication_pointer_sha256"] != pointer_sha256
            or (artifact["target"] is not None and not isinstance(artifact["target"], Mapping))
        ):
            raise RecoveryError("verification-artifact-invalid")
    identities = [
        (cast(str, child["role"]), cast(str, child["artifact_id"])) for child in artifacts
    ]
    artifact_ids = [cast(str, child["artifact_id"]) for child in artifacts]
    if (
        identities != sorted(set(identities))
        or len(artifact_ids) != len(set(artifact_ids))
        or Counter(child["role"] for child in artifacts) != Counter(ARTIFACT_ROLE_COUNTS)
    ):
        raise RecoveryError("verification-artifacts-invalid")
    return artifacts


_EVIDENCE_RECORD_FIELDS = {
    "schema",
    "evidence_id",
    "evidence_sha256",
    "event_id",
    "signal",
    "subject_kind",
    "subject_id",
    "trace_id",
    "outcome_id",
    "outcome_sha256",
    "action_id",
    "operation_id",
    "observed_at",
    "emitted_at",
    "retrieved_at",
    "clock_provenance",
    "clock_skew_milliseconds",
    "truncated",
    "source_label",
    "source_envelope_sha256",
    "source_envelope",
}


def build_evidence_record(
    *,
    event_id: str,
    signal: Literal["metric", "log", "trace"],
    subject_kind: Literal["command", "safe"],
    subject_id: str,
    trace_id: str | None,
    outcome_id: str,
    outcome_sha256: str,
    action_id: str,
    operation_id: str,
    observed_at: str,
    emitted_at: str,
    retrieved_at: str,
    clock_provenance: str,
    clock_skew_milliseconds: int,
    truncated: bool,
    source_label: str,
    source_envelope: Mapping[str, Any],
) -> dict[str, Any]:
    envelope = _mapping(source_envelope, code="evidence-envelope-invalid")
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > 2_097_152:
        raise RecoveryError("evidence-envelope-too-large")
    body = {
        "schema": EVIDENCE_RECORD_SCHEMA,
        "event_id": require_identifier(event_id, code="evidence-record-invalid"),
        "signal": signal,
        "subject_kind": subject_kind,
        "subject_id": require_identifier(subject_id, code="evidence-record-invalid"),
        "trace_id": trace_id,
        "outcome_id": require_identifier(outcome_id, code="evidence-record-invalid"),
        "outcome_sha256": require_digest(outcome_sha256, code="evidence-record-invalid"),
        "action_id": require_identifier(action_id, code="evidence-record-invalid"),
        "operation_id": require_identifier(operation_id, code="evidence-record-invalid"),
        "observed_at": timestamp(parse_timestamp(observed_at)),
        "emitted_at": timestamp(parse_timestamp(emitted_at)),
        "retrieved_at": timestamp(parse_timestamp(retrieved_at)),
        "clock_provenance": require_identifier(clock_provenance, code="evidence-record-invalid"),
        "clock_skew_milliseconds": clock_skew_milliseconds,
        "truncated": truncated,
        "source_label": require_identifier(source_label, code="evidence-record-invalid"),
        "source_envelope_sha256": prefixed_sha256(envelope_bytes),
        "source_envelope": envelope,
    }
    if trace_id is not None and _TRACE_ID.fullmatch(trace_id) is None:
        raise RecoveryError("evidence-record-invalid")
    digest = document_sha256(body)
    return validate_evidence_record(
        {
            **body,
            "evidence_id": f"recovery-evidence:{digest.removeprefix('sha256:')}",
            "evidence_sha256": digest,
        }
    )


def validate_evidence_record(value: Mapping[str, Any]) -> dict[str, Any]:
    record = _mapping(value, code="evidence-record-invalid")
    _exact(record, _EVIDENCE_RECORD_FIELDS, code="evidence-record-invalid")
    validate_schema("recovery-evidence-record-v1.schema.json", record)
    envelope = _mapping(record["source_envelope"], code="evidence-envelope-invalid")
    envelope_bytes = canonical_json_bytes(envelope)
    if len(envelope_bytes) > 2_097_152 or record["source_envelope_sha256"] != prefixed_sha256(
        envelope_bytes
    ):
        raise RecoveryError("evidence-envelope-digest-invalid")
    observed = parse_timestamp(record["observed_at"])
    emitted = parse_timestamp(record["emitted_at"])
    parse_timestamp(record["retrieved_at"])
    if emitted < observed:
        raise RecoveryError("evidence-record-time-invalid")
    body = {
        key: child for key, child in record.items() if key not in {"evidence_id", "evidence_sha256"}
    }
    digest = document_sha256(body)
    if (
        record["evidence_sha256"] != digest
        or record["evidence_id"] != f"recovery-evidence:{digest.removeprefix('sha256:')}"
    ):
        raise RecoveryError("evidence-record-digest-invalid")
    return record


def build_verification_snapshot(
    action_outcome: Mapping[str, Any],
    active_publication: Mapping[str, Any],
    verification_artifacts: Sequence[Mapping[str, Any]],
    *,
    created_at: datetime,
) -> dict[str, Any]:
    outcome = _validate_action_outcome(action_outcome)
    active = _validate_active_publication(active_publication, outcome)
    artifacts = _validate_artifacts(
        verification_artifacts,
        cast(str, active["pointer_sha256"]),
    )
    created = timestamp(created_at)
    if parse_timestamp(created) < parse_timestamp(active["observed_at"]):
        raise RecoveryError("snapshot-time-invalid")
    body = {
        "schema": SNAPSHOT_SCHEMA,
        "incident_id": outcome["incident_id"],
        "incident_version": outcome["incident_version"],
        "created_at": created,
        "action_outcome": outcome,
        "active_publication": active,
        "verification_artifacts": artifacts,
    }
    digest = document_sha256(body)
    snapshot = {
        **body,
        "snapshot_id": f"recovery-snapshot:{digest.removeprefix('sha256:')}",
        "snapshot_sha256": digest,
    }
    return validate_verification_snapshot(snapshot)


def validate_verification_snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = _mapping(value, code="snapshot-invalid")
    validate_schema("recovery-verification-snapshot-v1.schema.json", snapshot)
    outcome = _validate_action_outcome(snapshot["action_outcome"])
    active = _validate_active_publication(snapshot["active_publication"], outcome)
    _validate_artifacts(snapshot["verification_artifacts"], cast(str, active["pointer_sha256"]))
    if (
        snapshot["incident_id"] != outcome["incident_id"]
        or snapshot["incident_version"] != outcome["incident_version"]
        or parse_timestamp(snapshot["created_at"]) < parse_timestamp(active["observed_at"])
    ):
        raise RecoveryError("snapshot-binding-invalid")
    body = {
        key: child
        for key, child in snapshot.items()
        if key not in {"snapshot_id", "snapshot_sha256"}
    }
    digest = document_sha256(body)
    if (
        snapshot["snapshot_sha256"] != digest
        or snapshot["snapshot_id"] != f"recovery-snapshot:{digest.removeprefix('sha256:')}"
    ):
        raise RecoveryError("snapshot-digest-invalid")
    return snapshot


def verification_state_sha256(value: Mapping[str, Any]) -> str:
    """Digest recovery state while excluding re-observation timestamps and envelope IDs."""

    snapshot = validate_verification_snapshot(value)
    active = cast(dict[str, Any], snapshot["active_publication"])
    state = {
        "schema": "recovery-verification-state/v1",
        "incident_id": snapshot["incident_id"],
        "incident_version": snapshot["incident_version"],
        "action_outcome": snapshot["action_outcome"],
        "active_publication": {key: child for key, child in active.items() if key != "observed_at"},
        "verification_artifacts": snapshot["verification_artifacts"],
    }
    return document_sha256(state)


def build_evidence_request(
    snapshot_value: Mapping[str, Any],
    *,
    binding: Mapping[str, str],
    catalog_sha256: str,
    evaluation_started_at: datetime,
    predecessor_event_sha256: str | None = None,
) -> dict[str, Any]:
    snapshot = validate_verification_snapshot(snapshot_value)
    if set(binding) != {"prometheus_datasource_uid", "loki_datasource_uid", "tempo_datasource_uid"}:
        raise RecoveryError("evidence-binding-invalid")
    if any(
        require_identifier(value, code="evidence-binding-invalid") != value
        for value in binding.values()
    ):
        raise RecoveryError("evidence-binding-invalid")
    require_digest(catalog_sha256, code="evidence-catalog-invalid")
    if predecessor_event_sha256 is not None:
        require_digest(predecessor_event_sha256, code="evidence-predecessor-invalid")
    outcome = cast(dict[str, Any], snapshot["action_outcome"])
    queries: list[dict[str, Any]] = [
        {"catalog_key": "metric.simulator-action-observations", "trace_id": None},
        {"catalog_key": "log.simulator-action-events", "trace_id": None},
        *(
            {"catalog_key": "trace.simulator-action-command", "trace_id": trace_id}
            for trace_id in cast(list[str], outcome["new_trace_ids"])
        ),
    ]
    for index, query in enumerate(queries, start=1):
        identity = {
            "schema": "recovery-evidence-query-identity/v1",
            "snapshot_sha256": snapshot["snapshot_sha256"],
            "sequence": index,
            **query,
        }
        query["query_id"] = (
            f"recovery-query:{hashlib.sha256(canonical_json_bytes(identity)).hexdigest()}"
        )
    started = timestamp(evaluation_started_at)
    deadline = timestamp(evaluation_started_at.astimezone(UTC) + timedelta(seconds=60))
    body = {
        "schema": EVIDENCE_REQUEST_SCHEMA,
        "incident_id": snapshot["incident_id"],
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "state_equivalence_sha256": verification_state_sha256(snapshot),
        "outcome_id": outcome["outcome_id"],
        "outcome_sha256": outcome["outcome_sha256"],
        "evaluation_started_at": started,
        "evaluation_deadline_at": deadline,
        "catalog_version": "grafana-evidence-query-catalog/v1",
        "catalog_sha256": catalog_sha256,
        "binding": dict(binding),
        "queries": queries,
        "predecessor_event_sha256": predecessor_event_sha256,
    }
    digest = document_sha256(body)
    request = {
        **body,
        "request_id": f"recovery-evidence-request:{digest.removeprefix('sha256:')}",
        "request_sha256": digest,
    }
    return validate_evidence_request(request, snapshot=snapshot)


def validate_evidence_request(
    value: Mapping[str, Any],
    *,
    snapshot: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    request = _mapping(value, code="evidence-request-invalid")
    validate_schema("recovery-evidence-request-v1.schema.json", request)
    started = parse_timestamp(request["evaluation_started_at"])
    deadline = parse_timestamp(request["evaluation_deadline_at"])
    if deadline - started != timedelta(seconds=60):
        raise RecoveryError("evidence-deadline-invalid")
    queries = cast(list[dict[str, Any]], request["queries"])
    if len(queries) != 7:
        raise RecoveryError("evidence-query-set-invalid")
    if [child["catalog_key"] for child in queries[:2]] != [
        "metric.simulator-action-observations",
        "log.simulator-action-events",
    ]:
        raise RecoveryError("evidence-query-set-invalid")
    traces = [child["trace_id"] for child in queries[2:]]
    if any(child["catalog_key"] != "trace.simulator-action-command" for child in queries[2:]):
        raise RecoveryError("evidence-query-set-invalid")
    if traces != sorted(set(traces)) or any(
        not isinstance(trace, str) or _TRACE_ID.fullmatch(trace) is None for trace in traces
    ):
        raise RecoveryError("evidence-query-set-invalid")
    if len({child["query_id"] for child in queries}) != 7:
        raise RecoveryError("evidence-query-set-invalid")
    body = {
        key: child for key, child in request.items() if key not in {"request_id", "request_sha256"}
    }
    digest = document_sha256(body)
    if (
        request["request_sha256"] != digest
        or request["request_id"] != f"recovery-evidence-request:{digest.removeprefix('sha256:')}"
    ):
        raise RecoveryError("evidence-request-digest-invalid")
    if snapshot is not None:
        selected = validate_verification_snapshot(snapshot)
        outcome = cast(dict[str, Any], selected["action_outcome"])
        if (
            request["incident_id"] != selected["incident_id"]
            or request["snapshot_id"] != selected["snapshot_id"]
            or request["snapshot_sha256"] != selected["snapshot_sha256"]
            or request["outcome_id"] != outcome["outcome_id"]
            or request["outcome_sha256"] != outcome["outcome_sha256"]
            or request["state_equivalence_sha256"] != verification_state_sha256(selected)
            or traces != outcome["new_trace_ids"]
        ):
            raise RecoveryError("evidence-request-binding-invalid")
    return request


def build_check_result(
    check: str,
    state: Literal["passed", "failed", "unresolved"],
    *,
    normalized_inputs_sha256: str,
    evidence_ids: Sequence[str] = (),
    artifact_ids: Sequence[str] = (),
    reason_codes: Sequence[str] = (),
) -> dict[str, Any]:
    if check not in CHECK_POLICIES or state not in {"passed", "failed", "unresolved"}:
        raise RecoveryError("check-result-invalid")
    require_digest(normalized_inputs_sha256, code="check-result-invalid")
    evidence = sorted(set(evidence_ids))
    artifacts = sorted(set(artifact_ids))
    reasons = sorted(set(reason_codes))
    if len(evidence) != len(evidence_ids) or len(artifacts) != len(artifact_ids):
        raise RecoveryError("check-result-invalid")
    for identifier in (*evidence, *artifacts):
        require_identifier(identifier, code="check-result-invalid")
    if any(_REASON.fullmatch(reason) is None for reason in reasons):
        raise RecoveryError("check-result-invalid")
    if (state == "passed" and reasons) or (state != "passed" and not reasons):
        raise RecoveryError("check-result-invalid")
    body = {
        "schema": CHECK_RESULT_SCHEMA,
        "check": check,
        "policy": CHECK_POLICIES[check],
        "state": state,
        "normalized_inputs_sha256": normalized_inputs_sha256,
        "evidence_ids": evidence,
        "artifact_ids": artifacts,
        "reason_codes": reasons,
    }
    digest = document_sha256(body)
    result = {
        **body,
        "result_id": f"recovery-check-result:{digest.removeprefix('sha256:')}",
        "result_sha256": digest,
    }
    return validate_check_result(result)


def validate_check_result(value: Mapping[str, Any]) -> dict[str, Any]:
    result = _mapping(value, code="check-result-invalid")
    validate_schema("recovery-check-result-v1.schema.json", result)
    check = cast(str, result["check"])
    if result["policy"] != CHECK_POLICIES.get(check):
        raise RecoveryError("check-policy-invalid")
    evidence = _sorted_unique_strings(result["evidence_ids"], code="check-result-invalid")
    artifacts = _sorted_unique_strings(result["artifact_ids"], code="check-result-invalid")
    reasons = _sorted_unique_strings(result["reason_codes"], code="check-result-invalid")
    for identifier in (*evidence, *artifacts):
        require_identifier(identifier, code="check-result-invalid")
    state = result["state"]
    if (state == "passed" and reasons) or (state != "passed" and not reasons):
        raise RecoveryError("check-result-invalid")
    body = {
        key: child for key, child in result.items() if key not in {"result_id", "result_sha256"}
    }
    digest = document_sha256(body)
    if (
        result["result_sha256"] != digest
        or result["result_id"] != f"recovery-check-result:{digest.removeprefix('sha256:')}"
    ):
        raise RecoveryError("check-result-digest-invalid")
    return result


def assess_post_action_observations(
    snapshot_value: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    *,
    evaluation_started_at: datetime,
    evaluation_completed_at: datetime,
) -> tuple[
    Literal["passed", "failed", "unresolved"],
    tuple[str, ...],
    tuple[str, ...],
]:
    snapshot = validate_verification_snapshot(snapshot_value)
    outcome = cast(dict[str, Any], snapshot["action_outcome"])
    started = parse_timestamp(outcome["action_started_at"])
    if (
        evaluation_started_at.tzinfo is None
        or evaluation_started_at.utcoffset() is None
        or evaluation_completed_at.tzinfo is None
        or evaluation_completed_at.utcoffset() is None
    ):
        raise RecoveryError("evaluation-time-invalid")
    evaluation_start = evaluation_started_at.astimezone(UTC)
    evaluation_end = evaluation_completed_at.astimezone(UTC)
    if evaluation_end < evaluation_start:
        raise RecoveryError("evaluation-time-invalid")
    expected: dict[str, tuple[str, str, str, str | None]] = {}
    for command in cast(list[Mapping[str, Any]], outcome["command_outcomes"]):
        command_id = cast(str, command["command_id"])
        trace_id = cast(str, command["trace_id"])
        expected_observation = {
            "schema": "simulator-command-observation/v1",
            "result": command,
        }
        for signal in ("metric", "log", "trace"):
            event_id = stable_action_event_id(
                outcome_sha256=cast(str, outcome["outcome_sha256"]),
                signal=signal,
                observation=expected_observation,
            )
            expected[event_id] = (signal, "command", command_id, trace_id)
    for target in cast(list[Mapping[str, Any]], outcome["exclusions"]):
        target_id = cast(str, target["id"])
        expected_observation = {
            "schema": "simulator-safe-preservation-observation/v1",
            "target": target,
        }
        for signal in ("metric", "log"):
            event_id = stable_action_event_id(
                outcome_sha256=cast(str, outcome["outcome_sha256"]),
                signal=signal,
                observation=expected_observation,
            )
            expected[event_id] = (signal, "safe", target_id, None)
    if len(expected) != 21:
        raise RecoveryError("observation-authority-invalid")
    reasons: set[str] = set()
    accepted: dict[str, tuple[bytes, dict[str, Any]]] = {}
    for raw in observations:
        try:
            observation = validate_evidence_record(raw)
        except RecoveryError:
            reasons.add("observation-schema-invalid")
            continue
        event_id = cast(str, observation["event_id"])
        canonical_body = {
            key: child
            for key, child in observation.items()
            if key not in {"evidence_id", "evidence_sha256"}
        }
        encoded = canonical_json_bytes(canonical_body)
        previous = accepted.get(event_id)
        if previous is None:
            accepted[event_id] = (encoded, observation)
        elif previous[0] != encoded:
            reasons.add("observation-event-conflict")

    evidence_ids: list[str] = []
    counts: Counter[tuple[str, str]] = Counter()
    trace_ids: set[str] = set()
    matched_event_ids: set[str] = set()
    for _encoded, observation in accepted.values():
        try:
            evidence_id = require_identifier(
                observation["evidence_id"], code="recovery-observation-invalid"
            )
            require_identifier(observation["event_id"], code="recovery-observation-invalid")
            observed = parse_timestamp(observation["observed_at"])
            emitted = parse_timestamp(observation["emitted_at"])
            retrieved = parse_timestamp(observation["retrieved_at"])
        except RecoveryError:
            reasons.add("observation-schema-invalid")
            continue
        evidence_ids.append(evidence_id)
        if (
            observation["outcome_id"] != outcome["outcome_id"]
            or observation["outcome_sha256"] != outcome["outcome_sha256"]
            or observation["action_id"] != outcome["action_id"]
            or observation["operation_id"] != outcome["operation_id"]
        ):
            reasons.add("observation-correlation-mismatch")
        if observed <= started or emitted <= started or emitted < observed:
            reasons.add("pre-action-observation")
        outside_window = not evaluation_start <= retrieved <= evaluation_end
        retrieval_late = evaluation_end - retrieved > timedelta(seconds=60)
        if outside_window or retrieval_late:
            reasons.add("observation-retrieval-late")
        skew = observation["clock_skew_milliseconds"]
        if (
            observation["clock_provenance"] == "unknown"
            or not isinstance(skew, int)
            or isinstance(skew, bool)
            or abs(skew) > 5_000
        ):
            reasons.add("observation-time-ambiguous")
        if observation["truncated"] is not False:
            reasons.add("observation-truncated")
        signal = observation["signal"]
        subject = observation["subject_kind"]
        expected_binding = expected.get(cast(str, observation["event_id"]))
        actual_authority = (
            signal,
            subject,
            observation["subject_id"],
            observation["trace_id"],
        )
        if expected_binding is None or actual_authority != expected_binding:
            reasons.add("observation-authority-mismatch")
        else:
            matched_event_ids.add(cast(str, observation["event_id"]))
        if signal not in {"metric", "log", "trace"} or subject not in {"command", "safe"}:
            reasons.add("observation-schema-invalid")
        else:
            counts[(cast(str, signal), cast(str, subject))] += 1
        trace = observation["trace_id"]
        if signal == "trace":
            if not isinstance(trace, str) or _TRACE_ID.fullmatch(trace) is None:
                reasons.add("observation-trace-invalid")
            else:
                trace_ids.add(trace)
        elif trace is not None and (
            not isinstance(trace, str) or _TRACE_ID.fullmatch(trace) is None
        ):
            reasons.add("observation-trace-invalid")
    expected_counts = Counter(
        {
            ("metric", "command"): 5,
            ("metric", "safe"): 3,
            ("log", "command"): 5,
            ("log", "safe"): 3,
            ("trace", "command"): 5,
        }
    )
    if counts != expected_counts or len(accepted) != 21:
        reasons.add("observation-set-incomplete")
    if matched_event_ids != set(expected):
        reasons.add("observation-set-incomplete")
    if trace_ids != set(cast(list[str], outcome["new_trace_ids"])):
        reasons.add("observation-trace-set-mismatch")
    if reasons & {"observation-authority-mismatch", "observation-correlation-mismatch"}:
        return "failed", tuple(sorted(reasons)), tuple(sorted(set(evidence_ids)))
    if reasons:
        return "unresolved", tuple(sorted(reasons)), tuple(sorted(set(evidence_ids)))
    return "passed", (), tuple(sorted(evidence_ids))


def build_recovery_packet(
    snapshot_value: Mapping[str, Any],
    evidence_request_value: Mapping[str, Any],
    check_results: Sequence[Mapping[str, Any]],
    *,
    workflow_id: str,
    workflow_version: int,
    attempt_id: str,
    attempt_number: int,
    evaluation_completed_at: datetime,
    supersedes_packet_id: str | None = None,
    supersedes_packet_sha256: str | None = None,
) -> dict[str, Any]:
    snapshot = validate_verification_snapshot(snapshot_value)
    request = validate_evidence_request(evidence_request_value, snapshot=snapshot)
    require_identifier(workflow_id, code="packet-workflow-invalid")
    require_identifier(attempt_id, code="packet-attempt-invalid")
    _positive(workflow_version, code="packet-version-invalid")
    _positive(attempt_number, code="packet-attempt-invalid")
    if (supersedes_packet_id is None) != (supersedes_packet_sha256 is None):
        raise RecoveryError("packet-supersession-invalid")
    if supersedes_packet_id is not None:
        require_identifier(supersedes_packet_id, code="packet-supersession-invalid")
        require_digest(supersedes_packet_sha256, code="packet-supersession-invalid")
    results = [validate_check_result(child) for child in check_results]
    if [child["check"] for child in results] != list(CHECK_NAMES):
        raise RecoveryError("packet-check-set-invalid")
    states = [cast(str, child["state"]) for child in results]
    if "failed" in states:
        status = "recovery_failed"
    elif "unresolved" in states:
        status = "recovery_unresolved"
    else:
        status = "recovery_verified"
    evidence_ids = sorted(
        {
            evidence_id
            for result in results
            for evidence_id in cast(list[str], result["evidence_ids"])
        }
    )
    failures = [
        {"check": child["check"], "reason_codes": child["reason_codes"]}
        for child in results
        if child["state"] == "failed"
    ]
    unresolved = [
        {"check": child["check"], "reason_codes": child["reason_codes"]}
        for child in results
        if child["state"] == "unresolved"
    ]
    outcome = cast(dict[str, Any], snapshot["action_outcome"])
    completed = timestamp(evaluation_completed_at)
    evaluation_start = parse_timestamp(request["evaluation_started_at"])
    if (
        not evaluation_start
        <= parse_timestamp(completed)
        <= parse_timestamp(request["evaluation_deadline_at"])
    ):
        raise RecoveryError("packet-evaluation-time-invalid")
    body = {
        "schema": PACKET_SCHEMA,
        "incident_id": snapshot["incident_id"],
        "incident_version": snapshot["incident_version"],
        "workflow_id": workflow_id,
        "workflow_version": workflow_version,
        "attempt_id": attempt_id,
        "attempt_number": attempt_number,
        "snapshot_id": snapshot["snapshot_id"],
        "snapshot_sha256": snapshot["snapshot_sha256"],
        "outcome_id": outcome["outcome_id"],
        "outcome_sha256": outcome["outcome_sha256"],
        "action_id": outcome["action_id"],
        "action_started_at": outcome["action_started_at"],
        "evaluation_started_at": request["evaluation_started_at"],
        "evaluation_completed_at": completed,
        "evidence_request_id": request["request_id"],
        "evidence_request_sha256": request["request_sha256"],
        "evidence_ids": evidence_ids,
        "check_results": results,
        "status": status,
        "failure_items": failures,
        "unresolved_items": unresolved,
        "eligible_for_closure": status == "recovery_verified",
        "supersedes_packet_id": supersedes_packet_id,
        "supersedes_packet_sha256": supersedes_packet_sha256,
    }
    digest = document_sha256(body)
    packet = {
        **body,
        "packet_id": f"recovery-packet:{digest.removeprefix('sha256:')}",
        "packet_sha256": digest,
    }
    return validate_recovery_packet(packet, snapshot=snapshot, evidence_request=request)


def validate_recovery_packet(
    value: Mapping[str, Any],
    *,
    snapshot: Mapping[str, Any] | None = None,
    evidence_request: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    packet = _mapping(value, code="recovery-packet-invalid")
    validate_schema("recovery-packet-v1.schema.json", packet)
    results = [
        validate_check_result(child)
        for child in cast(list[dict[str, Any]], packet["check_results"])
    ]
    if [child["check"] for child in results] != list(CHECK_NAMES):
        raise RecoveryError("packet-check-set-invalid")
    states = {cast(str, child["state"]) for child in results}
    expected_status = (
        "recovery_failed"
        if "failed" in states
        else "recovery_unresolved"
        if "unresolved" in states
        else "recovery_verified"
    )
    if packet["status"] != expected_status or packet["eligible_for_closure"] is not (
        expected_status == "recovery_verified"
    ):
        raise RecoveryError("packet-status-invalid")
    expected_failures = [
        {"check": child["check"], "reason_codes": child["reason_codes"]}
        for child in results
        if child["state"] == "failed"
    ]
    expected_unresolved = [
        {"check": child["check"], "reason_codes": child["reason_codes"]}
        for child in results
        if child["state"] == "unresolved"
    ]
    expected_evidence = sorted(
        {evidence_id for child in results for evidence_id in cast(list[str], child["evidence_ids"])}
    )
    if (
        packet["failure_items"] != expected_failures
        or packet["unresolved_items"] != expected_unresolved
        or packet["evidence_ids"] != expected_evidence
    ):
        raise RecoveryError("packet-summary-invalid")
    body = {
        key: child for key, child in packet.items() if key not in {"packet_id", "packet_sha256"}
    }
    digest = document_sha256(body)
    if (
        packet["packet_sha256"] != digest
        or packet["packet_id"] != f"recovery-packet:{digest.removeprefix('sha256:')}"
    ):
        raise RecoveryError("packet-digest-invalid")
    if snapshot is not None:
        selected = validate_verification_snapshot(snapshot)
        outcome = cast(dict[str, Any], selected["action_outcome"])
        if (
            packet["incident_id"] != selected["incident_id"]
            or packet["incident_version"] != selected["incident_version"]
            or packet["snapshot_id"] != selected["snapshot_id"]
            or packet["snapshot_sha256"] != selected["snapshot_sha256"]
            or packet["outcome_id"] != outcome["outcome_id"]
            or packet["outcome_sha256"] != outcome["outcome_sha256"]
        ):
            raise RecoveryError("packet-snapshot-binding-invalid")
    if evidence_request is not None:
        request = validate_evidence_request(evidence_request, snapshot=snapshot)
        if (
            packet["evidence_request_id"] != request["request_id"]
            or packet["evidence_request_sha256"] != request["request_sha256"]
            or packet["evaluation_started_at"] != request["evaluation_started_at"]
            or parse_timestamp(packet["evaluation_completed_at"])
            > parse_timestamp(request["evaluation_deadline_at"])
        ):
            raise RecoveryError("packet-request-binding-invalid")
    return packet


def validate_closure_request(value: Mapping[str, Any]) -> dict[str, Any]:
    request = _mapping(value, code="closure-request-invalid")
    validate_schema("recovery-closure-request-v1.schema.json", request)
    require_idempotency_key(request["idempotency_key"])
    reason = request["reason"]
    if (
        not isinstance(reason, str)
        or not 1 <= len(reason) <= 512
        or reason.strip() != reason
        or any(ord(character) < 32 or ord(character) == 127 for character in reason)
    ):
        raise RecoveryError("closure-reason-invalid")
    return request


def validate_closure_result(value: Mapping[str, Any]) -> dict[str, Any]:
    result = _mapping(value, code="closure-result-invalid")
    validate_schema("recovery-closure-result-v1.schema.json", result)
    body = {
        key: child for key, child in result.items() if key not in {"closure_id", "closure_sha256"}
    }
    digest = document_sha256(body)
    if (
        result["closure_sha256"] != digest
        or result["closure_id"] != f"recovery-closure:{digest.removeprefix('sha256:')}"
    ):
        raise RecoveryError("closure-result-digest-invalid")
    if result["workflow_version_after"] != result["workflow_version_before"] + 1:
        raise RecoveryError("closure-version-invalid")
    return result


def build_audit_event(
    *,
    incident_id: str,
    workflow_id: str,
    sequence: int,
    event_type: str,
    actor: Mapping[str, Any],
    snapshot_id: str,
    snapshot_sha256: str,
    outcome_id: str,
    outcome_sha256: str,
    packet_id: str | None,
    packet_sha256: str | None,
    idempotency_key: str,
    predecessor_event_sha256: str | None,
    occurred_at: str,
    details: Mapping[str, Any],
) -> dict[str, Any]:
    if event_type not in AUDIT_EVENT_TYPES:
        raise RecoveryError("audit-event-type-invalid")
    body = {
        "schema": AUDIT_EVENT_SCHEMA,
        "incident_id": require_identifier(incident_id),
        "workflow_id": require_identifier(workflow_id),
        "sequence": _positive(sequence, code="audit-sequence-invalid"),
        "event_type": event_type,
        "actor": _mapping(actor, code="audit-actor-invalid"),
        "snapshot_id": require_identifier(snapshot_id),
        "snapshot_sha256": require_digest(snapshot_sha256),
        "outcome_id": require_identifier(outcome_id),
        "outcome_sha256": require_digest(outcome_sha256),
        "packet_id": packet_id,
        "packet_sha256": packet_sha256,
        "idempotency_key": require_idempotency_key(idempotency_key),
        "predecessor_event_sha256": predecessor_event_sha256,
        "occurred_at": timestamp(parse_timestamp(occurred_at)),
        "details": _mapping(details, code="audit-details-invalid"),
    }
    if (packet_id is None) != (packet_sha256 is None):
        raise RecoveryError("audit-packet-binding-invalid")
    if packet_id is not None:
        require_identifier(packet_id, code="audit-packet-binding-invalid")
        require_digest(packet_sha256, code="audit-packet-binding-invalid")
    if predecessor_event_sha256 is not None:
        require_digest(predecessor_event_sha256, code="audit-predecessor-invalid")
    digest = document_sha256(body)
    event = {
        **body,
        "event_id": f"recovery-audit-event:{digest.removeprefix('sha256:')}",
        "event_sha256": digest,
    }
    validate_schema("recovery-audit-event-v1.schema.json", event)
    return event


def validate_audit_history(events: Sequence[Mapping[str, Any]], *, workflow_id: str) -> None:
    predecessor: str | None = None
    for sequence, raw in enumerate(events, start=1):
        event = _mapping(raw, code="audit-history-invalid")
        validate_schema("recovery-audit-event-v1.schema.json", event)
        body = {
            key: child for key, child in event.items() if key not in {"event_id", "event_sha256"}
        }
        digest = document_sha256(body)
        if (
            event["workflow_id"] != workflow_id
            or event["sequence"] != sequence
            or event["predecessor_event_sha256"] != predecessor
            or event["event_sha256"] != digest
            or event["event_id"] != f"recovery-audit-event:{digest.removeprefix('sha256:')}"
        ):
            raise RecoveryError("audit-history-invalid")
        predecessor = digest


__all__ = [
    "ACTIVE_PUBLICATION_SCHEMA",
    "ARTIFACT_ROLE_COUNTS",
    "ARTIFACT_SCHEMA",
    "AUDIT_EVENT_TYPES",
    "CHECK_NAMES",
    "CHECK_POLICIES",
    "CLOSURE_REQUEST_SCHEMA",
    "CLOSURE_RESULT_SCHEMA",
    "EVIDENCE_RECORD_SCHEMA",
    "PACKET_SCHEMA",
    "RECOVERY_STATUSES",
    "RecoveryError",
    "SNAPSHOT_SCHEMA",
    "WORKFLOW_STATUSES",
    "assess_post_action_observations",
    "build_audit_event",
    "build_check_result",
    "build_evidence_request",
    "build_evidence_record",
    "build_recovery_packet",
    "build_verification_snapshot",
    "canonical_json_bytes",
    "document_sha256",
    "parse_timestamp",
    "plain_json",
    "prefixed_sha256",
    "require_digest",
    "require_identifier",
    "require_idempotency_key",
    "strict_json_bytes",
    "timestamp",
    "validate_audit_history",
    "validate_check_result",
    "validate_closure_request",
    "validate_closure_result",
    "validate_evidence_request",
    "validate_evidence_record",
    "validate_recovery_packet",
    "validate_schema",
    "validate_verification_snapshot",
    "verification_state_sha256",
]
