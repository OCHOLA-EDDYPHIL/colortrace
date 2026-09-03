from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import timedelta
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from colortrace_grafana_mcp import AdapterError, validate_evidence_envelope
from colortrace_investigation.contracts import (
    AlertIntake,
    canonical_json_bytes,
    parse_timestamp,
    prefixed_sha256,
    strict_json_bytes,
    strict_json_file,
    timestamp,
    validate_response_packet,
)
from colortrace_investigation.contracts import (
    ContractError as InvestigationContractError,
)
from colortrace_validator import validate_result_contract
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

SCHEMA_ROOT = Path(__file__).parent / "schemas"
TASK_SCHEMA = "incident-task/v1"
REPLAY_SCHEMA = "incident-replay/v1"
CLAIM_EVENT_SCHEMA = "incident-claim-event/v1"
HUMAN_AUDIT_EVENT_SCHEMA = "incident-human-audit-event/v1"
STORE_SCHEMA_VERSION = 5
CLAIM_LEASE_SECONDS = 30
CLAIM_HEARTBEAT_SECONDS = 10
INCIDENT_STATUSES = frozenset({"queued", "running", "resolved", "unresolved"})
TASK_STATUSES = frozenset({"queued", "running", "complete"})
CLAIM_EVENT_TYPES = (
    "claim.acquired",
    "claim.migrated",
    "claim.renewed",
    "claim.cancelled",
    "claim.reclaimed",
    "claim.completed",
)
HUMAN_AUDIT_EVENT_TYPES = ("incident.admitted",)
TRACE_EVENT_TYPES = (
    "api.intake.accepted",
    "task.queued",
    "worker.started",
    "packet.persisted",
    "incident.completed",
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")
_PREFIXED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COHORT_CORRELATION_FIELDS = {
    "metric.worker-cohort": ("fixture_id", "run_id", "worker_id"),
    "log.config-cohort": ("fixture_id", "run_id", "config_sha256"),
}


class SliceContractError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def plain_json(value: Any) -> Any:
    return strict_json_bytes(canonical_json_bytes(value))


def require_identifier(value: Any, *, code: str = "identifier-invalid") -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SliceContractError(code)
    return value


def require_trace_id(value: Any) -> str:
    if not isinstance(value, str) or _TRACE_ID.fullmatch(value) is None:
        raise SliceContractError("trace-id-invalid")
    return value


def require_prefixed_digest(value: Any, *, code: str = "digest-invalid") -> str:
    if not isinstance(value, str) or _PREFIXED_DIGEST.fullmatch(value) is None:
        raise SliceContractError(code)
    return value


def normalize_timestamp(value: Any, *, code: str = "timestamp-invalid") -> str:
    if not isinstance(value, str):
        raise SliceContractError(code)
    try:
        return timestamp(parse_timestamp(value))
    except InvestigationContractError as error:
        raise SliceContractError(code) from error


def claim_expiry(value: Any) -> str:
    normalized = normalize_timestamp(value, code="claim-time-invalid")
    try:
        parsed = parse_timestamp(normalized)
    except InvestigationContractError as error:  # pragma: no cover - normalized above
        raise SliceContractError("claim-time-invalid") from error
    return timestamp(parsed + timedelta(seconds=CLAIM_LEASE_SECONDS))


@cache
def _schema_validator(name: str) -> Draft202012Validator:
    schema = strict_json_file(SCHEMA_ROOT / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_schema(name: str, value: Mapping[str, Any]) -> None:
    try:
        _schema_validator(name).validate(dict(value))
    except ValidationError as error:
        raise SliceContractError("schema-validation") from error


def alert_digest(alert: Mapping[str, Any]) -> str:
    try:
        AlertIntake.from_mapping(alert)
    except (InvestigationContractError, TypeError, ValueError) as error:
        raise SliceContractError("alert-invalid") from error
    return prefixed_sha256(canonical_json_bytes(alert))


def stable_task_id(incident_id: str, digest: str) -> str:
    require_identifier(incident_id)
    require_prefixed_digest(digest)
    identity = {
        "schema": TASK_SCHEMA,
        "incident_id": incident_id,
        "alert_sha256": digest,
    }
    return f"task:{prefixed_sha256(canonical_json_bytes(identity)).removeprefix('sha256:')}"


def build_task_envelope(
    alert: Mapping[str, Any], *, created_at: str, expected_incident_version: int = 1
) -> dict[str, Any]:
    intake = AlertIntake.from_mapping(alert)
    digest = alert_digest(alert)
    task = {
        "schema": TASK_SCHEMA,
        "task_id": stable_task_id(intake.incident_id, digest),
        "incident_id": intake.incident_id,
        "expected_incident_version": expected_incident_version,
        "alert_sha256": digest,
        "trace_id": require_trace_id(intake.correlation_keys["trace_id"]),
        "created_at": created_at,
    }
    validate_schema("incident-task-v1.schema.json", task)
    return task


def trace_span_id(*, incident_id: str, sequence: int, event_type: str, payload_sha256: str) -> str:
    value = {
        "incident_id": incident_id,
        "sequence": sequence,
        "event_type": event_type,
        "payload_sha256": payload_sha256,
    }
    return prefixed_sha256(canonical_json_bytes(value)).removeprefix("sha256:")[:16]


def build_trace_event(
    *,
    incident_id: str,
    sequence: int,
    event_type: str,
    trace_id: str,
    parent_span_id: str | None,
    predecessor_event_sha256: str | None,
    payload: Mapping[str, Any],
    occurred_at: str,
) -> dict[str, Any]:
    if event_type not in TRACE_EVENT_TYPES:
        raise SliceContractError("event-type-invalid")
    payload_value = cast(dict[str, Any], plain_json(payload))
    payload_sha256 = prefixed_sha256(canonical_json_bytes(payload_value))
    body = {
        "schema": "incident-trace-event/v1",
        "incident_id": require_identifier(incident_id),
        "sequence": sequence,
        "event_type": event_type,
        "trace_id": require_trace_id(trace_id),
        "span_id": trace_span_id(
            incident_id=incident_id,
            sequence=sequence,
            event_type=event_type,
            payload_sha256=payload_sha256,
        ),
        "parent_span_id": parent_span_id,
        "predecessor_event_sha256": predecessor_event_sha256,
        "payload": payload_value,
        "payload_sha256": payload_sha256,
        "occurred_at": occurred_at,
    }
    event_sha256 = prefixed_sha256(canonical_json_bytes(body))
    event = {**body, "event_id": f"event:{event_sha256.removeprefix('sha256:')}"}
    event["event_sha256"] = event_sha256
    validate_schema("incident-trace-event-v1.schema.json", event)
    return event


def build_claim_event(
    *,
    task_id: str,
    incident_id: str,
    sequence: int,
    event_type: str,
    owner: str,
    generation: int,
    lease_expires_at: str,
    predecessor_event_sha256: str | None,
    occurred_at: str,
) -> dict[str, Any]:
    if event_type not in CLAIM_EVENT_TYPES:
        raise SliceContractError("claim-event-type-invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise SliceContractError("claim-event-sequence-invalid")
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise SliceContractError("claim-generation-invalid")
    body = {
        "schema": CLAIM_EVENT_SCHEMA,
        "task_id": require_identifier(task_id),
        "incident_id": require_identifier(incident_id),
        "sequence": sequence,
        "event_type": event_type,
        "owner": require_identifier(owner, code="claim-owner-invalid"),
        "generation": generation,
        "lease_expires_at": normalize_timestamp(lease_expires_at, code="claim-expiry-invalid"),
        "predecessor_event_sha256": predecessor_event_sha256,
        "occurred_at": normalize_timestamp(occurred_at, code="claim-time-invalid"),
    }
    event_sha256 = prefixed_sha256(canonical_json_bytes(body))
    event = {
        **body,
        "event_id": f"claim-event:{event_sha256.removeprefix('sha256:')}",
        "event_sha256": event_sha256,
    }
    validate_schema("incident-claim-event-v1.schema.json", event)
    return event


def human_audit_actor(value: Mapping[str, Any]) -> dict[str, str]:
    if set(value) != {
        "subject",
        "display_name",
        "issuer",
        "audience",
        "principal_kind",
    }:
        raise SliceContractError("human-audit-actor-invalid")
    subject = value.get("subject")
    display_name = value.get("display_name")
    issuer = value.get("issuer")
    audience = value.get("audience")
    principal_kind = value.get("principal_kind")
    if (
        not isinstance(subject, str)
        or not subject
        or len(subject) > 256
        or subject.strip() != subject
        or not isinstance(display_name, str)
        or not display_name
        or len(display_name) > 256
        or display_name.strip() != display_name
        or not isinstance(issuer, str)
        or not issuer
        or len(issuer) > 2_048
        or issuer.strip() != issuer
        or not isinstance(audience, str)
        or not audience
        or len(audience) > 4_096
        or audience.strip() != audience
        or principal_kind != "human"
    ):
        raise SliceContractError("human-audit-actor-invalid")
    return {
        "subject": subject,
        "display_name": display_name,
        "issuer": issuer,
        "audience": audience,
        "principal_kind": "human",
    }


def build_human_audit_event(
    *,
    incident_id: str,
    sequence: int,
    event_type: str,
    actor: Mapping[str, Any],
    predecessor_event_sha256: str | None,
    occurred_at: str,
    citations: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if event_type not in HUMAN_AUDIT_EVENT_TYPES:
        raise SliceContractError("human-audit-event-type-invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise SliceContractError("human-audit-sequence-invalid")
    citation_values = cast(list[dict[str, Any]], plain_json(citations))
    body = {
        "schema": HUMAN_AUDIT_EVENT_SCHEMA,
        "incident_id": require_identifier(incident_id),
        "sequence": sequence,
        "event_type": event_type,
        "actor": human_audit_actor(actor),
        "predecessor_event_sha256": predecessor_event_sha256,
        "occurred_at": normalize_timestamp(occurred_at, code="human-audit-time-invalid"),
        "citations": citation_values,
    }
    event_sha256 = prefixed_sha256(canonical_json_bytes(body))
    event = {
        **body,
        "event_id": f"human-audit-event:{event_sha256.removeprefix('sha256:')}",
        "event_sha256": event_sha256,
    }
    validate_schema("incident-human-audit-event-v1.schema.json", event)
    return event


def validate_human_audit_events(events: Sequence[Mapping[str, Any]], *, incident_id: str) -> None:
    expected_incident = require_identifier(incident_id)
    predecessor: str | None = None
    for sequence, event in enumerate(events, start=1):
        validate_schema("incident-human-audit-event-v1.schema.json", event)
        body = {
            key: child for key, child in event.items() if key not in {"event_id", "event_sha256"}
        }
        expected_digest = prefixed_sha256(canonical_json_bytes(body))
        if (
            event.get("incident_id") != expected_incident
            or event.get("sequence") != sequence
            or event.get("predecessor_event_sha256") != predecessor
            or event.get("event_sha256") != expected_digest
            or event.get("event_id")
            != f"human-audit-event:{expected_digest.removeprefix('sha256:')}"
        ):
            raise SliceContractError("human-audit-event-binding")
        human_audit_actor(cast(Mapping[str, Any], event["actor"]))
        predecessor = expected_digest


def validate_claim_events(
    events: Sequence[Mapping[str, Any]], *, task_id: str, incident_id: str
) -> None:
    expected_task = require_identifier(task_id)
    expected_incident = require_identifier(incident_id)
    predecessor: str | None = None
    previous: Mapping[str, Any] | None = None
    terminal = False
    for sequence, event in enumerate(events, start=1):
        validate_schema("incident-claim-event-v1.schema.json", event)
        body = {
            key: child for key, child in event.items() if key not in {"event_id", "event_sha256"}
        }
        expected_digest = prefixed_sha256(canonical_json_bytes(body))
        if (
            event.get("task_id") != expected_task
            or event.get("incident_id") != expected_incident
            or event.get("sequence") != sequence
            or event.get("predecessor_event_sha256") != predecessor
            or event.get("event_sha256") != expected_digest
            or event.get("event_id") != f"claim-event:{expected_digest.removeprefix('sha256:')}"
        ):
            raise SliceContractError("claim-event-binding")
        event_type = cast(str, event["event_type"])
        owner = cast(str, event["owner"])
        generation = cast(int, event["generation"])
        try:
            occurred_at = parse_timestamp(cast(str, event["occurred_at"]))
            expires_at = parse_timestamp(cast(str, event["lease_expires_at"]))
        except InvestigationContractError as error:
            raise SliceContractError("claim-event-binding") from error
        if terminal:
            raise SliceContractError("claim-event-binding")
        if previous is None:
            if event_type not in {"claim.acquired", "claim.migrated"} or generation != 1:
                raise SliceContractError("claim-event-binding")
            if expires_at - occurred_at != timedelta(seconds=CLAIM_LEASE_SECONDS):
                raise SliceContractError("claim-event-binding")
        else:
            previous_type = cast(str, previous["event_type"])
            previous_owner = cast(str, previous["owner"])
            previous_generation = cast(int, previous["generation"])
            previous_occurred_at = parse_timestamp(cast(str, previous["occurred_at"]))
            previous_expiry = parse_timestamp(cast(str, previous["lease_expires_at"]))
            if occurred_at < previous_occurred_at or previous_type == "claim.completed":
                raise SliceContractError("claim-event-binding")
            if previous_type == "claim.cancelled" and event_type not in {
                "claim.cancelled",
                "claim.reclaimed",
            }:
                raise SliceContractError("claim-event-binding")
            if event_type == "claim.reclaimed":
                if generation != previous_generation + 1 or occurred_at < previous_expiry:
                    raise SliceContractError("claim-event-binding")
                if expires_at - occurred_at != timedelta(seconds=CLAIM_LEASE_SECONDS):
                    raise SliceContractError("claim-event-binding")
            elif event_type == "claim.renewed":
                if (
                    generation != previous_generation
                    or owner != previous_owner
                    or occurred_at >= previous_expiry
                    or expires_at <= previous_expiry
                    or expires_at - occurred_at != timedelta(seconds=CLAIM_LEASE_SECONDS)
                ):
                    raise SliceContractError("claim-event-binding")
            elif event_type == "claim.cancelled":
                if (
                    generation != previous_generation
                    or owner != previous_owner
                    or expires_at > occurred_at
                    or expires_at > previous_expiry
                ):
                    raise SliceContractError("claim-event-binding")
            elif event_type == "claim.completed":
                if (
                    generation != previous_generation
                    or owner != previous_owner
                    or occurred_at >= previous_expiry
                    or expires_at != previous_expiry
                ):
                    raise SliceContractError("claim-event-binding")
                terminal = True
            else:
                raise SliceContractError("claim-event-binding")
        predecessor = expected_digest
        previous = event


def validate_trace_events(
    events: Sequence[Mapping[str, Any]], *, incident_id: str, trace_id: str
) -> None:
    if len(events) != len(TRACE_EVENT_TYPES):
        raise SliceContractError("trace-incomplete")
    predecessor: str | None = None
    parent: str | None = None
    for sequence, (event, expected_type) in enumerate(
        zip(events, TRACE_EVENT_TYPES, strict=True), start=1
    ):
        validate_schema("incident-trace-event-v1.schema.json", event)
        body = {
            key: child for key, child in event.items() if key not in {"event_id", "event_sha256"}
        }
        expected_digest = prefixed_sha256(canonical_json_bytes(body))
        payload = cast(Mapping[str, Any], event["payload"])
        if (
            event["incident_id"] != incident_id
            or event["trace_id"] != trace_id
            or event["sequence"] != sequence
            or event["event_type"] != expected_type
            or event["predecessor_event_sha256"] != predecessor
            or event["parent_span_id"] != parent
            or event["payload_sha256"] != prefixed_sha256(canonical_json_bytes(payload))
            or event["event_sha256"] != expected_digest
            or event["event_id"] != f"event:{expected_digest.removeprefix('sha256:')}"
        ):
            raise SliceContractError("trace-binding")
        span_id = cast(str, event["span_id"])
        predecessor = expected_digest
        parent = span_id


def _validator_evidence_ids(result: Mapping[str, Any]) -> set[str]:
    evidence = result.get("evidence")
    if not isinstance(evidence, Sequence) or isinstance(evidence, (str, bytes, bytearray)):
        raise SliceContractError("validator-result-invalid")
    identifiers: set[str] = set()
    for item in evidence:
        if not isinstance(item, Mapping):
            raise SliceContractError("validator-result-invalid")
        identifiers.add(require_identifier(item.get("evidence_id")))
    claims = result.get("claims")
    if not isinstance(claims, Sequence) or isinstance(claims, (str, bytes, bytearray)):
        raise SliceContractError("validator-result-invalid")
    for claim in claims:
        if not isinstance(claim, Mapping):
            raise SliceContractError("validator-result-invalid")
        deterministic_id = claim.get("deterministic_result_evidence_id")
        if deterministic_id is not None:
            identifiers.add(require_identifier(deterministic_id))
    return identifiers


def _validate_adaptive_trace_evidence(
    packet: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]]
) -> None:
    if packet.get("schema") != "response-packet/v2":
        return
    evidence_order = [cast(str, envelope["evidence_id"]) for envelope in evidence]
    evidence_by_id = {cast(str, envelope["evidence_id"]): envelope for envelope in evidence}
    traced_evidence: list[str] = []
    for entry in cast(Sequence[Mapping[str, Any]], packet.get("adaptive_trace", ())):
        evidence_id = entry.get("evidence_id")
        if evidence_id is None:
            continue
        envelope = evidence_by_id.get(cast(str, evidence_id))
        observation = None if envelope is None else envelope.get("observation")
        if (
            envelope is None
            or not isinstance(observation, Mapping)
            or entry.get("query_key") != observation.get("query_key")
        ):
            raise SliceContractError("adaptive-trace-evidence-binding")
        traced_evidence.append(cast(str, evidence_id))
    if traced_evidence != evidence_order:
        raise SliceContractError("adaptive-trace-evidence-binding")


def _validate_replay_bindings(value: Mapping[str, Any]) -> None:
    incident = cast(Mapping[str, Any], value["incident"])
    task = cast(Mapping[str, Any], value["task"])
    alert = cast(Mapping[str, Any], value["alert"])
    packet = cast(Mapping[str, Any], value["packet"])
    batches = cast(Sequence[Mapping[str, Any]], value["evidence_batches"])
    evidence = cast(Sequence[Mapping[str, Any]], value["evidence"])
    validator_results = cast(Sequence[Mapping[str, Any]], value["validator_results"])
    invocations = cast(Sequence[Mapping[str, Any]], value["invocations"])
    events = cast(Sequence[Mapping[str, Any]], value["trace_events"])

    intake = AlertIntake.from_mapping(alert)
    validate_response_packet(packet)
    validate_schema("incident-task-v1.schema.json", task)
    digest = alert_digest(alert)
    expected_task_id = stable_task_id(intake.incident_id, digest)
    trace_id = require_trace_id(intake.correlation_keys["trace_id"])
    if (
        incident.get("incident_id") != intake.incident_id
        or incident.get("alert_id") != intake.alert_id
        or incident.get("trace_id") != trace_id
        or incident.get("alert_sha256") != digest
        or incident.get("packet_id") != packet.get("packet_id")
        or incident.get("status") != packet.get("status")
        or task.get("task_id") != expected_task_id
        or task.get("incident_id") != intake.incident_id
        or task.get("alert_sha256") != digest
        or task.get("trace_id") != trace_id
        or task.get("status") != "complete"
        or task.get("packet_id") != packet.get("packet_id")
        or task.get("expected_incident_version") != 1
        or incident.get("version") != 3
        or packet.get("incident_id") != intake.incident_id
    ):
        raise SliceContractError("replay-binding")

    operational_ids: set[str] = set()
    evidence_predecessor: str | None = None
    for envelope in evidence:
        try:
            validate_evidence_envelope(envelope)
        except (AdapterError, TypeError, ValueError) as error:
            raise SliceContractError("evidence-invalid") from error
        if envelope.get("incident_id") != intake.incident_id:
            raise SliceContractError("evidence-binding")
        observation = envelope.get("observation")
        if not isinstance(observation, Mapping):
            raise SliceContractError("evidence-binding")
        query_key = observation.get("query_key")
        if not isinstance(query_key, str):
            raise SliceContractError("evidence-binding")
        fields = _COHORT_CORRELATION_FIELDS.get(query_key, tuple(intake.correlation_keys))
        expected_correlation = {
            field: intake.correlation_keys[field]
            for field in fields
            if field in intake.correlation_keys
        }
        correlation = envelope.get("correlation_keys")
        if not isinstance(correlation, Mapping) or dict(correlation) != expected_correlation:
            raise SliceContractError("evidence-binding")
        evidence_id = require_prefixed_digest(envelope.get("evidence_id"))
        if envelope.get("predecessor_event_sha256") != evidence_predecessor:
            raise SliceContractError("evidence-binding")
        operational_ids.add(evidence_id)
        evidence_predecessor = evidence_id
    if len(operational_ids) != len(evidence):
        raise SliceContractError("evidence-duplicate")
    if len(batches) > 1:
        raise SliceContractError("evidence-batch-duplicate")
    if batches:
        batch = batches[0]
        batch_envelopes = batch.get("envelopes")
        attempts = batch.get("attempts")
        envelope_schemas = {
            envelope.get("schema") for envelope in evidence if isinstance(envelope, Mapping)
        }
        expected_batch_schema = (
            "grafana-evidence-batch-result/v1"
            if envelope_schemas == {"evidence-envelope/v1"}
            else (
                "grafana-evidence-batch-result/v2"
                if envelope_schemas == {"evidence-envelope/v2"}
                else None
            )
        )
        if (
            batch.get("schema") != expected_batch_schema
            or not isinstance(batch_envelopes, Sequence)
            or isinstance(batch_envelopes, (str, bytes, bytearray))
            or list(batch_envelopes) != list(evidence)
            or not isinstance(attempts, Sequence)
            or isinstance(attempts, (str, bytes, bytearray))
            or batch.get("tool_calls_used") != len(attempts)
            or batch.get("maximum_calls_in_flight_observed") not in {0, 1, 2}
        ):
            raise SliceContractError("evidence-batch-binding")
    elif evidence:
        raise SliceContractError("evidence-batch-missing")

    _validate_adaptive_trace_evidence(packet, evidence)

    validator_ids: set[str] = set()
    validator_evidence: set[str] = set()
    for result in validator_results:
        try:
            validate_result_contract(dict(result))
        except (TypeError, ValueError) as error:
            raise SliceContractError("validator-result-invalid") from error
        if result.get("incident_id") != intake.incident_id:
            raise SliceContractError("validator-result-binding")
        validator_ids.add(require_identifier(result.get("result_id")))
        validator_evidence.update(_validator_evidence_ids(result))
    if len(validator_ids) != len(validator_results):
        raise SliceContractError("validator-result-duplicate")

    if list(invocations) != packet.get("invocation_records"):
        raise SliceContractError("invocation-binding")
    for invocation in invocations:
        if (
            invocation.get("incident_id") != intake.incident_id
            or invocation.get("trace_id") != trace_id
        ):
            raise SliceContractError("invocation-binding")

    deterministic_ids = {
        require_identifier(claim.get("deterministic_result_evidence_id"))
        for claim in cast(Sequence[Mapping[str, Any]], packet.get("claims", ()))
        if claim.get("deterministic_result_evidence_id") is not None
    }
    packet_evidence = set(cast(Sequence[str], packet.get("evidence_ids", ())))
    if not packet_evidence.issubset(operational_ids | validator_evidence | deterministic_ids):
        raise SliceContractError("evidence-replay-incomplete")
    packet_result_ids = {
        require_identifier(item.get("result_id"))
        for item in cast(Sequence[Mapping[str, Any]], packet.get("deterministic_results", ()))
    }
    if packet_result_ids != validator_ids:
        raise SliceContractError("validator-result-binding")
    validate_trace_events(events, incident_id=intake.incident_id, trace_id=trace_id)
    expected_payloads = [
        {
            "alert_id": intake.alert_id,
            "alert_sha256": digest,
            "source_predecessor_event_sha256": intake.predecessor_event_sha256,
        },
        {
            "task_id": expected_task_id,
            "expected_incident_version": 1,
            "payload_sha256": digest,
        },
        {
            "task_id": expected_task_id,
            "expected_incident_version": 1,
            "payload_sha256": digest,
        },
        {
            "packet_id": packet["packet_id"],
            "packet_sha256": prefixed_sha256(canonical_json_bytes(packet)),
            "status": packet["status"],
            "evidence_records": len(evidence),
            "evidence_batches": len(batches),
            "validator_results": len(validator_results),
            "invocation_records": len(invocations),
        },
        {
            "task_id": expected_task_id,
            "packet_id": packet["packet_id"],
            "status": packet["status"],
            "incident_version": 3,
        },
    ]
    if [event.get("payload") for event in events] != expected_payloads:
        raise SliceContractError("trace-payload-binding")


def finalize_replay(body: Mapping[str, Any]) -> dict[str, Any]:
    plain = cast(dict[str, Any], plain_json(body))
    derivation = prefixed_sha256(canonical_json_bytes(plain))
    replay = {**plain, "derivation_sha256": derivation}
    validate_replay(replay)
    return {key: replay[key] for key in sorted(replay)}


def validate_replay(value: Mapping[str, Any]) -> None:
    validate_schema("incident-replay-v1.schema.json", value)
    body = {key: child for key, child in value.items() if key != "derivation_sha256"}
    if value.get("derivation_sha256") != prefixed_sha256(canonical_json_bytes(body)):
        raise SliceContractError("replay-digest")
    try:
        _validate_replay_bindings(value)
    except (InvestigationContractError, KeyError, TypeError, ValueError) as error:
        raise SliceContractError("replay-binding") from error


def readonly_mapping(value: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(cast(dict[str, Any], plain_json(value)))


__all__ = [
    "CLAIM_EVENT_SCHEMA",
    "CLAIM_EVENT_TYPES",
    "CLAIM_HEARTBEAT_SECONDS",
    "CLAIM_LEASE_SECONDS",
    "INCIDENT_STATUSES",
    "REPLAY_SCHEMA",
    "STORE_SCHEMA_VERSION",
    "SliceContractError",
    "TASK_SCHEMA",
    "TASK_STATUSES",
    "TRACE_EVENT_TYPES",
    "alert_digest",
    "build_claim_event",
    "build_task_envelope",
    "build_trace_event",
    "canonical_json_bytes",
    "claim_expiry",
    "finalize_replay",
    "normalize_timestamp",
    "plain_json",
    "prefixed_sha256",
    "readonly_mapping",
    "require_identifier",
    "require_prefixed_digest",
    "require_trace_id",
    "stable_task_id",
    "strict_json_bytes",
    "timestamp",
    "validate_claim_events",
    "validate_replay",
    "validate_schema",
]
