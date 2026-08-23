from __future__ import annotations

import inspect
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import pytest
from colortrace_telemetry.action_contract import (
    build_action_receipt,
    validate_action_outcome,
    validate_action_receipt,
)
from colortrace_telemetry.action_emitter import (
    LOCAL_ACTION_OTLP_ENDPOINT,
    ActionOtelSink,
    ActionTelemetryEvent,
    MemoryActionTelemetrySink,
    _flat_action_attributes,
    _metric_action_attributes,
    build_action_events,
    emit_action_outcome,
)
from colortrace_telemetry.contract import canonical_json_bytes, sha256_bytes


def _digest(character: str) -> str:
    return f"sha256:{character * 64}"


def _target(kind: str, identifier: str) -> dict[str, str]:
    return {
        "schema": "simulator-target/v1",
        "namespace": "colortrace-simulator",
        "kind": kind,
        "id": identifier,
    }


def _command_result(
    command_id: str,
    result_kind: str,
    target: Mapping[str, str],
    trace_id: str,
    before: Mapping[str, str],
    after: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "schema": "simulator-command-result/v1",
        "command_id": command_id,
        "result_kind": result_kind,
        "target": dict(target),
        "trace_id": trace_id,
        "before": dict(before),
        "after": dict(after),
    }


def _seal(outcome: dict[str, Any]) -> dict[str, Any]:
    body = {
        key: child for key, child in outcome.items() if key not in {"outcome_id", "outcome_sha256"}
    }
    suffix = sha256_bytes(canonical_json_bytes(body))
    outcome["outcome_id"] = f"simulator-action-outcome:{suffix}"
    outcome["outcome_sha256"] = f"sha256:{suffix}"
    return outcome


def successful_outcome() -> dict[str, Any]:
    targets = [
        _target("color-resource", _digest("1")),
        _target("derivative", "derivative-affected"),
        _target("frame", "frame-affected-a"),
        _target("frame", "frame-affected-b"),
        _target("frame", "frame-affected-c"),
    ]
    exclusions = [
        _target("frame", "frame-safe-a"),
        _target("frame", "frame-safe-b"),
        _target("frame", "frame-safe-c"),
    ]
    command_outcomes = [
        _command_result(
            "command-01-quarantine",
            "quarantine",
            targets[0],
            "1" * 32,
            {"resource_sha256": _digest("1")},
            {"resource_sha256": _digest("2")},
        ),
        _command_result(
            "command-02-derivative",
            "derivative",
            targets[1],
            "2" * 32,
            {
                "derivative_sha256": _digest("3"),
                "derivative_display_sha256": _digest("4"),
            },
            {
                "derivative_sha256": _digest("5"),
                "derivative_display_sha256": _digest("6"),
            },
        ),
        _command_result(
            "command-03-frame-a",
            "frame",
            targets[2],
            "3" * 32,
            {"output_sha256": _digest("7"), "display_sha256": _digest("8")},
            {"output_sha256": _digest("9"), "display_sha256": _digest("a")},
        ),
        _command_result(
            "command-04-frame-b",
            "frame",
            targets[3],
            "4" * 32,
            {"output_sha256": _digest("b"), "display_sha256": _digest("c")},
            {"output_sha256": _digest("d"), "display_sha256": _digest("e")},
        ),
        _command_result(
            "command-05-frame-c",
            "frame",
            targets[4],
            "5" * 32,
            {"output_sha256": _digest("f"), "display_sha256": _digest("1")},
            {"output_sha256": _digest("2"), "display_sha256": _digest("3")},
        ),
    ]
    return _seal(
        {
            "schema": "simulator-action-outcome/v1",
            "outcome_id": "pending",
            "outcome_sha256": _digest("0"),
            "admission_id": f"simulator-admission:{'1' * 64}",
            "admission_sha256": _digest("1"),
            "action_id": f"simulator-action:{'2' * 64}",
            "task_key": f"dispatch-task:{'3' * 64}",
            "operation_id": f"dispatch-operation:{'3' * 64}",
            "payload_sha256": _digest("4"),
            "status": "succeeded",
            "reason_codes": [],
            "fixture_id": "ct-shadowed-lut-v1",
            "incident_id": "incident-action-01",
            "incident_version": 4,
            "plan_id": f"response-plan:{'5' * 64}",
            "plan_version": 2,
            "plan_sha256": _digest("5"),
            "approval_id": f"response-plan-decision:{'6' * 64}",
            "approval_sha256": _digest("6"),
            "authorization_id": f"dispatch-authorization:{'7' * 64}",
            "authorization_sha256": _digest("7"),
            "consumption_id": f"dispatch-consumption:{'8' * 64}",
            "consumption_sha256": _digest("8"),
            "dispatch_bundle_sha256": _digest("9"),
            "action_envelope_sha256": _digest("a"),
            "action_started_at": "2026-08-13T12:00:00.000Z",
            "publication_intent_id": f"simulator-publication-intent:{'a' * 64}",
            "publication_intent_sha256": _digest("a"),
            "publication_receipt_id": f"simulator-publication-receipt:{'b' * 64}",
            "publication_receipt_sha256": _digest("b"),
            "publication_promoted_at": "2026-08-13T12:00:01.000Z",
            "completed_at": "2026-08-13T12:00:02.000Z",
            "predecessor_publication_pointer_sha256": _digest("c"),
            "predecessor_publication_generation": 7,
            "candidate_publication_pointer_sha256": _digest("d"),
            "candidate_publication_generation": 8,
            "source_generation": 7,
            "candidate_generation": 8,
            "source_batch_id": "fixture-run-canonical",
            "source_batch_sha256": _digest("e"),
            "candidate_fixture_manifest_sha256": _digest("f"),
            "candidate_runtime_manifest_sha256": _digest("1"),
            "candidate_lineage_manifest_sha256": _digest("2"),
            "declared_resource_manifest_sha256": _digest("3"),
            "active_publication_pointer_sha256": _digest("d"),
            "active_runtime_manifest_sha256": _digest("1"),
            "preservation_manifest_sha256": _digest("4"),
            "safe_complement_before_sha256": _digest("5"),
            "safe_complement_after_sha256": _digest("5"),
            "safe_complement_proof_sha256": _digest("6"),
            "candidate_seal_sha256": _digest("7"),
            "candidate_tree_sha256": _digest("8"),
            "targets": targets,
            "exclusions": exclusions,
            "command_outcomes": command_outcomes,
            "new_trace_ids": [f"{index:x}" * 32 for index in range(1, 6)],
        }
    )


def failed_outcome() -> dict[str, Any]:
    outcome = successful_outcome()
    outcome["status"] = "failed"
    outcome["reason_codes"] = ["precondition-failed"]
    outcome["publication_intent_id"] = None
    outcome["publication_intent_sha256"] = None
    outcome["publication_receipt_id"] = None
    outcome["publication_receipt_sha256"] = None
    for name in (
        "fixture_id",
        "publication_promoted_at",
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
    ):
        outcome[name] = None
    outcome["command_outcomes"] = []
    outcome["new_trace_ids"] = []
    return _seal(outcome)


NOW = datetime(2026, 8, 13, 12, 0, 3, tzinfo=UTC)


def test_success_projects_exact_results_authority_and_safe_exclusions() -> None:
    outcome = successful_outcome()
    sink = MemoryActionTelemetrySink()
    receipt = emit_action_outcome(outcome, sink, clock=lambda: NOW)

    assert receipt["status"] == "emitted"
    assert receipt["error_code"] is None
    assert receipt["event_ids"] == receipt["emitted_event_ids"]
    assert len(sink.events) == 21
    assert len(set(receipt["event_ids"])) == 21

    command_events = [
        event
        for event in sink.events
        if event["observation"]["schema"] == "simulator-command-observation/v1"
    ]
    safe_events = [
        event
        for event in sink.events
        if event["observation"]["schema"] == "simulator-safe-preservation-observation/v1"
    ]
    assert len(command_events) == 15
    assert len(safe_events) == 6
    assert {event["signal"] for event in command_events} == {"metric", "log", "trace"}
    assert {event["signal"] for event in safe_events} == {"metric", "log"}
    assert {event["correlation"]["trace_id"] for event in command_events} == set(
        outcome["new_trace_ids"]
    )
    assert {event["correlation"]["trace_id"] for event in safe_events} == {None}
    assert {event["observation"]["target"]["id"] for event in safe_events} == {
        target["id"] for target in outcome["exclusions"]
    }
    assert all(
        event["publication"]["candidate_lineage_manifest_sha256"]
        == outcome["candidate_lineage_manifest_sha256"]
        and event["publication"]["safe_complement_proof_sha256"]
        == outcome["safe_complement_proof_sha256"]
        for event in sink.events
    )
    assert all(
        event["correlation"]["admission_id"] == outcome["admission_id"]
        and event["correlation"]["fixture_id"] == outcome["fixture_id"]
        and event["correlation"]["incident_version"] == outcome["incident_version"]
        for event in sink.events
    )
    assert b"recovery_verified" not in canonical_json_bytes(sink.events)


def test_retried_delivery_reuses_event_and_execution_trace_ids() -> None:
    outcome = successful_outcome()
    first = MemoryActionTelemetrySink()
    second = MemoryActionTelemetrySink()
    first_receipt = emit_action_outcome(outcome, first, clock=lambda: NOW)
    later = datetime(2026, 8, 13, 12, 1, 3, tzinfo=UTC)
    second_receipt = emit_action_outcome(outcome, second, clock=lambda: later)

    assert first_receipt["event_ids"] == second_receipt["event_ids"]
    assert [event["event_id"] for event in first.events] == [
        event["event_id"] for event in second.events
    ]
    assert [event["correlation"]["trace_id"] for event in first.events] == [
        event["correlation"]["trace_id"] for event in second.events
    ]
    assert {event["emitted_at"] for event in first.events} == {"2026-08-13T12:00:03.000Z"}
    assert {event["emitted_at"] for event in second.events} == {"2026-08-13T12:01:03.000Z"}


class FailingSink:
    def __init__(self, *, fail_emit_at: int | None = None, fail_flush: bool = False) -> None:
        self.fail_emit_at = fail_emit_at
        self.fail_flush = fail_flush
        self.calls = 0
        self.events: list[str] = []
        self.shutdown_called = False

    def emit(self, event: ActionTelemetryEvent) -> None:
        self.calls += 1
        if self.fail_emit_at == self.calls:
            raise RuntimeError("bounded sink failure")
        self.events.append(event.event_id)

    def force_flush(self) -> None:
        if self.fail_flush:
            raise RuntimeError("bounded flush failure")

    def shutdown(self) -> None:
        self.shutdown_called = True


def test_sink_failures_return_durable_retry_receipts_without_owning_lifecycle() -> None:
    outcome = successful_outcome()
    emit_failure = FailingSink(fail_emit_at=3)
    receipt = emit_action_outcome(outcome, emit_failure, clock=lambda: NOW)
    assert receipt["status"] == "failed"
    assert receipt["error_code"] == "sink-emit-failed"
    assert receipt["emitted_event_ids"] == receipt["event_ids"][:2]
    assert emit_failure.shutdown_called is False

    flush_failure = FailingSink(fail_flush=True)
    flush_receipt = emit_action_outcome(outcome, flush_failure, clock=lambda: NOW)
    assert flush_receipt["status"] == "failed"
    assert flush_receipt["error_code"] == "sink-flush-failed"
    assert flush_receipt["emitted_event_ids"] == flush_receipt["event_ids"]
    assert flush_failure.shutdown_called is False

    retry = FailingSink()
    retry_receipt = emit_action_outcome(outcome, retry, clock=lambda: NOW)
    assert retry_receipt["event_ids"] == receipt["event_ids"]
    assert retry_receipt["status"] == "emitted"


def test_failed_action_emits_only_non_trace_failure_observations() -> None:
    outcome = failed_outcome()
    sink = MemoryActionTelemetrySink()
    receipt = emit_action_outcome(outcome, sink, clock=lambda: NOW)

    assert receipt["status"] == "emitted"
    assert len(sink.events) == 2
    assert {event["signal"] for event in sink.events} == {"metric", "log"}
    assert all(event["publication"] is None for event in sink.events)
    assert all(event["publication_promoted_at"] is None for event in sink.events)
    assert all(event["correlation"]["trace_id"] is None for event in sink.events)
    assert all(
        event["observation"]["reason_codes"] == ["precondition-failed"] for event in sink.events
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"recovery_verified": True}),
        lambda value: value["new_trace_ids"].reverse(),
        lambda value: value.update({"safe_complement_after_sha256": _digest("9")}),
        lambda value: value.update({"candidate_runtime_manifest_sha256": _digest("9")}),
        lambda value: value["command_outcomes"][0].update({"trace_id": "0" * 32}),
        lambda value: value.pop("candidate_lineage_manifest_sha256"),
    ],
)
def test_outcome_projection_fails_closed_on_extra_stale_or_crossed_evidence(
    mutation: Any,
) -> None:
    outcome = successful_outcome()
    mutation(outcome)
    _seal(outcome)
    with pytest.raises(ValueError):
        validate_action_outcome(outcome)


def test_outcome_and_receipt_hashes_detect_tampering() -> None:
    outcome = successful_outcome()
    outcome["plan_version"] = 3
    with pytest.raises(ValueError, match="outcome digest"):
        validate_action_outcome(outcome)

    validated = validate_action_outcome(successful_outcome())
    event_ids = tuple(
        event.event_id
        for event in build_action_events(validated.document, emitted_at="2026-08-13T12:00:03.000Z")
    )
    receipt = build_action_receipt(
        validated,
        attempted_at="2026-08-13T12:00:03.000Z",
        event_ids=event_ids,
        emitted_event_ids=event_ids,
        error_code=None,
    )
    receipt["attempted_at"] = "2026-08-13T12:00:04.000Z"
    with pytest.raises(ValueError, match="receipt digest"):
        validate_action_receipt(receipt)


def test_precompletion_emission_is_rejected_before_sink_use() -> None:
    sink = FailingSink()
    early = datetime(2026, 8, 13, 12, 0, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="predates action completion"):
        emit_action_outcome(successful_outcome(), sink, clock=lambda: early)
    assert sink.calls == 0


def test_action_otel_sink_has_a_safe_default_and_bounded_endpoint_input() -> None:
    constructor = inspect.signature(ActionOtelSink)
    emit = inspect.signature(ActionOtelSink.emit)
    assert constructor.parameters["endpoint"].default == LOCAL_ACTION_OTLP_ENDPOINT
    assert list(emit.parameters) == ["self", "event"]
    assert LOCAL_ACTION_OTLP_ENDPOINT == "http://127.0.0.1:14318"

    for value in (
        "file:///tmp/collector",
        "http://user:secret@collector:4318",
        "http://collector:4318/path",
        "http://collector:4318?token=secret",
    ):
        with pytest.raises(ValueError, match="endpoint is invalid"):
            ActionOtelSink(value)

    configured = ActionOtelSink("http://otel.internal:4318/")
    try:
        assert configured.endpoint == "http://otel.internal:4318"
    finally:
        configured.shutdown()


def test_metric_projection_omits_redundant_publication_labels_only() -> None:
    events = build_action_events(successful_outcome(), emitted_at="2026-08-13T12:00:03.000Z")
    metric = next(event.to_dict() for event in events if event.signal == "metric")
    complete = _flat_action_attributes(metric)
    projected = _metric_action_attributes(metric)

    assert len(projected) < 58
    assert not any(name.startswith("publication.") for name in projected)
    assert all(
        projected[name] == complete[name]
        for name in (
            "action.action_id",
            "action.incident_id",
            "action.operation_id",
            "action.outcome_sha256",
            "telemetry.event_id",
            "telemetry.observed_at",
            "telemetry.emitted_at",
            "observation.contract",
            "observation.scope",
            "target.id",
        )
    )
    assert any(name.startswith("publication.") for name in complete)


def test_action_event_builder_returns_detached_validated_documents() -> None:
    outcome = successful_outcome()
    events = build_action_events(outcome, emitted_at="2026-08-13T12:00:03.000Z")
    outcome["command_outcomes"][0]["trace_id"] = "f" * 32
    assert events[0].to_dict()["correlation"]["trace_id"] == "1" * 32
