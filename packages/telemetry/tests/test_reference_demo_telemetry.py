from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from colortrace_telemetry import (
    REFERENCE_DATA_ORIGIN,
    MemoryReferenceTelemetrySink,
    ReferenceOtelSink,
    ReferenceRepresentative,
    ReferenceTelemetryContext,
    ReferenceTelemetryState,
    build_generated_reference_telemetry_plan,
    build_reference_telemetry_plan,
    emit_reference_telemetry,
    reference_event_attributes,
)
from colortrace_telemetry.contract import canonical_json_bytes, validate_schema

SCENARIOS = {
    "tos-resource-resolution-drift-v1": (
        "resource-resolution-drift/v1",
        {"runtime.effective_resource_sha256", "runtime.frame_pipeline_sha256"},
    ),
    "tos-config-rollout-drift-v1": (
        "configuration-rollout-drift/v1",
        {
            "runtime.effective_config_sha256",
            "runtime.config_generation",
            "runtime.frame_pipeline_sha256",
        },
    ),
    "tos-stale-derivative-cache-v1": (
        "stale-derivative-cache/v1",
        {"derivative.parent_sha256", "cache.generation"},
    ),
}

SEMANTIC_FIELDS = {
    "declared_reference.state",
    "runtime.effective_resource_sha256",
    "runtime.effective_config_sha256",
    "runtime.config_generation",
    "runtime.frame_pipeline_sha256",
    "derivative.parent_sha256",
    "cache.generation",
    "cache.key",
}


def _plans() -> list[Any]:
    observed = datetime(2026, 9, 4, 12, 1, tzinfo=UTC)
    return [
        build_generated_reference_telemetry_plan(
            scenario_id,
            incident_id=f"incident-reference-{index}",
            run_id=f"run-reference-{index}",
            observed_at=observed,
            emitted_at=observed + timedelta(seconds=1),
        )
        for index, scenario_id in enumerate(SCENARIOS, start=1)
    ]


@pytest.mark.parametrize(
    ("scenario_id", "expected_class", "expected_changes"),
    [(scenario_id, values[0], values[1]) for scenario_id, values in SCENARIOS.items()],
)
def test_generated_plan_carries_distinct_two_scope_cross_signal_evidence(
    scenario_id: str,
    expected_class: str,
    expected_changes: set[str],
) -> None:
    observed = datetime(2026, 9, 4, 12, 1, tzinfo=UTC)
    plan = build_generated_reference_telemetry_plan(
        scenario_id,
        incident_id="incident-reference-001",
        run_id="run-reference-001",
        observed_at=observed,
        emitted_at=observed + timedelta(seconds=1),
    )

    assert plan.incident_class == expected_class
    assert len(plan.events) == 6
    assert len({event.event_id for event in plan.events}) == 6
    assert {event.signal for event in plan.events} == {"metric", "log", "trace"}
    assert {event.attributes["reference.scope_role"] for event in plan.events} == {
        "affected",
        "protected",
    }
    assert all(
        event.correlation["incident_id"] == "incident-reference-001" for event in plan.events
    )
    assert all(event.correlation["fixture_id"] == plan.fixture_id for event in plan.events)
    assert all(event.correlation["run_id"] == plan.run_id for event in plan.events)
    assert all(
        event.attributes["reference.data_origin"] == REFERENCE_DATA_ORIGIN for event in plan.events
    )
    assert {
        (
            event.attributes["reference.evidence_scope"],
            event.attributes["reference.affected_representative_count"],
            event.attributes["reference.protected_representative_count"],
            event.attributes["reference.population_affected_artifact_count"],
            event.attributes["reference.population_protected_artifact_count"],
        )
        for event in plan.events
    } == {("representative", "1", "1", "72", "168")}

    by_role: dict[str, dict[str, str]] = {}
    for role in ("affected", "protected"):
        role_events = [
            event for event in plan.events if event.attributes["reference.scope_role"] == role
        ]
        assert {event.signal for event in role_events} == {"metric", "log", "trace"}
        assert all(SEMANTIC_FIELDS <= set(event.attributes) for event in role_events)
        assert len({tuple(sorted(event.attributes.items())) for event in role_events}) == 1
        assert len({event.correlation["job_id"] for event in role_events}) == 1
        assert len({event.correlation["artifact_id"] for event in role_events}) == 1
        assert len({event.correlation["trace_id"] for event in role_events}) == 1
        by_role[role] = dict(role_events[0].attributes)

    changed = {
        name
        for name in SEMANTIC_FIELDS - {"declared_reference.state"}
        if by_role["affected"][name] != by_role["protected"][name]
    }
    assert changed == expected_changes
    assert by_role["affected"]["declared_reference.state"] == "reference_mismatch"
    assert by_role["protected"]["declared_reference.state"] == "reference_match"


def test_generated_plan_uses_run_scoped_trace_and_event_identities() -> None:
    observed = datetime(2026, 9, 4, 12, 1, tzinfo=UTC)
    first = build_generated_reference_telemetry_plan(
        "tos-resource-resolution-drift-v1",
        incident_id="incident-reference-001",
        run_id="run-reference-001",
        observed_at=observed,
        emitted_at=observed + timedelta(seconds=1),
    )
    second = build_generated_reference_telemetry_plan(
        "tos-resource-resolution-drift-v1",
        incident_id="incident-reference-002",
        run_id="run-reference-002",
        observed_at=observed,
        emitted_at=observed + timedelta(seconds=1),
    )

    assert {event.correlation["trace_id"] for event in first.events}.isdisjoint(
        event.correlation["trace_id"] for event in second.events
    )
    assert {event.event_id for event in first.events}.isdisjoint(
        event.event_id for event in second.events
    )


def test_emitted_attribute_shapes_match_metric_log_and_trace_normalization() -> None:
    event_by_signal = {event.signal: event for event in _plans()[0].events}
    required_binding = {
        "fixture_id",
        "run_id",
        "job_id",
        "worker_id",
        "artifact_id",
        "trace_id",
        "config_sha256",
        "resource_sha256",
        "transform_id",
    }

    for signal in ("log", "trace"):
        attributes = reference_event_attributes(event_by_signal[signal])
        assert required_binding <= set(attributes)
        assert SEMANTIC_FIELDS <= set(attributes)
        assert attributes["telemetry.event_id"] == event_by_signal[signal].event_id
        assert attributes["telemetry.observed_at"] == event_by_signal[signal].observed_at
        assert attributes["telemetry.emitted_at"] == event_by_signal[signal].emitted_at

    metric_attributes = reference_event_attributes(event_by_signal["metric"], normalized_names=True)
    assert required_binding <= set(metric_attributes)
    assert {
        "telemetry_event_id",
        "telemetry_observed_at",
        "telemetry_emitted_at",
        "declared_reference_state",
        "runtime_effective_resource_sha256",
        "runtime_effective_config_sha256",
        "runtime_config_generation",
        "runtime_frame_pipeline_sha256",
        "derivative_parent_sha256",
        "cache_generation",
        "cache_key",
    } <= set(metric_attributes)


def test_otlp_metric_emission_uses_prometheus_safe_attribute_names() -> None:
    class Counter:
        def __init__(self) -> None:
            self.attributes: dict[str, str] | None = None

        def add(self, value: int, *, attributes: dict[str, str]) -> None:
            assert value == 1
            self.attributes = attributes

    counter = Counter()
    sink = object.__new__(ReferenceOtelSink)
    sink._observations = counter  # type: ignore[attr-defined]

    event = next(event for event in _plans()[0].events if event.signal == "metric")
    sink.emit(event)

    assert counter.attributes is not None
    assert "telemetry_event_id" in counter.attributes
    assert "runtime_effective_resource_sha256" in counter.attributes
    assert "telemetry.event_id" not in counter.attributes
    assert "runtime.effective_resource_sha256" not in counter.attributes


def test_emission_receipt_is_deterministic_and_retains_each_event() -> None:
    plan = _plans()[1]
    first_sink = MemoryReferenceTelemetrySink()
    second_sink = MemoryReferenceTelemetrySink()

    first = emit_reference_telemetry(plan, first_sink)
    second = emit_reference_telemetry(plan, second_sink)

    assert first == second
    assert first_sink.events == second_sink.events == [event.to_dict() for event in plan.events]
    assert first["signals"] == ["metric", "log", "trace"]
    assert first["scope_roles"] == ["affected", "protected"]
    body = {name: value for name, value in first.items() if name != "receipt_sha256"}
    assert first["receipt_sha256"] == (
        f"sha256:{hashlib.sha256(canonical_json_bytes(body)).hexdigest()}"
    )


def test_custom_plan_rejects_drift_outside_the_selected_scenario() -> None:
    def digest(label: str) -> str:
        return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"

    approved = ReferenceTelemetryState(
        resource_sha256=digest("resource"),
        config_sha256=digest("config"),
        config_generation=7,
        frame_pipeline_sha256=digest("pipeline"),
        derivative_parent_sha256=digest("parent"),
        derivative_generation=7,
        cache_key="cache-reference-g7",
    )
    affected = ReferenceTelemetryState(
        resource_sha256=digest("other-resource"),
        config_sha256=digest("other-config"),
        config_generation=6,
        frame_pipeline_sha256=digest("other-pipeline"),
        derivative_parent_sha256=approved.derivative_parent_sha256,
        derivative_generation=approved.derivative_generation,
        cache_key=approved.cache_key,
    )
    observed = datetime(2026, 9, 4, 12, 1, tzinfo=UTC)
    context = ReferenceTelemetryContext(
        scenario_id="tos-resource-resolution-drift-v1",
        incident_id="incident-reference-invalid",
        fixture_id="tears-of-steel-linear-exr-240-v1",
        run_id="run-reference-invalid",
        transform_id="look/main/v1",
        observed_at=observed,
        emitted_at=observed + timedelta(seconds=1),
        affected=ReferenceRepresentative(
            "affected", "job-affected", "worker-reference", "frame:03_2a:00000", "1" * 32
        ),
        protected=ReferenceRepresentative(
            "protected", "job-protected", "worker-reference", "frame:03_2a:00001", "2" * 32
        ),
    )

    with pytest.raises(ValueError, match="does not match"):
        build_reference_telemetry_plan(
            context=context,
            approved_state=approved,
            affected_state=affected,
        )


def test_event_schema_rejects_signal_name_mismatch() -> None:
    event = _plans()[2].events[0].to_dict()
    event["event_name"] = "colortrace.declared_reference.log"
    with pytest.raises(ValueError, match="validation failed"):
        validate_schema("reference-demonstration-telemetry-event-v1.schema.json", event)
