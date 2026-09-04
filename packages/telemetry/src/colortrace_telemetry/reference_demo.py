"""Generated demonstration telemetry for the reference color-pipeline scenarios."""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast

from colortrace_fixture.reference_scenarios import ReferenceScenario, reference_scenarios
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from colortrace_telemetry.contract import SERVICE_NAME, canonical_json_bytes, validate_schema

REFERENCE_TELEMETRY_EVENT_VERSION = "reference-demonstration-telemetry-event/v1"
REFERENCE_TELEMETRY_PLAN_VERSION = "reference-demonstration-telemetry-plan/v1"
REFERENCE_TELEMETRY_RECEIPT_VERSION = "reference-demonstration-telemetry-receipt/v1"
REFERENCE_TELEMETRY_SERVICE_VERSION = "reference-demonstration-telemetry/v1"
REFERENCE_DATA_ORIGIN = "generated-demonstration-telemetry"
REFERENCE_FIXTURE_ID = "tears-of-steel-linear-exr-240-v1"

ReferenceSignal = Literal["metric", "log", "trace"]
ReferenceScopeRole = Literal["affected", "protected"]

REFERENCE_EVENT_NAMES: Mapping[ReferenceSignal, str] = MappingProxyType(
    {
        "metric": "colortrace.declared_reference.observed",
        "log": "colortrace.declared_reference.log",
        "trace": "colortrace.declared_reference.trace",
    }
)
_SIGNALS: tuple[ReferenceSignal, ...] = ("metric", "log", "trace")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_PREFIXED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")


def _prefixed_sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def _require_identifier(label: str, value: str) -> None:
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"reference telemetry {label} is invalid")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("reference telemetry timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bare_digest(value: str) -> str:
    if _PREFIXED_DIGEST.fullmatch(value) is None:
        raise ValueError("reference telemetry digest is invalid")
    return value.removeprefix("sha256:")


@dataclass(frozen=True, slots=True)
class ReferenceTelemetryState:
    resource_sha256: str
    config_sha256: str
    config_generation: int
    frame_pipeline_sha256: str
    derivative_parent_sha256: str
    derivative_generation: int
    cache_key: str

    def __post_init__(self) -> None:
        for value in (
            self.resource_sha256,
            self.config_sha256,
            self.frame_pipeline_sha256,
            self.derivative_parent_sha256,
        ):
            _bare_digest(value)
        if (
            isinstance(self.config_generation, bool)
            or self.config_generation < 1
            or isinstance(self.derivative_generation, bool)
            or self.derivative_generation < 1
        ):
            raise ValueError("reference telemetry generation is invalid")
        _require_identifier("cache key", self.cache_key)

    def to_dict(self) -> dict[str, str | int]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ReferenceRepresentative:
    role: ReferenceScopeRole
    job_id: str
    worker_id: str
    artifact_id: str
    trace_id: str

    def __post_init__(self) -> None:
        for label, value in (
            ("job ID", self.job_id),
            ("worker ID", self.worker_id),
            ("artifact ID", self.artifact_id),
        ):
            _require_identifier(label, value)
        if _TRACE_ID.fullmatch(self.trace_id) is None or self.trace_id == "0" * 32:
            raise ValueError("reference telemetry trace ID is invalid")

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ReferenceTelemetryContext:
    scenario_id: str
    incident_id: str
    fixture_id: str
    run_id: str
    transform_id: str
    observed_at: datetime
    emitted_at: datetime
    affected: ReferenceRepresentative
    protected: ReferenceRepresentative

    def __post_init__(self) -> None:
        scenarios = reference_scenarios()
        if self.scenario_id not in scenarios:
            raise ValueError("reference telemetry scenario is invalid")
        for label, value in (
            ("incident ID", self.incident_id),
            ("fixture ID", self.fixture_id),
            ("run ID", self.run_id),
            ("transform ID", self.transform_id),
        ):
            _require_identifier(label, value)
        if (
            self.affected.role != "affected"
            or self.protected.role != "protected"
            or self.affected.job_id == self.protected.job_id
            or self.affected.artifact_id == self.protected.artifact_id
            or self.affected.trace_id == self.protected.trace_id
            or self.affected.worker_id != self.protected.worker_id
        ):
            raise ValueError("reference telemetry representative scope is invalid")
        observed = datetime.fromisoformat(_timestamp(self.observed_at).replace("Z", "+00:00"))
        emitted = datetime.fromisoformat(_timestamp(self.emitted_at).replace("Z", "+00:00"))
        if emitted < observed or emitted - observed > timedelta(minutes=10):
            raise ValueError("reference telemetry event time is invalid")


@dataclass(frozen=True, slots=True)
class ReferenceTelemetryEvent:
    scenario_id: str
    incident_class: str
    event_id: str
    signal: ReferenceSignal
    observed_at: str
    emitted_at: str
    correlation: Mapping[str, str]
    attributes: Mapping[str, str]

    def __post_init__(self) -> None:
        correlation = MappingProxyType(dict(self.correlation))
        attributes = MappingProxyType(dict(self.attributes))
        object.__setattr__(self, "correlation", correlation)
        object.__setattr__(self, "attributes", attributes)
        validate_schema("reference-demonstration-telemetry-event-v1.schema.json", self.to_dict())
        observed = datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        emitted = datetime.fromisoformat(self.emitted_at.replace("Z", "+00:00"))
        role = attributes["reference.scope_role"]
        if (
            emitted < observed
            or emitted - observed > timedelta(minutes=10)
            or correlation["incident_id"] != attributes["reference.incident_id"]
            or self.scenario_id != attributes["reference.scenario_id"]
            or self.incident_class != attributes["reference.incident_class"]
            or correlation["resource_sha256"]
            != _bare_digest(attributes["runtime.effective_resource_sha256"])
            or (role == "affected")
            != (attributes["declared_reference.state"] == "reference_mismatch")
        ):
            raise ValueError("reference telemetry event binding is invalid")

    @property
    def event_name(self) -> str:
        return REFERENCE_EVENT_NAMES[self.signal]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REFERENCE_TELEMETRY_EVENT_VERSION,
            "data_origin": REFERENCE_DATA_ORIGIN,
            "scenario_id": self.scenario_id,
            "incident_class": self.incident_class,
            "event_id": self.event_id,
            "signal": self.signal,
            "event_name": self.event_name,
            "observed_at": self.observed_at,
            "emitted_at": self.emitted_at,
            "correlation": dict(self.correlation),
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True, slots=True)
class ReferenceTelemetryPlan:
    scenario_id: str
    incident_class: str
    incident_id: str
    fixture_id: str
    run_id: str
    events: tuple[ReferenceTelemetryEvent, ...]
    plan_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        events = tuple(self.events)
        object.__setattr__(self, "events", events)
        body = self._body()
        validate_schema("reference-demonstration-telemetry-plan-v1.schema.json", body)
        roles_and_signals = {
            (event.attributes["reference.scope_role"], event.signal) for event in events
        }
        event_ids = {event.event_id for event in events}
        workers = {event.correlation["worker_id"] for event in events}
        config_digests = {event.correlation["config_sha256"] for event in events}
        role_jobs = {
            role: {
                event.correlation["job_id"]
                for event in events
                if event.attributes["reference.scope_role"] == role
            }
            for role in ("affected", "protected")
        }
        role_payloads = {
            role: {
                canonical_json_bytes(
                    {
                        "correlation": dict(event.correlation),
                        "attributes": dict(event.attributes),
                        "observed_at": event.observed_at,
                        "emitted_at": event.emitted_at,
                    }
                )
                for event in events
                if event.attributes["reference.scope_role"] == role
            }
            for role in ("affected", "protected")
        }
        if (
            len(event_ids) != 6
            or roles_and_signals
            != {(role, signal) for role in ("affected", "protected") for signal in _SIGNALS}
            or len(workers) != 1
            or len(config_digests) != 1
            or any(len(values) != 1 for values in role_jobs.values())
            or any(len(values) != 1 for values in role_payloads.values())
            or role_jobs["affected"] == role_jobs["protected"]
            or any(
                event.scenario_id != self.scenario_id
                or event.incident_class != self.incident_class
                or event.correlation["incident_id"] != self.incident_id
                or event.correlation["fixture_id"] != self.fixture_id
                or event.correlation["run_id"] != self.run_id
                for event in events
            )
        ):
            raise ValueError("reference telemetry plan binding is invalid")
        object.__setattr__(self, "plan_sha256", _prefixed_sha256(body))

    def _body(self) -> dict[str, Any]:
        return {
            "schema": REFERENCE_TELEMETRY_PLAN_VERSION,
            "data_origin": REFERENCE_DATA_ORIGIN,
            "scenario_id": self.scenario_id,
            "incident_class": self.incident_class,
            "incident_id": self.incident_id,
            "fixture_id": self.fixture_id,
            "run_id": self.run_id,
            "events": [event.to_dict() for event in self.events],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "plan_sha256": self.plan_sha256}


def _changed_fields(
    approved: ReferenceTelemetryState, observed: ReferenceTelemetryState
) -> frozenset[str]:
    return frozenset(
        name for name in approved.to_dict() if getattr(approved, name) != getattr(observed, name)
    )


def _validate_scenario_drift(
    scenario: ReferenceScenario,
    approved: ReferenceTelemetryState,
    observed: ReferenceTelemetryState,
) -> None:
    changed = _changed_fields(approved, observed)
    expected: Mapping[str, frozenset[str]] = {
        "resource-resolution-drift/v1": frozenset({"resource_sha256", "frame_pipeline_sha256"}),
        "configuration-rollout-drift/v1": frozenset(
            {"config_sha256", "config_generation", "frame_pipeline_sha256"}
        ),
        "stale-derivative-cache/v1": frozenset(
            {"derivative_parent_sha256", "derivative_generation"}
        ),
    }
    if changed != expected[scenario.incident_class]:
        raise ValueError("reference telemetry drift does not match the scenario class")
    if (
        approved.config_generation != scenario.expected_config_generation
        or observed.config_generation != scenario.observed_config_generation
        or approved.derivative_generation != scenario.expected_derivative_generation
        or observed.derivative_generation != scenario.observed_derivative_generation
    ):
        raise ValueError("reference telemetry generation does not match the scenario")


def _semantic_attributes(
    *,
    scenario: ReferenceScenario,
    context: ReferenceTelemetryContext,
    role: ReferenceScopeRole,
    state: ReferenceTelemetryState,
) -> dict[str, str]:
    return {
        "declared_reference.state": (
            "reference_mismatch" if role == "affected" else "reference_match"
        ),
        "runtime.effective_resource_sha256": state.resource_sha256,
        "runtime.effective_config_sha256": state.config_sha256,
        "runtime.config_generation": str(state.config_generation),
        "runtime.frame_pipeline_sha256": state.frame_pipeline_sha256,
        "derivative.parent_sha256": state.derivative_parent_sha256,
        "cache.generation": str(state.derivative_generation),
        "cache.key": state.cache_key,
        "reference.data_origin": REFERENCE_DATA_ORIGIN,
        "reference.scenario_id": scenario.scenario_id,
        "reference.incident_class": scenario.incident_class,
        "reference.incident_id": context.incident_id,
        "reference.scope_role": role,
        "reference.evidence_scope": "representative",
        "reference.affected_representative_count": "1",
        "reference.protected_representative_count": "1",
        "reference.population_affected_artifact_count": str(len(scenario.affected_artifact_ids)),
        "reference.population_protected_artifact_count": str(len(scenario.protected_artifact_ids)),
    }


def _event_id(*, scenario_id: str, incident_id: str, run_id: str, job_id: str, signal: str) -> str:
    digest = hashlib.sha256(
        canonical_json_bytes(
            {
                "schema": REFERENCE_TELEMETRY_EVENT_VERSION,
                "scenario_id": scenario_id,
                "incident_id": incident_id,
                "run_id": run_id,
                "job_id": job_id,
                "signal": signal,
            }
        )
    ).hexdigest()
    return f"refevt-{digest[:24]}"


def build_reference_telemetry_plan(
    *,
    context: ReferenceTelemetryContext,
    approved_state: ReferenceTelemetryState,
    affected_state: ReferenceTelemetryState,
) -> ReferenceTelemetryPlan:
    scenario = reference_scenarios()[context.scenario_id]
    _validate_scenario_drift(scenario, approved_state, affected_state)
    events: list[ReferenceTelemetryEvent] = []
    observed_at = _timestamp(context.observed_at)
    emitted_at = _timestamp(context.emitted_at)
    for representative, state in (
        (context.affected, affected_state),
        (context.protected, approved_state),
    ):
        correlation = {
            "incident_id": context.incident_id,
            "fixture_id": context.fixture_id,
            "run_id": context.run_id,
            "job_id": representative.job_id,
            "worker_id": representative.worker_id,
            "artifact_id": representative.artifact_id,
            "trace_id": representative.trace_id,
            "config_sha256": _bare_digest(approved_state.config_sha256),
            "resource_sha256": _bare_digest(state.resource_sha256),
            "transform_id": context.transform_id,
        }
        attributes = _semantic_attributes(
            scenario=scenario,
            context=context,
            role=representative.role,
            state=state,
        )
        for signal in _SIGNALS:
            events.append(
                ReferenceTelemetryEvent(
                    scenario_id=scenario.scenario_id,
                    incident_class=scenario.incident_class,
                    event_id=_event_id(
                        scenario_id=scenario.scenario_id,
                        incident_id=context.incident_id,
                        run_id=context.run_id,
                        job_id=representative.job_id,
                        signal=signal,
                    ),
                    signal=signal,
                    observed_at=observed_at,
                    emitted_at=emitted_at,
                    correlation=correlation,
                    attributes=attributes,
                )
            )
    return ReferenceTelemetryPlan(
        scenario_id=scenario.scenario_id,
        incident_class=scenario.incident_class,
        incident_id=context.incident_id,
        fixture_id=context.fixture_id,
        run_id=context.run_id,
        events=tuple(events),
    )


def _generated_digest(label: str) -> str:
    return f"sha256:{hashlib.sha256(label.encode()).hexdigest()}"


def _representative(
    scenario: ReferenceScenario,
    role: ReferenceScopeRole,
    *,
    worker_id: str,
    incident_id: str,
    run_id: str,
) -> ReferenceRepresentative:
    artifact_id = (
        scenario.affected_artifact_ids[0]
        if role == "affected"
        else scenario.protected_artifact_ids[0]
    )
    return ReferenceRepresentative(
        role=role,
        job_id=f"job:{artifact_id}",
        worker_id=worker_id,
        artifact_id=artifact_id,
        trace_id=hashlib.sha256(
            (f"{scenario.scenario_id}\0{incident_id}\0{run_id}\0{role}\0{artifact_id}").encode()
        ).hexdigest()[:32],
    )


def generated_reference_telemetry_states(
    scenario_id: str,
) -> tuple[ReferenceTelemetryState, ReferenceTelemetryState]:
    try:
        scenario = reference_scenarios()[scenario_id]
    except KeyError:
        raise ValueError("reference telemetry scenario is invalid") from None
    approved = ReferenceTelemetryState(
        resource_sha256=_generated_digest("reference-v3:approved-resource"),
        config_sha256=_generated_digest("reference-v3:approved-config"),
        config_generation=scenario.expected_config_generation,
        frame_pipeline_sha256=_generated_digest("reference-v3:approved-frame-pipeline"),
        derivative_parent_sha256=_generated_digest(
            f"reference-v3:{scenario_id}:approved-derivative-parent"
        ),
        derivative_generation=scenario.expected_derivative_generation,
        cache_key=f"cache:reference-v3:g{scenario.expected_derivative_generation}",
    )
    affected_values = approved.to_dict()
    if scenario.incident_class == "resource-resolution-drift/v1":
        affected_values.update(
            {
                "resource_sha256": _generated_digest("reference-v3:shadowed-resource"),
                "frame_pipeline_sha256": _generated_digest(
                    f"reference-v3:{scenario_id}:drifted-frame-pipeline"
                ),
            }
        )
    elif scenario.incident_class == "configuration-rollout-drift/v1":
        affected_values.update(
            {
                "config_sha256": _generated_digest("reference-v3:stale-rollout-config"),
                "config_generation": scenario.observed_config_generation,
                "frame_pipeline_sha256": _generated_digest(
                    f"reference-v3:{scenario_id}:drifted-frame-pipeline"
                ),
            }
        )
    else:
        affected_values.update(
            {
                "derivative_parent_sha256": _generated_digest(
                    f"reference-v3:{scenario_id}:stale-derivative-parent"
                ),
                "derivative_generation": scenario.observed_derivative_generation,
            }
        )
    affected = ReferenceTelemetryState(**cast(dict[str, Any], affected_values))
    return approved, affected


def build_generated_reference_telemetry_plan(
    scenario_id: str,
    *,
    incident_id: str,
    run_id: str,
    observed_at: datetime,
    emitted_at: datetime,
    fixture_id: str = REFERENCE_FIXTURE_ID,
) -> ReferenceTelemetryPlan:
    try:
        scenario = reference_scenarios()[scenario_id]
    except KeyError:
        raise ValueError("reference telemetry scenario is invalid") from None
    approved, affected = generated_reference_telemetry_states(scenario_id)
    worker_id = "reference-worker-00"
    context = ReferenceTelemetryContext(
        scenario_id=scenario_id,
        incident_id=incident_id,
        fixture_id=fixture_id,
        run_id=run_id,
        transform_id="look/main/v1",
        observed_at=observed_at,
        emitted_at=emitted_at,
        affected=_representative(
            scenario,
            "affected",
            worker_id=worker_id,
            incident_id=incident_id,
            run_id=run_id,
        ),
        protected=_representative(
            scenario,
            "protected",
            worker_id=worker_id,
            incident_id=incident_id,
            run_id=run_id,
        ),
    )
    return build_reference_telemetry_plan(
        context=context,
        approved_state=approved,
        affected_state=affected,
    )


def reference_event_attributes(
    event: ReferenceTelemetryEvent, *, normalized_names: bool = False
) -> dict[str, str]:
    attributes = {
        **dict(event.correlation),
        "telemetry.contract": REFERENCE_TELEMETRY_EVENT_VERSION,
        "telemetry.event_id": event.event_id,
        "telemetry.observed_at": event.observed_at,
        "telemetry.emitted_at": event.emitted_at,
        **dict(event.attributes),
    }
    if normalized_names:
        return {name.replace(".", "_"): value for name, value in attributes.items()}
    return attributes


class ReferenceTelemetrySink(Protocol):
    def emit(self, event: ReferenceTelemetryEvent) -> None: ...

    def force_flush(self) -> None: ...

    def shutdown(self) -> None: ...


class MemoryReferenceTelemetrySink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: ReferenceTelemetryEvent) -> None:
        self.events.append(event.to_dict())

    def force_flush(self) -> None:
        return

    def shutdown(self) -> None:
        return


class ReferenceOtelSink:
    """An isolated OTLP pipeline for generated reference telemetry."""

    def __init__(self, endpoint: str, *, timeout_seconds: float = 10.0) -> None:
        endpoint = endpoint.rstrip("/")
        self.endpoint = endpoint
        resource = Resource.create(
            {
                "service.name": SERVICE_NAME,
                "service.version": REFERENCE_TELEMETRY_SERVICE_VERSION,
                "telemetry.contract": REFERENCE_TELEMETRY_EVENT_VERSION,
                "reference.data_origin": REFERENCE_DATA_ORIGIN,
            }
        )
        span_exporter = OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", timeout=timeout_seconds)
        self._tracer_provider = TracerProvider(resource=resource)
        self._tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        self._tracer = self._tracer_provider.get_tracer(
            SERVICE_NAME, REFERENCE_TELEMETRY_SERVICE_VERSION
        )

        metric_exporter = OTLPMetricExporter(
            endpoint=f"{endpoint}/v1/metrics", timeout=timeout_seconds
        )
        self._metric_reader = PeriodicExportingMetricReader(
            metric_exporter, export_interval_millis=60_000
        )
        self._meter_provider = MeterProvider(
            resource=resource, metric_readers=[self._metric_reader]
        )
        meter = self._meter_provider.get_meter(SERVICE_NAME, REFERENCE_TELEMETRY_SERVICE_VERSION)
        self._observations = meter.create_counter(
            "colortrace.declared_reference.observations",
            description="Generated declared-reference observations delivered",
        )

        log_exporter = OTLPLogExporter(endpoint=f"{endpoint}/v1/logs", timeout=timeout_seconds)
        self._logger_provider = LoggerProvider(resource=resource)
        self._logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        self._logging_handler = LoggingHandler(
            level=logging.INFO, logger_provider=self._logger_provider
        )
        self._logger = logging.getLogger(f"{SERVICE_NAME}.reference.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._logger.addHandler(self._logging_handler)
        self._shutdown = False

    def emit(self, event: ReferenceTelemetryEvent) -> None:
        attributes = reference_event_attributes(
            event,
            normalized_names=event.signal == "metric",
        )
        if event.signal == "metric":
            self._observations.add(1, attributes=attributes)
            return
        if event.signal == "log":
            self._logger.info(event.event_name, extra=attributes)
            return
        if event.signal != "trace":  # pragma: no cover - schema validation closes this branch
            raise ValueError("reference telemetry signal is invalid")

        parent_span_id = (
            int.from_bytes(hashlib.sha256(event.event_id.encode()).digest()[:8], "big") or 1
        )
        parent = NonRecordingSpan(
            SpanContext(
                trace_id=int(event.correlation["trace_id"], 16),
                span_id=parent_span_id,
                is_remote=True,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
            )
        )
        context = trace.set_span_in_context(parent)
        start_time = int(
            datetime.fromisoformat(event.observed_at.replace("Z", "+00:00")).timestamp()
            * 1_000_000_000
        )
        end_time = int(
            datetime.fromisoformat(event.emitted_at.replace("Z", "+00:00")).timestamp()
            * 1_000_000_000
        )
        span = self._tracer.start_span(event.event_name, context=context, start_time=start_time)
        for name, value in attributes.items():
            span.set_attribute(name, value)
        span.end(end_time=max(start_time + 1, end_time))

    def force_flush(self) -> None:
        if not self._tracer_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("reference trace telemetry flush timed out")
        if not self._logger_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("reference log telemetry flush timed out")
        if not self._meter_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("reference metric telemetry flush timed out")

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._logger.removeHandler(self._logging_handler)
        self._tracer_provider.shutdown()
        self._logger_provider.shutdown()
        self._meter_provider.shutdown()


def emit_reference_telemetry(
    plan: ReferenceTelemetryPlan, sink: ReferenceTelemetrySink
) -> dict[str, Any]:
    try:
        for event in plan.events:
            sink.emit(event)
        sink.force_flush()
    finally:
        sink.shutdown()
    body = {
        "schema": REFERENCE_TELEMETRY_RECEIPT_VERSION,
        "data_origin": REFERENCE_DATA_ORIGIN,
        "plan_sha256": plan.plan_sha256,
        "scenario_id": plan.scenario_id,
        "incident_id": plan.incident_id,
        "fixture_id": plan.fixture_id,
        "run_id": plan.run_id,
        "signals": list(_SIGNALS),
        "scope_roles": ["affected", "protected"],
        "events": [event.to_dict() for event in plan.events],
    }
    receipt = {**body, "receipt_sha256": _prefixed_sha256(body)}
    validate_schema("reference-demonstration-telemetry-receipt-v1.schema.json", receipt)
    return receipt


__all__ = [
    "REFERENCE_DATA_ORIGIN",
    "REFERENCE_FIXTURE_ID",
    "REFERENCE_TELEMETRY_EVENT_VERSION",
    "REFERENCE_TELEMETRY_PLAN_VERSION",
    "REFERENCE_TELEMETRY_RECEIPT_VERSION",
    "MemoryReferenceTelemetrySink",
    "ReferenceOtelSink",
    "ReferenceRepresentative",
    "ReferenceTelemetryContext",
    "ReferenceTelemetryEvent",
    "ReferenceTelemetryPlan",
    "ReferenceTelemetrySink",
    "ReferenceTelemetryState",
    "build_generated_reference_telemetry_plan",
    "build_reference_telemetry_plan",
    "emit_reference_telemetry",
    "generated_reference_telemetry_states",
    "reference_event_attributes",
]
