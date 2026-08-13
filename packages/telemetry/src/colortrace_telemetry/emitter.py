"""Emit versioned simulator observations through OpenTelemetry."""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http._log_exporter import (
    OTLPLogExporter,
)
from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
    OTLPMetricExporter,
)
from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import (
    PeriodicExportingMetricReader,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
)

from colortrace_telemetry.contract import (
    COMPARISON_VERSION,
    EMISSION_RECEIPT_VERSION,
    OBSERVATION_VERSION,
    SERVICE_NAME,
    SERVICE_VERSION,
    TELEMETRY_EVENT_VERSION,
    DeliveryInstruction,
    DeliveryPlan,
    RuntimeJob,
    RuntimeJobs,
    validate_schema,
)

EVENT_NAMES = {
    "metric": "colortrace.declared_reference.observed",
    "log": "colortrace.declared_reference.log",
    "trace": "colortrace.declared_reference.trace",
}


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    event_id: str
    signal: str
    event_name: str
    scheduled_at: str
    emitted_at: str
    delivery_delay_ms: int
    delivery_ordinal: int
    correlation: dict[str, str]
    observation: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        value = {
            "schema": TELEMETRY_EVENT_VERSION,
            "event_id": self.event_id,
            "signal": self.signal,
            "event_name": self.event_name,
            "scheduled_at": self.scheduled_at,
            "emitted_at": self.emitted_at,
            "delivery_delay_ms": self.delivery_delay_ms,
            "delivery_ordinal": self.delivery_ordinal,
            "correlation": self.correlation,
            "observation": self.observation,
        }
        validate_schema("telemetry-event-v1.schema.json", value)
        return value


class TelemetrySink(Protocol):
    def emit(self, event: TelemetryEvent) -> None: ...

    def force_flush(self) -> None: ...

    def shutdown(self) -> None: ...


class MemorySink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: TelemetryEvent) -> None:
        self.events.append(event.to_dict())

    def force_flush(self) -> None:
        return

    def shutdown(self) -> None:
        return


def _flat_attributes(event: TelemetryEvent) -> dict[str, str | int]:
    attributes: dict[str, str | int] = dict(event.correlation)
    attributes.update(
        {
            "telemetry.contract": TELEMETRY_EVENT_VERSION,
            "telemetry.event_id": event.event_id,
            "telemetry.delivery_delay_ms": event.delivery_delay_ms,
            "telemetry.delivery_ordinal": event.delivery_ordinal,
            "telemetry.scheduled_at": event.scheduled_at,
            "telemetry.emitted_at": event.emitted_at,
            "declared_reference.contract": OBSERVATION_VERSION,
            "declared_reference.policy": COMPARISON_VERSION,
            "declared_reference.state": str(event.observation["state"]),
        }
    )
    measurements = event.observation["measurements"]
    if isinstance(measurements, dict):
        for name, value in measurements.items():
            attributes[f"declared_reference.{name}"] = value
    return attributes


class OtelSink:
    """One isolated SDK pipeline for a bounded local verification run."""

    def __init__(self, endpoint: str, *, timeout_seconds: float = 10.0) -> None:
        endpoint = endpoint.rstrip("/")
        resource = Resource.create(
            {
                "service.name": SERVICE_NAME,
                "service.version": SERVICE_VERSION,
                "telemetry.contract": TELEMETRY_EVENT_VERSION,
            }
        )

        span_exporter = OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces", timeout=timeout_seconds)
        self._tracer_provider = TracerProvider(resource=resource)
        self._tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        self._tracer = self._tracer_provider.get_tracer(SERVICE_NAME, SERVICE_VERSION)

        metric_exporter = OTLPMetricExporter(
            endpoint=f"{endpoint}/v1/metrics", timeout=timeout_seconds
        )
        self._metric_reader = PeriodicExportingMetricReader(
            metric_exporter, export_interval_millis=60_000
        )
        self._meter_provider = MeterProvider(
            resource=resource, metric_readers=[self._metric_reader]
        )
        meter = self._meter_provider.get_meter(SERVICE_NAME, SERVICE_VERSION)
        self._observations = meter.create_counter(
            "colortrace.declared_reference.observations",
            description="Versioned declared-reference observations delivered",
        )
        log_exporter = OTLPLogExporter(endpoint=f"{endpoint}/v1/logs", timeout=timeout_seconds)
        self._logger_provider = LoggerProvider(resource=resource)
        self._logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        self._logging_handler = LoggingHandler(
            level=logging.INFO, logger_provider=self._logger_provider
        )
        self._logger = logging.getLogger(f"{SERVICE_NAME}.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._logger.addHandler(self._logging_handler)
        self._shutdown = False

    def emit(self, event: TelemetryEvent) -> None:
        attributes = _flat_attributes(event)
        if event.signal == "metric":
            metric_attributes = {
                name: value
                for name, value in attributes.items()
                if name != "telemetry.delivery_ordinal"
            }
            self._observations.add(1, attributes=metric_attributes)
            return
        if event.signal == "log":
            self._logger.info(event.event_name, extra=attributes)
            return
        if event.signal != "trace":
            raise ValueError(f"unknown telemetry signal: {event.signal}")

        parent_span_id = (
            int.from_bytes(
                hashlib.sha256(
                    f"{event.event_id}:{event.delivery_ordinal}".encode("ascii")
                ).digest()[:8],
                "big",
            )
            or 1
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
            datetime.fromisoformat(event.scheduled_at.replace("Z", "+00:00")).timestamp()
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
            raise RuntimeError("trace telemetry flush timed out")
        if not self._logger_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("log telemetry flush timed out")
        if not self._meter_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("metric telemetry flush timed out")

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._logger.removeHandler(self._logging_handler)
        self._tracer_provider.shutdown()
        self._logger_provider.shutdown()
        self._meter_provider.shutdown()


def _timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event(
    job: RuntimeJob,
    instruction: DeliveryInstruction,
    run_id: str,
    delivery_ordinal: int,
    scheduled_at: str,
    emitted_at: str,
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=instruction.event_id,
        signal=instruction.signal,
        event_name=EVENT_NAMES[instruction.signal],
        scheduled_at=scheduled_at,
        emitted_at=emitted_at,
        delivery_delay_ms=instruction.delay_ms,
        delivery_ordinal=delivery_ordinal,
        correlation=job.correlation(run_id).to_dict(),
        observation=job.observation.to_dict(),
    )


def emit_plans(
    runtime: RuntimeJobs,
    plans: tuple[DeliveryPlan, ...],
    sink: TelemetrySink,
) -> dict[str, Any]:
    jobs = {job.job_id: job for job in runtime.jobs}
    runs: list[dict[str, Any]] = []
    try:
        for plan in plans:
            events: list[dict[str, Any]] = []
            for instruction in plan.instructions:
                emitted_time = datetime.now(UTC)
                scheduled_at = _timestamp(
                    emitted_time - timedelta(milliseconds=instruction.delay_ms)
                )
                emitted_at = _timestamp(emitted_time)
                for ordinal in range(instruction.copies):
                    event = _event(
                        jobs[instruction.job_id],
                        instruction,
                        plan.run_id,
                        ordinal,
                        scheduled_at,
                        emitted_at,
                    )
                    sink.emit(event)
                    events.append(event.to_dict())
            runs.append(
                {
                    "run_id": plan.run_id,
                    "case_index": plan.case_index,
                    "plans": [instruction.to_dict() for instruction in plan.instructions],
                    "events": events,
                }
            )
        sink.force_flush()
    finally:
        sink.shutdown()
    receipt = {
        "schema": EMISSION_RECEIPT_VERSION,
        "contract_version": TELEMETRY_EVENT_VERSION,
        "source_fixture_manifest_sha256": runtime.source_fixture_manifest_sha256,
        "source_validator_report_sha256": runtime.source_validator_report_sha256,
        "source_job_manifest_sha256": dict(runtime.job_manifest_sha256),
        "runs": runs,
    }
    validate_schema("telemetry-emission-receipt-v1.schema.json", receipt)
    return receipt
