"""Emit terminal simulator action evidence without reopening execution authority."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

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

from colortrace_telemetry.action_contract import (
    ACTION_EVENT_VERSION,
    COMMAND_OBSERVATION_VERSION,
    COMMAND_SIGNALS,
    FAILURE_OBSERVATION_VERSION,
    NON_TRACE_SIGNALS,
    SAFE_OBSERVATION_VERSION,
    ValidatedActionOutcome,
    action_correlation,
    action_publication,
    build_action_receipt,
    parse_action_timestamp,
    stable_action_event_id,
    validate_action_event,
    validate_action_outcome,
)

LOCAL_ACTION_OTLP_ENDPOINT = "http://127.0.0.1:14318"
ACTION_TELEMETRY_SERVICE = "colortrace-simulator"
ACTION_TELEMETRY_SERVICE_VERSION = "simulator-action-telemetry/v1"


def _validated_otlp_endpoint(value: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not 1 <= len(value) <= 2_048:
        raise ValueError("action telemetry endpoint is invalid")
    parsed = urlsplit(value)
    try:
        _port = parsed.port
    except ValueError:
        raise ValueError("action telemetry endpoint is invalid") from None
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("action telemetry endpoint is invalid")
    return value.rstrip("/")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("action telemetry clock must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ActionTelemetryEvent:
    document: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return validate_action_event(self.document)

    @property
    def event_id(self) -> str:
        return cast(str, self.document["event_id"])

    @property
    def signal(self) -> str:
        return cast(str, self.document["signal"])


class ActionTelemetrySink(Protocol):
    def emit(self, event: ActionTelemetryEvent) -> None: ...

    def force_flush(self) -> None: ...


class MemoryActionTelemetrySink:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event: ActionTelemetryEvent) -> None:
        self.events.append(event.to_dict())

    def force_flush(self) -> None:
        return


def _event_name(observation: Mapping[str, Any]) -> str:
    schema = observation["schema"]
    if schema == COMMAND_OBSERVATION_VERSION:
        result = cast(Mapping[str, Any], observation["result"])
        if result["result_kind"] == "quarantine":
            return "colortrace.simulator.action.quarantined"
        return "colortrace.simulator.action.rerendered"
    if schema == SAFE_OBSERVATION_VERSION:
        return "colortrace.simulator.safe.preserved"
    if schema == FAILURE_OBSERVATION_VERSION:
        return "colortrace.simulator.action.failed"
    raise ValueError("action telemetry observation schema is invalid")


def _event(
    outcome: ValidatedActionOutcome,
    *,
    signal: str,
    trace_id: str | None,
    observation: Mapping[str, Any],
    emitted_at: str,
) -> ActionTelemetryEvent:
    correlation = action_correlation(outcome, trace_id=trace_id)
    value = {
        "schema": ACTION_EVENT_VERSION,
        "event_id": stable_action_event_id(
            outcome_sha256=cast(str, outcome.document["outcome_sha256"]),
            signal=signal,
            observation=observation,
        ),
        "signal": signal,
        "event_name": _event_name(observation),
        "phase": "execution",
        "action_started_at": outcome.document["action_started_at"],
        "action_completed_at": outcome.document["completed_at"],
        "publication_promoted_at": outcome.document["publication_promoted_at"],
        "observed_at": outcome.document["completed_at"],
        "emitted_at": emitted_at,
        "correlation": correlation,
        "publication": action_publication(outcome),
        "observation": dict(observation),
    }
    return ActionTelemetryEvent(validate_action_event(value))


def _build_validated_events(
    outcome: ValidatedActionOutcome, *, emitted_at: str
) -> tuple[ActionTelemetryEvent, ...]:
    if parse_action_timestamp(emitted_at, label="emitted_at") < outcome.completed_at:
        raise ValueError("action telemetry emission predates action completion")
    events: list[ActionTelemetryEvent] = []
    if outcome.document["status"] == "failed":
        observation = {
            "schema": FAILURE_OBSERVATION_VERSION,
            "scope": "action",
            "status": "failed",
            "reason_codes": list(outcome.document["reason_codes"]),
            "publication_promoted": False,
        }
        for signal in NON_TRACE_SIGNALS:
            events.append(
                _event(
                    outcome,
                    signal=signal,
                    trace_id=None,
                    observation=observation,
                    emitted_at=emitted_at,
                )
            )
        return tuple(events)

    for result in outcome.command_outcomes:
        observation = {
            "schema": COMMAND_OBSERVATION_VERSION,
            "scope": "affected",
            "result": result,
        }
        for signal in COMMAND_SIGNALS:
            events.append(
                _event(
                    outcome,
                    signal=signal,
                    trace_id=cast(str, result["trace_id"]),
                    observation=observation,
                    emitted_at=emitted_at,
                )
            )
    for target in outcome.exclusions:
        observation = {
            "schema": SAFE_OBSERVATION_VERSION,
            "scope": "safe",
            "target": target,
            "preservation_manifest_sha256": outcome.document["preservation_manifest_sha256"],
            "safe_complement_before_sha256": outcome.document["safe_complement_before_sha256"],
            "safe_complement_after_sha256": outcome.document["safe_complement_after_sha256"],
            "safe_complement_proof_sha256": outcome.document["safe_complement_proof_sha256"],
            "unchanged": True,
        }
        for signal in NON_TRACE_SIGNALS:
            events.append(
                _event(
                    outcome,
                    signal=signal,
                    trace_id=None,
                    observation=observation,
                    emitted_at=emitted_at,
                )
            )
    event_ids = [event.event_id for event in events]
    if len(event_ids) != len(set(event_ids)):
        raise ValueError("action telemetry event IDs are not unique")
    return tuple(events)


def build_action_events(
    value: Mapping[str, Any], *, emitted_at: str
) -> tuple[ActionTelemetryEvent, ...]:
    return _build_validated_events(validate_action_outcome(value), emitted_at=emitted_at)


def emit_action_outcome(
    value: Mapping[str, Any],
    sink: ActionTelemetrySink,
    *,
    clock: Callable[[], datetime] = _utc_now,
) -> dict[str, Any]:
    outcome = validate_action_outcome(value)
    attempted_at = _timestamp(clock())
    events = _build_validated_events(outcome, emitted_at=attempted_at)
    event_ids = tuple(event.event_id for event in events)
    emitted_ids: list[str] = []
    error_code: str | None = None
    for event in events:
        try:
            sink.emit(event)
        except Exception:
            error_code = "sink-emit-failed"
            break
        emitted_ids.append(event.event_id)
    if error_code is None:
        try:
            sink.force_flush()
        except Exception:
            error_code = "sink-flush-failed"
    return build_action_receipt(
        outcome,
        attempted_at=attempted_at,
        event_ids=event_ids,
        emitted_event_ids=tuple(emitted_ids),
        error_code=error_code,
    )


def _flat_action_attributes(event: Mapping[str, Any]) -> dict[str, str | int | bool]:
    attributes: dict[str, str | int | bool] = {
        "telemetry.contract": cast(str, event["schema"]),
        "telemetry.event_id": cast(str, event["event_id"]),
        "telemetry.phase": cast(str, event["phase"]),
        "telemetry.observed_at": cast(str, event["observed_at"]),
        "telemetry.emitted_at": cast(str, event["emitted_at"]),
        "action.started_at": cast(str, event["action_started_at"]),
        "action.completed_at": cast(str, event["action_completed_at"]),
    }
    correlation = cast(Mapping[str, Any], event["correlation"])
    for name, child in correlation.items():
        if name == "schema" or child is None:
            continue
        if isinstance(child, (str, int, bool)):
            attributes[f"action.{name}"] = child
    publication = event["publication"]
    if isinstance(publication, Mapping):
        for name, child in publication.items():
            if name == "schema":
                continue
            if isinstance(child, (str, int, bool)):
                attributes[f"publication.{name}"] = child
    observation = cast(Mapping[str, Any], event["observation"])
    attributes["observation.contract"] = cast(str, observation["schema"])
    attributes["observation.scope"] = cast(str, observation["scope"])
    if observation["schema"] == COMMAND_OBSERVATION_VERSION:
        result = cast(Mapping[str, Any], observation["result"])
        attributes["command.id"] = cast(str, result["command_id"])
        attributes["command.result_kind"] = cast(str, result["result_kind"])
        target = cast(Mapping[str, Any], result["target"])
        before = cast(Mapping[str, Any], result["before"])
        after = cast(Mapping[str, Any], result["after"])
        for name in ("namespace", "kind", "id"):
            attributes[f"target.{name}"] = cast(str, target[name])
        for prefix, state in (("before", before), ("after", after)):
            for name, child in state.items():
                attributes[f"{prefix}.{name}"] = cast(str, child)
    elif observation["schema"] == SAFE_OBSERVATION_VERSION:
        target = cast(Mapping[str, Any], observation["target"])
        for name in ("namespace", "kind", "id"):
            attributes[f"target.{name}"] = cast(str, target[name])
        attributes["safe.unchanged"] = True
        attributes["safe.preservation_manifest_sha256"] = cast(
            str, observation["preservation_manifest_sha256"]
        )
        attributes["safe.complement_before_sha256"] = cast(
            str, observation["safe_complement_before_sha256"]
        )
        attributes["safe.complement_after_sha256"] = cast(
            str, observation["safe_complement_after_sha256"]
        )
        attributes["safe.complement_proof_sha256"] = cast(
            str, observation["safe_complement_proof_sha256"]
        )
    else:
        attributes["action.status"] = "failed"
        attributes["action.reason_codes"] = ",".join(cast(list[str], observation["reason_codes"]))
    return attributes


def _metric_action_attributes(event: Mapping[str, Any]) -> dict[str, str | int | bool]:
    return {
        name: value
        for name, value in _flat_action_attributes(event).items()
        if not name.startswith("publication.")
    }


class ActionOtelSink:
    """An isolated OTLP pipeline with no caller-controlled attributes."""

    def __init__(
        self,
        endpoint: str = LOCAL_ACTION_OTLP_ENDPOINT,
        *,
        timeout_seconds: float = 10.0,
    ) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 30
        ):
            raise ValueError("action telemetry timeout is invalid")
        self.endpoint = _validated_otlp_endpoint(endpoint)
        resource = Resource.create(
            {
                "service.name": ACTION_TELEMETRY_SERVICE,
                "service.version": ACTION_TELEMETRY_SERVICE_VERSION,
                "telemetry.contract": ACTION_EVENT_VERSION,
            }
        )
        span_exporter = OTLPSpanExporter(
            endpoint=f"{self.endpoint}/v1/traces", timeout=timeout_seconds
        )
        self._tracer_provider = TracerProvider(resource=resource)
        self._tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        self._tracer = self._tracer_provider.get_tracer(
            ACTION_TELEMETRY_SERVICE, ACTION_TELEMETRY_SERVICE_VERSION
        )

        metric_exporter = OTLPMetricExporter(
            endpoint=f"{self.endpoint}/v1/metrics", timeout=timeout_seconds
        )
        self._metric_reader = PeriodicExportingMetricReader(
            metric_exporter, export_interval_millis=60_000
        )
        self._meter_provider = MeterProvider(
            resource=resource, metric_readers=[self._metric_reader]
        )
        meter = self._meter_provider.get_meter(
            ACTION_TELEMETRY_SERVICE, ACTION_TELEMETRY_SERVICE_VERSION
        )
        self._observations = meter.create_counter(
            "colortrace.simulator.action.observations",
            description="Terminal simulator action observations delivered",
        )

        log_exporter = OTLPLogExporter(endpoint=f"{self.endpoint}/v1/logs", timeout=timeout_seconds)
        self._logger_provider = LoggerProvider(resource=resource)
        self._logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        self._logging_handler = LoggingHandler(
            level=logging.INFO, logger_provider=self._logger_provider
        )
        self._logger = logging.getLogger(f"{ACTION_TELEMETRY_SERVICE}.actions.{id(self)}")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        self._logger.addHandler(self._logging_handler)
        self._shutdown = False

    def emit(self, event: ActionTelemetryEvent) -> None:
        document = event.to_dict()
        signal = document["signal"]
        if signal == "metric":
            self._observations.add(1, attributes=_metric_action_attributes(document))
            return
        attributes = _flat_action_attributes(document)
        if signal == "log":
            self._logger.info(document["event_name"], extra=attributes)
            return
        if signal != "trace":  # pragma: no cover - schema validation rejects this
            raise ValueError("action telemetry signal is invalid")
        correlation = cast(Mapping[str, Any], document["correlation"])
        trace_id = cast(str, correlation["trace_id"])
        parent_span_id = (
            int.from_bytes(hashlib.sha256(event.event_id.encode("ascii")).digest()[:8], "big") or 1
        )
        parent = NonRecordingSpan(
            SpanContext(
                trace_id=int(trace_id, 16),
                span_id=parent_span_id,
                is_remote=True,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
            )
        )
        context = trace.set_span_in_context(parent)
        start_time = int(
            parse_action_timestamp(
                document["action_started_at"], label="action_started_at"
            ).timestamp()
            * 1_000_000_000
        )
        end_time = int(
            parse_action_timestamp(
                document["action_completed_at"], label="action_completed_at"
            ).timestamp()
            * 1_000_000_000
        )
        span = self._tracer.start_span(
            document["event_name"], context=context, start_time=start_time
        )
        for name, child in attributes.items():
            span.set_attribute(name, child)
        span.end(end_time=max(start_time + 1, end_time))

    def force_flush(self) -> None:
        if not self._tracer_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("action trace telemetry flush timed out")
        if not self._logger_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("action log telemetry flush timed out")
        if not self._meter_provider.force_flush(timeout_millis=30_000):
            raise RuntimeError("action metric telemetry flush timed out")

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self._logger.removeHandler(self._logging_handler)
        self._tracer_provider.shutdown()
        self._logger_provider.shutdown()
        self._meter_provider.shutdown()


__all__ = [
    "ACTION_TELEMETRY_SERVICE",
    "ACTION_TELEMETRY_SERVICE_VERSION",
    "LOCAL_ACTION_OTLP_ENDPOINT",
    "ActionOtelSink",
    "ActionTelemetryEvent",
    "ActionTelemetrySink",
    "MemoryActionTelemetrySink",
    "build_action_events",
    "emit_action_outcome",
]
