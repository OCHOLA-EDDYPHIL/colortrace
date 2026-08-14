"""Strict correlated telemetry for ColorTrace simulator jobs."""

from colortrace_telemetry.action_contract import (
    ACTION_EVENT_VERSION,
    ACTION_RECEIPT_VERSION,
    validate_action_outcome,
)
from colortrace_telemetry.action_emitter import (
    ActionOtelSink,
    ActionTelemetrySink,
    MemoryActionTelemetrySink,
    build_action_events,
    emit_action_outcome,
)
from colortrace_telemetry.contract import (
    CORRELATION_VERSION,
    TELEMETRY_EVENT_VERSION,
    Correlation,
    DeliveryPlan,
    RuntimeJobs,
    load_runtime_jobs,
)

__all__ = [
    "ACTION_EVENT_VERSION",
    "ACTION_RECEIPT_VERSION",
    "CORRELATION_VERSION",
    "TELEMETRY_EVENT_VERSION",
    "ActionOtelSink",
    "ActionTelemetrySink",
    "Correlation",
    "DeliveryPlan",
    "MemoryActionTelemetrySink",
    "RuntimeJobs",
    "build_action_events",
    "emit_action_outcome",
    "load_runtime_jobs",
    "validate_action_outcome",
]
