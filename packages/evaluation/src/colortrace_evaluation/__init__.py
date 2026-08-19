"""Sealed and independently recomputable ColorTrace reliability evaluation."""

from .action_runner import execute_recovery_failure_case
from .campaign import (
    EvaluationError,
    aggregate_campaign,
    build_alert,
    build_campaign_plan,
    build_manual_no_gemini_control,
    build_no_grafana_control,
    build_run_record,
    derive_investigation_observation,
    derive_recovery_observation,
    prepare_fixture,
    verify_control_record,
)
from .contracts import canonical_json_bytes, prefixed_sha256, strict_json_file
from .evidence import build_action_recovery_evidence
from .runner import execute_investigation_slot

__all__ = [
    "EvaluationError",
    "aggregate_campaign",
    "build_alert",
    "build_action_recovery_evidence",
    "build_campaign_plan",
    "build_manual_no_gemini_control",
    "build_no_grafana_control",
    "build_run_record",
    "canonical_json_bytes",
    "execute_investigation_slot",
    "execute_recovery_failure_case",
    "derive_investigation_observation",
    "derive_recovery_observation",
    "prefixed_sha256",
    "prepare_fixture",
    "strict_json_file",
    "verify_control_record",
]
