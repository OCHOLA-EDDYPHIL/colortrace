from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import unicodedata
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast

from colortrace_fixture import CANONICAL_SEED
from colortrace_grafana_mcp import AdapterError
from colortrace_investigation import ContractError as InvestigationContractError
from colortrace_investigation import ModelFailure, WorkflowError
from colortrace_recovery import (
    CHECK_NAMES,
    RecoveryError,
    canonical_json_bytes,
    document_sha256,
    validate_closure_result,
)
from colortrace_response_plans import ResponsePlanError
from colortrace_response_plans.contracts import REJECTION_CODES
from colortrace_simulator.bundle import SimulatorBundleError
from colortrace_simulator.repository import SimulatorRepositoryError
from colortrace_vertical_slice import SliceContractError

from .auth import Principal
from .recovery import RecoveryApi

RUN_REQUEST_SCHEMA = "colortrace-demo-run-request/v2"
RUN_SCHEMA = "colortrace-demo-run/v1"
APPROVAL_REQUEST_SCHEMA = "colortrace-demo-approval-request/v1"
REJECTION_REQUEST_SCHEMA = "colortrace-demo-rejection-request/v1"
CLOSURE_REQUEST_SCHEMA = "colortrace-demo-closure-request/v1"
RESET_REQUEST_SCHEMA = "colortrace-demo-reset-request/v1"
RESET_SCHEMA = "colortrace-demo-reset/v1"
RECEIPT_SCHEMA = "colortrace-demo-receipt/v1"
PREPARATION_SCHEMA = "colortrace-demo-preparation/v1"
EXECUTION_SCHEMA = "colortrace-demo-execution/v1"
RECONCILIATION_REQUEST_SCHEMA = "colortrace-demo-reconciliation-request/v1"

CANONICAL_SCENARIO = CANONICAL_SEED
APPROVAL_PHRASE = "APPROVE_COLORTRACE_SIMULATOR_ACTION"
LEASE_SECONDS = 15 * 60
POLL_AFTER_MILLISECONDS = 1_000

_ACTIVE_PHASES = frozenset(
    {"preparing", "awaiting-approval", "executing", "awaiting-closure", "closing"}
)
_TRANSIENT_PHASES = frozenset({"preparing", "executing", "closing"})
_TERMINAL_PHASES = frozenset({"closed", "unresolved", "expired"})
_VISUAL_KINDS = frozenset({"expected", "observed", "recovered", "diff"})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_RUN_ID = re.compile(r"^demo-run-[0-9a-f]{32}$")
_INCIDENT_ID = re.compile(r"^incident-demo-[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_REASON_CODE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
_MAX_VISUAL_BYTES = 8 * 1024 * 1024
_INVESTIGATION_TOOLS = {
    "alert.rule": "alerting_manage_rules",
    "log.correlated-events": "query_loki_logs",
    "metric.correlated-observations": "query_prometheus",
    "trace.by-id": "tempo_get-trace",
}
BUILD_PROVENANCE_SCHEMA = "colortrace-demo-build-provenance/v1"
INVESTIGATION_PROOF_SCHEMA_V1 = "colortrace-demo-investigation-proof/v1"
INVESTIGATION_PROOF_SCHEMA = "colortrace-demo-investigation-proof/v2"
EXECUTION_PROOF_SCHEMA = "colortrace-demo-execution-proof/v1"
_REJECTION_RESULT_SCHEMA = "colortrace-demo-rejection-result/v1"
_SCENARIO_RESET_RESULT_SCHEMA = "simulator-authored-scenario-reset/v1"


class DemoFacadeError(RuntimeError):
    def __init__(self, code: str, *, run_id: str | None = None) -> None:
        if run_id is not None and (
            code not in {"demo-active-run-exists", "demo-reset-required"}
            or _RUN_ID.fullmatch(run_id) is None
        ):
            raise ValueError("demo-error-context-invalid")
        self.code = code
        self.run_id = run_id
        super().__init__(code)


_KNOWN_OPERATION_ERRORS = (
    DemoFacadeError,
    AdapterError,
    InvestigationContractError,
    ModelFailure,
    WorkflowError,
    RecoveryError,
    ResponsePlanError,
    SimulatorBundleError,
    SimulatorRepositoryError,
    SliceContractError,
)


class DemoWorkflowPort(Protocol):
    def prepare(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def reject(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def review_rejection(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None: ...

    def reconcile(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None: ...


class DemoScenarioResetPort(Protocol):
    def restore_authored_scenario(self, *, operation_id: str) -> Mapping[str, Any]: ...


class DemoApi(Protocol):
    def start(self, body: Mapping[str, Any]) -> dict[str, Any]: ...

    def get(self, run_id: str) -> dict[str, Any]: ...

    def approve(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]: ...

    def reject(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]: ...

    def close(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]: ...

    def reset(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]: ...

    def receipt(self, run_id: str) -> dict[str, Any]: ...

    def visual(self, run_id: str, kind: str) -> DemoVisual: ...


@dataclass(frozen=True, slots=True)
class DemoVisual:
    content: bytes
    media_type: str
    sha256: str


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise DemoFacadeError("demo-time-invalid")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: Any, *, code: str = "stored-demo-run-invalid") -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise DemoFacadeError(code)
    try:
        selected = datetime.fromisoformat(value[:-1] + "+00:00")
    except (OverflowError, ValueError):
        raise DemoFacadeError(code) from None
    if selected.tzinfo is None or selected.utcoffset() != timedelta(0):
        raise DemoFacadeError(code)
    selected = selected.astimezone(UTC)
    if _timestamp(selected) != value:
        raise DemoFacadeError(code)
    return selected


def _require_exact(value: Mapping[str, Any], fields: frozenset[str], schema: str) -> None:
    if set(value) != fields or value.get("schema") != schema:
        raise DemoFacadeError("demo-request-invalid")


def _require_identifier(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise DemoFacadeError(code)
    return value


def _require_version(value: Any, *, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise DemoFacadeError(code)
    return value


def _require_digest(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise DemoFacadeError(code)
    return value


def _optional_digest(value: Any, *, code: str) -> str | None:
    return None if value is None else _require_digest(value, code=code)


def _require_idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise DemoFacadeError("demo-idempotency-key-invalid")
    return value


def _nonce_sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('ascii')).hexdigest()}"


def _canonical_digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def _scenario_reset_operation_id(*, run_id: str, request_sha256: str) -> str:
    operation = {
        "schema": "colortrace-demo-scenario-reset-operation/v1",
        "run_id": run_id,
        "request_sha256": request_sha256,
    }
    return f"demo-reset:{hashlib.sha256(canonical_json_bytes(operation)).hexdigest()}"


def _validate_scenario_reset(
    value: Mapping[str, Any],
    *,
    operation_id: str,
) -> dict[str, Any]:
    fields = frozenset(
        {
            "schema",
            "operation_id",
            "fixture_id",
            "source_batch_sha256",
            "previous_pointer_sha256",
            "active_pointer_sha256",
            "generation",
        }
    )
    if set(value) != fields or value.get("schema") != _SCENARIO_RESET_RESULT_SCHEMA:
        raise DemoFacadeError("demo-reset-result-invalid")
    if value.get("operation_id") != operation_id or value.get("generation") != 1:
        raise DemoFacadeError("demo-reset-result-invalid")
    return {
        "schema": _SCENARIO_RESET_RESULT_SCHEMA,
        "operation_id": operation_id,
        "fixture_id": _require_identifier(
            value.get("fixture_id"), code="demo-reset-result-invalid"
        ),
        "source_batch_sha256": _require_digest(
            value.get("source_batch_sha256"), code="demo-reset-result-invalid"
        ),
        "previous_pointer_sha256": _require_digest(
            value.get("previous_pointer_sha256"), code="demo-reset-result-invalid"
        ),
        "active_pointer_sha256": _require_digest(
            value.get("active_pointer_sha256"), code="demo-reset-result-invalid"
        ),
        "generation": 1,
    }


def _decode_document(value: Any, *, code: str) -> dict[str, Any]:
    if not isinstance(value, bytes):
        raise DemoFacadeError(code)
    try:
        decoded = json.loads(value.decode("utf-8"))
        encoded = canonical_json_bytes(decoded)
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise DemoFacadeError(code) from None
    if not isinstance(decoded, dict) or encoded != value:
        raise DemoFacadeError(code)
    return cast(dict[str, Any], decoded)


def _build_provenance(value: Mapping[str, Any], *, source_commit: str) -> tuple[bytes, str]:
    try:
        encoded = canonical_json_bytes(value)
        decoded = json.loads(encoded)
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise DemoFacadeError("demo-build-provenance-invalid") from None
    if (
        not isinstance(decoded, dict)
        or decoded.get("schema") != BUILD_PROVENANCE_SCHEMA
        or decoded.get("source_commit") != source_commit
        or set(decoded) < {"schema", "source_commit"}
    ):
        raise DemoFacadeError("demo-build-provenance-invalid")
    return encoded, document_sha256(decoded)


def _relative_visual_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or "\\" in value
        or "\x00" in value
    ):
        raise DemoFacadeError("demo-visual-path-invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise DemoFacadeError("demo-visual-path-invalid")
    if path.suffix.lower() != ".png":
        raise DemoFacadeError("demo-visual-media-invalid")
    return path.as_posix()


_VISUAL_FIELDS = frozenset({"kind", "path", "sha256", "media_type"})


def _visual_descriptors(
    value: Any,
    *,
    required_kinds: frozenset[str],
) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) != len(required_kinds):
        raise DemoFacadeError("demo-visuals-invalid")
    selected: list[dict[str, str]] = []
    observed: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != _VISUAL_FIELDS:
            raise DemoFacadeError("demo-visuals-invalid")
        kind = raw.get("kind")
        if not isinstance(kind, str) or kind not in required_kinds or kind in observed:
            raise DemoFacadeError("demo-visuals-invalid")
        media_type = raw.get("media_type")
        if media_type != "image/png":
            raise DemoFacadeError("demo-visual-media-invalid")
        selected.append(
            {
                "kind": kind,
                "path": _relative_visual_path(raw.get("path")),
                "sha256": _require_digest(raw.get("sha256"), code="demo-visual-digest-invalid"),
                "media_type": media_type,
            }
        )
        observed.add(kind)
    if observed != set(required_kinds):
        raise DemoFacadeError("demo-visuals-invalid")
    return sorted(selected, key=lambda item: item["kind"])


def _bounded_count(value: Any, *, maximum: int, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise DemoFacadeError(code)
    return value


def _validate_investigation_proof_v1(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "packet_id",
        "packet_sha256",
        "status",
        "model_invocations",
        "evidence",
        "validators",
        "scope",
        "budget_use",
        "plan",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("schema") != INVESTIGATION_PROOF_SCHEMA_V1
        or value.get("status") not in {"resolved", "unresolved"}
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    invocation_fields = {
        "invocation_id",
        "turn_kind",
        "model",
        "framework",
        "result_class",
        "inventory_sha256",
        "output_sha256",
        "trace_id",
    }
    raw_invocations = value.get("model_invocations")
    if not isinstance(raw_invocations, list) or len(raw_invocations) > 6:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    invocations: list[dict[str, Any]] = []
    for raw in raw_invocations:
        if not isinstance(raw, Mapping) or set(raw) != invocation_fields:
            raise DemoFacadeError("demo-investigation-proof-invalid")
        turn = raw.get("turn_kind")
        result_class = raw.get("result_class")
        trace_id = raw.get("trace_id")
        if (
            turn not in {"evidence-selection", "response-drafting"}
            or result_class not in {"accepted", "budget-rejected", "failed", "invalid"}
            or not isinstance(trace_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", trace_id) is None
        ):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        invocations.append(
            {
                "invocation_id": _require_identifier(
                    raw.get("invocation_id"), code="demo-investigation-proof-invalid"
                ),
                "turn_kind": turn,
                "model": _require_identifier(
                    raw.get("model"), code="demo-investigation-proof-invalid"
                ),
                "framework": _require_identifier(
                    raw.get("framework"), code="demo-investigation-proof-invalid"
                ),
                "result_class": result_class,
                "inventory_sha256": _optional_digest(
                    raw.get("inventory_sha256"), code="demo-investigation-proof-invalid"
                ),
                "output_sha256": _optional_digest(
                    raw.get("output_sha256"), code="demo-investigation-proof-invalid"
                ),
                "trace_id": trace_id,
            }
        )
    evidence_fields = {
        "evidence_id",
        "query_key",
        "tool",
        "inventory_sha256",
        "content_sha256",
        "freshness",
    }
    raw_evidence = value.get("evidence")
    if not isinstance(raw_evidence, list) or not 1 <= len(raw_evidence) <= 8:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    evidence: list[dict[str, str]] = []
    query_keys: set[str] = set()
    for raw in raw_evidence:
        if not isinstance(raw, Mapping) or set(raw) != evidence_fields:
            raise DemoFacadeError("demo-investigation-proof-invalid")
        query_key = _require_identifier(
            raw.get("query_key"), code="demo-investigation-proof-invalid"
        )
        if query_key in query_keys or raw.get("freshness") not in {
            "current",
            "stale",
            "unresolved",
        }:
            raise DemoFacadeError("demo-investigation-proof-invalid")
        query_keys.add(query_key)
        evidence.append(
            {
                "evidence_id": _require_digest(
                    raw.get("evidence_id"), code="demo-investigation-proof-invalid"
                ),
                "query_key": query_key,
                "tool": _require_identifier(
                    raw.get("tool"), code="demo-investigation-proof-invalid"
                ),
                "inventory_sha256": _require_digest(
                    raw.get("inventory_sha256"), code="demo-investigation-proof-invalid"
                ),
                "content_sha256": _require_digest(
                    raw.get("content_sha256"), code="demo-investigation-proof-invalid"
                ),
                "freshness": cast(str, raw["freshness"]),
            }
        )
    validator_fields = {
        "result_id",
        "validator",
        "validator_version",
        "status",
        "derivation_sha256",
    }
    raw_validators = value.get("validators")
    if not isinstance(raw_validators, list) or not 1 <= len(raw_validators) <= 16:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    validators: list[dict[str, str]] = []
    for raw in raw_validators:
        if (
            not isinstance(raw, Mapping)
            or set(raw) != validator_fields
            or raw.get("status") not in {"resolved", "unresolved"}
        ):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        validators.append(
            {
                "result_id": _require_identifier(
                    raw.get("result_id"), code="demo-investigation-proof-invalid"
                ),
                "validator": _require_identifier(
                    raw.get("validator"), code="demo-investigation-proof-invalid"
                ),
                "validator_version": _require_identifier(
                    raw.get("validator_version"), code="demo-investigation-proof-invalid"
                ),
                "status": cast(str, raw["status"]),
                "derivation_sha256": _require_digest(
                    raw.get("derivation_sha256"),
                    code="demo-investigation-proof-invalid",
                ),
            }
        )
    scope = value.get("scope")
    if not isinstance(scope, Mapping) or set(scope) != {
        "state",
        "affected_count",
        "safe_count",
        "unknown_count",
    }:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    if scope.get("state") not in {"resolved", "unresolved"}:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    budget = value.get("budget_use")
    budget_fields = {
        "elapsed_ms",
        "model_turns",
        "input_tokens",
        "output_tokens",
        "mcp_attempts",
        "validator_calls",
    }
    if not isinstance(budget, Mapping) or set(budget) != budget_fields:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    plan = value.get("plan")
    if (
        not isinstance(plan, Mapping)
        or set(plan) != {"status", "version", "plan_sha256", "target_sha256"}
        or plan.get("status") not in {"pending", "approved", "rejected", "stale"}
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    return {
        "schema": INVESTIGATION_PROOF_SCHEMA_V1,
        "packet_id": _require_identifier(
            value.get("packet_id"), code="demo-investigation-proof-invalid"
        ),
        "packet_sha256": _require_digest(
            value.get("packet_sha256"), code="demo-investigation-proof-invalid"
        ),
        "status": value["status"],
        "model_invocations": invocations,
        "evidence": evidence,
        "validators": validators,
        "scope": {
            "state": scope["state"],
            "affected_count": _bounded_count(
                scope.get("affected_count"), maximum=256, code="demo-investigation-proof-invalid"
            ),
            "safe_count": _bounded_count(
                scope.get("safe_count"), maximum=256, code="demo-investigation-proof-invalid"
            ),
            "unknown_count": _bounded_count(
                scope.get("unknown_count"), maximum=256, code="demo-investigation-proof-invalid"
            ),
        },
        "budget_use": {
            key: _bounded_count(
                budget.get(key), maximum=10_000_000, code="demo-investigation-proof-invalid"
            )
            for key in sorted(budget_fields)
        },
        "plan": {
            "status": plan["status"],
            "version": _require_version(
                plan.get("version"), code="demo-investigation-proof-invalid"
            ),
            "plan_sha256": _require_digest(
                plan.get("plan_sha256"), code="demo-investigation-proof-invalid"
            ),
            "target_sha256": _require_digest(
                plan.get("target_sha256"), code="demo-investigation-proof-invalid"
            ),
        },
    }


def _plain_text_excerpt(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 1_024
        or len(value.encode("utf-8")) > 4_096
        or any(
            unicodedata.category(character).startswith("C")
            for character in value
            if character not in {"\n", "\t"}
        )
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    return value


_TARGET_FIELDS = frozenset({"schema", "namespace", "kind", "id"})


def _validate_review_target(value: Any) -> dict[str, str]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _TARGET_FIELDS
        or value.get("schema") != "simulator-target/v1"
        or value.get("namespace") != "colortrace-simulator"
        or value.get("kind") not in {"color-resource", "frame", "derivative"}
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    return {
        "schema": "simulator-target/v1",
        "namespace": "colortrace-simulator",
        "kind": cast(str, value["kind"]),
        "id": _require_identifier(value.get("id"), code="demo-investigation-proof-invalid"),
    }


def _validate_review_targets(
    value: Any,
    *,
    minimum: int,
    maximum: int,
) -> list[dict[str, str]]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    targets = [_validate_review_target(item) for item in value]
    if len({canonical_json_bytes(item) for item in targets}) != len(targets):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    return targets


def _validate_command_summaries(
    value: Any,
    *,
    targets: Sequence[Mapping[str, str]],
    expected_config_sha256: str,
    expected_resource_sha256: str,
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) != 5:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    summaries: list[dict[str, Any]] = []
    command_ids: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        schema = raw.get("schema")
        target = _validate_review_target(raw.get("target"))
        command_id = _require_identifier(
            raw.get("command_id"), code="demo-investigation-proof-invalid"
        )
        if command_id in command_ids or raw.get("namespace") != "colortrace-simulator":
            raise DemoFacadeError("demo-investigation-proof-invalid")
        command_ids.add(command_id)
        if schema == "simulator-quarantine-command/v1":
            if (
                set(raw)
                != {
                    "schema",
                    "command_id",
                    "namespace",
                    "target",
                    "expected_resource_sha256",
                    "mode",
                }
                or target["kind"] != "color-resource"
                or raw.get("mode") != "quarantine-and-install-approved-replacement"
                or raw.get("expected_resource_sha256") != expected_resource_sha256
            ):
                raise DemoFacadeError("demo-investigation-proof-invalid")
            summaries.append(
                {
                    "schema": schema,
                    "command_id": command_id,
                    "namespace": "colortrace-simulator",
                    "target": target,
                    "expected_resource_sha256": _require_digest(
                        raw.get("expected_resource_sha256"),
                        code="demo-investigation-proof-invalid",
                    ),
                    "mode": "quarantine-and-install-approved-replacement",
                }
            )
            continue
        if schema != "simulator-targeted-rerender-command/v1":
            raise DemoFacadeError("demo-investigation-proof-invalid")
        common = {
            "schema",
            "command_id",
            "namespace",
            "target",
            "job_id",
            "transform_id",
            "source_id",
            "source_manifest_sha256",
            "source_png_sha256",
            "expected_config_sha256",
            "lineage_parent_artifact_id",
        }
        artifact_fields = (
            {"expected_output_sha256", "expected_display_sha256"}
            if target["kind"] == "frame"
            else {"expected_derivative_sha256", "expected_derivative_display_sha256"}
        )
        if (
            target["kind"] not in {"frame", "derivative"}
            or set(raw) != common | artifact_fields
            or raw.get("transform_id") not in {"look/main/v1", "identity/v1"}
            or raw.get("expected_config_sha256") != expected_config_sha256
        ):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        summary: dict[str, Any] = {
            "schema": schema,
            "command_id": command_id,
            "namespace": "colortrace-simulator",
            "target": target,
            "job_id": _require_identifier(
                raw.get("job_id"), code="demo-investigation-proof-invalid"
            ),
            "transform_id": cast(str, raw["transform_id"]),
            "source_id": _require_identifier(
                raw.get("source_id"), code="demo-investigation-proof-invalid"
            ),
            "source_manifest_sha256": _require_digest(
                raw.get("source_manifest_sha256"), code="demo-investigation-proof-invalid"
            ),
            "source_png_sha256": _require_digest(
                raw.get("source_png_sha256"), code="demo-investigation-proof-invalid"
            ),
            "expected_config_sha256": _require_digest(
                raw.get("expected_config_sha256"), code="demo-investigation-proof-invalid"
            ),
            "lineage_parent_artifact_id": _require_identifier(
                raw.get("lineage_parent_artifact_id"),
                code="demo-investigation-proof-invalid",
            ),
        }
        for field in sorted(artifact_fields):
            summary[field] = _require_digest(
                raw.get(field), code="demo-investigation-proof-invalid"
            )
        summaries.append(summary)
    if {canonical_json_bytes(cast(Mapping[str, Any], item["target"])) for item in summaries} != {
        canonical_json_bytes(item) for item in targets
    }:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    if sum(item["schema"] == "simulator-quarantine-command/v1" for item in summaries) != 1:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    return summaries


def _validate_investigation_proof_v2(value: Any) -> dict[str, Any]:
    fields = {
        "schema",
        "packet_id",
        "packet_sha256",
        "status",
        "adjudication",
        "model_invocations",
        "comparison",
        "claims",
        "evidence",
        "validators",
        "scope",
        "budget_use",
        "plan",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("schema") != INVESTIGATION_PROOF_SCHEMA
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    plan = value.get("plan")
    plan_fields = {
        "status",
        "version",
        "plan_sha256",
        "target_sha256",
        "exclusions_sha256",
        "commands_sha256",
        "targets",
        "protected_exclusions",
        "shared_action_bindings",
        "command_summaries",
    }
    if not isinstance(plan, Mapping) or set(plan) != plan_fields:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    raw_evidence = value.get("evidence")
    if not isinstance(raw_evidence, list):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    legacy_evidence: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    evidence_fields = {
        "evidence_id",
        "query_key",
        "tool",
        "inventory_sha256",
        "content_sha256",
        "freshness",
        "display_excerpt",
        "display_excerpt_truncated",
    }
    for raw in raw_evidence:
        if (
            not isinstance(raw, Mapping)
            or set(raw) != evidence_fields
            or not isinstance(raw.get("display_excerpt_truncated"), bool)
        ):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        base = {
            key: raw[key]
            for key in raw
            if key
            not in {
                "display_excerpt",
                "display_excerpt_truncated",
            }
        }
        legacy_evidence.append(base)
        evidence.append(
            {
                **base,
                "display_excerpt": _plain_text_excerpt(raw.get("display_excerpt")),
                "display_excerpt_truncated": raw["display_excerpt_truncated"],
            }
        )
    legacy = _validate_investigation_proof_v1(
        {
            "schema": INVESTIGATION_PROOF_SCHEMA_V1,
            "packet_id": value.get("packet_id"),
            "packet_sha256": value.get("packet_sha256"),
            "status": value.get("status"),
            "model_invocations": value.get("model_invocations"),
            "evidence": legacy_evidence,
            "validators": value.get("validators"),
            "scope": value.get("scope"),
            "budget_use": value.get("budget_use"),
            "plan": {
                key: plan.get(key) for key in ("status", "version", "plan_sha256", "target_sha256")
            },
        }
    )
    if (
        legacy["packet_id"] != f"response-packet:{legacy['packet_sha256'].removeprefix('sha256:')}"
        or any(
            item["result_id"]
            != f"validation-result:{item['derivation_sha256'].removeprefix('sha256:')}"
            for item in legacy["validators"]
        )
        or len({item["evidence_id"] for item in legacy["evidence"]}) != len(legacy["evidence"])
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    adjudication = value.get("adjudication")
    if adjudication != {
        "model_role": "evidence-selection-and-advisory-drafting",
        "model_authority": "advisory-only",
        "validator_role": "deterministic-claim-adjudication",
        "decision_mode": "deterministic-validation",
    }:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    comparison = value.get("comparison")
    if (
        not isinstance(comparison, Mapping)
        or set(comparison) != {"renders", "nominal_config_match", "resolved_lut_match"}
        or comparison.get("nominal_config_match") is not True
        or comparison.get("resolved_lut_match") is not False
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    raw_renders = comparison.get("renders")
    if not isinstance(raw_renders, list) or len(raw_renders) != 2:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    renders: list[dict[str, str]] = []
    for raw in raw_renders:
        if (
            not isinstance(raw, Mapping)
            or set(raw)
            != {
                "job_id",
                "worker_id",
                "status",
                "nominal_config_sha256",
                "resolved_lut_sha256",
            }
            or raw.get("status") != "succeeded"
        ):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        renders.append(
            {
                "job_id": _require_identifier(
                    raw.get("job_id"), code="demo-investigation-proof-invalid"
                ),
                "worker_id": _require_identifier(
                    raw.get("worker_id"), code="demo-investigation-proof-invalid"
                ),
                "status": "succeeded",
                "nominal_config_sha256": _require_digest(
                    raw.get("nominal_config_sha256"),
                    code="demo-investigation-proof-invalid",
                ),
                "resolved_lut_sha256": _require_digest(
                    raw.get("resolved_lut_sha256"),
                    code="demo-investigation-proof-invalid",
                ),
            }
        )
    if (
        len({item["job_id"] for item in renders}) != 2
        or len({item["worker_id"] for item in renders}) != 2
        or len({item["nominal_config_sha256"] for item in renders}) != 1
        or len({item["resolved_lut_sha256"] for item in renders}) != 2
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    raw_claims = value.get("claims")
    if not isinstance(raw_claims, list) or not 1 <= len(raw_claims) <= 16:
        raise DemoFacadeError("demo-investigation-proof-invalid")
    claims: list[dict[str, Any]] = []
    claim_ids: set[str] = set()
    claim_fields = {
        "claim_id",
        "claim_type",
        "subject",
        "state",
        "reason_codes",
        "evidence_ids",
        "source_validator_result_id",
    }
    validator_ids = {item["result_id"] for item in legacy["validators"]}
    if len(validator_ids) != len(legacy["validators"]):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    for raw in raw_claims:
        if (
            not isinstance(raw, Mapping)
            or set(raw) != claim_fields
            or raw.get("state") not in {"confirmed", "rejected"}
        ):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        claim_id = _require_identifier(raw.get("claim_id"), code="demo-investigation-proof-invalid")
        subject = raw.get("subject")
        reasons = raw.get("reason_codes")
        links = raw.get("evidence_ids")
        if (
            claim_id in claim_ids
            or not isinstance(subject, Mapping)
            or set(subject) != {"kind", "value"}
            or not isinstance(reasons, list)
            or not 1 <= len(reasons) <= 16
            or len(set(reasons)) != len(reasons)
            or any(
                not isinstance(reason, str) or _REASON_CODE.fullmatch(reason) is None
                for reason in reasons
            )
            or not isinstance(links, list)
            or not 1 <= len(links) <= 64
            or len(set(links)) != len(links)
        ):
            raise DemoFacadeError("demo-investigation-proof-invalid")
        claim_ids.add(claim_id)
        claims.append(
            {
                "claim_id": claim_id,
                "claim_type": _require_identifier(
                    raw.get("claim_type"), code="demo-investigation-proof-invalid"
                ),
                "subject": {
                    "kind": _require_identifier(
                        subject.get("kind"), code="demo-investigation-proof-invalid"
                    ),
                    "value": _require_identifier(
                        subject.get("value"), code="demo-investigation-proof-invalid"
                    ),
                },
                "state": raw["state"],
                "reason_codes": list(reasons),
                "evidence_ids": [
                    _require_identifier(link, code="demo-investigation-proof-invalid")
                    for link in links
                ],
                "source_validator_result_id": _require_identifier(
                    raw.get("source_validator_result_id"),
                    code="demo-investigation-proof-invalid",
                ),
            }
        )
    if {item["state"] for item in claims} != {"confirmed", "rejected"} or any(
        item["source_validator_result_id"] not in validator_ids for item in claims
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    targets = _validate_review_targets(plan.get("targets"), minimum=1, maximum=8)
    exclusions = _validate_review_targets(plan.get("protected_exclusions"), minimum=0, maximum=8)
    if (
        len(targets) != 5
        or len(exclusions) != 3
        or {item["kind"] for item in exclusions} != {"frame"}
        or sum(item["kind"] == "color-resource" for item in targets) != 1
        or sum(item["kind"] == "frame" for item in targets) != 3
        or sum(item["kind"] == "derivative" for item in targets) != 1
        or {canonical_json_bytes(item) for item in targets}
        & {canonical_json_bytes(item) for item in exclusions}
        or _canonical_digest(targets) != plan.get("target_sha256")
        or _canonical_digest(exclusions) != plan.get("exclusions_sha256")
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    bindings = plan.get("shared_action_bindings")
    binding_fields = {
        "schema",
        "fixture_id",
        "fixture_manifest_sha256",
        "fixture_generation",
        "source_batch_id",
        "source_batch_sha256",
        "runtime_manifest_sha256",
        "runtime_generation",
        "expected_publication_pointer_sha256",
        "expected_publication_generation",
        "expected_resource_sha256",
        "replacement_resource_logical_path",
        "replacement_resource_sha256",
        "declared_resource_manifest_sha256",
        "ocio_version",
        "preservation_manifest_sha256",
        "safe_complement_sha256",
        "lineage_manifest_sha256",
        "lineage_generation",
    }
    if (
        not isinstance(bindings, Mapping)
        or set(bindings) != binding_fields
        or bindings.get("schema") != "simulator-action-envelope/v1"
        or bindings.get("replacement_resource_logical_path") != "luts/show_look.cube"
        or bindings.get("ocio_version") != "2.5.2"
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    selected_bindings = {
        "schema": "simulator-action-envelope/v1",
        "fixture_id": _require_identifier(
            bindings.get("fixture_id"), code="demo-investigation-proof-invalid"
        ),
        "fixture_manifest_sha256": _require_digest(
            bindings.get("fixture_manifest_sha256"), code="demo-investigation-proof-invalid"
        ),
        "fixture_generation": _require_version(
            bindings.get("fixture_generation"), code="demo-investigation-proof-invalid"
        ),
        "source_batch_id": _require_identifier(
            bindings.get("source_batch_id"), code="demo-investigation-proof-invalid"
        ),
        "source_batch_sha256": _require_digest(
            bindings.get("source_batch_sha256"), code="demo-investigation-proof-invalid"
        ),
        "runtime_manifest_sha256": _require_digest(
            bindings.get("runtime_manifest_sha256"), code="demo-investigation-proof-invalid"
        ),
        "runtime_generation": _require_version(
            bindings.get("runtime_generation"), code="demo-investigation-proof-invalid"
        ),
        "expected_publication_pointer_sha256": _require_digest(
            bindings.get("expected_publication_pointer_sha256"),
            code="demo-investigation-proof-invalid",
        ),
        "expected_publication_generation": _require_version(
            bindings.get("expected_publication_generation"),
            code="demo-investigation-proof-invalid",
        ),
        "expected_resource_sha256": _require_digest(
            bindings.get("expected_resource_sha256"), code="demo-investigation-proof-invalid"
        ),
        "replacement_resource_logical_path": "luts/show_look.cube",
        "replacement_resource_sha256": _require_digest(
            bindings.get("replacement_resource_sha256"),
            code="demo-investigation-proof-invalid",
        ),
        "declared_resource_manifest_sha256": _require_digest(
            bindings.get("declared_resource_manifest_sha256"),
            code="demo-investigation-proof-invalid",
        ),
        "ocio_version": _require_identifier(
            bindings.get("ocio_version"), code="demo-investigation-proof-invalid"
        ),
        "preservation_manifest_sha256": _require_digest(
            bindings.get("preservation_manifest_sha256"),
            code="demo-investigation-proof-invalid",
        ),
        "safe_complement_sha256": _require_digest(
            bindings.get("safe_complement_sha256"), code="demo-investigation-proof-invalid"
        ),
        "lineage_manifest_sha256": _require_digest(
            bindings.get("lineage_manifest_sha256"), code="demo-investigation-proof-invalid"
        ),
        "lineage_generation": _require_version(
            bindings.get("lineage_generation"), code="demo-investigation-proof-invalid"
        ),
    }
    generations = {
        selected_bindings["fixture_generation"],
        selected_bindings["runtime_generation"],
        selected_bindings["expected_publication_generation"],
        selected_bindings["lineage_generation"],
    }
    resource_targets = [item for item in targets if item["kind"] == "color-resource"]
    if (
        resource_targets[0]["id"] != selected_bindings["expected_resource_sha256"]
        or selected_bindings["expected_resource_sha256"]
        == selected_bindings["replacement_resource_sha256"]
        or len(generations) != 1
    ):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    summaries = _validate_command_summaries(
        plan.get("command_summaries"),
        targets=targets,
        expected_config_sha256=renders[0]["nominal_config_sha256"],
        expected_resource_sha256=selected_bindings["expected_resource_sha256"],
    )
    commands = [{**summary, "action_envelope": selected_bindings} for summary in summaries]
    if _canonical_digest(commands) != plan.get("commands_sha256"):
        raise DemoFacadeError("demo-investigation-proof-invalid")
    return {
        "schema": INVESTIGATION_PROOF_SCHEMA,
        "packet_id": legacy["packet_id"],
        "packet_sha256": legacy["packet_sha256"],
        "status": legacy["status"],
        "adjudication": dict(adjudication),
        "model_invocations": legacy["model_invocations"],
        "comparison": {
            "renders": renders,
            "nominal_config_match": True,
            "resolved_lut_match": False,
        },
        "claims": claims,
        "evidence": evidence,
        "validators": legacy["validators"],
        "scope": legacy["scope"],
        "budget_use": legacy["budget_use"],
        "plan": {
            "status": legacy["plan"]["status"],
            "version": legacy["plan"]["version"],
            "plan_sha256": legacy["plan"]["plan_sha256"],
            "target_sha256": legacy["plan"]["target_sha256"],
            "exclusions_sha256": _require_digest(
                plan.get("exclusions_sha256"), code="demo-investigation-proof-invalid"
            ),
            "commands_sha256": _require_digest(
                plan.get("commands_sha256"), code="demo-investigation-proof-invalid"
            ),
            "targets": targets,
            "protected_exclusions": exclusions,
            "shared_action_bindings": selected_bindings,
            "command_summaries": summaries,
        },
    }


def _validate_investigation_proof(
    value: Any,
    *,
    stored: bool = False,
) -> dict[str, Any]:
    schema = value.get("schema") if isinstance(value, Mapping) else None
    if schema == INVESTIGATION_PROOF_SCHEMA:
        return _validate_investigation_proof_v2(value)
    if stored and schema == INVESTIGATION_PROOF_SCHEMA_V1:
        return _validate_investigation_proof_v1(value)
    raise DemoFacadeError("demo-investigation-proof-invalid")


def _validate_execution_proof(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"schema", "action", "recovery"}
        or value.get("schema") != EXECUTION_PROOF_SCHEMA
    ):
        raise DemoFacadeError("demo-execution-proof-invalid")
    action = value.get("action")
    action_fields = {
        "action_id",
        "status",
        "outcome_id",
        "outcome_sha256",
        "publication_generation_before",
        "publication_generation_after",
        "affected_count",
        "safe_count",
        "safe_complement_before_sha256",
        "safe_complement_after_sha256",
        "safe_complement_proof_sha256",
        "publication_receipt_sha256",
    }
    if (
        not isinstance(action, Mapping)
        or set(action) != action_fields
        or action.get("status") != "succeeded"
    ):
        raise DemoFacadeError("demo-execution-proof-invalid")
    recovery = value.get("recovery")
    recovery_fields = {
        "status",
        "workflow_id",
        "workflow_version",
        "packet_id",
        "packet_sha256",
        "evidence_count",
        "evidence_request_sha256",
        "checks",
    }
    if (
        not isinstance(recovery, Mapping)
        or set(recovery) != recovery_fields
        or recovery.get("status")
        not in {"recovery_verified", "recovery_failed", "recovery_unresolved"}
    ):
        raise DemoFacadeError("demo-execution-proof-invalid")
    checks = recovery.get("checks")
    if not isinstance(checks, list) or not 1 <= len(checks) <= 7:
        raise DemoFacadeError("demo-execution-proof-invalid")
    selected_checks: list[dict[str, str]] = []
    for raw in checks:
        if (
            not isinstance(raw, Mapping)
            or set(raw) != {"check", "status", "result_sha256"}
            or raw.get("status") not in {"passed", "failed", "unresolved"}
        ):
            raise DemoFacadeError("demo-execution-proof-invalid")
        selected_checks.append(
            {
                "check": _require_identifier(raw.get("check"), code="demo-execution-proof-invalid"),
                "status": cast(str, raw["status"]),
                "result_sha256": _require_digest(
                    raw.get("result_sha256"), code="demo-execution-proof-invalid"
                ),
            }
        )
    return {
        "schema": EXECUTION_PROOF_SCHEMA,
        "action": {
            "action_id": _require_identifier(
                action.get("action_id"), code="demo-execution-proof-invalid"
            ),
            "status": "succeeded",
            "outcome_id": _require_identifier(
                action.get("outcome_id"), code="demo-execution-proof-invalid"
            ),
            "outcome_sha256": _require_digest(
                action.get("outcome_sha256"), code="demo-execution-proof-invalid"
            ),
            "publication_generation_before": _require_version(
                action.get("publication_generation_before"),
                code="demo-execution-proof-invalid",
            ),
            "publication_generation_after": _require_version(
                action.get("publication_generation_after"),
                code="demo-execution-proof-invalid",
            ),
            "affected_count": _bounded_count(
                action.get("affected_count"), maximum=256, code="demo-execution-proof-invalid"
            ),
            "safe_count": _bounded_count(
                action.get("safe_count"), maximum=256, code="demo-execution-proof-invalid"
            ),
            "safe_complement_before_sha256": _require_digest(
                action.get("safe_complement_before_sha256"),
                code="demo-execution-proof-invalid",
            ),
            "safe_complement_after_sha256": _require_digest(
                action.get("safe_complement_after_sha256"),
                code="demo-execution-proof-invalid",
            ),
            "safe_complement_proof_sha256": _require_digest(
                action.get("safe_complement_proof_sha256"),
                code="demo-execution-proof-invalid",
            ),
            "publication_receipt_sha256": _require_digest(
                action.get("publication_receipt_sha256"),
                code="demo-execution-proof-invalid",
            ),
        },
        "recovery": {
            "status": recovery["status"],
            "workflow_id": _require_identifier(
                recovery.get("workflow_id"), code="demo-execution-proof-invalid"
            ),
            "workflow_version": _require_version(
                recovery.get("workflow_version"), code="demo-execution-proof-invalid"
            ),
            "packet_id": _require_identifier(
                recovery.get("packet_id"), code="demo-execution-proof-invalid"
            ),
            "packet_sha256": _require_digest(
                recovery.get("packet_sha256"), code="demo-execution-proof-invalid"
            ),
            "evidence_count": _bounded_count(
                recovery.get("evidence_count"), maximum=256, code="demo-execution-proof-invalid"
            ),
            "evidence_request_sha256": _require_digest(
                recovery.get("evidence_request_sha256"),
                code="demo-execution-proof-invalid",
            ),
            "checks": selected_checks,
        },
    }


_PREPARATION_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "incident_id",
        "incident_version",
        "plan_version",
        "plan_sha256",
        "target_sha256",
        "visuals",
    }
)
_PREPARATION_PROOF_FIELDS = _PREPARATION_FIELDS | {"investigation"}


def _validate_preparation(
    value: Mapping[str, Any],
    *,
    run_id: str,
    incident_id: str,
) -> dict[str, Any]:
    if set(value) != _PREPARATION_PROOF_FIELDS or value.get("schema") != PREPARATION_SCHEMA:
        raise DemoFacadeError("demo-preparation-invalid")
    if value.get("run_id") != run_id or value.get("incident_id") != incident_id:
        raise DemoFacadeError("demo-preparation-binding-invalid")
    result = {
        "incident_version": _require_version(
            value.get("incident_version"), code="demo-incident-version-invalid"
        ),
        "plan_version": _require_version(
            value.get("plan_version"), code="demo-plan-version-invalid"
        ),
        "plan_sha256": _require_digest(value.get("plan_sha256"), code="demo-plan-digest-invalid"),
        "target_sha256": _require_digest(
            value.get("target_sha256"), code="demo-target-digest-invalid"
        ),
        "visuals": _visual_descriptors(
            value.get("visuals"),
            required_kinds=frozenset({"expected", "observed", "diff"}),
        ),
    }
    proof = _validate_investigation_proof(value["investigation"])
    scope = cast(Mapping[str, Any], proof["scope"])
    plan = cast(Mapping[str, Any], proof["plan"])
    evidence = cast(Sequence[Mapping[str, Any]], proof["evidence"])
    invocations = cast(Sequence[Mapping[str, Any]], proof["model_invocations"])
    accepted_invocations = [item for item in invocations if item["result_class"] == "accepted"]
    inventory_versions = {item["inventory_sha256"] for item in evidence}
    if (
        proof["status"] != "resolved"
        or (scope["affected_count"], scope["safe_count"], scope["unknown_count"]) != (4, 3, 0)
        or plan["status"] != "pending"
        or plan["version"] != result["plan_version"]
        or plan["plan_sha256"] != result["plan_sha256"]
        or plan["target_sha256"] != result["target_sha256"]
        or {item["query_key"] for item in evidence} != set(_INVESTIGATION_TOOLS)
        or any(item["tool"] != _INVESTIGATION_TOOLS[item["query_key"]] for item in evidence)
        or any(item["freshness"] != "current" for item in evidence)
        or len(inventory_versions) != 1
        or len(invocations) < 2
        or {item["turn_kind"] for item in accepted_invocations}
        != {"evidence-selection", "response-drafting"}
        or any(item["inventory_sha256"] not in inventory_versions for item in accepted_invocations)
        or any(item["status"] != "resolved" for item in proof["validators"])
    ):
        raise DemoFacadeError("demo-investigation-proof-binding-invalid")
    result["investigation"] = proof
    return result


_EXECUTION_FIELDS = frozenset(
    {
        "schema",
        "run_id",
        "incident_id",
        "incident_version",
        "plan_version",
        "plan_sha256",
        "target_sha256",
        "idempotency_key",
        "outcome_id",
        "outcome_sha256",
        "workflow_id",
        "workflow_version",
        "packet_id",
        "packet_sha256",
        "visuals",
    }
)
_EXECUTION_PROOF_FIELDS = _EXECUTION_FIELDS | {"execution"}


def _validate_execution(
    value: Mapping[str, Any],
    *,
    run: Mapping[str, Any],
) -> dict[str, Any]:
    if set(value) != _EXECUTION_PROOF_FIELDS or value.get("schema") != EXECUTION_SCHEMA:
        raise DemoFacadeError("demo-execution-invalid")
    if (
        value.get("run_id") != run["run_id"]
        or value.get("incident_id") != run["incident_id"]
        or value.get("incident_version") != run["incident_version"]
        or value.get("plan_version") != run["plan_version"]
        or value.get("plan_sha256") != run["plan_sha256"]
        or value.get("target_sha256") != run["target_sha256"]
    ):
        raise DemoFacadeError("demo-execution-binding-invalid")
    result = {
        "outcome_id": _require_identifier(value.get("outcome_id"), code="demo-outcome-id-invalid"),
        "outcome_sha256": _require_digest(
            value.get("outcome_sha256"), code="demo-outcome-digest-invalid"
        ),
        "workflow_id": _require_identifier(
            value.get("workflow_id"), code="demo-workflow-id-invalid"
        ),
        "workflow_version": _require_version(
            value.get("workflow_version"), code="demo-workflow-version-invalid"
        ),
        "packet_id": _require_identifier(value.get("packet_id"), code="demo-packet-id-invalid"),
        "packet_sha256": _require_digest(
            value.get("packet_sha256"), code="demo-packet-digest-invalid"
        ),
        "plan_version": _require_version(
            value.get("plan_version"), code="demo-plan-version-invalid"
        ),
        "plan_sha256": _require_digest(value.get("plan_sha256"), code="demo-plan-digest-invalid"),
        "target_sha256": _require_digest(
            value.get("target_sha256"), code="demo-target-digest-invalid"
        ),
        "idempotency_key": _require_idempotency_key(value.get("idempotency_key")),
        "visuals": _visual_descriptors(
            value.get("visuals"), required_kinds=frozenset({"recovered"})
        ),
    }
    proof = _validate_execution_proof(value["execution"])
    action = cast(Mapping[str, Any], proof["action"])
    recovery = cast(Mapping[str, Any], proof["recovery"])
    if (
        action["outcome_id"] != result["outcome_id"]
        or action["outcome_sha256"] != result["outcome_sha256"]
        or action["publication_generation_after"]
        != cast(int, action["publication_generation_before"]) + 1
        or action["affected_count"] != 4
        or action["safe_count"] != 3
        or action["safe_complement_before_sha256"] != action["safe_complement_after_sha256"]
        or recovery["status"] != "recovery_verified"
        or recovery["workflow_id"] != result["workflow_id"]
        or recovery["workflow_version"] != result["workflow_version"]
        or recovery["packet_id"] != result["packet_id"]
        or recovery["packet_sha256"] != result["packet_sha256"]
        or recovery["evidence_count"] != 21
        or [item["check"] for item in cast(Sequence[Mapping[str, Any]], recovery["checks"])]
        != list(CHECK_NAMES)
        or any(
            item["status"] != "passed"
            for item in cast(Sequence[Mapping[str, Any]], recovery["checks"])
        )
    ):
        raise DemoFacadeError("demo-execution-proof-binding-invalid")
    result["execution"] = proof
    return result


_SCHEMA = """
CREATE TABLE demo_runs (
    run_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE,
    scenario_id TEXT NOT NULL,
    start_idempotency_key TEXT NOT NULL UNIQUE,
    start_request_sha256 TEXT NOT NULL,
    source_commit TEXT NOT NULL,
    build_sha256 TEXT NOT NULL,
    build_document BLOB NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN (
        'preparing', 'awaiting-approval', 'executing', 'awaiting-closure',
        'closing', 'closed', 'unresolved', 'expired'
    )),
    version INTEGER NOT NULL CHECK(version >= 1),
    lease_expires_at TEXT NOT NULL,
    approval_nonce_sha256 TEXT NOT NULL,
    approval_phrase TEXT NOT NULL,
    incident_version INTEGER,
    plan_version INTEGER,
    plan_sha256 TEXT,
    target_sha256 TEXT,
    outcome_id TEXT,
    outcome_sha256 TEXT,
    workflow_id TEXT,
    workflow_version INTEGER,
    packet_id TEXT,
    packet_sha256 TEXT,
    closure_id TEXT,
    closure_sha256 TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    terminal_at TEXT,
    terminal_reason TEXT,
    CHECK(
        (phase = 'preparing' AND incident_version IS NULL AND plan_version IS NULL
            AND plan_sha256 IS NULL AND target_sha256 IS NULL)
        OR (phase != 'preparing' AND phase IN ('awaiting-approval', 'executing',
            'awaiting-closure', 'closing', 'closed') AND incident_version >= 1
            AND plan_version >= 1 AND plan_sha256 IS NOT NULL AND target_sha256 IS NOT NULL)
        OR (phase IN ('unresolved', 'expired'))
    ),
    CHECK(
        (phase IN ('awaiting-closure', 'closing', 'closed')
            AND outcome_id IS NOT NULL AND outcome_sha256 IS NOT NULL
            AND workflow_id IS NOT NULL AND workflow_version >= 1
            AND packet_id IS NOT NULL AND packet_sha256 IS NOT NULL)
        OR (phase NOT IN ('awaiting-closure', 'closing', 'closed'))
    ),
    CHECK(
        (phase IN ('closed', 'unresolved', 'expired')
            AND terminal_at IS NOT NULL AND terminal_reason IS NOT NULL)
        OR (phase NOT IN ('closed', 'unresolved', 'expired')
            AND terminal_at IS NULL AND terminal_reason IS NULL)
    ),
    CHECK(
        (phase = 'closed' AND closure_id IS NOT NULL AND closure_sha256 IS NOT NULL)
        OR (phase != 'closed' AND closure_id IS NULL AND closure_sha256 IS NULL)
    )
) STRICT;
CREATE TABLE demo_active_run (
    slot INTEGER PRIMARY KEY CHECK(slot = 1),
    run_id TEXT NOT NULL UNIQUE REFERENCES demo_runs(run_id)
) STRICT;
CREATE TABLE demo_operations (
    run_id TEXT NOT NULL REFERENCES demo_runs(run_id),
    operation TEXT NOT NULL CHECK(operation IN ('prepare', 'approve', 'close')),
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    delegated_request_sha256 TEXT NOT NULL,
    delegated_request_document BLOB NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'complete')),
    result_document BLOB,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    PRIMARY KEY(run_id, operation),
    CHECK(
        (status = 'pending' AND result_document IS NULL AND completed_at IS NULL)
        OR (status = 'complete' AND result_document IS NOT NULL AND completed_at IS NOT NULL)
    )
) STRICT;
CREATE TABLE demo_visuals (
    run_id TEXT NOT NULL REFERENCES demo_runs(run_id),
    kind TEXT NOT NULL CHECK(kind IN ('expected', 'observed', 'recovered', 'diff')),
    relative_path TEXT NOT NULL,
    media_type TEXT NOT NULL CHECK(media_type = 'image/png'),
    content_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(run_id, kind)
) STRICT;
CREATE TABLE demo_proofs (
    run_id TEXT NOT NULL REFERENCES demo_runs(run_id),
    stage TEXT NOT NULL CHECK(stage IN ('investigation', 'execution')),
    proof_sha256 TEXT NOT NULL,
    proof_document BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(run_id, stage)
) STRICT;
CREATE TABLE demo_receipts (
    run_id TEXT PRIMARY KEY REFERENCES demo_runs(run_id),
    receipt_id TEXT NOT NULL UNIQUE,
    receipt_sha256 TEXT NOT NULL,
    receipt_document BLOB NOT NULL,
    created_at TEXT NOT NULL
) STRICT;
CREATE TABLE demo_resets (
    run_id TEXT PRIMARY KEY REFERENCES demo_runs(run_id),
    idempotency_key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'complete')),
    result_document BLOB,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    CHECK(
        (status = 'pending' AND result_document IS NULL AND completed_at IS NULL)
        OR (status = 'complete' AND result_document IS NOT NULL AND completed_at IS NOT NULL)
    )
) STRICT;
CREATE TRIGGER demo_runs_no_delete
BEFORE DELETE ON demo_runs BEGIN
    SELECT RAISE(ABORT, 'demo-runs-no-delete');
END;
CREATE TRIGGER demo_runs_identity_immutable
BEFORE UPDATE ON demo_runs
WHEN NEW.run_id != OLD.run_id OR NEW.incident_id != OLD.incident_id
    OR NEW.scenario_id != OLD.scenario_id OR NEW.source_commit != OLD.source_commit
    OR NEW.start_idempotency_key != OLD.start_idempotency_key
    OR NEW.start_request_sha256 != OLD.start_request_sha256
    OR NEW.build_sha256 != OLD.build_sha256 OR NEW.build_document != OLD.build_document
    OR NEW.approval_nonce_sha256 != OLD.approval_nonce_sha256
    OR NEW.approval_phrase != OLD.approval_phrase OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'demo-run-identity-immutable');
END;
CREATE TRIGGER demo_runs_terminal_immutable
BEFORE UPDATE ON demo_runs
WHEN OLD.phase IN ('closed', 'unresolved', 'expired')
BEGIN
    SELECT RAISE(ABORT, 'demo-run-terminal-immutable');
END;
CREATE TRIGGER demo_runs_valid_transition
BEFORE UPDATE ON demo_runs
WHEN NOT (
    NEW.version = OLD.version + 1 AND (
        (OLD.phase = 'preparing' AND NEW.phase IN ('awaiting-approval', 'unresolved', 'expired'))
        OR (OLD.phase = 'awaiting-approval' AND NEW.phase IN ('executing', 'unresolved', 'expired'))
        OR (OLD.phase = 'executing' AND NEW.phase IN ('awaiting-closure', 'unresolved', 'expired'))
        OR (OLD.phase = 'awaiting-closure' AND NEW.phase IN ('closing', 'unresolved', 'expired'))
        OR (OLD.phase = 'closing' AND NEW.phase IN ('closed', 'unresolved', 'expired'))
    )
)
BEGIN
    SELECT RAISE(ABORT, 'demo-run-transition-invalid');
END;
CREATE TRIGGER demo_operations_no_delete
BEFORE DELETE ON demo_operations BEGIN
    SELECT RAISE(ABORT, 'demo-operations-no-delete');
END;
CREATE TRIGGER demo_operations_identity_immutable
BEFORE UPDATE ON demo_operations
WHEN NEW.run_id != OLD.run_id OR NEW.operation != OLD.operation
    OR NEW.idempotency_key != OLD.idempotency_key
    OR NEW.request_sha256 != OLD.request_sha256
    OR NEW.delegated_request_sha256 != OLD.delegated_request_sha256
    OR NEW.delegated_request_document != OLD.delegated_request_document
    OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'demo-operation-identity-immutable');
END;
CREATE TRIGGER demo_operations_valid_transition
BEFORE UPDATE ON demo_operations
WHEN NOT (OLD.status = 'pending' AND NEW.status = 'complete')
BEGIN
    SELECT RAISE(ABORT, 'demo-operation-transition-invalid');
END;
CREATE TRIGGER demo_visuals_immutable
BEFORE UPDATE ON demo_visuals BEGIN
    SELECT RAISE(ABORT, 'demo-visuals-immutable');
END;
CREATE TRIGGER demo_visuals_no_delete
BEFORE DELETE ON demo_visuals BEGIN
    SELECT RAISE(ABORT, 'demo-visuals-no-delete');
END;
CREATE TRIGGER demo_proofs_immutable
BEFORE UPDATE ON demo_proofs BEGIN
    SELECT RAISE(ABORT, 'demo-proofs-immutable');
END;
CREATE TRIGGER demo_proofs_no_delete
BEFORE DELETE ON demo_proofs BEGIN
    SELECT RAISE(ABORT, 'demo-proofs-no-delete');
END;
CREATE TRIGGER demo_receipts_immutable
BEFORE UPDATE ON demo_receipts BEGIN
    SELECT RAISE(ABORT, 'demo-receipts-immutable');
END;
CREATE TRIGGER demo_receipts_no_delete
BEFORE DELETE ON demo_receipts BEGIN
    SELECT RAISE(ABORT, 'demo-receipts-no-delete');
END;
CREATE TRIGGER demo_resets_identity_immutable
BEFORE UPDATE ON demo_resets BEGIN
    SELECT CASE WHEN NEW.run_id != OLD.run_id
        OR NEW.idempotency_key != OLD.idempotency_key
        OR NEW.request_sha256 != OLD.request_sha256
        OR NEW.created_at != OLD.created_at
        THEN RAISE(ABORT, 'demo-reset-identity-immutable') END;
END;
CREATE TRIGGER demo_resets_valid_transition
BEFORE UPDATE ON demo_resets
WHEN NOT (OLD.status = 'pending' AND NEW.status = 'complete')
BEGIN
    SELECT RAISE(ABORT, 'demo-reset-transition-invalid');
END;
CREATE TRIGGER demo_resets_no_delete
BEFORE DELETE ON demo_resets BEGIN
    SELECT RAISE(ABORT, 'demo-resets-no-delete');
END;
"""

_APPLICATION_ID = 0x4354444D
_SCHEMA_VERSION = 4
_SchemaManifest = tuple[tuple[str, str, str, str | None], ...]


def _normalized_sql(value: str | None) -> str | None:
    return None if value is None else value.strip().replace("\r\n", "\n").replace("\r", "\n")


def _schema_manifest(connection: sqlite3.Connection) -> _SchemaManifest:
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'trigger') "
        "AND NOT (type = 'table' AND name LIKE 'sqlite_%') "
        "AND NOT (type IN ('index', 'trigger') AND tbl_name LIKE 'sqlite_%') "
        "ORDER BY type, name"
    ).fetchall()
    return tuple(
        (
            cast(str, row[0]),
            cast(str, row[1]),
            cast(str, row[2]),
            _normalized_sql(cast(str | None, row[3])),
        )
        for row in rows
    )


def _expected_schema() -> _SchemaManifest:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA)
        return _schema_manifest(connection)
    finally:
        connection.close()


_EXPECTED_SCHEMA = _expected_schema()


class SQLiteDemoRunStore:
    _operation_locks_guard = threading.Lock()
    _operation_locks: dict[tuple[int, int], Any] = {}

    def __init__(self, path: str | Path) -> None:
        self._path, created, self._identity = self._prepare_path(Path(path))
        with self._operation_locks_guard:
            self._operation_lock = self._operation_locks.setdefault(
                self._identity,
                threading.RLock(),
            )
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            self._initialize_or_validate(connection, created=created)
        except DemoFacadeError:
            raise
        except sqlite3.DatabaseError as error:
            raise DemoFacadeError("demo-store-invalid") from error
        finally:
            if connection is not None:
                connection.close()

    @property
    def operation_lock(self) -> Any:
        return self._operation_lock

    @staticmethod
    def _validate_stat(path: Path, value: os.stat_result) -> None:
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or path.is_symlink():
            raise DemoFacadeError("demo-store-path-invalid")
        if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o600:
            raise DemoFacadeError("demo-store-permissions-invalid")

    @classmethod
    def _prepare_path(cls, raw_path: Path) -> tuple[Path, bool, tuple[int, int]]:
        path = raw_path.absolute()
        try:
            parent = path.parent.stat(follow_symlinks=False)
        except OSError as error:
            raise DemoFacadeError("demo-store-path-invalid") from error
        if not stat.S_ISDIR(parent.st_mode):
            raise DemoFacadeError("demo-store-path-invalid")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            try:
                value = path.lstat()
            except OSError as error:
                raise DemoFacadeError("demo-store-path-invalid") from error
            cls._validate_stat(path, value)
            return path, False, (value.st_dev, value.st_ino)
        except OSError as error:
            raise DemoFacadeError("demo-store-path-invalid") from error
        try:
            os.fchmod(descriptor, 0o600)
            value = os.fstat(descriptor)
            cls._validate_stat(path, value)
            return path, True, (value.st_dev, value.st_ino)
        finally:
            os.close(descriptor)

    @classmethod
    def _validate_path(cls, path: Path, identity: tuple[int, int]) -> None:
        try:
            value = path.lstat()
        except OSError as error:
            raise DemoFacadeError("demo-store-path-invalid") from error
        cls._validate_stat(path, value)
        if (value.st_dev, value.st_ino) != identity:
            raise DemoFacadeError("demo-store-path-changed")

    def _connect(self) -> sqlite3.Connection:
        self._validate_path(self._path, self._identity)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=rw",
                timeout=5.0,
                isolation_level=None,
                uri=True,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            journal = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if journal is None or str(journal[0]).lower() != "delete":
                raise DemoFacadeError("demo-store-invalid")
            self._validate_path(self._path, self._identity)
            return connection
        except DemoFacadeError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.close()
            raise DemoFacadeError("demo-store-unavailable") from error

    @classmethod
    def _initialize_or_validate(cls, connection: sqlite3.Connection, *, created: bool) -> None:
        if created:
            if (
                connection.execute("PRAGMA application_id").fetchone()[0] != 0
                or connection.execute("PRAGMA user_version").fetchone()[0] != 0
                or _schema_manifest(connection)
            ):
                raise DemoFacadeError("demo-store-schema-invalid")
            connection.executescript(_SCHEMA)
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        cls._validate_schema(connection)

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION
            or _schema_manifest(connection) != _EXPECTED_SCHEMA
        ):
            raise DemoFacadeError("demo-store-schema-invalid")
        integrity = connection.execute("PRAGMA integrity_check").fetchall()
        if len(integrity) != 1 or integrity[0][0] != "ok":
            raise DemoFacadeError("demo-store-integrity-invalid")

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            self._validate_schema(connection)
            yield connection
            connection.commit()
            self._validate_path(self._path, self._identity)
        except DemoFacadeError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as error:
            if connection.in_transaction:
                connection.rollback()
            raise DemoFacadeError("demo-store-integrity-invalid") from error
        except sqlite3.OperationalError as error:
            if connection.in_transaction:
                connection.rollback()
            raise DemoFacadeError("demo-store-unavailable") from error
        except sqlite3.DatabaseError as error:
            if connection.in_transaction:
                connection.rollback()
            raise DemoFacadeError("demo-store-invalid") from error
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _row(connection: sqlite3.Connection, run_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM demo_runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise DemoFacadeError("demo-run-not-found")
        return cast(sqlite3.Row, row)

    @staticmethod
    def _run(row: sqlite3.Row) -> dict[str, Any]:
        value = {key: row[key] for key in row.keys()}
        if (
            _RUN_ID.fullmatch(cast(str, value.get("run_id"))) is None
            or _INCIDENT_ID.fullmatch(cast(str, value.get("incident_id"))) is None
            or value.get("scenario_id") != CANONICAL_SCENARIO
            or _IDEMPOTENCY_KEY.fullmatch(cast(str, value.get("start_idempotency_key"))) is None
            or _DIGEST.fullmatch(cast(str, value.get("start_request_sha256"))) is None
            or _COMMIT.fullmatch(cast(str, value.get("source_commit"))) is None
            or _DIGEST.fullmatch(cast(str, value.get("build_sha256"))) is None
            or value.get("phase") not in _ACTIVE_PHASES | _TERMINAL_PHASES
            or not isinstance(value.get("version"), int)
            or isinstance(value.get("version"), bool)
            or cast(int, value["version"]) < 1
            or _DIGEST.fullmatch(cast(str, value.get("approval_nonce_sha256"))) is None
            or value.get("approval_phrase") != APPROVAL_PHRASE
        ):
            raise DemoFacadeError("stored-demo-run-invalid")
        _parse_timestamp(value.get("created_at"))
        _parse_timestamp(value.get("updated_at"))
        _parse_timestamp(value.get("lease_expires_at"))
        provenance = _decode_document(
            value.get("build_document"), code="stored-demo-build-provenance-invalid"
        )
        encoded, digest = _build_provenance(
            provenance, source_commit=cast(str, value["source_commit"])
        )
        if encoded != value["build_document"] or digest != value["build_sha256"]:
            raise DemoFacadeError("stored-demo-build-provenance-invalid")
        value["build_provenance"] = provenance
        return value

    @staticmethod
    def _is_reset(connection: sqlite3.Connection, run_id: str) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM demo_resets WHERE run_id = ? AND status = 'complete'",
                (run_id,),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _proofs(connection: sqlite3.Connection, run_id: str) -> dict[str, dict[str, Any]]:
        rows = connection.execute(
            "SELECT stage, proof_sha256, proof_document FROM demo_proofs "
            "WHERE run_id = ? ORDER BY stage",
            (run_id,),
        ).fetchall()
        proofs: dict[str, dict[str, Any]] = {}
        for row in rows:
            stage = cast(str, row["stage"])
            raw = _decode_document(row["proof_document"], code="stored-demo-proof-invalid")
            if stage == "investigation":
                proof = _validate_investigation_proof(raw, stored=True)
            elif stage == "execution":
                proof = _validate_execution_proof(raw)
            else:  # pragma: no cover - constrained by SQLite
                raise DemoFacadeError("stored-demo-proof-invalid")
            encoded = canonical_json_bytes(proof)
            if encoded != row["proof_document"] or document_sha256(proof) != row["proof_sha256"]:
                raise DemoFacadeError("stored-demo-proof-invalid")
            proofs[stage] = proof
        return proofs

    @staticmethod
    def _visual_comparison(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> dict[str, dict[str, str]]:
        rows = connection.execute(
            "SELECT kind, media_type, content_sha256 FROM demo_visuals "
            "WHERE run_id = ? ORDER BY kind",
            (run_id,),
        ).fetchall()
        return {
            cast(str, row["kind"]): {
                "href": f"/v1/demo/runs/{run_id}/visuals/{row['kind']}",
                "sha256": cast(str, row["content_sha256"]),
                "media_type": cast(str, row["media_type"]),
                "label": "illustrative-authored-fixture",
            }
            for row in rows
        }

    @classmethod
    def _projection(cls, connection: sqlite3.Connection, run: Mapping[str, Any]) -> dict[str, Any]:
        phase = cast(str, run["phase"])
        approval = None
        if run.get("plan_sha256") is not None:
            approval = {
                "phrase": run["approval_phrase"],
                "incident_version": run["incident_version"],
                "plan_version": run["plan_version"],
                "plan_sha256": run["plan_sha256"],
                "target_sha256": run["target_sha256"],
            }
        recovery = None
        if run.get("workflow_id") is not None:
            recovery = {
                "outcome_id": run["outcome_id"],
                "outcome_sha256": run["outcome_sha256"],
                "workflow_id": run["workflow_id"],
                "workflow_version": run["workflow_version"],
                "packet_id": run["packet_id"],
                "packet_sha256": run["packet_sha256"],
                "closure_id": run["closure_id"],
                "closure_sha256": run["closure_sha256"],
            }
        terminal = phase in _TERMINAL_PHASES
        result = {
            "schema": RUN_SCHEMA,
            "run_id": run["run_id"],
            "incident_id": run["incident_id"],
            "scenario_id": run["scenario_id"],
            "source_commit": run["source_commit"],
            "build_sha256": run["build_sha256"],
            "phase": phase,
            "version": run["version"],
            "lease_expires_at": None if terminal else run["lease_expires_at"],
            "poll": {
                "href": f"/v1/demo/runs/{run['run_id']}",
                "after_milliseconds": POLL_AFTER_MILLISECONDS,
            },
            "approval": approval,
            "recovery": recovery,
            "visual_comparison": cls._visual_comparison(
                connection,
                cast(str, run["run_id"]),
            ),
            "terminal": terminal,
            "terminal_reason": run["terminal_reason"],
            "receipt_href": (f"/v1/demo/runs/{run['run_id']}/receipt" if terminal else None),
            "reset": cls._is_reset(connection, cast(str, run["run_id"])),
        }
        result.update(cls._proofs(connection, cast(str, run["run_id"])))
        return result

    @classmethod
    def _receipt_document(
        cls, connection: sqlite3.Connection, run: Mapping[str, Any]
    ) -> dict[str, Any]:
        visuals = [
            {"kind": row[0], "sha256": row[1]}
            for row in connection.execute(
                "SELECT kind, content_sha256 FROM demo_visuals WHERE run_id = ? ORDER BY kind",
                (run["run_id"],),
            ).fetchall()
        ]
        proofs = [
            {"stage": row[0], "sha256": row[1]}
            for row in connection.execute(
                "SELECT stage, proof_sha256 FROM demo_proofs WHERE run_id = ? ORDER BY stage",
                (run["run_id"],),
            ).fetchall()
        ]
        body = {
            "schema": RECEIPT_SCHEMA,
            "run_id": run["run_id"],
            "incident_id": run["incident_id"],
            "scenario_id": run["scenario_id"],
            "source_commit": run["source_commit"],
            "build_sha256": run["build_sha256"],
            "provenance": run["build_provenance"],
            "phase": run["phase"],
            "run_version": run["version"],
            "created_at": run["created_at"],
            "terminal_at": run["terminal_at"],
            "reason_code": run["terminal_reason"],
            "bindings": {
                "incident_version": run["incident_version"],
                "plan_version": run["plan_version"],
                "plan_sha256": run["plan_sha256"],
                "target_sha256": run["target_sha256"],
                "outcome_id": run["outcome_id"],
                "outcome_sha256": run["outcome_sha256"],
                "workflow_id": run["workflow_id"],
                "workflow_version": run["workflow_version"],
                "packet_id": run["packet_id"],
                "packet_sha256": run["packet_sha256"],
                "closure_id": run["closure_id"],
                "closure_sha256": run["closure_sha256"],
            },
            "proofs": proofs,
            "visuals": visuals,
        }
        digest = document_sha256(body)
        return {
            **body,
            "receipt_id": f"demo-receipt:{digest.removeprefix('sha256:')}",
            "receipt_sha256": digest,
        }

    @classmethod
    def _terminalize(
        cls,
        connection: sqlite3.Connection,
        run: Mapping[str, Any],
        *,
        phase: str,
        reason: str,
        now: datetime,
        closure: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if phase not in _TERMINAL_PHASES or _REASON_CODE.fullmatch(reason) is None:
            raise DemoFacadeError("demo-terminal-state-invalid")
        if run["phase"] in _TERMINAL_PHASES:
            return dict(run)
        now_value = _timestamp(now)
        closure_id = None if closure is None else closure["closure_id"]
        closure_sha256 = None if closure is None else closure["closure_sha256"]
        connection.execute(
            "UPDATE demo_runs SET phase = ?, version = version + 1, updated_at = ?, "
            "terminal_at = ?, terminal_reason = ?, closure_id = ?, closure_sha256 = ? "
            "WHERE run_id = ?",
            (
                phase,
                now_value,
                now_value,
                reason,
                closure_id,
                closure_sha256,
                run["run_id"],
            ),
        )
        connection.execute("DELETE FROM demo_active_run WHERE run_id = ?", (run["run_id"],))
        selected = cls._run(cls._row(connection, cast(str, run["run_id"])))
        receipt = cls._receipt_document(connection, selected)
        encoded = canonical_json_bytes(receipt)
        connection.execute(
            "INSERT INTO demo_receipts(run_id, receipt_id, receipt_sha256, "
            "receipt_document, created_at) VALUES(?, ?, ?, ?, ?)",
            (
                selected["run_id"],
                receipt["receipt_id"],
                receipt["receipt_sha256"],
                encoded,
                now_value,
            ),
        )
        pending = connection.execute(
            "SELECT operation FROM demo_operations WHERE run_id = ? AND status = 'pending'",
            (selected["run_id"],),
        ).fetchall()
        response = canonical_json_bytes(cls._projection(connection, selected))
        for operation in pending:
            connection.execute(
                "UPDATE demo_operations SET status = 'complete', result_document = ?, "
                "completed_at = ? WHERE run_id = ? AND operation = ?",
                (response, now_value, selected["run_id"], operation[0]),
            )
        return selected

    @classmethod
    def _expire_active(cls, connection: sqlite3.Connection, *, now: datetime) -> None:
        active = connection.execute(
            "SELECT runs.* FROM demo_active_run AS active "
            "JOIN demo_runs AS runs ON runs.run_id = active.run_id WHERE active.slot = 1"
        ).fetchone()
        if active is None:
            return
        run = cls._run(cast(sqlite3.Row, active))
        if run["phase"] in _TRANSIENT_PHASES:
            return
        if _parse_timestamp(run["lease_expires_at"]) <= now:
            cls._terminalize(connection, run, phase="expired", reason="lease-expired", now=now)

    def create(
        self,
        *,
        run_id: str,
        incident_id: str,
        start_idempotency_key: str,
        start_request_sha256: str,
        source_commit: str,
        build_provenance: Mapping[str, Any],
        nonce_sha256: str,
        preparation_request: Mapping[str, Any],
        now: datetime,
    ) -> tuple[dict[str, Any], bool]:
        now_value = _timestamp(now)
        expires = _timestamp(now + timedelta(seconds=LEASE_SECONDS))
        build_document, build_sha256 = _build_provenance(
            build_provenance, source_commit=source_commit
        )
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            existing_row = connection.execute(
                "SELECT * FROM demo_runs WHERE start_idempotency_key = ?",
                (start_idempotency_key,),
            ).fetchone()
            if existing_row is not None:
                existing = self._run(cast(sqlite3.Row, existing_row))
                if not (
                    hmac.compare_digest(
                        cast(str, existing["start_request_sha256"]),
                        start_request_sha256,
                    )
                    and hmac.compare_digest(
                        cast(str, existing["approval_nonce_sha256"]),
                        nonce_sha256,
                    )
                ):
                    raise DemoFacadeError("demo-idempotency-conflict")
                return existing, False
            active = connection.execute(
                "SELECT run_id FROM demo_active_run WHERE slot = 1"
            ).fetchone()
            if active is not None:
                raise DemoFacadeError(
                    "demo-active-run-exists",
                    run_id=cast(str, active["run_id"]),
                )
            unreset = connection.execute(
                "SELECT runs.run_id FROM demo_runs AS runs "
                "LEFT JOIN demo_resets AS resets ON resets.run_id = runs.run_id "
                "WHERE resets.status IS NULL OR resets.status != 'complete' "
                "ORDER BY runs.created_at DESC LIMIT 1"
            ).fetchone()
            if unreset is not None:
                raise DemoFacadeError(
                    "demo-reset-required",
                    run_id=cast(str, unreset["run_id"]),
                )
            connection.execute(
                "INSERT INTO demo_runs(run_id, incident_id, scenario_id, "
                "start_idempotency_key, start_request_sha256, source_commit, "
                "build_sha256, build_document, phase, "
                "version, lease_expires_at, approval_nonce_sha256, approval_phrase, created_at, "
                "updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'preparing', 1, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    incident_id,
                    CANONICAL_SCENARIO,
                    start_idempotency_key,
                    start_request_sha256,
                    source_commit,
                    build_sha256,
                    build_document,
                    expires,
                    nonce_sha256,
                    APPROVAL_PHRASE,
                    now_value,
                    now_value,
                ),
            )
            connection.execute("INSERT INTO demo_active_run(slot, run_id) VALUES(1, ?)", (run_id,))
            request_document = canonical_json_bytes(preparation_request)
            connection.execute(
                "INSERT INTO demo_operations(run_id, operation, idempotency_key, "
                "request_sha256, delegated_request_sha256, delegated_request_document, "
                "status, created_at) VALUES(?, 'prepare', ?, ?, ?, ?, 'pending', ?)",
                (
                    run_id,
                    preparation_request["idempotency_key"],
                    start_request_sha256,
                    document_sha256(preparation_request),
                    request_document,
                    now_value,
                ),
            )
            return self._run(self._row(connection, run_id)), True

    def replay_start(
        self,
        *,
        start_idempotency_key: str,
        start_request_sha256: str,
        nonce_sha256: str,
        now: datetime,
    ) -> dict[str, Any] | None:
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            row = connection.execute(
                "SELECT * FROM demo_runs WHERE start_idempotency_key = ?",
                (start_idempotency_key,),
            ).fetchone()
            if row is None:
                return None
            run = self._run(cast(sqlite3.Row, row))
            if not (
                hmac.compare_digest(
                    cast(str, run["start_request_sha256"]),
                    start_request_sha256,
                )
                and hmac.compare_digest(
                    cast(str, run["approval_nonce_sha256"]),
                    nonce_sha256,
                )
            ):
                raise DemoFacadeError("demo-idempotency-conflict")
            return run

    @staticmethod
    def _insert_visuals(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        visuals: Sequence[Mapping[str, str]],
        now_value: str,
    ) -> None:
        for visual in visuals:
            connection.execute(
                "INSERT INTO demo_visuals(run_id, kind, relative_path, media_type, "
                "content_sha256, created_at) VALUES(?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    visual["kind"],
                    visual["path"],
                    visual["media_type"],
                    visual["sha256"],
                    now_value,
                ),
            )

    @staticmethod
    def _insert_proof(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        stage: str,
        proof: Mapping[str, Any],
        now_value: str,
    ) -> None:
        if stage not in {"investigation", "execution"}:
            raise DemoFacadeError("demo-proof-stage-invalid")
        encoded = canonical_json_bytes(proof)
        if len(encoded) > 128 * 1024:
            raise DemoFacadeError("demo-proof-too-large")
        connection.execute(
            "INSERT INTO demo_proofs(run_id, stage, proof_sha256, proof_document, created_at) "
            "VALUES(?, ?, ?, ?, ?)",
            (run_id, stage, document_sha256(proof), encoded, now_value),
        )

    @staticmethod
    def _completed_operation_result(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT status, result_document FROM demo_operations "
            "WHERE run_id = ? AND operation = ?",
            (run_id, operation),
        ).fetchone()
        if row is None or row["status"] != "complete":
            return None
        return _decode_document(row["result_document"], code="stored-demo-operation-invalid")

    def complete_preparation(
        self,
        run_id: str,
        preparation: Mapping[str, Any],
        *,
        now: datetime,
    ) -> dict[str, Any]:
        now_value = _timestamp(now)
        expires = _timestamp(now + timedelta(seconds=LEASE_SECONDS))
        with self._transaction(write=True) as connection:
            run = self._run(self._row(connection, run_id))
            if run["phase"] != "preparing":
                if (
                    self._completed_operation_result(
                        connection,
                        run_id=run_id,
                        operation="prepare",
                    )
                    is not None
                ):
                    return run
                raise DemoFacadeError("demo-run-phase-conflict")
            connection.execute(
                "UPDATE demo_runs SET phase = 'awaiting-approval', version = version + 1, "
                "lease_expires_at = ?, incident_version = ?, plan_version = ?, "
                "plan_sha256 = ?, target_sha256 = ?, updated_at = ? WHERE run_id = ?",
                (
                    expires,
                    preparation["incident_version"],
                    preparation["plan_version"],
                    preparation["plan_sha256"],
                    preparation["target_sha256"],
                    now_value,
                    run_id,
                ),
            )
            self._insert_visuals(
                connection,
                run_id=run_id,
                visuals=cast(Sequence[Mapping[str, str]], preparation["visuals"]),
                now_value=now_value,
            )
            self._insert_proof(
                connection,
                run_id=run_id,
                stage="investigation",
                proof=cast(Mapping[str, Any], preparation["investigation"]),
                now_value=now_value,
            )
            selected = self._run(self._row(connection, run_id))
            result = self._projection(connection, selected)
            changed = connection.execute(
                "UPDATE demo_operations SET status = 'complete', result_document = ?, "
                "completed_at = ? WHERE run_id = ? AND operation = 'prepare' "
                "AND status = 'pending'",
                (canonical_json_bytes(result), now_value, run_id),
            )
            if changed.rowcount != 1:
                raise DemoFacadeError("demo-operation-state-invalid")
            return selected

    def get(self, run_id: str, *, now: datetime) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            run = self._run(self._row(connection, run_id))
            return self._projection(connection, run)

    def raw(self, run_id: str, *, now: datetime) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            return self._run(self._row(connection, run_id))

    def transient(self, *, now: datetime) -> dict[str, Any] | None:
        with self._transaction(write=True) as connection:
            row = connection.execute(
                "SELECT runs.* FROM demo_active_run AS active "
                "JOIN demo_runs AS runs ON runs.run_id = active.run_id "
                "WHERE active.slot = 1"
            ).fetchone()
            if row is None:
                return None
            run = self._run(cast(sqlite3.Row, row))
            if run["phase"] not in _TRANSIENT_PHASES:
                self._expire_active(connection, now=now)
                return None
            operation = connection.execute(
                "SELECT operation, idempotency_key, request_sha256, "
                "delegated_request_sha256, delegated_request_document "
                "FROM demo_operations WHERE run_id = ? AND status = 'pending'",
                (run["run_id"],),
            ).fetchall()
            if len(operation) != 1:
                raise DemoFacadeError("demo-operation-state-invalid")
            selected = operation[0]
            expected_operation = {
                "preparing": "prepare",
                "executing": "approve",
                "closing": "close",
            }[cast(str, run["phase"])]
            if selected["operation"] != expected_operation:
                raise DemoFacadeError("demo-operation-state-invalid")
            request = _decode_document(
                selected["delegated_request_document"], code="stored-demo-operation-invalid"
            )
            if (
                selected["delegated_request_sha256"] != document_sha256(request)
                or request.get("idempotency_key") != selected["idempotency_key"]
            ):
                raise DemoFacadeError("stored-demo-operation-invalid")
            return {
                **run,
                "operation": selected["operation"],
                "operation_idempotency_key": selected["idempotency_key"],
                "client_request_sha256": selected["request_sha256"],
                "operation_request_sha256": selected["delegated_request_sha256"],
                "operation_request": request,
                "lease_expired": _parse_timestamp(run["lease_expires_at"]) <= now,
            }

    def active(self, *, now: datetime) -> dict[str, Any] | None:
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            row = connection.execute(
                "SELECT runs.* FROM demo_active_run AS active "
                "JOIN demo_runs AS runs ON runs.run_id = active.run_id WHERE active.slot = 1"
            ).fetchone()
            return None if row is None else self._run(cast(sqlite3.Row, row))

    def rejection_candidate(self) -> dict[str, Any] | None:
        with self._transaction(write=False) as connection:
            row = connection.execute(
                "SELECT runs.* FROM demo_active_run AS active "
                "JOIN demo_runs AS runs ON runs.run_id = active.run_id "
                "WHERE active.slot = 1 AND runs.phase = 'awaiting-approval'"
            ).fetchone()
            return None if row is None else self._run(cast(sqlite3.Row, row))

    def fail(
        self,
        run_id: str,
        *,
        reason: str,
        now: datetime,
        expected_phase: str | None = None,
    ) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            run = self._run(self._row(connection, run_id))
            if expected_phase is not None and run["phase"] != expected_phase:
                return self._projection(connection, run)
            selected = self._terminalize(
                connection, run, phase="unresolved", reason=reason, now=now
            )
            return self._projection(connection, selected)

    def complete_rejection(
        self,
        run_id: str,
        *,
        expected_version: int,
        reason: str,
        now: datetime,
    ) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            run = self._run(self._row(connection, run_id))
            if run["phase"] in _TERMINAL_PHASES:
                if (
                    run["phase"] != "unresolved"
                    or run["terminal_reason"] != reason
                    or run["version"] != expected_version + 1
                ):
                    raise DemoFacadeError("demo-run-phase-conflict")
                return self._projection(connection, run)
            if run["phase"] != "awaiting-approval":
                raise DemoFacadeError("demo-run-phase-conflict")
            if run["version"] != expected_version:
                raise DemoFacadeError("demo-run-version-conflict")
            selected = self._terminalize(
                connection,
                run,
                phase="unresolved",
                reason=reason,
                now=now,
            )
            return self._projection(connection, selected)

    @staticmethod
    def _operation_replay(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        operation: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT * FROM demo_operations WHERE run_id = ? AND operation = ?",
            (run_id, operation),
        ).fetchone()
        if row is None:
            return None
        if row["idempotency_key"] != idempotency_key or row["request_sha256"] != request_sha256:
            raise DemoFacadeError("demo-idempotency-conflict")
        if row["status"] == "pending":
            raise DemoFacadeError("demo-operation-in-progress")
        return _decode_document(row["result_document"], code="stored-demo-operation-invalid")

    def begin_operation(
        self,
        run_id: str,
        *,
        operation: str,
        expected_phase: str,
        next_phase: str,
        expected_version: int,
        idempotency_key: str,
        request_sha256: str,
        operation_request: Mapping[str, Any],
        now: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        if operation_request.get("idempotency_key") != idempotency_key:
            raise DemoFacadeError("demo-operation-request-invalid")
        now_value = _timestamp(now)
        expires = _timestamp(now + timedelta(seconds=LEASE_SECONDS))
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            run = self._run(self._row(connection, run_id))
            replay = self._operation_replay(
                connection,
                run_id=run_id,
                operation=operation,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return run, replay
            if run["phase"] != expected_phase:
                raise DemoFacadeError("demo-run-phase-conflict")
            if run["version"] != expected_version:
                raise DemoFacadeError("demo-run-version-conflict")
            connection.execute(
                "INSERT INTO demo_operations(run_id, operation, idempotency_key, "
                "request_sha256, delegated_request_sha256, delegated_request_document, "
                "status, created_at) VALUES(?, ?, ?, ?, ?, ?, 'pending', ?)",
                (
                    run_id,
                    operation,
                    idempotency_key,
                    request_sha256,
                    document_sha256(operation_request),
                    canonical_json_bytes(operation_request),
                    now_value,
                ),
            )
            connection.execute(
                "UPDATE demo_runs SET phase = ?, version = version + 1, lease_expires_at = ?, "
                "updated_at = ? WHERE run_id = ?",
                (next_phase, expires, now_value, run_id),
            )
            return self._run(self._row(connection, run_id)), None

    def complete_execution(
        self,
        run_id: str,
        execution: Mapping[str, Any],
        *,
        now: datetime,
    ) -> dict[str, Any]:
        now_value = _timestamp(now)
        expires = _timestamp(now + timedelta(seconds=LEASE_SECONDS))
        with self._transaction(write=True) as connection:
            run = self._run(self._row(connection, run_id))
            if run["phase"] != "executing":
                replay = self._completed_operation_result(
                    connection,
                    run_id=run_id,
                    operation="approve",
                )
                if replay is not None:
                    return replay
                raise DemoFacadeError("demo-run-phase-conflict")
            connection.execute(
                "UPDATE demo_runs SET phase = 'awaiting-closure', version = version + 1, "
                "lease_expires_at = ?, outcome_id = ?, outcome_sha256 = ?, workflow_id = ?, "
                "workflow_version = ?, packet_id = ?, packet_sha256 = ?, updated_at = ? "
                "WHERE run_id = ?",
                (
                    expires,
                    execution["outcome_id"],
                    execution["outcome_sha256"],
                    execution["workflow_id"],
                    execution["workflow_version"],
                    execution["packet_id"],
                    execution["packet_sha256"],
                    now_value,
                    run_id,
                ),
            )
            self._insert_visuals(
                connection,
                run_id=run_id,
                visuals=cast(Sequence[Mapping[str, str]], execution["visuals"]),
                now_value=now_value,
            )
            self._insert_proof(
                connection,
                run_id=run_id,
                stage="execution",
                proof=cast(Mapping[str, Any], execution["execution"]),
                now_value=now_value,
            )
            selected = self._run(self._row(connection, run_id))
            result = self._projection(connection, selected)
            changed = connection.execute(
                "UPDATE demo_operations SET status = 'complete', result_document = ?, "
                "completed_at = ? WHERE run_id = ? AND operation = 'approve' "
                "AND status = 'pending'",
                (canonical_json_bytes(result), now_value, run_id),
            )
            if changed.rowcount != 1:
                raise DemoFacadeError("demo-operation-state-invalid")
            return result

    def complete_closure(
        self,
        run_id: str,
        closure: Mapping[str, Any],
        *,
        now: datetime,
    ) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            run = self._run(self._row(connection, run_id))
            if run["phase"] != "closing":
                replay = self._completed_operation_result(
                    connection,
                    run_id=run_id,
                    operation="close",
                )
                if replay is not None:
                    return replay
                raise DemoFacadeError("demo-run-phase-conflict")
            if closure.get("workflow_version_after") != cast(int, run["workflow_version"]) + 1:
                raise DemoFacadeError("demo-closure-binding-invalid")
            selected = self._terminalize(
                connection,
                run,
                phase="closed",
                reason="recovery-closed",
                now=now,
                closure=closure,
            )
            completed = connection.execute(
                "SELECT status FROM demo_operations WHERE run_id = ? AND operation = 'close'",
                (run_id,),
            ).fetchone()
            if completed is None or completed["status"] != "complete":
                raise DemoFacadeError("demo-operation-state-invalid")
            return self._projection(connection, selected)

    def begin_reset(
        self,
        run_id: str,
        *,
        expected_version: int,
        idempotency_key: str,
        request_sha256: str,
        now: datetime,
    ) -> dict[str, Any] | None:
        now_value = _timestamp(now)
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            run = self._run(self._row(connection, run_id))
            existing = connection.execute(
                "SELECT * FROM demo_resets WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["idempotency_key"] != idempotency_key
                    or existing["request_sha256"] != request_sha256
                ):
                    raise DemoFacadeError("demo-idempotency-conflict")
                if existing["status"] == "complete":
                    return _decode_document(
                        existing["result_document"], code="stored-demo-reset-invalid"
                    )
                return None
            if run["phase"] not in _TERMINAL_PHASES:
                raise DemoFacadeError("demo-reset-not-terminal")
            if run["version"] != expected_version:
                raise DemoFacadeError("demo-run-version-conflict")
            connection.execute(
                "INSERT INTO demo_resets(run_id, idempotency_key, request_sha256, "
                "status, created_at) VALUES(?, ?, ?, 'pending', ?)",
                (run_id, idempotency_key, request_sha256, now_value),
            )
            return None

    def complete_reset(
        self,
        run_id: str,
        *,
        restoration: Mapping[str, Any],
        now: datetime,
    ) -> dict[str, Any]:
        now_value = _timestamp(now)
        with self._transaction(write=True) as connection:
            run = self._run(self._row(connection, run_id))
            existing = connection.execute(
                "SELECT * FROM demo_resets WHERE run_id = ?", (run_id,)
            ).fetchone()
            if existing is None:
                raise DemoFacadeError("demo-reset-state-invalid")
            if existing["status"] == "complete":
                return _decode_document(
                    existing["result_document"], code="stored-demo-reset-invalid"
                )
            result = {
                "schema": RESET_SCHEMA,
                "run_id": run_id,
                "phase": run["phase"],
                "version": run["version"],
                "reset": True,
                "receipt_href": f"/v1/demo/runs/{run_id}/receipt",
                "restoration": dict(restoration),
            }
            changed = connection.execute(
                "UPDATE demo_resets SET status = 'complete', result_document = ?, "
                "completed_at = ? WHERE run_id = ? AND status = 'pending'",
                (canonical_json_bytes(result), now_value, run_id),
            )
            if changed.rowcount != 1:
                raise DemoFacadeError("demo-reset-state-invalid")
            return result

    def pending_reset(self) -> dict[str, Any] | None:
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT run_id, idempotency_key, request_sha256, created_at "
                "FROM demo_resets WHERE status = 'pending' ORDER BY created_at, run_id"
            ).fetchall()
            if not rows:
                return None
            if len(rows) != 1:
                raise DemoFacadeError("stored-demo-reset-invalid")
            row = rows[0]
            run = self._run(self._row(connection, cast(str, row["run_id"])))
            key = row["idempotency_key"]
            request_sha256 = row["request_sha256"]
            if (
                run["phase"] not in _TERMINAL_PHASES
                or not isinstance(key, str)
                or _IDEMPOTENCY_KEY.fullmatch(key) is None
                or not isinstance(request_sha256, str)
                or _DIGEST.fullmatch(request_sha256) is None
            ):
                raise DemoFacadeError("stored-demo-reset-invalid")
            _parse_timestamp(row["created_at"])
            request = {
                "schema": RESET_REQUEST_SCHEMA,
                "expected_run_version": run["version"],
                "idempotency_key": key,
            }
            if not hmac.compare_digest(document_sha256(request), request_sha256):
                raise DemoFacadeError("stored-demo-reset-invalid")
            return {
                "run_id": run["run_id"],
                "request_sha256": request_sha256,
            }

    def receipt(self, run_id: str, *, now: datetime) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            self._run(self._row(connection, run_id))
            row = connection.execute(
                "SELECT * FROM demo_receipts WHERE run_id = ?", (run_id,)
            ).fetchone()
            if row is None:
                raise DemoFacadeError("demo-receipt-not-ready")
            value = _decode_document(row["receipt_document"], code="stored-demo-receipt-invalid")
            receipt_sha256 = value.get("receipt_sha256")
            receipt_id = value.get("receipt_id")
            body = {
                key: child
                for key, child in value.items()
                if key not in {"receipt_id", "receipt_sha256"}
            }
            expected = document_sha256(body)
            if (
                receipt_sha256 != expected
                or receipt_id != f"demo-receipt:{expected.removeprefix('sha256:')}"
                or row["receipt_id"] != receipt_id
                or row["receipt_sha256"] != receipt_sha256
            ):
                raise DemoFacadeError("stored-demo-receipt-invalid")
            return value

    def visual_descriptor(self, run_id: str, kind: str, *, now: datetime) -> dict[str, str]:
        with self._transaction(write=True) as connection:
            self._expire_active(connection, now=now)
            self._run(self._row(connection, run_id))
            row = connection.execute(
                "SELECT relative_path, media_type, content_sha256 FROM demo_visuals "
                "WHERE run_id = ? AND kind = ?",
                (run_id, kind),
            ).fetchone()
            if row is None:
                raise DemoFacadeError("demo-visual-not-found")
            return {
                "path": _relative_visual_path(row["relative_path"]),
                "media_type": cast(str, row["media_type"]),
                "sha256": _require_digest(row["content_sha256"], code="stored-demo-visual-invalid"),
            }


class DemoFacade:
    def __init__(
        self,
        *,
        store: SQLiteDemoRunStore,
        workflow: DemoWorkflowPort,
        source_commit: str,
        visual_root: str | Path,
        build_provenance: Mapping[str, Any] | None = None,
        recovery: RecoveryApi | None = None,
        scenario_reset: DemoScenarioResetPort | None = None,
        closure_principal: Principal | None = None,
        closure_principal_factory: Callable[[str], Principal] | None = None,
        clock: Callable[[], datetime] = _utc_now,
        run_id_factory: Callable[[], str] | None = None,
        reconcile_on_startup: bool = True,
    ) -> None:
        if _COMMIT.fullmatch(source_commit) is None:
            raise DemoFacadeError("demo-source-commit-invalid")
        if closure_principal is not None and closure_principal_factory is not None:
            raise DemoFacadeError("demo-closure-principal-invalid")
        root = Path(visual_root)
        try:
            resolved = root.resolve(strict=True)
            metadata = root.lstat()
        except OSError as error:
            raise DemoFacadeError("demo-visual-root-invalid") from error
        if root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise DemoFacadeError("demo-visual-root-invalid")
        self._store = store
        self._operation_lock = store.operation_lock
        self._workflow = workflow
        self._source_commit = source_commit
        selected_provenance = (
            {
                "schema": BUILD_PROVENANCE_SCHEMA,
                "source_commit": source_commit,
            }
            if build_provenance is None
            else build_provenance
        )
        self._build_document, self._build_sha256 = _build_provenance(
            selected_provenance,
            source_commit=source_commit,
        )
        self._build_provenance = _decode_document(
            self._build_document, code="demo-build-provenance-invalid"
        )
        self._visual_root = resolved
        self._recovery = recovery
        self._scenario_reset = scenario_reset
        self._closure_principal = closure_principal
        self._closure_principal_factory = closure_principal_factory
        self._clock = clock
        self._run_id_factory = run_id_factory or (lambda: f"demo-run-{secrets.token_hex(16)}")
        self._assert_active_build_binding()
        if reconcile_on_startup:
            self.reconcile_startup()

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise DemoFacadeError("demo-time-invalid")
        return value.astimezone(UTC)

    def _assert_active_build_binding(self) -> None:
        self._reconcile_rejection_before_expiry()
        active = self._store.active(now=self._now())
        if active is not None and (
            active["source_commit"] != self._source_commit
            or active["build_sha256"] != self._build_sha256
        ):
            raise DemoFacadeError("demo-build-binding-conflict")

    def _reconcile_rejection_before_expiry(self) -> None:
        active = self._store.rejection_candidate()
        if active is None:
            return
        if (
            active["source_commit"] != self._source_commit
            or active["build_sha256"] != self._build_sha256
        ):
            return
        reviewer = getattr(self._workflow, "review_rejection", None)
        if not callable(reviewer):
            return
        request = {
            "schema": "colortrace-demo-rejection-reconciliation/v1",
            "run_id": active["run_id"],
            "incident_id": active["incident_id"],
            "incident_version": active["incident_version"],
            "plan_version": active["plan_version"],
            "plan_sha256": active["plan_sha256"],
            "target_sha256": active["target_sha256"],
        }
        expired = _parse_timestamp(active["lease_expires_at"]) <= self._now()
        try:
            raw_rejection = reviewer(request)
            if raw_rejection is None:
                return
            rejection = self._validate_rejection_result(
                raw_rejection,
                run=active,
            )
            self._store.complete_rejection(
                cast(str, active["run_id"]),
                expected_version=cast(int, active["version"]),
                reason=f"plan-rejected-{rejection['reason_code']}",
                now=self._now(),
            )
        except _KNOWN_OPERATION_ERRORS:
            if expired:
                return
            self._store.fail(
                cast(str, active["run_id"]),
                reason="restart-reconciliation-invalid",
                now=self._now(),
                expected_phase="awaiting-approval",
            )
        except Exception:
            return

    def _record_known_failure(
        self,
        run_id: str,
        *,
        phase: str,
        error: BaseException,
    ) -> None:
        code = getattr(error, "code", None)
        reason = (
            code if isinstance(code, str) and _REASON_CODE.fullmatch(code) else "operation-failed"
        )
        self._store.fail(
            run_id,
            reason=reason,
            now=self._now(),
            expected_phase=phase,
        )

    def _expire_inconclusive(self, run: Mapping[str, Any]) -> None:
        if run.get("lease_expired") is True:
            self._store.fail(
                cast(str, run["run_id"]),
                reason="restart-reconciliation-timeout",
                now=self._now(),
                expected_phase=cast(str, run["phase"]),
            )

    def _verify_visual(self, descriptor: Mapping[str, str]) -> None:
        self._read_visual(descriptor)

    def _read_visual(self, descriptor: Mapping[str, str]) -> bytes:
        relative = _relative_visual_path(descriptor.get("path"))
        candidate = self._visual_root.joinpath(*PurePosixPath(relative).parts)
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self._visual_root)
            if candidate != resolved or candidate.is_symlink():
                raise DemoFacadeError("demo-visual-path-invalid")
            metadata = resolved.stat(follow_symlinks=False)
        except DemoFacadeError:
            raise
        except (OSError, ValueError) as error:
            raise DemoFacadeError("demo-visual-unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size < 1
            or metadata.st_size > _MAX_VISUAL_BYTES
        ):
            raise DemoFacadeError("demo-visual-invalid")
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor_fd = os.open(resolved, flags)
            try:
                opened = os.fstat(descriptor_fd)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise DemoFacadeError("demo-visual-path-changed")
                chunks: list[bytes] = []
                remaining = _MAX_VISUAL_BYTES + 1
                while remaining > 0:
                    chunk = os.read(descriptor_fd, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(chunks)
            finally:
                os.close(descriptor_fd)
        except DemoFacadeError:
            raise
        except OSError as error:
            raise DemoFacadeError("demo-visual-unavailable") from error
        if not content.startswith(b"\x89PNG\r\n\x1a\n") or len(content) > _MAX_VISUAL_BYTES:
            raise DemoFacadeError("demo-visual-invalid")
        actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if not hmac.compare_digest(actual, descriptor["sha256"]):
            raise DemoFacadeError("demo-visual-digest-conflict")
        return content

    def _verify_visuals(self, visuals: Sequence[Mapping[str, str]]) -> None:
        for descriptor in visuals:
            self._verify_visual(descriptor)

    def start(self, body: Mapping[str, Any]) -> dict[str, Any]:
        with self._operation_lock:
            return self._start(body)

    def _start(self, body: Mapping[str, Any]) -> dict[str, Any]:
        _require_exact(
            body,
            frozenset({"schema", "scenario_id", "approval_nonce", "idempotency_key"}),
            RUN_REQUEST_SCHEMA,
        )
        if body.get("scenario_id") != CANONICAL_SCENARIO:
            raise DemoFacadeError("demo-scenario-invalid")
        nonce = body.get("approval_nonce")
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise DemoFacadeError("demo-approval-nonce-invalid")
        idempotency_key = _require_idempotency_key(body.get("idempotency_key"))
        start_request = {
            "schema": RUN_REQUEST_SCHEMA,
            "scenario_id": CANONICAL_SCENARIO,
            "approval_nonce": nonce,
            "idempotency_key": idempotency_key,
        }
        self._reconcile_startup()
        start_request_sha256 = document_sha256(start_request)
        nonce_sha256 = _nonce_sha256(nonce)
        replay = self._store.replay_start(
            start_idempotency_key=idempotency_key,
            start_request_sha256=start_request_sha256,
            nonce_sha256=nonce_sha256,
            now=self._now(),
        )
        if replay is not None:
            selected_run_id = cast(str, replay["run_id"])
            self._reconcile_startup()
            result = self._store.get(selected_run_id, now=self._now())
            if result["phase"] == "awaiting-approval":
                result["approval_nonce"] = nonce
            return result
        run_id = self._run_id_factory()
        if _RUN_ID.fullmatch(run_id) is None:
            raise DemoFacadeError("demo-identity-generation-invalid")
        incident_id = f"incident-demo-{run_id.removeprefix('demo-run-')}"
        now = self._now()
        request = {
            "schema": "colortrace-demo-preparation-request/v1",
            "run_id": run_id,
            "incident_id": incident_id,
            "scenario_id": CANONICAL_SCENARIO,
            "source_commit": self._source_commit,
            "idempotency_key": f"prepare:{run_id}",
        }
        created_run, created = self._store.create(
            run_id=run_id,
            incident_id=incident_id,
            start_idempotency_key=idempotency_key,
            start_request_sha256=start_request_sha256,
            source_commit=self._source_commit,
            build_provenance=self._build_provenance,
            nonce_sha256=nonce_sha256,
            preparation_request=request,
            now=now,
        )
        selected_run_id = cast(str, created_run["run_id"])
        if not created:
            self.reconcile_startup()
            result = self._store.get(selected_run_id, now=self._now())
            if result["phase"] == "awaiting-approval":
                result["approval_nonce"] = nonce
            return result
        try:
            raw = self._workflow.prepare(request)
            preparation = _validate_preparation(raw, run_id=run_id, incident_id=incident_id)
            self._verify_visuals(cast(Sequence[Mapping[str, str]], preparation["visuals"]))
        except _KNOWN_OPERATION_ERRORS as error:
            self._record_known_failure(run_id, phase="preparing", error=error)
            if isinstance(error, DemoFacadeError):
                raise
            raise DemoFacadeError("demo-operation-failed") from error
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error
        try:
            self._store.complete_preparation(run_id, preparation, now=self._now())
            result = self._store.get(selected_run_id, now=self._now())
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error
        if result["phase"] == "awaiting-approval":
            result["approval_nonce"] = nonce
        return result

    @staticmethod
    def _approval_request(body: Mapping[str, Any]) -> dict[str, Any]:
        fields = frozenset(
            {
                "schema",
                "approval_nonce",
                "approval_phrase",
                "expected_run_version",
                "expected_incident_version",
                "expected_plan_version",
                "expected_plan_sha256",
                "expected_target_sha256",
                "idempotency_key",
            }
        )
        _require_exact(body, fields, APPROVAL_REQUEST_SCHEMA)
        nonce = body.get("approval_nonce")
        phrase = body.get("approval_phrase")
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise DemoFacadeError("demo-approval-nonce-invalid")
        if phrase != APPROVAL_PHRASE:
            raise DemoFacadeError("demo-approval-phrase-invalid")
        return {
            "schema": APPROVAL_REQUEST_SCHEMA,
            "approval_nonce": nonce,
            "approval_phrase": phrase,
            "expected_run_version": _require_version(
                body.get("expected_run_version"), code="demo-run-version-invalid"
            ),
            "expected_incident_version": _require_version(
                body.get("expected_incident_version"), code="demo-incident-version-invalid"
            ),
            "expected_plan_version": _require_version(
                body.get("expected_plan_version"), code="demo-plan-version-invalid"
            ),
            "expected_plan_sha256": _require_digest(
                body.get("expected_plan_sha256"), code="demo-plan-digest-invalid"
            ),
            "expected_target_sha256": _require_digest(
                body.get("expected_target_sha256"), code="demo-target-digest-invalid"
            ),
            "idempotency_key": _require_idempotency_key(body.get("idempotency_key")),
        }

    def approve(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        with self._operation_lock:
            return self._approve(run_id, body)

    def _approve(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if _RUN_ID.fullmatch(run_id) is None:
            raise DemoFacadeError("demo-run-id-invalid")
        self._assert_active_build_binding()
        self.reconcile_startup()
        request = self._approval_request(body)
        current = self._store.raw(run_id, now=self._now())
        if not hmac.compare_digest(
            cast(str, current["approval_nonce_sha256"]),
            _nonce_sha256(cast(str, request["approval_nonce"])),
        ):
            raise DemoFacadeError("demo-approval-nonce-invalid")
        bindings = {
            "expected_incident_version": "incident_version",
            "expected_plan_version": "plan_version",
            "expected_plan_sha256": "plan_sha256",
            "expected_target_sha256": "target_sha256",
        }
        if any(request[provided] != current[stored] for provided, stored in bindings.items()):
            raise DemoFacadeError("demo-approval-binding-conflict")
        execution_request = {
            "schema": "colortrace-demo-execution-request/v1",
            "run_id": current["run_id"],
            "incident_id": current["incident_id"],
            "incident_version": current["incident_version"],
            "plan_version": current["plan_version"],
            "plan_sha256": current["plan_sha256"],
            "target_sha256": current["target_sha256"],
            "idempotency_key": request["idempotency_key"],
        }
        request_sha256 = document_sha256(request)
        started, replay = self._store.begin_operation(
            run_id,
            operation="approve",
            expected_phase="awaiting-approval",
            next_phase="executing",
            expected_version=cast(int, request["expected_run_version"]),
            idempotency_key=cast(str, request["idempotency_key"]),
            request_sha256=request_sha256,
            operation_request=execution_request,
            now=self._now(),
        )
        if replay is not None:
            return replay
        try:
            raw = self._workflow.execute(execution_request)
            execution = _validate_execution(raw, run=started)
            if execution["idempotency_key"] != execution_request["idempotency_key"]:
                raise DemoFacadeError("demo-execution-binding-invalid")
            self._verify_visuals(cast(Sequence[Mapping[str, str]], execution["visuals"]))
        except _KNOWN_OPERATION_ERRORS as error:
            self._record_known_failure(run_id, phase="executing", error=error)
            if isinstance(error, DemoFacadeError):
                raise
            raise DemoFacadeError("demo-operation-failed") from error
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error
        try:
            return self._store.complete_execution(run_id, execution, now=self._now())
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error

    @staticmethod
    def _rejection_request(body: Mapping[str, Any]) -> dict[str, Any]:
        fields = frozenset(
            {
                "schema",
                "approval_nonce",
                "expected_run_version",
                "expected_incident_version",
                "expected_plan_version",
                "expected_plan_sha256",
                "expected_target_sha256",
                "reason_code",
                "idempotency_key",
            }
        )
        _require_exact(body, fields, REJECTION_REQUEST_SCHEMA)
        nonce = body.get("approval_nonce")
        if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
            raise DemoFacadeError("demo-approval-nonce-invalid")
        reason = body.get("reason_code")
        if reason not in REJECTION_CODES:
            raise DemoFacadeError("demo-rejection-reason-invalid")
        return {
            "schema": REJECTION_REQUEST_SCHEMA,
            "approval_nonce": nonce,
            "expected_run_version": _require_version(
                body.get("expected_run_version"), code="demo-run-version-invalid"
            ),
            "expected_incident_version": _require_version(
                body.get("expected_incident_version"), code="demo-incident-version-invalid"
            ),
            "expected_plan_version": _require_version(
                body.get("expected_plan_version"), code="demo-plan-version-invalid"
            ),
            "expected_plan_sha256": _require_digest(
                body.get("expected_plan_sha256"), code="demo-plan-digest-invalid"
            ),
            "expected_target_sha256": _require_digest(
                body.get("expected_target_sha256"), code="demo-target-digest-invalid"
            ),
            "reason_code": reason,
            "idempotency_key": _require_idempotency_key(body.get("idempotency_key")),
        }

    @staticmethod
    def _validate_rejection_result(
        value: Mapping[str, Any],
        *,
        run: Mapping[str, Any],
        reason_code: str | None = None,
    ) -> dict[str, Any]:
        fields = {
            "schema",
            "run_id",
            "incident_id",
            "incident_version",
            "plan_version",
            "plan_sha256",
            "target_sha256",
            "reason_code",
            "decision_id",
            "decision_sha256",
        }
        if (
            set(value) != fields
            or value.get("schema") != _REJECTION_RESULT_SCHEMA
            or value.get("run_id") != run["run_id"]
            or value.get("incident_id") != run["incident_id"]
            or value.get("incident_version") != run["incident_version"]
            or value.get("plan_version") != run["plan_version"]
            or value.get("plan_sha256") != run["plan_sha256"]
            or value.get("target_sha256") != run["target_sha256"]
            or value.get("reason_code") not in REJECTION_CODES
            or (reason_code is not None and value.get("reason_code") != reason_code)
        ):
            raise DemoFacadeError("demo-rejection-decision-invalid")
        return {
            **dict(value),
            "decision_id": _require_identifier(
                value.get("decision_id"), code="demo-rejection-decision-invalid"
            ),
            "decision_sha256": _require_digest(
                value.get("decision_sha256"), code="demo-rejection-decision-invalid"
            ),
        }

    @staticmethod
    def _rejection_workflow_request(
        run: Mapping[str, Any],
        *,
        reason_code: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return {
            "schema": "colortrace-demo-rejection-operation/v1",
            "run_id": run["run_id"],
            "incident_id": run["incident_id"],
            "incident_version": run["incident_version"],
            "plan_version": run["plan_version"],
            "plan_sha256": run["plan_sha256"],
            "target_sha256": run["target_sha256"],
            "reason_code": reason_code,
            "idempotency_key": idempotency_key,
        }

    def reject(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        with self._operation_lock:
            return self._reject(run_id, body)

    def _reject(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if _RUN_ID.fullmatch(run_id) is None:
            raise DemoFacadeError("demo-run-id-invalid")
        self._assert_active_build_binding()
        request = self._rejection_request(body)
        current = self._store.raw(run_id, now=self._now())
        if not hmac.compare_digest(
            cast(str, current["approval_nonce_sha256"]),
            _nonce_sha256(cast(str, request["approval_nonce"])),
        ):
            raise DemoFacadeError("demo-approval-nonce-invalid")
        bindings = {
            "expected_incident_version": "incident_version",
            "expected_plan_version": "plan_version",
            "expected_plan_sha256": "plan_sha256",
            "expected_target_sha256": "target_sha256",
        }
        if any(request[provided] != current[stored] for provided, stored in bindings.items()):
            raise DemoFacadeError("demo-rejection-binding-conflict")
        expected_run_version = cast(int, request["expected_run_version"])
        if current["phase"] == "awaiting-approval":
            if current["version"] != expected_run_version:
                raise DemoFacadeError("demo-run-version-conflict")
        elif not (
            current["phase"] == "unresolved"
            and current["version"] == expected_run_version + 1
            and cast(str, current["terminal_reason"]).startswith("plan-rejected-")
        ):
            raise DemoFacadeError("demo-run-phase-conflict")
        operation_request = self._rejection_workflow_request(
            current,
            reason_code=cast(str, request["reason_code"]),
            idempotency_key=cast(str, request["idempotency_key"]),
        )
        try:
            raw = self._workflow.reject(operation_request)
            rejection = self._validate_rejection_result(
                raw,
                run=current,
                reason_code=cast(str, request["reason_code"]),
            )
        except ResponsePlanError as error:
            if error.code == "idempotency-conflict":
                raise DemoFacadeError("demo-idempotency-conflict") from error
            raise
        except DemoFacadeError:
            raise
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error
        terminal_reason = f"plan-rejected-{rejection['reason_code']}"
        try:
            return self._store.complete_rejection(
                run_id,
                expected_version=expected_run_version,
                reason=terminal_reason,
                now=self._now(),
            )
        except DemoFacadeError:
            raise
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error

    @staticmethod
    def _closure_request(body: Mapping[str, Any]) -> dict[str, Any]:
        fields = frozenset(
            {
                "schema",
                "expected_run_version",
                "expected_incident_version",
                "expected_workflow_version",
                "expected_packet_id",
                "expected_packet_sha256",
                "expected_outcome_id",
                "expected_outcome_sha256",
                "reason",
                "idempotency_key",
            }
        )
        _require_exact(body, fields, CLOSURE_REQUEST_SCHEMA)
        reason = body.get("reason")
        if (
            not isinstance(reason, str)
            or reason != reason.strip()
            or not 1 <= len(reason) <= 512
            or "\x00" in reason
        ):
            raise DemoFacadeError("demo-closure-reason-invalid")
        return {
            "schema": CLOSURE_REQUEST_SCHEMA,
            "expected_run_version": _require_version(
                body.get("expected_run_version"), code="demo-run-version-invalid"
            ),
            "expected_incident_version": _require_version(
                body.get("expected_incident_version"), code="demo-incident-version-invalid"
            ),
            "expected_workflow_version": _require_version(
                body.get("expected_workflow_version"), code="demo-workflow-version-invalid"
            ),
            "expected_packet_id": _require_identifier(
                body.get("expected_packet_id"), code="demo-packet-id-invalid"
            ),
            "expected_packet_sha256": _require_digest(
                body.get("expected_packet_sha256"), code="demo-packet-digest-invalid"
            ),
            "expected_outcome_id": _require_identifier(
                body.get("expected_outcome_id"), code="demo-outcome-id-invalid"
            ),
            "expected_outcome_sha256": _require_digest(
                body.get("expected_outcome_sha256"), code="demo-outcome-digest-invalid"
            ),
            "reason": reason,
            "idempotency_key": _require_idempotency_key(body.get("idempotency_key")),
        }

    @staticmethod
    def _validate_closure(
        value: Mapping[str, Any],
        *,
        run: Mapping[str, Any],
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        selected = validate_closure_result(value)
        bindings = {
            "incident_id": run["incident_id"],
            "workflow_id": run["workflow_id"],
            "workflow_version_before": run["workflow_version"],
            "packet_id": run["packet_id"],
            "packet_sha256": run["packet_sha256"],
            "outcome_id": run["outcome_id"],
            "outcome_sha256": run["outcome_sha256"],
        }
        if any(selected.get(key) != expected for key, expected in bindings.items()):
            raise DemoFacadeError("demo-closure-binding-invalid")
        if selected.get("idempotency_key") != request.get("idempotency_key") or selected.get(
            "reason"
        ) != request.get("reason"):
            raise DemoFacadeError("demo-closure-binding-invalid")
        after = _require_version(
            selected.get("workflow_version_after"), code="demo-workflow-version-invalid"
        )
        if after != cast(int, run["workflow_version"]) + 1:
            raise DemoFacadeError("demo-closure-binding-invalid")
        return selected

    def _closure_actor(self, incident_id: str) -> Principal | None:
        return (
            self._closure_principal_factory(incident_id)
            if self._closure_principal_factory is not None
            else self._closure_principal
        )

    def close(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        with self._operation_lock:
            return self._close(run_id, body)

    def _close(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if _RUN_ID.fullmatch(run_id) is None:
            raise DemoFacadeError("demo-run-id-invalid")
        self._assert_active_build_binding()
        self.reconcile_startup()
        request = self._closure_request(body)
        current = self._store.raw(run_id, now=self._now())
        bindings = {
            "expected_incident_version": "incident_version",
            "expected_workflow_version": "workflow_version",
            "expected_packet_id": "packet_id",
            "expected_packet_sha256": "packet_sha256",
            "expected_outcome_id": "outcome_id",
            "expected_outcome_sha256": "outcome_sha256",
        }
        if any(request[provided] != current[stored] for provided, stored in bindings.items()):
            raise DemoFacadeError("demo-closure-binding-conflict")
        delegated = {
            "schema": "recovery-closure-request/v1",
            "expected_incident_version": request["expected_incident_version"],
            "expected_workflow_version": request["expected_workflow_version"],
            "expected_packet_id": request["expected_packet_id"],
            "expected_packet_sha256": request["expected_packet_sha256"],
            "expected_outcome_id": request["expected_outcome_id"],
            "expected_outcome_sha256": request["expected_outcome_sha256"],
            "reason": request["reason"],
            "idempotency_key": request["idempotency_key"],
        }
        request_sha256 = document_sha256(request)
        started, replay = self._store.begin_operation(
            run_id,
            operation="close",
            expected_phase="awaiting-closure",
            next_phase="closing",
            expected_version=cast(int, request["expected_run_version"]),
            idempotency_key=cast(str, request["idempotency_key"]),
            request_sha256=request_sha256,
            operation_request=delegated,
            now=self._now(),
        )
        if replay is not None:
            return replay
        principal = self._closure_actor(cast(str, started["incident_id"]))
        if self._recovery is None or principal is None:
            return self._store.fail(
                run_id,
                reason="closure-unavailable",
                now=self._now(),
                expected_phase="closing",
            )
        try:
            raw = self._recovery.close(
                principal,
                cast(str, started["incident_id"]),
                delegated,
            )
            closure = self._validate_closure(raw, run=started, request=delegated)
        except _KNOWN_OPERATION_ERRORS as error:
            self._record_known_failure(run_id, phase="closing", error=error)
            if isinstance(error, DemoFacadeError):
                raise
            raise DemoFacadeError("demo-operation-failed") from error
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error
        try:
            return self._store.complete_closure(run_id, closure, now=self._now())
        except Exception as error:
            raise DemoFacadeError("demo-operation-uncertain") from error

    def get(self, run_id: str) -> dict[str, Any]:
        with self._operation_lock:
            if _RUN_ID.fullmatch(run_id) is None:
                raise DemoFacadeError("demo-run-id-invalid")
            self._assert_active_build_binding()
            self.reconcile_startup()
            return self._store.get(run_id, now=self._now())

    def reset(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        with self._operation_lock:
            return self._reset(run_id, body)

    def _reset(self, run_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
        if _RUN_ID.fullmatch(run_id) is None:
            raise DemoFacadeError("demo-run-id-invalid")
        _require_exact(
            body,
            frozenset({"schema", "expected_run_version", "idempotency_key"}),
            RESET_REQUEST_SCHEMA,
        )
        expected = _require_version(
            body.get("expected_run_version"), code="demo-run-version-invalid"
        )
        key = _require_idempotency_key(body.get("idempotency_key"))
        request = {
            "schema": RESET_REQUEST_SCHEMA,
            "expected_run_version": expected,
            "idempotency_key": key,
        }
        replay = self._store.begin_reset(
            run_id,
            expected_version=expected,
            idempotency_key=key,
            request_sha256=document_sha256(request),
            now=self._now(),
        )
        if replay is not None:
            return replay
        if self._scenario_reset is None:
            raise DemoFacadeError("demo-reset-unavailable")
        operation_id = _scenario_reset_operation_id(
            run_id=run_id,
            request_sha256=document_sha256(request),
        )
        try:
            raw = self._scenario_reset.restore_authored_scenario(operation_id=operation_id)
            restoration = _validate_scenario_reset(raw, operation_id=operation_id)
        except DemoFacadeError:
            raise
        except Exception as error:
            raise DemoFacadeError("demo-reset-uncertain") from error
        return self._store.complete_reset(
            run_id,
            restoration=restoration,
            now=self._now(),
        )

    def receipt(self, run_id: str) -> dict[str, Any]:
        with self._operation_lock:
            if _RUN_ID.fullmatch(run_id) is None:
                raise DemoFacadeError("demo-run-id-invalid")
            return self._store.receipt(run_id, now=self._now())

    def visual(self, run_id: str, kind: str) -> DemoVisual:
        with self._operation_lock:
            if _RUN_ID.fullmatch(run_id) is None:
                raise DemoFacadeError("demo-run-id-invalid")
            if kind not in _VISUAL_KINDS:
                raise DemoFacadeError("demo-visual-kind-invalid")
            descriptor = self._store.visual_descriptor(run_id, kind, now=self._now())
            content = self._read_visual(descriptor)
            return DemoVisual(
                content=content,
                media_type=descriptor["media_type"],
                sha256=descriptor["sha256"],
            )

    def reconcile_startup(self) -> None:
        with self._operation_lock:
            self._reconcile_startup()

    def _reconcile_startup(self) -> None:
        self._reconcile_rejection_before_expiry()
        pending_reset = self._store.pending_reset()
        if pending_reset is not None:
            if self._scenario_reset is None:
                raise DemoFacadeError("demo-reset-unavailable")
            run_id = cast(str, pending_reset["run_id"])
            operation_id = _scenario_reset_operation_id(
                run_id=run_id,
                request_sha256=cast(str, pending_reset["request_sha256"]),
            )
            try:
                raw_reset = self._scenario_reset.restore_authored_scenario(
                    operation_id=operation_id
                )
                restoration = _validate_scenario_reset(raw_reset, operation_id=operation_id)
                self._store.complete_reset(
                    run_id,
                    restoration=restoration,
                    now=self._now(),
                )
            except DemoFacadeError:
                raise
            except Exception as error:
                raise DemoFacadeError("demo-reset-uncertain") from error
        run = self._store.transient(now=self._now())
        if run is None:
            return
        if run["source_commit"] != self._source_commit:
            raise DemoFacadeError("demo-build-binding-conflict")
        operation_request = cast(Mapping[str, Any], run["operation_request"])
        if run["phase"] == "closing":
            if self._recovery is None:
                self._expire_inconclusive(run)
                return
            try:
                review = self._recovery.review(cast(str, run["incident_id"]))
            except _KNOWN_OPERATION_ERRORS as error:
                self._record_known_failure(
                    cast(str, run["run_id"]),
                    phase="closing",
                    error=error,
                )
                return
            except Exception:
                self._expire_inconclusive(run)
                return
            snapshot = review.get("snapshot") if isinstance(review, Mapping) else None
            if (
                not isinstance(review, Mapping)
                or review.get("schema") != "recovery-review/v1"
                or not isinstance(snapshot, Mapping)
                or snapshot.get("incident_id") != run["incident_id"]
                or "closure" not in review
            ):
                self._store.fail(
                    cast(str, run["run_id"]),
                    reason="restart-reconciliation-invalid",
                    now=self._now(),
                    expected_phase="closing",
                )
                return
            raw_closure = review["closure"]
            if raw_closure is None:
                principal = self._closure_actor(cast(str, run["incident_id"]))
                if principal is None:
                    self._expire_inconclusive(run)
                    return
                try:
                    raw_closure = self._recovery.close(
                        principal,
                        cast(str, run["incident_id"]),
                        operation_request,
                    )
                except _KNOWN_OPERATION_ERRORS as error:
                    self._record_known_failure(
                        cast(str, run["run_id"]),
                        phase="closing",
                        error=error,
                    )
                    return
                except Exception:
                    self._expire_inconclusive(run)
                    return
            if not isinstance(raw_closure, Mapping):
                self._store.fail(
                    cast(str, run["run_id"]),
                    reason="restart-reconciliation-invalid",
                    now=self._now(),
                    expected_phase="closing",
                )
                return
            try:
                closure = self._validate_closure(
                    raw_closure,
                    run=run,
                    request=operation_request,
                )
                self._store.complete_closure(cast(str, run["run_id"]), closure, now=self._now())
            except DemoFacadeError:
                self._store.fail(
                    cast(str, run["run_id"]),
                    reason="restart-reconciliation-invalid",
                    now=self._now(),
                    expected_phase="closing",
                )
            return
        request = {
            "schema": RECONCILIATION_REQUEST_SCHEMA,
            "run_id": run["run_id"],
            "incident_id": run["incident_id"],
            "phase": run["phase"],
            "run_version": run["version"],
            "operation": run["operation"],
            "idempotency_key": run["operation_idempotency_key"],
            "operation_request_sha256": run["operation_request_sha256"],
            "operation_request": operation_request,
            "lease_expired": run["lease_expired"],
        }
        try:
            result = self._workflow.reconcile(request)
        except _KNOWN_OPERATION_ERRORS as error:
            self._record_known_failure(
                cast(str, run["run_id"]),
                phase=cast(str, run["phase"]),
                error=error,
            )
            return
        except Exception:
            self._expire_inconclusive(run)
            return
        if result is None:
            self._expire_inconclusive(run)
            return
        try:
            if run["phase"] == "preparing":
                preparation = _validate_preparation(
                    result,
                    run_id=cast(str, run["run_id"]),
                    incident_id=cast(str, run["incident_id"]),
                )
                self._verify_visuals(cast(Sequence[Mapping[str, str]], preparation["visuals"]))
                self._store.complete_preparation(
                    cast(str, run["run_id"]), preparation, now=self._now()
                )
            elif run["phase"] == "executing":
                execution = _validate_execution(result, run=run)
                if execution["idempotency_key"] != operation_request.get("idempotency_key"):
                    raise DemoFacadeError("demo-execution-binding-invalid")
                self._verify_visuals(cast(Sequence[Mapping[str, str]], execution["visuals"]))
                self._store.complete_execution(cast(str, run["run_id"]), execution, now=self._now())
            else:
                raise DemoFacadeError("demo-reconciliation-inconclusive")
        except DemoFacadeError:
            self._store.fail(
                cast(str, run["run_id"]),
                reason="restart-reconciliation-invalid",
                now=self._now(),
                expected_phase=cast(str, run["phase"]),
            )


__all__ = [
    "APPROVAL_PHRASE",
    "APPROVAL_REQUEST_SCHEMA",
    "CANONICAL_SCENARIO",
    "CLOSURE_REQUEST_SCHEMA",
    "DemoApi",
    "DemoFacade",
    "DemoFacadeError",
    "DemoVisual",
    "DemoWorkflowPort",
    "EXECUTION_SCHEMA",
    "LEASE_SECONDS",
    "PREPARATION_SCHEMA",
    "RECEIPT_SCHEMA",
    "REJECTION_REQUEST_SCHEMA",
    "RECONCILIATION_REQUEST_SCHEMA",
    "RESET_REQUEST_SCHEMA",
    "RESET_SCHEMA",
    "RUN_REQUEST_SCHEMA",
    "RUN_SCHEMA",
    "SQLiteDemoRunStore",
]
