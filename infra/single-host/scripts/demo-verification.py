#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

RUN_SCHEMA = "colortrace-demo-run/v1"
RUN_REQUEST_SCHEMA = "colortrace-demo-run-request/v2"
APPROVAL_REQUEST_SCHEMA = "colortrace-demo-approval-request/v1"
CLOSURE_REQUEST_SCHEMA = "colortrace-demo-closure-request/v1"
RECEIPT_SCHEMA = "colortrace-demo-receipt/v1"
SCENARIO_ID = "ct-shadowed-lut-v1:canonical"
APPROVAL_PHRASE = "APPROVE_COLORTRACE_SIMULATOR_ACTION"
CHECK_NAMES = [
    "active-publication",
    "approved-resource-state",
    "declared-reference-recovery",
    "exact-typed-lineage",
    "approved-recovery-scope",
    "safe-complement-preservation",
    "post-action-telemetry-correlation",
]
SOURCE_COMPONENTS = ("runtime", "web", "caddy", "grafana", "loki", "tempo")
ALL_COMPONENTS = (*SOURCE_COMPONENTS[:5], "prometheus", SOURCE_COMPONENTS[5])
VISUAL_KINDS = ("diff", "expected", "observed", "recovered")
RUN_BASE_FIELDS = {
    "schema",
    "run_id",
    "incident_id",
    "scenario_id",
    "source_commit",
    "build_sha256",
    "phase",
    "version",
    "lease_expires_at",
    "poll",
    "approval",
    "recovery",
    "visual_comparison",
    "terminal",
    "terminal_reason",
    "receipt_href",
    "reset",
}
RUN_ID = re.compile(r"^demo-run-[0-9a-f]{32}$")
INCIDENT_ID = re.compile(r"^incident-demo-[0-9a-f]{32}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
RESET_OPERATION_ID = re.compile(r"^demo-reset:[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
MODEL = {
    "provider": "vertex-ai",
    "framework": "google-adk",
    "model": "gemini-3.5-flash",
    "location": "global",
    "versions": {
        "google-adk": "2.6.3",
        "google-genai": "2.17.0",
        "mcp": "1.29.0",
    },
}
MCP_IDENTITY = {
    "source_commit": "007e8d82154899a28e19e8dfe9c2bb4452c5211a",
    "source_version": "1.1.0",
    "binary_sha256": ("sha256:5f6b1492ff35f92506e17310b3ea8b689c3f04c1fe0f6d4cc0a1f6e50bd52d93"),
    "transport": "stdio",
    "write_tools_enabled": False,
}
MCP_CATALOG_IDENTITY = {
    "schema": "grafana-mcp-tool-inventory/v1",
    "server_version": "1.1.0",
    "server_commit": MCP_IDENTITY["source_commit"],
    "binary_sha256": MCP_IDENTITY["binary_sha256"].removeprefix("sha256:"),
    "mcp_sdk_version": MODEL["versions"]["mcp"],
    "mcp_protocol_version": "2025-06-18",
}
MCP_SELECTED_TOOLS = {
    "alerting_manage_rules",
    "query_loki_logs",
    "query_prometheus",
    "tempo_get-trace",
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DEMO_CONFIG = REPOSITORY_ROOT / "config/demo/local-demo.json"
PROVENANCE_CANONICAL_FILES = {
    "investigation_policy_sha256": (
        REPOSITORY_ROOT / "config/investigation/investigation-policy.json"
    ),
    "model_profile_sha256": REPOSITORY_ROOT / "config/investigation/model-profile.json",
    "query_catalog_sha256": REPOSITORY_ROOT / "config/grafana-mcp/query-catalog.json",
}


class VerificationError(ValueError):
    pass


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise VerificationError("duplicate-json-key")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(
                VerificationError("floating-point-values-are-not-canonical")
            ),
            parse_constant=lambda _value: (_ for _ in ()).throw(VerificationError()),
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise VerificationError(f"invalid-json:{path.name}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"invalid-object:{path.name}")
    return value


def _canonical(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, float):
            raise VerificationError("floating-point-values-are-not-canonical")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise VerificationError("canonical-object-keys-must-be-strings")
            return {key: normalize(child) for key, child in item.items()}
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        return item

    return json.dumps(
        normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _document_sha256(value: Any) -> str:
    return _sha256(_canonical(value))


def _file_sha256(path: Path) -> str:
    try:
        return _sha256(path.read_bytes())
    except OSError as error:
        raise VerificationError(f"unreadable-file:{path.name}") from error


def _require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise VerificationError(code)
    return value


def _require_identifier(value: Any, code: str) -> str:
    if not _is_identifier(value):
        raise VerificationError(code)
    return value


def _is_identifier(value: Any) -> bool:
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def _require_timestamp(value: Any, code: str) -> str:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise VerificationError(code)
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise VerificationError(code) from error
    return value


def _require_fields(value: Any, expected: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise VerificationError(code)
    return value


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(json.dumps(value, sort_keys=True, indent=2).encode("utf-8"))
            target.write(b"\n")
            target.flush()
            os.fsync(target.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _validate_projection_identity(value: dict[str, Any]) -> None:
    if (
        value.get("schema") != RUN_SCHEMA
        or not isinstance(value.get("run_id"), str)
        or RUN_ID.fullmatch(value["run_id"]) is None
        or not isinstance(value.get("incident_id"), str)
        or INCIDENT_ID.fullmatch(value["incident_id"]) is None
        or value.get("scenario_id") != SCENARIO_ID
        or not isinstance(value.get("source_commit"), str)
        or COMMIT.fullmatch(value["source_commit"]) is None
        or not isinstance(value.get("version"), int)
        or isinstance(value.get("version"), bool)
        or value["version"] < 1
        or value.get("poll")
        != {
            "href": f"/v1/demo/runs/{value['run_id']}",
            "after_milliseconds": 1000,
        }
    ):
        raise VerificationError("run-identity-invalid")
    _require_digest(value.get("build_sha256"), "run-build-digest-invalid")


def _validate_visual_comparison(
    value: Any,
    *,
    run_id: str,
    required_kinds: set[str],
    visual_root: Path | None = None,
) -> list[dict[str, str]]:
    if not isinstance(value, dict) or set(value) != required_kinds:
        raise VerificationError("visual-comparison-invalid")
    expected_receipt: list[dict[str, str]] = []
    if visual_root is not None:
        if not visual_root.is_dir() or visual_root.is_symlink():
            raise VerificationError("visual-assets-invalid")
        if {path.name for path in visual_root.iterdir()} != {
            f"{kind}.png" for kind in required_kinds
        }:
            raise VerificationError("visual-assets-invalid")
    for kind in sorted(required_kinds):
        descriptor = _require_fields(
            value[kind],
            {"href", "sha256", "media_type", "label"},
            "visual-comparison-invalid",
        )
        digest = _require_digest(descriptor["sha256"], "visual-comparison-invalid")
        if descriptor != {
            "href": f"/v1/demo/runs/{run_id}/visuals/{kind}",
            "sha256": digest,
            "media_type": "image/png",
            "label": "illustrative-authored-fixture",
        }:
            raise VerificationError("visual-comparison-invalid")
        if visual_root is not None:
            visual_path = visual_root / f"{kind}.png"
            if (
                not visual_path.is_file()
                or visual_path.is_symlink()
                or _file_sha256(visual_path) != digest
            ):
                raise VerificationError("visual-assets-invalid")
        expected_receipt.append({"kind": kind, "sha256": digest})
    return expected_receipt


def new_start(arguments: argparse.Namespace) -> None:
    request = {
        "schema": RUN_REQUEST_SCHEMA,
        "scenario_id": SCENARIO_ID,
        "approval_nonce": secrets.token_urlsafe(32),
        "idempotency_key": f"verify:{secrets.token_hex(24)}",
    }
    _atomic_json(arguments.output.resolve(), request)


def prepare_approval(arguments: argparse.Namespace) -> None:
    run = _load(arguments.run.resolve(strict=True))
    _require_fields(
        run,
        RUN_BASE_FIELDS | {"investigation", "approval_nonce"},
        "approval-projection-invalid",
    )
    _validate_projection_identity(run)
    approval = _require_fields(
        run.get("approval"),
        {"phrase", "incident_version", "plan_version", "plan_sha256", "target_sha256"},
        "approval-projection-invalid",
    )
    nonce = run.get("approval_nonce")
    if (
        run.get("phase") != "awaiting-approval"
        or run.get("terminal") is not False
        or run.get("terminal_reason") is not None
        or run.get("receipt_href") is not None
        or run.get("reset") is not False
        or run.get("recovery") is not None
        or approval["phrase"] != APPROVAL_PHRASE
        or not isinstance(approval.get("incident_version"), int)
        or isinstance(approval.get("incident_version"), bool)
        or approval["incident_version"] < 1
        or not isinstance(approval.get("plan_version"), int)
        or isinstance(approval.get("plan_version"), bool)
        or approval["plan_version"] < 1
        or not isinstance(nonce, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{32,256}", nonce) is None
    ):
        raise VerificationError("approval-projection-invalid")
    _require_timestamp(run.get("lease_expires_at"), "approval-projection-invalid")
    _validate_visual_comparison(
        run.get("visual_comparison"),
        run_id=run["run_id"],
        required_kinds={"diff", "expected", "observed"},
    )
    _validate_investigation(run.get("investigation"))
    request = {
        "schema": APPROVAL_REQUEST_SCHEMA,
        "approval_nonce": nonce,
        "approval_phrase": APPROVAL_PHRASE,
        "expected_run_version": run["version"],
        "expected_incident_version": approval["incident_version"],
        "expected_plan_version": approval["plan_version"],
        "expected_plan_sha256": _require_digest(
            approval["plan_sha256"], "approval-projection-invalid"
        ),
        "expected_target_sha256": _require_digest(
            approval["target_sha256"], "approval-projection-invalid"
        ),
        "idempotency_key": f"approve:{run['run_id']}",
    }
    _atomic_json(arguments.output.resolve(), request)
    print(run["run_id"])


def prepare_closure(arguments: argparse.Namespace) -> None:
    run = _load(arguments.run.resolve(strict=True))
    _require_fields(
        run,
        RUN_BASE_FIELDS | {"investigation", "execution"},
        "closure-projection-invalid",
    )
    _validate_projection_identity(run)
    approval = _require_fields(
        run.get("approval"),
        {"phrase", "incident_version", "plan_version", "plan_sha256", "target_sha256"},
        "closure-projection-invalid",
    )
    recovery = _require_fields(
        run.get("recovery"),
        {
            "outcome_id",
            "outcome_sha256",
            "workflow_id",
            "workflow_version",
            "packet_id",
            "packet_sha256",
            "closure_id",
            "closure_sha256",
        },
        "closure-projection-invalid",
    )
    if (
        run.get("phase") != "awaiting-closure"
        or run.get("terminal") is not False
        or run.get("terminal_reason") is not None
        or run.get("receipt_href") is not None
        or run.get("reset") is not False
        or recovery["closure_id"] is not None
        or recovery["closure_sha256"] is not None
    ):
        raise VerificationError("closure-projection-invalid")
    _require_timestamp(run.get("lease_expires_at"), "closure-projection-invalid")
    _validate_visual_comparison(
        run.get("visual_comparison"),
        run_id=run["run_id"],
        required_kinds=set(VISUAL_KINDS),
    )
    _validate_investigation(run.get("investigation"))
    _validate_execution(run.get("execution"))
    request = {
        "schema": CLOSURE_REQUEST_SCHEMA,
        "expected_run_version": run["version"],
        "expected_incident_version": approval["incident_version"],
        "expected_workflow_version": recovery["workflow_version"],
        "expected_packet_id": recovery["packet_id"],
        "expected_packet_sha256": _require_digest(
            recovery["packet_sha256"], "closure-projection-invalid"
        ),
        "expected_outcome_id": recovery["outcome_id"],
        "expected_outcome_sha256": _require_digest(
            recovery["outcome_sha256"], "closure-projection-invalid"
        ),
        "reason": "Verified recovery reviewed against post-action evidence.",
        "idempotency_key": f"close:{run['run_id']}",
    }
    _atomic_json(arguments.output.resolve(), request)


def conflict_run_id(arguments: argparse.Namespace) -> None:
    error = _load(arguments.error.resolve(strict=True))
    if (
        set(error) != {"code", "run_id"}
        or error["code"] not in {"demo-active-run-exists", "demo-reset-required"}
        or not isinstance(error["run_id"], str)
        or RUN_ID.fullmatch(error["run_id"]) is None
    ):
        raise VerificationError("start-conflict-invalid")
    print(error["run_id"])


def prepare_reset(arguments: argparse.Namespace) -> None:
    run = _load(arguments.run.resolve(strict=True))
    if not RUN_BASE_FIELDS <= set(run) or not set(run) - RUN_BASE_FIELDS <= {
        "investigation",
        "execution",
    }:
        raise VerificationError("reset-projection-invalid")
    _validate_projection_identity(run)
    if run.get("terminal") is not True or run.get("phase") not in {
        "closed",
        "unresolved",
        "expired",
    }:
        raise VerificationError("reset-projection-invalid")
    request = {
        "schema": "colortrace-demo-reset-request/v1",
        "expected_run_version": run["version"],
        "idempotency_key": f"reset:verify:{run['run_id']}",
    }
    _atomic_json(arguments.output.resolve(), request)
    print(run["run_id"])


def verify_reset(arguments: argparse.Namespace) -> None:
    reset = _load(arguments.reset.resolve(strict=True))
    run = _load(arguments.run.resolve(strict=True))
    _require_fields(
        reset,
        {"schema", "run_id", "phase", "version", "reset", "receipt_href", "restoration"},
        "reset-result-invalid",
    )
    restoration = _require_fields(
        reset["restoration"],
        {
            "schema",
            "operation_id",
            "fixture_id",
            "source_batch_sha256",
            "previous_pointer_sha256",
            "active_pointer_sha256",
            "generation",
        },
        "reset-result-invalid",
    )
    if (
        reset["schema"] != "colortrace-demo-reset/v1"
        or reset["run_id"] != run.get("run_id")
        or reset["phase"] != run.get("phase")
        or reset["version"] != run.get("version")
        or reset["reset"] is not True
        or reset["receipt_href"] != f"/v1/demo/runs/{run['run_id']}/receipt"
        or restoration["schema"] != "simulator-authored-scenario-reset/v1"
        or not isinstance(restoration.get("operation_id"), str)
        or RESET_OPERATION_ID.fullmatch(restoration["operation_id"]) is None
        or restoration.get("fixture_id") != "ct-shadowed-lut-v1"
        or restoration["generation"] != 1
        or any(
            DIGEST.fullmatch(str(restoration.get(field))) is None
            for field in (
                "source_batch_sha256",
                "previous_pointer_sha256",
                "active_pointer_sha256",
            )
        )
    ):
        raise VerificationError("reset-result-invalid")


def _validate_artifact(binding: dict[str, Any]) -> None:
    if binding.get("schema") != "colortrace-single-host-admission/v1":
        raise VerificationError("artifact-binding-invalid")
    source = binding.get("source")
    images = binding.get("images")
    if not isinstance(source, dict) or not isinstance(images, dict):
        raise VerificationError("artifact-binding-invalid")
    if (
        set(images) != set(ALL_COMPONENTS)
        or not isinstance(source.get("commit"), str)
        or COMMIT.fullmatch(source["commit"]) is None
        or not isinstance(source.get("tree"), str)
        or COMMIT.fullmatch(source["tree"]) is None
    ):
        raise VerificationError("artifact-binding-invalid")
    for reference in images.values():
        if (
            not isinstance(reference, str)
            or "@" not in reference
            or DIGEST.fullmatch(reference.rsplit("@", 1)[1]) is None
        ):
            raise VerificationError("artifact-binding-invalid")
    for field in (
        "build_manifest_sha256",
        "scan_binding_sha256",
        "observability_lock_sha256",
        "fixture_manifest_sha256",
    ):
        _require_digest(binding.get(field), "artifact-binding-invalid")


def verify_instance_metadata(arguments: argparse.Namespace) -> None:
    instance = _load(arguments.instance.resolve(strict=True))
    binding = _load(arguments.artifact.resolve(strict=True))
    _validate_artifact(binding)
    items = instance.get("metadata", {}).get("items")
    if instance.get("status") != "RUNNING" or not isinstance(items, list):
        raise VerificationError("instance-metadata-invalid")
    metadata: dict[str, str] = {}
    for item in items:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("key"), str)
            or not isinstance(item.get("value"), str)
            or item["key"] in metadata
        ):
            raise VerificationError("instance-metadata-invalid")
        metadata[item["key"]] = item["value"]
    runtime_build_binding = {
        "schema": "colortrace-runtime-build-binding/v1",
        "source_commit": binding["source"]["commit"],
        "source_tree": binding["source"]["tree"],
    }
    expected = {
        "colortrace-staging-generation": arguments.generation,
        "colortrace-candidate-commit": binding["source"]["commit"],
        "colortrace-candidate-tree": binding["source"]["tree"],
        "colortrace-artifact-binding-sha256": _document_sha256(binding),
        "colortrace-build-manifest-sha256": binding["build_manifest_sha256"],
        "colortrace-fixture-manifest-sha256": binding["fixture_manifest_sha256"],
        "colortrace-observability-lock-sha256": binding["observability_lock_sha256"],
        "colortrace-runtime-build-binding-sha256": _sha256(
            _canonical(runtime_build_binding) + b"\n"
        ),
        "colortrace-scan-binding-sha256": binding["scan_binding_sha256"],
        "colortrace-scan-report-set-sha256": binding["scanner"]["report_set_sha256"],
        "colortrace-scanner-version-sha256": binding["scanner"]["version_sha256"],
    }
    if any(metadata.get(key) != value for key, value in expected.items()):
        raise VerificationError("instance-metadata-invalid")


def _validate_provenance(
    provenance: Any,
    *,
    binding: dict[str, Any],
    public_url: str,
    generation: str,
) -> dict[str, Any]:
    selected = _require_fields(
        provenance,
        {
            "schema",
            "source_commit",
            "source_tree",
            "runtime_image",
            "public_url",
            "staging_generation",
            "fixture_manifest_sha256",
            "configuration",
            "model",
            "mcp",
        },
        "receipt-provenance-invalid",
    )
    configuration = _require_fields(
        selected["configuration"],
        {
            "demo_sha256",
            "build_binding_sha256",
            "investigation_policy_sha256",
            "model_profile_sha256",
            "query_catalog_sha256",
        },
        "receipt-provenance-invalid",
    )
    if any(DIGEST.fullmatch(str(value)) is None for value in configuration.values()):
        raise VerificationError("receipt-provenance-invalid")
    source = binding["source"]
    build_binding = {
        "schema": "colortrace-runtime-build-binding/v1",
        "source_commit": source["commit"],
        "source_tree": source["tree"],
    }
    expected_build_binding_sha256 = _sha256(_canonical(build_binding) + b"\n")
    if (
        selected["schema"] != "colortrace-demo-build-provenance/v1"
        or selected["source_commit"] != source["commit"]
        or selected["source_tree"] != source["tree"]
        or selected["runtime_image"] != binding["images"]["runtime"]
        or selected["public_url"] != public_url
        or selected["staging_generation"] != generation
        or selected["fixture_manifest_sha256"] != binding["fixture_manifest_sha256"]
        or configuration["build_binding_sha256"] != expected_build_binding_sha256
        or configuration["demo_sha256"] != _file_sha256(DEMO_CONFIG)
        or any(
            configuration[field] != _document_sha256(_load(path))
            for field, path in PROVENANCE_CANONICAL_FILES.items()
        )
        or selected["model"] != MODEL
    ):
        raise VerificationError("receipt-provenance-invalid")
    mcp = _require_fields(
        selected["mcp"],
        {
            "source_commit",
            "source_version",
            "binary_sha256",
            "inventory_sha256",
            "transport",
            "write_tools_enabled",
        },
        "receipt-provenance-invalid",
    )
    if (
        any(mcp.get(key) != value for key, value in MCP_IDENTITY.items())
        or DIGEST.fullmatch(str(mcp.get("inventory_sha256"))) is None
    ):
        raise VerificationError("receipt-provenance-invalid")
    return selected


def _validate_investigation(value: Any) -> dict[str, Any]:
    investigation = _require_fields(
        value,
        {
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
        },
        "investigation-proof-invalid",
    )
    scope = _require_fields(
        investigation["scope"],
        {"state", "affected_count", "safe_count", "unknown_count"},
        "investigation-proof-invalid",
    )
    invocations = investigation["model_invocations"]
    evidence = investigation["evidence"]
    validators = investigation["validators"]
    budget = _require_fields(
        investigation["budget_use"],
        {
            "elapsed_ms",
            "model_turns",
            "input_tokens",
            "output_tokens",
            "mcp_attempts",
            "validator_calls",
        },
        "investigation-proof-invalid",
    )
    plan = _require_fields(
        investigation["plan"],
        {"status", "version", "plan_sha256", "target_sha256"},
        "investigation-proof-invalid",
    )
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
    evidence_fields = {
        "evidence_id",
        "query_key",
        "tool",
        "inventory_sha256",
        "content_sha256",
        "freshness",
    }
    expected_tools = {
        "alert.rule": "alerting_manage_rules",
        "log.correlated-events": "query_loki_logs",
        "metric.correlated-observations": "query_prometheus",
        "trace.by-id": "tempo_get-trace",
    }
    if (
        investigation["schema"] != "colortrace-demo-investigation-proof/v1"
        or not _is_identifier(investigation.get("packet_id"))
        or investigation["status"] != "resolved"
        or scope != {"state": "resolved", "affected_count": 4, "safe_count": 3, "unknown_count": 0}
        or not isinstance(invocations, list)
        or len(invocations) != 2
        or {item.get("turn_kind") for item in invocations if isinstance(item, dict)}
        != {"evidence-selection", "response-drafting"}
        or any(
            not isinstance(item, dict)
            or set(item) != invocation_fields
            or item.get("result_class") != "accepted"
            or item.get("model") != MODEL["model"]
            or item.get("framework") != MODEL["framework"]
            or not _is_identifier(item.get("invocation_id"))
            or DIGEST.fullmatch(str(item.get("inventory_sha256"))) is None
            or DIGEST.fullmatch(str(item.get("output_sha256"))) is None
            or re.fullmatch(r"[0-9a-f]{32}", str(item.get("trace_id"))) is None
            for item in invocations
        )
        or not isinstance(evidence, list)
        or len(evidence) != 4
        or {item.get("query_key") for item in evidence if isinstance(item, dict)}
        != set(expected_tools)
        or any(
            not isinstance(item, dict)
            or set(item) != evidence_fields
            or item.get("tool") != expected_tools.get(item.get("query_key"))
            or item.get("freshness") != "current"
            or not _is_identifier(item.get("evidence_id"))
            or any(
                DIGEST.fullmatch(str(item.get(field))) is None
                for field in ("evidence_id", "inventory_sha256", "content_sha256")
            )
            for item in evidence
        )
        or not isinstance(validators, list)
        or not validators
        or any(
            not isinstance(item, dict)
            or set(item)
            != {
                "result_id",
                "validator",
                "validator_version",
                "status",
                "derivation_sha256",
            }
            or item.get("status") != "resolved"
            or not _is_identifier(item.get("result_id"))
            or not _is_identifier(item.get("validator"))
            or not _is_identifier(item.get("validator_version"))
            or DIGEST.fullmatch(str(item.get("derivation_sha256"))) is None
            for item in validators
        )
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in budget.values()
        )
        or plan.get("status") != "pending"
        or not isinstance(plan.get("version"), int)
        or isinstance(plan.get("version"), bool)
        or plan["version"] < 1
        or DIGEST.fullmatch(str(plan.get("plan_sha256"))) is None
        or DIGEST.fullmatch(str(plan.get("target_sha256"))) is None
        or DIGEST.fullmatch(str(investigation.get("packet_sha256"))) is None
    ):
        raise VerificationError("investigation-proof-invalid")
    inventory_versions = {item["inventory_sha256"] for item in evidence}
    if len(inventory_versions) != 1 or any(
        item["inventory_sha256"] not in inventory_versions for item in invocations
    ):
        raise VerificationError("investigation-proof-invalid")
    return investigation


def _validate_execution(value: Any) -> dict[str, Any]:
    execution = _require_fields(
        value,
        {"schema", "action", "recovery"},
        "execution-proof-invalid",
    )
    action = _require_fields(
        execution["action"],
        {
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
        },
        "execution-proof-invalid",
    )
    recovery = _require_fields(
        execution["recovery"],
        {
            "status",
            "workflow_id",
            "workflow_version",
            "packet_id",
            "packet_sha256",
            "evidence_count",
            "evidence_request_sha256",
            "checks",
        },
        "execution-proof-invalid",
    )
    checks = recovery["checks"]
    before = action.get("publication_generation_before")
    after = action.get("publication_generation_after")
    action_digests = (
        "outcome_sha256",
        "safe_complement_before_sha256",
        "safe_complement_after_sha256",
        "safe_complement_proof_sha256",
        "publication_receipt_sha256",
    )
    if (
        execution["schema"] != "colortrace-demo-execution-proof/v1"
        or action.get("status") != "succeeded"
        or not _is_identifier(action.get("action_id"))
        or not _is_identifier(action.get("outcome_id"))
        or not isinstance(before, int)
        or isinstance(before, bool)
        or before < 1
        or after != before + 1
        or action.get("affected_count") != 4
        or action.get("safe_count") != 3
        or action.get("safe_complement_before_sha256") != action.get("safe_complement_after_sha256")
        or any(DIGEST.fullmatch(str(action.get(field))) is None for field in action_digests)
        or recovery.get("status") != "recovery_verified"
        or not _is_identifier(recovery.get("workflow_id"))
        or not isinstance(recovery.get("workflow_version"), int)
        or isinstance(recovery.get("workflow_version"), bool)
        or recovery["workflow_version"] < 1
        or not _is_identifier(recovery.get("packet_id"))
        or recovery.get("evidence_count") != 21
        or DIGEST.fullmatch(str(recovery.get("packet_sha256"))) is None
        or DIGEST.fullmatch(str(recovery.get("evidence_request_sha256"))) is None
        or not isinstance(checks, list)
        or len(checks) != 7
        or [item.get("check") for item in checks if isinstance(item, dict)] != CHECK_NAMES
        or any(
            not isinstance(item, dict)
            or set(item) != {"check", "status", "result_sha256"}
            or item.get("status") != "passed"
            or DIGEST.fullmatch(str(item.get("result_sha256"))) is None
            for item in checks
        )
    ):
        raise VerificationError("execution-proof-invalid")
    return execution


def verify_contract(arguments: argparse.Namespace) -> None:
    run = _load(arguments.run.resolve(strict=True))
    receipt = _load(arguments.receipt.resolve(strict=True))
    binding = _load(arguments.artifact.resolve(strict=True))
    visual_root = arguments.visuals.resolve(strict=True)
    _require_fields(
        run,
        RUN_BASE_FIELDS | {"investigation", "execution"},
        "closed-run-fields-invalid",
    )
    _validate_projection_identity(run)
    _validate_artifact(binding)
    try:
        elapsed_ms = int(arguments.elapsed_ms)
    except ValueError as error:
        raise VerificationError("workflow-duration-invalid") from error
    if elapsed_ms < 0 or elapsed_ms >= 120_000:
        raise VerificationError("workflow-duration-invalid")
    if (
        run.get("phase") != "closed"
        or run.get("terminal") is not True
        or run.get("terminal_reason") != "recovery-closed"
        or run.get("lease_expires_at") is not None
        or run.get("reset") is not False
        or run.get("receipt_href") != f"/v1/demo/runs/{run['run_id']}/receipt"
        or run.get("source_commit") != binding["source"]["commit"]
    ):
        raise VerificationError("closed-run-invalid")
    expected_visuals = _validate_visual_comparison(
        run.get("visual_comparison"),
        run_id=run["run_id"],
        required_kinds=set(VISUAL_KINDS),
        visual_root=visual_root,
    )
    investigation = _validate_investigation(run.get("investigation"))
    execution = _validate_execution(run.get("execution"))
    action = execution["action"]
    recovery_proof = execution["recovery"]
    checks = recovery_proof["checks"]
    provenance = _validate_provenance(
        receipt.get("provenance"),
        binding=binding,
        public_url=arguments.public_url,
        generation=arguments.generation,
    )
    mcp_inventory_sha256 = provenance["mcp"]["inventory_sha256"]
    proof_inventory_versions = {item["inventory_sha256"] for item in investigation["evidence"]} | {
        item["inventory_sha256"] for item in investigation["model_invocations"]
    }
    if proof_inventory_versions != {mcp_inventory_sha256}:
        raise VerificationError("receipt-mcp-inventory-binding-invalid")
    receipt_fields = {
        "schema",
        "run_id",
        "incident_id",
        "scenario_id",
        "source_commit",
        "build_sha256",
        "provenance",
        "phase",
        "run_version",
        "created_at",
        "terminal_at",
        "reason_code",
        "bindings",
        "proofs",
        "visuals",
        "receipt_id",
        "receipt_sha256",
    }
    _require_fields(receipt, receipt_fields, "receipt-fields-invalid")
    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or receipt["run_id"] != run["run_id"]
        or receipt["incident_id"] != run.get("incident_id")
        or receipt["scenario_id"] != SCENARIO_ID
        or receipt["source_commit"] != binding["source"]["commit"]
        or receipt["phase"] != "closed"
        or receipt["run_version"] != run["version"]
        or receipt["reason_code"] != "recovery-closed"
        or receipt["build_sha256"] != _document_sha256(provenance)
        or receipt["build_sha256"] != run["build_sha256"]
        or _require_timestamp(receipt.get("created_at"), "receipt-binding-invalid")
        > _require_timestamp(receipt.get("terminal_at"), "receipt-binding-invalid")
    ):
        raise VerificationError("receipt-binding-invalid")
    expected_proofs = [
        {"stage": "execution", "sha256": _document_sha256(execution)},
        {"stage": "investigation", "sha256": _document_sha256(investigation)},
    ]
    if receipt["proofs"] != expected_proofs:
        raise VerificationError("receipt-proof-hash-invalid")
    if receipt["visuals"] != expected_visuals:
        raise VerificationError("receipt-visuals-invalid")
    approval = run.get("approval")
    recovery = run.get("recovery")
    if not isinstance(approval, dict) or not isinstance(recovery, dict):
        raise VerificationError("receipt-binding-invalid")
    plan = investigation["plan"]
    if (
        set(approval)
        != {"phrase", "incident_version", "plan_version", "plan_sha256", "target_sha256"}
        or approval["phrase"] != APPROVAL_PHRASE
        or plan["version"] != approval["plan_version"]
        or plan["plan_sha256"] != approval["plan_sha256"]
        or plan["target_sha256"] != approval["target_sha256"]
        or set(recovery)
        != {
            "outcome_id",
            "outcome_sha256",
            "workflow_id",
            "workflow_version",
            "packet_id",
            "packet_sha256",
            "closure_id",
            "closure_sha256",
        }
        or action["outcome_id"] != recovery["outcome_id"]
        or action["outcome_sha256"] != recovery["outcome_sha256"]
        or recovery_proof["workflow_id"] != recovery["workflow_id"]
        or recovery_proof["workflow_version"] != recovery["workflow_version"]
        or recovery_proof["packet_id"] != recovery["packet_id"]
        or recovery_proof["packet_sha256"] != recovery["packet_sha256"]
        or not _is_identifier(recovery.get("closure_id"))
        or DIGEST.fullmatch(str(recovery.get("closure_sha256"))) is None
    ):
        raise VerificationError("receipt-binding-invalid")
    expected_bindings = {
        "incident_version": approval.get("incident_version"),
        "plan_version": approval.get("plan_version"),
        "plan_sha256": approval.get("plan_sha256"),
        "target_sha256": approval.get("target_sha256"),
        "outcome_id": recovery.get("outcome_id"),
        "outcome_sha256": recovery.get("outcome_sha256"),
        "workflow_id": recovery.get("workflow_id"),
        "workflow_version": recovery.get("workflow_version"),
        "packet_id": recovery.get("packet_id"),
        "packet_sha256": recovery.get("packet_sha256"),
        "closure_id": recovery.get("closure_id"),
        "closure_sha256": recovery.get("closure_sha256"),
    }
    if receipt["bindings"] != expected_bindings:
        raise VerificationError("receipt-binding-invalid")
    body = {
        key: value for key, value in receipt.items() if key not in {"receipt_id", "receipt_sha256"}
    }
    receipt_sha256 = _document_sha256(body)
    if (
        receipt["receipt_sha256"] != receipt_sha256
        or receipt["receipt_id"] != f"demo-receipt:{receipt_sha256.removeprefix('sha256:')}"
    ):
        raise VerificationError("receipt-hash-invalid")
    summary = {
        "run_id": run["run_id"],
        "source_commit": binding["source"]["commit"],
        "source_tree": binding["source"]["tree"],
        "receipt_id": receipt["receipt_id"],
        "receipt_sha256": receipt_sha256,
        "build_sha256": receipt["build_sha256"],
        "workflow_elapsed_ms": elapsed_ms,
        "publication_generation_before": action["publication_generation_before"],
        "publication_generation_after": action["publication_generation_after"],
        "recovery_check_count": len(checks),
        "recovery_evidence_count": recovery_proof["evidence_count"],
        "proofs": expected_proofs,
        "vertex_model": MODEL,
        "mcp_inventory_sha256": mcp_inventory_sha256,
    }
    _atomic_json(arguments.output.resolve(), summary)


def remote_script(arguments: argparse.Namespace) -> None:
    binding = _load(arguments.artifact.resolve(strict=True))
    _validate_artifact(binding)
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{6,30}[a-z0-9]", arguments.generation) is None:
        raise VerificationError("staging-generation-invalid")
    assignments = [
        f"expected_commit={shlex.quote(binding['source']['commit'])}",
        f"expected_tree={shlex.quote(binding['source']['tree'])}",
        f"expected_fixture={shlex.quote(binding['fixture_manifest_sha256'])}",
        f"expected_generation={shlex.quote(arguments.generation)}",
    ]
    assignments.extend(
        f"image_{component}={shlex.quote(binding['images'][component])}"
        for component in ALL_COMPONENTS
    )
    script = (
        "\n".join(assignments)
        + "\n"
        + r"""set -Eeuo pipefail
expected_names='colortrace-caddy
colortrace-grafana
colortrace-loki
colortrace-prometheus
colortrace-runtime
colortrace-tempo
colortrace-web'
actual_names=$(
  sudo --non-interactive docker ps \
    --filter name=colortrace- --format '{{.Names}}' \
    | LC_ALL=C sort
)
test "$actual_names" = "$expected_names"
services_healthy=false
for _ in $(seq 1 60); do
  runtime_health=$(sudo --non-interactive docker inspect \
    --format '{{.State.Health.Status}}' colortrace-runtime)
  web_health=$(sudo --non-interactive docker inspect \
    --format '{{.State.Health.Status}}' colortrace-web)
  if test "$runtime_health" = healthy && test "$web_health" = healthy; then
    services_healthy=true
    break
  fi
  if test "$runtime_health" = unhealthy || test "$web_health" = unhealthy; then
    break
  fi
  sleep 2
done
test "$services_healthy" = true
sudo --non-interactive test -L /var/lib/colortrace-lifecycle/current
test "$(sudo --non-interactive cat /var/lib/colortrace-lifecycle/current/generation)" = \
  "$expected_generation"
activated_at=$(sudo --non-interactive \
  cat /var/lib/colortrace-lifecycle/current/activated-at)
case "$activated_at" in ''|*[!0-9]*) exit 1 ;; esac
deadline=$((activated_at + 604800))
test "$deadline" -gt "$(date +%s)"
sudo --non-interactive systemctl is-active --quiet colortrace-auto-stop.timer
timer_deadline=$(sudo --non-interactive \
  systemctl show --timestamp=unix colortrace-auto-stop.timer \
  --property=NextElapseUSecRealtime --value)
test "$(date --date="$timer_deadline" +%s)" -eq "$deadline"
for component in runtime web caddy grafana loki prometheus tempo; do
  eval "reference=\$image_$component"
  container="colortrace-$component"
  container_status=$(sudo --non-interactive docker inspect \
    --format '{{.State.Status}}' "$container")
  configured_image=$(sudo --non-interactive docker inspect \
    --format '{{.Config.Image}}' "$container")
  test "$container_status" = running
  test "$configured_image" = "$reference"
  container_image=$(sudo --non-interactive docker inspect --format '{{.Image}}' "$container")
  local_image=$(sudo --non-interactive docker image inspect --format '{{.Id}}' "$reference")
  test "$container_image" = "$local_image"
  if test "$component" != prometheus; then
    revision=$(sudo --non-interactive docker image inspect \
      --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' \
      "$reference")
    source_tree=$(sudo --non-interactive docker image inspect \
      --format '{{ index .Config.Labels "org.colortrace.source-tree" }}' \
      "$reference")
    test "$revision" = "$expected_commit"
    test "$source_tree" = "$expected_tree"
  fi
done
sudo --non-interactive docker exec --user 65532:65532 colortrace-runtime \
  /opt/colortrace/bin/python -c 'import hashlib, pathlib, sys
path = pathlib.Path("/opt/colortrace/fixture/runtime/manifests/fixture-runtime-manifest.json")
actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
raise SystemExit(0 if actual == sys.argv[1] else 1)' "$expected_fixture"
accept_rule='-A DOCKER-USER -s 172.30.0.10/32 -d 169.254.169.254/32 -j ACCEPT'
drop_rule='-A DOCKER-USER -d 169.254.169.254/32 -j DROP'
rules=$(sudo --non-interactive iptables --wait 5 --list-rules DOCKER-USER)
test "$(printf '%s\n' "$rules" | grep -Fxc -- "$accept_rule")" -eq 1
test "$(printf '%s\n' "$rules" | grep -Fxc -- "$drop_rule")" -eq 1
accept_line=$(printf '%s\n' "$rules" | grep -Fxn -- "$accept_rule" | cut -d: -f1)
drop_line=$(printf '%s\n' "$rules" | grep -Fxn -- "$drop_rule" | cut -d: -f1)
test -n "$accept_line" && test -n "$drop_line" && test "$((accept_line + 1))" -eq "$drop_line"
unexpected_pre_drop=$(printf '%s\n' "$rules" \
  | head -n "$((drop_line - 1))" \
  | grep -Fvx -- '-N DOCKER-USER' \
  | grep -Fvx -- "$accept_rule" || true)
test -z "$unexpected_pre_drop"
sudo --non-interactive docker inspect \
  colortrace-caddy \
  colortrace-grafana \
  colortrace-loki \
  colortrace-prometheus \
  colortrace-runtime \
  colortrace-tempo \
  colortrace-web \
  | sudo --non-interactive docker exec --interactive --user 65532:65532 \
    colortrace-runtime /opt/colortrace/bin/python -c 'import json, sys
containers = json.load(sys.stdin)
expected = {
    "colortrace-caddy": {"colortrace-edge", "colortrace-internal"},
    "colortrace-grafana": {"colortrace-internal"},
    "colortrace-loki": {"colortrace-internal"},
    "colortrace-prometheus": {"colortrace-internal"},
    "colortrace-runtime": {"colortrace-internal"},
    "colortrace-tempo": {"colortrace-internal"},
    "colortrace-web": {"colortrace-edge"},
}
assert len(containers) == len(expected)
for container in containers:
    name = container["Name"].removeprefix("/")
    assert name in expected
    assert container["HostConfig"]["NetworkMode"] != "host"
    networks = container["NetworkSettings"]["Networks"]
    assert set(networks) == expected[name]
    addresses = {details["IPAddress"] for details in networks.values()}
    if name == "colortrace-runtime":
        assert addresses == {"172.30.0.10"}
    else:
        assert "172.30.0.10" not in addresses
'
sudo --non-interactive docker exec --user 65532:65532 colortrace-runtime \
  /opt/colortrace/bin/python -c 'import urllib.request
request = urllib.request.Request(
    "http://metadata.google.internal/computeMetadata/v1/instance/id",
    headers={"Metadata-Flavor": "Google"},
)
with urllib.request.urlopen(request, timeout=4) as response:
    assert response.headers.get("Metadata-Flavor") == "Google"
    assert response.read()'
if sudo --non-interactive timeout 6 docker exec colortrace-web node -e '
const controller = new AbortController();
setTimeout(() => controller.abort(), 4000);
fetch("http://metadata.google.internal/computeMetadata/v1/instance/id", {
  headers: {"Metadata-Flavor": "Google"}, signal: controller.signal
}).then(() => process.exit(0)).catch(() => process.exit(1));'; then
  echo 'non-runtime container reached metadata' >&2
  exit 1
fi
printf '%s\n' colortrace-live-binding-ok
"""
    )
    output = arguments.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(script, encoding="utf-8")
    output.chmod(0o700)


def mcp_script(arguments: argparse.Namespace) -> None:
    summary = _load(arguments.summary.resolve(strict=True))
    expected_inventory = _require_digest(summary.get("mcp_inventory_sha256"), "mcp-summary-invalid")
    expected_identity = json.dumps(MCP_CATALOG_IDENTITY, sort_keys=True)
    expected_tools = json.dumps(sorted(MCP_SELECTED_TOOLS))
    validation = """import json, sys
value = json.load(open(sys.argv[1], encoding=\"utf-8\"))
expected_identity = json.loads(sys.argv[2])
expected_tools = set(json.loads(sys.argv[3]))
assert set(value) == set(expected_identity) | {\"selected_tools\", \"inventory_version\"}
assert all(value[key] == expected for key, expected in expected_identity.items())
assert isinstance(value[\"selected_tools\"], dict)
assert set(value[\"selected_tools\"]) == expected_tools
assert value[\"inventory_version\"] == sys.argv[4]
"""
    script = f"""set -Eeuo pipefail
probe=/tmp/colortrace-hosted-mcp-inventory.json
cleanup() {{
  sudo --non-interactive docker exec colortrace-runtime \\
    rm -f \"$probe\" >/dev/null 2>&1 || true
}}
trap cleanup EXIT
cleanup
sudo --non-interactive docker exec --user 65532:65532 colortrace-runtime \\
  /opt/colortrace/bin/python -m colortrace_grafana_mcp.cli catalog \\
  --grafana-url https://grafana.internal:8443 \\
  --token-file /run/colortrace-private/grafana-viewer-token \\
  --tls-ca-file /etc/colortrace/caddy-root.crt \\
  --binary /usr/local/bin/mcp-grafana \\
  --lock /opt/colortrace-config/grafana-mcp/mcp-grafana.lock.json \\
  --catalog /opt/colortrace-config/grafana-mcp/query-catalog.json \\
  --output \"$probe\"
sudo --non-interactive docker exec --user 65532:65532 colortrace-runtime \\
  /opt/colortrace/bin/python -c {shlex.quote(validation)} \\
  \"$probe\" \\
  {shlex.quote(expected_identity)} \\
  {shlex.quote(expected_tools)} \\
  {shlex.quote(expected_inventory)}
"""
    output = arguments.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(script, encoding="utf-8")
    output.chmod(0o700)


def write_report(arguments: argparse.Namespace) -> None:
    summary = _load(arguments.summary.resolve(strict=True))
    binding = _load(arguments.artifact.resolve(strict=True))
    _validate_artifact(binding)
    checks = {
        "tls": "pass",
        "access_gate": "pass",
        "malformed_request": "pass",
        "wrong_origin": "pass",
        "general_api_private": "pass",
        "non_https_public_tcp": "pass",
        "fresh_v2_workflow_under_120_seconds": "pass",
        "vertex_prediction": "pass",
        "exact_success_contract": "pass",
        "canonical_receipt_and_proof_hashes": "pass",
        "instance_metadata_artifact_binding": "pass",
        "all_container_image_bindings": "pass",
        "source_and_fixture_bindings": "pass",
        "metadata_runtime_allow_nonruntime_deny": "pass",
        "runtime_health_after_restart": "pass",
        "grafana_mcp_inventory_after_restart": "pass",
        "receipt_persistence_after_restart": "pass",
        "scenario_reset_for_repeatability": "pass",
    }
    report = {
        "schema": "colortrace-single-host-verification/v2",
        "checked_at": arguments.checked_at,
        "public_url": arguments.public_url,
        "instance": {
            "project": arguments.project,
            "zone": arguments.zone,
            "name": arguments.instance,
        },
        "staging_generation": arguments.generation,
        "deployment_artifact_binding_sha256": _document_sha256(binding),
        "build_manifest_sha256": binding["build_manifest_sha256"],
        "scan_binding_sha256": binding["scan_binding_sha256"],
        "source_commit": binding["source"]["commit"],
        "source_tree": binding["source"]["tree"],
        "workflow": summary,
        "checks": checks,
    }
    _atomic_json(arguments.output.resolve(), report)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    start = commands.add_parser("new-start")
    start.add_argument("output", type=Path)
    start.set_defaults(handler=new_start)
    approval = commands.add_parser("prepare-approval")
    approval.add_argument("run", type=Path)
    approval.add_argument("output", type=Path)
    approval.set_defaults(handler=prepare_approval)
    closure = commands.add_parser("prepare-closure")
    closure.add_argument("run", type=Path)
    closure.add_argument("output", type=Path)
    closure.set_defaults(handler=prepare_closure)
    conflict = commands.add_parser("conflict-run-id")
    conflict.add_argument("error", type=Path)
    conflict.set_defaults(handler=conflict_run_id)
    reset = commands.add_parser("prepare-reset")
    reset.add_argument("run", type=Path)
    reset.add_argument("output", type=Path)
    reset.set_defaults(handler=prepare_reset)
    reset_result = commands.add_parser("verify-reset")
    reset_result.add_argument("reset", type=Path)
    reset_result.add_argument("run", type=Path)
    reset_result.set_defaults(handler=verify_reset)
    metadata = commands.add_parser("verify-instance-metadata")
    metadata.add_argument("instance", type=Path)
    metadata.add_argument("artifact", type=Path)
    metadata.add_argument("generation")
    metadata.set_defaults(handler=verify_instance_metadata)
    verify = commands.add_parser("verify-contract")
    verify.add_argument("run", type=Path)
    verify.add_argument("receipt", type=Path)
    verify.add_argument("artifact", type=Path)
    verify.add_argument("public_url")
    verify.add_argument("generation")
    verify.add_argument("elapsed_ms")
    verify.add_argument("visuals", type=Path)
    verify.add_argument("output", type=Path)
    verify.set_defaults(handler=verify_contract)
    remote = commands.add_parser("remote-script")
    remote.add_argument("artifact", type=Path)
    remote.add_argument("generation")
    remote.add_argument("output", type=Path)
    remote.set_defaults(handler=remote_script)
    mcp = commands.add_parser("mcp-script")
    mcp.add_argument("summary", type=Path)
    mcp.add_argument("output", type=Path)
    mcp.set_defaults(handler=mcp_script)
    report = commands.add_parser("write-report")
    report.add_argument("summary", type=Path)
    report.add_argument("artifact", type=Path)
    report.add_argument("checked_at")
    report.add_argument("public_url")
    report.add_argument("project")
    report.add_argument("zone")
    report.add_argument("instance")
    report.add_argument("generation")
    report.add_argument("output", type=Path)
    report.set_defaults(handler=write_report)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        arguments.handler(arguments)
    except VerificationError as error:
        print(f"demo-verification: {error}", file=os.sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
