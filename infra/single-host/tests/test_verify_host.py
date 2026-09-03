from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "infra/single-host/scripts/verify-host.sh"
CONTRACT_HELPER = ROOT / "infra/single-host/scripts/demo-verification.py"
FAKE_JQ = Path(__file__).with_name("fake_jq.py")
CHECK_NAMES = [
    "active-publication",
    "approved-resource-state",
    "declared-reference-recovery",
    "exact-typed-lineage",
    "approved-recovery-scope",
    "safe-complement-preservation",
    "post-action-telemetry-correlation",
]
APT_AUTOMATIC_UNITS = (
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "apt-daily.service",
    "apt-daily-upgrade.service",
)
VISUAL_BYTES = {
    kind: b"\x89PNG\r\n\x1a\ncolortrace-" + kind.encode("ascii")
    for kind in ("diff", "expected", "observed", "recovered")
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical(value)).hexdigest()}"


def _raw_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _file_digest(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _json_digest(path: Path) -> str:
    return _digest(json.loads(path.read_text(encoding="utf-8")))


def _adaptive_arguments(
    query_key: str,
    *,
    correlation: dict[str, str],
    window: dict[str, str],
) -> dict[str, Any]:
    if query_key == "alert.rule":
        return {
            "operation": "get",
            "rule_uid": "ct-declared-reference-divergence-v1",
            "limit_alerts": 100,
        }
    if query_key in {"metric.correlated-observations", "metric.worker-cohort"}:
        fields = (
            ("fixture_id", "run_id", "worker_id")
            if query_key == "metric.worker-cohort"
            else (
                "fixture_id",
                "run_id",
                "job_id",
                "worker_id",
                "artifact_id",
                "trace_id",
                "config_sha256",
                "transform_id",
            )
        )
        selector = ",".join(f'{name}="{correlation[name]}"' for name in fields)
        return {
            "datasourceUid": "prometheus",
            "expr": f"colortrace_declared_reference_observations_total{{{selector}}}",
            "queryType": "instant",
            "endTime": window["end"],
        }
    if query_key in {"log.correlated-events", "log.config-cohort"}:
        fields = (
            ("fixture_id", "run_id", "config_sha256")
            if query_key == "log.config-cohort"
            else ("fixture_id", "run_id", "job_id")
        )
        filters = " ".join(f'| {name}="{correlation[name]}"' for name in fields)
        return {
            "datasourceUid": "loki",
            "logql": f'{{service_name="colortrace-simulator"}} {filters}',
            "queryType": "range",
            "startRfc3339": window["start"],
            "endRfc3339": window["end"],
            "direction": "forward",
            "limit": 200,
        }
    if query_key == "trace.by-id":
        return {"trace_id": correlation["trace_id"], "datasourceUid": "tempo"}
    raise ValueError("unsupported adaptive query")


def _rebind_v4_evidence(investigation: dict[str, Any]) -> None:
    evidence = investigation["evidence"]
    old_ids = [item["evidence_id"] for item in evidence]
    replacements: dict[str, str] = {}
    predecessor: str | None = None
    for item in evidence:
        content = {"query_key": item["query_key"], "outcome": "collected"}
        item["content_sha256"] = _digest(content)
        item["display_excerpt"] = _canonical(content).decode("utf-8")
        item["predecessor_event_sha256"] = predecessor
        envelope_body = {
            "schema": item["envelope_schema"],
            "incident_id": item["incident_id"],
            "request_id": item["request_id"],
            "source": item["source"],
            "observation": item["observation"],
            "timing": {**item["timing"], "freshness": "unresolved"},
            "content_sha256": item["content_sha256"],
            "content": content,
            "display_excerpt": item["display_excerpt"],
            "correlation_keys": item["correlation_keys"],
            "collection": item["collection"],
            "trust": item["trust"],
            "producer_version": item["producer_version"],
            "predecessor_event_sha256": predecessor,
        }
        event_sha256 = _digest(envelope_body)
        replacements[item["evidence_id"]] = event_sha256
        item["evidence_id"] = event_sha256
        item["event_sha256"] = event_sha256
        predecessor = event_sha256

    def replace_ids(values: list[str]) -> list[str]:
        return [replacements.get(value, value) for value in values]

    investigation["packet_evidence_ids"] = sorted(replace_ids(investigation["packet_evidence_ids"]))
    for invocation in investigation["model_invocations"]:
        invocation["input_evidence_ids"] = replace_ids(invocation["input_evidence_ids"])
        invocation["normalized_input_sha256"] = _digest(
            {
                "turn_kind": invocation["turn_kind"],
                "input_evidence_ids": invocation["input_evidence_ids"],
            }
        )
        body = {
            key: value
            for key, value in invocation.items()
            if key not in {"invocation_id", "derivation_sha256"}
        }
        invocation["derivation_sha256"] = _digest(body)
        invocation["invocation_id"] = "model-invocation:" + invocation[
            "derivation_sha256"
        ].removeprefix("sha256:")
    selection = next(
        item
        for item in investigation["model_invocations"]
        if item["turn_kind"] == "evidence-selection" and item["result_class"] == "accepted"
    )
    for trace, item in zip(investigation["adaptive_trace"], evidence, strict=True):
        trace["evidence_id"] = item["evidence_id"]
        if trace["selected_by"] == "model":
            trace["selection_invocation_id"] = selection["invocation_id"]
            trace["selection_output_sha256"] = selection["output_sha256"]
    for claim in investigation["claims"]:
        claim["evidence_ids"] = replace_ids(claim["evidence_ids"])
    investigation["model_advisory"]["evidence_ids"] = replace_ids(
        investigation["model_advisory"]["evidence_ids"]
    )
    for hypothesis in investigation["hypotheses"]:
        hypothesis["evidence_ids"] = replace_ids(hypothesis["evidence_ids"])
    packet_body = {
        "schema": investigation["packet_schema"],
        "incident_id": investigation["incident_id"],
        "evidence_ids": investigation["packet_evidence_ids"],
        "adaptive_trace": investigation["adaptive_trace"],
        "hypotheses": investigation["hypotheses"],
        "stop_reason": investigation["stop_reason"],
    }
    investigation["packet_sha256"] = _digest(packet_body)
    investigation["packet_id"] = "response-packet:" + investigation["packet_sha256"].removeprefix(
        "sha256:"
    )
    if old_ids == [item["evidence_id"] for item in evidence]:
        raise AssertionError("adaptive evidence identities were not refreshed")


def _write_visuals(path: Path) -> None:
    path.mkdir()
    for kind, contents in VISUAL_BYTES.items():
        (path / f"{kind}.png").write_bytes(contents)


def _v2_investigation(investigation: dict[str, Any], approval: dict[str, Any]) -> None:
    resource_sha256 = "sha256:" + "4" * 64
    nominal_sha256 = "sha256:" + "5" * 64
    targets = [
        {
            "schema": "simulator-target/v1",
            "namespace": "colortrace-simulator",
            "kind": "color-resource",
            "id": resource_sha256,
        },
        *[
            {
                "schema": "simulator-target/v1",
                "namespace": "colortrace-simulator",
                "kind": "frame",
                "id": f"frame-{index}",
            }
            for index in range(1, 4)
        ],
        {
            "schema": "simulator-target/v1",
            "namespace": "colortrace-simulator",
            "kind": "derivative",
            "id": "derivative-1",
        },
    ]
    exclusions = [
        {
            "schema": "simulator-target/v1",
            "namespace": "colortrace-simulator",
            "kind": "frame",
            "id": f"protected-frame-{index}",
        }
        for index in range(1, 4)
    ]
    command_summaries: list[dict[str, Any]] = [
        {
            "schema": "simulator-quarantine-command/v1",
            "command_id": "command-quarantine",
            "namespace": "colortrace-simulator",
            "target": targets[0],
            "expected_resource_sha256": resource_sha256,
            "mode": "quarantine-and-install-approved-replacement",
        }
    ]
    for index, target in enumerate(targets[1:], start=1):
        command = {
            "schema": "simulator-targeted-rerender-command/v1",
            "command_id": f"command-rerender-{index}",
            "namespace": "colortrace-simulator",
            "target": target,
            "job_id": f"job-{index}",
            "transform_id": "look/main/v1",
            "source_id": f"source-{index}",
            "source_manifest_sha256": f"sha256:{index:064x}",
            "source_png_sha256": f"sha256:{index + 4:064x}",
            "expected_config_sha256": nominal_sha256,
            "lineage_parent_artifact_id": f"artifact-{index}",
        }
        if target["kind"] == "frame":
            command.update(
                {
                    "expected_output_sha256": f"sha256:{index + 8:064x}",
                    "expected_display_sha256": f"sha256:{index + 12:064x}",
                }
            )
        else:
            command.update(
                {
                    "expected_derivative_sha256": f"sha256:{index + 8:064x}",
                    "expected_derivative_display_sha256": f"sha256:{index + 12:064x}",
                }
            )
        command_summaries.append(command)
    bindings = {
        "schema": "simulator-action-envelope/v1",
        "fixture_id": "ct-shadowed-lut-v1",
        "fixture_manifest_sha256": "sha256:" + "a" * 64,
        "fixture_generation": 1,
        "source_batch_id": "source-batch-1",
        "source_batch_sha256": "sha256:" + "b" * 64,
        "runtime_manifest_sha256": "sha256:" + "c" * 64,
        "runtime_generation": 1,
        "expected_publication_pointer_sha256": "sha256:" + "d" * 64,
        "expected_publication_generation": 1,
        "expected_resource_sha256": resource_sha256,
        "replacement_resource_logical_path": "luts/show_look.cube",
        "replacement_resource_sha256": "sha256:" + "8" * 64,
        "declared_resource_manifest_sha256": "sha256:" + "e" * 64,
        "ocio_version": "2.5.2",
        "preservation_manifest_sha256": "sha256:" + "f" * 64,
        "safe_complement_sha256": "sha256:" + "9" * 64,
        "lineage_manifest_sha256": "sha256:" + "0" * 64,
        "lineage_generation": 1,
    }
    approval["target_sha256"] = _digest(targets)
    investigation["schema"] = "colortrace-demo-investigation-proof/v2"
    for validator in investigation["validators"]:
        validator["result_id"] = "validation-result:" + validator["derivation_sha256"].removeprefix(
            "sha256:"
        )
    investigation["adjudication"] = {
        "model_role": "evidence-selection-and-advisory-drafting",
        "model_authority": "advisory-only",
        "validator_role": "deterministic-claim-adjudication",
        "decision_mode": "deterministic-validation",
    }
    investigation["comparison"] = {
        "renders": [
            {
                "job_id": f"job-{worker.lower()}-02",
                "worker_id": worker,
                "status": "succeeded",
                "nominal_config_sha256": nominal_sha256,
                "resolved_lut_sha256": f"sha256:{digit * 64}",
            }
            for worker, digit in (("A", "6"), ("B", "7"))
        ],
        "nominal_config_match": True,
        "resolved_lut_match": False,
    }
    evidence_ids = [item["evidence_id"] for item in investigation["evidence"]]
    investigation["claims"] = [
        {
            "claim_id": "claim-confirmed",
            "claim_type": "resource-divergence",
            "subject": {"kind": "resource", "value": "show-look"},
            "state": "confirmed",
            "reason_codes": ["resolved-lut-differs"],
            "evidence_ids": evidence_ids[:2],
            "source_validator_result_id": investigation["validators"][0]["result_id"],
        },
        {
            "claim_id": "claim-rejected",
            "claim_type": "nominal-config-divergence",
            "subject": {"kind": "config", "value": "show-config"},
            "state": "rejected",
            "reason_codes": ["nominal-config-matches"],
            "evidence_ids": evidence_ids[2:],
            "source_validator_result_id": investigation["validators"][0]["result_id"],
        },
    ]
    investigation["evidence"] = [
        {
            **item,
            "display_excerpt": f"Bounded evidence for {item['query_key']}.",
            "display_excerpt_truncated": False,
        }
        for item in investigation["evidence"]
    ]
    investigation["plan"] = {
        "status": "pending",
        "version": approval["plan_version"],
        "plan_sha256": approval["plan_sha256"],
        "target_sha256": approval["target_sha256"],
        "exclusions_sha256": _digest(exclusions),
        "commands_sha256": _digest(
            [{**command, "action_envelope": bindings} for command in command_summaries]
        ),
        "targets": targets,
        "protected_exclusions": exclusions,
        "shared_action_bindings": bindings,
        "command_summaries": command_summaries,
    }


def _v3_investigation(investigation: dict[str, Any], approval: dict[str, Any]) -> None:
    _v2_investigation(investigation, approval)
    evidence_ids = [item["evidence_id"] for item in investigation["evidence"]]
    internal_evidence_id = "sha256:" + "f" * 64
    validator_result_id = investigation["validators"][0]["result_id"]
    investigation["schema"] = "colortrace-demo-investigation-proof/v3"
    investigation["claims"] = [
        {
            "claim_id": "claim:" + digit * 64,
            "claim_type": claim_type,
            "subject": subject,
            "state": state,
            "reason_codes": [reason_code],
            "evidence_ids": cited_evidence_ids,
            "source_validator_result_id": validator_result_id,
        }
        for digit, claim_type, subject, state, reason_code, cited_evidence_ids in (
            (
                "1",
                "causal-resource",
                {"kind": "resource-sha256", "value": "7" * 64},
                "confirmed",
                "causal-resource-confirmed",
                [internal_evidence_id],
            ),
            (
                "2",
                "nominal-config",
                {"kind": "config-sha256", "value": "5" * 64},
                "rejected",
                "nominal-config-authoritatively-rejected",
                evidence_ids[:2],
            ),
            (
                "3",
                "worker-alone",
                {"kind": "worker-id", "value": "B"},
                "rejected",
                "worker-alone-authoritatively-rejected",
                evidence_ids[1:3],
            ),
            (
                "4",
                "distractor",
                {"kind": "event-id", "value": "distractor-01"},
                "rejected",
                "distractor-authoritatively-rejected",
                evidence_ids[2:],
            ),
        )
    ]
    investigation["model_invocations"] = [
        {
            **item,
            "attempt": 1,
            "location": "global",
            "framework_version": "2.6.3",
            "client_version": "2.17.0",
            "prompt_version": f"{item['turn_kind']}/v1",
            "policy_version": "bounded-investigation/v1",
            "normalized_input_sha256": "sha256:" + digit * 64,
            "input_evidence_ids": (
                evidence_ids[:1] if item["turn_kind"] == "evidence-selection" else evidence_ids
            ),
            "latency_ms": 0,
            "usage": {
                "input_tokens": 50,
                "output_tokens": 10,
                "model_calls": 1,
                "unobserved_model_calls": 0,
            },
            "error_code": None,
            "derivation_sha256": "sha256:" + digit * 64,
        }
        for item, digit in zip(investigation["model_invocations"], ("8", "9"), strict=True)
    ]
    investigation["evidence"] = [
        {
            **item,
            "source": {
                "kind": "grafana-mcp",
                "server": "mcp-grafana",
                "server_version": "1.1.0",
                "server_commit": "007e8d82154899a28e19e8dfe9c2bb4452c5211a",
                "binary_sha256": (
                    "a3dacdcace8d8082dd7cb245e41be54e8da4a9375969cb39c85c420a30ea0809"
                ),
                "mcp_sdk_version": "1.29.0",
                "mcp_protocol_version": "2025-06-18",
                "tool": item["tool"],
                "tool_input_schema_sha256": f"{index:064x}",
                "tool_annotations_sha256": f"{index + 4:064x}",
                "inventory_version": item["inventory_sha256"],
            },
            "timing": {
                "source_time": None,
                "event_time": None,
                "retrieved_at": f"2026-08-23T12:00:0{index}.000Z",
            },
        }
        for index, item in enumerate(investigation["evidence"], start=1)
    ]
    drafting = next(
        item
        for item in investigation["model_invocations"]
        if item["turn_kind"] == "response-drafting"
    )
    investigation["model_advisory"] = {
        "trust": "untrusted-model-output",
        "summary": "The deterministic evidence identifies a shadowed LUT resource.",
        "evidence_ids": evidence_ids,
        "output_sha256": drafting["output_sha256"],
    }
    investigation["finalized_at"] = "2026-08-23T12:00:05.000Z"


def _v4_investigation(
    investigation: dict[str, Any],
    approval: dict[str, Any],
    *,
    incident_id: str,
) -> None:
    _v3_investigation(investigation, approval)
    evidence = investigation["evidence"][:3]
    evidence[-1]["query_key"] = "metric.worker-cohort"
    evidence_ids = [item["evidence_id"] for item in evidence]
    internal_evidence_id = "sha256:" + "f" * 64
    policy_sha256 = _json_digest(ROOT / "config/investigation/investigation-policy.json")
    catalog_sha256 = _json_digest(ROOT / "config/grafana-mcp/query-catalog.json")
    window = {
        "start": "2026-08-23T11:50:00.000Z",
        "end": "2026-08-23T12:00:00.000Z",
        "frozen_at": "2026-08-23T12:00:00.000Z",
    }
    request_id = "evidence-" + hashlib.sha256(incident_id.encode("utf-8")).hexdigest()[:24]
    for invocation in investigation["model_invocations"]:
        invocation["prompt_version"] = f"{invocation['turn_kind']}/v2"
        invocation["policy_version"] = "bounded-adaptive-investigation/v1"
        invocation["policy_sha256"] = policy_sha256
        if invocation["turn_kind"] == "response-drafting":
            invocation["input_evidence_ids"] = evidence_ids
    for index, item in enumerate(evidence):
        query_key = item["query_key"]
        correlation = (
            {
                "fixture_id": "fixture-1",
                "run_id": "run-1",
                "worker_id": "B",
            }
            if query_key == "metric.worker-cohort"
            else {
                "fixture_id": "fixture-1",
                "run_id": "run-1",
                "job_id": "job-b-02",
                "worker_id": "B",
                "artifact_id": "output-job-b-02",
                "trace_id": "1" * 32,
                "config_sha256": "5" * 64,
                "transform_id": "look/main/v1",
            }
        )
        item.update(
            {
                "envelope_schema": "evidence-envelope/v2",
                "incident_id": incident_id,
                "request_id": request_id,
                "observation": {
                    "kind": "grafana-mcp-query",
                    "query_key": query_key,
                    "catalog_version": "grafana-evidence-query-catalog/v2",
                    "catalog_sha256": catalog_sha256,
                    "normalized_arguments": _adaptive_arguments(
                        query_key,
                        correlation=correlation,
                        window=window,
                    ),
                    "model_visible_arguments": [],
                    "fixed_time_range": {
                        "start": window["start"],
                        "end": window["end"],
                    },
                },
                "correlation_keys": correlation,
                "collection": {
                    "outcome": "collected",
                    "attempts": 1,
                    "retries": 0,
                    "error": None,
                },
                "trust": "untrusted-provider-data",
                "producer_version": "grafana-mcp-evidence-adapter/v1",
                "predecessor_event_sha256": (
                    None if index == 0 else evidence[index - 1]["evidence_id"]
                ),
                "event_sha256": item["evidence_id"],
            }
        )
    investigation["schema"] = "colortrace-demo-investigation-proof/v4"
    investigation["packet_schema"] = "response-packet/v2"
    investigation["packet_version"] = 2
    investigation["packet_evidence_ids"] = sorted([*evidence_ids, internal_evidence_id])
    investigation["incident_id"] = incident_id
    investigation["fixed_window"] = window
    investigation["policy_binding"] = {
        "version": "bounded-adaptive-investigation/v1",
        "sha256": policy_sha256,
    }
    selection = next(
        item
        for item in investigation["model_invocations"]
        if item["turn_kind"] == "evidence-selection"
    )
    validator_result_id = investigation["validators"][0]["result_id"]
    investigation["adaptive_trace"] = [
        {
            "sequence": index,
            "selected_by": "policy" if index == 0 else "model",
            "query_key": item["query_key"],
            "selection_request_sha256": _digest({"query_key": item["query_key"]}),
            "selection_invocation_id": None if index == 0 else selection["invocation_id"],
            "selection_output_sha256": None if index == 0 else selection["output_sha256"],
            "evidence_id": item["evidence_id"],
            "disposition": "resolved" if index == len(evidence) - 1 else "continue",
            "reason_code": (
                "baseline-valid"
                if index == 0
                else (
                    "sufficient-evidence"
                    if index == len(evidence) - 1
                    else "additional-evidence-required"
                )
            ),
            "validator_result_id": validator_result_id if index == len(evidence) - 1 else None,
        }
        for index, item in enumerate(evidence)
    ]
    investigation["hypotheses"] = [
        {
            "ordinal": 1,
            "hypothesis_key": "color-resource-drift",
            "evidence_ids": evidence_ids[:2],
        },
        {
            "ordinal": 2,
            "hypothesis_key": "worker-only-failure",
            "evidence_ids": evidence_ids[2:],
        },
    ]
    investigation["stop_reason"] = "sufficient-evidence"
    investigation["evidence"] = evidence
    investigation["claims"][-1]["evidence_ids"] = evidence_ids[-1:]
    investigation["model_advisory"]["evidence_ids"] = evidence_ids
    investigation["budget_use"]["mcp_attempts"] = len(evidence)
    _rebind_v4_evidence(investigation)


def _timeline(phase: str) -> list[dict[str, Any]]:
    events = [
        ("run-created", "preparing"),
        ("investigation-completed", "awaiting-approval"),
        ("approval-submitted", "executing"),
        ("recovery-verified", "awaiting-closure"),
        ("closure-submitted", "closing"),
        ("recovery-closed", "closed"),
    ]
    selected = events[
        : next(index for index, item in enumerate(events, start=1) if item[1] == phase)
    ]
    return [
        {
            "run_version": index,
            "kind": kind,
            "phase": event_phase,
            "recorded_at": (
                "2026-08-23T12:00:30.000Z"
                if phase == "closed" and event_phase == "closed"
                else f"2026-08-23T12:00:0{index - 1}.000Z"
            ),
        }
        for index, (kind, event_phase) in enumerate(selected, start=1)
    ]


def _artifact() -> dict[str, Any]:
    registry = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
    components = ("runtime", "web", "caddy", "grafana", "loki", "prometheus", "tempo")
    images = {
        component: f"{registry}/{component}@sha256:{str(index) * 64}"
        for index, component in enumerate(components, 1)
    }
    fixture = json.loads(
        (ROOT / "packages/fixture-generator/fixtures/canonical-digests.json").read_text(
            encoding="utf-8"
        )
    )
    return {
        "schema": "colortrace-single-host-admission/v1",
        "build_manifest_sha256": "sha256:" + "7" * 64,
        "scan_binding_sha256": "sha256:" + "8" * 64,
        "observability_lock_sha256": _file_digest(ROOT / "config/observability/images.lock.json"),
        "build": {
            "id": "build-123",
            "project": "colortrace-test-project",
            "region": "us-central1",
            "service_account": (
                "projects/colortrace-test-project/serviceAccounts/"
                "ct-singlehost-builder@colortrace-test-project.iam.gserviceaccount.com"
            ),
            "registry": registry,
            "config_sha256": _file_digest(ROOT / "infra/single-host/cloudbuild.images.yaml"),
            "create_time": "2026-08-23T12:00:00Z",
            "finish_time": "2026-08-23T12:10:00Z",
        },
        "source": {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "date_epoch": 1787486400,
        },
        "fixture_manifest_sha256": (
            "sha256:" + fixture["files"]["runtime/manifests/fixture-runtime-manifest.json"]
        ),
        "images": images,
        "scanner": {
            "image": (
                "aquasec/trivy@sha256:"
                "bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
            ),
            "version_sha256": "sha256:" + "9" * 64,
            "databases": {
                "current": {
                    "content_sha256": "sha256:" + "a" * 64,
                    "metadata_sha256": "sha256:" + "b" * 64,
                    "updated_at": "2026-08-23T12:00:00Z",
                },
                "frozen": {
                    "image": (
                        "ghcr.io/aquasecurity/trivy-db@sha256:"
                        "67136d9c032b639278e256601e29b8af0ff4ed28e66d859e4cac692f7c1deef6"
                    ),
                    "content_sha256": (
                        "sha256:eb94cd71f35e20ce5b572803f65009bb61a13a75f8d7c4f1f111ec732c98d314"
                    ),
                    "metadata_sha256": "sha256:" + "c" * 64,
                    "updated_at": "2026-08-22T12:57:22.518776499Z",
                },
            },
            "report_set_sha256": "sha256:" + "d" * 64,
        },
    }


def _workflow(
    artifact: dict[str, Any],
    *,
    run_digit: str = "a",
    proof_version: int = 4,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    run_id = "demo-run-" + run_digit * 32
    visual_comparison = {
        kind: {
            "href": f"/v1/demo/runs/{run_id}/visuals/{kind}",
            "sha256": _raw_digest(contents),
            "media_type": "image/png",
            "label": "illustrative-authored-fixture",
        }
        for kind, contents in VISUAL_BYTES.items()
    }
    approval = {
        "phrase": "APPROVE_COLORTRACE_SIMULATOR_ACTION",
        "incident_version": 7,
        "plan_version": 3,
        "plan_sha256": "sha256:" + "1" * 64,
        "target_sha256": "sha256:" + "2" * 64,
    }
    recovery = {
        "outcome_id": "simulator-action-outcome:" + "3" * 64,
        "outcome_sha256": "sha256:" + "3" * 64,
        "workflow_id": "recovery-workflow:" + "4" * 64,
        "workflow_version": 2,
        "packet_id": "recovery-packet:" + "5" * 64,
        "packet_sha256": "sha256:" + "5" * 64,
        "closure_id": "recovery-closure:" + "6" * 64,
        "closure_sha256": "sha256:" + "6" * 64,
    }
    investigation = {
        "schema": "colortrace-demo-investigation-proof/v1",
        "packet_id": "response-packet:" + "6" * 64,
        "packet_sha256": "sha256:" + "6" * 64,
        "status": "resolved",
        "model_invocations": [
            {
                "invocation_id": "model-invocation:" + digit * 64,
                "turn_kind": turn,
                "model": "gemini-3.5-flash",
                "framework": "google-adk",
                "result_class": "accepted",
                "inventory_sha256": "sha256:" + "7" * 64,
                "output_sha256": "sha256:" + digit * 64,
                "trace_id": digit * 32,
            }
            for digit, turn in (
                ("8", "evidence-selection"),
                ("9", "response-drafting"),
            )
        ],
        "evidence": [
            {
                "evidence_id": "sha256:" + character * 64,
                "query_key": query_key,
                "tool": tool,
                "inventory_sha256": "sha256:" + "7" * 64,
                "content_sha256": "sha256:" + character * 64,
                "freshness": "current",
            }
            for character, query_key, tool in (
                ("a", "alert.rule", "alerting_manage_rules"),
                ("b", "log.correlated-events", "query_loki_logs"),
                ("c", "metric.correlated-observations", "query_prometheus"),
                ("d", "trace.by-id", "tempo_get-trace"),
            )
        ],
        "validators": [
            {
                "result_id": "validator-result:" + "e" * 64,
                "validator": "colortrace-validator",
                "validator_version": "1.0.0",
                "status": "resolved",
                "derivation_sha256": "sha256:" + "e" * 64,
            }
        ],
        "scope": {
            "state": "resolved",
            "affected_count": 4,
            "safe_count": 3,
            "unknown_count": 0,
        },
        "budget_use": {
            "elapsed_ms": 1,
            "model_turns": 2,
            "input_tokens": 100,
            "output_tokens": 20,
            "mcp_attempts": 4,
            "validator_calls": 6,
        },
        "plan": {},
    }
    investigation["plan"] = {
        "status": "pending",
        "version": approval["plan_version"],
        "plan_sha256": approval["plan_sha256"],
        "target_sha256": approval["target_sha256"],
    }
    if proof_version == 4:
        _v4_investigation(investigation, approval, incident_id="incident-demo-" + run_digit * 32)
    elif proof_version == 3:
        _v3_investigation(investigation, approval)
    elif proof_version == 2:
        _v2_investigation(investigation, approval)
    elif proof_version != 1:
        raise ValueError("unsupported proof version")
    execution = {
        "schema": "colortrace-demo-execution-proof/v1",
        "action": {
            "action_id": "simulator-action:" + "a" * 64,
            "status": "succeeded",
            "outcome_id": recovery["outcome_id"],
            "outcome_sha256": recovery["outcome_sha256"],
            "publication_generation_before": 1,
            "publication_generation_after": 2,
            "affected_count": 4,
            "safe_count": 3,
            "safe_complement_before_sha256": "sha256:" + "b" * 64,
            "safe_complement_after_sha256": "sha256:" + "b" * 64,
            "safe_complement_proof_sha256": "sha256:" + "c" * 64,
            "publication_receipt_sha256": "sha256:" + "d" * 64,
        },
        "recovery": {
            "status": "recovery_verified",
            "workflow_id": recovery["workflow_id"],
            "workflow_version": recovery["workflow_version"],
            "packet_id": recovery["packet_id"],
            "packet_sha256": recovery["packet_sha256"],
            "evidence_count": 21,
            "evidence_request_sha256": "sha256:" + "e" * 64,
            "checks": [
                {
                    "check": check,
                    "status": "passed",
                    "result_sha256": f"sha256:{index:064x}",
                }
                for index, check in enumerate(CHECK_NAMES, 1)
            ],
        },
    }
    base = {
        "schema": "colortrace-demo-run/v2",
        "run_id": run_id,
        "incident_id": "incident-demo-" + run_digit * 32,
        "scenario_id": "ct-shadowed-lut-v1:canonical",
        "source_commit": artifact["source"]["commit"],
        "build_sha256": "sha256:" + "0" * 64,
        "lease_expires_at": "2026-08-23T12:15:00.000Z",
        "poll": {"href": f"/v1/demo/runs/{run_id}", "after_milliseconds": 1000},
        "approval": approval,
        "visual_comparison": {
            kind: descriptor
            for kind, descriptor in visual_comparison.items()
            if kind != "recovered"
        },
        "terminal_reason": None,
        "receipt_href": None,
        "reset": False,
    }
    started = {
        **base,
        "phase": "awaiting-approval",
        "version": 2,
        "terminal": False,
        "recovery": None,
        "investigation": investigation,
        "approval_nonce": "n" * 32,
        "timeline": _timeline("awaiting-approval"),
    }
    approved = {
        **base,
        "visual_comparison": visual_comparison,
        "phase": "awaiting-closure",
        "version": 4,
        "terminal": False,
        "recovery": {**recovery, "closure_id": None, "closure_sha256": None},
        "investigation": investigation,
        "execution": execution,
        "timeline": _timeline("awaiting-closure"),
    }
    build_binding = {
        "schema": "colortrace-runtime-build-binding/v1",
        "source_commit": artifact["source"]["commit"],
        "source_tree": artifact["source"]["tree"],
    }
    provenance = {
        "schema": "colortrace-demo-build-provenance/v1",
        "source_commit": artifact["source"]["commit"],
        "source_tree": artifact["source"]["tree"],
        "runtime_image": artifact["images"]["runtime"],
        "public_url": "https://203-0-113-42.sslip.io",
        "staging_generation": "stage-0001",
        "fixture_manifest_sha256": artifact["fixture_manifest_sha256"],
        "configuration": {
            "demo_sha256": _file_digest(ROOT / "config/demo/local-demo.json"),
            "build_binding_sha256": _raw_digest(_canonical(build_binding) + b"\n"),
            "investigation_policy_sha256": _json_digest(
                ROOT / "config/investigation/investigation-policy.json"
            ),
            "model_profile_sha256": _json_digest(ROOT / "config/investigation/model-profile.json"),
            "query_catalog_sha256": _json_digest(ROOT / "config/grafana-mcp/query-catalog.json"),
        },
        "model": {
            "provider": "vertex-ai",
            "framework": "google-adk",
            "model": "gemini-3.5-flash",
            "location": "global",
            "versions": {
                "google-adk": "2.6.3",
                "google-genai": "2.17.0",
                "mcp": "1.29.0",
            },
        },
        "mcp": {
            "source_commit": "007e8d82154899a28e19e8dfe9c2bb4452c5211a",
            "source_version": "1.1.0",
            "binary_sha256": (
                "sha256:a3dacdcace8d8082dd7cb245e41be54e8da4a9375969cb39c85c420a30ea0809"
            ),
            "inventory_sha256": "sha256:" + "7" * 64,
            "transport": "stdio",
            "write_tools_enabled": False,
        },
    }
    build_sha256 = _digest(provenance)
    closed = {
        **base,
        "visual_comparison": visual_comparison,
        "build_sha256": build_sha256,
        "phase": "closed",
        "version": 6,
        "lease_expires_at": None,
        "terminal": True,
        "terminal_reason": "recovery-closed",
        "receipt_href": f"/v1/demo/runs/{run_id}/receipt",
        "recovery": recovery,
        "investigation": investigation,
        "execution": execution,
        "timeline": _timeline("closed"),
    }
    body = {
        "schema": "colortrace-demo-receipt/v1",
        "run_id": run_id,
        "incident_id": closed["incident_id"],
        "scenario_id": closed["scenario_id"],
        "source_commit": closed["source_commit"],
        "build_sha256": build_sha256,
        "provenance": provenance,
        "phase": "closed",
        "run_version": 6,
        "created_at": "2026-08-23T12:00:00.000Z",
        "terminal_at": "2026-08-23T12:00:30.000Z",
        "reason_code": "recovery-closed",
        "bindings": {
            "incident_version": approval["incident_version"],
            "plan_version": approval["plan_version"],
            "plan_sha256": approval["plan_sha256"],
            "target_sha256": approval["target_sha256"],
            "outcome_id": recovery["outcome_id"],
            "outcome_sha256": recovery["outcome_sha256"],
            "workflow_id": recovery["workflow_id"],
            "workflow_version": recovery["workflow_version"],
            "packet_id": recovery["packet_id"],
            "packet_sha256": recovery["packet_sha256"],
            "closure_id": recovery["closure_id"],
            "closure_sha256": recovery["closure_sha256"],
        },
        "proofs": [
            {"stage": "execution", "sha256": _digest(execution)},
            {"stage": "investigation", "sha256": _digest(investigation)},
        ],
        "visuals": [
            {"kind": kind, "sha256": visual_comparison[kind]["sha256"]}
            for kind in ("diff", "expected", "observed", "recovered")
        ],
    }
    receipt_sha256 = _digest(body)
    receipt = {
        **body,
        "receipt_id": f"demo-receipt:{receipt_sha256.removeprefix('sha256:')}",
        "receipt_sha256": receipt_sha256,
    }
    reset = {
        "schema": "colortrace-demo-reset/v1",
        "run_id": run_id,
        "phase": "closed",
        "version": 6,
        "reset": True,
        "receipt_href": f"/v1/demo/runs/{run_id}/receipt",
        "restoration": {
            "schema": "simulator-authored-scenario-reset/v1",
            "operation_id": "demo-reset:" + "7" * 64,
            "fixture_id": "ct-shadowed-lut-v1",
            "source_batch_sha256": "sha256:" + "7" * 64,
            "previous_pointer_sha256": "sha256:" + "8" * 64,
            "active_pointer_sha256": "sha256:" + "9" * 64,
            "generation": 1,
        },
    }
    return started, approved, closed, receipt, reset


def _rejected_workflow(
    artifact: dict[str, Any],
    *,
    run_digit: str = "a",
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    started, _approved, closed, approved_receipt, reset = _workflow(
        artifact,
        run_digit=run_digit,
        proof_version=4,
    )
    build_sha256 = closed["build_sha256"]
    started["build_sha256"] = build_sha256
    rejected = {key: value for key, value in started.items() if key != "approval_nonce"}
    rejected.update(
        {
            "phase": "unresolved",
            "version": started["version"] + 1,
            "lease_expires_at": None,
            "terminal": True,
            "terminal_reason": "plan-rejected-insufficient-evidence",
            "receipt_href": f"/v1/demo/runs/{started['run_id']}/receipt",
            "timeline": [
                *started["timeline"],
                {
                    "run_version": 3,
                    "kind": "plan-rejected",
                    "phase": "unresolved",
                    "recorded_at": "2026-08-23T12:00:15.000Z",
                },
            ],
        }
    )
    approval = rejected["approval"]
    body = {
        "schema": "colortrace-demo-receipt/v1",
        "run_id": rejected["run_id"],
        "incident_id": rejected["incident_id"],
        "scenario_id": rejected["scenario_id"],
        "source_commit": rejected["source_commit"],
        "build_sha256": build_sha256,
        "provenance": approved_receipt["provenance"],
        "phase": "unresolved",
        "run_version": rejected["version"],
        "created_at": "2026-08-23T12:00:00.000Z",
        "terminal_at": "2026-08-23T12:00:15.000Z",
        "reason_code": rejected["terminal_reason"],
        "bindings": {
            "incident_version": approval["incident_version"],
            "plan_version": approval["plan_version"],
            "plan_sha256": approval["plan_sha256"],
            "target_sha256": approval["target_sha256"],
            "outcome_id": None,
            "outcome_sha256": None,
            "workflow_id": None,
            "workflow_version": None,
            "packet_id": None,
            "packet_sha256": None,
            "closure_id": None,
            "closure_sha256": None,
        },
        "proofs": [
            {
                "stage": "investigation",
                "sha256": _digest(rejected["investigation"]),
            }
        ],
        "visuals": [
            {
                "kind": kind,
                "sha256": rejected["visual_comparison"][kind]["sha256"],
            }
            for kind in ("diff", "expected", "observed")
        ],
    }
    receipt_sha256 = _digest(body)
    receipt = {
        **body,
        "receipt_id": f"demo-receipt:{receipt_sha256.removeprefix('sha256:')}",
        "receipt_sha256": receipt_sha256,
    }
    reset.update(
        {
            "run_id": rejected["run_id"],
            "phase": "unresolved",
            "version": rejected["version"],
            "receipt_href": rejected["receipt_href"],
        }
    )
    return started, rejected, receipt, reset


def _scenario_preview(started: dict[str, Any], *, build_sha256: str) -> dict[str, Any]:
    return {
        "schema": "colortrace-demo-scenario-preview/v1",
        "scenario_id": started["scenario_id"],
        "source_commit": started["source_commit"],
        "build_sha256": build_sha256,
        "comparison": started["investigation"]["comparison"],
        "visual_comparison": {
            kind: {
                **started["visual_comparison"][kind],
                "href": f"/v1/demo/visuals/{kind}",
            }
            for kind in ("diff", "expected", "observed")
        },
    }


def _preview_verification(preview: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "colortrace-demo-preview-verification/v1",
        "scenario_id": preview["scenario_id"],
        "source_commit": preview["source_commit"],
        "build_sha256": preview["build_sha256"],
        "preview_sha256": _digest(preview),
        "comparison_sha256": _digest(preview["comparison"]),
        "visuals": [
            {
                "kind": kind,
                "sha256": preview["visual_comparison"][kind]["sha256"],
            }
            for kind in ("diff", "expected", "observed")
        ],
    }


class VerifyHostTests(unittest.TestCase):
    def test_fresh_workflow_live_bindings_and_restart_are_verified_without_secret_leak(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            binary_directory = temporary / "bin"
            binary_directory.mkdir()
            shutil.copy2(FAKE_JQ, binary_directory / "jq")
            (binary_directory / "jq").chmod(0o755)
            command_log = temporary / "commands.jsonl"
            output = temporary / "verification.json"
            artifact = _artifact()
            admission = temporary / "admission.tfvars.json"
            admission.write_text(
                json.dumps(
                    {
                        "project_id": "colortrace-test-project",
                        "region": "us-central1",
                        "resource_prefix": "ct-singlehost",
                        "deployment_artifact_binding": artifact,
                        "deployment_artifact_binding_sha256": _digest(artifact),
                    }
                ),
                encoding="utf-8",
            )
            rejection_started, rejected, rejected_receipt, rejected_reset = _rejected_workflow(
                artifact, run_digit="a"
            )
            started, approved, closed, receipt, reset = _workflow(
                artifact,
                run_digit="b",
            )
            preview = _scenario_preview(started, build_sha256=closed["build_sha256"])
            responses = temporary / "responses"
            responses.mkdir()
            for name, value in (
                ("preview", preview),
                ("rejection-started", rejection_started),
                ("rejected", rejected),
                ("rejected-receipt", rejected_receipt),
                ("rejected-reset", rejected_reset),
                ("approval-started", started),
                ("approved", approved),
                ("closed", closed),
                ("receipt", receipt),
                ("reset", reset),
            ):
                (responses / f"{name}.json").write_text(json.dumps(value), encoding="utf-8")
            for kind, contents in VISUAL_BYTES.items():
                (responses / f"{kind}.png").write_bytes(contents)

            gcloud = binary_directory / "gcloud"
            gcloud.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

if (
    "COLORTRACE_ACCESS_PASSWORD" in os.environ
    or "COLORTRACE_STAGING_HARD_STOP_EPOCH" in os.environ
):
    raise SystemExit(90)
log = pathlib.Path(os.environ["FAKE_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["gcloud", *sys.argv[1:]]) + "\\n")
artifact = json.loads(pathlib.Path(os.environ["FAKE_ARTIFACT"]).read_text())
if sys.argv[1:4] == ["compute", "instances", "describe"]:
    build_binding = {
        "schema": "colortrace-runtime-build-binding/v1",
        "source_commit": artifact["source"]["commit"],
        "source_tree": artifact["source"]["tree"],
    }
    encoded = json.dumps(build_binding, sort_keys=True, separators=(",", ":")).encode() + b"\\n"
    runtime_build_binding_sha256 = "sha256:" + __import__("hashlib").sha256(encoded).hexdigest()
    metadata = {
        "colortrace-staging-generation": "stage-0001",
        "colortrace-staging-hard-stop-epoch": os.environ["FAKE_HARD_STOP_EPOCH"],
        "colortrace-candidate-commit": artifact["source"]["commit"],
        "colortrace-candidate-tree": artifact["source"]["tree"],
        "colortrace-artifact-binding-sha256": os.environ["FAKE_ARTIFACT_DIGEST"],
        "colortrace-build-manifest-sha256": artifact["build_manifest_sha256"],
        "colortrace-fixture-manifest-sha256": artifact["fixture_manifest_sha256"],
        "colortrace-observability-lock-sha256": artifact["observability_lock_sha256"],
        "colortrace-runtime-build-binding-sha256": runtime_build_binding_sha256,
        "colortrace-scan-binding-sha256": artifact["scan_binding_sha256"],
        "colortrace-scan-report-set-sha256": artifact["scanner"]["report_set_sha256"],
        "colortrace-scanner-version-sha256": artifact["scanner"]["version_sha256"],
    }
    print(json.dumps({
        "metadata": {"items": [
            {"key": key, "value": value} for key, value in metadata.items()
        ]},
        "status": "RUNNING",
    }))
    raise SystemExit(0)
if sys.argv[1:3] == ["compute", "ssh"]:
    command = sys.argv[sys.argv.index("--command") + 1]
    if "colortrace-live-binding-ok" in command:
        required_apt_checks = (
            "apt-daily.timer",
            "apt-daily-upgrade.timer",
            "apt-daily.service",
            "apt-daily-upgrade.service",
            'systemctl is-enabled "$unit"',
            'systemctl is-active "$unit"',
            'test "$enabled_state" = masked',
            'test "$active_state" = inactive',
            "expected_hard_stop_epoch=2000000000",
            "colortrace-staging-hard-stop-epoch",
            "generation_deadline=$((activated_at + 604800))",
            'deadline=$expected_hard_stop_epoch',
        )
        if not all(check in command for check in required_apt_checks):
            raise SystemExit(91)
        if (
            os.environ["FAKE_APT_ENABLED_STATE"] != "masked"
            or os.environ["FAKE_APT_ACTIVE_STATE"] != "inactive"
        ):
            raise SystemExit(92)
        print("colortrace-live-binding-ok")
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            gcloud.chmod(0o755)

            terraform = binary_directory / "terraform"
            terraform.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

if (
    "COLORTRACE_ACCESS_PASSWORD" in os.environ
    or "COLORTRACE_STAGING_HARD_STOP_EPOCH" in os.environ
):
    raise SystemExit(90)
with pathlib.Path(os.environ["FAKE_COMMAND_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["terraform", *sys.argv[1:]]) + "\\n")
if sys.argv[2:] == ["output", "-raw", "staging_hard_stop_epoch"]:
    print(os.environ["FAKE_TERRAFORM_HARD_STOP"], end="")
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            terraform.chmod(0o755)

            curl = binary_directory / "curl"
            curl.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import shutil
import sys

arguments = sys.argv[1:]
if "COLORTRACE_ACCESS_PASSWORD" in os.environ:
    raise SystemExit(90)
log = pathlib.Path(os.environ["FAKE_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["curl", *arguments]) + "\\n")
url = arguments[-1]
authenticated = "--netrc-file" in arguments
output = None
if "--output" in arguments:
    output = pathlib.Path(arguments[arguments.index("--output") + 1])
responses = pathlib.Path(os.environ["FAKE_RESPONSES"])
if url.endswith("/v1/demo") and "--write-out" in arguments:
    counter = pathlib.Path(os.environ["FAKE_API_READY_COUNTER"])
    count = int(counter.read_text()) if counter.exists() else 0
    counter.write_text(str(count + 1))
    failures = int(os.environ["FAKE_API_READY_FAILURES"])
    print("502" if count < failures else "200", end="")
    raise SystemExit(0)
if "--write-out" in arguments and "%{content_type}" in arguments:
    kind = url.rsplit("/", 1)[-1]
    shutil.copyfile(responses / f"{kind}.png", output)
    print("image/png", end="")
    raise SystemExit(0)
if url.endswith("/v1/demo"):
    shutil.copyfile(responses / "preview.json", output)
    raise SystemExit(0)
if "--write-out" in arguments and "--data-binary" not in arguments:
    if not authenticated or "--user" in arguments:
        status = "401"
    elif url.endswith("/v1/session") or url.endswith("/v1/incidents"):
        status = "404"
    elif url.endswith("/reset") and "Origin: https://invalid.example" in arguments:
        status = "403"
    elif url.endswith("/reset"):
        status = "415"
    else:
        status = "200"
        if "--dump-header" in arguments:
            path = pathlib.Path(arguments[arguments.index("--dump-header") + 1])
            path.write_text(
                "HTTP/2 200\\r\\n"
                "Referrer-Policy: no-referrer\\r\\n"
                "X-Content-Type-Options: nosniff\\r\\n"
                "X-Frame-Options: DENY\\r\\n\\r\\n",
                encoding="utf-8",
            )
    print(status, end="")
    raise SystemExit(0)
if "--data-binary" in arguments:
    if url.endswith("/v1/demo/runs"):
        counter = pathlib.Path(os.environ["FAKE_START_COUNTER"])
        count = int(counter.read_text()) if counter.exists() else 0
        counter.write_text(str(count + 1))
        if count == 0:
            source, status = responses / "rejection-started.json", "201"
        else:
            source, status = responses / "approval-started.json", "201"
        request_argument = arguments[arguments.index("--data-binary") + 1]
        request_path = pathlib.Path(request_argument.removeprefix("@"))
        request = json.loads(request_path.read_text(encoding="utf-8"))
        response = json.loads(source.read_text(encoding="utf-8"))
        response["approval_nonce"] = request["approval_nonce"]
        output.write_text(json.dumps(response), encoding="utf-8")
        print(status, end="")
        raise SystemExit(0)
    elif url.endswith("/reject"):
        source, status = responses / "rejected.json", "200"
    elif url.endswith("/approve"):
        source, status = responses / "approved.json", "200"
    elif url.endswith("/close"):
        source, status = responses / "closed.json", "200"
    elif url.endswith("/reset"):
        if "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in url:
            source = responses / "rejected-reset.json"
        else:
            source = responses / "reset.json"
        status = "200"
    else:
        raise SystemExit(2)
    shutil.copyfile(source, output)
    print(status, end="")
    raise SystemExit(0)
if url.endswith("/receipt"):
    source = (
        responses / "rejected-receipt.json"
        if "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in url
        else responses / "receipt.json"
    )
    shutil.copyfile(source, output)
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            curl.chmod(0o755)

            timeout = binary_directory / "timeout"
            timeout.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

if "COLORTRACE_ACCESS_PASSWORD" in os.environ:
    raise SystemExit(90)
log = pathlib.Path(os.environ["FAKE_COMMAND_LOG"])
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["timeout", *sys.argv[1:]]) + "\\n")
raise SystemExit(124)
""",
                encoding="utf-8",
            )
            timeout.chmod(0o755)

            sleep = binary_directory / "sleep"
            sleep.write_text(
                """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

if "COLORTRACE_ACCESS_PASSWORD" in os.environ:
    raise SystemExit(90)
with pathlib.Path(os.environ["FAKE_COMMAND_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(["sleep", *sys.argv[1:]]) + "\\n")
raise SystemExit(0)
""",
                encoding="utf-8",
            )
            sleep.chmod(0o755)

            password = "CorrectHorse42"
            artifact_path = temporary / "artifact.json"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            environment = {
                **os.environ,
                "COLORTRACE_ACCESS_PASSWORD": password,
                "COLORTRACE_RESUME_ATTEMPTS": "1",
                "COLORTRACE_RESUME_DELAY_SECONDS": "0",
                "FAKE_COMMAND_LOG": str(command_log),
                "FAKE_ARTIFACT": str(artifact_path),
                "FAKE_ARTIFACT_DIGEST": _digest(artifact),
                "FAKE_HARD_STOP_EPOCH": "2000000000",
                "FAKE_TERRAFORM_HARD_STOP": "2000000000",
                "FAKE_RESPONSES": str(responses),
                "FAKE_API_READY_COUNTER": str(temporary / "api-ready-counter"),
                "FAKE_API_READY_FAILURES": "0",
                "FAKE_START_COUNTER": str(temporary / "start-counter"),
                "FAKE_APT_ENABLED_STATE": "masked",
                "FAKE_APT_ACTIVE_STATE": "inactive",
                "PATH": f"{binary_directory}:{os.environ['PATH']}",
            }
            environment.pop("COLORTRACE_STAGING_HARD_STOP_EPOCH", None)
            verify_command = [
                SCRIPT,
                "https://203-0-113-42.sslip.io",
                "colortrace",
                "colortrace-test-project",
                "us-central1-a",
                "ct-singlehost-vm",
                "stage-0001",
                admission,
                output,
            ]
            for hard_stop_epoch in ("not-an-epoch", "1"):
                with self.subTest(hard_stop_epoch=hard_stop_epoch):
                    invalid_log = temporary / f"invalid-hard-stop-{hard_stop_epoch}.jsonl"
                    invalid_log.touch()
                    invalid_output = temporary / f"invalid-hard-stop-{hard_stop_epoch}.json"
                    invalid_environment = {
                        **environment,
                        "FAKE_COMMAND_LOG": str(invalid_log),
                        "FAKE_HARD_STOP_EPOCH": hard_stop_epoch,
                    }
                    rejected = subprocess.run(
                        [*verify_command[:-1], invalid_output],
                        check=False,
                        capture_output=True,
                        env=invalid_environment,
                        text=True,
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    invalid_calls = [
                        json.loads(line) for line in invalid_log.read_text().splitlines()
                    ]
                    self.assertFalse(
                        any(call[:3] == ["gcloud", "compute", "ssh"] for call in invalid_calls)
                    )
            expired_log = temporary / "expired-hard-stop.jsonl"
            expired_log.touch()
            expired_environment = {
                **environment,
                "FAKE_COMMAND_LOG": str(expired_log),
                "FAKE_HARD_STOP_EPOCH": "1",
                "FAKE_TERRAFORM_HARD_STOP": "1",
            }
            expired = subprocess.run(
                [*verify_command[:-1], temporary / "expired-hard-stop.json"],
                check=False,
                capture_output=True,
                env=expired_environment,
                text=True,
            )
            self.assertNotEqual(expired.returncode, 0)
            expired_calls = [json.loads(line) for line in expired_log.read_text().splitlines()]
            self.assertEqual(expired_calls[0][0], "terraform")
            self.assertFalse(any(call[0] == "gcloud" for call in expired_calls))

            overflow_log = temporary / "overflowing-hard-stop.jsonl"
            overflow_log.touch()
            overflow_environment = {
                **environment,
                "FAKE_COMMAND_LOG": str(overflow_log),
                "FAKE_TERRAFORM_HARD_STOP": "9" * 40,
            }
            overflow_rejected = subprocess.run(
                [*verify_command[:-1], temporary / "overflowing-hard-stop.json"],
                check=False,
                capture_output=True,
                env=overflow_environment,
                text=True,
            )
            self.assertNotEqual(overflow_rejected.returncode, 0)
            overflow_calls = [json.loads(line) for line in overflow_log.read_text().splitlines()]
            self.assertEqual(overflow_calls[0][0], "terraform")
            self.assertFalse(any(call[0] == "gcloud" for call in overflow_calls))

            override_log = temporary / "mismatched-hard-stop-override.jsonl"
            override_log.touch()
            override_environment = {
                **environment,
                "COLORTRACE_STAGING_HARD_STOP_EPOCH": "1999999999",
                "FAKE_COMMAND_LOG": str(override_log),
            }
            override_rejected = subprocess.run(
                [*verify_command[:-1], temporary / "mismatched-hard-stop-override.json"],
                check=False,
                capture_output=True,
                env=override_environment,
                text=True,
            )
            self.assertNotEqual(override_rejected.returncode, 0)
            override_calls = [json.loads(line) for line in override_log.read_text().splitlines()]
            self.assertEqual(override_calls[0][0], "terraform")
            self.assertFalse(any(call[0] == "gcloud" for call in override_calls))
            for state_name, invalid_state in (
                ("FAKE_APT_ENABLED_STATE", "enabled"),
                ("FAKE_APT_ACTIVE_STATE", "active"),
            ):
                with self.subTest(state_name=state_name, invalid_state=invalid_state):
                    invalid_log = temporary / f"invalid-{state_name}.jsonl"
                    invalid_log.touch()
                    invalid_output = temporary / f"invalid-{state_name}.json"
                    invalid_environment = {
                        **environment,
                        "FAKE_COMMAND_LOG": str(invalid_log),
                        "FAKE_START_COUNTER": str(temporary / f"invalid-{state_name}-counter"),
                        state_name: invalid_state,
                    }
                    rejected = subprocess.run(
                        [*verify_command[:-1], invalid_output],
                        check=False,
                        capture_output=True,
                        env=invalid_environment,
                        text=True,
                    )
                    self.assertNotEqual(rejected.returncode, 0)
                    invalid_calls = [
                        json.loads(line) for line in invalid_log.read_text().splitlines()
                    ]
                    self.assertTrue(
                        any(
                            call[:3] == ["gcloud", "compute", "ssh"]
                            and "--command" in call
                            and "colortrace-live-binding-ok" in call[call.index("--command") + 1]
                            for call in invalid_calls
                        )
                    )

            api_ready_counter = temporary / "successful-api-ready-counter"
            completed_environment = {
                **environment,
                "FAKE_API_READY_COUNTER": str(api_ready_counter),
                "FAKE_API_READY_FAILURES": "1",
            }
            completed = subprocess.run(
                verify_command,
                check=False,
                capture_output=True,
                env=completed_environment,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "colortrace-single-host-verification/v4")
            self.assertEqual(report["preview"]["initial"]["preview_sha256"], _digest(preview))
            self.assertEqual(
                report["preview"]["after_rejection_reset"], report["preview"]["initial"]
            )
            self.assertEqual(
                report["preview"]["after_approval_reset"], report["preview"]["initial"]
            )
            self.assertEqual(report["preview"]["first_run_start"]["http_status"], 201)
            self.assertEqual(report["workflows"]["approved"]["run_id"], started["run_id"])
            self.assertNotEqual(
                report["workflows"]["approved"]["run_id"],
                report["workflows"]["rejected"]["run_id"],
            )
            self.assertEqual(report["workflows"]["approved"]["recovery_check_count"], 7)
            self.assertEqual(report["workflows"]["approved"]["recovery_evidence_count"], 21)
            self.assertEqual(
                set(report["workflows"]["approved"]["mcp_tool_bindings"]),
                {
                    "alerting_manage_rules",
                    "query_loki_logs",
                    "query_prometheus",
                },
            )
            self.assertEqual(report["workflows"]["rejected"]["run_id"], rejection_started["run_id"])
            self.assertEqual(
                report["workflows"]["rejected"]["reason_code"],
                "insufficient-evidence",
            )
            self.assertFalse(report["workflows"]["rejected"]["execution_proof_present"])
            self.assertFalse(report["workflows"]["rejected"]["action_bindings_present"])
            self.assertTrue(all(value == "pass" for value in report["checks"].values()))
            calls = [json.loads(line) for line in command_log.read_text().splitlines()]
            self.assertEqual(api_ready_counter.read_text(encoding="utf-8"), "2")
            serialized_calls = json.dumps(calls)
            self.assertNotIn(password, serialized_calls)
            readiness_events = [call for call in calls if call[0] in {"curl", "sleep"}][:5]
            self.assertEqual(
                [(call[0], call[-1]) for call in readiness_events],
                [
                    ("curl", "https://203-0-113-42.sslip.io/"),
                    ("curl", "https://203-0-113-42.sslip.io/v1/demo"),
                    ("sleep", "5"),
                    ("curl", "https://203-0-113-42.sslip.io/"),
                    ("curl", "https://203-0-113-42.sslip.io/v1/demo"),
                ],
            )
            self.assertEqual(serialized_calls.count("docker restart colortrace-runtime"), 2)
            self.assertIn("python -m colortrace_grafana_mcp.cli catalog", serialized_calls)
            self.assertNotIn("/opt/colortrace/bin/colortrace-grafana-mcp", serialized_calls)
            self.assertIn("colortrace-live-binding-ok", serialized_calls)
            self.assertIn("sha256:" + "7" * 64, serialized_calls)
            self.assertIn("unexpected_pre_drop", serialized_calls)
            self.assertIn("colortrace-internal", serialized_calls)
            remote_checks = [
                call[call.index("--command") + 1]
                for call in calls
                if call[:3] == ["gcloud", "compute", "ssh"]
                and "--command" in call
                and "colortrace-live-binding-ok" in call[call.index("--command") + 1]
            ]
            self.assertEqual(len(remote_checks), 2)
            for command in remote_checks:
                for unit in APT_AUTOMATIC_UNITS:
                    self.assertIn(unit, command)
                self.assertIn('systemctl is-enabled "$unit"', command)
                self.assertIn('systemctl is-active "$unit"', command)
                self.assertIn('test "$enabled_state" = masked', command)
                self.assertIn('test "$active_state" = inactive', command)
                self.assertIn("expected_hard_stop_epoch=2000000000", command)
                self.assertIn("colortrace-staging-hard-stop-epoch", command)
                self.assertIn("generation_deadline=$((activated_at + 604800))", command)
                self.assertIn("deadline=$expected_hard_stop_epoch", command)
            reset_calls = [
                call
                for call in calls
                if call[0] == "curl" and "--data-binary" in call and call[-1].endswith("/reset")
            ]
            self.assertEqual(len(reset_calls), 2)
            reject_calls = [
                call
                for call in calls
                if call[0] == "curl" and "--data-binary" in call and call[-1].endswith("/reject")
            ]
            self.assertEqual(len(reject_calls), 2)
            self.assertEqual(reject_calls[0][-1], reject_calls[1][-1])
            start_calls = [
                call
                for call in calls
                if call[0] == "curl"
                and "--data-binary" in call
                and call[-1].endswith("/v1/demo/runs")
            ]
            self.assertEqual(len(start_calls), 2)
            workflow_url = "https://203-0-113-42.sslip.io/v1/demo/runs"
            workflow_mutation_urls = [
                call[-1]
                for call in calls
                if call[0] == "curl"
                and "--data-binary" in call
                and (
                    call[-1] == workflow_url
                    or call[-1].startswith(f"{workflow_url}/{rejection_started['run_id']}/")
                    or call[-1].startswith(f"{workflow_url}/{started['run_id']}/")
                )
            ]
            self.assertEqual(
                workflow_mutation_urls,
                [
                    workflow_url,
                    f"{workflow_url}/{rejection_started['run_id']}/reject",
                    f"{workflow_url}/{rejection_started['run_id']}/reject",
                    f"{workflow_url}/{rejection_started['run_id']}/reset",
                    workflow_url,
                    f"{workflow_url}/{started['run_id']}/approve",
                    f"{workflow_url}/{started['run_id']}/close",
                    f"{workflow_url}/{started['run_id']}/reset",
                ],
            )
            api_readiness_indices = [
                index
                for index, call in enumerate(calls)
                if call[0] == "curl" and "--write-out" in call and call[-1].endswith("/v1/demo")
            ]
            self.assertEqual(len(api_readiness_indices), 2)
            first_start_index = next(
                index for index, call in enumerate(calls) if call == start_calls[0]
            )
            self.assertLess(api_readiness_indices[-1], first_start_index)
            boundary_urls = {
                call[-1] for call in calls if call[0] == "curl" and "--write-out" in call
            }
            self.assertIn(
                "https://203-0-113-42.sslip.io/v1/demo/runs/"
                "demo-run-00000000000000000000000000000000",
                boundary_urls,
            )
            self.assertIn(
                "https://203-0-113-42.sslip.io/v1/incidents",
                boundary_urls,
            )
            preview_calls = [
                call
                for call in calls
                if call[0] == "curl" and "--write-out" not in call and call[-1].endswith("/v1/demo")
            ]
            self.assertEqual(len(preview_calls), 3)
            self.assertLess(calls.index(preview_calls[0]), calls.index(start_calls[0]))
            private_port_calls = [call for call in calls if call[0] == "timeout"]
            self.assertEqual(
                sorted(int(call[-1]) for call in private_port_calls),
                [22, 80, 3000, 3100, 3200, 4318, 8080, 8443, 9090, 13000, 13100, 13200, 19090],
            )
            terraform_calls = [call for call in calls if call[0] == "terraform"]
            self.assertEqual(len(terraform_calls), 1)
            self.assertEqual(
                terraform_calls[0][-3:],
                ["output", "-raw", "staging_hard_stop_epoch"],
            )

    def test_mcp_probe_accepts_allowlisted_catalog_with_adaptive_used_subset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            binary_directory = temporary / "bin"
            binary_directory.mkdir()
            inventory_sha256 = "sha256:" + "f" * 64
            used_tools = {
                name: {
                    "input_schema_sha256": digit * 64,
                    "annotations_sha256": str(int(digit) + 4) * 64,
                }
                for name, digit in (
                    ("alerting_manage_rules", "1"),
                    ("query_loki_logs", "2"),
                    ("tempo_get-trace", "3"),
                )
            }
            selected_tools = {
                **used_tools,
                "query_prometheus": {
                    "input_schema_sha256": "4" * 64,
                    "annotations_sha256": "8" * 64,
                },
            }
            summary = temporary / "summary.json"
            summary.write_text(
                json.dumps(
                    {
                        "mcp_inventory_sha256": inventory_sha256,
                        "mcp_tool_bindings": used_tools,
                    }
                ),
                encoding="utf-8",
            )
            catalog = temporary / "catalog.json"
            catalog_value = {
                "schema": "grafana-mcp-tool-inventory/v1",
                "server_version": "1.1.0",
                "server_commit": "007e8d82154899a28e19e8dfe9c2bb4452c5211a",
                "binary_sha256": (
                    "a3dacdcace8d8082dd7cb245e41be54e8da4a9375969cb39c85c420a30ea0809"
                ),
                "mcp_sdk_version": "1.29.0",
                "mcp_protocol_version": "2025-06-18",
                "selected_tools": selected_tools,
                "inventory_version": inventory_sha256,
            }
            catalog.write_text(json.dumps(catalog_value), encoding="utf-8")
            probe = temporary / "mcp-probe.sh"
            generated = subprocess.run(
                [CONTRACT_HELPER, "mcp-script", summary, probe],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            self.assertEqual(set(selected_tools) - set(used_tools), {"query_prometheus"})

            sudo = binary_directory / "sudo"
            sudo.write_text(
                """#!/usr/bin/env python3
import os
import pathlib
import shutil
import sys

arguments = sys.argv[1:]
if "rm" in arguments:
    pathlib.Path(arguments[-1]).unlink(missing_ok=True)
    raise SystemExit(0)
if "-m" in arguments and "colortrace_grafana_mcp.cli" in arguments:
    output = pathlib.Path(arguments[arguments.index("--output") + 1])
    shutil.copyfile(os.environ["FAKE_MCP_CATALOG"], output)
    raise SystemExit(0)
if "-c" in arguments:
    command_index = arguments.index("-c")
    os.execv(sys.executable, [sys.executable, *arguments[command_index:]])
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            sudo.chmod(0o755)
            environment = {
                **os.environ,
                "FAKE_MCP_CATALOG": str(catalog),
                "PATH": f"{binary_directory}:{os.environ['PATH']}",
            }
            completed = subprocess.run(
                ["bash", probe],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            catalog_value["selected_tools"]["delete_dashboard"] = {
                "input_schema_sha256": "5" * 64,
                "annotations_sha256": "9" * 64,
            }
            catalog.write_text(json.dumps(catalog_value), encoding="utf-8")
            rejected = subprocess.run(
                ["bash", probe],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)

    def test_legacy_zero_hard_stop_and_overflow_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            artifact = _artifact()
            artifact_path = temporary / "artifact.json"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            runtime_binding = {
                "schema": "colortrace-runtime-build-binding/v1",
                "source_commit": artifact["source"]["commit"],
                "source_tree": artifact["source"]["tree"],
            }
            metadata = {
                "colortrace-staging-generation": "stage-0001",
                "colortrace-staging-hard-stop-epoch": "0",
                "colortrace-candidate-commit": artifact["source"]["commit"],
                "colortrace-candidate-tree": artifact["source"]["tree"],
                "colortrace-artifact-binding-sha256": _digest(artifact),
                "colortrace-build-manifest-sha256": artifact["build_manifest_sha256"],
                "colortrace-fixture-manifest-sha256": artifact["fixture_manifest_sha256"],
                "colortrace-observability-lock-sha256": artifact["observability_lock_sha256"],
                "colortrace-runtime-build-binding-sha256": _raw_digest(
                    _canonical(runtime_binding) + b"\n"
                ),
                "colortrace-scan-binding-sha256": artifact["scan_binding_sha256"],
                "colortrace-scan-report-set-sha256": artifact["scanner"]["report_set_sha256"],
                "colortrace-scanner-version-sha256": artifact["scanner"]["version_sha256"],
            }
            instance = temporary / "instance.json"
            instance.write_text(
                json.dumps(
                    {
                        "status": "RUNNING",
                        "metadata": {
                            "items": [
                                {"key": key, "value": value} for key, value in metadata.items()
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )

            metadata_check = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-instance-metadata",
                    instance,
                    artifact_path,
                    "stage-0001",
                    "0",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(metadata_check.returncode, 0, metadata_check.stderr)

            remote_script = temporary / "remote.sh"
            generated = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "remote-script",
                    artifact_path,
                    "stage-0001",
                    "0",
                    remote_script,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)
            source = remote_script.read_text(encoding="utf-8")
            self.assertIn("expected_hard_stop_epoch=0", source)
            self.assertIn("deadline=$generation_deadline", source)
            self.assertIn('if test "$expected_hard_stop_epoch" -ne 0', source)

            overflow = str(253_402_300_799 + 1)
            rejected = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "remote-script",
                    artifact_path,
                    "stage-0001",
                    overflow,
                    temporary / "overflow.sh",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rejected.returncode, 65)
            self.assertIn("staging-hard-stop-invalid", rejected.stderr)

    def test_prepare_rejection_binds_nonce_versions_plan_target_and_reason(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            started, _rejected, _receipt, _reset = _rejected_workflow(_artifact())
            run_path = root / "run.json"
            request_path = root / "request.json"
            run_path.write_text(json.dumps(started), encoding="utf-8")

            completed = subprocess.run(
                [CONTRACT_HELPER, "prepare-rejection", run_path, request_path],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            proof = started["investigation"]
            self.assertEqual(proof["schema"], "colortrace-demo-investigation-proof/v4")
            self.assertEqual(proof["packet_schema"], "response-packet/v2")
            self.assertEqual(
                {item["query_key"] for item in proof["evidence"]},
                {"alert.rule", "log.correlated-events", "metric.worker-cohort"},
            )
            self.assertEqual(
                [item["sequence"] for item in proof["adaptive_trace"]],
                list(range(len(proof["adaptive_trace"]))),
            )
            self.assertEqual(proof["stop_reason"], "sufficient-evidence")
            exposed_evidence_ids = {
                item["evidence_id"] for item in started["investigation"]["evidence"]
            }
            claim_evidence_ids = {
                evidence_id
                for claim in started["investigation"]["claims"]
                for evidence_id in claim["evidence_ids"]
            }
            self.assertTrue(claim_evidence_ids - exposed_evidence_ids)
            self.assertEqual(completed.stdout.strip(), started["run_id"])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            self.assertEqual(
                request,
                {
                    "schema": "colortrace-demo-rejection-request/v1",
                    "approval_nonce": started["approval_nonce"],
                    "expected_run_version": started["version"],
                    "expected_incident_version": started["approval"]["incident_version"],
                    "expected_plan_version": started["approval"]["plan_version"],
                    "expected_plan_sha256": started["approval"]["plan_sha256"],
                    "expected_target_sha256": started["approval"]["target_sha256"],
                    "reason_code": "insufficient-evidence",
                    "idempotency_key": f"reject:{started['run_id']}",
                },
            )

    def test_current_investigation_rejects_unknown_projection_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            started, _rejected, _receipt, _reset = _rejected_workflow(_artifact())
            started["investigation"]["unexpected"] = "unsafe-expansion"
            run_path = root / "run.json"
            run_path.write_text(json.dumps(started), encoding="utf-8")

            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "prepare-rejection",
                    run_path,
                    root / "request.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 65)
            self.assertIn("investigation-proof-invalid", completed.stderr)

    def test_current_investigation_accepts_an_alternate_exact_and_cohort_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            started, _rejected, _receipt, _reset = _rejected_workflow(_artifact())
            proof = started["investigation"]
            evidence = proof["evidence"][-1]
            evidence["query_key"] = "log.config-cohort"
            evidence["tool"] = "query_loki_logs"
            evidence["source"]["tool"] = "query_loki_logs"
            evidence["source"]["tool_input_schema_sha256"] = proof["evidence"][1]["source"][
                "tool_input_schema_sha256"
            ]
            evidence["source"]["tool_annotations_sha256"] = proof["evidence"][1]["source"][
                "tool_annotations_sha256"
            ]
            evidence["observation"]["query_key"] = "log.config-cohort"
            evidence["correlation_keys"] = {
                "fixture_id": "fixture-1",
                "run_id": "run-1",
                "config_sha256": "5" * 64,
            }
            evidence["observation"]["normalized_arguments"] = _adaptive_arguments(
                "log.config-cohort",
                correlation=evidence["correlation_keys"],
                window=proof["fixed_window"],
            )
            trace = proof["adaptive_trace"][-1]
            trace["query_key"] = "log.config-cohort"
            trace["selection_request_sha256"] = _digest({"query_key": "log.config-cohort"})
            _rebind_v4_evidence(proof)
            run_path = root / "run.json"
            run_path.write_text(json.dumps(started), encoding="utf-8")

            completed = subprocess.run(
                [CONTRACT_HELPER, "prepare-rejection", run_path, root / "request.json"],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_current_claim_requires_an_existing_source_validator_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            started, _rejected, _receipt, _reset = _rejected_workflow(_artifact())
            started["investigation"]["claims"][0]["source_validator_result_id"] = (
                "validator-result:" + "f" * 64
            )
            run_path = root / "run.json"
            run_path.write_text(json.dumps(started), encoding="utf-8")

            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "prepare-rejection",
                    run_path,
                    root / "request.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 65)
            self.assertIn("investigation-proof-invalid", completed.stderr)

    def test_current_investigation_rejects_noncanonical_derived_bindings(self) -> None:
        for case in ("packet", "validator", "commands"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                started, _rejected, _receipt, _reset = _rejected_workflow(_artifact())
                investigation = started["investigation"]
                if case == "packet":
                    investigation["packet_id"] = "response-packet:" + "f" * 64
                elif case == "validator":
                    result_id = "validation-result:" + "f" * 64
                    investigation["validators"][0]["result_id"] = result_id
                    for claim in investigation["claims"]:
                        claim["source_validator_result_id"] = result_id
                else:
                    investigation["plan"]["commands_sha256"] = "sha256:" + "f" * 64
                run_path = root / "run.json"
                run_path.write_text(json.dumps(started), encoding="utf-8")

                completed = subprocess.run(
                    [
                        CONTRACT_HELPER,
                        "prepare-rejection",
                        run_path,
                        root / "request.json",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

                self.assertEqual(completed.returncode, 65)
                self.assertIn("investigation-proof-invalid", completed.stderr)

    def test_rejection_contract_rejects_execution_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _artifact()
            started, rejected, receipt, _reset = _rejected_workflow(artifact)
            request = {
                "schema": "colortrace-demo-rejection-request/v1",
                "approval_nonce": started["approval_nonce"],
                "expected_run_version": started["version"],
                "expected_incident_version": started["approval"]["incident_version"],
                "expected_plan_version": started["approval"]["plan_version"],
                "expected_plan_sha256": started["approval"]["plan_sha256"],
                "expected_target_sha256": started["approval"]["target_sha256"],
                "reason_code": "insufficient-evidence",
                "idempotency_key": f"reject:{started['run_id']}",
            }
            receipt["bindings"]["outcome_id"] = "simulator-action-outcome:" + "f" * 64
            body = {
                key: value
                for key, value in receipt.items()
                if key not in {"receipt_id", "receipt_sha256"}
            }
            receipt["receipt_sha256"] = _digest(body)
            receipt["receipt_id"] = "demo-receipt:" + receipt["receipt_sha256"].removeprefix(
                "sha256:"
            )
            paths = {}
            for name, value in (
                ("artifact", artifact),
                ("request", request),
                ("run", rejected),
                ("receipt", receipt),
            ):
                paths[name] = root / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")

            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-rejection-contract",
                    paths["run"],
                    paths["request"],
                    paths["receipt"],
                    paths["artifact"],
                    "https://203-0-113-42.sslip.io",
                    "stage-0001",
                    "1000",
                    root / "summary.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 65)
            self.assertIn("receipt-binding-invalid", completed.stderr)

    def test_rejection_contract_rejects_request_binding_conflicts(self) -> None:
        artifact = _artifact()
        started, rejected, receipt, _reset = _rejected_workflow(artifact)
        request = {
            "schema": "colortrace-demo-rejection-request/v1",
            "approval_nonce": started["approval_nonce"],
            "expected_run_version": started["version"],
            "expected_incident_version": started["approval"]["incident_version"],
            "expected_plan_version": started["approval"]["plan_version"],
            "expected_plan_sha256": started["approval"]["plan_sha256"],
            "expected_target_sha256": started["approval"]["target_sha256"],
            "reason_code": "insufficient-evidence",
            "idempotency_key": f"reject:{started['run_id']}",
        }
        conflicts = {
            "expected_run_version": request["expected_run_version"] + 1,
            "expected_incident_version": request["expected_incident_version"] + 1,
            "expected_plan_sha256": "sha256:" + "f" * 64,
            "expected_target_sha256": "sha256:" + "e" * 64,
            "reason_code": "unsafe-scope",
        }
        for field, conflicting_value in conflicts.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                conflicting_request = {**request, field: conflicting_value}
                paths = {}
                for name, value in (
                    ("artifact", artifact),
                    ("request", conflicting_request),
                    ("run", rejected),
                    ("receipt", receipt),
                ):
                    paths[name] = root / f"{name}.json"
                    paths[name].write_text(json.dumps(value), encoding="utf-8")

                completed = subprocess.run(
                    [
                        CONTRACT_HELPER,
                        "verify-rejection-contract",
                        paths["run"],
                        paths["request"],
                        paths["receipt"],
                        paths["artifact"],
                        "https://203-0-113-42.sslip.io",
                        "stage-0001",
                        "1000",
                        root / "summary.json",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

                self.assertEqual(completed.returncode, 65)

    def test_fresh_contract_rejects_legacy_investigation_proofs(self) -> None:
        for proof_version in (1, 3):
            with (
                self.subTest(proof_version=proof_version),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                artifact = _artifact()
                _started, _approved, closed, receipt, _reset = _workflow(
                    artifact, proof_version=proof_version
                )
                visuals = root / "visuals"
                _write_visuals(visuals)
                paths = {}
                for name, value in (
                    ("artifact", artifact),
                    ("run", closed),
                    ("receipt", receipt),
                ):
                    paths[name] = root / f"{name}.json"
                    paths[name].write_text(json.dumps(value), encoding="utf-8")

                completed = subprocess.run(
                    [
                        CONTRACT_HELPER,
                        "verify-contract",
                        paths["run"],
                        paths["receipt"],
                        paths["artifact"],
                        "https://203-0-113-42.sslip.io",
                        "stage-0001",
                        "1000",
                        visuals,
                        root / "summary.json",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

                self.assertEqual(completed.returncode, 65)
                self.assertIn("closed-run-invalid", completed.stderr)

    def test_contract_rejects_rehashed_receipt_with_wrong_proof_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _artifact()
            _started, _approved, closed, receipt, _reset = _workflow(artifact)
            visuals = root / "visuals"
            _write_visuals(visuals)
            receipt["proofs"][0]["sha256"] = "sha256:" + "f" * 64
            body = {
                key: value
                for key, value in receipt.items()
                if key not in {"receipt_id", "receipt_sha256"}
            }
            receipt["receipt_sha256"] = _digest(body)
            receipt["receipt_id"] = "demo-receipt:" + receipt["receipt_sha256"].removeprefix(
                "sha256:"
            )
            paths = {}
            for name, value in (
                ("artifact", artifact),
                ("run", closed),
                ("receipt", receipt),
            ):
                paths[name] = root / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-contract",
                    paths["run"],
                    paths["receipt"],
                    paths["artifact"],
                    "https://203-0-113-42.sslip.io",
                    "stage-0001",
                    "119999",
                    visuals,
                    root / "summary.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("receipt-proof-hash-invalid", completed.stderr)

    def test_contract_rejects_floating_point_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _artifact()
            _started, _approved, closed, receipt, _reset = _workflow(artifact)
            visuals = root / "visuals"
            _write_visuals(visuals)
            receipt["terminal_at"] = 1.5
            paths = {}
            for name, value in (
                ("artifact", artifact),
                ("run", closed),
                ("receipt", receipt),
            ):
                paths[name] = root / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-contract",
                    paths["run"],
                    paths["receipt"],
                    paths["artifact"],
                    "https://203-0-113-42.sslip.io",
                    "stage-0001",
                    "1000",
                    visuals,
                    root / "summary.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("invalid-json:receipt.json", completed.stderr)

    def test_contract_rejects_receipt_inventory_not_used_by_investigation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _artifact()
            _started, _approved, closed, receipt, _reset = _workflow(artifact)
            visuals = root / "visuals"
            _write_visuals(visuals)
            receipt["provenance"]["mcp"]["inventory_sha256"] = "sha256:" + "f" * 64
            receipt["build_sha256"] = _digest(receipt["provenance"])
            closed["build_sha256"] = receipt["build_sha256"]
            body = {
                key: value
                for key, value in receipt.items()
                if key not in {"receipt_id", "receipt_sha256"}
            }
            receipt["receipt_sha256"] = _digest(body)
            receipt["receipt_id"] = "demo-receipt:" + receipt["receipt_sha256"].removeprefix(
                "sha256:"
            )
            paths = {}
            for name, value in (
                ("artifact", artifact),
                ("run", closed),
                ("receipt", receipt),
            ):
                paths[name] = root / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-contract",
                    paths["run"],
                    paths["receipt"],
                    paths["artifact"],
                    "https://203-0-113-42.sslip.io",
                    "stage-0001",
                    "1000",
                    visuals,
                    root / "summary.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("receipt-mcp-inventory-binding-invalid", completed.stderr)

    def test_contract_rejects_visual_bytes_that_do_not_match_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _artifact()
            _started, _approved, closed, receipt, _reset = _workflow(artifact)
            visuals = root / "visuals"
            _write_visuals(visuals)
            (visuals / "observed.png").write_bytes(b"tampered")
            paths = {}
            for name, value in (
                ("artifact", artifact),
                ("run", closed),
                ("receipt", receipt),
            ):
                paths[name] = root / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-contract",
                    paths["run"],
                    paths["receipt"],
                    paths["artifact"],
                    "https://203-0-113-42.sslip.io",
                    "stage-0001",
                    "1000",
                    visuals,
                    root / "summary.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("visual-assets-invalid", completed.stderr)

    def test_run_free_preview_is_strict_hash_bound_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _artifact()
            started, _approved, closed, _receipt, _reset = _workflow(artifact)
            preview = _scenario_preview(started, build_sha256=closed["build_sha256"])
            preview_path = root / "preview.json"
            artifact_path = root / "artifact.json"
            visual_root = root / "visuals"
            visual_root.mkdir()
            for kind in ("diff", "expected", "observed"):
                (visual_root / f"{kind}.png").write_bytes(VISUAL_BYTES[kind])
            preview_path.write_text(json.dumps(preview), encoding="utf-8")
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            baseline = root / "baseline.json"
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-preview",
                    preview_path,
                    visual_root,
                    artifact_path,
                    baseline,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            summary = json.loads(baseline.read_text(encoding="utf-8"))
            self.assertEqual(summary["preview_sha256"], _digest(preview))
            self.assertEqual(
                [item["kind"] for item in summary["visuals"]],
                ["diff", "expected", "observed"],
            )

            stable = root / "stable.json"
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-preview",
                    preview_path,
                    visual_root,
                    artifact_path,
                    stable,
                    "--baseline",
                    baseline,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(stable.read_bytes(), baseline.read_bytes())

            preview["comparison"]["renders"][1]["resolved_lut_sha256"] = "sha256:" + "f" * 64
            preview_path.write_text(json.dumps(preview), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-preview",
                    preview_path,
                    visual_root,
                    artifact_path,
                    root / "changed.json",
                    "--baseline",
                    baseline,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("scenario-preview-changed", completed.stderr)

            preview["unexpected"] = "field"
            preview_path.write_text(json.dumps(preview), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-preview",
                    preview_path,
                    visual_root,
                    artifact_path,
                    root / "invalid.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("scenario-preview-invalid", completed.stderr)

    def test_v4_investigation_rejects_adaptive_binding_and_proof_tampering(self) -> None:
        for case in (
            "source",
            "timing",
            "attempt",
            "usage",
            "model-citation",
            "advisory-citation",
            "advisory-output",
            "claim-type",
            "claim-state",
            "claim-reason",
            "packet-schema",
            "packet-evidence",
            "incident-binding",
            "policy-binding",
            "invocation-policy",
            "envelope-schema",
            "observation-catalog",
            "model-arguments",
            "provider-arguments",
            "provider-binding",
            "batch-request",
            "batch-request-all",
            "envelope-chain",
            "missing-exact-path",
            "missing-cohort-path",
            "trace-order",
            "trace-selection",
            "hypothesis-citation",
            "stop-reason",
            "mcp-attempts",
            "finalized-at",
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory)
                started, _rejected, _receipt, _reset = _rejected_workflow(_artifact())
                proof = started["investigation"]
                if case == "source":
                    proof["evidence"][0]["source"]["server"] = "lookalike-mcp"
                elif case == "timing":
                    proof["evidence"][0]["timing"]["retrieved_at"] = None
                elif case == "attempt":
                    proof["model_invocations"][0]["attempt"] = 2
                elif case == "usage":
                    proof["budget_use"]["model_turns"] += 1
                elif case == "model-citation":
                    proof["model_invocations"][0]["input_evidence_ids"] = ["sha256:" + "f" * 64]
                elif case == "advisory-citation":
                    proof["model_advisory"]["evidence_ids"] = ["sha256:" + "f" * 64]
                elif case == "advisory-output":
                    proof["model_advisory"]["output_sha256"] = "sha256:" + "f" * 64
                elif case == "claim-type":
                    proof["claims"][0]["claim_type"] = "operator-error"
                elif case == "claim-state":
                    proof["claims"][0]["state"] = "rejected"
                elif case == "claim-reason":
                    proof["claims"][0]["reason_codes"] = ["causal-resource-rejected"]
                elif case == "packet-schema":
                    proof["packet_schema"] = "response-packet/v1"
                elif case == "packet-evidence":
                    proof["packet_evidence_ids"].remove(proof["evidence"][1]["evidence_id"])
                elif case == "incident-binding":
                    proof["incident_id"] = "incident-demo-" + "f" * 32
                elif case == "policy-binding":
                    proof["policy_binding"]["sha256"] = "sha256:" + "f" * 64
                elif case == "invocation-policy":
                    proof["model_invocations"][0]["policy_sha256"] = "sha256:" + "f" * 64
                elif case == "envelope-schema":
                    proof["evidence"][0]["envelope_schema"] = "evidence-envelope/v1"
                elif case == "observation-catalog":
                    proof["evidence"][0]["observation"]["catalog_version"] = (
                        "grafana-evidence-query-catalog/v1"
                    )
                elif case == "model-arguments":
                    proof["evidence"][1]["observation"]["model_visible_arguments"] = ["query"]
                elif case == "provider-arguments":
                    proof["evidence"][1]["observation"]["normalized_arguments"]["query"] = (
                        "operator-supplied"
                    )
                elif case == "provider-binding":
                    proof["evidence"][1]["observation"]["normalized_arguments"]["datasourceUid"] = (
                        "loki-lookalike"
                    )
                elif case == "batch-request":
                    proof["evidence"][1]["request_id"] = "evidence-" + "f" * 24
                elif case == "batch-request-all":
                    for evidence in proof["evidence"]:
                        evidence["request_id"] = "evidence-" + "f" * 24
                    _rebind_v4_evidence(proof)
                elif case == "envelope-chain":
                    proof["evidence"][1]["predecessor_event_sha256"] = "sha256:" + "f" * 64
                elif case == "missing-exact-path":
                    evidence = proof["evidence"][1]
                    evidence["query_key"] = "log.config-cohort"
                    evidence["observation"]["query_key"] = "log.config-cohort"
                    evidence["correlation_keys"] = {
                        "fixture_id": "fixture-1",
                        "run_id": "run-1",
                        "config_sha256": "5" * 64,
                    }
                    evidence["observation"]["normalized_arguments"] = _adaptive_arguments(
                        "log.config-cohort",
                        correlation=evidence["correlation_keys"],
                        window=proof["fixed_window"],
                    )
                    trace = proof["adaptive_trace"][1]
                    trace["query_key"] = "log.config-cohort"
                    trace["selection_request_sha256"] = _digest({"query_key": "log.config-cohort"})
                    _rebind_v4_evidence(proof)
                elif case == "missing-cohort-path":
                    evidence = proof["evidence"][2]
                    evidence["query_key"] = "metric.correlated-observations"
                    evidence["observation"]["query_key"] = "metric.correlated-observations"
                    evidence["correlation_keys"] = dict(proof["evidence"][0]["correlation_keys"])
                    evidence["observation"]["normalized_arguments"] = _adaptive_arguments(
                        "metric.correlated-observations",
                        correlation=evidence["correlation_keys"],
                        window=proof["fixed_window"],
                    )
                    trace = proof["adaptive_trace"][2]
                    trace["query_key"] = "metric.correlated-observations"
                    trace["selection_request_sha256"] = _digest(
                        {"query_key": "metric.correlated-observations"}
                    )
                    _rebind_v4_evidence(proof)
                elif case == "trace-order":
                    proof["adaptive_trace"][1], proof["adaptive_trace"][2] = (
                        proof["adaptive_trace"][2],
                        proof["adaptive_trace"][1],
                    )
                elif case == "trace-selection":
                    proof["adaptive_trace"][1]["selection_output_sha256"] = "sha256:" + "f" * 64
                elif case == "hypothesis-citation":
                    proof["hypotheses"][0]["evidence_ids"] = ["sha256:" + "f" * 64]
                elif case == "stop-reason":
                    proof["stop_reason"] = "budget-exhausted"
                elif case == "mcp-attempts":
                    proof["budget_use"]["mcp_attempts"] += 1
                elif case == "finalized-at":
                    proof["finalized_at"] = "2026-08-23T12:00:00.000Z"
                else:  # pragma: no cover - the parameter list is exhaustive
                    self.fail(f"unsupported mutation: {case}")
                run_path = root / "run.json"
                run_path.write_text(json.dumps(started), encoding="utf-8")
                completed = subprocess.run(
                    [
                        CONTRACT_HELPER,
                        "prepare-rejection",
                        run_path,
                        root / "request.json",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 65)
                self.assertIn("investigation-proof-invalid", completed.stderr)

    def test_v2_timeline_rejects_noncausal_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            started, _rejected, _receipt, _reset = _rejected_workflow(_artifact())
            started["timeline"][1]["kind"] = "approval-submitted"
            started["timeline"][1]["phase"] = "executing"
            run_path = root / "run.json"
            run_path.write_text(json.dumps(started), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "prepare-rejection",
                    run_path,
                    root / "request.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("run-timeline-invalid", completed.stderr)

    def test_closed_timeline_must_bind_receipt_boundary_timestamps(self) -> None:
        for boundary, replacement in (
            ("first", "2026-08-23T11:59:59.000Z"),
            ("final", "2026-08-23T12:00:31.000Z"),
        ):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                artifact = _artifact()
                _started, _approved, closed, receipt, _reset = _workflow(artifact)
                closed["timeline"][0 if boundary == "first" else -1]["recorded_at"] = replacement
                visuals = root / "visuals"
                _write_visuals(visuals)
                paths: dict[str, Path] = {}
                for name, value in (
                    ("artifact", artifact),
                    ("run", closed),
                    ("receipt", receipt),
                ):
                    paths[name] = root / f"{name}.json"
                    paths[name].write_text(json.dumps(value), encoding="utf-8")
                completed = subprocess.run(
                    [
                        CONTRACT_HELPER,
                        "verify-contract",
                        paths["run"],
                        paths["receipt"],
                        paths["artifact"],
                        "https://203-0-113-42.sslip.io",
                        "stage-0001",
                        "1000",
                        visuals,
                        root / "summary.json",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 65)
                self.assertIn("run-timeline-receipt-binding-invalid", completed.stderr)

    def test_rejected_timeline_must_bind_receipt_terminal_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = _artifact()
            started, rejected, receipt, _reset = _rejected_workflow(artifact)
            rejected["timeline"][-1]["recorded_at"] = "2026-08-23T12:00:16.000Z"
            request = {
                "schema": "colortrace-demo-rejection-request/v1",
                "approval_nonce": started["approval_nonce"],
                "expected_run_version": started["version"],
                "expected_incident_version": started["approval"]["incident_version"],
                "expected_plan_version": started["approval"]["plan_version"],
                "expected_plan_sha256": started["approval"]["plan_sha256"],
                "expected_target_sha256": started["approval"]["target_sha256"],
                "reason_code": "insufficient-evidence",
                "idempotency_key": f"reject:{started['run_id']}",
            }
            paths: dict[str, Path] = {}
            for name, value in (
                ("artifact", artifact),
                ("request", request),
                ("run", rejected),
                ("receipt", receipt),
            ):
                paths[name] = root / f"{name}.json"
                paths[name].write_text(json.dumps(value), encoding="utf-8")
            completed = subprocess.run(
                [
                    CONTRACT_HELPER,
                    "verify-rejection-contract",
                    paths["run"],
                    paths["request"],
                    paths["receipt"],
                    paths["artifact"],
                    "https://203-0-113-42.sslip.io",
                    "stage-0001",
                    "1000",
                    root / "summary.json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("run-timeline-receipt-binding-invalid", completed.stderr)

    def test_report_requires_bound_preview_reset_and_first_start_evidence(self) -> None:
        artifact = _artifact()
        started, _approved, closed, _receipt, _reset = _workflow(artifact)
        preview = _scenario_preview(started, build_sha256=closed["build_sha256"])
        preview_summary = _preview_verification(preview)
        first_start = {
            "schema": "colortrace-demo-first-start-verification/v1",
            "http_status": 201,
            "request_sha256": "sha256:" + "1" * 64,
            "response_sha256": "sha256:" + "2" * 64,
            "run_id": started["run_id"],
            "run_schema": "colortrace-demo-run/v2",
            "run_version": 2,
            "preview_sha256": preview_summary["preview_sha256"],
        }
        cases = (
            "rejection-preview",
            "approval-preview",
            "start-status",
            "start-preview",
            "missing-first-start",
            "same-run-id",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                rejection_preview = json.loads(json.dumps(preview_summary))
                approval_preview = json.loads(json.dumps(preview_summary))
                selected_start = json.loads(json.dumps(first_start))
                if case == "rejection-preview":
                    rejection_preview["preview_sha256"] = "sha256:" + "f" * 64
                elif case == "approval-preview":
                    approval_preview["visuals"][0]["sha256"] = "sha256:" + "f" * 64
                elif case == "start-status":
                    selected_start["http_status"] = 409
                elif case == "start-preview":
                    selected_start["preview_sha256"] = "sha256:" + "f" * 64
                values = {
                    "summary": {
                        "run_id": "demo-run-" + "b" * 32,
                        "build_sha256": closed["build_sha256"],
                    },
                    "rejection": {"run_id": started["run_id"]},
                    "artifact": artifact,
                    "initial": preview_summary,
                    "rejection-preview": rejection_preview,
                    "approval-preview": approval_preview,
                    "first-start": selected_start,
                }
                if case == "same-run-id":
                    values["summary"]["run_id"] = started["run_id"]
                paths: dict[str, Path] = {}
                for name, value in values.items():
                    paths[name] = root / f"{name}.json"
                    paths[name].write_text(json.dumps(value), encoding="utf-8")
                command = [
                    CONTRACT_HELPER,
                    "write-report",
                    paths["summary"],
                    paths["artifact"],
                    "2026-08-23T12:01:00Z",
                    "https://203-0-113-42.sslip.io",
                    "colortrace-test-project",
                    "us-central1-a",
                    "ct-singlehost-vm",
                    "stage-0001",
                    root / "report.json",
                    "--rejection-summary",
                    paths["rejection"],
                    "--preview-summary",
                    paths["initial"],
                    "--rejection-reset-preview-summary",
                    paths["rejection-preview"],
                    "--approval-reset-preview-summary",
                    paths["approval-preview"],
                ]
                if case != "missing-first-start":
                    command.extend(("--first-start-summary", paths["first-start"]))
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 65)
                self.assertFalse((root / "report.json").exists())

    def test_legacy_terminal_projections_remain_resettable(self) -> None:
        for proof_version in (1, 3):
            with (
                self.subTest(proof_version=proof_version),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                _started, _approved, closed, _receipt, _reset = _workflow(
                    _artifact(), proof_version=proof_version
                )
                closed["schema"] = "colortrace-demo-run/v1"
                del closed["timeline"]
                run_path = root / "run.json"
                request_path = root / "request.json"
                run_path.write_text(json.dumps(closed), encoding="utf-8")
                completed = subprocess.run(
                    [CONTRACT_HELPER, "prepare-reset", run_path, request_path],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout.strip(), closed["run_id"])

    def test_reset_rejects_wrong_fixture_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = _artifact()
            _started, _approved, closed, _receipt, reset = _workflow(artifact)
            reset["restoration"]["fixture_id"] = "wrong-fixture"
            run_path = root / "run.json"
            reset_path = root / "reset.json"
            run_path.write_text(json.dumps(closed), encoding="utf-8")
            reset_path.write_text(json.dumps(reset), encoding="utf-8")
            completed = subprocess.run(
                [CONTRACT_HELPER, "verify-reset", reset_path, run_path],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 65)
            self.assertIn("reset-result-invalid", completed.stderr)


if __name__ == "__main__":
    unittest.main()
