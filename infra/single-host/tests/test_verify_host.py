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


def _write_visuals(path: Path) -> None:
    path.mkdir()
    for kind, contents in VISUAL_BYTES.items():
        (path / f"{kind}.png").write_bytes(contents)


def _artifact() -> dict[str, Any]:
    registry = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
    components = ("runtime", "web", "caddy", "grafana", "loki", "tempo")
    images = {
        component: f"{registry}/{component}@sha256:{str(index) * 64}"
        for index, component in enumerate(components, 1)
    }
    images["prometheus"] = (
        "docker.io/prom/prometheus@sha256:"
        "5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
    )
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
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    run_id = "demo-run-" + "a" * 32
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
        "schema": "colortrace-demo-run/v1",
        "run_id": run_id,
        "incident_id": "incident-demo-" + "a" * 32,
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
                "sha256:5f6b1492ff35f92506e17310b3ea8b689c3f04c1fe0f6d4cc0a1f6e50bd52d93"
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
            started, approved, closed, receipt, reset = _workflow(artifact)
            responses = temporary / "responses"
            responses.mkdir()
            for name, value in (
                ("started", started),
                ("approved", approved),
                ("closed", closed),
                ("receipt", receipt),
                ("reset", reset),
                (
                    "conflict",
                    {"code": "demo-reset-required", "run_id": closed["run_id"]},
                ),
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

if "COLORTRACE_ACCESS_PASSWORD" in os.environ:
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
        print("colortrace-live-binding-ok")
    raise SystemExit(0)
raise SystemExit(2)
""",
                encoding="utf-8",
            )
            gcloud.chmod(0o755)

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
if "--write-out" in arguments and "%{content_type}" in arguments:
    kind = url.rsplit("/", 1)[-1]
    shutil.copyfile(responses / f"{kind}.png", output)
    print("image/png", end="")
    raise SystemExit(0)
if "--write-out" in arguments and "--data-binary" not in arguments:
    if not authenticated or "--user" in arguments:
        status = "401"
    elif url.endswith("/v1/session"):
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
        if os.environ.get("FAKE_INITIAL_CONFLICT") == "true" and not counter.exists():
            counter.touch()
            source, status = responses / "conflict.json", "409"
        else:
            source, status = responses / "started.json", "201"
    elif url.endswith("/approve"):
        source, status = responses / "approved.json", "200"
    elif url.endswith("/close"):
        source, status = responses / "closed.json", "200"
    elif url.endswith("/reset"):
        source, status = responses / "reset.json", "200"
    else:
        raise SystemExit(2)
    shutil.copyfile(source, output)
    print(status, end="")
    raise SystemExit(0)
if url.endswith("/receipt"):
    shutil.copyfile(responses / "receipt.json", output)
    raise SystemExit(0)
if "/v1/demo/runs/" in url:
    shutil.copyfile(responses / "closed.json", output)
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
                "FAKE_RESPONSES": str(responses),
                "FAKE_INITIAL_CONFLICT": "true",
                "FAKE_START_COUNTER": str(temporary / "start-counter"),
                "PATH": f"{binary_directory}:{os.environ['PATH']}",
            }
            completed = subprocess.run(
                [
                    SCRIPT,
                    "https://203-0-113-42.sslip.io",
                    "colortrace",
                    "colortrace-test-project",
                    "us-central1-a",
                    "ct-singlehost-vm",
                    "stage-0001",
                    admission,
                    output,
                ],
                check=False,
                capture_output=True,
                env=environment,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "colortrace-single-host-verification/v2")
            self.assertEqual(report["workflow"]["run_id"], started["run_id"])
            self.assertEqual(report["workflow"]["recovery_check_count"], 7)
            self.assertEqual(report["workflow"]["recovery_evidence_count"], 21)
            self.assertTrue(all(value == "pass" for value in report["checks"].values()))
            calls = [json.loads(line) for line in command_log.read_text().splitlines()]
            serialized_calls = json.dumps(calls)
            self.assertNotIn(password, serialized_calls)
            self.assertIn("docker restart colortrace-runtime", serialized_calls)
            self.assertIn("python -m colortrace_grafana_mcp.cli catalog", serialized_calls)
            self.assertNotIn("/opt/colortrace/bin/colortrace-grafana-mcp", serialized_calls)
            self.assertIn("colortrace-live-binding-ok", serialized_calls)
            self.assertIn("sha256:" + "7" * 64, serialized_calls)
            self.assertIn("unexpected_pre_drop", serialized_calls)
            self.assertIn("colortrace-internal", serialized_calls)
            reset_calls = [
                call
                for call in calls
                if call[0] == "curl" and "--data-binary" in call and call[-1].endswith("/reset")
            ]
            self.assertEqual(len(reset_calls), 2)
            private_port_calls = [call for call in calls if call[0] == "timeout"]
            self.assertEqual(
                sorted(int(call[-1]) for call in private_port_calls),
                [22, 80, 3000, 3100, 3200, 4318, 8080, 8443, 9090, 13000, 13100, 13200, 19090],
            )

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
