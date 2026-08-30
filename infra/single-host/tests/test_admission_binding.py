from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[3]
SCRIPT = ROOT / "infra/single-host/scripts/admission-binding.py"
BUILD_CONFIG = ROOT / "infra/single-host/cloudbuild.images.yaml"
OBSERVABILITY_LOCK = ROOT / "config/observability/images.lock.json"
FIXTURE_DIGESTS = ROOT / "packages/fixture-generator/fixtures/canonical-digests.json"
FROZEN_DATABASE_SHA256 = "sha256:eb94cd71f35e20ce5b572803f65009bb61a13a75f8d7c4f1f111ec732c98d314"
PROMETHEUS_REFERENCE = (
    "docker.io/prom/prometheus@sha256:"
    "5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
)


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


class AdmissionBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest = self.root / "build.json"
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.admission = self.root / "admission.tfvars.json"
        fixture = json.loads(FIXTURE_DIGESTS.read_text(encoding="utf-8"))
        fixture_digest = fixture["files"]["runtime/manifests/fixture-runtime-manifest.json"]
        commit = "1" * 40
        registry = "us-central1-docker.pkg.dev/colortrace-test-project/ct-singlehost-images"
        components = ("runtime", "web", "caddy", "grafana", "loki", "tempo")
        build_paths = {
            "runtime": ("containers/Dockerfile.runtime", "runtime"),
            "web": ("containers/Dockerfile.web", None),
            "caddy": ("containers/Dockerfile.caddy", None),
            "grafana": ("containers/Dockerfile.observability", "grafana"),
            "loki": ("containers/Dockerfile.observability", "loki"),
            "tempo": ("containers/Dockerfile.observability", "tempo"),
        }
        images = {}
        for index, component in enumerate(components, 1):
            digest = f"sha256:{str(index) * 64}"
            dockerfile, target = build_paths[component]
            images[component] = {
                "dockerfile": dockerfile,
                "target": target,
                "tag": f"{registry}/{component}:{commit}",
                "digest": digest,
                "reference": f"{registry}/{component}@{digest}",
            }
        self.build = {
            "schema": "colortrace-single-host-image-build/v2",
            "build": {
                "id": "build-123",
                "project": "colortrace-test-project",
                "region": "us-central1",
                "service_account": (
                    "projects/colortrace-test-project/serviceAccounts/"
                    "ct-singlehost-builder@colortrace-test-project.iam.gserviceaccount.com"
                ),
                "registry": registry,
                "config_sha256": _sha256(BUILD_CONFIG),
                "create_time": "2026-08-23T12:00:00Z",
                "finish_time": "2026-08-23T12:10:00Z",
            },
            "source": {
                "commit": commit,
                "tree": "2" * 40,
                "date_epoch": 1787486400,
            },
            "fixture_manifest_sha256": f"sha256:{fixture_digest}",
            "images": images,
        }
        _write_json(self.manifest, self.build)
        observability = json.loads(OBSERVABILITY_LOCK.read_text(encoding="utf-8"))
        scan_images = dict(images)
        scan_images["prometheus"] = {
            "reference": PROMETHEUS_REFERENCE,
            "upstream": observability["upstream"]["prometheus"],
        }
        _write_json(
            self.evidence / "current-db-metadata.json",
            {
                "Version": 2,
                "NextUpdate": "2026-08-24T12:00:00Z",
                "UpdatedAt": "2026-08-23T12:00:00Z",
                "DownloadedAt": "2026-08-23T12:10:00Z",
            },
        )
        _write_json(
            self.evidence / "frozen-db-metadata.json",
            {
                "Version": 2,
                "NextUpdate": "2026-08-23T12:57:22.518775968Z",
                "UpdatedAt": "2026-08-22T12:57:22.518776499Z",
                "DownloadedAt": "2026-08-23T12:10:00Z",
            },
        )
        _write_json(
            self.evidence / "scanner.json",
            {"Version": "0.69.3", "VulnerabilityDB": {"Version": 2}},
        )
        for database in ("current", "frozen"):
            for component, image in scan_images.items():
                _write_json(
                    self.evidence / f"{database}-{component}.json",
                    {
                        "SchemaVersion": 2,
                        "ArtifactName": (
                            image["reference"].removeprefix("docker.io/")
                            if component == "prometheus"
                            else image["reference"]
                        ),
                        "Results": [],
                    },
                )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(self, *arguments: object) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [SCRIPT, *(str(argument) for argument in arguments)],
            check=False,
            capture_output=True,
            text=True,
        )

    def _record(self) -> subprocess.CompletedProcess[str]:
        return self._run(
            "record-scan",
            self.manifest,
            OBSERVABILITY_LOCK,
            self.evidence,
            "sha256:" + "a" * 64,
            FROZEN_DATABASE_SHA256,
        )

    def _rewrite_checksums(self) -> None:
        lines = [
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(self.evidence.glob("*.json"))
        ]
        (self.evidence / "SHA256SUMS").write_text("".join(lines), encoding="ascii")

    def test_checked_scan_produces_one_hashed_terraform_admission(self) -> None:
        recorded = self._record()
        self.assertEqual(recorded.returncode, 0, recorded.stderr)
        scan = json.loads((self.evidence / "scan-bindings.json").read_text())
        self.assertEqual(scan["schema"], "colortrace-single-host-image-scan/v2")
        self.assertEqual(scan["build_manifest_sha256"], _sha256(self.manifest))
        self.assertEqual(scan["observability_lock_sha256"], _sha256(OBSERVABILITY_LOCK))
        self.assertEqual(len(scan["reports"]), 14)
        self.assertEqual(len((self.evidence / "SHA256SUMS").read_text().splitlines()), 18)

        prepared = self._run(
            "prepare", self.manifest, self.evidence / "scan-bindings.json", self.admission
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        self.assertEqual(os.stat(self.admission).st_mode & 0o777, 0o600)
        value = json.loads(self.admission.read_text())
        binding = value["deployment_artifact_binding"]
        canonical = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(
            value["deployment_artifact_binding_sha256"],
            f"sha256:{hashlib.sha256(canonical).hexdigest()}",
        )
        self.assertEqual(binding["images"]["prometheus"], PROMETHEUS_REFERENCE)
        self.assertEqual(
            binding["scanner"]["databases"]["frozen"]["content_sha256"], FROZEN_DATABASE_SHA256
        )

        normalized = self.root / "normalized.json"
        validated = self._run("validate-admission", self.admission, normalized)
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.assertEqual(json.loads(normalized.read_text()), binding)

    def test_build_with_wrong_cloud_build_configuration_hash_is_rejected(self) -> None:
        self.build["build"]["config_sha256"] = "sha256:" + "f" * 64
        _write_json(self.manifest, self.build)
        completed = self._run("validate-build", self.manifest)
        self.assertEqual(completed.returncode, 65)
        self.assertIn("build-config-digest-invalid", completed.stderr)

    def test_vulnerable_report_is_rejected_before_binding_is_recorded(self) -> None:
        report = self.evidence / "current-runtime.json"
        value = json.loads(report.read_text())
        value["Results"] = [{"Vulnerabilities": [{"VulnerabilityID": "CVE-test"}]}]
        _write_json(report, value)
        completed = self._record()
        self.assertEqual(completed.returncode, 65)
        self.assertIn("scan-report-vulnerable", completed.stderr)
        self.assertFalse((self.evidence / "scan-bindings.json").exists())

    def test_unrecognized_prometheus_artifact_name_is_rejected(self) -> None:
        report = self.evidence / "current-prometheus.json"
        value = json.loads(report.read_text())
        value["ArtifactName"] = "example.invalid/prometheus@sha256:" + "5" * 64
        _write_json(report, value)
        completed = self._record()
        self.assertEqual(completed.returncode, 65)
        self.assertIn("scan-report-invalid:current-prometheus.json", completed.stderr)

    def test_tampered_prometheus_reference_fails_even_with_new_checksums(self) -> None:
        self.assertEqual(self._record().returncode, 0)
        binding_path = self.evidence / "scan-bindings.json"
        binding = json.loads(binding_path.read_text())
        binding["images"]["prometheus"]["reference"] = (
            "docker.io/prom/prometheus@sha256:" + "f" * 64
        )
        _write_json(binding_path, binding)
        self._rewrite_checksums()
        completed = self._run("prepare", self.manifest, binding_path, self.admission)
        self.assertEqual(completed.returncode, 65)
        self.assertIn("scan-images-invalid", completed.stderr)

    def test_changed_report_fails_against_recorded_report_hash(self) -> None:
        self.assertEqual(self._record().returncode, 0)
        report = self.evidence / "frozen-web.json"
        report.write_text(report.read_text() + "\n", encoding="utf-8")
        completed = self._run(
            "prepare", self.manifest, self.evidence / "scan-bindings.json", self.admission
        )
        self.assertEqual(completed.returncode, 65)
        self.assertIn("scan-report-checksums-invalid", completed.stderr)


if __name__ == "__main__":
    unittest.main()
