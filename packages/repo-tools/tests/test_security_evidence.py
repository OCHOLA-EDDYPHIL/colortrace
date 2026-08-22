from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from colortrace_repo.dependencies import resolved_locked_packages
from colortrace_repo.security_evidence import (
    _deployment_inputs,
    finalize_security_evidence,
    prepare_security_evidence,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
CANDIDATE = "a" * 40
TREE = "b" * 40
SCANNER = "scanner@sha256:" + "c" * 64


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class SecurityEvidenceTest(unittest.TestCase):
    def _write_passing_image_reports(self, output: Path) -> None:
        images = output / "images"
        images.mkdir(exist_ok=True)
        profiles = {
            "hosted-runtime": "hosted-readonly",
            "runtime": "private-full",
            "web": "public-readonly",
        }
        summary_images = []
        for image, profile in profiles.items():
            image_output = images / image
            image_output.mkdir()
            for name in ("raw-sbom.cdx.json", "enriched-sbom.cdx.json"):
                (image_output / name).write_text(
                    json.dumps(
                        {
                            "bomFormat": "CycloneDX",
                            "components": [{"name": "component"}],
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            reference = f"fixture-{image}:{CANDIDATE}"
            image_record = {
                "archive_index_sha256": "sha256:" + "0" * 64,
                "archive_sha256": "sha256:" + "1" * 64,
                "config_digest": "sha256:" + "2" * 64,
                "image_digest": "sha256:" + "3" * 64,
                "platform_manifest_digest": "sha256:" + "4" * 64,
                "reference": reference,
            }
            bundle = {
                "manifest_sha256": "sha256:" + "5" * 64,
                "sha256sums_sha256": "sha256:" + "6" * 64,
            }
            inputs = [
                {
                    "path": "Dockerfile.runtime" if image != "web" else "Dockerfile.web",
                    "sha256": "sha256:" + "7" * 64,
                    "size_bytes": 1,
                }
            ]
            coverage = {
                "bundle": bundle,
                "candidate": {"commit": CANDIDATE, "tree": TREE},
                "findings": [],
                "image": image_record,
                "profile": profile,
                "scanner_image": SCANNER,
                "schema": "colortrace-final-image-coverage/v1",
                "source_inputs": inputs,
                "status": "pass",
            }
            coverage_path = image_output / "coverage.json"
            coverage_path.write_text(json.dumps(coverage) + "\n", encoding="utf-8")
            binding = {
                "bundle": bundle,
                "candidate": {"commit": CANDIDATE, "tree": TREE},
                "image": image_record,
                "inputs": inputs,
                "profile": profile,
                "reports": {
                    "coverage_sha256": _sha256(coverage_path),
                    "enriched_sbom_sha256": _sha256(image_output / "enriched-sbom.cdx.json"),
                    "raw_sbom_sha256": _sha256(image_output / "raw-sbom.cdx.json"),
                },
                "scanner_image": SCANNER,
                "schema": "colortrace-final-image-binding/v1",
                "status": "pass",
            }
            (image_output / "image-binding.json").write_text(
                json.dumps(binding) + "\n", encoding="utf-8"
            )
            summary_images.append({"name": image, "profile": profile, "reference": reference})
        (images / "summary.json").write_text(
            json.dumps(
                {
                    "candidate": {"commit": CANDIDATE, "tree": TREE},
                    "findings": [],
                    "images": summary_images,
                    "scanner_image": SCANNER,
                    "schema": "colortrace-final-image-evidence/v1",
                    "status": "pass",
                }
            )
            + "\n",
            encoding="utf-8",
        )

    def test_deployment_inputs_use_git_candidate_and_exclude_ignored_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            infra = root / "infra"
            infra.mkdir()
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (infra / "main.tf").write_text("terraform {}\n", encoding="utf-8")
            (infra / ".terraform.lock.hcl").write_text("tracked\n", encoding="utf-8")
            (root / "Dockerfile.local").write_text("FROM scratch\n", encoding="utf-8")
            ignored = root / "ignored"
            ignored.mkdir()
            (ignored / "Dockerfile.private").write_text("private\n", encoding="utf-8")
            cache = root / ".cache"
            cache.mkdir()
            (cache / "generated.tf").write_text("private\n", encoding="utf-8")

            candidate_names = (
                b"Dockerfile\x00Dockerfile.local\x00infra/.terraform.lock.hcl\x00infra/main.tf\x00"
            )
            with mock.patch(
                "colortrace_repo.deployment.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stdout=candidate_names),
            ) as git_ls_files:
                self.assertEqual(
                    _deployment_inputs(root),
                    (
                        "Dockerfile",
                        "Dockerfile.local",
                        "infra/.terraform.lock.hcl",
                        "infra/main.tf",
                    ),
                )

            git_ls_files.assert_called_once_with(
                [
                    "git",
                    "-C",
                    str(root.resolve()),
                    "ls-files",
                    "-z",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                ],
                check=False,
                capture_output=True,
                timeout=5,
            )

    def test_sbom_is_deterministic_and_covers_every_resolved_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = root / "first"
            second = root / "second"

            self.assertEqual(prepare_security_evidence(REPOSITORY_ROOT, first), [])
            self.assertEqual(prepare_security_evidence(REPOSITORY_ROOT, second), [])

            first_bytes = (first / "sbom.cdx.json").read_bytes()
            self.assertEqual(first_bytes, (second / "sbom.cdx.json").read_bytes())
            document = json.loads(first_bytes)
            packages, findings = resolved_locked_packages(REPOSITORY_ROOT)
            self.assertEqual(findings, [])
            self.assertEqual(len(document["components"]), len(packages))
            references = [component["bom-ref"] for component in document["components"]]
            self.assertEqual(len(references), len(set(references)))
            self.assertEqual(document["dependencies"][0]["dependsOn"], references)

    def test_manifest_binds_candidate_inputs_tools_and_passing_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            self.assertEqual(prepare_security_evidence(REPOSITORY_ROOT, output), [])
            (output / "secret.json").write_text("[]\n", encoding="utf-8")
            (output / "vulnerability.json").write_text(
                json.dumps({"Results": [{"Vulnerabilities": None}]}) + "\n",
                encoding="utf-8",
            )
            self._write_passing_image_reports(output)

            findings = finalize_security_evidence(
                REPOSITORY_ROOT,
                output,
                candidate_sha=CANDIDATE,
                candidate_tree=TREE,
                scanner_image=SCANNER,
                scanner_metadata=json.dumps(
                    {
                        "Version": "0.69.3",
                        "VulnerabilityDB": {"UpdatedAt": "2026-08-18T00:00:00Z", "Version": 2},
                    }
                ),
                secret_scanner_image="secret@sha256:" + "d" * 64,
            )

            self.assertEqual(findings, [])
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "pass")
            self.assertEqual(manifest["candidate"]["commit"], CANDIDATE)
            self.assertEqual(
                {report["path"] for report in manifest["reports"]},
                {
                    "action-pins.json",
                    "ai-runtime.json",
                    "dependency.json",
                    "deployment.json",
                    "images/hosted-runtime/coverage.json",
                    "images/hosted-runtime/enriched-sbom.cdx.json",
                    "images/hosted-runtime/image-binding.json",
                    "images/hosted-runtime/raw-sbom.cdx.json",
                    "images/runtime/coverage.json",
                    "images/runtime/enriched-sbom.cdx.json",
                    "images/runtime/image-binding.json",
                    "images/runtime/raw-sbom.cdx.json",
                    "images/summary.json",
                    "images/web/coverage.json",
                    "images/web/enriched-sbom.cdx.json",
                    "images/web/image-binding.json",
                    "images/web/raw-sbom.cdx.json",
                    "runner-isolation.json",
                    "sbom.cdx.json",
                    "secret.json",
                    "vulnerability.json",
                    "vulnerability-scanner.json",
                },
            )
            self.assertTrue(
                all(value["sha256"].startswith("sha256:") for value in manifest["reports"])
            )
            input_paths = [value["path"] for value in manifest["inputs"]]
            self.assertEqual(len(input_paths), len(set(input_paths)))
            self.assertFalse(any(path.startswith((".cache/", ".git/")) for path in input_paths))

    def test_manifest_fails_closed_on_a_vulnerability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            self.assertEqual(prepare_security_evidence(REPOSITORY_ROOT, output), [])
            (output / "secret.json").write_text("[]\n", encoding="utf-8")
            (output / "vulnerability.json").write_text(
                json.dumps(
                    {
                        "Results": [
                            {
                                "Vulnerabilities": [
                                    {"Severity": "HIGH", "VulnerabilityID": "CVE-test"}
                                ]
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            self._write_passing_image_reports(output)

            findings = finalize_security_evidence(
                REPOSITORY_ROOT,
                output,
                candidate_sha=CANDIDATE,
                candidate_tree=TREE,
                scanner_image=SCANNER,
                scanner_metadata=json.dumps(
                    {
                        "Version": "0.69.3",
                        "VulnerabilityDB": {"UpdatedAt": "2026-08-18T00:00:00Z", "Version": 2},
                    }
                ),
                secret_scanner_image="secret@sha256:" + "d" * 64,
            )

            self.assertEqual({finding.code for finding in findings}, {"security.report.failed"})
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "fail")

    def test_manifest_rejects_a_stale_image_report_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory)
            self.assertEqual(prepare_security_evidence(REPOSITORY_ROOT, output), [])
            (output / "secret.json").write_text("[]\n", encoding="utf-8")
            (output / "vulnerability.json").write_text(
                json.dumps({"Results": [{"Vulnerabilities": None}]}) + "\n",
                encoding="utf-8",
            )
            self._write_passing_image_reports(output)
            coverage_path = output / "images" / "web" / "coverage.json"
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            coverage["candidate"]["tree"] = "e" * 40
            coverage_path.write_text(json.dumps(coverage) + "\n", encoding="utf-8")

            findings = finalize_security_evidence(
                REPOSITORY_ROOT,
                output,
                candidate_sha=CANDIDATE,
                candidate_tree=TREE,
                scanner_image=SCANNER,
                scanner_metadata=json.dumps(
                    {
                        "Version": "0.69.3",
                        "VulnerabilityDB": {
                            "UpdatedAt": "2026-08-18T00:00:00Z",
                            "Version": 2,
                        },
                    }
                ),
                secret_scanner_image="secret@sha256:" + "d" * 64,
            )

            self.assertIn("security.image.binding", {finding.code for finding in findings})
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "fail")


if __name__ == "__main__":
    unittest.main()
