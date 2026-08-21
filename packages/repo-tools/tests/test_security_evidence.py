from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from colortrace_repo.dependencies import resolved_locked_packages
from colortrace_repo.security_evidence import (
    finalize_security_evidence,
    prepare_security_evidence,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class SecurityEvidenceTest(unittest.TestCase):
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

            findings = finalize_security_evidence(
                REPOSITORY_ROOT,
                output,
                candidate_sha="a" * 40,
                candidate_tree="b" * 40,
                scanner_image="scanner@sha256:" + "c" * 64,
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
            self.assertEqual(manifest["candidate"]["commit"], "a" * 40)
            self.assertEqual(
                {report["path"] for report in manifest["reports"]},
                {
                    "action-pins.json",
                    "ai-runtime.json",
                    "dependency.json",
                    "deployment.json",
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

            findings = finalize_security_evidence(
                REPOSITORY_ROOT,
                output,
                candidate_sha="a" * 40,
                candidate_tree="b" * 40,
                scanner_image="scanner@sha256:" + "c" * 64,
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


if __name__ == "__main__":
    unittest.main()
