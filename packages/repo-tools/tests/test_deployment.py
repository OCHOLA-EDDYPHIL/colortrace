from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from colortrace_repo.deployment import check_deployment

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class DeploymentPolicyTest(unittest.TestCase):
    def test_repository_deployment_sources_pass(self) -> None:
        self.assertEqual(check_deployment(REPOSITORY_ROOT), [])

    def test_rejects_mutable_and_non_google_deployment_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            infra = root / "infra"
            infra.mkdir()
            (infra / "main.tf").write_text(
                'terraform { required_version = ">= 1.0" }\n'
                'provider "aws" {}\n'
                'resource "aws_s3_bucket" "data" {}\n'
                'locals { image = "example.invalid/app:latest" }\n',
                encoding="utf-8",
            )
            (root / "Dockerfile").write_text(
                "FROM python:3.12\nADD https://example.invalid/tool /tool\n",
                encoding="utf-8",
            )

            codes = {finding.code for finding in check_deployment(root)}

            self.assertIn("deployment.terraform.provider", codes)
            self.assertIn("deployment.terraform.version", codes)
            self.assertIn("deployment.terraform.lock", codes)
            self.assertIn("deployment.container.base-mutable", codes)
            self.assertIn("deployment.container.download-mutable", codes)
            self.assertIn("deployment.image.mutable", codes)
            self.assertIn("deployment.runtime.provider", codes)

    def test_accepts_exact_google_provider_and_digest_pinned_container(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            infra = root / "infra"
            infra.mkdir()
            (infra / "main.tf").write_text(
                "terraform {\n"
                '  required_version = "= 1.15.9"\n'
                "  required_providers {\n"
                "    google = {\n"
                '      source  = "hashicorp/google"\n'
                '      version = "= 7.45.0"\n'
                "    }\n"
                "  }\n"
                "}\n"
                'resource "google_storage_bucket" "data" { name = "example" }\n',
                encoding="utf-8",
            )
            (infra / ".terraform.lock.hcl").write_text(
                'provider "registry.terraform.io/hashicorp/google" {\n'
                '  version     = "7.45.0"\n'
                '  constraints = "7.45.0"\n'
                "  hashes = [\n"
                '    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",\n'
                "  ]\n"
                "}\n",
                encoding="utf-8",
            )
            (root / "Dockerfile").write_text(
                "FROM python@sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )

            self.assertEqual(check_deployment(root), [])


if __name__ == "__main__":
    unittest.main()
