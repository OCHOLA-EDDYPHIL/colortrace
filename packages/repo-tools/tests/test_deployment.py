from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from colortrace_repo.deployment import check_deployment

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
GOOGLE_VERSION = "7.45.0"
IMAGE_DIGEST = "sha256:" + "a" * 64
DOWNLOAD_DIGEST = "sha256:" + "b" * 64
ZH_DIGEST = "zh:" + "c" * 64


def _write_lock(infra: Path, *, version: str = GOOGLE_VERSION) -> None:
    (infra / ".terraform.lock.hcl").write_text(
        'provider "registry.terraform.io/hashicorp/google" {\n'
        f'  version     = "{version}"\n'
        f'  constraints = "{version}"\n'
        "  hashes = [\n"
        '    "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",\n'
        f'    "{ZH_DIGEST}",\n'
        "  ]\n"
        "}\n",
        encoding="utf-8",
    )


def _write_valid_root(root: Path, *, child_module: bool = False) -> None:
    infra = root / "infra"
    infra.mkdir()
    module_source = ""
    if child_module:
        child = infra / "modules" / "storage"
        child.mkdir(parents=True)
        (child / "main.tf").write_text(
            'resource "google_storage_bucket" "child" { name = "child" }\n',
            encoding="utf-8",
        )
        module_source = 'module "storage" { source = "./modules/storage" }\n'
    (infra / "main.tf").write_text(
        "# AWS and OpenAI are not deployment providers.\n"
        "terraform {\n"
        '  required_version = "= 1.15.9"\n'
        "  required_providers {\n"
        "    google = {\n"
        '      source  = "hashicorp/google"\n'
        f'      version = "= {GOOGLE_VERSION}"\n'
        "    }\n"
        "  }\n"
        "}\n"
        'provider "google" {}\n'
        f"{module_source}"
        'resource "google_storage_bucket" "data" { name = "example" }\n',
        encoding="utf-8",
    )
    _write_lock(infra)
    (root / "Dockerfile").write_text(
        f"FROM python@{IMAGE_DIGEST} AS builder\n"
        "FROM scratch AS empty\n"
        "FROM builder AS runtime\n"
        f"ADD --checksum={DOWNLOAD_DIGEST} \\\n"
        "    https://example.invalid/tool \\\n"
        "    /usr/local/bin/tool\n",
        encoding="utf-8",
    )


class DeploymentPolicyTest(unittest.TestCase):
    def test_repository_deployment_sources_pass(self) -> None:
        self.assertEqual(check_deployment(REPOSITORY_ROOT), [])

    def test_rejects_nonexact_versions_provider_image_and_download(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            infra = root / "infra"
            infra.mkdir()
            (infra / "main.tf").write_text(
                "terraform {\n"
                '  required_version = ">= 1.0"\n'
                "  required_providers {\n"
                "    google = {\n"
                '      source  = "hashicorp/google"\n'
                '      version = "~> 7.0"\n'
                "    }\n"
                "  }\n"
                "}\n"
                'provider "kubernetes" {}\n'
                'resource "google_storage_bucket" "data" { name = "example" }\n'
                'locals { image = "example.invalid/app:v1" }\n',
                encoding="utf-8",
            )
            _write_lock(infra, version="7.44.0")
            (root / "Dockerfile").write_text(
                "FROM python@sha256:abcd\nADD \\\n    https://example.invalid/tool \\\n    /tool\n",
                encoding="utf-8",
            )

            codes = {finding.code for finding in check_deployment(root)}

            self.assertIn("deployment.terraform.provider", codes)
            self.assertIn("deployment.terraform.version", codes)
            self.assertIn("deployment.terraform.lock", codes)
            self.assertIn("deployment.container.base-mutable", codes)
            self.assertIn("deployment.container.download-mutable", codes)
            self.assertIn("deployment.image.mutable", codes)

    def test_accepts_comments_local_modules_internal_stages_and_multiline_add(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write_valid_root(root, child_module=True)

            self.assertEqual(check_deployment(root), [])

    def test_dynamic_terraform_image_is_not_misclassified_as_a_literal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write_valid_root(root)
            main = root / "infra" / "main.tf"
            main.write_text(
                main.read_text(encoding="utf-8")
                + 'locals { runtime_image = "registry.example/${var.name}@${var.digest}" }\n',
                encoding="utf-8",
            )

            self.assertEqual(check_deployment(root), [])

    def test_rejects_remote_modules_and_lock_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write_valid_root(root)
            main = root / "infra" / "main.tf"
            main.write_text(
                main.read_text(encoding="utf-8")
                + 'module "remote" { source = "example/remote/google" }\n',
                encoding="utf-8",
            )
            _write_lock(root / "infra", version="7.44.0")

            codes = {finding.code for finding in check_deployment(root)}

            self.assertIn("deployment.terraform.module", codes)
            self.assertIn("deployment.terraform.lock", codes)

    def test_local_modules_must_resolve_inside_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            sandbox = Path(temporary_directory)
            root = sandbox / "candidate"
            root.mkdir()
            _write_valid_root(root)
            external = sandbox / "external"
            external.mkdir()
            (external / "main.tf").write_text(
                'resource "google_storage_bucket" "external" { name = "external" }\n',
                encoding="utf-8",
            )
            main = root / "infra" / "main.tf"
            main.write_text(
                main.read_text(encoding="utf-8")
                + 'module "escape" { source = "../../external" }\n',
                encoding="utf-8",
            )

            codes = {finding.code for finding in check_deployment(root)}

            self.assertIn("deployment.terraform.module", codes)

    def test_module_graph_allows_candidate_sibling_and_detects_independent_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write_valid_root(root)
            shared = root / "shared"
            shared.mkdir()
            (shared / "main.tf").write_text(
                'resource "google_storage_bucket" "shared" { name = "shared" }\n',
                encoding="utf-8",
            )
            main = root / "infra" / "main.tf"
            main.write_text(
                main.read_text(encoding="utf-8") + 'module "shared" { source = "../shared" }\n',
                encoding="utf-8",
            )

            self.assertEqual(check_deployment(root), [])

            standalone = root / "infra" / "examples" / "standalone"
            standalone.mkdir(parents=True)
            (standalone / "main.tf").write_text(
                "terraform {\n"
                '  required_version = "= 1.15.9"\n'
                "  required_providers {\n"
                "    google = {\n"
                '      source = "hashicorp/google"\n'
                f'      version = "= {GOOGLE_VERSION}"\n'
                "    }\n"
                "  }\n"
                "}\n"
                'resource "google_storage_bucket" "standalone" { name = "standalone" }\n',
                encoding="utf-8",
            )

            codes = {finding.code for finding in check_deployment(root)}

            self.assertIn("deployment.terraform.lock", codes)

    def test_rejects_spoofed_exact_assignments_and_invalid_lock_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            infra = root / "infra"
            infra.mkdir()
            (infra / "main.tf").write_text(
                "terraform {\n"
                '  required_version = ">= 1.0"\n'
                "  required_providers {\n"
                "    google = {\n"
                '      source  = "hashicorp/google"\n'
                '      version = ">= 7.0"\n'
                "    }\n"
                "  }\n"
                "}\n"
                'locals { first_version = "= 1.15.9"; second_version = "= 7.45.0" }\n',
                encoding="utf-8",
            )
            (infra / ".terraform.lock.hcl").write_text(
                'provider "registry.terraform.io/hashicorp/google" {\n'
                '  version = "7.45.0"\n'
                '  constraints = "7.45.0"\n'
                '  hashes = ["h1:short", "zh:not-a-digest"]\n'
                "}\n",
                encoding="utf-8",
            )

            codes = {finding.code for finding in check_deployment(root)}

            self.assertIn("deployment.terraform.version", codes)
            self.assertIn("deployment.terraform.lock", codes)

    def test_accepts_exact_terraform_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            infra = root / "infra"
            infra.mkdir()
            (infra / "main.tf.json").write_text(
                "{\n"
                '  "terraform": {\n'
                '    "required_version": "= 1.15.9",\n'
                '    "required_providers": {\n'
                '      "google": {"source": "hashicorp/google", "version": "= 7.45.0"}\n'
                "    }\n"
                "  },\n"
                '  "provider": {"google": [{}]},\n'
                '  "resource": {"google_storage_bucket": {"data": {"name": "example"}}}\n'
                "}\n",
                encoding="utf-8",
            )
            _write_lock(infra)

            self.assertEqual(check_deployment(root), [])


if __name__ == "__main__":
    unittest.main()
