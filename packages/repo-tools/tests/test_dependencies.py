from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from colortrace_repo.dependencies import check_dependencies

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class DependencyPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "policy").mkdir()
        policy = (REPOSITORY_ROOT / "policy" / "dependency-policy.json").read_text(encoding="utf-8")
        (self.root / "policy" / "dependency-policy.json").write_text(policy, encoding="utf-8")
        self._write_manifests()
        self._write_locks()
        self._write_inventory()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write_manifests(self, python_requirement: str = "safe-python==1.0.0") -> None:
        (self.root / "pyproject.toml").write_text(
            f"""
[project]
name = "example-python"
version = "0.0.0"
dependencies = ["{python_requirement}"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        (self.root / "package.json").write_text(
            json.dumps(
                {
                    "name": "example-node",
                    "private": True,
                    "dependencies": {"safe-node": "1.0.0"},
                }
            ),
            encoding="utf-8",
        )

    def _write_locks(self) -> None:
        python_digest = "a" * 64
        artifact = (
            'sdist = { url = "https://files.pythonhosted.org/packages/safe-python.tar.gz", '
            f'hash = "sha256:{python_digest}" }}'
        )
        (self.root / "uv.lock").write_text(
            f"""
version = 1

[[package]]
name = "example-python"
version = "0.0.0"
source = {{ editable = "." }}

[[package]]
name = "safe-python"
version = "1.0.0"
source = {{ registry = "https://pypi.org/simple" }}
{artifact}
""".strip()
            + "\n",
            encoding="utf-8",
        )
        npm_digest = "A" * 48
        (self.root / "pnpm-lock.yaml").write_text(
            f"""
lockfileVersion: '9.0'

packages:

  safe-node@1.0.0:
    resolution: {{integrity: sha512-{npm_digest}}}
""".strip()
            + "\n",
            encoding="utf-8",
        )

    def _write_inventory(self, python_license: str = "MIT", include_node: bool = True) -> None:
        packages = [
            {
                "ecosystem": "pypi",
                "license": python_license,
                "name": "safe-python",
                "source": "https://pypi.org/simple",
                "version": "1.0.0",
            }
        ]
        if include_node:
            packages.append(
                {
                    "ecosystem": "npm",
                    "license": "Apache-2.0 OR MIT",
                    "name": "safe-node",
                    "source": "https://registry.npmjs.org",
                    "version": "1.0.0",
                }
            )
        (self.root / "policy" / "dependency-inventory.json").write_text(
            json.dumps({"schema_version": 1, "packages": packages}),
            encoding="utf-8",
        )

    def test_accepts_registry_sources_integrity_and_allowed_licenses(self) -> None:
        self.assertEqual(check_dependencies(self.root), [])

    def test_unknown_license_record_fails_closed(self) -> None:
        self._write_inventory(include_node=False)

        codes = {finding.code for finding in check_dependencies(self.root)}

        self.assertIn("dependency.license.unknown", codes)

    def test_disallowed_license_fails_closed(self) -> None:
        self._write_inventory(python_license="GPL-3.0-only")

        codes = {finding.code for finding in check_dependencies(self.root)}

        self.assertIn("dependency.license.disallowed", codes)

    def test_non_registry_runtime_dependency_fails_closed(self) -> None:
        self._write_manifests("unsafe-python @ git+https://code.invalid/source.git")

        codes = {finding.code for finding in check_dependencies(self.root)}

        self.assertIn("dependency.source.non-registry", codes)


if __name__ == "__main__":
    unittest.main()
