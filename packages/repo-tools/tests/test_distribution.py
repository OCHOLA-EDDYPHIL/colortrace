from __future__ import annotations

import json
import re
import shutil
import tempfile
import tomllib
import unittest
import warnings
import zipfile
from collections.abc import Mapping
from pathlib import Path

from colortrace_repo.common import Finding
from colortrace_repo.distribution import check_distribution_wheels, check_package_metadata

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class DistributionTest(unittest.TestCase):
    @staticmethod
    def _copy_metadata_tree(root: Path) -> None:
        shutil.copy2(REPOSITORY_ROOT / "LICENSE", root / "LICENSE")
        manifests = [
            REPOSITORY_ROOT / "pyproject.toml",
            REPOSITORY_ROOT / "package.json",
            *sorted((REPOSITORY_ROOT / "packages").glob("*/pyproject.toml")),
            *sorted((REPOSITORY_ROOT / "packages").glob("*/package.json")),
        ]
        for source in manifests:
            relative = source.relative_to(REPOSITORY_ROOT)
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

    @staticmethod
    def _wheel_projects() -> dict[str, str]:
        projects: dict[str, str] = {}
        for manifest in sorted((REPOSITORY_ROOT / "packages").glob("*/pyproject.toml")):
            with manifest.open("rb") as handle:
                document = tomllib.load(handle)
            if isinstance(document.get("build-system"), dict):
                wheel = document["tool"]["hatch"]["build"]["targets"]["wheel"]
                projects[str(document["project"]["name"])] = str(
                    wheel["force-include"]["../../LICENSE"]
                )
        return projects

    @staticmethod
    def _write_wheel(
        directory: Path,
        project_name: str,
        license_path: str,
        *,
        license_expression: str = "Apache-2.0",
        license_text: bytes | None = None,
        include_license_file: bool = True,
        schema_overrides: Mapping[str, bytes | None] | None = None,
    ) -> Path:
        normalized = re.sub(r"[-_.]+", "_", project_name)
        dist_info = f"{normalized}-1.0.0.dist-info"
        wheel = directory / f"{normalized}-1.0.0-py3-none-any.whl"
        metadata = (
            "Metadata-Version: 2.4\n"
            f"Name: {project_name}\n"
            "Version: 1.0.0\n"
            f"License-Expression: {license_expression}\n"
            "\n"
        ).encode()
        if license_text is None:
            license_text = (REPOSITORY_ROOT / "LICENSE").read_bytes()
        namespace = re.sub(r"[-_.]+", "_", project_name)
        schema_roots = sorted((REPOSITORY_ROOT / "packages").glob(f"*/src/{namespace}/schemas"))
        if len(schema_roots) > 1:
            raise AssertionError(f"multiple schema roots for {project_name}")
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(f"{dist_info}/METADATA", metadata)
            if include_license_file:
                archive.writestr(license_path, license_text)
            if schema_roots:
                for source in sorted(schema_roots[0].rglob("*.schema.json")):
                    member = f"{namespace}/schemas/{source.relative_to(schema_roots[0]).as_posix()}"
                    override = (schema_overrides or {}).get(member, source.read_bytes())
                    if override is not None:
                        archive.writestr(member, override)
        return wheel

    def test_repository_metadata_is_complete(self) -> None:
        self.assertEqual(check_package_metadata(REPOSITORY_ROOT), [])

    def test_metadata_check_rejects_wrong_and_duplicate_license_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._copy_metadata_tree(root)
            package_json = json.loads((root / "package.json").read_text(encoding="utf-8"))
            package_json["license"] = "MIT"
            (root / "package.json").write_text(json.dumps(package_json), encoding="utf-8")
            api_manifest = root / "packages" / "api" / "pyproject.toml"
            api_manifest.write_text(
                api_manifest.read_text(encoding="utf-8").replace(
                    '"../../LICENSE" = "colortrace_api/LICENSE"',
                    '"../LICENSE" = "colortrace_api/LICENSE"',
                ),
                encoding="utf-8",
            )
            (root / "packages" / "api" / "LICENSE").write_text("stale\n", encoding="utf-8")

            codes = {finding.code for finding in check_package_metadata(root)}

            self.assertIn("distribution.license.metadata", codes)
            self.assertIn("distribution.license.force-include", codes)
            self.assertIn("distribution.license.duplicate", codes)

    def test_metadata_inventory_fails_closed_on_addition_and_removal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._copy_metadata_tree(root)
            (root / "packages" / "api" / "pyproject.toml").unlink()
            unexpected = root / "packages" / "unregistered" / "pyproject.toml"
            unexpected.parent.mkdir(parents=True)
            unexpected.write_text(
                '[project]\nname = "colortrace-unregistered"\nversion = "1.0.0"\n'
                'license = "Apache-2.0"\nlicense-files = ["LICENSE"]\n',
                encoding="utf-8",
            )

            codes = {finding.code for finding in check_package_metadata(root)}

            self.assertIn("distribution.metadata.missing", codes)
            self.assertIn("distribution.metadata.unexpected", codes)

    def test_metadata_inventory_does_not_resolve_unregistered_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self._copy_metadata_tree(root)
            unexpected = root / "packages" / "unregistered" / "pyproject.toml"
            unexpected.parent.mkdir(parents=True)
            unexpected.symlink_to(root / "packages" / "api" / "pyproject.toml")

            findings = check_package_metadata(root)

            self.assertIn(
                Finding(
                    "packages/unregistered/pyproject.toml",
                    "distribution.metadata.unexpected",
                    "manifest is not registered in the first-party license inventory",
                ),
                findings,
            )

    def test_wheel_check_requires_all_twelve_exact_license_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            projects = self._wheel_projects()
            names = list(projects)
            self.assertEqual(len(projects), 12)
            wheels = {
                name: self._write_wheel(directory, name, license_path)
                for name, license_path in projects.items()
            }
            self.assertEqual(check_distribution_wheels(REPOSITORY_ROOT, directory), [])

            self._write_wheel(
                directory,
                names[0],
                projects[names[0]],
                license_expression="MIT",
            )
            self._write_wheel(
                directory,
                names[1],
                projects[names[1]],
                license_text=b"stale\n",
            )
            wheels[names[2]].unlink()
            self._write_wheel(
                directory,
                names[3],
                projects[names[3]],
                include_license_file=False,
            )
            self._write_wheel(
                directory,
                "colortrace-unregistered",
                "colortrace_unregistered/LICENSE",
            )

            codes = {
                finding.code for finding in check_distribution_wheels(REPOSITORY_ROOT, directory)
            }
            self.assertIn("distribution.wheel.license-expression", codes)
            self.assertIn("distribution.wheel.license-stale", codes)
            self.assertIn("distribution.wheel.license-file", codes)
            self.assertIn("distribution.wheel.missing", codes)
            self.assertIn("distribution.wheel.unexpected", codes)

    def test_wheel_check_rejects_symlinked_directory_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            directory = root / "wheels"
            directory.mkdir()
            for name, license_path in self._wheel_projects().items():
                self._write_wheel(directory, name, license_path)
            symlink = root / "wheel-link"
            symlink.symlink_to(directory, target_is_directory=True)

            findings = check_distribution_wheels(REPOSITORY_ROOT, symlink)

            self.assertEqual(
                {finding.code for finding in findings},
                {"distribution.wheel.directory"},
            )

    def test_wheel_check_rejects_duplicate_missing_stale_and_unexpected_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            projects = self._wheel_projects()
            wheels = {
                name: self._write_wheel(directory, name, license_path)
                for name, license_path in projects.items()
            }
            duplicate_member = (
                "colortrace_evaluation/schemas/manual-no-gemini-observation-v1.schema.json"
            )
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(wheels["colortrace-evaluation"], "a") as archive:
                    archive.writestr(duplicate_member, archive.read(duplicate_member))
                    archive.writestr(
                        "colortrace_evaluation/schemas/unregistered.schema.json",
                        b"{}\n",
                    )
            self._write_wheel(
                directory,
                "colortrace-investigation",
                projects["colortrace-investigation"],
                schema_overrides={
                    "colortrace_investigation/schemas/alert-intake-v1.schema.json": None,
                },
            )
            self._write_wheel(
                directory,
                "colortrace-vertical-slice",
                projects["colortrace-vertical-slice"],
                schema_overrides={
                    "colortrace_vertical_slice/schemas/incident-task-v1.schema.json": b"{}\n",
                },
            )

            codes = {
                finding.code for finding in check_distribution_wheels(REPOSITORY_ROOT, directory)
            }

            self.assertIn("distribution.wheel.member-duplicate", codes)
            self.assertIn("distribution.wheel.schema-member", codes)
            self.assertIn("distribution.wheel.schema-stale", codes)
            self.assertIn("distribution.wheel.schema-unexpected", codes)


if __name__ == "__main__":
    unittest.main()
