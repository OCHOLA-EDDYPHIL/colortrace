from __future__ import annotations

import email
import json
import re
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from colortrace_repo.common import Finding, load_json, sorted_findings, walk_files

_LICENSE_EXPRESSION = "Apache-2.0"

# This explicit inventory makes additions and removals fail closed. A new first-party
# manifest must be deliberately added to the license policy in the same change.
_PYTHON_PROJECTS: dict[str, tuple[str, str | None]] = {
    "pyproject.toml": ("colortrace-workspace", None),
    "packages/api/pyproject.toml": ("colortrace-api", "colortrace_api/LICENSE"),
    "packages/evaluation/pyproject.toml": (
        "colortrace-evaluation",
        "colortrace_evaluation/LICENSE",
    ),
    "packages/fixture-generator/pyproject.toml": (
        "colortrace-fixture",
        "colortrace_fixture/LICENSE",
    ),
    "packages/grafana-mcp/pyproject.toml": (
        "colortrace-grafana-mcp",
        "colortrace_grafana_mcp/LICENSE",
    ),
    "packages/investigation/pyproject.toml": (
        "colortrace-investigation",
        "colortrace_investigation/LICENSE",
    ),
    "packages/persistence/pyproject.toml": (
        "colortrace-persistence",
        "colortrace_persistence/LICENSE",
    ),
    "packages/recovery/pyproject.toml": (
        "colortrace-recovery",
        "colortrace_recovery/LICENSE",
    ),
    "packages/repo-tools/pyproject.toml": ("colortrace-repo", "colortrace_repo/LICENSE"),
    "packages/response-plans/pyproject.toml": (
        "colortrace-response-plans",
        "colortrace_response_plans/LICENSE",
    ),
    "packages/simulator/pyproject.toml": (
        "colortrace-simulator",
        "colortrace_simulator/LICENSE",
    ),
    "packages/telemetry/pyproject.toml": (
        "colortrace-telemetry",
        "colortrace_telemetry/LICENSE",
    ),
    "packages/validators/pyproject.toml": (
        "colortrace-validator",
        "colortrace_validator/LICENSE",
    ),
    "packages/vertical-slice/pyproject.toml": (
        "colortrace-vertical-slice",
        "colortrace_vertical_slice/LICENSE",
    ),
}

_NPM_PROJECTS: dict[str, str] = {
    "package.json": "colortrace-workspace",
    "packages/api-client/package.json": "@colortrace/api-client",
    "packages/contracts/package.json": "@colortrace/contracts",
    "packages/web/package.json": "@colortrace/web",
    "packages/workspace-model/package.json": "@colortrace/workspace-model",
}


class DistributionMetadataError(ValueError):
    pass


def _normalize_python_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _lexical_relative_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            document = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise DistributionMetadataError(f"cannot load TOML: {error}") from error
    if not isinstance(document, dict):
        raise DistributionMetadataError("manifest must be a TOML object")
    return document


def _canonical_license(root: Path) -> tuple[bytes | None, list[Finding]]:
    path = root / "LICENSE"
    if not path.is_file() or path.is_symlink():
        return None, [
            Finding(
                "LICENSE",
                "distribution.license.missing",
                "canonical LICENSE must be a regular, non-symlink file",
            )
        ]
    try:
        return path.read_bytes(), []
    except OSError as error:
        return None, [Finding("LICENSE", "distribution.license.missing", str(error))]


def _manifest_inventory_findings(
    root: Path, filename: str, expected_paths: set[str]
) -> list[Finding]:
    discovered = {
        _lexical_relative_path(root, path) for path in walk_files(root, frozenset({filename}))
    }
    findings = [
        Finding(
            path,
            "distribution.metadata.missing",
            "expected first-party manifest is missing",
        )
        for path in sorted(expected_paths - discovered)
    ]
    findings.extend(
        Finding(
            path,
            "distribution.metadata.unexpected",
            "manifest is not registered in the first-party license inventory",
        )
        for path in sorted(discovered - expected_paths)
    )
    return findings


def _check_python_manifest(
    root: Path,
    relative: str,
    expected_name: str,
    wheel_license_path: str | None,
) -> list[Finding]:
    path = root / relative
    if path.is_symlink() or (path.exists() and not path.is_file()):
        return [
            Finding(
                relative,
                "distribution.metadata.invalid",
                "manifest must be a regular, non-symlink file",
            )
        ]
    if not path.is_file():
        return []
    findings: list[Finding] = []
    try:
        document = _load_toml(path)
        project = document.get("project")
        if not isinstance(project, dict):
            raise DistributionMetadataError("manifest must contain a project table")
    except DistributionMetadataError as error:
        return [Finding(relative, "distribution.metadata.invalid", str(error))]
    if project.get("name") != expected_name:
        findings.append(
            Finding(
                relative,
                "distribution.metadata.name",
                f"project name must equal {expected_name}",
            )
        )
    if project.get("license") != _LICENSE_EXPRESSION:
        findings.append(
            Finding(
                relative,
                "distribution.license.metadata",
                f"first-party Python project must declare license = {_LICENSE_EXPRESSION}",
            )
        )
    expected_license_files = ["LICENSE"] if wheel_license_path is None else []
    if project.get("license-files") != expected_license_files:
        findings.append(
            Finding(
                relative,
                "distribution.license.files",
                f"project must declare license-files = {expected_license_files!r}",
            )
        )
    if wheel_license_path is not None and not isinstance(document.get("build-system"), dict):
        findings.append(
            Finding(
                relative,
                "distribution.metadata.build-system",
                "wheel project must declare a build-system table",
            )
        )
    if wheel_license_path is not None:
        wheel_config: Any = document
        for key in ("tool", "hatch", "build", "targets", "wheel"):
            wheel_config = wheel_config.get(key) if isinstance(wheel_config, dict) else None
        force_include = (
            wheel_config.get("force-include") if isinstance(wheel_config, dict) else None
        )
        if (
            not isinstance(force_include, dict)
            or force_include.get("../../LICENSE") != wheel_license_path
        ):
            findings.append(
                Finding(
                    relative,
                    "distribution.license.force-include",
                    "wheel must force-include ../../LICENSE as " + wheel_license_path,
                )
            )
        local_license = path.parent / "LICENSE"
        if local_license.exists() or local_license.is_symlink():
            findings.append(
                Finding(
                    _lexical_relative_path(root, local_license),
                    "distribution.license.duplicate",
                    "wheel project must source its LICENSE only from the repository root",
                )
            )
    return findings


def _check_npm_manifest(root: Path, relative: str, expected_name: str) -> list[Finding]:
    path = root / relative
    if path.is_symlink() or (path.exists() and not path.is_file()):
        return [
            Finding(
                relative,
                "distribution.metadata.invalid",
                "manifest must be a regular, non-symlink file",
            )
        ]
    if not path.is_file():
        return []
    try:
        document = load_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [Finding(relative, "distribution.metadata.invalid", str(error))]
    if not isinstance(document, dict):
        return [
            Finding(relative, "distribution.metadata.invalid", "manifest must be a JSON object")
        ]
    findings: list[Finding] = []
    if document.get("name") != expected_name:
        findings.append(
            Finding(
                relative,
                "distribution.metadata.name",
                f"package name must equal {expected_name}",
            )
        )
    if document.get("license") != _LICENSE_EXPRESSION:
        findings.append(
            Finding(
                relative,
                "distribution.license.metadata",
                f"first-party npm project must declare license {_LICENSE_EXPRESSION}",
            )
        )
    return findings


def check_package_metadata(root: Path) -> list[Finding]:
    root = root.resolve()
    canonical_license, findings = _canonical_license(root)
    findings.extend(_manifest_inventory_findings(root, "pyproject.toml", set(_PYTHON_PROJECTS)))
    findings.extend(_manifest_inventory_findings(root, "package.json", set(_NPM_PROJECTS)))
    if canonical_license is None:
        return sorted_findings(findings)
    for relative, (expected_name, wheel_license_path) in _PYTHON_PROJECTS.items():
        findings.extend(
            _check_python_manifest(
                root,
                relative,
                expected_name,
                wheel_license_path,
            )
        )
    for relative, expected_name in _NPM_PROJECTS.items():
        findings.extend(_check_npm_manifest(root, relative, expected_name))
    return sorted_findings(findings)


def _expected_wheels() -> dict[str, str]:
    return {
        _normalize_python_name(name): license_path
        for name, license_path in _PYTHON_PROJECTS.values()
        if license_path is not None
    }


def check_distribution_wheels(root: Path, directory: Path) -> list[Finding]:
    root = root.resolve()
    canonical_license, findings = _canonical_license(root)
    if canonical_license is None:
        return findings
    directory_display = str(directory)
    if directory.is_symlink() or not directory.is_dir():
        return [
            Finding(
                directory_display,
                "distribution.wheel.directory",
                "wheel directory must be a regular, non-symlink directory",
            )
        ]
    directory = directory.resolve()

    expected = _expected_wheels()
    observed: set[str] = set()
    try:
        wheels = sorted(directory.glob("*.whl"))
    except OSError as error:
        return [Finding(str(directory), "distribution.wheel.directory", str(error))]
    for wheel in wheels:
        if not wheel.is_file() or wheel.is_symlink():
            findings.append(
                Finding(
                    wheel.name,
                    "distribution.wheel.invalid",
                    "wheel must be a regular, non-symlink file",
                )
            )
            continue
        try:
            with zipfile.ZipFile(wheel) as archive:
                names = archive.namelist()
                metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
                if len(metadata_names) != 1:
                    raise DistributionMetadataError(
                        "wheel must contain exactly one .dist-info/METADATA file"
                    )
                metadata_name = metadata_names[0]
                metadata = email.message_from_bytes(archive.read(metadata_name))
                raw_names = metadata.get_all("Name", [])
                if len(raw_names) != 1 or not isinstance(raw_names[0], str) or not raw_names[0]:
                    raise DistributionMetadataError("wheel metadata must contain exactly one Name")
                raw_name = raw_names[0]
                name = _normalize_python_name(raw_name)
                if name not in expected:
                    findings.append(
                        Finding(
                            wheel.name,
                            "distribution.wheel.unexpected",
                            f"wheel Name {raw_name} is not a registered first-party project",
                        )
                    )
                    continue
                if name in observed:
                    findings.append(
                        Finding(
                            wheel.name,
                            "distribution.wheel.duplicate",
                            f"multiple wheels were supplied for {raw_name}",
                        )
                    )
                observed.add(name)
                if metadata.get_all("License-Expression", []) != [_LICENSE_EXPRESSION]:
                    findings.append(
                        Finding(
                            wheel.name,
                            "distribution.wheel.license-expression",
                            f"{raw_name} must carry License-Expression: {_LICENSE_EXPRESSION}",
                        )
                    )
                license_name = expected[name]
                license_entries = [
                    entry for entry in names if PurePosixPath(entry).name == "LICENSE"
                ]
                if metadata.get_all("License-File", []):
                    findings.append(
                        Finding(
                            wheel.name,
                            "distribution.wheel.license-metadata",
                            f"{raw_name} must source LICENSE through the canonical force-include",
                        )
                    )
                if license_entries != [license_name]:
                    findings.append(
                        Finding(
                            wheel.name,
                            "distribution.wheel.license-file",
                            f"{raw_name} must carry exactly one LICENSE at {license_name}",
                        )
                    )
                elif archive.read(license_name) != canonical_license:
                    findings.append(
                        Finding(
                            wheel.name,
                            "distribution.wheel.license-stale",
                            f"{raw_name} wheel LICENSE differs from canonical root LICENSE",
                        )
                    )
        except (
            OSError,
            zipfile.BadZipFile,
            KeyError,
            RuntimeError,
            DistributionMetadataError,
        ) as error:
            findings.append(Finding(wheel.name, "distribution.wheel.invalid", str(error)))
    for name in sorted(expected.keys() - observed):
        findings.append(
            Finding(
                str(directory),
                "distribution.wheel.missing",
                f"missing first-party wheel {name}",
            )
        )
    return sorted_findings(findings)
