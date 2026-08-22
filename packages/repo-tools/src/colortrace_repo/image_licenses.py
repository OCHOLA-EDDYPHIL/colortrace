from __future__ import annotations

import argparse
import email.policy
import hashlib
import json
import platform
import re
import shutil
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

_HEX40 = re.compile(r"[0-9a-f]{40}")
_GO_BUILD_INFO_MAGIC = b"\xff Go buildinf:"
_LICENSE_NAMES = ("license", "notice", "copying", "authors")
# Keep this fail-closed inventory aligned with the installable Python projects in
# distribution.py. The repository root is deliberately absent because its
# ``tool.uv.package`` setting is false.
FIRST_PARTY_PYTHON_DISTRIBUTIONS = frozenset(
    {
        "colortrace-api",
        "colortrace-evaluation",
        "colortrace-fixture",
        "colortrace-grafana-mcp",
        "colortrace-investigation",
        "colortrace-persistence",
        "colortrace-recovery",
        "colortrace-repo",
        "colortrace-response-plans",
        "colortrace-simulator",
        "colortrace-telemetry",
        "colortrace-validator",
        "colortrace-vertical-slice",
    }
)


class BundleError(ValueError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _require_file(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise BundleError(f"{description} must be a regular, non-symlink file: {path}")
    return path


def _require_directory(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise BundleError(f"{description} must be a non-symlink directory: {path}")
    return path


def _require_contained_file(root: Path, path: Path, description: str) -> Path:
    root = _require_directory(root.absolute(), description)
    candidate = path.absolute()
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise BundleError(f"{description} escapes its input root: {path}") from error
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise BundleError(f"{description} has a symlink path component: {path}")
    _require_file(current, description)
    try:
        current.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise BundleError(f"{description} escapes its input root: {path}") from error
    return current


def _copy_source(source: Path, output: Path, relative: str) -> dict[str, str]:
    _require_file(source, "bundle source")
    destination_relative = PurePosixPath(relative)
    if destination_relative.is_absolute() or ".." in destination_relative.parts:
        raise BundleError(f"unsafe bundle path: {relative}")
    destination = output.joinpath(*destination_relative.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)
    return {"path": destination_relative.as_posix(), "sha256": _sha256(destination)}


def _write_source(output: Path, relative: str, content: bytes) -> dict[str, str]:
    destination_relative = PurePosixPath(relative)
    if destination_relative.is_absolute() or ".." in destination_relative.parts:
        raise BundleError(f"unsafe bundle path: {relative}")
    destination = output.joinpath(*destination_relative.parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o644)
    return {"path": destination_relative.as_posix(), "sha256": _sha256(destination)}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o644)


def _read_uvarint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            raise BundleError("truncated Go build-info varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
    raise BundleError("invalid Go build-info varint")


def _go_build_info(binary: Path) -> tuple[str, str]:
    data = _require_file(binary, "Go binary").read_bytes()
    position = data.find(_GO_BUILD_INFO_MAGIC)
    if position < 0:
        raise BundleError("Go build-info header is absent")
    header = data[position : position + 32]
    if len(header) != 32 or header[14] not in (4, 8) or header[15] & 2 == 0:
        raise BundleError("Go binary does not use supported inline build info")
    position += 32
    version_length, position = _read_uvarint(data, position)
    version = data[position : position + version_length].decode("utf-8")
    position += version_length
    module_length, position = _read_uvarint(data, position)
    framed = data[position : position + module_length]
    if len(framed) != module_length or len(framed) < 32:
        raise BundleError("truncated Go module build info")
    module_text = framed[16:-16].decode("utf-8")
    if not module_text.startswith("path\t"):
        raise BundleError("invalid Go module build info")
    return version, module_text


def _go_components(
    module_text: str,
    lock: dict[str, Any],
    license_source: dict[str, str],
) -> list[dict[str, Any]]:
    records = [line.split("\t") for line in module_text.splitlines() if line]
    module = next((record for record in records if record[0] == "mod"), None)
    if module is None or len(module) < 3:
        raise BundleError("Go build info has no main module")
    if (
        module[1] != "github.com/grafana/mcp-grafana"
        or module[2].removeprefix("v") != lock["release_version"]
    ):
        raise BundleError("mcp-grafana build info does not match its runtime lock")
    vcs_revision = next(
        (
            record[1].removeprefix("vcs.revision=")
            for record in records
            if len(record) == 2 and record[0] == "build" and record[1].startswith("vcs.revision=")
        ),
        None,
    )
    if vcs_revision != lock["source_commit"]:
        raise BundleError("mcp-grafana source revision does not match its runtime lock")
    components: list[dict[str, Any]] = [
        {
            "kind": "go-module",
            "license_evidence_status": "delivered-text",
            "license_expression": "Apache-2.0",
            "license_sources": [license_source],
            "name": module[1],
            "owner_legal_status": "pending",
            "source_commit": vcs_revision,
            "source_url": lock["source_repository"],
            "version": module[2],
        }
    ]
    dependency_count = 0
    for record in records:
        if record[0] != "dep" or len(record) not in (3, 4):
            continue
        dependency_count += 1
        name, version = record[1:3]
        components.append(
            {
                "kind": "go-module",
                "license_evidence_status": "unresolved",
                "license_expression": None,
                "name": name,
                "owner_legal_status": "pending",
                "source_checksum": record[3] if len(record) == 4 else None,
                "source_url": f"https://pkg.go.dev/{name}@{version}",
                "version": version,
            }
        )
    if dependency_count == 0:
        raise BundleError("mcp-grafana build info has no dependency closure")
    return components


def _parse_apk_database(path: Path, source: dict[str, str]) -> list[dict[str, Any]]:
    text = _require_file(path, "Alpine installed database").read_text(encoding="utf-8")
    components: list[dict[str, Any]] = []
    for raw_record in text.split("\n\n"):
        if not raw_record.strip():
            continue
        fields: dict[str, str] = {}
        for line in raw_record.splitlines():
            if len(line) >= 2 and line[1] == ":" and line[0] in "PVALUoc":
                fields.setdefault(line[0], line[2:])
        if "P" not in fields or "V" not in fields:
            continue
        license_expression = fields.get("L") or None
        source_commit = fields.get("c") or None
        components.append(
            {
                "architecture": fields.get("A") or None,
                "kind": "apk",
                "license_evidence_status": (
                    "declared-in-installed-database" if license_expression else "unresolved"
                ),
                "license_expression": license_expression,
                "license_source": source,
                "name": fields["P"],
                "owner_legal_status": (
                    "pending" if license_expression and "GPL" in license_expression else None
                ),
                "source_commit": source_commit,
                "source_commit_url": (
                    f"https://gitlab.alpinelinux.org/alpine/aports/-/commit/{source_commit}"
                    if source_commit
                    else None
                ),
                "source_origin": fields.get("o") or None,
                "upstream_url": fields.get("U") or None,
                "version": fields["V"],
            }
        )
    if not components:
        raise BundleError("Alpine installed database has no package records")
    return components


def _safe_metadata_license(site_packages: Path, dist_info: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise BundleError(f"unsafe Python License-File value: {value}")
    candidates = (
        dist_info / "licenses" / Path(*relative.parts),
        dist_info / Path(*relative.parts),
        site_packages / Path(*relative.parts),
    )
    for candidate in candidates:
        if candidate.is_file() or candidate.is_symlink():
            return _require_contained_file(site_packages, candidate, "Python license source")
    raise BundleError(f"declared Python License-File is missing: {value}")


def _python_components(
    site_packages: Path,
    output: Path,
    provenance: dict[str, Any],
    root_license: dict[str, str],
    source_group: str,
) -> list[dict[str, Any]]:
    site_packages = _require_directory(site_packages, "Python site-packages")
    components: list[dict[str, Any]] = []
    metadata_paths = sorted(site_packages.glob("*.dist-info/METADATA"))
    if not metadata_paths:
        raise BundleError("Python site-packages has no installed metadata")
    for metadata_path in metadata_paths:
        metadata_path = _require_contained_file(
            site_packages, metadata_path, "Python distribution metadata"
        )
        dist_info = metadata_path.parent
        message = BytesParser(policy=email.policy.compat32).parsebytes(metadata_path.read_bytes())
        name = message.get("Name")
        version = message.get("Version")
        if not name or not version:
            raise BundleError(f"Python metadata has no Name/Version: {metadata_path}")
        destination_root = f"sources/python/{source_group}/{dist_info.name}"
        sources = [_copy_source(metadata_path, output, f"{destination_root}/METADATA")]
        license_files: set[Path] = set()
        for value in message.get_all("License-File", []) or []:
            source = _safe_metadata_license(site_packages, dist_info, value)
            license_files.add(source)
        for candidate in dist_info.rglob("*"):
            if candidate.is_file() and candidate.name.lower().startswith(_LICENSE_NAMES):
                license_files.add(
                    _require_contained_file(site_packages, candidate, "Python license source")
                )
        for source in sorted(license_files):
            try:
                relative = source.relative_to(dist_info)
            except ValueError as error:
                try:
                    relative = source.relative_to(site_packages)
                except ValueError:
                    raise BundleError("Python license source escapes site-packages") from error
            sources.append(
                _copy_source(source, output, f"{destination_root}/{relative.as_posix()}")
            )
        license_expression = message.get("License-Expression") or None
        legacy_license = message.get("License") or None
        normalized_name = re.sub(r"[-_.]+", "-", name).lower()
        if normalized_name in FIRST_PARTY_PYTHON_DISTRIBUTIONS:
            sources.append(root_license)
        components.append(
            {
                "kind": "python-distribution",
                "license_evidence_status": (
                    "delivered-text"
                    if len(sources) > 1
                    else "declared-in-metadata"
                    if license_expression or legacy_license
                    else "unresolved"
                ),
                "legacy_license": legacy_license,
                "license_expression": license_expression,
                "license_sources": sources,
                "name": name,
                "owner_legal_status": "pending"
                if "GPL" in (license_expression or "") or "GPL" in (legacy_license or "")
                else None,
                "provenance": provenance,
                "project_urls": sorted(message.get_all("Project-URL", []) or []),
                "version": version,
            }
        )
    return components


def _embedded_python_wheel(
    wheel: Path,
    output: Path,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    wheel = _require_file(wheel, "embedded Python wheel")
    try:
        with zipfile.ZipFile(wheel) as archive:
            members = archive.infolist()
            names = [member.filename for member in members]
            if len(names) != len(set(names)):
                raise BundleError("embedded Python wheel has duplicate members")
            for member_name in names:
                relative = PurePosixPath(member_name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise BundleError(f"embedded Python wheel has unsafe member: {member_name}")
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise BundleError("embedded Python wheel must have exactly one METADATA")
            metadata_name = metadata_names[0]
            metadata_content = archive.read(metadata_name)
            message = BytesParser(policy=email.policy.compat32).parsebytes(metadata_content)
            name = message.get("Name")
            version = message.get("Version")
            if not name or not version:
                raise BundleError("embedded Python wheel METADATA has no Name/Version")
            dist_info = PurePosixPath(metadata_name).parent
            license_names = {
                member_name
                for member_name in names
                if PurePosixPath(member_name).parent == dist_info
                and PurePosixPath(member_name).name.lower().startswith(_LICENSE_NAMES)
            }
            for value in message.get_all("License-File", []) or []:
                relative = PurePosixPath(value)
                if relative.is_absolute() or ".." in relative.parts:
                    raise BundleError(f"unsafe embedded Python License-File value: {value}")
                candidates = {
                    (dist_info / relative).as_posix(),
                    (dist_info / "licenses" / relative).as_posix(),
                }
                matches = candidates & set(names)
                if not matches:
                    raise BundleError(f"embedded Python License-File is missing: {value}")
                license_names.update(matches)
            destination_root = f"sources/python/base-image/ensurepip/{dist_info.name}"
            sources = [_write_source(output, f"{destination_root}/METADATA", metadata_content)]
            sources.extend(
                _write_source(
                    output,
                    f"{destination_root}/{PurePosixPath(member_name).name}",
                    archive.read(member_name),
                )
                for member_name in sorted(license_names)
            )
    except (OSError, zipfile.BadZipFile) as error:
        raise BundleError(f"cannot read embedded Python wheel: {error}") from error
    wheel_source = _copy_source(wheel, output, f"sources/python/base-image/ensurepip/{wheel.name}")
    license_expression = message.get("License-Expression") or None
    legacy_license = message.get("License") or None
    return {
        "archive_sha256": _sha256(wheel),
        "kind": "embedded-python-wheel",
        "legacy_license": legacy_license,
        "license_evidence_status": "delivered-text" if len(sources) > 1 else "unresolved",
        "license_expression": license_expression,
        "license_sources": sources,
        "name": name,
        "owner_legal_status": "pending"
        if "GPL" in (license_expression or "") or "GPL" in (legacy_license or "")
        else None,
        "package_source": wheel_source,
        "provenance": provenance,
        "version": version,
    }


def _os_component(os_release: Path, source: dict[str, str]) -> dict[str, Any]:
    values: dict[str, str] = {}
    for line in _require_file(os_release, "os-release").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return {
        "kind": "operating-system-aggregate",
        "license_evidence_status": "unresolved",
        "license_expression": None,
        "license_source": source,
        "name": values.get("NAME", "Alpine Linux"),
        "owner_legal_status": "pending",
        "source_url": values.get("HOME_URL"),
        "version": values.get("VERSION_ID"),
    }


def _common_bundle(
    args: argparse.Namespace,
    output: Path,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if not _HEX40.fullmatch(args.source_commit) or not _HEX40.fullmatch(args.source_tree):
        raise BundleError("source commit and tree must be lowercase 40-character hashes")
    if not re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", args.base_image):
        raise BundleError("base image must be an immutable name@sha256:<lowercase-hex> reference")
    root_license = _copy_source(args.root_license, output, "sources/first-party/LICENSE")
    apk_database = _copy_source(args.apk_database, output, "sources/alpine/installed")
    os_release = _copy_source(args.os_release, output, "sources/alpine/os-release")
    components = [
        {
            "kind": "application",
            "license_evidence_status": "delivered-text",
            "license_expression": "Apache-2.0",
            "license_sources": [root_license],
            "name": "ColorTrace",
            "owner_legal_status": "pending",
            "source_commit": args.source_commit,
            "source_tree": args.source_tree,
            "version": args.source_commit,
        },
        _os_component(args.os_release, os_release),
    ]
    components.extend(_parse_apk_database(args.apk_database, apk_database))
    return components, root_license


def build_runtime_bundle(args: argparse.Namespace) -> None:
    mcp_values = tuple(
        getattr(args, name, None)
        for name in ("mcp_binary", "mcp_lock", "mcp_license", "go_license")
    )
    if args.profile == "private-full":
        if any(value is None for value in mcp_values):
            raise BundleError("private-full requires every mcp-grafana input")
    elif args.profile == "hosted-readonly":
        if any(value is not None for value in mcp_values):
            raise BundleError("hosted-readonly forbids mcp-grafana inputs")
    else:
        raise BundleError(f"unsupported runtime profile: {args.profile}")
    output = _new_output(args.output)
    components, root_license = _common_bundle(args, output)
    python_version = platform.python_version()
    lock_source = _copy_source(args.uv_lock, output, "sources/python/uv.lock")
    python_license = _copy_source(
        args.python_license, output, "sources/language-runtimes/python/LICENSE.txt"
    )
    components.append(
        {
            "kind": "language-runtime",
            "license_evidence_status": "delivered-text",
            "license_expression": None,
            "license_source_url": (
                f"https://raw.githubusercontent.com/python/cpython/v{python_version}/LICENSE"
            ),
            "license_sources": [python_license],
            "name": "Python",
            "owner_legal_status": "pending",
            "source_url": (
                "https://www.python.org/downloads/release/"
                f"python-{python_version.replace('.', '')}/"
            ),
            "version": python_version,
        }
    )
    application_components = _python_components(
        args.python_site_packages,
        output,
        {"kind": "uv-lock", "source": lock_source},
        root_license,
        "application",
    )
    base_provenance = {"kind": "base-image", "reference": args.base_image}
    base_components = _python_components(
        args.global_python_site_packages,
        output,
        base_provenance,
        root_license,
        "base-image",
    )
    embedded_wheel = _embedded_python_wheel(args.ensurepip_wheel, output, base_provenance)
    if not any(
        re.sub(r"[-_.]+", "-", component["name"]).lower()
        == re.sub(r"[-_.]+", "-", embedded_wheel["name"]).lower()
        and component["version"] == embedded_wheel["version"]
        for component in base_components
    ):
        raise BundleError("embedded Python wheel does not match an installed base distribution")
    components.extend(application_components)
    components.extend(base_components)
    components.append(embedded_wheel)
    if args.mcp_binary is not None:
        mcp_binary = _require_file(args.mcp_binary, "mcp-grafana binary")
        lock = json.loads(_require_file(args.mcp_lock, "mcp-grafana lock").read_text())
        if not isinstance(lock, dict):
            raise BundleError("mcp-grafana lock must be an object")
        binary_sha256 = _sha256(mcp_binary)
        if binary_sha256 != lock.get("binary_sha256"):
            raise BundleError("mcp-grafana binary hash does not match its runtime lock")
        go_version, module_text = _go_build_info(mcp_binary)
        mcp_lock = _copy_source(args.mcp_lock, output, "sources/mcp-grafana/runtime-lock.json")
        mcp_license = _copy_source(args.mcp_license, output, "sources/mcp-grafana/LICENSE")
        go_license = _copy_source(args.go_license, output, "sources/language-runtimes/go/LICENSE")
        components.extend(
            [
                {
                    "archive_sha256": lock.get("archive_sha256"),
                    "binary_sha256": binary_sha256,
                    "kind": "application",
                    "license_evidence_status": "delivered-text",
                    "license_expression": "Apache-2.0",
                    "license_source_url": (
                        "https://raw.githubusercontent.com/grafana/mcp-grafana/"
                        f"{lock.get('source_commit')}/LICENSE"
                    ),
                    "license_sources": [mcp_license],
                    "name": "mcp-grafana",
                    "owner_legal_status": "pending",
                    "runtime_lock": mcp_lock,
                    "source_commit": lock.get("source_commit"),
                    "source_url": lock.get("source_repository"),
                    "version": lock.get("release_version"),
                },
                {
                    "kind": "language-runtime",
                    "license_evidence_status": "delivered-text",
                    "license_expression": None,
                    "license_source_url": (
                        f"https://raw.githubusercontent.com/golang/go/{go_version}/LICENSE"
                    ),
                    "license_sources": [go_license],
                    "name": "Go standard library",
                    "owner_legal_status": "pending",
                    "source_url": f"https://go.dev/dl/{go_version}.src.tar.gz",
                    "version": go_version.removeprefix("go"),
                },
            ]
        )
        components.extend(_go_components(module_text, lock, mcp_license))
    _finish_bundle(args, output, components)


def build_web_bundle(args: argparse.Namespace) -> None:
    if args.profile != "public-readonly":
        raise BundleError(f"unsupported web profile: {args.profile}")
    output = _new_output(args.output)
    components, root_license = _common_bundle(args, output)
    node_license = _copy_source(args.node_license, output, "sources/language-runtimes/node/LICENSE")
    node_version_source = _copy_source(
        args.node_version, output, "sources/language-runtimes/node/version"
    )
    node_version = _require_file(args.node_version, "Node version").read_text().strip()
    if not re.fullmatch(r"v\d+\.\d+\.\d+", node_version):
        raise BundleError("invalid Node version input")
    components.append(
        {
            "kind": "language-runtime",
            "license_evidence_status": "delivered-text",
            "license_expression": "MIT",
            "license_source_url": (
                f"https://raw.githubusercontent.com/nodejs/node/{node_version}/LICENSE"
            ),
            "license_sources": [node_license],
            "name": "Node.js",
            "owner_legal_status": "pending",
            "source_url": f"https://github.com/nodejs/node/tree/{node_version}",
            "version": node_version.removeprefix("v"),
            "version_source": node_version_source,
        }
    )
    lock_source = _copy_source(args.pnpm_lock, output, "sources/web/pnpm-lock.yaml")
    first_party_expected = {
        "@colortrace/api-client",
        "@colortrace/web",
        "@colortrace/workspace-model",
    }
    first_party_actual: set[str] = set()
    _require_directory(args.first_party_web_manifests, "first-party web package metadata root")
    for package_json in sorted(args.first_party_web_manifests.glob("*/package.json")):
        package_json = _require_contained_file(
            args.first_party_web_manifests,
            package_json,
            "first-party web package metadata",
        )
        document = json.loads(package_json.read_text(encoding="utf-8"))
        name = document.get("name") if isinstance(document, dict) else None
        if (
            not isinstance(name, str)
            or name not in first_party_expected
            or name in first_party_actual
        ):
            raise BundleError(f"unexpected first-party web package: {name!r}")
        first_party_actual.add(name)
        package_source = _copy_source(
            package_json,
            output,
            f"sources/web/first-party/{name.removeprefix('@colortrace/')}/package.json",
        )
        components.append(
            {
                "kind": "bundled-first-party-javascript",
                "license_evidence_status": "delivered-text",
                "license_expression": document.get("license"),
                "license_sources": [root_license],
                "name": name,
                "owner_legal_status": "pending",
                "package_source": package_source,
                "source_commit": args.source_commit,
                "source_tree": args.source_tree,
                "version": document.get("version"),
            }
        )
    if first_party_actual != first_party_expected:
        raise BundleError(
            "first-party web packages differ: "
            f"expected {sorted(first_party_expected)}, got {sorted(first_party_actual)}"
        )
    expected = {"react", "react-dom", "scheduler"}
    actual: set[str] = set()
    _require_directory(args.web_packages, "web runtime package metadata root")
    for package_json in sorted(args.web_packages.glob("*/package.json")):
        package_json = _require_contained_file(
            args.web_packages, package_json, "web runtime package metadata"
        )
        package_dir = package_json.parent
        document = json.loads(package_json.read_text(encoding="utf-8"))
        name = document.get("name") if isinstance(document, dict) else None
        if not isinstance(name, str) or name not in expected or name in actual:
            raise BundleError(f"unexpected web runtime package: {name!r}")
        actual.add(name)
        license_path = _require_contained_file(
            args.web_packages, package_dir / "LICENSE", f"{name} license"
        )
        package_source = _copy_source(package_json, output, f"sources/web/{name}/package.json")
        license_source = _copy_source(license_path, output, f"sources/web/{name}/LICENSE")
        repository = document.get("repository")
        source_url = repository.get("url") if isinstance(repository, dict) else repository
        components.append(
            {
                "kind": "bundled-javascript",
                "license_evidence_status": "delivered-text",
                "license_expression": document.get("license"),
                "license_sources": [license_source],
                "lock_source": lock_source,
                "name": name,
                "owner_legal_status": "pending",
                "package_source": package_source,
                "source_url": source_url,
                "version": document.get("version"),
            }
        )
    if actual != expected:
        raise BundleError(
            f"web runtime packages differ: expected {sorted(expected)}, got {sorted(actual)}"
        )
    _finish_bundle(args, output, components)


def _new_output(output: Path) -> Path:
    if output.exists() and (output.is_symlink() or not output.is_dir() or any(output.iterdir())):
        raise BundleError("output must be an absent or empty non-symlink directory")
    output.mkdir(parents=True, exist_ok=True)
    output.chmod(0o755)
    return output


def _finish_bundle(
    args: argparse.Namespace,
    output: Path,
    components: list[dict[str, Any]],
) -> None:
    components.sort(key=lambda value: (value["kind"], value["name"], value.get("version") or ""))
    manifest = {
        "base_image": args.base_image,
        "compatibility_decision": "owner-legal-pending",
        "components": components,
        "profile": args.profile,
        "schema": "colortrace-image-license-bundle/v1",
        "source_commit": args.source_commit,
        "source_tree": args.source_tree,
    }
    _write_json(output / "manifest.json", manifest)
    lines = [
        f"{_sha256(path)}  {path.relative_to(output).as_posix()}"
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    (output / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (output / "SHA256SUMS").chmod(0o644)


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--root-license", type=Path, required=True)
    parser.add_argument("--apk-database", type=Path, required=True)
    parser.add_argument("--os-release", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    runtime = subparsers.add_parser("runtime")
    _common_arguments(runtime)
    runtime.add_argument("--python-site-packages", type=Path, required=True)
    runtime.add_argument("--global-python-site-packages", type=Path, required=True)
    runtime.add_argument("--ensurepip-wheel", type=Path, required=True)
    runtime.add_argument("--python-license", type=Path, required=True)
    runtime.add_argument("--uv-lock", type=Path, required=True)
    runtime.add_argument("--mcp-binary", type=Path)
    runtime.add_argument("--mcp-lock", type=Path)
    runtime.add_argument("--mcp-license", type=Path)
    runtime.add_argument("--go-license", type=Path)
    web = subparsers.add_parser("web")
    _common_arguments(web)
    web.add_argument("--node-license", type=Path, required=True)
    web.add_argument("--node-version", type=Path, required=True)
    web.add_argument("--pnpm-lock", type=Path, required=True)
    web.add_argument("--first-party-web-manifests", type=Path, required=True)
    web.add_argument("--web-packages", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "runtime":
        mcp_values = (args.mcp_binary, args.mcp_lock, args.mcp_license, args.go_license)
        if any(value is not None for value in mcp_values) and any(
            value is None for value in mcp_values
        ):
            raise BundleError("all mcp-grafana inputs must be supplied together")
        build_runtime_bundle(args)
    else:
        build_web_bundle(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
