from __future__ import annotations

import copy
import gzip
import hashlib
import json
import re
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

from colortrace_repo.common import Finding, sorted_findings
from colortrace_repo.security_evidence import _sha256, _write_json

_HEX40 = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_IMAGE_REFERENCE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}")
_PROFILES = {
    "runtime": "private-full",
    "hosted-runtime": "hosted-readonly",
    "web": "public-readonly",
}
_BUNDLE_ONLY = {
    "private-full": {
        ("application", "colortrace"),
        ("embedded-python-wheel", "pip"),
        ("language-runtime", "python"),
    },
    "hosted-readonly": {
        ("application", "colortrace"),
        ("embedded-python-wheel", "pip"),
        ("language-runtime", "python"),
    },
    "public-readonly": {
        ("application", "colortrace"),
        ("bundled-first-party-javascript", "@colortrace/api-client"),
        ("bundled-first-party-javascript", "@colortrace/web"),
        ("bundled-first-party-javascript", "@colortrace/workspace-model"),
        ("bundled-javascript", "react"),
        ("bundled-javascript", "react-dom"),
        ("bundled-javascript", "scheduler"),
        ("language-runtime", "node.js"),
    },
}
_IMAGE_INPUTS = {
    "runtime": (
        "Dockerfile.runtime",
        "Dockerfile.runtime.dockerignore",
        "LICENSE",
        "config/grafana-mcp/mcp-grafana.lock.json",
        "deploy/runtime-entrypoint.py",
        "packages/repo-tools/src/colortrace_repo/image_licenses.py",
        "uv.lock",
    ),
    "hosted-runtime": (
        "Dockerfile.runtime",
        "Dockerfile.runtime.dockerignore",
        "LICENSE",
        "config/grafana-mcp/mcp-grafana.lock.json",
        "deploy/runtime-entrypoint.py",
        "packages/repo-tools/src/colortrace_repo/image_licenses.py",
        "uv.lock",
    ),
    "web": (
        "Dockerfile.web",
        "Dockerfile.web.dockerignore",
        "LICENSE",
        "deploy/web-server.mjs",
        "package.json",
        "packages/api-client/package.json",
        "packages/repo-tools/src/colortrace_repo/image_licenses.py",
        "packages/web/package.json",
        "packages/workspace-model/package.json",
        "pnpm-lock.yaml",
    ),
}


@dataclass(frozen=True)
class ImageEvidenceInput:
    name: str
    archive: Path
    bundle: Path
    raw_sbom: Path
    expected_reference: str


class EvidenceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> NoReturn:
    raise EvidenceError(code, message)


def _bytes_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _safe_path(value: str, code: str) -> PurePosixPath:
    path = PurePosixPath(value.removeprefix("./"))
    if not path.parts or path.is_absolute() or ".." in path.parts:
        _fail(code, f"unsafe path: {value}")
    return path


def _archive_file(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
) -> bytes:
    member = members.get(name)
    if member is None or not member.isfile():
        _fail("image.archive.invalid", f"missing regular archive member: {name}")
    handle = archive.extractfile(member)
    if handle is None:
        _fail("image.archive.invalid", f"unreadable archive member: {name}")
    return handle.read()


def _archive_digest(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    handle = archive.extractfile(member)
    if handle is None:
        _fail("image.archive.invalid", f"unreadable archive member: {member.name}")
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _blob_path(digest: Any) -> str:
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        _fail("image.oci.invalid", f"invalid OCI digest: {digest!r}")
    return f"blobs/sha256/{digest.removeprefix('sha256:')}"


def _json_object(value: bytes, description: str) -> dict[str, Any]:
    try:
        document = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("image.oci.invalid", f"invalid {description}: {error}")
    if not isinstance(document, dict):
        _fail("image.oci.invalid", f"{description} must be an object")
    return document


def _descriptor_bytes(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: Any,
    description: str,
) -> bytes:
    if not isinstance(descriptor, dict):
        _fail("image.oci.invalid", f"{description} descriptor must be an object")
    path = _blob_path(descriptor.get("digest"))
    member = members.get(path)
    if member is None or not member.isfile() or descriptor.get("size") != member.size:
        _fail("image.oci.hash", f"{description} descriptor does not match its blob")
    return _archive_file(archive, members, path)


def _image_manifests(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptors: list[Any],
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    manifests: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    visited: set[tuple[str, str]] = set()
    active: set[tuple[str, str]] = set()

    def visit(descriptor: Any, image_digest: str) -> None:
        content = _descriptor_bytes(archive, members, descriptor, "OCI")
        digest = descriptor.get("digest")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            _fail("image.oci.invalid", "OCI descriptor digest is invalid")
        key = (image_digest, digest)
        if key in active:
            _fail("image.oci.invalid", "OCI descriptor graph contains a cycle")
        if key in visited:
            return
        active.add(key)
        document = _json_object(content, "OCI descriptor document")
        children = document.get("manifests")
        if isinstance(children, list):
            if not children:
                _fail("image.oci.invalid", "nested OCI index has no descriptors")
            for child in children:
                visit(child, image_digest)
        else:
            config = document.get("config")
            layers = document.get("layers")
            if not isinstance(config, dict) or not isinstance(layers, list):
                _fail("image.oci.invalid", "OCI leaf is not an image manifest")
            _descriptor_bytes(archive, members, config, "OCI config")
            for layer in layers:
                if not isinstance(layer, dict):
                    _fail("image.oci.invalid", "OCI layer descriptor must be an object")
                layer_path = _blob_path(layer.get("digest"))
                layer_member = members.get(layer_path)
                if (
                    layer_member is None
                    or not layer_member.isfile()
                    or layer.get("size") != layer_member.size
                ):
                    _fail("image.oci.hash", "OCI layer descriptor does not match its blob")
            manifests.append((image_digest, descriptor, document))
        active.remove(key)
        visited.add(key)

    for descriptor in descriptors:
        if not isinstance(descriptor, dict):
            _fail("image.oci.invalid", "OCI index descriptor must be an object")
        digest = descriptor.get("digest")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            _fail("image.oci.invalid", "OCI index descriptor digest is invalid")
        visit(descriptor, digest)
    return manifests


def _verify_web_layer_paths(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: dict[str, Any],
) -> None:
    path = _blob_path(descriptor.get("digest"))
    member = members.get(path)
    if member is None or not member.isfile():
        _fail("image.archive.invalid", "web layer blob is absent or invalid")
    handle = archive.extractfile(member)
    if handle is None:
        _fail("image.archive.invalid", "web layer cannot be read")
    media_type = descriptor.get("mediaType")
    stream: Any
    if isinstance(media_type, str) and media_type.endswith("+gzip"):
        stream = gzip.GzipFile(fileobj=handle)
    elif isinstance(media_type, str) and media_type.endswith(".tar"):
        stream = handle
    else:
        _fail("image.oci.invalid", f"unsupported web layer media type: {media_type!r}")
    try:
        layer = tarfile.open(fileobj=stream, mode="r|")
        with layer:
            for member in layer:
                value = _safe_path(member.name, "image.archive.invalid").as_posix()
                if "yarn" in value.casefold():
                    _fail("image.yarn.present", f"Yarn path remains in final layer: {value}")
    except (OSError, tarfile.TarError) as error:
        _fail("image.archive.invalid", f"cannot inspect web layer: {error}")
    finally:
        stream.close()


def _archive_binding(
    path: Path,
    *,
    expected_reference: str,
    profile: str,
    candidate_sha: str,
    candidate_tree: str,
) -> tuple[dict[str, Any], list[Finding]]:
    if path.is_symlink() or not path.is_file():
        _fail("image.archive.invalid", f"image archive is absent or invalid: {path}")
    try:
        archive = tarfile.open(path, mode="r:*")
    except (OSError, tarfile.TarError) as error:
        _fail("image.archive.invalid", f"cannot open image archive: {error}")
    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        for member in archive.getmembers():
            name = _safe_path(member.name, "image.archive.invalid").as_posix()
            if name in members:
                _fail("image.archive.duplicate", f"duplicate archive member: {name}")
            members[name] = member
        try:
            docker_manifest = json.loads(_archive_file(archive, members, "manifest.json"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            _fail("image.oci.invalid", f"invalid docker manifest: {error}")
        index_bytes = _archive_file(archive, members, "index.json")
        index = _json_object(index_bytes, "OCI index")
        if not isinstance(docker_manifest, list) or len(docker_manifest) != 1:
            _fail("image.oci.invalid", "archive must contain exactly one image")
        docker_record = docker_manifest[0]
        if not isinstance(docker_record, dict):
            _fail("image.oci.invalid", "docker manifest entry must be an object")
        if docker_record.get("RepoTags") != [expected_reference]:
            _fail("image.binding.stale", "archive tag differs from the expected reference")
        config_path = docker_record.get("Config")
        layer_paths = docker_record.get("Layers")
        if not isinstance(config_path, str) or not isinstance(layer_paths, list):
            _fail("image.oci.invalid", "docker manifest lacks config or layer paths")
        config_path = _safe_path(config_path, "image.oci.invalid").as_posix()
        if not all(isinstance(value, str) for value in layer_paths):
            _fail("image.oci.invalid", "docker manifest has an invalid layer path")
        layer_paths = [_safe_path(value, "image.oci.invalid").as_posix() for value in layer_paths]
        blobs: list[dict[str, Any]] = []
        for name, member in sorted(members.items()):
            if not name.startswith("blobs/sha256/"):
                continue
            expected = name.removeprefix("blobs/sha256/")
            if _archive_digest(archive, member) != expected:
                _fail("image.oci.hash", f"blob filename hash mismatch: {name}")
            blobs.append({"digest": f"sha256:{expected}", "size_bytes": member.size})
        descriptors = index.get("manifests")
        if not isinstance(descriptors, list) or not descriptors:
            _fail("image.oci.invalid", "OCI index has no manifests")
        selected: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        for image_digest, descriptor, manifest in _image_manifests(archive, members, descriptors):
            manifest_config = manifest.get("config")
            manifest_layers = manifest.get("layers")
            if not isinstance(manifest_config, dict) or not isinstance(manifest_layers, list):
                _fail("image.oci.invalid", "image manifest lacks config or layers")
            candidate_layers = [_blob_path(value.get("digest")) for value in manifest_layers]
            if (
                _blob_path(manifest_config.get("digest")) == config_path
                and candidate_layers == layer_paths
            ):
                selected.append((image_digest, descriptor, manifest))
        if len(selected) != 1:
            _fail("image.oci.invalid", "archive does not bind one exact image manifest")
        image_digest, manifest_descriptor, manifest = selected[0]
        config_descriptor = manifest["config"]
        layers = manifest["layers"]
        config_bytes = _archive_file(archive, members, config_path)
        if (
            not isinstance(config_descriptor, dict)
            or config_descriptor.get("size") != len(config_bytes)
            or config_descriptor.get("digest") != _bytes_sha256(config_bytes)
        ):
            _fail("image.oci.hash", "image config descriptor does not match its blob")
        config = _json_object(config_bytes, "image config")
        runtime_config = config.get("config")
        if not isinstance(runtime_config, dict):
            _fail("image.binding.invalid", "image lacks runtime config")
        expected_labels = {
            "org.colortrace.runtime-profile": profile,
            "org.colortrace.source-tree": candidate_tree,
            "org.opencontainers.image.revision": candidate_sha,
        }
        labels = runtime_config.get("Labels")
        findings: list[Finding] = []
        if not isinstance(labels, dict) or any(
            labels.get(name) != value for name, value in expected_labels.items()
        ):
            findings.append(
                Finding("", "image.binding.stale", "image labels differ from the candidate")
            )
        user = runtime_config.get("User")
        if not isinstance(user, str) or not user or user.casefold() in {"0", "root"}:
            findings.append(
                Finding("", "image.binding.user", "final image is not configured non-root")
            )
        if profile == "public-readonly":
            if len(layers) != 1:
                findings.append(
                    Finding("", "image.yarn.present", "web image is not a clean one-layer rootfs")
                )
            elif isinstance(layers[0], dict):
                _verify_web_layer_paths(archive, members, layers[0])
            if b"yarn" in config_bytes.lower():
                findings.append(
                    Finding("", "image.yarn.present", "web image config/history contains Yarn")
                )
        rootfs = config.get("rootfs")
        diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
        if not isinstance(diff_ids, list) or len(diff_ids) != len(layers):
            findings.append(
                Finding("", "image.oci.invalid", "layer count differs from config diff IDs")
            )
        return (
            {
                "archive_sha256": _sha256(path),
                "blob_count": len(blobs),
                "blobs": blobs,
                "config_digest": config_descriptor.get("digest"),
                "history_sha256": _bytes_sha256(
                    json.dumps(config.get("history"), sort_keys=True).encode()
                ),
                "archive_index_sha256": _bytes_sha256(index_bytes),
                "image_digest": image_digest,
                "labels": (
                    {name: labels.get(name) for name in expected_labels}
                    if isinstance(labels, dict)
                    else None
                ),
                "layer_digests": [value.get("digest") for value in layers],
                "layer_diff_ids": diff_ids,
                "platform_manifest_digest": manifest_descriptor.get("digest"),
                "non_root_user": user,
                "reference": expected_reference,
            },
            findings,
        )


def _bundle_files(root: Path) -> dict[str, bytes]:
    if root.is_symlink() or not root.is_dir():
        _fail("image.bundle.missing", f"bundle directory is absent or invalid: {root}")
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            _fail("image.bundle.invalid", f"bundle contains a symlink: {path}")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = path.read_bytes()
        elif not path.is_dir():
            _fail("image.bundle.invalid", f"bundle contains a special file: {path}")
    return files


def _source_records(value: Any) -> list[dict[str, str]]:
    records: dict[tuple[str, str], dict[str, str]] = {}
    if isinstance(value, dict):
        path = value.get("path")
        digest = value.get("sha256")
        if isinstance(path, str) and isinstance(digest, str):
            records[(path, digest)] = {"path": path, "sha256": digest}
        for child in value.values():
            for record in _source_records(child):
                records[(record["path"], record["sha256"])] = record
    elif isinstance(value, list):
        for child in value:
            for record in _source_records(child):
                records[(record["path"], record["sha256"])] = record
    return [records[key] for key in sorted(records)]


def _verify_bundle(
    root: Path,
    *,
    candidate_sha: str,
    candidate_tree: str,
    profile: str,
) -> tuple[dict[str, Any], dict[str, Any], list[Finding]]:
    files = _bundle_files(root)
    if not {"manifest.json", "SHA256SUMS"} <= set(files):
        _fail("image.bundle.missing", "bundle lacks manifest.json or SHA256SUMS")
    checksum_text = files["SHA256SUMS"].decode("utf-8")
    lines = checksum_text.splitlines()
    if not checksum_text.endswith("\n"):
        _fail("image.bundle.stale", "bundle checksums lack a final newline")
    expected: dict[str, str] = {}
    listed_paths: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            _fail("image.bundle.invalid", f"invalid checksum line: {line!r}")
        digest, relative = match.groups()
        relative = _safe_path(relative, "image.bundle.invalid").as_posix()
        if relative in expected or relative == "SHA256SUMS":
            _fail("image.bundle.duplicate", f"duplicate checksum path: {relative}")
        expected[relative] = digest
        listed_paths.append(relative)
    if listed_paths != sorted(listed_paths):
        _fail("image.bundle.stale", "bundle checksum paths are not sorted")
    if set(expected) != set(files) - {"SHA256SUMS"}:
        _fail("image.bundle.stale", "bundle checksum closure differs from its files")
    for relative, digest in expected.items():
        if hashlib.sha256(files[relative]).hexdigest() != digest:
            _fail("image.bundle.checksum", f"bundle checksum mismatch: {relative}")
    manifest = json.loads(files["manifest.json"])
    if not isinstance(manifest, dict) or any(
        manifest.get(name) != value
        for name, value in {
            "compatibility_decision": "owner-legal-pending",
            "profile": profile,
            "schema": "colortrace-image-license-bundle/v1",
            "source_commit": candidate_sha,
            "source_tree": candidate_tree,
        }.items()
    ):
        _fail("image.bundle.stale", "bundle identity differs from the image candidate")
    if (
        not isinstance(manifest.get("base_image"), str)
        or _IMAGE_REFERENCE.fullmatch(manifest["base_image"]) is None
    ):
        _fail("image.bundle.invalid", "bundle base image is not digest-pinned")
    components = manifest.get("components")
    if not isinstance(components, list) or not components:
        _fail("image.bundle.invalid", "bundle has no components")
    identities: set[tuple[str, str, str]] = set()
    findings: list[Finding] = []
    for component in components:
        if not isinstance(component, dict) or not all(
            isinstance(component.get(key), str) and bool(component[key].strip())
            for key in ("kind", "name", "version")
        ):
            _fail("image.bundle.invalid", "bundle component lacks an exact identity")
        identity = (
            component["kind"],
            component["name"].casefold(),
            component["version"],
        )
        if identity in identities:
            _fail("image.bundle.duplicate", f"duplicate bundle component: {identity}")
        identities.add(identity)
        status = component.get("license_evidence_status")
        if status not in {
            "declared-in-installed-database",
            "declared-in-metadata",
            "delivered-text",
            "unresolved",
        }:
            _fail("image.bundle.invalid", f"invalid license evidence status: {identity}")
        declared_licenses = _declared_licenses(component)
        requires_owner_review = status == "unresolved" or any(
            "gpl" in value.casefold() for value in declared_licenses
        )
        if requires_owner_review and component.get("owner_legal_status") != "pending":
            findings.append(
                Finding(
                    str(identity),
                    "image.bundle.unresolved",
                    "component lacks its required pending owner/legal status",
                )
            )
        sources = _source_records(component)
        license_sources = _source_records(component.get("license_sources"))
        for source in sources:
            if (
                source["path"] not in files
                or hashlib.sha256(files[source["path"]]).hexdigest() != source["sha256"]
            ):
                _fail("image.bundle.checksum", f"stale component source: {source['path']}")
        minimum_license_sources = (
            2 if component["kind"] in {"embedded-python-wheel", "python-distribution"} else 1
        )
        if status == "delivered-text" and len(license_sources) < minimum_license_sources:
            _fail(
                "image.bundle.invalid",
                f"delivered-text component lacks a verified license source: {identity}",
            )
        if status in {"declared-in-installed-database", "declared-in-metadata"}:
            if not declared_licenses:
                _fail("image.bundle.invalid", f"declared component lacks a license: {identity}")
            source_key = (
                "license_source"
                if status == "declared-in-installed-database"
                else "license_sources"
            )
            if not _source_records(component.get(source_key)):
                _fail(
                    "image.bundle.invalid",
                    f"declared component lacks exact embedded evidence: {identity}",
                )
        if not sources and not any(
            isinstance(component.get(key), str) and component[key]
            for key in ("source_checksum", "source_commit", "source_url", "upstream_url")
        ):
            _fail("image.bundle.invalid", f"component lacks provenance: {identity}")
    return (
        manifest,
        {
            "file_count": len(files),
            "manifest_sha256": _bytes_sha256(files["manifest.json"]),
            "sha256sums_sha256": _bytes_sha256(files["SHA256SUMS"]),
            "verified_file_count": len(expected),
        },
        findings,
    )


def _property(component: dict[str, Any], name: str) -> str | None:
    properties = component.get("properties", [])
    if not isinstance(properties, list):
        _fail("image.scanner.invalid", "scanner component properties are not a list")
    values = [
        value.get("value")
        for value in properties
        if isinstance(value, dict) and value.get("name") == name
    ]
    return values[0] if len(values) == 1 and isinstance(values[0], str) else None


def _normalize_python(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _scanner_identity(component: dict[str, Any]) -> tuple[str, str, str]:
    name = component.get("name")
    version = component.get("version")
    package_type = _property(component, "aquasecurity:trivy:PkgType")
    detected_type = _property(component, "aquasecurity:trivy:Type")
    if component.get("type") == "operating-system" and detected_type == "alpine":
        if not isinstance(version, str) or not version.strip():
            _fail("image.coverage.unknown-class", "Alpine record lacks a version")
        return ("os", "alpine", version)
    if component.get("type") == "application" and detected_type == "gobinary":
        if not isinstance(name, str) or not name.strip():
            _fail("image.coverage.unknown-class", "Go application lacks a name")
        return ("application", PurePosixPath(name).name.casefold(), "")
    if (
        not isinstance(name, str)
        or not name.strip()
        or not isinstance(version, str)
        or not version.strip()
    ):
        _fail("image.coverage.unknown-class", "scanner component lacks an identity")
    classes = {
        "alpine": ("apk", name.casefold(), version),
        "gobinary": (
            "go-runtime" if name == "stdlib" else "go",
            "go-standard-library" if name == "stdlib" else name,
            version.removeprefix("v") if name == "stdlib" else version,
        ),
        "node-pkg": ("javascript", name.casefold(), version),
        "python-pkg": ("python", _normalize_python(name), version),
    }
    if package_type not in classes:
        _fail("image.coverage.unknown-class", f"unknown scanner class: {package_type!r}")
    return classes[package_type]


def _bundle_identity(component: dict[str, Any]) -> tuple[str, str, str] | None:
    kind, name, version = component["kind"], component["name"], component["version"]
    if kind == "operating-system-aggregate" and name == "Alpine Linux":
        return ("os", "alpine", version)
    if kind == "apk":
        return ("apk", name.casefold(), version)
    if kind == "python-distribution":
        return ("python", _normalize_python(name), version)
    if kind == "go-module":
        return ("go", name, version)
    if kind == "language-runtime" and name == "Go standard library":
        return ("go-runtime", "go-standard-library", version.removeprefix("v"))
    if kind in {"bundled-javascript", "bundled-first-party-javascript"}:
        return None
    if kind == "application" and name == "mcp-grafana":
        return ("application", "mcp-grafana", "")
    return None


def _licenses(component: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    licenses = component.get("licenses", [])
    if not isinstance(licenses, list):
        _fail("image.scanner.invalid", "scanner component licenses are not a list")
    for value in licenses:
        if not isinstance(value, dict):
            continue
        if isinstance(value.get("expression"), str):
            result.add(value["expression"])
        elif isinstance(value.get("license"), dict):
            license_value = value["license"]
            candidate = license_value.get("id") or license_value.get("name")
            if isinstance(candidate, str):
                result.add(candidate)
    return result


def _declared_licenses(component: dict[str, Any]) -> set[str]:
    for key in ("license_expression", "legacy_license"):
        value = component.get(key)
        if isinstance(value, str) and value.strip():
            return {value.strip()}
    return set()


def _normalized_licenses(values: set[str]) -> set[str]:
    return {re.sub(r"\s+", " ", value.strip()).casefold() for value in values}


def _bundle_bom_ref(component: dict[str, Any]) -> str:
    identity = f"{component['kind']}:{component['name']}:{component['version']}"
    return "urn:colortrace:image-bundle:" + hashlib.sha256(identity.encode()).hexdigest()


def _enrich(raw: dict[str, Any], bundle: dict[str, Any], manifest_digest: str) -> dict[str, Any]:
    result = copy.deepcopy(raw)
    properties = result.setdefault("properties", [])
    if not isinstance(properties, list):
        _fail("image.coverage.invalid", "scanner properties are not a list")
    properties.extend(
        [
            {"name": "colortrace:bundle-kind", "value": bundle["kind"]},
            {"name": "colortrace:bundle-manifest-sha256", "value": manifest_digest},
            {
                "name": "colortrace:license-evidence-status",
                "value": bundle["license_evidence_status"],
            },
        ]
        + [
            {"name": f"colortrace:notice:{value['path']}:sha256", "value": value["sha256"]}
            for value in _source_records(bundle)
        ]
    )
    properties.sort(key=lambda value: (str(value.get("name")), str(value.get("value"))))
    if not _licenses(result) and (licenses := _declared_licenses(bundle)):
        result["licenses"] = [{"expression": value} for value in sorted(licenses)]
    return result


def _bundle_only_component(component: dict[str, Any], manifest_digest: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "bom-ref": _bundle_bom_ref(component),
        "name": component["name"],
        "properties": [
            {"name": "colortrace:bundle-kind", "value": component["kind"]},
            {"name": "colortrace:bundle-manifest-sha256", "value": manifest_digest},
            {
                "name": "colortrace:license-evidence-status",
                "value": component["license_evidence_status"],
            },
        ]
        + [
            {"name": f"colortrace:notice:{value['path']}:sha256", "value": value["sha256"]}
            for value in _source_records(component)
        ],
        "type": "application" if component["kind"] == "application" else "library",
        "version": component["version"],
    }
    if licenses := _declared_licenses(component):
        result["licenses"] = [{"expression": value} for value in sorted(licenses)]
    return result


def _sort_component_arrays(component: dict[str, Any]) -> None:
    for key in ("hashes", "licenses", "properties", "externalReferences"):
        values = component.get(key)
        if isinstance(values, list):
            values.sort(key=lambda value: json.dumps(value, sort_keys=True))


def _reconcile(
    raw: dict[str, Any],
    bundle: dict[str, Any],
    bundle_record: dict[str, Any],
    profile: str,
) -> tuple[dict[str, Any], dict[str, Any], list[Finding]]:
    raw_components = raw.get("components")
    if raw.get("bomFormat") != "CycloneDX" or not isinstance(raw_components, list):
        _fail("image.scanner.invalid", "raw output is not a CycloneDX SBOM")
    scanner: dict[tuple[str, str, str], dict[str, Any]] = {}
    matchable: dict[tuple[str, str, str], dict[str, Any]] = {}
    bundle_only: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for component in raw_components:
        if not isinstance(component, dict):
            _fail("image.scanner.invalid", "scanner component is not an object")
        scanner_identity = _scanner_identity(component)
        if scanner_identity in scanner:
            findings.append(
                Finding(str(scanner_identity), "image.coverage.duplicate", "scanner duplicate")
            )
        scanner[scanner_identity] = component
    for component in bundle["components"]:
        bundle_identity = _bundle_identity(component)
        if bundle_identity is None:
            bundle_only.append(component)
        elif bundle_identity in matchable:
            findings.append(
                Finding(str(bundle_identity), "image.coverage.duplicate", "bundle duplicate")
            )
        else:
            matchable[bundle_identity] = component
    allowed = _BUNDLE_ONLY[profile]
    actual_only = {(value["kind"], value["name"].casefold()) for value in bundle_only}
    only_counts: dict[tuple[str, str], int] = {}
    for value in bundle_only:
        only_identity = (value["kind"], value["name"].casefold())
        only_counts[only_identity] = only_counts.get(only_identity, 0) + 1
    for only_identity, count in sorted(only_counts.items()):
        if count != 1:
            findings.append(
                Finding(
                    str(only_identity),
                    "image.coverage.duplicate",
                    "bundle-only component is not unique",
                )
            )
    for only_identity in sorted(actual_only - allowed):
        findings.append(
            Finding(
                str(only_identity),
                "image.coverage.unknown-class",
                "unknown bundle-only class",
            )
        )
    for only_identity in sorted(allowed - actual_only):
        findings.append(
            Finding(str(only_identity), "image.coverage.missing", "bundle-only record is absent")
        )
    matches: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    enriched: list[dict[str, Any]] = []
    for identity, component in sorted(scanner.items()):
        matched = matchable.get(identity)
        if matched is None:
            same_name = any(value[:2] == identity[:2] for value in matchable)
            findings.append(
                Finding(
                    str(identity),
                    "image.coverage.version" if same_name else "image.coverage.missing",
                    "scanner record has no exact bundle match",
                )
            )
            enriched.append(copy.deepcopy(component))
            continue
        raw_licenses = _licenses(component)
        bundle_licenses = _declared_licenses(matched)
        if (
            raw_licenses
            and bundle_licenses
            and _normalized_licenses(raw_licenses) != _normalized_licenses(bundle_licenses)
        ):
            conflicts.append(
                {
                    "bundle": sorted(bundle_licenses),
                    "identity": list(identity),
                    "scanner": sorted(raw_licenses),
                    "status": "unexplained",
                }
            )
            findings.append(
                Finding(str(identity), "image.coverage.conflict", "license evidence conflicts")
            )
        matches.append(
            {
                "bundle_kind": matched["kind"],
                "identity": list(identity),
                "scanner_bom_ref": component.get("bom-ref"),
            }
        )
        enriched.append(_enrich(component, matched, bundle_record["manifest_sha256"]))
    for identity in sorted(set(matchable) - set(scanner)):
        findings.append(
            Finding(str(identity), "image.coverage.missing", "bundle record has no scanner match")
        )
    enriched.extend(
        _bundle_only_component(value, bundle_record["manifest_sha256"]) for value in bundle_only
    )
    for component in enriched:
        _sort_component_arrays(component)
    enriched.sort(key=lambda value: str(value.get("bom-ref")))
    references = [value.get("bom-ref") for value in enriched]
    if not all(isinstance(value, str) and value for value in references) or len(references) != len(
        set(references)
    ):
        findings.append(Finding("", "image.coverage.duplicate", "enriched BOM refs are invalid"))
    result = copy.deepcopy(raw)
    result.pop("serialNumber", None)
    if isinstance(result.get("metadata"), dict):
        result["metadata"].pop("timestamp", None)
        metadata_component = result["metadata"].get("component")
        if isinstance(metadata_component, dict):
            _sort_component_arrays(metadata_component)
        metadata_properties = result["metadata"].get("properties")
        if isinstance(metadata_properties, list):
            metadata_properties.sort(key=lambda value: json.dumps(value, sort_keys=True))
    result["serialNumber"] = "urn:uuid:" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"{profile}:{bundle_record['manifest_sha256']}")
    )
    result["components"] = enriched
    dependencies = result.get("dependencies")
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if isinstance(dependency, dict) and isinstance(dependency.get("dependsOn"), list):
                dependency["dependsOn"].sort()
        dependencies.sort(
            key=lambda value: str(value.get("ref")) if isinstance(value, dict) else ""
        )
    coverage = {
        "bundle_only": [
            {
                "bom_ref": _bundle_bom_ref(value),
                "kind": value["kind"],
                "name": value["name"],
                "version": value["version"],
            }
            for value in sorted(
                bundle_only, key=lambda item: (item["kind"], item["name"], item["version"])
            )
        ],
        "conflicts": conflicts,
        "counts": {
            "bundle": len(bundle["components"]),
            "bundle_only": len(bundle_only),
            "matched": len(matches),
            "scanner": len(raw_components),
        },
        "matches": matches,
        "profile": profile,
        "schema": "colortrace-final-image-coverage/v1",
        "status": "pass" if not findings else "fail",
    }
    return result, coverage, findings


def _process(
    root: Path,
    output: Path,
    value: ImageEvidenceInput,
    *,
    candidate_sha: str,
    candidate_tree: str,
    scanner_image: str,
) -> list[Finding]:
    profile = _PROFILES[value.name]
    archive, archive_findings = _archive_binding(
        value.archive,
        expected_reference=value.expected_reference,
        profile=profile,
        candidate_sha=candidate_sha,
        candidate_tree=candidate_tree,
    )
    bundle, bundle_record, bundle_findings = _verify_bundle(
        value.bundle,
        candidate_sha=candidate_sha,
        candidate_tree=candidate_tree,
        profile=profile,
    )
    if value.raw_sbom.is_symlink() or not value.raw_sbom.is_file():
        _fail("image.scanner.invalid", "raw SBOM is absent or invalid")
    raw_bytes = value.raw_sbom.read_bytes()
    raw = json.loads(raw_bytes)
    if not isinstance(raw, dict):
        _fail("image.scanner.invalid", "raw SBOM must be an object")
    enriched, coverage, coverage_findings = _reconcile(raw, bundle, bundle_record, profile)
    inputs: list[dict[str, Any]] = []
    input_findings: list[Finding] = []
    for relative in _IMAGE_INPUTS[value.name]:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            input_findings.append(Finding(relative, "image.binding.input", "input is invalid"))
        else:
            inputs.append(
                {"path": relative, "sha256": _sha256(path), "size_bytes": path.stat().st_size}
            )
    findings = [*archive_findings, *bundle_findings, *coverage_findings, *input_findings]
    coverage.update(
        {
            "bundle": bundle_record,
            "candidate": {"commit": candidate_sha, "tree": candidate_tree},
            "findings": [finding.as_dict() for finding in sorted_findings(findings)],
            "image": {
                key: archive[key]
                for key in (
                    "archive_index_sha256",
                    "archive_sha256",
                    "config_digest",
                    "image_digest",
                    "platform_manifest_digest",
                    "reference",
                )
            },
            "scanner_image": scanner_image,
            "source_inputs": inputs,
            "status": "pass" if not findings else "fail",
        }
    )
    image_output = output / "images" / value.name
    enriched_path = image_output / "enriched-sbom.cdx.json"
    coverage_path = image_output / "coverage.json"
    _write_json(enriched_path, enriched)
    _write_json(coverage_path, coverage)
    _write_json(
        image_output / "image-binding.json",
        {
            "bundle": bundle_record,
            "candidate": {"commit": candidate_sha, "tree": candidate_tree},
            "image": archive,
            "inputs": inputs,
            "profile": profile,
            "reports": {
                "coverage_sha256": _sha256(coverage_path),
                "enriched_sbom_sha256": _sha256(enriched_path),
                "raw_sbom_sha256": _bytes_sha256(raw_bytes),
            },
            "scanner_image": scanner_image,
            "schema": "colortrace-final-image-binding/v1",
            "status": "pass" if not findings else "fail",
        },
    )
    return sorted_findings(findings)


def build_final_image_evidence(
    root: Path,
    output: Path,
    *,
    candidate_sha: str,
    candidate_tree: str,
    scanner_image: str,
    images: tuple[ImageEvidenceInput, ...],
) -> list[Finding]:
    if _HEX40.fullmatch(candidate_sha) is None or _HEX40.fullmatch(candidate_tree) is None:
        return [Finding("", "image.candidate.invalid", "candidate identity is invalid")]
    if _IMAGE_REFERENCE.fullmatch(scanner_image) is None:
        return [Finding("", "image.scanner.invalid", "scanner image is not digest-pinned")]
    if len(images) != 3 or {value.name for value in images} != set(_PROFILES):
        return [Finding("", "image.input.invalid", "exactly three named images are required")]
    findings: list[Finding] = []
    for value in sorted(images, key=lambda item: item.name):
        try:
            findings.extend(
                _process(
                    root.resolve(),
                    output.resolve(),
                    value,
                    candidate_sha=candidate_sha,
                    candidate_tree=candidate_tree,
                    scanner_image=scanner_image,
                )
            )
        except (
            KeyError,
            OSError,
            TypeError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            tarfile.TarError,
            EvidenceError,
        ) as error:
            code = error.code if isinstance(error, EvidenceError) else "image.evidence.invalid"
            findings.append(Finding(value.name, code, str(error)))
    _write_json(
        output.resolve() / "images" / "summary.json",
        {
            "candidate": {"commit": candidate_sha, "tree": candidate_tree},
            "images": [
                {
                    "name": value.name,
                    "profile": _PROFILES[value.name],
                    "reference": value.expected_reference,
                }
                for value in sorted(images, key=lambda item: item.name)
            ],
            "scanner_image": scanner_image,
            "schema": "colortrace-final-image-evidence/v1",
            "findings": [finding.as_dict() for finding in sorted_findings(findings)],
            "status": "pass" if not findings else "fail",
        },
    )
    return sorted_findings(findings)
