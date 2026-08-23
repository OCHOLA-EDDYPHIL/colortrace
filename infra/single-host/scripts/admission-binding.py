#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

BUILD_SCHEMA = "colortrace-single-host-image-build/v2"
SCAN_SCHEMA = "colortrace-single-host-image-scan/v2"
ADMISSION_SCHEMA = "colortrace-single-host-admission/v1"
TRIVY_IMAGE = (
    "aquasec/trivy@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"
)
FROZEN_DATABASE_IMAGE = (
    "ghcr.io/aquasecurity/trivy-db@sha256:"
    "67136d9c032b639278e256601e29b8af0ff4ed28e66d859e4cac692f7c1deef6"
)
FROZEN_DATABASE_SHA256 = "sha256:eb94cd71f35e20ce5b572803f65009bb61a13a75f8d7c4f1f111ec732c98d314"
FROZEN_DATABASE_UPDATED_AT = "2026-08-22T12:57:22.518776499Z"
FROZEN_DATABASE_NEXT_UPDATE = "2026-08-23T12:57:22.518775968Z"
PROMETHEUS_REFERENCE = (
    "docker.io/prom/prometheus@sha256:"
    "5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0"
)
PROMETHEUS_UPSTREAM = {
    "version": "3.14.0",
    "index_digest": "sha256:5ce7540c3c00ef4ab0c9d2c995c6a5b9c421f44b4a115d97a2c7af3b1c21cbb0",
    "linux_amd64_digest": "sha256:e906cef998316bbe319f98711e1b4d8613ad37e14b08ff831d7036e77b7464f9",
}
COMPONENTS = ("runtime", "web", "caddy", "grafana", "loki", "tempo")
SCAN_COMPONENTS = (*COMPONENTS[:5], "prometheus", COMPONENTS[5])
BUILD_PATHS: dict[str, tuple[str, str | None]] = {
    "runtime": ("Dockerfile.runtime", "runtime"),
    "web": ("Dockerfile.web", None),
    "caddy": ("Dockerfile.caddy", None),
    "grafana": ("Dockerfile.observability", "grafana"),
    "loki": ("Dockerfile.observability", "loki"),
    "tempo": ("Dockerfile.observability", "tempo"),
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
PREFIX = re.compile(r"^[a-z][a-z0-9-]{2,19}[a-z0-9]$")
BUILD_ID = re.compile(r"^[A-Za-z0-9-]+$")
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BUILD_CONFIG = REPOSITORY_ROOT / "infra/single-host/cloudbuild.images.yaml"
FIXTURE_DIGESTS = REPOSITORY_ROOT / "packages/fixture-generator/fixtures/canonical-digests.json"
OBSERVABILITY_LOCK = REPOSITORY_ROOT / "config/observability/images.lock.json"


class BindingError(ValueError):
    pass


def _pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise BindingError("duplicate-json-key")
        result[key] = value
    return result


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(BindingError()),
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise BindingError(f"invalid-json:{path.name}") from error
    if not isinstance(value, dict):
        raise BindingError(f"invalid-object:{path.name}")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sha256_file(path: Path) -> str:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise BindingError(f"unreadable-file:{path.name}") from error
    return f"sha256:{digest.hexdigest()}"


def _require_keys(value: dict[str, Any], expected: set[str], code: str) -> None:
    if set(value) != expected:
        raise BindingError(code)


def _require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise BindingError(code)
    return value


def _validate_build(value: dict[str, Any]) -> tuple[str, str, str]:
    _require_keys(
        value,
        {"schema", "build", "source", "fixture_manifest_sha256", "images"},
        "build-fields-invalid",
    )
    if value["schema"] != BUILD_SCHEMA:
        raise BindingError("build-schema-invalid")
    build = value["build"]
    source = value["source"]
    images = value["images"]
    if not isinstance(build, dict) or not isinstance(source, dict) or not isinstance(images, dict):
        raise BindingError("build-shape-invalid")
    _require_keys(
        build,
        {
            "id",
            "project",
            "region",
            "service_account",
            "registry",
            "config_sha256",
            "create_time",
            "finish_time",
        },
        "build-identity-invalid",
    )
    _require_keys(source, {"commit", "tree", "date_epoch"}, "build-source-invalid")
    if (
        not isinstance(build["id"], str)
        or BUILD_ID.fullmatch(build["id"]) is None
        or not isinstance(build["project"], str)
        or PROJECT.fullmatch(build["project"]) is None
        or build["region"] != "us-central1"
        or not isinstance(build["create_time"], str)
        or not build["create_time"]
        or not isinstance(build["finish_time"], str)
        or not build["finish_time"]
    ):
        raise BindingError("build-identity-invalid")
    if build["config_sha256"] != _sha256_file(BUILD_CONFIG):
        raise BindingError("build-config-digest-invalid")
    registry_match = re.fullmatch(
        r"us-central1-docker\.pkg\.dev/([a-z][a-z0-9-]{4,28}[a-z0-9])/"
        r"([a-z][a-z0-9-]{2,19}[a-z0-9])-images",
        str(build["registry"]),
    )
    if registry_match is None:
        raise BindingError("build-registry-invalid")
    project, prefix = registry_match.groups()
    if project != build["project"] or PREFIX.fullmatch(prefix) is None:
        raise BindingError("build-registry-invalid")
    expected_builder = (
        f"projects/{project}/serviceAccounts/{prefix}-builder@{project}.iam.gserviceaccount.com"
    )
    if build["service_account"] != expected_builder:
        raise BindingError("build-service-account-invalid")
    if (
        not isinstance(source["commit"], str)
        or COMMIT.fullmatch(source["commit"]) is None
        or not isinstance(source["tree"], str)
        or COMMIT.fullmatch(source["tree"]) is None
        or not isinstance(source["date_epoch"], int)
        or isinstance(source["date_epoch"], bool)
        or source["date_epoch"] <= 0
    ):
        raise BindingError("build-source-invalid")
    fixture_digests = _load(FIXTURE_DIGESTS)
    try:
        expected_fixture_digest = (
            "sha256:" + fixture_digests["files"]["runtime/manifests/fixture-runtime-manifest.json"]
        )
    except (KeyError, TypeError) as error:
        raise BindingError("fixture-source-invalid") from error
    if value["fixture_manifest_sha256"] != expected_fixture_digest:
        raise BindingError("fixture-digest-invalid")
    if set(images) != set(COMPONENTS):
        raise BindingError("build-components-invalid")
    for component in COMPONENTS:
        image = images[component]
        if not isinstance(image, dict):
            raise BindingError("build-image-invalid")
        _require_keys(
            image,
            {"dockerfile", "target", "tag", "digest", "reference"},
            "build-image-invalid",
        )
        dockerfile, target = BUILD_PATHS[component]
        digest = _require_digest(image["digest"], "build-image-digest-invalid")
        tag = f"{build['registry']}/{component}:{source['commit']}"
        if (
            image["dockerfile"] != dockerfile
            or image["target"] != target
            or image["tag"] != tag
            or image["reference"] != f"{build['registry']}/{component}@{digest}"
        ):
            raise BindingError("build-image-binding-invalid")
    return project, prefix, source["commit"]


def _validate_observability(lock: dict[str, Any]) -> None:
    try:
        prometheus = lock["upstream"]["prometheus"]
    except (KeyError, TypeError) as error:
        raise BindingError("prometheus-lock-invalid") from error
    if (
        lock.get("schema") != "colortrace-staging-observability-images/v2"
        or prometheus != PROMETHEUS_UPSTREAM
    ):
        raise BindingError("prometheus-lock-invalid")


def _expected_scan_images(build: dict[str, Any], observability: dict[str, Any]) -> dict[str, Any]:
    _validate_observability(observability)
    images = dict(build["images"])
    images["prometheus"] = {
        "reference": PROMETHEUS_REFERENCE,
        "upstream": observability["upstream"]["prometheus"],
    }
    return images


def _report_records(output: Path, images: dict[str, Any]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for database in ("current", "frozen"):
        for component in SCAN_COMPONENTS:
            filename = f"{database}-{component}.json"
            report_path = output / filename
            report = _load(report_path)
            expected_reference = images[component]["reference"]
            accepted_artifact_names = {expected_reference}
            if component == "prometheus":
                accepted_artifact_names.add(expected_reference.removeprefix("docker.io/"))
            results = report.get("Results")
            if report.get("ArtifactName") not in accepted_artifact_names or not isinstance(
                results, list
            ):
                raise BindingError(f"scan-report-invalid:{filename}")
            for result in results:
                if not isinstance(result, dict):
                    raise BindingError(f"scan-report-invalid:{filename}")
                vulnerabilities = result.get("Vulnerabilities")
                if vulnerabilities is not None and not isinstance(vulnerabilities, list):
                    raise BindingError(f"scan-report-invalid:{filename}")
                if vulnerabilities:
                    raise BindingError(f"scan-report-vulnerable:{filename}")
            records.append(
                {
                    "database": database,
                    "component": component,
                    "file": filename,
                    "sha256": _sha256_file(report_path),
                }
            )
    return records


def _validate_database_metadata(value: dict[str, Any], *, frozen: bool) -> None:
    if (
        set(value) != {"Version", "NextUpdate", "UpdatedAt", "DownloadedAt"}
        or value.get("Version") != 2
        or not isinstance(value.get("NextUpdate"), str)
        or not value["NextUpdate"]
        or not isinstance(value.get("UpdatedAt"), str)
        or not value["UpdatedAt"]
        or not isinstance(value.get("DownloadedAt"), str)
        or not value["DownloadedAt"]
    ):
        raise BindingError("database-metadata-invalid")
    if frozen and (
        value["UpdatedAt"] != FROZEN_DATABASE_UPDATED_AT
        or value["NextUpdate"] != FROZEN_DATABASE_NEXT_UPDATE
    ):
        raise BindingError("database-metadata-invalid")


def _atomic_json(path: Path, value: Any, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as target:
            target.write(json.dumps(value, sort_keys=True, indent=2).encode("utf-8"))
            target.write(b"\n")
            target.flush()
            os.fsync(target.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _expected_evidence_files() -> set[str]:
    files = {
        "current-db-metadata.json",
        "frozen-db-metadata.json",
        "scanner.json",
        "scan-bindings.json",
    }
    files.update(
        f"{database}-{component}.json"
        for database in ("current", "frozen")
        for component in SCAN_COMPONENTS
    )
    return files


def _write_checksums(output: Path) -> None:
    paths = list(output.glob("*.json"))
    if {path.name for path in paths} != _expected_evidence_files():
        raise BindingError("scan-evidence-files-invalid")
    entries = []
    for path in sorted(paths, key=lambda selected: selected.name):
        entries.append(f"{_sha256_file(path).removeprefix('sha256:')}  {path.name}\n")
    checksum_path = output / "SHA256SUMS"
    descriptor, temporary_name = tempfile.mkstemp(prefix=".SHA256SUMS.", dir=output)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as target:
            target.writelines(entries)
            target.flush()
            os.fsync(target.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, checksum_path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def record_scan(arguments: argparse.Namespace) -> None:
    manifest_path = arguments.build_manifest.resolve(strict=True)
    observability_path = arguments.observability_lock.resolve(strict=True)
    output = arguments.output.resolve(strict=True)
    build = _load(manifest_path)
    observability = _load(observability_path)
    _validate_build(build)
    if _sha256_file(observability_path) != _sha256_file(OBSERVABILITY_LOCK):
        raise BindingError("observability-lock-digest-invalid")
    images = _expected_scan_images(build, observability)
    current_metadata = _load(output / "current-db-metadata.json")
    frozen_metadata = _load(output / "frozen-db-metadata.json")
    _validate_database_metadata(current_metadata, frozen=False)
    _validate_database_metadata(frozen_metadata, frozen=True)
    scanner = _load(output / "scanner.json")
    if not isinstance(scanner.get("Version"), str) or not scanner["Version"]:
        raise BindingError("scanner-version-invalid")
    reports = _report_records(output, images)
    binding = {
        "schema": SCAN_SCHEMA,
        "build_manifest_sha256": _sha256_file(manifest_path),
        "observability_lock_sha256": _sha256_file(observability_path),
        "build": build["build"],
        "source": build["source"],
        "fixture_manifest_sha256": build["fixture_manifest_sha256"],
        "images": images,
        "scanner": {"image": TRIVY_IMAGE, "version": scanner},
        "databases": {
            "current": {
                "content_sha256": arguments.current_database_sha256,
                "metadata_sha256": _sha256_file(output / "current-db-metadata.json"),
                "updated_at": current_metadata["UpdatedAt"],
            },
            "frozen": {
                "image": FROZEN_DATABASE_IMAGE,
                "content_sha256": arguments.frozen_database_sha256,
                "metadata_sha256": _sha256_file(output / "frozen-db-metadata.json"),
                "updated_at": frozen_metadata["UpdatedAt"],
            },
        },
        "reports": reports,
        "severities": ["HIGH", "CRITICAL"],
        "vulnerability_ignores": False,
        "result": "pass",
    }
    _require_digest(arguments.current_database_sha256, "current-database-digest-invalid")
    if arguments.frozen_database_sha256 != FROZEN_DATABASE_SHA256:
        raise BindingError("frozen-database-digest-invalid")
    _atomic_json(output / "scan-bindings.json", binding, mode=0o600)
    _write_checksums(output)


def _validate_checksum_file(output: Path) -> None:
    checksum_path = output / "SHA256SUMS"
    try:
        lines = checksum_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise BindingError("scan-checksums-invalid") from error
    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9.-]*\.json)", line)
        if match is None or match.group(2) in entries:
            raise BindingError("scan-checksums-invalid")
        entries[match.group(2)] = f"sha256:{match.group(1)}"
    expected = _expected_evidence_files()
    if set(entries) != expected:
        raise BindingError("scan-checksums-invalid")
    for filename, digest in entries.items():
        if _sha256_file(output / filename) != digest:
            raise BindingError("scan-checksums-invalid")


def _validate_scan(
    value: dict[str, Any],
    *,
    scan_path: Path,
    build: dict[str, Any],
    build_path: Path,
) -> None:
    _require_keys(
        value,
        {
            "schema",
            "build_manifest_sha256",
            "observability_lock_sha256",
            "build",
            "source",
            "fixture_manifest_sha256",
            "images",
            "scanner",
            "databases",
            "reports",
            "severities",
            "vulnerability_ignores",
            "result",
        },
        "scan-fields-invalid",
    )
    if (
        value["schema"] != SCAN_SCHEMA
        or value["build_manifest_sha256"] != _sha256_file(build_path)
        or value["observability_lock_sha256"] != _sha256_file(OBSERVABILITY_LOCK)
        or value["build"] != build["build"]
        or value["source"] != build["source"]
        or value["fixture_manifest_sha256"] != build["fixture_manifest_sha256"]
        or value["severities"] != ["HIGH", "CRITICAL"]
        or value["vulnerability_ignores"] is not False
        or value["result"] != "pass"
    ):
        raise BindingError("scan-binding-invalid")
    scanner = value["scanner"]
    databases = value["databases"]
    if (
        not isinstance(scanner, dict)
        or scanner.get("image") != TRIVY_IMAGE
        or not isinstance(scanner.get("version"), dict)
        or not isinstance(databases, dict)
        or set(databases) != {"current", "frozen"}
    ):
        raise BindingError("scan-tooling-invalid")
    current = databases["current"]
    frozen = databases["frozen"]
    if not isinstance(current, dict) or not isinstance(frozen, dict):
        raise BindingError("scan-database-invalid")
    for database in (current, frozen):
        _require_digest(database.get("content_sha256"), "scan-database-invalid")
        _require_digest(database.get("metadata_sha256"), "scan-database-invalid")
        if not isinstance(database.get("updated_at"), str):
            raise BindingError("scan-database-invalid")
    if (
        frozen.get("image") != FROZEN_DATABASE_IMAGE
        or frozen.get("content_sha256") != FROZEN_DATABASE_SHA256
        or frozen.get("updated_at") != FROZEN_DATABASE_UPDATED_AT
        or set(current) != {"content_sha256", "metadata_sha256", "updated_at"}
        or set(frozen) != {"image", "content_sha256", "metadata_sha256", "updated_at"}
    ):
        raise BindingError("scan-database-invalid")
    observability = _load(OBSERVABILITY_LOCK)
    expected_images = _expected_scan_images(build, observability)
    if value["images"] != expected_images:
        raise BindingError("scan-images-invalid")
    if scanner["version"] != _load(scan_path.parent / "scanner.json"):
        raise BindingError("scan-tooling-invalid")
    if current["metadata_sha256"] != _sha256_file(
        scan_path.parent / "current-db-metadata.json"
    ) or frozen["metadata_sha256"] != _sha256_file(scan_path.parent / "frozen-db-metadata.json"):
        raise BindingError("scan-database-invalid")
    current_metadata = _load(scan_path.parent / "current-db-metadata.json")
    frozen_metadata = _load(scan_path.parent / "frozen-db-metadata.json")
    _validate_database_metadata(current_metadata, frozen=False)
    _validate_database_metadata(frozen_metadata, frozen=True)
    if (
        current_metadata["UpdatedAt"] != current["updated_at"]
        or frozen_metadata["UpdatedAt"] != frozen["updated_at"]
    ):
        raise BindingError("scan-database-invalid")
    expected_reports = _report_records(scan_path.parent, value["images"])
    if value["reports"] != expected_reports:
        raise BindingError("scan-report-checksums-invalid")
    _validate_checksum_file(scan_path.parent)


def prepare(arguments: argparse.Namespace) -> None:
    build_path = arguments.build_manifest.resolve(strict=True)
    scan_path = arguments.scan_binding.resolve(strict=True)
    build = _load(build_path)
    scan = _load(scan_path)
    project, prefix, _commit = _validate_build(build)
    _validate_scan(scan, scan_path=scan_path, build=build, build_path=build_path)
    image_references = {
        component: scan["images"][component]["reference"] for component in SCAN_COMPONENTS
    }
    artifact_binding = {
        "schema": ADMISSION_SCHEMA,
        "build_manifest_sha256": _sha256_file(build_path),
        "scan_binding_sha256": _sha256_file(scan_path),
        "observability_lock_sha256": scan["observability_lock_sha256"],
        "build": build["build"],
        "source": build["source"],
        "fixture_manifest_sha256": build["fixture_manifest_sha256"],
        "images": image_references,
        "scanner": {
            "image": scan["scanner"]["image"],
            "version_sha256": _sha256_bytes(_canonical(scan["scanner"]["version"])),
            "databases": scan["databases"],
            "report_set_sha256": _sha256_bytes(_canonical(scan["reports"])),
        },
    }
    result = {
        "project_id": project,
        "region": build["build"]["region"],
        "resource_prefix": prefix,
        "deployment_artifact_binding": artifact_binding,
        "deployment_artifact_binding_sha256": _sha256_bytes(_canonical(artifact_binding)),
    }
    _validate_admission(result)
    _atomic_json(arguments.output.resolve(), result, mode=0o600)


def validate_build(arguments: argparse.Namespace) -> None:
    _validate_build(_load(arguments.build_manifest.resolve(strict=True)))


def _validate_admission(value: dict[str, Any]) -> dict[str, Any]:
    _require_keys(
        value,
        {
            "project_id",
            "region",
            "resource_prefix",
            "deployment_artifact_binding",
            "deployment_artifact_binding_sha256",
        },
        "admission-fields-invalid",
    )
    binding = value["deployment_artifact_binding"]
    if not isinstance(binding, dict):
        raise BindingError("admission-binding-invalid")
    _require_keys(
        binding,
        {
            "schema",
            "build_manifest_sha256",
            "scan_binding_sha256",
            "observability_lock_sha256",
            "build",
            "source",
            "fixture_manifest_sha256",
            "images",
            "scanner",
        },
        "admission-binding-fields-invalid",
    )
    for field in (
        "build_manifest_sha256",
        "scan_binding_sha256",
        "observability_lock_sha256",
        "fixture_manifest_sha256",
    ):
        _require_digest(binding[field], f"admission-{field}-invalid")
    build = binding["build"]
    source = binding["source"]
    images = binding["images"]
    scanner = binding["scanner"]
    if not all(isinstance(item, dict) for item in (build, source, images, scanner)):
        raise BindingError("admission-shape-invalid")
    _require_keys(
        build,
        {
            "id",
            "project",
            "region",
            "service_account",
            "registry",
            "config_sha256",
            "create_time",
            "finish_time",
        },
        "admission-build-invalid",
    )
    _require_keys(source, {"commit", "tree", "date_epoch"}, "admission-source-invalid")
    _require_keys(
        scanner,
        {"image", "version_sha256", "databases", "report_set_sha256"},
        "admission-scanner-invalid",
    )
    fixture_digests = _load(FIXTURE_DIGESTS)
    try:
        expected_fixture_digest = (
            "sha256:" + fixture_digests["files"]["runtime/manifests/fixture-runtime-manifest.json"]
        )
    except (KeyError, TypeError) as error:
        raise BindingError("fixture-source-invalid") from error
    if (
        binding["schema"] != ADMISSION_SCHEMA
        or binding["observability_lock_sha256"] != _sha256_file(OBSERVABILITY_LOCK)
        or build["config_sha256"] != _sha256_file(BUILD_CONFIG)
        or binding["fixture_manifest_sha256"] != expected_fixture_digest
        or value["project_id"] != build["project"]
        or value["region"] != build["region"]
        or build["region"] != "us-central1"
        or value["deployment_artifact_binding_sha256"] != _sha256_bytes(_canonical(binding))
    ):
        raise BindingError("admission-binding-invalid")
    project = value["project_id"]
    prefix = value["resource_prefix"]
    if (
        not isinstance(project, str)
        or PROJECT.fullmatch(project) is None
        or not isinstance(prefix, str)
        or PREFIX.fullmatch(prefix) is None
        or build["registry"] != f"us-central1-docker.pkg.dev/{project}/{prefix}-images"
        or build["service_account"]
        != f"projects/{project}/serviceAccounts/{prefix}-builder@{project}.iam.gserviceaccount.com"
    ):
        raise BindingError("admission-build-invalid")
    if (
        not isinstance(build["id"], str)
        or BUILD_ID.fullmatch(build["id"]) is None
        or not isinstance(build["create_time"], str)
        or not build["create_time"]
        or not isinstance(build["finish_time"], str)
        or not build["finish_time"]
        or not isinstance(source["commit"], str)
        or COMMIT.fullmatch(source["commit"]) is None
        or not isinstance(source["tree"], str)
        or COMMIT.fullmatch(source["tree"]) is None
        or not isinstance(source["date_epoch"], int)
        or isinstance(source["date_epoch"], bool)
        or source["date_epoch"] <= 0
    ):
        raise BindingError("admission-identity-invalid")
    if set(images) != set(SCAN_COMPONENTS):
        raise BindingError("admission-images-invalid")
    for component in COMPONENTS:
        expected_prefix = f"{build['registry']}/{component}@sha256:"
        reference = images[component]
        if (
            not isinstance(reference, str)
            or not reference.startswith(expected_prefix)
            or DIGEST.fullmatch(reference.rsplit("@", 1)[1]) is None
        ):
            raise BindingError("admission-images-invalid")
    if images["prometheus"] != PROMETHEUS_REFERENCE:
        raise BindingError("admission-images-invalid")
    databases = scanner.get("databases")
    if not isinstance(databases, dict) or set(databases) != {"current", "frozen"}:
        raise BindingError("admission-scanner-invalid")
    current = databases["current"]
    frozen = databases["frozen"]
    if not isinstance(current, dict) or not isinstance(frozen, dict):
        raise BindingError("admission-scanner-invalid")
    if (
        set(current) != {"content_sha256", "metadata_sha256", "updated_at"}
        or set(frozen) != {"image", "content_sha256", "metadata_sha256", "updated_at"}
        or not isinstance(current.get("updated_at"), str)
        or not current["updated_at"]
    ):
        raise BindingError("admission-scanner-invalid")
    if (
        scanner.get("image") != TRIVY_IMAGE
        or frozen.get("image") != FROZEN_DATABASE_IMAGE
        or frozen.get("content_sha256") != FROZEN_DATABASE_SHA256
        or frozen.get("updated_at") != FROZEN_DATABASE_UPDATED_AT
    ):
        raise BindingError("admission-scanner-invalid")
    for digest in (
        scanner.get("version_sha256"),
        scanner.get("report_set_sha256"),
        current.get("content_sha256"),
        current.get("metadata_sha256"),
        frozen.get("metadata_sha256"),
    ):
        _require_digest(digest, "admission-scanner-invalid")
    return binding


def validate_admission(arguments: argparse.Namespace) -> None:
    value = _load(arguments.admission.resolve(strict=True))
    binding = _validate_admission(value)
    if arguments.output is not None:
        _atomic_json(arguments.output.resolve(), binding, mode=0o600)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("validate-build")
    build.add_argument("build_manifest", type=Path)
    build.set_defaults(handler=validate_build)
    record = subparsers.add_parser("record-scan")
    record.add_argument("build_manifest", type=Path)
    record.add_argument("observability_lock", type=Path)
    record.add_argument("output", type=Path)
    record.add_argument("current_database_sha256")
    record.add_argument("frozen_database_sha256")
    record.set_defaults(handler=record_scan)
    admission = subparsers.add_parser("prepare")
    admission.add_argument("build_manifest", type=Path)
    admission.add_argument("scan_binding", type=Path)
    admission.add_argument("output", type=Path)
    admission.set_defaults(handler=prepare)
    validate = subparsers.add_parser("validate-admission")
    validate.add_argument("admission", type=Path)
    validate.add_argument("output", type=Path, nargs="?")
    validate.set_defaults(handler=validate_admission)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        arguments.handler(arguments)
    except BindingError as error:
        print(f"admission-binding: {error}", file=os.sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
