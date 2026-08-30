from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import quote

from colortrace_repo.actions import check_actions
from colortrace_repo.ai_policy import check_ai_policy
from colortrace_repo.common import Finding, load_json, sorted_findings
from colortrace_repo.dependencies import check_dependencies, resolved_locked_packages
from colortrace_repo.deployment import check_deployment, deployment_input_paths

_DIGEST = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_PROFILES = {
    "runtime": "private-full",
    "web": "public-readonly",
}
_SOURCE_REPORTS = (
    "action-pins.json",
    "ai-runtime.json",
    "dependency.json",
    "deployment.json",
    "runner-isolation.json",
    "sbom.cdx.json",
    "secret.json",
    "vulnerability.json",
    "vulnerability-scanner.json",
)
_IMAGE_REPORTS = tuple(
    f"images/{image}/{report}"
    for image in ("runtime", "web")
    for report in (
        "coverage.json",
        "enriched-sbom.cdx.json",
        "image-binding.json",
        "raw-sbom.cdx.json",
        "vulnerability.json",
    )
)
_REPORTS = (
    *_SOURCE_REPORTS,
    "mcp-grafana-reproducibility.json",
    "images/summary.json",
    *_IMAGE_REPORTS,
)
_BOUND_INPUTS = (
    ".github/workflows/ci.yml",
    ".gitleaks.toml",
    "Makefile",
    "containers/Dockerfile.runtime",
    "containers/Dockerfile.runtime.dockerignore",
    "containers/Dockerfile.web",
    "containers/Dockerfile.web.dockerignore",
    "config/grafana-mcp/build/go.mod",
    "config/grafana-mcp/build/go.sum",
    "config/grafana-mcp/build/modules.txt",
    "config/grafana-mcp/mcp-grafana.lock.json",
    "pnpm-lock.yaml",
    "policy/ai-boundary.json",
    "policy/dependency-inventory.json",
    "policy/dependency-policy.json",
    "policy/trivyignore.yaml",
    "packages/repo-tools/src/colortrace_repo/final_image_evidence.py",
    "packages/repo-tools/src/colortrace_repo/image_licenses.py",
    "packages/repo-tools/src/colortrace_repo/mcp_build_evidence.py",
    "uv.lock",
)


def _deployment_inputs(root: Path) -> tuple[str, ...]:
    return tuple(path.relative_to(root).as_posix() for path in deployment_input_paths(root))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _policy_report(command: str, findings: list[Finding]) -> dict[str, Any]:
    return {
        "command": command,
        "findings": [finding.as_dict() for finding in sorted_findings(findings)],
        "ok": not findings,
        "schema": "colortrace-security-policy-report/v1",
    }


def _license_inventory(root: Path) -> dict[tuple[str, str, str], str]:
    document = load_json(root / "policy" / "dependency-inventory.json")
    records: dict[tuple[str, str, str], str] = {}
    if not isinstance(document, dict) or not isinstance(document.get("packages"), list):
        return records
    for value in document["packages"]:
        if not isinstance(value, dict):
            continue
        ecosystem = value.get("ecosystem")
        name = value.get("name")
        version = value.get("version")
        license_expression = value.get("license")
        if not all(
            isinstance(item, str) for item in (ecosystem, name, version, license_expression)
        ):
            continue
        assert isinstance(ecosystem, str)
        assert isinstance(name, str)
        assert isinstance(version, str)
        assert isinstance(license_expression, str)
        records[(ecosystem, name, version)] = license_expression
    return records


def _purl(ecosystem: str, name: str, version: str) -> str:
    package_type = "pypi" if ecosystem == "pypi" else "npm"
    return f"pkg:{package_type}/{quote(name, safe='/')}@{quote(version, safe='')}"


def _lock_properties(root: Path) -> list[dict[str, str]]:
    return [
        {
            "name": f"colortrace:input:{name}:sha256",
            "value": _sha256(root / name).removeprefix("sha256:"),
        }
        for name in ("pnpm-lock.yaml", "uv.lock")
    ]


def build_sbom(root: Path) -> tuple[dict[str, Any], list[Finding]]:
    root = root.resolve()
    packages, lock_findings = resolved_locked_packages(root)
    dependency_findings = check_dependencies(root)
    licenses = _license_inventory(root)
    components: list[dict[str, Any]] = []
    for package in packages:
        purl = _purl(package.ecosystem, package.name, package.version)
        component: dict[str, Any] = {
            "bom-ref": purl,
            "name": package.name,
            "properties": [
                {"name": "colortrace:ecosystem", "value": package.ecosystem},
                {"name": "colortrace:registry", "value": package.source},
                *[
                    {"name": "colortrace:locked-integrity", "value": value}
                    for value in package.integrities
                ],
            ],
            "purl": purl,
            "type": "library",
            "version": package.version,
        }
        license_expression = licenses.get(package.identity)
        if license_expression is not None:
            component["licenses"] = [{"expression": license_expression}]
        components.append(component)
    component_refs = [component["bom-ref"] for component in components]
    root_ref = "urn:colortrace:repository"
    sbom = {
        "bomFormat": "CycloneDX",
        "components": components,
        "dependencies": [
            {"dependsOn": component_refs, "ref": root_ref},
            *[{"dependsOn": [], "ref": value} for value in component_refs],
        ],
        "metadata": {
            "component": {
                "bom-ref": root_ref,
                "name": "colortrace",
                "type": "application",
                "version": "0.0.0",
            },
            "properties": _lock_properties(root),
            "tools": {
                "components": [
                    {
                        "name": "colortrace-repo",
                        "type": "application",
                        "version": "0.1.0",
                    }
                ]
            },
        },
        "specVersion": "1.6",
        "version": 1,
    }
    return sbom, sorted_findings([*lock_findings, *dependency_findings])


def _runner_report() -> dict[str, Any]:
    endpoint = os.environ.get("COLORTRACE_DOCKER_ENDPOINT", "")
    if endpoint.startswith("tcp://127.0.0.1:"):
        endpoint_class = "loopback-tcp"
    elif endpoint:
        endpoint_class = "other"
    else:
        endpoint_class = "not-observed"
    return {
        "docker": {
            "endpoint_class": endpoint_class,
            "host_socket_present": os.environ.get(
                "COLORTRACE_HOST_DOCKER_SOCKET_PRESENT", "false"
            ).lower()
            == "true",
        },
        "limitations": [
            "This job-boundary observation does not attest host orchestration; "
            "the owner issue records the separate host inspection."
        ],
        "runner": {
            "arch": os.environ.get("COLORTRACE_RUNNER_ARCH", "unknown"),
            "ci": os.environ.get("COLORTRACE_CI", "").lower() == "true",
            "name": os.environ.get("COLORTRACE_RUNNER_NAME", "local"),
            "os": os.environ.get("COLORTRACE_RUNNER_OS", "unknown"),
        },
        "schema": "colortrace-runner-isolation-observation/v1",
    }


def prepare_security_evidence(root: Path, output: Path) -> list[Finding]:
    root = root.resolve()
    output = output.resolve()
    images = output / "images"
    if images.exists():
        if images.is_symlink() or not images.is_dir():
            return [Finding("images", "security.output.invalid", "image output is invalid")]
        shutil.rmtree(images)
    for name in (*_REPORTS, "manifest.json"):
        (output / name).unlink(missing_ok=True)
    dependency_findings = check_dependencies(root)
    ai_findings = check_ai_policy(root)
    action_findings = check_actions(root)
    deployment_findings = check_deployment(root)
    sbom, sbom_findings = build_sbom(root)
    _write_json(output / "dependency.json", _policy_report("dependencies", dependency_findings))
    _write_json(output / "ai-runtime.json", _policy_report("ai-policy", ai_findings))
    _write_json(output / "action-pins.json", _policy_report("actions", action_findings))
    _write_json(output / "deployment.json", _policy_report("deployment", deployment_findings))
    _write_json(output / "runner-isolation.json", _runner_report())
    _write_json(output / "sbom.cdx.json", sbom)
    return sorted_findings(
        [
            *dependency_findings,
            *ai_findings,
            *action_findings,
            *deployment_findings,
            *sbom_findings,
        ]
    )


def _report_status(name: str, document: Any) -> str:
    if name in {"action-pins.json", "ai-runtime.json", "dependency.json", "deployment.json"}:
        return "pass" if isinstance(document, dict) and document.get("ok") is True else "fail"
    if name == "secret.json":
        return "pass" if document == [] else "fail"
    if name == "vulnerability.json" or name.endswith("/vulnerability.json"):
        if not isinstance(document, dict) or not isinstance(document.get("Results"), list):
            return "fail"
        vulnerabilities = [
            finding
            for result in document["Results"]
            if isinstance(result, dict)
            for finding in (result.get("Vulnerabilities") or [])
        ]
        return "pass" if not vulnerabilities else "fail"
    if name == "vulnerability-scanner.json":
        if not isinstance(document, dict):
            return "fail"
        database = document.get("VulnerabilityDB")
        return (
            "pass"
            if isinstance(document.get("Version"), str)
            and isinstance(database, dict)
            and database.get("Version") == 2
            and isinstance(database.get("UpdatedAt"), str)
            else "fail"
        )
    if name == "runner-isolation.json":
        if not isinstance(document, dict):
            return "fail"
        runner = document.get("runner", {})
        docker = document.get("docker", {})
        if isinstance(runner, dict) and runner.get("ci") is True:
            return (
                "pass"
                if isinstance(docker, dict)
                and docker.get("endpoint_class") == "loopback-tcp"
                and docker.get("host_socket_present") is False
                else "fail"
            )
        return "informational"
    if name == "sbom.cdx.json" or name.endswith(("raw-sbom.cdx.json", "enriched-sbom.cdx.json")):
        return (
            "pass"
            if isinstance(document, dict)
            and document.get("bomFormat") == "CycloneDX"
            and isinstance(document.get("components"), list)
            and bool(document["components"])
            else "fail"
        )
    image_schemas = {
        "images/summary.json": "colortrace-final-image-evidence/v1",
        "mcp-grafana-reproducibility.json": "colortrace-mcp-build-reproducibility/v1",
        "coverage.json": "colortrace-final-image-coverage/v1",
        "image-binding.json": "colortrace-final-image-binding/v1",
    }
    schema = image_schemas.get(name) or next(
        (value for suffix, value in image_schemas.items() if name.endswith(suffix)), None
    )
    if schema is not None:
        return (
            "pass"
            if isinstance(document, dict)
            and document.get("status") == "pass"
            and document.get("schema") == schema
            else "fail"
        )
    return "fail"


def _image_report_findings(
    output: Path,
    documents: dict[str, Any],
    candidate_sha: str,
    candidate_tree: str,
    scanner_image: str,
) -> list[Finding]:
    findings: list[Finding] = []
    expected_candidate = {"commit": candidate_sha, "tree": candidate_tree}
    summary = documents.get("images/summary.json")
    if not isinstance(summary, dict):
        return findings
    if (
        summary.get("candidate") != expected_candidate
        or summary.get("scanner_image") != scanner_image
        or summary.get("findings") != []
    ):
        findings.append(
            Finding(
                "images/summary.json",
                "security.image.binding",
                "image summary differs from the finalized candidate or scanner",
            )
        )
    summary_images = summary.get("images")
    records: dict[str, dict[str, Any]] = {}
    if isinstance(summary_images, list):
        for value in summary_images:
            if isinstance(value, dict) and isinstance(value.get("name"), str):
                if value["name"] in records:
                    records.clear()
                    break
                records[value["name"]] = value
    if set(records) != set(_IMAGE_PROFILES):
        findings.append(
            Finding(
                "images/summary.json",
                "security.image.binding",
                "image summary does not contain one record per required image",
            )
        )
        return findings
    for image, profile in _IMAGE_PROFILES.items():
        prefix = f"images/{image}"
        coverage = documents.get(f"{prefix}/coverage.json")
        binding = documents.get(f"{prefix}/image-binding.json")
        if not isinstance(coverage, dict) or not isinstance(binding, dict):
            continue
        image_record = binding.get("image")
        coverage_image = coverage.get("image")
        report_hashes = binding.get("reports")
        bundle = binding.get("bundle")
        inputs = binding.get("inputs")
        digests_are_valid = isinstance(image_record, dict) and all(
            isinstance(image_record.get(key), str)
            and _SHA256.fullmatch(image_record[key]) is not None
            for key in (
                "archive_index_sha256",
                "archive_sha256",
                "config_digest",
                "image_digest",
                "platform_manifest_digest",
            )
        )
        bundle_is_valid = isinstance(bundle, dict) and all(
            isinstance(bundle.get(key), str) and _SHA256.fullmatch(bundle[key]) is not None
            for key in ("manifest_sha256", "sha256sums_sha256")
        )
        inputs_are_valid = (
            isinstance(inputs, list)
            and bool(inputs)
            and all(
                isinstance(value, dict)
                and isinstance(value.get("path"), str)
                and isinstance(value.get("sha256"), str)
                and _SHA256.fullmatch(value["sha256"]) is not None
                and isinstance(value.get("size_bytes"), int)
                for value in inputs
            )
        )
        expected_hashes = {
            "coverage_sha256": _sha256(output / prefix / "coverage.json"),
            "enriched_sbom_sha256": _sha256(output / prefix / "enriched-sbom.cdx.json"),
            "raw_sbom_sha256": _sha256(output / prefix / "raw-sbom.cdx.json"),
        }
        expected_image = (
            {
                key: image_record.get(key)
                for key in (
                    "archive_index_sha256",
                    "archive_sha256",
                    "config_digest",
                    "image_digest",
                    "platform_manifest_digest",
                    "reference",
                )
            }
            if isinstance(image_record, dict)
            else None
        )
        if any(
            (
                records[image].get("profile") != profile,
                records[image].get("reference")
                != (image_record.get("reference") if isinstance(image_record, dict) else None),
                coverage.get("candidate") != expected_candidate,
                binding.get("candidate") != expected_candidate,
                coverage.get("profile") != profile,
                binding.get("profile") != profile,
                coverage.get("scanner_image") != scanner_image,
                binding.get("scanner_image") != scanner_image,
                coverage.get("findings") != [],
                coverage.get("bundle") != binding.get("bundle"),
                coverage.get("source_inputs") != binding.get("inputs"),
                coverage_image != expected_image,
                report_hashes != expected_hashes,
                not digests_are_valid,
                not bundle_is_valid,
                not inputs_are_valid,
            )
        ):
            findings.append(
                Finding(
                    prefix,
                    "security.image.binding",
                    "image reports are stale, substituted, or internally inconsistent",
                )
            )
    return findings


def _mcp_reproducibility_findings(
    root: Path,
    document: Any,
    candidate_sha: str,
    candidate_tree: str,
) -> list[Finding]:
    path = "mcp-grafana-reproducibility.json"
    if not isinstance(document, dict):
        return [Finding(path, "security.mcp.reproducibility", "MCP report is invalid")]
    lock_path = root / "config" / "grafana-mcp" / "mcp-grafana.lock.json"
    try:
        lock = load_json(lock_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [
            Finding(
                path,
                "security.mcp.reproducibility",
                f"cannot load the MCP runtime lock: {error}",
            )
        ]
    expected_binary = f"sha256:{lock.get('binary_sha256')}" if isinstance(lock, dict) else None
    builds = document.get("builds")
    valid_builds = (
        isinstance(builds, list)
        and len(builds) == 2
        and [build.get("ordinal") for build in builds if isinstance(build, dict)] == [1, 2]
        and len({build.get("binary_sha256") for build in builds if isinstance(build, dict)}) == 1
        and len({build.get("image_identity") for build in builds if isinstance(build, dict)}) == 1
        and all(
            isinstance(build, dict)
            and build.get("binary_sha256") == expected_binary
            and isinstance(build.get("archive_sha256"), str)
            and _SHA256.fullmatch(build["archive_sha256"]) is not None
            and isinstance(build.get("config_digest"), str)
            and _SHA256.fullmatch(build["config_digest"]) is not None
            and isinstance(build.get("image_identity"), str)
            and _SHA256.fullmatch(build["image_identity"]) is not None
            for build in builds
        )
        and len({build.get("config_digest") for build in builds}) == 1
    )
    if any(
        (
            document.get("candidate") != {"commit": candidate_sha, "tree": candidate_tree},
            document.get("findings") != [],
            document.get("method") != "two-buildx-mcp-no-cache-builds",
            document.get("runtime_lock_sha256") != _sha256(lock_path),
            not valid_builds,
        )
    ):
        return [
            Finding(
                path,
                "security.mcp.reproducibility",
                "MCP build evidence is stale, substituted, or internally inconsistent",
            )
        ]
    return []


def finalize_security_evidence(
    root: Path,
    output: Path,
    *,
    candidate_sha: str,
    candidate_tree: str,
    scanner_image: str,
    scanner_metadata: str,
    secret_scanner_image: str,
    require_images: bool,
) -> list[Finding]:
    root = root.resolve()
    output = output.resolve()
    findings: list[Finding] = []
    if _DIGEST.fullmatch(candidate_sha) is None:
        findings.append(Finding("", "security.candidate.invalid", "candidate SHA is invalid"))
    if _DIGEST.fullmatch(candidate_tree) is None:
        findings.append(Finding("", "security.candidate.invalid", "candidate tree is invalid"))
    if _IMAGE_DIGEST.fullmatch(scanner_image) is None:
        findings.append(
            Finding(
                "",
                "security.tool.invalid",
                "vulnerability scanner image is not digest-pinned",
            )
        )
    if _IMAGE_DIGEST.fullmatch(secret_scanner_image) is None:
        findings.append(
            Finding("", "security.tool.invalid", "secret scanner image is not digest-pinned")
        )
    try:
        parsed_scanner_metadata = json.loads(scanner_metadata)
    except json.JSONDecodeError as error:
        parsed_scanner_metadata = {}
        findings.append(
            Finding(
                "vulnerability-scanner.json",
                "security.report.invalid",
                f"cannot parse scanner metadata: {error}",
            )
        )
    _write_json(output / "vulnerability-scanner.json", parsed_scanner_metadata)
    reports: list[dict[str, Any]] = []
    documents: dict[str, Any] = {}
    expected_reports = _REPORTS if require_images else _SOURCE_REPORTS
    for name in expected_reports:
        path = output / name
        try:
            if path.is_symlink() or not path.is_file():
                raise OSError("report must be a regular, non-symlink file")
            document = load_json(path)
            documents[name] = document
            status = _report_status(name, document)
            reports.append(
                {
                    "path": name,
                    "sha256": _sha256(path),
                    "size_bytes": path.stat().st_size,
                    "status": status,
                }
            )
            if status == "fail":
                findings.append(
                    Finding(name, "security.report.failed", "security report did not pass")
                )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            findings.append(
                Finding(name, "security.report.invalid", f"cannot load report: {error}")
            )
    if require_images:
        mcp_reproducibility = documents.get("mcp-grafana-reproducibility.json")
        if mcp_reproducibility is not None:
            findings.extend(
                _mcp_reproducibility_findings(
                    root,
                    mcp_reproducibility,
                    candidate_sha,
                    candidate_tree,
                )
            )
        try:
            findings.extend(
                _image_report_findings(
                    output,
                    documents,
                    candidate_sha,
                    candidate_tree,
                    scanner_image,
                )
            )
        except OSError as error:
            findings.append(
                Finding(
                    "images",
                    "security.image.binding",
                    f"cannot verify image report hashes: {error}",
                )
            )
    inputs: list[dict[str, Any]] = []
    for name in dict.fromkeys((*_BOUND_INPUTS, *_deployment_inputs(root))):
        path = root / name
        if not path.is_file():
            findings.append(Finding(name, "security.input.missing", "bound input is missing"))
            continue
        if path.is_symlink():
            findings.append(
                Finding(
                    name,
                    "security.input.invalid",
                    "bound input must be a regular candidate file",
                )
            )
            continue
        inputs.append(
            {
                "path": name,
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    manifest = {
        "candidate": {"commit": candidate_sha, "tree": candidate_tree},
        "inputs": inputs,
        "reports": reports,
        "schema": "colortrace-security-evidence-manifest/v1",
        "scope": "final-images" if require_images else "source",
        "status": "pass" if not findings else "fail",
        "tools": {
            "secret_scanner_image": secret_scanner_image,
            "vulnerability_scanner_image": scanner_image,
        },
    }
    _write_json(output / "manifest.json", manifest)
    return sorted_findings(findings)
