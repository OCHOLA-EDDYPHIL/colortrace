from __future__ import annotations

import hashlib
import json
import os
import re
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
_REPORTS = (
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
_BOUND_INPUTS = (
    ".github/workflows/ci.yml",
    ".gitleaks.toml",
    "Makefile",
    "pnpm-lock.yaml",
    "policy/ai-boundary.json",
    "policy/dependency-inventory.json",
    "policy/dependency-policy.json",
    "policy/trivyignore.yaml",
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
    if name == "vulnerability.json":
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
    if name == "sbom.cdx.json":
        return (
            "pass"
            if isinstance(document, dict)
            and document.get("bomFormat") == "CycloneDX"
            and isinstance(document.get("components"), list)
            and bool(document["components"])
            else "fail"
        )
    return "fail"


def finalize_security_evidence(
    root: Path,
    output: Path,
    *,
    candidate_sha: str,
    candidate_tree: str,
    scanner_image: str,
    scanner_metadata: str,
    secret_scanner_image: str,
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
    for name in _REPORTS:
        path = output / name
        try:
            document = load_json(path)
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
        "status": "pass" if not findings else "fail",
        "tools": {
            "secret_scanner_image": secret_scanner_image,
            "vulnerability_scanner_image": scanner_image,
        },
    }
    _write_json(output / "manifest.json", manifest)
    return sorted_findings(findings)
