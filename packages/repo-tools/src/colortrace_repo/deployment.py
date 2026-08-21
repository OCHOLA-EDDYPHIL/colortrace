from __future__ import annotations

import re
from pathlib import Path

from colortrace_repo.common import Finding, relative_path, sorted_findings, walk_files

_EXACT_VERSION = re.compile(
    r'^\s*(?:required_version|version)\s*=\s*"= [0-9]+\.[0-9]+\.[0-9]+"\s*$', re.MULTILINE
)
_PROVIDER_SOURCE = re.compile(r'^\s*source\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
_RESOURCE = re.compile(r'^\s*(?:data|resource)\s+"([^"]+)"', re.MULTILINE)
_FROM = re.compile(r"^\s*FROM\s+([^\s]+)", re.IGNORECASE | re.MULTILINE)
_REMOTE_ADD = re.compile(r"^\s*ADD\s+([^\n]*https://[^\s]+[^\n]*)$", re.IGNORECASE | re.MULTILINE)
_MUTABLE_IMAGE = re.compile(
    r"(?:image\s*=|docker\.pkg\.dev/)[^\n]*(?::latest\b|@latest\b)", re.IGNORECASE
)
_ALTERNATE_CLOUD_OR_AI = re.compile(
    r"\b(?:anthropic|bedrock|openai|azure(?:rm)?|aws)\b",
    re.IGNORECASE,
)


def _read(root: Path, path: Path) -> tuple[str | None, list[Finding]]:
    try:
        return path.read_text(encoding="utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [Finding(relative_path(root, path), "deployment.source.invalid", str(error))]


def _terraform_findings(root: Path, paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    provider_sources: set[str] = set()
    exact_versions = 0
    for path in paths:
        source, errors = _read(root, path)
        findings.extend(errors)
        if source is None:
            continue
        display_path = relative_path(root, path)
        provider_sources.update(_PROVIDER_SOURCE.findall(source))
        exact_versions += len(_EXACT_VERSION.findall(source))
        for resource_type in _RESOURCE.findall(source):
            if not resource_type.startswith("google_"):
                findings.append(
                    Finding(
                        display_path,
                        "deployment.terraform.provider",
                        f"resource type {resource_type!r} is outside the Google Cloud boundary",
                    )
                )
        if _MUTABLE_IMAGE.search(source):
            findings.append(
                Finding(
                    display_path,
                    "deployment.image.mutable",
                    "deployment image references may not use a mutable latest tag",
                )
            )
        if _ALTERNATE_CLOUD_OR_AI.search(source):
            findings.append(
                Finding(
                    display_path,
                    "deployment.runtime.provider",
                    "Terraform source names a cloud or AI provider outside "
                    "the accepted Google boundary",
                )
            )
    if paths and provider_sources != {"hashicorp/google"}:
        findings.append(
            Finding(
                "infra",
                "deployment.terraform.provider",
                "Terraform must use only the hashicorp/google provider",
            )
        )
    if paths and exact_versions < 2:
        findings.append(
            Finding(
                "infra",
                "deployment.terraform.version",
                "Terraform and every external provider must use exact semantic versions",
            )
        )
    return findings


def _lock_findings(root: Path, terraform_paths: list[Path]) -> list[Finding]:
    if not terraform_paths:
        return []
    lock_paths = sorted({path.parent / ".terraform.lock.hcl" for path in terraform_paths})
    findings: list[Finding] = []
    for path in lock_paths:
        display_path = relative_path(root, path)
        if not path.is_file():
            findings.append(
                Finding(display_path, "deployment.terraform.lock", "provider lock is missing")
            )
            continue
        source, errors = _read(root, path)
        findings.extend(errors)
        if source is None:
            continue
        if 'provider "registry.terraform.io/hashicorp/google"' not in source:
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.lock",
                    "provider lock must bind the hashicorp/google provider",
                )
            )
        if 'constraints = "7.45.0"' not in source or 'version     = "7.45.0"' not in source:
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.lock",
                    "provider lock must bind the exact reviewed Google provider version",
                )
            )
        if len(re.findall(r'^\s+"h1:[A-Za-z0-9+/=]+"', source, re.MULTILINE)) < 1:
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.lock",
                    "provider lock must retain signed package checksums",
                )
            )
    return findings


def _docker_findings(root: Path, paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        source, errors = _read(root, path)
        findings.extend(errors)
        if source is None:
            continue
        display_path = relative_path(root, path)
        for image in _FROM.findall(source):
            if "@sha256:" not in image:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.container.base-mutable",
                        f"container base {image!r} must be pinned by SHA-256 digest",
                    )
                )
        for instruction in _REMOTE_ADD.findall(source):
            if "--checksum=sha256:" not in instruction:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.container.download-mutable",
                        "remote Dockerfile ADD must include an exact SHA-256 checksum",
                    )
                )
        if _MUTABLE_IMAGE.search(source):
            findings.append(
                Finding(
                    display_path,
                    "deployment.image.mutable",
                    "container source may not use a mutable latest tag",
                )
            )
        if _ALTERNATE_CLOUD_OR_AI.search(source):
            findings.append(
                Finding(
                    display_path,
                    "deployment.runtime.provider",
                    "container source names a cloud or AI provider outside "
                    "the accepted Google boundary",
                )
            )
    return findings


def check_deployment(root: Path) -> list[Finding]:
    root = root.resolve()
    files = walk_files(root)
    terraform_paths = [path for path in files if path.suffix == ".tf"]
    docker_paths = [path for path in files if path.name.startswith("Dockerfile")]
    return sorted_findings(
        [
            *_terraform_findings(root, terraform_paths),
            *_lock_findings(root, terraform_paths),
            *_docker_findings(root, docker_paths),
        ]
    )


__all__ = ["check_deployment"]
