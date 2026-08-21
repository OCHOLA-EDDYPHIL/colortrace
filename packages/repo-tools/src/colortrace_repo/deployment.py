from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from colortrace_repo.common import Finding, relative_path, sorted_findings, walk_files

_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_EXACT_VERSION = re.compile(r"^= ([0-9]+\.[0-9]+\.[0-9]+)$")
_IMAGE_DIGEST = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_H1 = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
_ZH = re.compile(r"^zh:[0-9a-f]{64}$")
_GOOGLE_PROVIDER = "hashicorp/google"
_GOOGLE_PROVIDER_LOCK = "registry.terraform.io/hashicorp/google"


@dataclass(frozen=True, slots=True)
class _Block:
    labels: tuple[str, ...]
    body: str


@dataclass(frozen=True, slots=True)
class _TerraformFacts:
    core_versions: tuple[str, ...]
    google_versions: tuple[str, ...]
    module_directories: tuple[Path, ...]


def _deployment_input(path: Path) -> bool:
    return (
        path.name.startswith("Dockerfile")
        or path.name == ".terraform.lock.hcl"
        or path.name.endswith(".tf")
        or path.name.endswith(".tf.json")
        or path.name.endswith(".tftest.hcl")
    )


def deployment_input_paths(root: Path) -> tuple[Path, ...]:
    root = root.resolve()
    candidates: list[Path] | None = None
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            check=False,
            capture_output=True,
            timeout=5,
        )
        if completed.returncode == 0:
            candidates = []
            for raw_name in completed.stdout.split(b"\x00"):
                if not raw_name:
                    continue
                try:
                    name = raw_name.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    candidates = None
                    break
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    continue
                path = root / relative
                if path.is_file():
                    candidates.append(path)
    except (OSError, subprocess.SubprocessError):
        candidates = None
    selected = walk_files(root) if candidates is None else candidates
    return tuple(
        sorted(
            (path for path in selected if _deployment_input(path)),
            key=lambda path: path.relative_to(root).as_posix(),
        )
    )


def _read(root: Path, path: Path) -> tuple[str | None, list[Finding]]:
    display_path = relative_path(root, path)
    if path.is_symlink():
        return None, [
            Finding(
                display_path,
                "deployment.source.invalid",
                "deployment source must be a regular candidate file",
            )
        ]
    try:
        return path.read_text(encoding="utf-8"), []
    except (OSError, UnicodeDecodeError) as error:
        return None, [Finding(display_path, "deployment.source.invalid", str(error))]


def _mask_span(values: list[str], start: int, end: int) -> None:
    for index in range(start, end):
        if values[index] != "\n":
            values[index] = " "


def _heredoc_end(source: str, start: int) -> int | None:
    line_end = source.find("\n", start)
    if line_end < 0:
        return None
    declaration = source[start:line_end]
    match = re.match(r"<<(?P<indent>-?)\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*$", declaration)
    if match is None:
        return None
    marker = match.group("name")
    allow_indent = bool(match.group("indent"))
    cursor = line_end + 1
    while cursor <= len(source):
        next_end = source.find("\n", cursor)
        if next_end < 0:
            next_end = len(source)
        line = source[cursor:next_end]
        if (line.strip() if allow_indent else line) == marker:
            return next_end
        if next_end == len(source):
            return len(source)
        cursor = next_end + 1
    return len(source)


def _hcl_views(source: str) -> tuple[str, str]:
    visible = list(source)
    structural = list(source)
    index = 0
    while index < len(source):
        heredoc_end = _heredoc_end(source, index) if source.startswith("<<", index) else None
        if heredoc_end is not None:
            _mask_span(visible, index, heredoc_end)
            _mask_span(structural, index, heredoc_end)
            index = heredoc_end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = len(source) if end < 0 else end + 2
            _mask_span(visible, index, end)
            _mask_span(structural, index, end)
            index = end
            continue
        if source[index] == "#" or source.startswith("//", index):
            end = source.find("\n", index)
            end = len(source) if end < 0 else end
            _mask_span(visible, index, end)
            _mask_span(structural, index, end)
            index = end
            continue
        if source[index] == '"':
            start = index
            index += 1
            escaped = False
            while index < len(source):
                character = source[index]
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    index += 1
                    break
                index += 1
            _mask_span(structural, start, index)
            continue
        index += 1
    return "".join(visible), "".join(structural)


def _depths(structural: str) -> list[int]:
    depths: list[int] = []
    depth = 0
    for character in structural:
        depths.append(depth)
        if character == "{":
            depth += 1
        elif character == "}" and depth > 0:
            depth -= 1
    depths.append(depth)
    return depths


def _matching_brace(structural: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(structural)):
        if structural[index] == "{":
            depth += 1
        elif structural[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _blocks(source: str, keyword: str) -> tuple[_Block, ...]:
    visible, structural = _hcl_views(source)
    depths = _depths(structural)
    pattern = re.compile(
        rf"(?m)^[ \t]*{re.escape(keyword)}\b"
        r'(?P<labels>(?:[ \t]+"[^"\n]+")*)[ \t]*\{'
    )
    blocks: list[_Block] = []
    for match in pattern.finditer(visible):
        keyword_at = visible.find(keyword, match.start(), match.end())
        if keyword_at < 0 or depths[keyword_at] != 0:
            continue
        opening = structural.find("{", keyword_at, match.end())
        if opening < 0:
            continue
        closing = _matching_brace(structural, opening)
        if closing is None:
            continue
        labels = tuple(re.findall(r'"([^"\n]+)"', match.group("labels")))
        blocks.append(_Block(labels=labels, body=visible[opening + 1 : closing]))
    return tuple(blocks)


def _object_assignments(source: str) -> tuple[tuple[str, str], ...]:
    visible, structural = _hcl_views(source)
    depths = _depths(structural)
    pattern = re.compile(r"(?m)^[ \t]*([A-Za-z][A-Za-z0-9_-]*)[ \t]*=[ \t]*\{")
    values: list[tuple[str, str]] = []
    for match in pattern.finditer(visible):
        name_at = match.start(1)
        if depths[name_at] != 0:
            continue
        opening = structural.find("{", match.start(), match.end())
        closing = None if opening < 0 else _matching_brace(structural, opening)
        if opening < 0 or closing is None:
            continue
        values.append((match.group(1), visible[opening + 1 : closing]))
    return tuple(values)


def _string_assignments(source: str, name: str) -> tuple[str, ...]:
    visible, structural = _hcl_views(source)
    depths = _depths(structural)
    pattern = re.compile(
        rf"\b{re.escape(name)}[ \t]*=[ \t]*\"([^\"\n]*)\"",
        re.MULTILINE,
    )
    values: list[str] = []
    for match in pattern.finditer(visible):
        if depths[match.start()] == 0 and structural[match.start()] != " ":
            values.append(match.group(1))
    return tuple(values)


def _exact_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = _EXACT_VERSION.fullmatch(value)
    return None if match is None else match.group(1)


def _image_literal_findings(display_path: str, source: str) -> list[Finding]:
    visible, structural = _hcl_views(source)
    pattern = re.compile(r"\b(?:[A-Za-z][A-Za-z0-9_-]*_)?image[ \t]*=[ \t]*\"([^\"\n]+)\"")
    findings: list[Finding] = []
    for match in pattern.finditer(visible):
        if structural[match.start()] == " ":
            continue
        if _IMAGE_DIGEST.fullmatch(match.group(1)) is None:
            findings.append(
                Finding(
                    display_path,
                    "deployment.image.mutable",
                    "literal deployment images must use an exact SHA-256 digest",
                )
            )
    return findings


def _provider_requirement_findings(
    display_path: str,
    name: str,
    body: str,
) -> tuple[str | None, list[Finding]]:
    findings: list[Finding] = []
    sources = _string_assignments(body, "source")
    versions = _string_assignments(body, "version")
    if name != "google" or sources != (_GOOGLE_PROVIDER,):
        findings.append(
            Finding(
                display_path,
                "deployment.terraform.provider",
                "Terraform may require only the hashicorp/google provider",
            )
        )
    version = _exact_version(versions[0]) if len(versions) == 1 else None
    if version is None:
        findings.append(
            Finding(
                display_path,
                "deployment.terraform.version",
                f"provider {name!r} must use one exact semantic version",
            )
        )
    return (version if name == "google" and sources == (_GOOGLE_PROVIDER,) else None), findings


def _local_module_directory(
    root: Path,
    source_path: Path,
    source: object,
    terraform_directories: set[Path],
) -> Path | None:
    if not isinstance(source, str) or not source.startswith(("./", "../")):
        return None
    lexical_path = Path(os.path.abspath(source_path.parent / source))
    try:
        lexical_path.relative_to(root)
    except ValueError:
        return None
    if lexical_path.resolve() != lexical_path or lexical_path not in terraform_directories:
        return None
    return lexical_path


def _hcl_findings(
    root: Path,
    path: Path,
    source: str,
    terraform_directories: set[Path],
) -> tuple[_TerraformFacts, list[Finding]]:
    display_path = relative_path(root, path)
    findings = _image_literal_findings(display_path, source)
    core_versions: list[str] = []
    google_versions: list[str] = []
    module_directories: list[Path] = []
    for terraform in _blocks(source, "terraform"):
        for constraint in _string_assignments(terraform.body, "required_version"):
            version = _exact_version(constraint)
            if version is None:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.terraform.version",
                        "Terraform core must use one exact semantic version",
                    )
                )
            else:
                core_versions.append(version)
        for required in _blocks(terraform.body, "required_providers"):
            for name, body in _object_assignments(required.body):
                version, errors = _provider_requirement_findings(display_path, name, body)
                findings.extend(errors)
                if version is not None:
                    google_versions.append(version)
    for provider in _blocks(source, "provider"):
        if provider.labels != ("google",):
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.provider",
                    "Terraform provider blocks may configure only Google Cloud",
                )
            )
    for kind in ("resource", "data"):
        for block in _blocks(source, kind):
            resource_type = block.labels[0] if block.labels else ""
            allowed = resource_type.startswith("google_") or (
                kind == "resource" and resource_type == "terraform_data"
            )
            if not allowed:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.terraform.provider",
                        f"{kind} type {resource_type!r} is outside the Google Cloud boundary",
                    )
                )
    for module in _blocks(source, "module"):
        sources = _string_assignments(module.body, "source")
        module_directory = (
            _local_module_directory(root, path, sources[0], terraform_directories)
            if len(sources) == 1
            else None
        )
        if module_directory is None:
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.module",
                    "Terraform modules must resolve to candidate-bound relative directories",
                )
            )
        else:
            module_directories.append(module_directory)
    return _TerraformFacts(
        tuple(core_versions), tuple(google_versions), tuple(module_directories)
    ), findings


def _json_image_findings(display_path: str, value: object) -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, list):
        for child in value:
            findings.extend(_json_image_findings(display_path, child))
    elif isinstance(value, dict):
        for key, child in value.items():
            if (
                isinstance(key, str)
                and key.lower().endswith("image")
                and isinstance(child, str)
                and _IMAGE_DIGEST.fullmatch(child) is None
            ):
                findings.append(
                    Finding(
                        display_path,
                        "deployment.image.mutable",
                        "literal deployment images must use an exact SHA-256 digest",
                    )
                )
            findings.extend(_json_image_findings(display_path, child))
    return findings


def _json_findings(
    root: Path,
    path: Path,
    source: str,
    terraform_directories: set[Path],
) -> tuple[_TerraformFacts, list[Finding]]:
    display_path = relative_path(root, path)
    try:
        document = json.loads(source)
    except json.JSONDecodeError as error:
        return _TerraformFacts((), (), ()), [
            Finding(display_path, "deployment.source.invalid", f"invalid Terraform JSON: {error}")
        ]
    if not isinstance(document, dict):
        return _TerraformFacts((), (), ()), [
            Finding(
                display_path,
                "deployment.source.invalid",
                "Terraform JSON must contain an object",
            )
        ]
    findings = _json_image_findings(display_path, document)
    core_versions: list[str] = []
    google_versions: list[str] = []
    module_directories: list[Path] = []
    terraform = document.get("terraform")
    if isinstance(terraform, dict):
        if "required_version" in terraform:
            version = _exact_version(terraform.get("required_version"))
            if version is None:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.terraform.version",
                        "Terraform core must use one exact semantic version",
                    )
                )
            else:
                core_versions.append(version)
        required = terraform.get("required_providers")
        if isinstance(required, dict):
            for name, body in required.items():
                if not isinstance(name, str) or not isinstance(body, dict):
                    findings.append(
                        Finding(
                            display_path,
                            "deployment.terraform.provider",
                            "Terraform required provider configuration is invalid",
                        )
                    )
                    continue
                source_value = body.get("source")
                version_value = _exact_version(body.get("version"))
                if name != "google" or source_value != _GOOGLE_PROVIDER:
                    findings.append(
                        Finding(
                            display_path,
                            "deployment.terraform.provider",
                            "Terraform may require only the hashicorp/google provider",
                        )
                    )
                if version_value is None:
                    findings.append(
                        Finding(
                            display_path,
                            "deployment.terraform.version",
                            f"provider {name!r} must use one exact semantic version",
                        )
                    )
                elif name == "google" and source_value == _GOOGLE_PROVIDER:
                    google_versions.append(version_value)
    provider = document.get("provider")
    if isinstance(provider, dict):
        for name in provider:
            if name != "google":
                findings.append(
                    Finding(
                        display_path,
                        "deployment.terraform.provider",
                        "Terraform provider blocks may configure only Google Cloud",
                    )
                )
    for kind in ("resource", "data"):
        values = document.get(kind)
        if not isinstance(values, dict):
            continue
        for resource_type in values:
            allowed = isinstance(resource_type, str) and (
                resource_type.startswith("google_")
                or (kind == "resource" and resource_type == "terraform_data")
            )
            if not allowed:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.terraform.provider",
                        f"{kind} type {resource_type!r} is outside the Google Cloud boundary",
                    )
                )
    modules = document.get("module")
    if isinstance(modules, dict):
        for body in modules.values():
            source_value = body.get("source") if isinstance(body, dict) else None
            module_directory = _local_module_directory(
                root, path, source_value, terraform_directories
            )
            if module_directory is None:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.terraform.module",
                        "Terraform modules must resolve to candidate-bound relative directories",
                    )
                )
            else:
                module_directories.append(module_directory)
    return _TerraformFacts(
        tuple(core_versions), tuple(google_versions), tuple(module_directories)
    ), findings


def _module_closure(
    terraform_root: Path,
    edges: dict[Path, set[Path]],
) -> set[Path]:
    visited: set[Path] = set()
    pending = [terraform_root]
    while pending:
        directory = pending.pop()
        if directory in visited:
            continue
        visited.add(directory)
        pending.extend(edges.get(directory, set()) - visited)
    return visited


def _terraform_findings(
    root: Path,
    paths: list[Path],
) -> tuple[list[Finding], dict[Path, str | None]]:
    findings: list[Finding] = []
    facts: dict[Path, _TerraformFacts] = {}
    terraform_directories = {path.parent for path in paths}
    for path in paths:
        source, errors = _read(root, path)
        findings.extend(errors)
        if source is None:
            facts[path] = _TerraformFacts((), (), ())
            continue
        parsed, errors = (
            _json_findings(root, path, source, terraform_directories)
            if path.name.endswith(".tf.json")
            else _hcl_findings(root, path, source, terraform_directories)
        )
        facts[path] = parsed
        findings.extend(errors)
    edges: dict[Path, set[Path]] = {directory: set() for directory in terraform_directories}
    for path, value in facts.items():
        edges[path.parent].update(value.module_directories)
    referenced_directories = {directory for targets in edges.values() for directory in targets}
    terraform_roots = sorted(
        terraform_directories - referenced_directories,
        key=lambda path: (len(path.parts), str(path)),
    )
    if terraform_directories and not terraform_roots:
        findings.append(
            Finding(
                "infra",
                "deployment.terraform.module",
                "Terraform module graph must contain at least one candidate root",
            )
        )
    expected_versions: dict[Path, str | None] = {}
    for terraform_root in terraform_roots:
        direct = [path for path in paths if path.parent == terraform_root]
        closure = _module_closure(terraform_root, edges)
        descendants = [path for path in paths if path.parent in closure]
        core_versions = {value for path in direct for value in facts[path].core_versions}
        root_google_versions = {value for path in direct for value in facts[path].google_versions}
        all_google_versions = {
            value for path in descendants for value in facts[path].google_versions
        }
        display_root = relative_path(root, terraform_root)
        if len(core_versions) != 1:
            findings.append(
                Finding(
                    display_root,
                    "deployment.terraform.version",
                    "each Terraform root must declare one exact core version",
                )
            )
        if len(root_google_versions) != 1 or all_google_versions != root_google_versions:
            findings.append(
                Finding(
                    display_root,
                    "deployment.terraform.version",
                    "each Terraform root and its modules must bind one Google provider version",
                )
            )
            expected_versions[terraform_root] = None
        else:
            expected_versions[terraform_root] = next(iter(root_google_versions))
    return findings, expected_versions


def _lock_findings(
    root: Path,
    expected_versions: dict[Path, str | None],
    candidate_paths: set[Path],
) -> list[Finding]:
    findings: list[Finding] = []
    for terraform_root, expected_version in expected_versions.items():
        path = terraform_root / ".terraform.lock.hcl"
        display_path = relative_path(root, path)
        if path not in candidate_paths or not path.is_file():
            findings.append(
                Finding(display_path, "deployment.terraform.lock", "root provider lock is missing")
            )
            continue
        source, errors = _read(root, path)
        findings.extend(errors)
        if source is None:
            continue
        providers = _blocks(source, "provider")
        if len(providers) != 1 or providers[0].labels != (_GOOGLE_PROVIDER_LOCK,):
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.lock",
                    "root provider lock must contain only hashicorp/google",
                )
            )
            continue
        provider = providers[0]
        versions = _string_assignments(provider.body, "version")
        constraints = _string_assignments(provider.body, "constraints")
        version = versions[0] if len(versions) == 1 and _SEMVER.fullmatch(versions[0]) else None
        constraint = constraints[0] if len(constraints) == 1 else None
        if (
            expected_version is None
            or version != expected_version
            or constraint not in {expected_version, f"= {expected_version}"}
        ):
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.lock",
                    "provider lock must match the exact declared Google provider version",
                )
            )
        hashes = re.findall(r'"(h1:[A-Za-z0-9+/=]+|zh:[0-9A-Fa-f]+)"', provider.body)
        if not any(_H1.fullmatch(value) for value in hashes) or not any(
            _ZH.fullmatch(value) for value in hashes
        ):
            findings.append(
                Finding(
                    display_path,
                    "deployment.terraform.lock",
                    "provider lock must retain exact h1 and registry package checksums",
                )
            )
    return findings


def _docker_instructions(source: str) -> tuple[str, ...]:
    instructions: list[str] = []
    logical: list[str] = []
    for line in source.splitlines():
        stripped = line.strip()
        if not logical and (not stripped or stripped.startswith("#")):
            continue
        continuation = line.rstrip().endswith("\\")
        logical.append(line.rstrip()[:-1] if continuation else line)
        if not continuation:
            instruction = " ".join(part.strip() for part in logical if part.strip())
            if instruction:
                instructions.append(instruction)
            logical = []
    if logical:
        instructions.append(" ".join(part.strip() for part in logical if part.strip()))
    return tuple(instructions)


def _docker_findings(root: Path, paths: list[Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        source, errors = _read(root, path)
        findings.extend(errors)
        if source is None:
            continue
        display_path = relative_path(root, path)
        stages: set[str] = set()
        for instruction in _docker_instructions(source):
            try:
                tokens = shlex.split(instruction, comments=False, posix=True)
            except ValueError:
                findings.append(
                    Finding(
                        display_path,
                        "deployment.source.invalid",
                        "container instruction cannot be parsed",
                    )
                )
                continue
            if not tokens:
                continue
            operation = tokens[0].upper()
            if operation == "FROM":
                arguments = [value for value in tokens[1:] if not value.startswith("--")]
                if not arguments:
                    findings.append(
                        Finding(
                            display_path,
                            "deployment.container.base-mutable",
                            "container base image is missing",
                        )
                    )
                    continue
                image = arguments[0]
                if image.lower() != "scratch" and image.lower() not in stages:
                    if _IMAGE_DIGEST.fullmatch(image) is None:
                        findings.append(
                            Finding(
                                display_path,
                                "deployment.container.base-mutable",
                                f"external container base {image!r} must use an exact "
                                "SHA-256 digest",
                            )
                        )
                if len(arguments) >= 3 and arguments[-2].upper() == "AS":
                    stages.add(arguments[-1].lower())
            elif operation == "ADD" and re.search(r"https?://", instruction, re.IGNORECASE):
                checksum_values = [
                    value.removeprefix("--checksum=")
                    for value in tokens[1:]
                    if value.startswith("--checksum=")
                ]
                urls = re.findall(r"https?://[^\s\]\\\"']+", instruction, re.IGNORECASE)
                if (
                    len(checksum_values) != 1
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", checksum_values[0]) is None
                    or any(not value.startswith("https://") for value in urls)
                ):
                    findings.append(
                        Finding(
                            display_path,
                            "deployment.container.download-mutable",
                            "remote Dockerfile ADD must use HTTPS and one exact SHA-256 checksum",
                        )
                    )
    return findings


def check_deployment(root: Path) -> list[Finding]:
    root = root.resolve()
    candidate_paths = deployment_input_paths(root)
    terraform_paths = [
        path
        for path in candidate_paths
        if path.name.endswith(".tf") or path.name.endswith(".tf.json")
    ]
    docker_paths = [path for path in candidate_paths if path.name.startswith("Dockerfile")]
    terraform_findings, expected_versions = _terraform_findings(root, terraform_paths)
    return sorted_findings(
        [
            *terraform_findings,
            *_lock_findings(root, expected_versions, set(candidate_paths)),
            *_docker_findings(root, docker_paths),
        ]
    )


__all__ = ["check_deployment", "deployment_input_paths"]
