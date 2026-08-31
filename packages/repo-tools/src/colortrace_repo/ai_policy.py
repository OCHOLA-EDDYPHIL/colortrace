from __future__ import annotations

import ast
import json
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from colortrace_repo.common import Finding, load_json, relative_path, sorted_findings, walk_files
from colortrace_repo.dependencies import resolved_locked_packages

_MANIFEST_NAMES = frozenset({"package.json", "pyproject.toml"})
_PYTHON_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^]]+\])?")
_ECOSYSTEM_LIST_KEYS = (
    "allowed_ai_packages",
    "allowed_non_ai_runtime_packages",
    "disallowed_ai_packages",
    "disallowed_ai_prefixes",
)
_CONFIGURATION_LIST_KEYS = (
    "provider_keys",
    "allowed_providers",
    "framework_keys",
    "allowed_frameworks",
    "model_keys",
    "allowed_model_prefixes",
    "transport_keys",
    "allowed_mcp_transports",
    "mcp_server_keys",
)


def _normalize_python_package(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _normalize_policy_value(value: str) -> str:
    return value.strip().lower().replace("_", "-").replace(" ", "-")


def _python_requirement_name(requirement: str) -> str | None:
    match = _PYTHON_REQUIREMENT.match(requirement.strip())
    return _normalize_python_package(match.group(1)) if match else None


def _runtime_dependencies(path: Path, document: dict[str, Any]) -> Iterable[tuple[str, str]]:
    if path.name == "package.json":
        for section_name in ("dependencies", "optionalDependencies"):
            section = document.get(section_name, {})
            if isinstance(section, dict):
                for name in section:
                    if isinstance(name, str):
                        yield name.lower(), f"/{section_name}/{name}"
        return

    project = document.get("project", {})
    if not isinstance(project, dict):
        return
    dependencies = project.get("dependencies", [])
    if isinstance(dependencies, list):
        for index, requirement in enumerate(dependencies):
            if isinstance(requirement, str):
                name = _python_requirement_name(requirement)
                if name:
                    yield name, f"/project/dependencies/{index}"
    optional = project.get("optional-dependencies", {})
    if isinstance(optional, dict):
        for group_name, requirements in optional.items():
            if not isinstance(requirements, list):
                continue
            for index, requirement in enumerate(requirements):
                if isinstance(requirement, str):
                    name = _python_requirement_name(requirement)
                    if name:
                        yield name, f"/project/optional-dependencies/{group_name}/{index}"


def _development_dependencies(path: Path, document: dict[str, Any]) -> Iterable[tuple[str, str]]:
    if path.name == "package.json":
        section = document.get("devDependencies", {})
        if isinstance(section, dict):
            for name in section:
                if isinstance(name, str):
                    yield name.lower(), f"/devDependencies/{name}"
        return

    groups = document.get("dependency-groups", {})
    if not isinstance(groups, dict):
        return
    for group_name, requirements in groups.items():
        if not isinstance(requirements, list):
            continue
        for index, requirement in enumerate(requirements):
            if isinstance(requirement, str):
                name = _python_requirement_name(requirement)
                if name:
                    yield name, f"/dependency-groups/{group_name}/{index}"


def _load_structured(path: Path) -> dict[str, Any]:
    if path.suffix.lower() == ".json":
        value = load_json(path)
    elif path.suffix.lower() == ".toml":
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    else:
        raise ValueError("unsupported structured file")
    if not isinstance(value, dict):
        raise ValueError("top-level value must be an object")
    return value


def _required_string_list(
    document: dict[str, Any], key: str, allow_empty: bool = False
) -> list[str] | None:
    value = document.get(key)
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        return None
    if not allow_empty and not value:
        return None
    return value


def _policy_findings(root: Path, path: Path, policy: dict[str, Any]) -> list[Finding]:
    display_path = relative_path(root, path)
    findings: list[Finding] = []

    for ecosystem in ("python", "node"):
        rules = policy.get(ecosystem)
        if not isinstance(rules, dict):
            findings.append(
                Finding(
                    display_path,
                    "ai.policy.invalid",
                    f"policy requires an object at /{ecosystem}",
                )
            )
            continue
        parsed: dict[str, set[str]] = {}
        for key in _ECOSYSTEM_LIST_KEYS:
            allow_empty = key.startswith("allowed_non_ai_")
            values = _required_string_list(rules, key, allow_empty=allow_empty)
            if values is None:
                findings.append(
                    Finding(
                        display_path,
                        "ai.policy.invalid",
                        f"policy requires a string array at /{ecosystem}/{key}",
                    )
                )
                continue
            parsed[key] = {value.lower() for value in values}
        if len(parsed) != len(_ECOSYSTEM_LIST_KEYS):
            continue
        allowed = parsed["allowed_ai_packages"]
        neutral = parsed["allowed_non_ai_runtime_packages"]
        disallowed = parsed["disallowed_ai_packages"]
        if allowed & neutral or allowed & disallowed or neutral & disallowed:
            findings.append(
                Finding(
                    display_path,
                    "ai.policy.invalid",
                    f"runtime package classifications overlap under /{ecosystem}",
                )
            )

    globs = _required_string_list(policy, "structured_config_globs")
    if globs is None:
        findings.append(
            Finding(
                display_path,
                "ai.policy.invalid",
                "policy requires a non-empty string array at /structured_config_globs",
            )
        )
    configuration = policy.get("configuration")
    if not isinstance(configuration, dict):
        findings.append(
            Finding(
                display_path,
                "ai.policy.invalid",
                "policy requires an object at /configuration",
            )
        )
    else:
        for key in _CONFIGURATION_LIST_KEYS:
            if _required_string_list(configuration, key) is None:
                findings.append(
                    Finding(
                        display_path,
                        "ai.policy.invalid",
                        f"policy requires a non-empty string array at /configuration/{key}",
                    )
                )
    return findings


def _dependency_findings(
    root: Path,
    path: Path,
    document: dict[str, Any],
    policy: dict[str, Any],
) -> list[Finding]:
    ecosystem = "node" if path.name == "package.json" else "python"
    ecosystem_policy = policy.get(ecosystem, {})
    if not isinstance(ecosystem_policy, dict):
        return [
            Finding(
                relative_path(root, path),
                "ai.policy.invalid",
                f"policy is missing {ecosystem} package rules",
            )
        ]
    allowed = {str(value).lower() for value in ecosystem_policy.get("allowed_ai_packages", [])}
    neutral = {
        str(value).lower() for value in ecosystem_policy.get("allowed_non_ai_runtime_packages", [])
    }
    disallowed = {
        str(value).lower() for value in ecosystem_policy.get("disallowed_ai_packages", [])
    }
    prefixes = tuple(
        str(value).lower() for value in ecosystem_policy.get("disallowed_ai_prefixes", [])
    )
    findings: list[Finding] = []
    display_path = relative_path(root, path)
    for package, pointer in _runtime_dependencies(path, document):
        normalized = package.lower()
        if normalized in allowed:
            continue
        if normalized in disallowed or any(normalized.startswith(prefix) for prefix in prefixes):
            findings.append(
                Finding(
                    display_path,
                    "ai.dependency.disallowed",
                    f"runtime dependency {package!r} is outside the accepted AI boundary",
                    f"#{pointer}",
                )
            )
        elif normalized not in neutral:
            findings.append(
                Finding(
                    display_path,
                    "ai.dependency.unclassified",
                    f"runtime dependency {package!r} is not explicitly classified by policy",
                    f"#{pointer}",
                )
            )
    for package, pointer in _development_dependencies(path, document):
        normalized = package.lower()
        if normalized in disallowed or any(normalized.startswith(prefix) for prefix in prefixes):
            findings.append(
                Finding(
                    display_path,
                    "ai.dependency.disallowed",
                    f"development dependency {package!r} is outside the accepted AI boundary",
                    f"#{pointer}",
                )
            )
    return findings


def _resolved_dependency_findings(
    root: Path,
    policy: dict[str, Any],
) -> list[Finding]:
    packages, findings = resolved_locked_packages(root)
    for package in packages:
        ecosystem = "python" if package.ecosystem == "pypi" else "node"
        rules = policy.get(ecosystem, {})
        if not isinstance(rules, dict):
            continue
        disallowed = {str(value).lower() for value in rules.get("disallowed_ai_packages", [])}
        prefixes = tuple(str(value).lower() for value in rules.get("disallowed_ai_prefixes", []))
        if package.name in disallowed or any(
            package.name.startswith(prefix) for prefix in prefixes
        ):
            lockfile = "uv.lock" if package.ecosystem == "pypi" else "pnpm-lock.yaml"
            findings.append(
                Finding(
                    lockfile,
                    "ai.resolved-dependency.disallowed",
                    f"resolved {package.ecosystem} dependency {package.name!r} "
                    "is outside the accepted AI boundary",
                )
            )
    return findings


_NODE_IMPORT = re.compile(
    r"(?:^\s*(?:import|export)\b[^\n]*?\bfrom\s*|^\s*import\s*|\brequire\s*\(|\bimport\s*\()"
    r"[\"']([^\"']+)[\"']",
    re.MULTILINE,
)


def _node_package_name(specifier: str) -> str:
    if specifier.startswith("@"):
        return "/".join(specifier.split("/")[:2]).lower()
    return specifier.split("/", 1)[0].lower()


def _source_import_findings(root: Path, policy: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for path in walk_files(root):
        if "src" not in path.parts:
            continue
        suffix = path.suffix.lower()
        ecosystem: str
        imports: set[str]
        if suffix == ".py":
            ecosystem = "python"
        elif suffix in {".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"}:
            ecosystem = "node"
        else:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            findings.append(Finding(relative_path(root, path), "ai.source.invalid", str(error)))
            continue
        if ecosystem == "python":
            try:
                tree = ast.parse(source, filename=path.as_posix())
            except SyntaxError as error:
                findings.append(
                    Finding(
                        relative_path(root, path),
                        "ai.source.invalid",
                        f"cannot parse Python source: {error.msg}",
                        f":{error.lineno or 1}",
                    )
                )
                continue
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".", 1)[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".", 1)[0])
            imports = {_normalize_python_package(value) for value in imports}
        else:
            imports = {_node_package_name(match) for match in _NODE_IMPORT.findall(source)}
        rules = policy.get(ecosystem, {})
        if not isinstance(rules, dict):
            continue
        disallowed = {str(value).lower() for value in rules.get("disallowed_ai_packages", [])}
        prefixes = tuple(str(value).lower() for value in rules.get("disallowed_ai_prefixes", []))
        for package in sorted(imports):
            if package in disallowed or any(package.startswith(prefix) for prefix in prefixes):
                findings.append(
                    Finding(
                        relative_path(root, path),
                        "ai.source-import.disallowed",
                        f"source import {package!r} is outside the accepted AI boundary",
                    )
                )
    return findings


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []


def _configuration_findings(
    root: Path,
    path: Path,
    document: dict[str, Any],
    policy: dict[str, Any],
) -> list[Finding]:
    rules = policy.get("configuration", {})
    if not isinstance(rules, dict):
        return [
            Finding(
                relative_path(root, path),
                "ai.policy.invalid",
                "policy is missing configuration rules",
            )
        ]
    provider_keys = {str(value) for value in rules.get("provider_keys", [])}
    framework_keys = {str(value) for value in rules.get("framework_keys", [])}
    model_keys = {str(value) for value in rules.get("model_keys", [])}
    transport_keys = {str(value) for value in rules.get("transport_keys", [])}
    mcp_server_keys = {str(value) for value in rules.get("mcp_server_keys", [])}
    allowed_providers = {
        _normalize_policy_value(str(value)) for value in rules.get("allowed_providers", [])
    }
    allowed_frameworks = {
        _normalize_policy_value(str(value)) for value in rules.get("allowed_frameworks", [])
    }
    model_prefixes = tuple(
        _normalize_policy_value(str(value)) for value in rules.get("allowed_model_prefixes", [])
    )
    allowed_transports = {
        _normalize_policy_value(str(value)) for value in rules.get("allowed_mcp_transports", [])
    }
    display_path = relative_path(root, path)
    findings: list[Finding] = []

    def add(code: str, message: str, pointer: str) -> None:
        findings.append(Finding(display_path, code, message, f"#{pointer or '/'}"))

    def walk(value: Any, pointer: str, in_mcp_server: bool = False) -> None:
        if isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{pointer}/{index}", in_mcp_server)
            return
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            child_pointer = f"{pointer}/{key}"
            normalized_values = [_normalize_policy_value(item) for item in _strings(child)]
            if key in provider_keys:
                if not normalized_values:
                    add(
                        "ai.config.provider",
                        "provider must be a string or string array",
                        child_pointer,
                    )
                for candidate in normalized_values:
                    if candidate not in allowed_providers:
                        add(
                            "ai.config.provider",
                            f"provider {candidate!r} is outside the accepted Google boundary",
                            child_pointer,
                        )
            elif key in framework_keys:
                if not normalized_values:
                    add(
                        "ai.config.framework",
                        "framework must be a string or string array",
                        child_pointer,
                    )
                for candidate in normalized_values:
                    if candidate not in allowed_frameworks:
                        add(
                            "ai.config.framework",
                            f"agent framework {candidate!r} is not Google ADK",
                            child_pointer,
                        )
            elif key in model_keys:
                if not normalized_values:
                    add("ai.config.model", "model must be a string or string array", child_pointer)
                for candidate in normalized_values:
                    if not any(candidate.startswith(prefix) for prefix in model_prefixes):
                        add(
                            "ai.config.model",
                            f"model {candidate!r} is not a Gemini model identifier",
                            child_pointer,
                        )
            elif key in transport_keys:
                if not normalized_values:
                    add("ai.config.transport", "transport must be a string", child_pointer)
                for candidate in normalized_values:
                    if candidate not in allowed_transports:
                        add(
                            "ai.config.transport",
                            f"MCP transport {candidate!r} is not private stdio",
                            child_pointer,
                        )

            if in_mcp_server and key in {
                "base_url",
                "endpoint",
                "headers",
                "host",
                "port",
                "uri",
                "url",
            }:
                add(
                    "ai.config.mcp-public",
                    f"network field {key!r} is not permitted for a private stdio MCP server",
                    child_pointer,
                )

            if key in mcp_server_keys:
                if not isinstance(child, dict):
                    add("ai.config.mcp", "MCP servers must be an object", child_pointer)
                    continue
                for server_name, server in child.items():
                    server_pointer = f"{child_pointer}/{server_name}"
                    if not isinstance(server, dict):
                        add("ai.config.mcp", "MCP server must be an object", server_pointer)
                        continue
                    command = server.get("command")
                    if not isinstance(command, str) or not command.strip():
                        add(
                            "ai.config.mcp-command",
                            "private stdio MCP server requires a non-empty command",
                            f"{server_pointer}/command",
                        )
                    walk(server, server_pointer, True)
                continue
            walk(child, child_pointer, in_mcp_server)

    walk(document, "")
    return findings


def check_ai_policy(root: Path, policy_path: Path | None = None) -> list[Finding]:
    root = root.resolve()
    policy_path = policy_path.resolve() if policy_path else (root / "policy" / "ai-boundary.json")
    display_policy_path = relative_path(root, policy_path)
    try:
        policy = load_json(policy_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [Finding(display_policy_path, "ai.policy.invalid", f"cannot load policy: {error}")]
    if not isinstance(policy, dict) or policy.get("schema_version") != 1:
        return [
            Finding(
                display_policy_path,
                "ai.policy.invalid",
                "AI policy must be a schema_version 1 object",
            )
        ]

    policy_errors = _policy_findings(root, policy_path, policy)
    if policy_errors:
        return sorted_findings(policy_errors)

    findings: list[Finding] = []
    for manifest_path in walk_files(root, _MANIFEST_NAMES):
        display_path = relative_path(root, manifest_path)
        try:
            document = _load_structured(manifest_path)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            tomllib.TOMLDecodeError,
            ValueError,
        ) as error:
            findings.append(
                Finding(
                    display_path,
                    "ai.manifest.invalid",
                    f"cannot parse structured dependency manifest: {error}",
                )
            )
            continue
        findings.extend(_dependency_findings(root, manifest_path, document, policy))

    findings.extend(_resolved_dependency_findings(root, policy))
    findings.extend(_source_import_findings(root, policy))

    config_paths: set[Path] = set()
    globs = policy.get("structured_config_globs", [])
    if not isinstance(globs, list) or any(not isinstance(value, str) for value in globs):
        findings.append(
            Finding(
                display_policy_path,
                "ai.policy.invalid",
                "structured_config_globs must be an array of strings",
            )
        )
        globs = []
    for expression in globs:
        config_paths.update(path for path in root.glob(expression) if path.is_file())
    for config_path in sorted(config_paths):
        display_path = relative_path(root, config_path)
        try:
            document = _load_structured(config_path)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            tomllib.TOMLDecodeError,
            ValueError,
        ) as error:
            findings.append(
                Finding(
                    display_path,
                    "ai.config.invalid",
                    f"cannot parse structured AI configuration: {error}",
                )
            )
            continue
        findings.extend(_configuration_findings(root, config_path, document, policy))
    return sorted_findings(findings)
