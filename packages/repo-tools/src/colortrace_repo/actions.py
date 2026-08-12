from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from yaml import SafeLoader, YAMLError, compose, safe_load  # type: ignore[import-untyped]
from yaml.nodes import MappingNode, ScalarNode, SequenceNode  # type: ignore[import-untyped]

from colortrace_repo.common import Finding, relative_path, sorted_findings, walk_files

_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_DOCKER_DIGEST = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def _validate_target(
    root: Path,
    target: str,
    display_path: str,
    line_number: int,
    findings: list[Finding],
    pending_files: set[Path],
) -> None:
    if target != target.strip() or not target:
        findings.append(
            Finding(
                display_path,
                "action.ref.invalid",
                "action reference must be a non-empty string without surrounding whitespace",
                f":{line_number}",
            )
        )
        return
    if "\\" in target:
        findings.append(
            Finding(
                display_path,
                "action.ref.invalid",
                "action reference must use portable forward slashes",
                f":{line_number}",
            )
        )
        return
    normalized_target = target
    if normalized_target.startswith("./"):
        candidate = (root / normalized_target).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            findings.append(
                Finding(
                    display_path,
                    "action.local.escape",
                    f"local action reference {target!r} escapes the repository",
                    f":{line_number}",
                )
            )
            return
        if not candidate.exists():
            findings.append(
                Finding(
                    display_path,
                    "action.local.missing",
                    f"local action reference {target!r} does not exist",
                    f":{line_number}",
                )
            )
            return
        if candidate.is_dir():
            metadata = [
                path
                for name in ("action.yml", "action.yaml")
                if (path := candidate / name).is_file()
            ]
            if not metadata:
                findings.append(
                    Finding(
                        display_path,
                        "action.local.metadata",
                        f"local action directory {target!r} has no action.yml or action.yaml",
                        f":{line_number}",
                    )
                )
            elif any(not path.resolve().is_relative_to(root) for path in metadata):
                findings.append(
                    Finding(
                        display_path,
                        "action.local.escape",
                        f"local action metadata for {target!r} escapes the repository",
                        f":{line_number}",
                    )
                )
            else:
                pending_files.update(path.resolve() for path in metadata)
        elif (
            candidate.is_file()
            and candidate.suffix.lower() in {".yaml", ".yml"}
            and (root / ".github" / "workflows") in candidate.parents
        ):
            pending_files.add(candidate)
        else:
            findings.append(
                Finding(
                    display_path,
                    "action.local.invalid",
                    f"local reference {target!r} is not an action directory or workflow",
                    f":{line_number}",
                )
            )
        return
    if (
        normalized_target.startswith("../")
        or normalized_target.startswith("/")
        or re.match(r"^[A-Za-z]:/", normalized_target)
    ):
        findings.append(
            Finding(
                display_path,
                "action.local.escape",
                f"local action reference {target!r} escapes the repository",
                f":{line_number}",
            )
        )
        return
    if _DOCKER_DIGEST.fullmatch(target):
        return
    if "@" not in target:
        findings.append(
            Finding(
                display_path,
                "action.ref.missing",
                f"action reference {target!r} has no immutable revision",
                f":{line_number}",
            )
        )
        return
    _, revision = target.rsplit("@", 1)
    if _FULL_SHA.fullmatch(revision) is None:
        findings.append(
            Finding(
                display_path,
                "action.ref.mutable",
                f"action reference {target!r} must use a full 40-character commit SHA",
                f":{line_number}",
            )
        )


def _walk_workflow(
    root: Path,
    node: Any,
    display_path: str,
    findings: list[Finding],
    pending_files: set[Path],
    visited: set[int] | None = None,
) -> None:
    visited = set() if visited is None else visited
    identity = id(node)
    if identity in visited:
        return
    visited.add(identity)
    if isinstance(node, MappingNode):
        for key_node, value_node in node.value:
            if isinstance(key_node, ScalarNode) and key_node.value == "uses":
                line_number = key_node.start_mark.line + 1
                if (
                    not isinstance(value_node, ScalarNode)
                    or value_node.tag != "tag:yaml.org,2002:str"
                ):
                    findings.append(
                        Finding(
                            display_path,
                            "action.ref.invalid",
                            "action reference must be a string",
                            f":{line_number}",
                        )
                    )
                else:
                    _validate_target(
                        root,
                        value_node.value,
                        display_path,
                        line_number,
                        findings,
                        pending_files,
                    )
            _walk_workflow(root, value_node, display_path, findings, pending_files, visited)
    elif isinstance(node, SequenceNode):
        for value_node in node.value:
            _walk_workflow(root, value_node, display_path, findings, pending_files, visited)


def _validate_action_metadata(
    document: Any,
    display_path: str,
    findings: list[Finding],
) -> None:
    if not isinstance(document, dict):
        return
    runs = document.get("runs")
    if not isinstance(runs, dict):
        return
    using = runs.get("using")
    if not isinstance(using, str) or using.casefold() != "docker":
        return
    image = runs.get("image")
    if not isinstance(image, str) or _DOCKER_DIGEST.fullmatch(image) is None:
        findings.append(
            Finding(
                display_path,
                "action.docker.image",
                "Docker action image must be an external docker:// reference pinned by SHA-256",
            )
        )


def check_actions(root: Path) -> list[Finding]:
    root = root.resolve()
    workflow_root = root / ".github" / "workflows"
    if not workflow_root.is_dir():
        return [
            Finding(
                relative_path(root, workflow_root),
                "action.directory.missing",
                "workflow directory does not exist",
            )
        ]
    findings: list[Finding] = []
    workflow_files = {
        path
        for path in workflow_root.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yaml", ".yml"}
    }
    action_files = {
        path
        for path in walk_files(root, frozenset({"action.yml", "action.yaml"}))
        if path.is_file()
    }
    pending_files = workflow_files | action_files
    visited_files: set[Path] = set()
    while pending_files:
        path = min(pending_files)
        pending_files.remove(path)
        path = path.resolve()
        if path in visited_files:
            continue
        visited_files.add(path)
        display_path = relative_path(root, path)
        if not path.is_relative_to(root):
            findings.append(
                Finding(
                    display_path,
                    "action.local.escape",
                    "action or workflow metadata escapes the repository",
                )
            )
            continue
        try:
            source = path.read_text(encoding="utf-8")
            document = compose(source, Loader=SafeLoader)
            loaded_document = safe_load(source)
        except (OSError, UnicodeDecodeError, YAMLError) as error:
            findings.append(
                Finding(display_path, "action.workflow.invalid", f"cannot parse workflow: {error}")
            )
            continue
        if not isinstance(document, MappingNode):
            findings.append(
                Finding(
                    display_path,
                    "action.workflow.invalid",
                    "workflow must be a YAML mapping",
                )
            )
            continue
        _walk_workflow(root, document, display_path, findings, pending_files)
        _validate_action_metadata(loaded_document, display_path, findings)
    return sorted_findings(findings)
