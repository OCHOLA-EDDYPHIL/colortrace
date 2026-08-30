from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from colortrace_repo.common import (
    REDISTRIBUTION_REVIEW_STATES,
    Finding,
    contained_path,
    contained_repository_path,
    is_canonical_spdx,
    lexical_relative_path,
    load_json,
    relative_path,
    sorted_findings,
)

_TREE = "packages/api-client/src/generated"
_COMMAND = "pnpm --filter @colortrace/api-client run generate"
_INPUTS = {
    "config": "packages/api-client/openapi-ts.config.ts",
    "lockfile": "pnpm-lock.yaml",
    "openapi": "packages/contracts/openapi.json",
    "package": "packages/api-client/package.json",
}


def _tree(root: Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    if not root.is_dir() or root.is_symlink():
        return entries
    for current_root, directories, filenames in os.walk(root):
        directories.sort()
        filenames.sort()
        current = Path(current_root)
        for name in directories + filenames:
            path = current / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                entries[relative] = ("symlink", os.readlink(path))
            elif path.is_dir():
                entries[relative] = ("directory", "")
            else:
                entries[relative] = ("file", hashlib.sha256(path.read_bytes()).hexdigest())
    return entries


def compare_generated_trees(root: Path, expected: Path, actual: Path) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for role, path in (("expected", expected), ("actual", actual)):
        display = relative_path(root, path)
        if path.is_symlink():
            findings.append(
                Finding(display, f"generated.{role}.symlink", f"{role} tree root is a symlink")
            )
        elif not path.is_dir():
            findings.append(
                Finding(display, f"generated.{role}.missing", f"{role} generated tree is missing")
            )
    if findings:
        return sorted_findings(findings)

    expected_tree = _tree(expected)
    actual_tree = _tree(actual)
    expected_display = relative_path(root, expected)
    actual_display = relative_path(root, actual)
    for relative in sorted(set(expected_tree) | set(actual_tree)):
        expected_entry = expected_tree.get(relative)
        actual_entry = actual_tree.get(relative)
        if expected_entry is None:
            findings.append(
                Finding(
                    f"{actual_display}/{relative}",
                    "generated.unexpected",
                    "candidate contains an unexpected entry",
                )
            )
        elif actual_entry is None:
            findings.append(
                Finding(
                    f"{expected_display}/{relative}",
                    "generated.missing",
                    "candidate is missing this expected entry",
                )
            )
        elif expected_entry[0] != actual_entry[0]:
            findings.append(
                Finding(
                    f"{actual_display}/{relative}",
                    "generated.type",
                    f"candidate is {actual_entry[0]}, expected {expected_entry[0]}",
                )
            )
        elif expected_entry[1] != actual_entry[1]:
            findings.append(
                Finding(
                    f"{actual_display}/{relative}",
                    "generated.content",
                    "candidate content differs from the expected generated tree",
                )
            )
    return sorted_findings(findings)


def _exact(value: object, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _sha(value: object) -> bool:
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _records(value: object, keys: set[str]) -> list[dict[str, Any]] | None:
    return value if isinstance(value, list) and all(_exact(item, keys) for item in value) else None


def _bad(display: str, code: str) -> Finding:
    return Finding(display, code, "generated provenance policy is invalid")


def _generator_source(root: Path) -> dict[str, str] | None:
    package_path = contained_path(root, _INPUTS["package"])
    inventory_path = contained_path(root, "policy/dependency-inventory.json")
    if package_path is None or inventory_path is None:
        return None
    try:
        package = load_json(package_path)
        inventory = load_json(inventory_path)
        version = package["devDependencies"]["@hey-api/openapi-ts"]
        matches = [
            item
            for item in inventory["packages"]
            if isinstance(item, dict)
            and item.get("ecosystem") == "npm"
            and item.get("name") == "@hey-api/openapi-ts"
            and item.get("version") == version
        ]
        return (
            {key: matches[0][key] for key in ("name", "version", "license", "source")}
            if len(matches) == 1
            else None
        )
    except (KeyError, TypeError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def check_generated_manifest(root: Path, manifest_path: Path | None = None) -> list[Finding]:
    root = root.resolve()
    requested_path = manifest_path or root / "policy/generated-trees.json"
    display = lexical_relative_path(root, requested_path)
    manifest_path = contained_repository_path(root, requested_path)
    if manifest_path is None:
        return [
            Finding(
                display,
                "generated.policy.path",
                "policy path must be a lexical, non-symlink path within the repository",
            )
        ]
    try:
        document = load_json(manifest_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [Finding(display, "generated.policy.invalid", f"cannot load policy: {error}")]
    if (
        not _exact(document, {"schema_version", "trees", "files"})
        or document.get("schema_version") != 2
    ):
        return [_bad(display, "generated.policy.invalid")]

    findings: list[Finding] = []
    tree_keys = {
        "path",
        "license",
        "redistribution_review",
        "generator",
        "inputs",
        "generation_command",
        "outputs",
    }
    trees = document["trees"]
    if not isinstance(trees, list) or len(trees) != 1 or not _exact(trees[0], tree_keys):
        findings.append(_bad(display, "generated.tree.invalid"))
    else:
        tree = trees[0]
        tree_root = contained_path(root, tree["path"])
        if tree["path"] != _TREE or tree_root is None or not tree_root.is_dir():
            findings.append(_bad(display, "generated.tree.path"))
        if not is_canonical_spdx(tree["license"]):
            findings.append(_bad(display, "generated.license.invalid"))
        review = tree["redistribution_review"]
        if not isinstance(review, str) or review not in REDISTRIBUTION_REVIEW_STATES:
            findings.append(_bad(display, "generated.redistribution.invalid"))
        generator = tree["generator"]
        if (
            not _exact(generator, {"name", "version", "license", "source"})
            or generator != _generator_source(root)
            or not is_canonical_spdx(generator["license"])
        ):
            findings.append(_bad(display, "generated.generator.invalid"))
        if tree["generation_command"] != _COMMAND:
            findings.append(_bad(display, "generated.command.invalid"))

        inputs = _records(tree["inputs"], {"role", "path", "sha256"})
        bindings = (
            {item["role"]: item["path"] for item in inputs}
            if inputs is not None
            and all(
                isinstance(item["role"], str) and isinstance(item["path"], str) for item in inputs
            )
            else {}
        )
        if inputs is None or len(inputs) != len(_INPUTS) or bindings != _INPUTS:
            findings.append(_bad(display, "generated.inputs.invalid"))
        else:
            for item in inputs:
                path = contained_path(root, item["path"])
                if path is None or not path.is_file() or not _sha(item["sha256"]):
                    findings.append(_bad(display, "generated.input.invalid"))
                elif hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                    findings.append(_bad(item["path"], "generated.input.mismatch"))

        outputs = _records(tree["outputs"], {"path", "sha256"})
        valid_outputs = outputs is not None and all(
            isinstance(item["path"], str) and _sha(item["sha256"]) for item in outputs
        )
        registered = (
            {item["path"]: item["sha256"] for item in outputs or []} if valid_outputs else {}
        )
        if (
            not valid_outputs
            or len(registered) != len(outputs or [])
            or outputs != sorted(outputs or [], key=lambda item: item["path"])
        ):
            findings.append(_bad(display, "generated.outputs.invalid"))
        if tree_root is not None:
            actual_entries = _tree(tree_root)
            actual = {p: digest for p, (kind, digest) in actual_entries.items() if kind == "file"}
            if any(kind == "symlink" for kind, _ in actual_entries.values()):
                findings.append(_bad(_TREE, "generated.output.symlink"))
            if registered != actual:
                findings.append(_bad(_TREE, "generated.output.mismatch"))

    files = document["files"]
    if files != []:
        findings.append(_bad(display, "generated.file.invalid"))
    return sorted_findings(findings)
