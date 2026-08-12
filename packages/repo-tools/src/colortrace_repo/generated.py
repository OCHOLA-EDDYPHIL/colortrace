from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from colortrace_repo.common import Finding, load_json, relative_path, sorted_findings


def _tree(root: Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    if not root.is_dir():
        return entries
    for current_root, directories, filenames in os.walk(root):
        directories.sort()
        filenames.sort()
        current = Path(current_root)
        for directory in directories:
            path = current / directory
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                entries[relative] = ("symlink", os.readlink(path))
            else:
                entries[relative] = ("directory", "")
        for filename in filenames:
            path = current / filename
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                entries[relative] = ("symlink", os.readlink(path))
            else:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                entries[relative] = ("file", digest)
    return entries


def compare_generated_trees(root: Path, expected: Path, actual: Path) -> list[Finding]:
    root = root.resolve()
    expected = expected.resolve()
    actual = actual.resolve()
    findings: list[Finding] = []
    expected_display = relative_path(root, expected)
    actual_display = relative_path(root, actual)
    if not expected.is_dir():
        findings.append(
            Finding(
                expected_display,
                "generated.expected.missing",
                "expected generated tree does not exist",
            )
        )
    if not actual.is_dir():
        findings.append(
            Finding(
                actual_display,
                "generated.actual.missing",
                "candidate generated tree does not exist",
            )
        )
    if findings:
        return sorted_findings(findings)

    expected_tree = _tree(expected)
    actual_tree = _tree(actual)
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


def check_generated_manifest(root: Path, manifest_path: Path | None = None) -> list[Finding]:
    root = root.resolve()
    manifest_path = (
        manifest_path.resolve() if manifest_path else (root / "policy" / "generated-trees.json")
    )
    display_path = relative_path(root, manifest_path)
    try:
        document = load_json(manifest_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [Finding(display_path, "generated.policy.invalid", f"cannot load policy: {error}")]
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return [
            Finding(
                display_path,
                "generated.policy.invalid",
                "generated tree policy must be a schema_version 1 object",
            )
        ]
    trees = document.get("trees")
    if not isinstance(trees, list):
        return [
            Finding(
                display_path,
                "generated.policy.invalid",
                "generated tree policy must contain a trees array",
            )
        ]
    findings: list[Finding] = []
    for index, entry in enumerate(trees):
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(key), str) and entry[key] for key in ("actual", "expected")
        ):
            findings.append(
                Finding(
                    display_path,
                    "generated.policy.entry",
                    "tree entry requires non-empty expected and actual paths",
                    f"#/trees/{index}",
                )
            )
            continue
        findings.extend(
            compare_generated_trees(root, root / entry["expected"], root / entry["actual"])
        )
    return sorted_findings(findings)
