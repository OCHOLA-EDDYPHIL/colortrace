from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from colortrace_repo.common import (
    IGNORED_DIRECTORIES,
    Finding,
    load_json,
    relative_path,
    sorted_findings,
    walk_files,
)


def _candidate_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=False,
        )
    except OSError:
        return walk_files(root)
    if result.returncode == 0:
        paths: list[Path] = []
        for raw_path in result.stdout.split(b"\0"):
            if not raw_path:
                continue
            try:
                relative = raw_path.decode("utf-8")
            except UnicodeDecodeError:
                continue
            path = root / relative
            if path.is_file():
                paths.append(path)
        return sorted(paths)
    return walk_files(root)


def _is_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:8192]
    except OSError:
        return False
    if b"\0" in sample:
        return True
    try:
        sample.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def check_binary_assets(root: Path, policy_path: Path | None = None) -> list[Finding]:
    root = root.resolve()
    policy_path = policy_path.resolve() if policy_path else (root / "policy" / "binary-assets.json")
    display_policy = relative_path(root, policy_path)
    try:
        document = load_json(policy_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [Finding(display_policy, "binary.policy.invalid", f"cannot load policy: {error}")]
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        return [
            Finding(
                display_policy,
                "binary.policy.invalid",
                "binary asset policy must be a schema_version 1 object",
            )
        ]
    raw_assets = document.get("assets")
    if not isinstance(raw_assets, list):
        return [
            Finding(
                display_policy,
                "binary.policy.invalid",
                "binary asset policy must contain an assets array",
            )
        ]

    findings: list[Finding] = []
    registry: dict[str, dict[str, Any]] = {}
    for index, asset in enumerate(raw_assets):
        pointer = f"#/assets/{index}"
        if not isinstance(asset, dict) or any(
            not isinstance(asset.get(key), str) or not asset[key]
            for key in ("license", "path", "provenance", "sha256")
        ):
            findings.append(
                Finding(
                    display_policy,
                    "binary.policy.entry",
                    "asset requires non-empty path, sha256, provenance, and license strings",
                    pointer,
                )
            )
            continue
        path_value = asset["path"]
        candidate = (root / path_value).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            findings.append(
                Finding(
                    display_policy,
                    "binary.policy.path",
                    "asset path escapes the repository",
                    pointer,
                )
            )
            continue
        if path_value in registry:
            findings.append(
                Finding(
                    display_policy,
                    "binary.policy.duplicate",
                    f"duplicate registry entry for {path_value!r}",
                    pointer,
                )
            )
        registry[path_value] = asset

    binary_paths: set[str] = set()
    for path in _candidate_files(root):
        if any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if not _is_binary(path):
            continue
        path_value = relative_path(root, path)
        binary_paths.add(path_value)
        asset = registry.get(path_value)
        if asset is None:
            findings.append(
                Finding(
                    path_value,
                    "binary.asset.unregistered",
                    "tracked binary asset has no provenance registry entry",
                )
            )
            continue
        expected_digest = asset["sha256"].lower()
        if len(expected_digest) != 64 or any(
            character not in "0123456789abcdef" for character in expected_digest
        ):
            findings.append(
                Finding(
                    display_policy,
                    "binary.digest.invalid",
                    f"registered digest for {path_value!r} is not SHA-256",
                )
            )
        else:
            actual_digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_digest != expected_digest:
                findings.append(
                    Finding(
                        path_value,
                        "binary.digest.mismatch",
                        "binary asset does not match its registered SHA-256 digest",
                    )
                )

    for path_value in set(registry) - binary_paths:
        path = root / path_value
        code = "binary.asset.missing" if not path.is_file() else "binary.asset.not-binary"
        message = (
            "registered binary asset does not exist"
            if not path.is_file()
            else "registered asset is not detected as binary"
        )
        findings.append(Finding(path_value, code, message))
    return sorted_findings(findings)
