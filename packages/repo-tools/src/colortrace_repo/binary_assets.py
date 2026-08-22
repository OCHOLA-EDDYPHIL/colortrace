from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

from colortrace_repo.common import (
    IGNORED_DIRECTORIES,
    REDISTRIBUTION_REVIEW_STATES,
    Finding,
    contained_path,
    contained_repository_path,
    is_canonical_spdx,
    lexical_relative_path,
    load_json,
    sorted_findings,
    walk_files,
)

_ASSET_KEYS = {
    "license",
    "path",
    "provenance",
    "redistribution_review",
    "sha256",
}


def _candidate_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=False
        )
    except OSError:
        return walk_files(root)
    if result.returncode != 0:
        return walk_files(root)
    paths = []
    for raw in result.stdout.split(b"\0"):
        try:
            path = root / raw.decode()
        except UnicodeDecodeError:
            continue
        if raw and (path.is_file() or path.is_symlink()):
            paths.append(path)
    return sorted(paths)


def _is_binary(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:8192]
        return b"\0" in sample or not _is_utf8(sample)
    except OSError:
        return False


def _is_utf8(value: bytes) -> bool:
    try:
        value.decode()
        return True
    except UnicodeDecodeError:
        return False


def _exact(value: object, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _bad(display: str, code: str, location: str = "") -> Finding:
    return Finding(display, code, "binary asset provenance policy is invalid", location)


def check_binary_assets(root: Path, policy_path: Path | None = None) -> list[Finding]:
    root = root.resolve()
    requested_path = policy_path or root / "policy/binary-assets.json"
    display = lexical_relative_path(root, requested_path)
    policy_path = contained_repository_path(root, requested_path)
    if policy_path is None:
        return [
            Finding(
                display,
                "binary.policy.path",
                "policy path must be a lexical, non-symlink path within the repository",
            )
        ]
    try:
        document = load_json(policy_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return [Finding(display, "binary.policy.invalid", f"cannot load policy: {error}")]
    if (
        not _exact(document, {"schema_version", "assets"})
        or document.get("schema_version") != 2
        or not isinstance(document["assets"], list)
    ):
        return [_bad(display, "binary.policy.invalid")]

    findings: list[Finding] = []
    registry: dict[str, dict[str, object]] = {}
    for index, asset in enumerate(document["assets"]):
        location = f"#/assets/{index}"
        if not _exact(asset, _ASSET_KEYS):
            findings.append(_bad(display, "binary.policy.entry", location))
            continue
        path = contained_path(root, asset["path"])
        if path is None:
            findings.append(_bad(display, "binary.policy.path", location))
            continue
        name = asset["path"]
        if name in registry:
            findings.append(_bad(display, "binary.policy.duplicate", location))
        registry[name] = asset
        if not is_canonical_spdx(asset["license"]):
            findings.append(_bad(display, "binary.license.invalid", location))
        review = asset["redistribution_review"]
        if not isinstance(review, str) or review not in REDISTRIBUTION_REVIEW_STATES:
            findings.append(_bad(display, "binary.redistribution.invalid", location))
        if not isinstance(asset["provenance"], str) or not asset["provenance"]:
            findings.append(_bad(display, "binary.provenance.invalid", location))
        if not _sha256(asset["sha256"]):
            findings.append(_bad(display, "binary.digest.invalid", location))

    binary_paths: set[str] = set()
    for path in _candidate_files(root):
        name = path.relative_to(root).as_posix()
        if any(part in IGNORED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            findings.append(_bad(name, "binary.asset.symlink"))
            continue
        if not _is_binary(path):
            continue
        binary_paths.add(name)
        asset = registry.get(name)
        if asset is None:
            findings.append(_bad(name, "binary.asset.unregistered"))
            continue
        if _sha256(asset["sha256"]):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != asset["sha256"]:
                findings.append(_bad(name, "binary.digest.mismatch"))

    for name in set(registry) - binary_paths:
        code = "binary.asset.missing" if not (root / name).is_file() else "binary.asset.not-binary"
        findings.append(_bad(name, code))
    return sorted_findings(findings)
