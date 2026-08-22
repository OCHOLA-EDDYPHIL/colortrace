from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression

IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".terraform",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
    }
)

REDISTRIBUTION_REVIEW_STATES = frozenset({"owner-approved", "owner-review-required", "prohibited"})


@dataclass(frozen=True, order=True)
class Finding:
    """A stable, user-facing policy violation."""

    path: str
    code: str
    message: str
    location: str = ""

    def render(self) -> str:
        suffix = f"{self.path}{self.location}" if self.path else "<repository>"
        return f"{suffix}: {self.code}: {self.message}"

    def as_dict(self) -> dict[str, str]:
        result = {"code": self.code, "message": self.message, "path": self.path}
        if self.location:
            result["location"] = self.location
        return result


def relative_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def contained_path(root: Path, value: object) -> Path | None:
    """Return a normalized repository path only when no component is a symlink."""
    if not isinstance(value, str) or not value or "\\" in value:
        return None
    relative = Path(value)
    if relative.is_absolute() or relative.as_posix() != value or ".." in relative.parts:
        return None
    current = root.resolve()
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return None
    try:
        current.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return current


def contained_repository_path(root: Path, path: Path) -> Path | None:
    """Return a lexical repository path only when no component is a symlink."""
    root = root.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        relative = candidate.relative_to(root).as_posix()
    except ValueError:
        return None
    return contained_path(root, relative)


def lexical_relative_path(root: Path, path: Path) -> str:
    """Display a path relative to root without following symlinks."""
    candidate = path if path.is_absolute() else root / path
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        return candidate.as_posix()


def is_canonical_spdx(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return canonicalize_license_expression(value) == value
    except InvalidLicenseExpression:
        return False


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(set(findings))


def walk_files(root: Path, names: frozenset[str] | None = None) -> list[Path]:
    files: list[Path] = []
    for current_root, directories, filenames in os.walk(root):
        directories[:] = sorted(
            directory for directory in directories if directory not in IGNORED_DIRECTORIES
        )
        for filename in sorted(filenames):
            if names is None or filename in names:
                files.append(Path(current_root, filename))
    return files
