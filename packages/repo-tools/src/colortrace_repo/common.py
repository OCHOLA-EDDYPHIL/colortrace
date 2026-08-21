from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
