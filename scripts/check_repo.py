#!/usr/bin/env python3
"""Validate the pre-G0 ColorTrace repository without third-party dependencies."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "package.json",
    "pnpm-workspace.yaml",
    "pyproject.toml",
    "docs/product/product-contract.md",
    "docs/product/non-goals.md",
    "docs/product/user-and-authority-model.md",
    "docs/product/incident-lifecycle.md",
    "docs/architecture/system.md",
    "docs/architecture/data-contracts.md",
    "docs/architecture/deployment.md",
    "docs/security/threat-model.md",
    "docs/security/repository-controls.md",
    "docs/validation/fixture-contract.md",
    "docs/validation/acceptance-matrix.md",
    "docs/validation/practitioner-interview-guide.md",
    "docs/submission/compliance-matrix.md",
    "docs/submission/demo-storyboard.md",
    ".github/workflows/ci.yml",
    ".github/ISSUE_TEMPLATE/task.yml",
    ".github/ISSUE_TEMPLATE/research.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/pull_request_template.md",
}
REQUIRED_DIRS = {
    "apps/web",
    "apps/api",
    "apps/worker",
    "apps/simulator",
    "packages/contracts",
    "packages/domain",
    "packages/validators",
    "packages/telemetry",
    "infra/terraform",
    "infra/grafana",
    "fixtures/shadowed-lut-v1",
    "fixtures/provenance",
}
RUNTIME_DIRS = tuple(ROOT / path for path in ("apps", "packages", "infra"))
ALLOWED_RUNTIME_SUFFIXES = {".md", ".gitkeep"}
SENSITIVE_PATTERNS = {
    "private research path": re.compile(r"deep-research/runs|ObsidianVault|NotebookLM", re.I),
    "home-directory leak": re.compile(r"/home/(?:ideation|nyamabites)/", re.I),
    "credential assignment": re.compile(
        r"(?i)(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[:=]\s*[\"']?[A-Za-z0-9_./+\-=]{12,}"
    ),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
PROHIBITED_RUNTIME_PATTERNS = {
    "disallowed AI provider": re.compile(
        r"(?i)\b(openai|anthropic|bedrock|azure[ _-]?openai|mistral|ollama|langchain|crewai|autogen)\b"
    ),
    "public MCP listener": re.compile(r"(?i)mcp.*(?:0\.0\.0\.0|listen|streamable[_ -]?http|sse)"),
}


def tracked_text_files() -> list[Path]:
    excluded = {".git", "node_modules", ".venv", ".terraform"}
    return [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and not any(part in excluded for part in path.relative_to(ROOT).parts)
    ]


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def check_scaffold(errors: list[str]) -> None:
    for relative in sorted(REQUIRED_FILES):
        path = ROOT / relative
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"missing or empty required file: {relative}")
    for relative in sorted(REQUIRED_DIRS):
        if not (ROOT / relative).is_dir():
            errors.append(f"missing required directory: {relative}")
    adrs = sorted((ROOT / "docs/adr").glob("*.md"))
    if len(adrs) != 10:
        errors.append(f"expected 10 initial ADRs, found {len(adrs)}")
    for directory in RUNTIME_DIRS:
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix not in ALLOWED_RUNTIME_SUFFIXES:
                errors.append(f"product implementation before G0: {path.relative_to(ROOT)}")


def check_format(errors: list[str]) -> None:
    for path in tracked_text_files():
        text = read_text(path)
        if text is None:
            continue
        relative = path.relative_to(ROOT)
        if "\r\n" in text:
            errors.append(f"CRLF line endings: {relative}")
        if text and not text.endswith("\n"):
            errors.append(f"missing final newline: {relative}")
        for number, line in enumerate(text.splitlines(), 1):
            if line.endswith((" ", "\t")):
                errors.append(f"trailing whitespace: {relative}:{number}")


def check_policy(errors: list[str]) -> None:
    for path in tracked_text_files():
        text = read_text(path)
        if text is None:
            continue
        relative = path.relative_to(ROOT)
        if relative == Path("scripts/check_repo.py"):
            continue
        for name, pattern in SENSITIVE_PATTERNS.items():
            if pattern.search(text):
                errors.append(f"{name}: {relative}")
        if any(path.is_relative_to(directory) for directory in RUNTIME_DIRS):
            for name, pattern in PROHIBITED_RUNTIME_PATTERNS.items():
                if pattern.search(text):
                    errors.append(f"{name} in runtime path: {relative}")
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    if package.get("private") is not True:
        errors.append("workspace package.json must remain private")
    if package.get("license") != "Apache-2.0":
        errors.append("workspace license must be Apache-2.0")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("check", choices=("all", "scaffold", "format", "policy"))
    args = parser.parse_args()
    errors: list[str] = []
    if args.check in {"all", "scaffold"}:
        check_scaffold(errors)
    if args.check in {"all", "format"}:
        check_format(errors)
    if args.check in {"all", "policy"}:
        check_policy(errors)
    if errors:
        print("Repository validation failed:", file=sys.stderr)
        for error in sorted(set(errors)):
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"ColorTrace repository {args.check} checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
