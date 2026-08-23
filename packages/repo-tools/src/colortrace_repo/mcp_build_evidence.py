from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from colortrace_repo.common import Finding, sorted_findings
from colortrace_repo.final_image_evidence import EvidenceError, _archive_binding

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOCK_PATH = Path("config/grafana-mcp/mcp-grafana.lock.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def build_mcp_reproducibility_evidence(
    root: Path,
    output: Path,
    *,
    candidate_sha: str,
    candidate_tree: str,
    first_binary: Path,
    second_binary: Path,
    first_archive: Path,
    second_archive: Path,
    first_reference: str,
    second_reference: str,
) -> list[Finding]:
    root = root.resolve()
    output = output.resolve()
    findings: list[Finding] = []
    if _HEX40.fullmatch(candidate_sha) is None or _HEX40.fullmatch(candidate_tree) is None:
        findings.append(
            Finding(
                output.as_posix(),
                "mcp.reproducibility.candidate",
                "candidate commit and tree must be lowercase 40-character hashes",
            )
        )
    lock_path = root / _LOCK_PATH
    lock: dict[str, Any] = {}
    try:
        if not _regular_file(lock_path):
            raise OSError("runtime lock must be a regular, non-symlink file")
        document = json.loads(lock_path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("runtime lock must be an object")
        lock = document
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        findings.append(
            Finding(
                _LOCK_PATH.as_posix(),
                "mcp.reproducibility.lock",
                f"cannot load the runtime lock: {error}",
            )
        )
    expected_binary = lock.get("binary_sha256")
    binary_hashes: list[str | None] = []
    for ordinal, binary in enumerate((first_binary, second_binary), start=1):
        if not _regular_file(binary):
            findings.append(
                Finding(
                    binary.as_posix(),
                    "mcp.reproducibility.binary",
                    f"build {ordinal} binary must be a regular, non-symlink file",
                )
            )
            binary_hashes.append(None)
            continue
        binary_hash = _sha256(binary)
        binary_hashes.append(binary_hash)
        if binary_hash.removeprefix("sha256:") != expected_binary:
            findings.append(
                Finding(
                    binary.as_posix(),
                    "mcp.reproducibility.binary",
                    f"build {ordinal} binary does not match the runtime lock",
                )
            )
    if len(set(binary_hashes)) != 1 or None in binary_hashes:
        findings.append(
            Finding(
                output.as_posix(),
                "mcp.reproducibility.binary",
                "the two no-cache builds did not produce one binary identity",
            )
        )
    bindings: list[dict[str, Any]] = []
    for ordinal, (archive, reference) in enumerate(
        ((first_archive, first_reference), (second_archive, second_reference)),
        start=1,
    ):
        try:
            binding, archive_findings = _archive_binding(
                archive,
                expected_reference=reference,
                profile="private-full",
                candidate_sha=candidate_sha,
                candidate_tree=candidate_tree,
            )
            bindings.append(binding)
            findings.extend(archive_findings)
        except (EvidenceError, OSError) as error:
            bindings.append({})
            findings.append(
                Finding(
                    archive.as_posix(),
                    "mcp.reproducibility.image",
                    f"cannot verify runtime build {ordinal}: {error}",
                )
            )
    identity_keys = (
        "config_digest",
        "history_sha256",
        "layer_digests",
        "layer_diff_ids",
        "platform_manifest_digest",
    )
    identities = [tuple(binding.get(key) for key in identity_keys) for binding in bindings]
    if (
        any(
            _SHA256.fullmatch(str(binding.get("platform_manifest_digest"))) is None
            for binding in bindings
        )
        or len(set(map(repr, identities))) != 1
    ):
        findings.append(
            Finding(
                output.as_posix(),
                "mcp.reproducibility.image",
                "the two builds did not produce one runtime platform-manifest identity",
            )
        )
    builds = [
        {
            "archive_sha256": binding.get("archive_sha256"),
            "binary_sha256": binary_hash,
            "config_digest": binding.get("config_digest"),
            "image_identity": binding.get("platform_manifest_digest"),
            "ordinal": ordinal,
        }
        for ordinal, (binary_hash, binding) in enumerate(
            zip(binary_hashes, bindings, strict=True),
            start=1,
        )
    ]
    report = {
        "builds": builds,
        "candidate": {"commit": candidate_sha, "tree": candidate_tree},
        "findings": [finding.as_dict() for finding in sorted_findings(findings)],
        "method": "two-buildx-mcp-no-cache-builds",
        "runtime_lock_sha256": _sha256(lock_path) if _regular_file(lock_path) else None,
        "schema": "colortrace-mcp-build-reproducibility/v1",
        "status": "pass" if not findings else "fail",
    }
    _write_json(output, report)
    return sorted_findings(findings)
