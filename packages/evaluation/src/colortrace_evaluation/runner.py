from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from colortrace_investigation import (  # type: ignore[import-untyped, unused-ignore]
    validate_response_packet,
)
from colortrace_vertical_slice import (  # type: ignore[import-untyped, unused-ignore]
    SqliteIncidentStore,
    VerticalSliceApi,
    validate_replay,
)

from .campaign import EvaluationError, _artifact_reference, _verify_plan
from .contracts import canonical_json_bytes, sha256_file, strict_json_file, validate_schema

_SAFE_PROCESS_ERROR = re.compile(rb"^colortrace-slice: [a-z][a-z0-9-]{1,63}\n?$")


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def _child_environment(repository: Path) -> tuple[dict[str, str], str]:
    sources = tuple(sorted((repository / "packages").glob("*/src")))
    if not sources or any(
        path.is_symlink() or not path.is_dir() or repository not in path.resolve().parents
        for path in sources
    ):
        raise EvaluationError("child-candidate-sources-invalid")
    dependencies: list[Path] = []
    for value in sys.path:
        if not value:
            continue
        try:
            path = Path(value).resolve(strict=True)
        except OSError:
            continue
        if path.name not in {"site-packages", "dist-packages"} or repository in path.parents:
            continue
        if path not in dependencies:
            dependencies.append(path)
    if not dependencies:
        raise EvaluationError("child-dependencies-unavailable")
    pythonpath = os.pathsep.join(str(path) for path in (*sources, *dependencies))
    environment = os.environ.copy()
    environment["PYTHONPATH"] = pythonpath
    return environment, f"sha256:{hashlib.sha256(pythonpath.encode()).hexdigest()}"


def _verify_child_runtime(repository: Path, environment: Mapping[str, str]) -> None:
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import colortrace_vertical_slice"],
            cwd=repository,
            env=dict(environment),
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise EvaluationError("child-runtime-unavailable") from error
    if result.returncode != 0 or result.stdout or result.stderr:
        raise EvaluationError("child-runtime-unavailable")


def _write_bytes_exclusive(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(value)
        handle.flush()
        os.fsync(handle.fileno())


def _sanitized_stream(value: bytes) -> bytes:
    if not value or _SAFE_PROCESS_ERROR.fullmatch(value) is not None:
        return value
    summary = {
        "schema": "sanitized-process-stream/v1",
        "byte_length": len(value),
        "sha256": f"sha256:{hashlib.sha256(value).hexdigest()}",
    }
    return canonical_json_bytes(summary) + b"\n"


def _inside(path: Path, root: Path, *, code: str) -> Path:
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as error:
        raise EvaluationError(code) from error
    return resolved


def execute_investigation_slot(
    *,
    plan: Mapping[str, Any],
    spec_id: str,
    repository: Path,
    campaign_root: Path,
    alert_path: Path,
    project_id: str,
    grafana_url: str,
    token_file: Path,
    mcp_binary: Path,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    _verify_plan(plan)
    repository = repository.resolve(strict=True)
    root = campaign_root.resolve(strict=True)
    if repository == root or repository in root.parents or root in repository.parents:
        raise EvaluationError("campaign-root-must-be-outside-repository")
    candidate = {
        "commit": _git(repository, "rev-parse", "HEAD"),
        "tree": _git(repository, "rev-parse", "HEAD^{tree}"),
    }
    if candidate != plan["candidate"]:
        raise EvaluationError("candidate-binding-drift")
    if _git(repository, "status", "--porcelain=v1", "--untracked-files=all"):
        raise EvaluationError("candidate-worktree-dirty")
    spec = next(
        (
            item
            for item in cast(Sequence[Mapping[str, Any]], plan["specs"])
            if item["spec_id"] == spec_id
        ),
        None,
    )
    if spec is None:
        raise EvaluationError("spec-not-in-plan")
    run_root = root / "runs" / f"{cast(int, spec['execution_order']):02d}-{spec_id}"
    bundle = (run_root / "runtime-bundle").resolve(strict=True)
    alert = _inside(alert_path, run_root, code="alert-outside-run-root")
    token = token_file.resolve(strict=True)
    binary = mcp_binary.resolve(strict=True)
    if repository in token.parents or token == repository:
        raise EvaluationError("credential-inside-repository")
    if root in token.parents or token == root:
        raise EvaluationError("credential-inside-campaign")
    if not project_id or not grafana_url.startswith(("https://", "http://127.0.0.1:")):
        raise EvaluationError("execution-endpoint-invalid")
    if not 1 <= timeout_seconds <= 180:
        raise EvaluationError("execution-timeout-invalid")
    if token.stat().st_mode & 0o077:
        raise EvaluationError("credential-permissions-too-broad")
    if not os.access(binary, os.X_OK):
        raise EvaluationError("mcp-binary-not-executable")
    database = run_root / "incident.sqlite3"
    packet_path = run_root / "packet.json"
    replay_path = run_root / "replay.json"
    stdout_path = run_root / "runner-stdout.log"
    stderr_path = run_root / "runner-stderr.log"
    if any(
        path.exists() for path in (database, packet_path, replay_path, stdout_path, stderr_path)
    ):
        raise EvaluationError("slot-already-attempted")
    child_environment, child_pythonpath_sha256 = _child_environment(repository)
    _verify_child_runtime(repository, child_environment)
    command = [
        sys.executable,
        "-m",
        "colortrace_vertical_slice",
        "run",
        "--alert",
        str(alert),
        "--bundle",
        str(bundle),
        "--database",
        str(database),
        "--output",
        str(packet_path),
        "--project-id",
        project_id,
        "--grafana-url",
        grafana_url,
        "--token-file",
        str(token),
        "--mcp-binary",
        str(binary),
        "--mcp-lock",
        str(repository / "config/grafana-mcp/mcp-grafana.lock.json"),
        "--query-catalog",
        str(repository / "config/grafana-mcp/query-catalog.json"),
        "--investigation-policy",
        str(repository / "config/investigation/investigation-policy.json"),
        "--model-profile",
        str(repository / "config/investigation/model-profile.json"),
    ]
    started_at = _timestamp()
    started = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(
            command,
            cwd=repository,
            env=child_environment,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
        exit_code: int | None = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        exit_code = None
        stdout = error.stdout or b""
        stderr = error.stderr or b""
    finished_at = _timestamp()
    elapsed_ms = int((time.monotonic() - started) * 1000)
    _write_bytes_exclusive(stdout_path, _sanitized_stream(stdout))
    _write_bytes_exclusive(stderr_path, _sanitized_stream(stderr))
    packet: dict[str, Any] | None = None
    if packet_path.is_file():
        packet = strict_json_file(packet_path)
        validate_response_packet(packet)
        alert_document = strict_json_file(alert)
        replay = VerticalSliceApi(SqliteIncidentStore(database)).replay(
            cast(str, alert_document["incident_id"])
        )
        validate_replay(replay)
        _write_bytes_exclusive(replay_path, canonical_json_bytes(replay) + b"\n")
    model_invocations = 0 if packet is None else len(packet["invocation_records"])
    transparent_retries = (
        0
        if packet is None
        else cast(int, cast(Mapping[str, Any], packet["budget_use"])["trusted_transient_retries"])
    )
    body: dict[str, Any] = {
        "schema": "reliability-slot-execution/v1",
        "plan_sha256": plan["sha256"],
        "spec_id": spec_id,
        "execution_order": spec["execution_order"],
        "candidate": candidate,
        "started_at": started_at,
        "finished_at": finished_at,
        "elapsed_ms": elapsed_ms,
        "timeout_seconds": timeout_seconds,
        "process_invocations": 1,
        "timed_out": timed_out,
        "exit_code": exit_code,
        "outcome": "complete" if exit_code == 0 and packet is not None else "failed",
        "model_invocations": model_invocations,
        "transparent_transient_retries": transparent_retries,
        "bindings": {
            "model_profile_sha256": sha256_file(
                repository / "config/investigation/model-profile.json"
            ),
            "investigation_policy_sha256": sha256_file(
                repository / "config/investigation/investigation-policy.json"
            ),
            "query_catalog_sha256": sha256_file(
                repository / "config/grafana-mcp/query-catalog.json"
            ),
            "mcp_lock_sha256": sha256_file(repository / "config/grafana-mcp/mcp-grafana.lock.json"),
            "mcp_binary_sha256": sha256_file(binary),
            "child_python_sha256": sha256_file(Path(sys.executable).resolve(strict=True)),
            "child_pythonpath_sha256": child_pythonpath_sha256,
            "project_id_sha256": f"sha256:{hashlib.sha256(project_id.encode()).hexdigest()}",
            "grafana_url_sha256": f"sha256:{hashlib.sha256(grafana_url.encode()).hexdigest()}",
        },
        "artifacts": {
            "alert": _artifact_reference(alert, root),
            "database": _artifact_reference(database, root) if database.is_file() else None,
            "packet": _artifact_reference(packet_path, root) if packet_path.is_file() else None,
            "replay": _artifact_reference(replay_path, root) if replay_path.is_file() else None,
            "stdout": _artifact_reference(stdout_path, root),
            "stderr": _artifact_reference(stderr_path, root),
        },
    }
    validate_schema("reliability-slot-execution-v1.schema.json", body)
    return body
