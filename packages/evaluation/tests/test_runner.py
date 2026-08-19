from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from colortrace_evaluation import runner as subject
from colortrace_evaluation.campaign import build_campaign_plan
from colortrace_evaluation.contracts import canonical_json_bytes
from colortrace_evaluation.runner import execute_investigation_slot

COMMIT = "1" * 40
TREE = "2" * 40


def _plan() -> dict[str, Any]:
    return build_campaign_plan(
        candidate_commit=COMMIT,
        candidate_tree=TREE,
        campaign_seed="runner-test",
        created_at="2026-08-19T00:00:00Z",
    )


def test_runner_executes_exactly_one_product_process_and_retains_sanitized_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan()
    spec = min(plan["specs"], key=lambda item: item["execution_order"])
    repository = tmp_path / "repository"
    campaign = tmp_path / "campaign"
    (repository / "packages" / "vertical-slice" / "src").mkdir(parents=True)
    (repository / "uv.lock").write_bytes(b"locked dependencies\n")
    run_root = campaign / "runs" / f"{spec['execution_order']:02d}-{spec['spec_id']}"
    (run_root / "runtime-bundle").mkdir(parents=True)
    alert = run_root / "alert.json"
    alert.write_bytes(
        canonical_json_bytes({"schema": "test-alert/v1", "incident_id": "incident-test"}) + b"\n"
    )
    for relative in (
        "config/investigation/model-profile.json",
        "config/investigation/investigation-policy.json",
        "config/grafana-mcp/query-catalog.json",
        "config/grafana-mcp/mcp-grafana.lock.json",
    ):
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"{}\n")
    token = tmp_path / "token.secret"
    token.write_text("secret", encoding="utf-8")
    token.chmod(0o600)
    binary = tmp_path / "mcp-grafana"
    binary.write_bytes(b"binary")
    binary.chmod(0o700)

    def fake_git(_repository: Path, *arguments: str) -> str:
        if arguments == ("rev-parse", "HEAD"):
            return COMMIT
        if arguments == ("rev-parse", "HEAD^{tree}"):
            return TREE
        assert arguments == ("status", "--porcelain=v1", "--untracked-files=all")
        return ""

    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append((command, kwargs))
        if command[1:] == ["-c", "import colortrace_vertical_slice"]:
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        output = Path(command[command.index("--output") + 1])
        database = Path(command[command.index("--database") + 1])
        packet = {
            "invocation_records": [{"invocation_id": "one"}, {"invocation_id": "two"}],
            "budget_use": {"trusted_transient_retries": 0},
        }
        output.write_bytes(canonical_json_bytes(packet) + b"\n")
        database.write_bytes(b"sqlite")
        return SimpleNamespace(returncode=0, stdout=b"provider detail\n", stderr=b"")

    monkeypatch.setattr(subject, "_git", fake_git)
    monkeypatch.setattr(subject.subprocess, "run", fake_run)
    monkeypatch.setattr(subject, "validate_response_packet", lambda value: None)
    monkeypatch.setattr(subject, "SqliteIncidentStore", lambda path: path)
    monkeypatch.setattr(
        subject,
        "VerticalSliceApi",
        lambda store: SimpleNamespace(replay=lambda incident_id: {"incident_id": incident_id}),
    )
    monkeypatch.setattr(subject, "validate_replay", lambda value: None)
    receipt = execute_investigation_slot(
        plan=plan,
        spec_id=spec["spec_id"],
        repository=repository,
        campaign_root=campaign,
        alert_path=alert,
        project_id="test-project",
        grafana_url="http://127.0.0.1:3000",
        token_file=token,
        mcp_binary=binary,
    )
    assert len(calls) == 2
    product_command, product_options = calls[1]
    assert product_command[1:3] == ["-m", "colortrace_vertical_slice"]
    assert str(repository / "packages" / "vertical-slice" / "src") in (
        product_options["env"]["PYTHONPATH"].split(os.pathsep)
    )
    assert receipt["process_invocations"] == 1
    assert receipt["bindings"]["dependency_lock_sha256"].startswith("sha256:")
    assert receipt["model_invocations"] == 2
    assert receipt["outcome"] == "complete"
    assert receipt["artifacts"]["replay"] is not None
    stdout = campaign / receipt["artifacts"]["stdout"]["path"]
    assert b"provider detail" not in stdout.read_bytes()
    assert b"sanitized-process-stream/v1" in stdout.read_bytes()


def test_runner_refuses_product_admission_when_child_import_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    (repository / "packages" / "vertical-slice" / "src").mkdir(parents=True)
    environment, _ = subject._child_environment(repository)
    monkeypatch.setattr(
        subject.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1,
            stdout=b"",
            stderr=b"module unavailable",
        ),
    )
    with pytest.raises(subject.EvaluationError, match="child-runtime-unavailable"):
        subject._verify_child_runtime(repository, environment)


def test_child_environment_admits_only_canonical_candidate_venv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    source = repository / "packages" / "vertical-slice" / "src"
    dependency = (
        repository
        / ".venv"
        / "lib"
        / f"python{subject.sys.version_info.major}.{subject.sys.version_info.minor}"
        / "site-packages"
    )
    source.mkdir(parents=True)
    dependency.mkdir(parents=True)
    monkeypatch.setattr(subject.sys, "path", [str(dependency)])
    environment, _ = subject._child_environment(repository)
    assert environment["PYTHONPATH"].split(os.pathsep) == [str(source), str(dependency)]


def test_child_environment_rejects_arbitrary_candidate_site_packages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    (repository / "packages" / "vertical-slice" / "src").mkdir(parents=True)
    dependency = repository / "vendor" / "site-packages"
    dependency.mkdir(parents=True)
    monkeypatch.setattr(subject.sys, "path", [str(dependency)])
    with pytest.raises(subject.EvaluationError, match="child-dependencies-unavailable"):
        subject._child_environment(repository)


def test_runner_rejects_second_attempt_before_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = _plan()
    spec = min(plan["specs"], key=lambda item: item["execution_order"])
    repository = tmp_path / "repository"
    repository.mkdir()
    campaign = tmp_path / "campaign"
    run_root = campaign / "runs" / f"{spec['execution_order']:02d}-{spec['spec_id']}"
    (run_root / "runtime-bundle").mkdir(parents=True)
    (run_root / "alert.json").write_text("{}\n", encoding="utf-8")
    (run_root / "packet.json").write_text("{}\n", encoding="utf-8")
    token = tmp_path / "token"
    token.write_text("x", encoding="utf-8")
    token.chmod(0o600)
    binary = tmp_path / "mcp"
    binary.write_text("x", encoding="utf-8")
    binary.chmod(0o700)
    monkeypatch.setattr(
        subject,
        "_git",
        lambda _repository, *arguments: (
            COMMIT if arguments[-1] == "HEAD" else TREE if arguments[-1] == "HEAD^{tree}" else ""
        ),
    )
    with pytest.raises(subject.EvaluationError, match="slot-already-attempted"):
        execute_investigation_slot(
            plan=plan,
            spec_id=spec["spec_id"],
            repository=repository,
            campaign_root=campaign,
            alert_path=run_root / "alert.json",
            project_id="test-project",
            grafana_url="http://127.0.0.1:3000",
            token_file=token,
            mcp_binary=binary,
        )
