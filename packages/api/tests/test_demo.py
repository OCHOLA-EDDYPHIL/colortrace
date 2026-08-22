from __future__ import annotations

import hashlib
import io
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from colortrace_api import demo
from colortrace_fixture import CANONICAL_SEED, build_scenario

COMMIT = "1" * 40
TREE = "2" * 40
IMAGE = "sha256:" + "3" * 64
APPROVAL = "APPROVE_COLORTRACE_SIMULATOR_ACTION"
CONFIG = {
    "schema": "colortrace-local-demo-config/v1",
    "incident_id": "incident-local-demo-001",
    "incident_version": 1,
    "fixture_variant": "canonical",
    "fixture_seed": CANONICAL_SEED,
    "issuer": "https://identity.colortrace.invalid",
    "audience": "colortrace-local-demo",
    "approval_phrase": APPROVAL,
}


def _config(root: Path) -> Path:
    path = root / "local-demo.json"
    path.write_text(json.dumps(CONFIG, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)
    return path


@pytest.fixture(scope="session")
def canonical_fixture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("demo-canonical-fixture")
    fixture = root / "fixture"
    build_scenario(
        fixture,
        oracle_root=root / "fixture-oracle",
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    return fixture


@pytest.fixture
def local_fixture_builder(
    monkeypatch: pytest.MonkeyPatch,
    canonical_fixture: Path,
) -> None:
    def clone(
        destination: Path,
        *,
        oracle_root: Path | None,
        variant_id: str,
        seed: str,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        assert variant_id == "canonical"
        assert seed == CANONICAL_SEED
        assert oracle_root is not None
        shutil.copytree(canonical_fixture, destination, copy_function=shutil.copyfile)
        oracle_root.mkdir(mode=0o700)
        return {}

    monkeypatch.setattr(demo, "build_scenario", clone)


def _arguments(config: Path, workspace: Path, *, approval: str | None) -> list[str]:
    values = [
        "--config",
        str(config),
        "--workspace",
        str(workspace),
        "--source-commit",
        COMMIT,
        "--source-tree",
        TREE,
        "--image-digest",
        IMAGE,
    ]
    if approval is not None:
        values.extend(("--approval", approval))
    return values


def test_demo_executes_one_authorized_action_and_side_effect_free_replay(
    tmp_path: Path,
    local_fixture_builder: None,
) -> None:
    config = _config(tmp_path)
    workspace = tmp_path / "run"
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = demo.main(
        _arguments(config, workspace, approval=APPROVAL),
        stdin=io.StringIO(),
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 0
    assert stderr.getvalue() == ""
    encoded = stdout.getvalue()
    assert encoded.endswith("\n") and encoded.count("\n") == 1
    receipt = json.loads(encoded)
    assert encoded == json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
    assert receipt["schema"] == "colortrace-local-demo-receipt/v1"
    assert receipt["binding"] == {
        "binding_sha256": receipt["binding"]["binding_sha256"],
        "config_path": config.name,
        "config_sha256": "sha256:" + hashlib.sha256(config.read_bytes()).hexdigest(),
        "image_digest": IMAGE,
        "source_commit": COMMIT,
        "source_tree": TREE,
    }
    assert str(tmp_path) not in encoded
    assert receipt["authority"]["preapproval_dispatch"] == "rejected"
    assert receipt["authority"]["preapproval_reason"] == "plan-not-approved"
    assert receipt["authority"]["preapproval_publication_unchanged"] is True
    assert receipt["authority"]["approval_actor_kind"] == "human"
    assert receipt["authority"]["dispatcher_actor_kind"] == "service"
    assert receipt["authority"]["executor_actor_kind"] == "service"
    assert receipt["action"]["action_count"] == 1
    assert receipt["action"]["command_count"] == 5
    assert receipt["action"]["generation_after"] == receipt["action"]["generation_before"] + 1
    assert receipt["replay"] == {
        "generation_unchanged": True,
        "identical_outcome": True,
        "same_execution_path": True,
    }
    assert receipt["safety"]["safe_frame_digest_equal"] is True
    assert (
        receipt["safety"]["safe_frame_before_sha256"]
        == receipt["safety"]["safe_frame_after_sha256"]
    )
    with sqlite3.connect(workspace / "simulator.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM simulator_actions").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM simulator_action_outcomes").fetchone() == (
            1,
        )
        assert connection.execute(
            "SELECT count(*) FROM simulator_publication_receipts"
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    ("approval", "expected"),
    [(None, "approval-input-missing"), ("approve", "approval-phrase-invalid")],
)
def test_missing_or_wrong_approval_fails_before_dispatch_and_action(
    tmp_path: Path,
    local_fixture_builder: None,
    approval: str | None,
    expected: str,
) -> None:
    config = _config(tmp_path)
    workspace = tmp_path / "run"
    stdout = io.StringIO()
    stderr = io.StringIO()
    stdin = io.StringIO() if approval is None else io.StringIO("unused\n")

    status = demo.main(
        _arguments(config, workspace, approval=approval),
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue().endswith(f"colortrace-demo: {expected}\n")
    if approval is None:
        assert "Recommendation:" in stderr.getvalue()
        assert f"Type {APPROVAL}" in stderr.getvalue()
    pointer = json.loads((workspace / "publication/state/active.json").read_bytes())
    assert pointer["generation"] == 1
    assert not (workspace / "simulator.sqlite3").exists()
    with sqlite3.connect(workspace / "response-plans.sqlite3") as connection:
        assert connection.execute("SELECT count(*) FROM response_plan_decisions").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM dispatch_authorizations").fetchone() == (0,)


def test_nonempty_workspace_is_refused_without_changing_caller_data(tmp_path: Path) -> None:
    config = _config(tmp_path)
    workspace = tmp_path / "run"
    workspace.mkdir(mode=0o700)
    sentinel = workspace / "caller-data"
    sentinel.write_bytes(b"keep-me")

    with pytest.raises(demo.DemoError, match="workspace-not-empty"):
        demo.run_demo(
            config_path=config,
            workspace=workspace,
            source_commit=COMMIT,
            source_tree=TREE,
            image_digest=IMAGE,
            approval_provider=lambda _recommendation, _phrase: APPROVAL,
        )

    assert sentinel.read_bytes() == b"keep-me"
    assert tuple(workspace.iterdir()) == (sentinel,)
