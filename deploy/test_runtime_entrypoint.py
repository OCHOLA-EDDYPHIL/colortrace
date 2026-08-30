from __future__ import annotations

import importlib.util
import stat
from pathlib import Path
from types import ModuleType

import pytest


def _entrypoint() -> ModuleType:
    path = Path(__file__).with_name("runtime-entrypoint.py")
    specification = importlib.util.spec_from_file_location("colortrace_runtime_entrypoint", path)
    if specification is None or specification.loader is None:
        raise RuntimeError("entrypoint import unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_private_root_uses_canonical_run_path() -> None:
    entrypoint = _entrypoint()

    assert entrypoint._PRIVATE_ROOT == Path("/run/colortrace-private")
    assert entrypoint._PRIVATE_ROOT.resolve() == entrypoint._PRIVATE_ROOT


@pytest.mark.parametrize(
    "relative_path",
    (
        "containers/Dockerfile.runtime",
        "infra/single-host/scripts/demo-verification.py",
        "infra/single-host/templates/compose.yaml.tftpl",
        "infra/single-host/templates/startup.sh.tftpl",
    ),
)
def test_runtime_surfaces_do_not_use_var_run_alias(relative_path: str) -> None:
    repository = Path(__file__).resolve().parents[1]
    content = (repository / relative_path).read_text(encoding="utf-8")

    assert "/run/colortrace-private" in content
    assert "/var/run/colortrace-private" not in content


def test_private_secret_is_copied_to_one_owner_only_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint = _entrypoint()
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    source = tmp_path / "mounted-secret"
    source.write_text("synthetic-token", encoding="utf-8")
    source.chmod(0o444)
    target = private_root / "grafana-viewer"
    monkeypatch.setattr(entrypoint, "_PRIVATE_ROOT", private_root)

    entrypoint._copy_private_secret(str(source), str(target))

    assert target.read_text(encoding="utf-8") == "synthetic-token"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert tuple(private_root.iterdir()) == (target,)


def test_private_secret_atomic_publish_preserves_existing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint = _entrypoint()
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    source = tmp_path / "mounted-secret"
    source.write_text("replacement-token", encoding="utf-8")
    target = private_root / "grafana-viewer"
    target.write_text("existing-token", encoding="utf-8")
    target.chmod(0o600)
    monkeypatch.setattr(entrypoint, "_PRIVATE_ROOT", private_root)

    with pytest.raises(FileExistsError):
        entrypoint._copy_private_secret(str(source), str(target))

    assert target.read_text(encoding="utf-8") == "existing-token"
    assert tuple(private_root.iterdir()) == (target,)


def test_private_secret_rejects_links_and_nonprivate_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint = _entrypoint()
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    source = tmp_path / "mounted-secret"
    source.write_text("synthetic-token", encoding="utf-8")
    link = tmp_path / "mounted-link"
    link.symlink_to(source)
    alias_root = tmp_path / "private-alias"
    alias_root.symlink_to(private_root, target_is_directory=True)
    monkeypatch.setattr(entrypoint, "_PRIVATE_ROOT", private_root)

    with pytest.raises(RuntimeError, match="private-secret-source-invalid"):
        entrypoint._copy_private_secret(str(link), str(private_root / "token"))
    with pytest.raises(RuntimeError, match="private-secret-path-invalid"):
        entrypoint._copy_private_secret(str(source), str(tmp_path / "outside"))
    with pytest.raises(RuntimeError, match="private-secret-path-invalid"):
        entrypoint._copy_private_secret(str(source), str(alias_root / "token"))


def test_api_stages_grafana_token_and_removes_source_path_from_child_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint = _entrypoint()
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    source = tmp_path / "mounted-grafana-token"
    source.write_text("synthetic-token", encoding="utf-8")
    source.chmod(0o444)
    target = private_root / "grafana-viewer"
    environment = {
        "COLORTRACE_GRAFANA_TOKEN_SOURCE": str(source),
        "COLORTRACE_GRAFANA_TOKEN_FILE": str(target),
    }
    monkeypatch.setattr(entrypoint, "_PRIVATE_ROOT", private_root)

    entrypoint._prepare_private_runtime(environment)

    assert target.read_text(encoding="utf-8") == "synthetic-token"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert "COLORTRACE_GRAFANA_TOKEN_SOURCE" not in environment
    assert environment["COLORTRACE_GRAFANA_TOKEN_FILE"] == str(target)


def test_entrypoint_exposes_only_the_single_host_api() -> None:
    entrypoint = _entrypoint()

    assert entrypoint._SERVICE_COMMANDS == {
        "api": ("/opt/colortrace/bin/python", "-m", "colortrace_api")
    }
