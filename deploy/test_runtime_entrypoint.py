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
    monkeypatch.setattr(entrypoint, "_PRIVATE_ROOT", private_root)

    with pytest.raises(RuntimeError, match="private-secret-source-invalid"):
        entrypoint._copy_private_secret(str(link), str(private_root / "token"))
    with pytest.raises(RuntimeError, match="private-secret-path-invalid"):
        entrypoint._copy_private_secret(str(source), str(tmp_path / "outside"))
