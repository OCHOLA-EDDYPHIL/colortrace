from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

_PRIVATE_ROOT = Path("/var/run/colortrace-private")
_SERVICE_COMMANDS = {
    "api": ("/opt/colortrace/bin/python", "-m", "colortrace_api"),
}


def _copy_private_secret(source_value: str, target_value: str) -> None:
    source = Path(source_value)
    target = Path(target_value)
    if not source.is_absolute() or not target.is_absolute() or target.parent != _PRIVATE_ROOT:
        raise RuntimeError("private-secret-path-invalid")
    source_info = source.lstat()
    if not stat.S_ISREG(source_info.st_mode) or source.is_symlink():
        raise RuntimeError("private-secret-source-invalid")
    value = source.read_bytes()
    if (
        not 0 < len(value) <= 16_384
        or value != value.strip()
        or any(chr(byte).isspace() for byte in value)
    ):
        raise RuntimeError("private-secret-source-invalid")
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise


def _prepare_private_runtime(environment: dict[str, str]) -> None:
    source = environment.get("COLORTRACE_GRAFANA_TOKEN_SOURCE")
    target = environment.get("COLORTRACE_GRAFANA_TOKEN_FILE")
    if source is None and target is None:
        return
    if source is None or target is None:
        raise RuntimeError("private-secret-configuration-invalid")
    _copy_private_secret(source, target)


def main(arguments: list[str] | None = None) -> None:
    selected = sys.argv[1:] if arguments is None else arguments
    if len(selected) != 1 or selected[0] not in _SERVICE_COMMANDS:
        raise RuntimeError("runtime-service-invalid")
    _prepare_private_runtime(dict(os.environ))
    command = _SERVICE_COMMANDS[selected[0]]
    os.execve(command[0], command, dict(os.environ))


if __name__ == "__main__":
    main()
