from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

_PRIVATE_ROOT = Path("/run/colortrace-private")
_SERVICE_COMMANDS = {
    "api": ("/opt/colortrace/bin/python", "-m", "colortrace_api"),
}


def _copy_private_secret(source_value: str, target_value: str) -> None:
    source = Path(source_value)
    target = Path(target_value)
    if not source.is_absolute() or not target.is_absolute() or target.parent != _PRIVATE_ROOT:
        raise RuntimeError("private-secret-path-invalid")
    try:
        source_info = source.lstat()
        if not stat.S_ISREG(source_info.st_mode) or source.is_symlink():
            raise OSError
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                opened.st_dev != source_info.st_dev
                or opened.st_ino != source_info.st_ino
                or not stat.S_ISREG(opened.st_mode)
            ):
                raise OSError
            value = handle.read(16_385)
    except OSError:
        raise RuntimeError("private-secret-source-invalid") from None
    if (
        not 0 < len(value) <= 16_384
        or value != value.strip()
        or any(chr(byte).isspace() for byte in value)
    ):
        raise RuntimeError("private-secret-source-invalid")
    temporary = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, target, follow_symlinks=False)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    temporary.unlink()


def _copy_configured_secret(
    environment: dict[str, str],
    *,
    source_name: str,
    target_name: str,
) -> None:
    source = environment.get(source_name)
    target = environment.get(target_name)
    if source is None and target is None:
        return
    if source is None or target is None:
        raise RuntimeError("private-secret-configuration-invalid")
    _copy_private_secret(source, target)
    environment.pop(source_name)


def _prepare_private_runtime(environment: dict[str, str]) -> None:
    _copy_configured_secret(
        environment,
        source_name="COLORTRACE_GRAFANA_TOKEN_SOURCE",
        target_name="COLORTRACE_GRAFANA_TOKEN_FILE",
    )


def main(arguments: list[str] | None = None) -> None:
    selected = sys.argv[1:] if arguments is None else arguments
    if len(selected) != 1 or selected[0] not in _SERVICE_COMMANDS:
        raise RuntimeError("runtime-service-invalid")
    environment = dict(os.environ)
    _prepare_private_runtime(environment)
    command = _SERVICE_COMMANDS[selected[0]]
    os.execve(command[0], command, environment)


if __name__ == "__main__":
    main()
