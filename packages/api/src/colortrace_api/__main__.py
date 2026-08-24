from __future__ import annotations

import os
from collections.abc import Mapping

import uvicorn

from .runtime import create_application


def _bind(environment: Mapping[str, str]) -> tuple[str, int]:
    host = environment.get("COLORTRACE_BIND_HOST", "127.0.0.1")
    port_value = environment.get("PORT", "8000")
    if host not in {"0.0.0.0", "127.0.0.1"}:
        raise ValueError("bind-host-invalid")
    if not port_value.isdecimal():
        raise ValueError("bind-port-invalid")
    port = int(port_value)
    if not 1 <= port <= 65_535:
        raise ValueError("bind-port-invalid")
    return host, port


def main(environment: Mapping[str, str] | None = None) -> None:
    selected = os.environ if environment is None else environment
    host, port = _bind(selected)
    application = create_application(selected)
    uvicorn.run(application, host=host, port=port)


if __name__ == "__main__":
    main()
