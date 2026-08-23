from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from .adapter import (
    AdapterError,
    EvidenceAdapter,
    EvidenceBatch,
    OfficialMcpRuntime,
    QueryCatalog,
    canonical_json_bytes,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="colortrace-grafana-mcp",
        description="Collect bounded read-only evidence through official mcp-grafana.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def runtime_arguments(command: argparse.ArgumentParser) -> None:
        command.add_argument("--grafana-url", required=True)
        command.add_argument("--token-file", required=True, type=Path)
        command.add_argument("--tls-ca-file", type=Path)
        command.add_argument("--binary", type=Path, default=Path("/usr/local/bin/mcp-grafana"))
        command.add_argument(
            "--lock",
            type=Path,
            default=Path("config/grafana-mcp/mcp-grafana.lock.json"),
        )
        command.add_argument(
            "--catalog",
            type=Path,
            default=Path("config/grafana-mcp/query-catalog.json"),
        )
        command.add_argument("--output", required=True, type=Path)

    catalog = subparsers.add_parser(
        "catalog", description="Verify the exact runtime and read-only tool inventory."
    )
    runtime_arguments(catalog)

    collect = subparsers.add_parser(
        "collect", description="Execute one schema-checked typed evidence batch."
    )
    runtime_arguments(collect)
    collect.add_argument("--request", required=True, type=Path)
    return parser


def _write_exclusive(path: Path, value: Any) -> None:
    data = canonical_json_bytes(value) + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _runtime(args: argparse.Namespace) -> OfficialMcpRuntime:
    return OfficialMcpRuntime.verify(
        grafana_url=args.grafana_url,
        token_file=args.token_file,
        binary=args.binary,
        lock_path=args.lock,
        tls_ca_file=args.tls_ca_file,
    )


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    runtime = _runtime(args)
    catalog = QueryCatalog.load(args.catalog)
    adapter = EvidenceAdapter(runtime=runtime, catalog=catalog)
    if args.command == "catalog":
        inventory = await adapter.verify_inventory()
        return inventory.to_dict()
    if args.command == "collect":
        batch = EvidenceBatch.from_file(args.request)
        return (await adapter.collect(batch)).to_dict()
    raise AdapterError("command_invalid")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = asyncio.run(_run(args))
        _write_exclusive(args.output, result)
    except AdapterError as error:
        print(f"colortrace-grafana-mcp: {error.code}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError):
        print("colortrace-grafana-mcp: internal_failure", file=sys.stderr)
        return 2
    except Exception:
        print("colortrace-grafana-mcp: internal_failure", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
