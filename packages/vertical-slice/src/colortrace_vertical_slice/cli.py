from __future__ import annotations

import argparse
import asyncio
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from colortrace_grafana_mcp import (
    AdapterError,
    EvidenceAdapter,
    OfficialMcpRuntime,
    QueryCatalog,
)
from colortrace_investigation import (
    AdkVertexGateway,
    ColorStateValidatorGateway,
    ContractError,
    InvestigationPolicy,
    ModelFailure,
)
from colortrace_investigation.contracts import canonical_json_bytes, strict_json_file
from colortrace_investigation.workflow import EvidenceCollector

from .contracts import SliceContractError
from .service import VerticalSliceApi, VerticalSliceWorker
from .store import SqliteIncidentStore

_RESET_CONFIRMATION = "RESET_LOCAL_COLORTRACE_INCIDENT_STORE"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="colortrace-slice",
        description="Run and replay the persisted alert-to-response-packet workflow.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser(
        "run",
        description="Accept one alert, execute one worker task, and persist the exact packet.",
    )
    run.add_argument("--alert", type=Path, required=True)
    run.add_argument("--bundle", type=Path, required=True)
    run.add_argument("--database", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--project-id", required=True)
    run.add_argument("--grafana-url", required=True)
    run.add_argument("--token-file", type=Path, required=True)
    run.add_argument("--mcp-binary", type=Path, required=True)
    run.add_argument(
        "--mcp-lock",
        type=Path,
        default=Path("config/grafana-mcp/mcp-grafana.lock.json"),
    )
    run.add_argument(
        "--query-catalog",
        type=Path,
        default=Path("config/grafana-mcp/query-catalog.json"),
    )
    run.add_argument(
        "--investigation-policy",
        type=Path,
        default=Path("config/investigation/investigation-policy.json"),
    )
    run.add_argument(
        "--model-profile",
        type=Path,
        default=Path("config/investigation/model-profile.json"),
    )

    show = subparsers.add_parser("show", description="Read the current persisted incident view.")
    show.add_argument("--database", type=Path, required=True)
    show.add_argument("--incident-id", required=True)
    show.add_argument("--output", type=Path, required=True)

    replay = subparsers.add_parser(
        "replay",
        description="Verify and emit persisted evidence, invocation, packet, and trace provenance.",
    )
    replay.add_argument("--database", type=Path, required=True)
    replay.add_argument("--incident-id", required=True)
    replay.add_argument("--output", type=Path, required=True)

    reset = subparsers.add_parser("reset", description="Clear one explicit local incident store.")
    reset.add_argument("--database", type=Path, required=True)
    reset.add_argument("--confirm", required=True)
    reset.add_argument("--output", type=Path, required=True)
    return parser


def _write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    encoded = canonical_json_bytes(value) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise SliceContractError("output-exists") from error
    except OSError as error:
        raise SliceContractError("output-unavailable") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


async def _run(arguments: argparse.Namespace) -> dict[str, Any]:
    store = SqliteIncidentStore(arguments.database)
    api = VerticalSliceApi(store)
    alert = strict_json_file(arguments.alert.resolve(strict=True))
    accepted = api.accept_alert(alert)
    completed = store.completed_packet(cast(str, accepted["task_id"]))
    if completed is not None:
        return completed
    runtime = OfficialMcpRuntime.verify(
        grafana_url=arguments.grafana_url,
        token_file=arguments.token_file.resolve(strict=True),
        binary=arguments.mcp_binary.resolve(strict=True),
        lock_path=arguments.mcp_lock.resolve(strict=True),
    )
    evidence = EvidenceAdapter(
        runtime=runtime,
        catalog=QueryCatalog.load(arguments.query_catalog.resolve(strict=True)),
    )
    policy = InvestigationPolicy.load(
        arguments.investigation_policy.resolve(strict=True),
        arguments.model_profile.resolve(strict=True),
    )
    worker = VerticalSliceWorker(
        store,
        policy=policy,
        model=AdkVertexGateway(project_id=arguments.project_id),
        evidence=cast(EvidenceCollector, evidence),
        validator=ColorStateValidatorGateway(),
    )
    return await worker.execute(
        cast(str, accepted["task_id"]),
        bundle_root=arguments.bundle.resolve(strict=True),
    )


def _execute(arguments: argparse.Namespace) -> dict[str, Any]:
    if arguments.command == "run":
        return asyncio.run(_run(arguments))
    store = SqliteIncidentStore(arguments.database)
    api = VerticalSliceApi(store)
    if arguments.command == "show":
        return api.get_incident(arguments.incident_id)
    if arguments.command == "replay":
        return api.replay(arguments.incident_id)
    if arguments.command == "reset":
        if arguments.confirm != _RESET_CONFIRMATION:
            raise SliceContractError("reset-confirmation-invalid")
        return cast(dict[str, Any], api.reset())
    raise SliceContractError("command-invalid")


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = _execute(arguments)
        _write_exclusive(arguments.output, result)
    except (AdapterError, ContractError, ModelFailure, SliceContractError) as error:
        code = getattr(error, "code", "contract-failure")
        print(f"colortrace-slice: {code}", file=sys.stderr)
        return 2
    except (OSError, RuntimeError, TypeError, ValueError):
        print("colortrace-slice: internal-failure", file=sys.stderr)
        return 2
    except Exception:
        print("colortrace-slice: internal-failure", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
