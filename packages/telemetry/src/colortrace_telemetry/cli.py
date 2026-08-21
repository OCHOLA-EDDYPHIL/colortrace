"""Command line entry point for local telemetry evidence."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from colortrace_telemetry.contract import (
    DeliveryPlan,
    canonical_json_bytes,
    load_candidate_binding,
    load_runtime_jobs,
    strict_json,
)
from colortrace_telemetry.emitter import OtelSink, emit_plans
from colortrace_telemetry.observer import (
    BackendEndpoints,
    observe_without_grafana,
    telemetry_isolation_receipt,
    validated_isolation_receipt,
    verify_real_backends,
    wait_for_grafana_readiness,
)


def _endpoints(arguments: argparse.Namespace) -> BackendEndpoints:
    return BackendEndpoints(
        otlp=arguments.otlp,
        prometheus=arguments.prometheus,
        loki=arguments.loki,
        tempo=arguments.tempo,
        grafana=arguments.grafana,
    )


def _add_backend_arguments(parser: argparse.ArgumentParser, *, unavailable: bool = False) -> None:
    local = BackendEndpoints.local()
    fallback = "http://127.0.0.1:1" if unavailable else None
    parser.add_argument("--otlp", default=fallback or local.otlp)
    parser.add_argument("--prometheus", default=fallback or local.prometheus)
    parser.add_argument("--loki", default=fallback or local.loki)
    parser.add_argument("--tempo", default=fallback or local.tempo)
    parser.add_argument("--grafana", default=fallback or local.grafana)


def _write(path: Path | None, value: dict[str, Any]) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    if path is None:
        sys.stdout.buffer.write(payload)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _plans(scenario: Path, runs: int) -> tuple[Any, tuple[DeliveryPlan, ...]]:
    runtime = load_runtime_jobs(scenario)
    plans = tuple(
        DeliveryPlan.build(runtime, case_index=index, run_id=f"telemetry-run-{index:02d}")
        for index in range(runs)
    )
    return runtime, plans


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="colortrace-telemetry")
    commands = parser.add_subparsers(dest="command", required=True)

    emit = commands.add_parser("emit")
    emit.add_argument("--scenario", type=Path, required=True)
    emit.add_argument("--runs", type=int, choices=range(1, 51), default=50)
    emit.add_argument("--receipt", type=Path)
    _add_backend_arguments(emit)

    verify = commands.add_parser("verify")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--report", type=Path)
    verify.add_argument("--isolation-receipt", type=Path, required=True)
    verify.add_argument(
        "--stack-config", type=Path, default=Path("config/telemetry/local-stack.json")
    )
    verify.add_argument("--ingestion-timeout-seconds", type=float, default=30.0)
    verify.add_argument("--alert-timeout-seconds", type=float, default=90.0)
    _add_backend_arguments(verify)

    integration = commands.add_parser("integration")
    integration.add_argument("--scenario", type=Path, required=True)
    integration.add_argument("--receipt", type=Path)
    integration.add_argument("--report", type=Path)
    integration.add_argument("--isolation-receipt", type=Path, required=True)
    integration.add_argument(
        "--stack-config", type=Path, default=Path("config/telemetry/local-stack.json")
    )
    integration.add_argument("--ingestion-timeout-seconds", type=float, default=30.0)
    integration.add_argument("--alert-timeout-seconds", type=float, default=90.0)
    _add_backend_arguments(integration)

    unavailable = commands.add_parser("no-grafana")
    unavailable.add_argument("--scenario", type=Path, required=True)
    unavailable.add_argument("--isolation-receipt", type=Path, required=True)
    unavailable.add_argument("--report", type=Path)
    _add_backend_arguments(unavailable, unavailable=True)

    isolation = commands.add_parser("isolation")
    isolation.add_argument("--report", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if arguments.command == "isolation":
        _write(arguments.report, telemetry_isolation_receipt())
        return 0
    endpoints = _endpoints(arguments)
    if arguments.command == "no-grafana":
        candidate = load_candidate_binding(arguments.scenario)
        isolation_digest = validated_isolation_receipt(arguments.isolation_receipt)
        _write(
            arguments.report,
            observe_without_grafana(endpoints, candidate, isolation_digest),
        )
        return 0
    if arguments.command == "emit":
        runtime, plans = _plans(arguments.scenario, arguments.runs)
        wait_for_grafana_readiness(endpoints)
        receipt = emit_plans(runtime, plans, OtelSink(endpoints.otlp))
        _write(arguments.receipt, receipt)
        return 0
    if arguments.command == "verify":
        receipt = strict_json(arguments.receipt)
        wait_for_grafana_readiness(endpoints)
        report = verify_real_backends(
            receipt,
            endpoints,
            stack_config_path=arguments.stack_config,
            isolation_receipt_path=arguments.isolation_receipt,
            ingestion_timeout_seconds=arguments.ingestion_timeout_seconds,
            alert_timeout_seconds=arguments.alert_timeout_seconds,
        )
        _write(arguments.report, report)
        return 0
    if arguments.command == "integration":
        runtime, plans = _plans(arguments.scenario, 50)
        wait_for_grafana_readiness(endpoints)
        receipt = emit_plans(runtime, plans, OtelSink(endpoints.otlp))
        _write(arguments.receipt, receipt)
        report = verify_real_backends(
            receipt,
            endpoints,
            stack_config_path=arguments.stack_config,
            isolation_receipt_path=arguments.isolation_receipt,
            ingestion_timeout_seconds=arguments.ingestion_timeout_seconds,
            alert_timeout_seconds=arguments.alert_timeout_seconds,
        )
        _write(arguments.report, report)
        return 0
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
