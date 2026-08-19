from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from .action_runner import execute_recovery_failure_case
from .campaign import (
    EvaluationError,
    aggregate_campaign,
    build_alert,
    build_campaign_plan,
    build_manual_no_gemini_control,
    build_no_grafana_control,
    build_run_record,
    derive_investigation_observation,
    derive_recovery_observation,
    prepare_fixture,
    utc_now,
)
from .contracts import ContractError, strict_json_file, write_exclusive
from .evidence import build_action_recovery_evidence
from .runner import execute_investigation_slot


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="colortrace-evaluation")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--candidate-commit", required=True)
    plan.add_argument("--candidate-tree", required=True)
    plan.add_argument("--campaign-seed", required=True)
    plan.add_argument("--created-at", default=None)
    plan.add_argument("--output", type=Path, required=True)

    record = subparsers.add_parser("record")
    record.add_argument("--plan", type=Path, required=True)
    record.add_argument("--spec-id", required=True)
    record.add_argument("--packet", type=Path, required=True)
    record.add_argument("--oracle", type=Path, required=True)
    record.add_argument("--observation", type=Path, required=True)
    record.add_argument("--action-evidence", type=Path)
    record.add_argument("--run-root", type=Path, required=True)
    record.add_argument("--artifact", type=Path, action="append", required=True)
    record.add_argument("--started-at", required=True)
    record.add_argument("--finished-at", required=True)
    record.add_argument("--output", type=Path, required=True)

    observe = subparsers.add_parser("observe-investigation")
    observe.add_argument("--plan", type=Path, required=True)
    observe.add_argument("--spec-id", required=True)
    observe.add_argument("--packet", type=Path, required=True)
    observe.add_argument("--execution", type=Path, required=True)
    observe.add_argument("--replay", type=Path, required=True)
    observe.add_argument("--output", type=Path, required=True)

    action_evidence = subparsers.add_parser("build-action-recovery-evidence")
    action_evidence.add_argument("--plan", type=Path, required=True)
    action_evidence.add_argument("--spec-id", required=True)
    action_evidence.add_argument("--response-plan-database", type=Path, required=True)
    action_evidence.add_argument("--simulator-database", type=Path, required=True)
    action_evidence.add_argument("--recovery-database", type=Path, required=True)
    action_evidence.add_argument("--task-key", required=True)
    action_evidence.add_argument("--operation-id", required=True)
    action_evidence.add_argument("--payload-sha256", required=True)
    action_evidence.add_argument("--workflow-id", required=True)
    action_evidence.add_argument("--output", type=Path, required=True)

    recovery = subparsers.add_parser("observe-recovery")
    recovery.add_argument("--plan", type=Path, required=True)
    recovery.add_argument("--spec-id", required=True)
    recovery.add_argument("--packet", type=Path, required=True)
    recovery.add_argument("--execution", type=Path, required=True)
    recovery.add_argument("--replay", type=Path, required=True)
    recovery.add_argument("--action-evidence", type=Path, required=True)
    recovery.add_argument("--output", type=Path, required=True)

    run_recovery = subparsers.add_parser("run-recovery-failure")
    run_recovery.add_argument("--plan", type=Path, required=True)
    run_recovery.add_argument("--spec-id", required=True)
    run_recovery.add_argument("--replay", type=Path, required=True)
    run_recovery.add_argument("--fixture-bundle", type=Path, required=True)
    run_recovery.add_argument("--run-root", type=Path, required=True)
    run_recovery.add_argument("--query-catalog", type=Path, required=True)
    run_recovery.add_argument("--output", type=Path, required=True)

    prepare = subparsers.add_parser("prepare-fixture")
    prepare.add_argument("--plan", type=Path, required=True)
    prepare.add_argument("--spec-id", required=True)
    prepare.add_argument("--campaign-root", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)

    alert = subparsers.add_parser("build-alert")
    alert.add_argument("--plan", type=Path, required=True)
    alert.add_argument("--spec-id", required=True)
    alert.add_argument("--emission-receipt", type=Path, required=True)
    alert.add_argument("--prometheus-datasource-uid", required=True)
    alert.add_argument("--loki-datasource-uid", required=True)
    alert.add_argument("--tempo-datasource-uid", required=True)
    alert.add_argument("--alert-rule-uid", required=True)
    alert.add_argument("--output", type=Path, required=True)

    run = subparsers.add_parser("run-investigation")
    run.add_argument("--plan", type=Path, required=True)
    run.add_argument("--spec-id", required=True)
    run.add_argument("--repository", type=Path, required=True)
    run.add_argument("--campaign-root", type=Path, required=True)
    run.add_argument("--alert", type=Path, required=True)
    run.add_argument("--project-id", required=True)
    run.add_argument("--grafana-url", required=True)
    run.add_argument("--token-file", type=Path, required=True)
    run.add_argument("--mcp-binary", type=Path, required=True)
    run.add_argument("--timeout-seconds", type=int, default=180)
    run.add_argument("--output", type=Path, required=True)

    no_grafana = subparsers.add_parser("control-no-grafana")
    no_grafana.add_argument("--plan", type=Path, required=True)
    no_grafana.add_argument("--observation", type=Path, required=True)
    no_grafana.add_argument("--artifact-root", type=Path, required=True)
    no_grafana.add_argument("--started-at", required=True)
    no_grafana.add_argument("--finished-at", required=True)
    no_grafana.add_argument("--output", type=Path, required=True)

    manual = subparsers.add_parser("control-manual-no-gemini")
    manual.add_argument("--plan", type=Path, required=True)
    manual.add_argument("--observation", type=Path, required=True)
    manual.add_argument("--artifact-root", type=Path, required=True)
    manual.add_argument("--output", type=Path, required=True)

    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--plan", type=Path, required=True)
    aggregate.add_argument("--records", type=Path, required=True)
    aggregate.add_argument("--artifact-root", type=Path, required=True)
    aggregate.add_argument("--control", type=Path, action="append", required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    return parser


def _execute(arguments: argparse.Namespace) -> dict[str, Any]:
    if arguments.command == "plan":
        return build_campaign_plan(
            candidate_commit=arguments.candidate_commit,
            candidate_tree=arguments.candidate_tree,
            campaign_seed=arguments.campaign_seed,
            created_at=arguments.created_at or utc_now(),
        )
    if arguments.command == "record":
        return build_run_record(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            packet=strict_json_file(arguments.packet.resolve(strict=True)),
            oracle=strict_json_file(arguments.oracle.resolve(strict=True)),
            observation=strict_json_file(arguments.observation.resolve(strict=True)),
            run_root=arguments.run_root.resolve(strict=True),
            packet_path=arguments.packet.resolve(strict=True),
            oracle_path=arguments.oracle.resolve(strict=True),
            observation_path=arguments.observation.resolve(strict=True),
            action_evidence_path=(
                None
                if arguments.action_evidence is None
                else arguments.action_evidence.resolve(strict=True)
            ),
            artifact_paths=sorted(
                {
                    arguments.packet.resolve(strict=True),
                    arguments.oracle.resolve(strict=True),
                    arguments.observation.resolve(strict=True),
                    *(
                        []
                        if arguments.action_evidence is None
                        else [arguments.action_evidence.resolve(strict=True)]
                    ),
                    *(path.resolve(strict=True) for path in arguments.artifact),
                }
            ),
            started_at=arguments.started_at,
            finished_at=arguments.finished_at,
        )
    if arguments.command == "observe-investigation":
        return derive_investigation_observation(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            packet=strict_json_file(arguments.packet.resolve(strict=True)),
            execution=strict_json_file(arguments.execution.resolve(strict=True)),
            replay=strict_json_file(arguments.replay.resolve(strict=True)),
        )
    if arguments.command == "build-action-recovery-evidence":
        return build_action_recovery_evidence(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            response_plan_database=arguments.response_plan_database,
            simulator_database=arguments.simulator_database,
            recovery_database=arguments.recovery_database,
            task_key=arguments.task_key,
            operation_id=arguments.operation_id,
            payload_sha256=arguments.payload_sha256,
            workflow_id=arguments.workflow_id,
        )
    if arguments.command == "observe-recovery":
        return derive_recovery_observation(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            packet=strict_json_file(arguments.packet.resolve(strict=True)),
            execution=strict_json_file(arguments.execution.resolve(strict=True)),
            replay=strict_json_file(arguments.replay.resolve(strict=True)),
            action_evidence=strict_json_file(arguments.action_evidence.resolve(strict=True)),
        )
    if arguments.command == "run-recovery-failure":
        return execute_recovery_failure_case(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            replay_path=arguments.replay,
            fixture_bundle=arguments.fixture_bundle,
            run_root=arguments.run_root,
            query_catalog_path=arguments.query_catalog,
        )
    if arguments.command == "prepare-fixture":
        return prepare_fixture(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            campaign_root=arguments.campaign_root,
        )
    if arguments.command == "build-alert":
        return build_alert(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            emission_receipt=strict_json_file(arguments.emission_receipt.resolve(strict=True)),
            binding={
                "prometheus_datasource_uid": arguments.prometheus_datasource_uid,
                "loki_datasource_uid": arguments.loki_datasource_uid,
                "tempo_datasource_uid": arguments.tempo_datasource_uid,
                "alert_rule_uid": arguments.alert_rule_uid,
            },
        )
    if arguments.command == "run-investigation":
        return execute_investigation_slot(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            spec_id=arguments.spec_id,
            repository=arguments.repository,
            campaign_root=arguments.campaign_root,
            alert_path=arguments.alert,
            project_id=arguments.project_id,
            grafana_url=arguments.grafana_url,
            token_file=arguments.token_file,
            mcp_binary=arguments.mcp_binary,
            timeout_seconds=arguments.timeout_seconds,
        )
    if arguments.command == "control-no-grafana":
        return build_no_grafana_control(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            observation=strict_json_file(arguments.observation.resolve(strict=True)),
            observation_path=arguments.observation.resolve(strict=True),
            artifact_root=arguments.artifact_root.resolve(strict=True),
            started_at=arguments.started_at,
            finished_at=arguments.finished_at,
        )
    if arguments.command == "control-manual-no-gemini":
        return build_manual_no_gemini_control(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            observation=strict_json_file(arguments.observation.resolve(strict=True)),
            observation_path=arguments.observation.resolve(strict=True),
            artifact_root=arguments.artifact_root.resolve(strict=True),
        )
    if arguments.command == "aggregate":
        records = [
            strict_json_file(path)
            for path in sorted(arguments.records.resolve(strict=True).glob("*.json"))
        ]
        controls = [strict_json_file(path.resolve(strict=True)) for path in arguments.control]
        return aggregate_campaign(
            plan=strict_json_file(arguments.plan.resolve(strict=True)),
            records=records,
            controls=controls,
            artifact_root=arguments.artifact_root.resolve(strict=True),
        )
    raise EvaluationError("command-invalid")


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = _execute(arguments)
        write_exclusive(arguments.output, result)
    except (ContractError, EvaluationError, OSError, TypeError, ValueError) as error:
        code = str(error) or "evaluation-failed"
        print(f"colortrace-evaluation: {code.split(':', 1)[0]}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
