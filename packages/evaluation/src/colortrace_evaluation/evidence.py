from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from colortrace_recovery import SQLiteRecoveryRepository
from colortrace_response_plans import (
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    ResponsePlanService,
    SQLiteResponsePlanRepository,
)
from colortrace_simulator import DispatchIdentity
from colortrace_simulator.repository import (
    SQLiteSimulatorRepository,
)

from .campaign import EvaluationError, validate_action_recovery_evidence
from .contracts import prefixed_sha256


def build_action_recovery_evidence(
    *,
    plan: Mapping[str, Any],
    spec_id: str,
    response_plan_database: Path,
    simulator_database: Path,
    recovery_database: Path,
    task_key: str,
    operation_id: str,
    payload_sha256: str,
    workflow_id: str,
) -> dict[str, Any]:
    for path in (response_plan_database, simulator_database, recovery_database):
        if not path.resolve(strict=True).is_file():
            raise EvaluationError("evidence-database-invalid")
    authority = CanonicalAuthorityBoundary()
    plan_repository = SQLiteResponsePlanRepository(
        response_plan_database.resolve(strict=True),
        authority_boundary=authority,
    )
    simulator_repository = SQLiteSimulatorRepository(simulator_database.resolve(strict=True))
    recovery_repository = SQLiteRecoveryRepository(recovery_database.resolve(strict=True))
    try:
        plan_service = ResponsePlanService(
            repository=plan_repository,
            identity_boundary=OIDCTrustBoundary(
                trusted_issuers=frozenset({"https://evaluation.invalid"}),
                audience="colortrace-evaluation",
            ),
        )
        identity = DispatchIdentity(
            task_key=task_key,
            operation_id=operation_id,
            payload_sha256=payload_sha256,
        )
        proof = plan_service.current_consumed_dispatch(
            task_key=task_key,
            operation_id=operation_id,
            payload_sha256=payload_sha256,
        )
        admission = simulator_repository.replay_admission(identity)
        if admission is None:
            raise EvaluationError("simulator-admission-missing")
        primary = simulator_repository.outcome(identity)
        if primary is None:
            raise EvaluationError("simulator-outcome-missing")
        before = simulator_repository.audit_history(identity)
        replay = simulator_repository.outcome(identity)
        after = simulator_repository.audit_history(identity)
        if replay is None:
            raise EvaluationError("simulator-replay-missing")
        aggregate = recovery_repository.durable_aggregate(workflow_id)
        body = {
            "schema": "reliability-action-recovery-evidence/v1",
            "plan_sha256": plan["sha256"],
            "spec_id": spec_id,
            "candidate": plan["candidate"],
            "response_plan_proof": proof,
            "simulator": {
                "identity": {
                    "task_key": task_key,
                    "operation_id": operation_id,
                    "payload_sha256": payload_sha256,
                },
                "admission": admission,
                "primary_outcome": primary,
                "replay_outcome": replay,
                "audit_before_replay": before,
                "audit_after_replay": after,
            },
            "recovery_aggregate": aggregate,
        }
        digest = prefixed_sha256(body)
        evidence = cast(
            dict[str, Any],
            {
                **body,
                "evidence_id": (f"reliability-action-recovery:{digest.removeprefix('sha256:')}"),
                "sha256": digest,
            },
        )
        validate_action_recovery_evidence(evidence, plan=plan, spec_id=spec_id)
        return evidence
    finally:
        recovery_repository.close()
        simulator_repository.close()
        plan_repository.close()


__all__ = ["build_action_recovery_evidence"]
