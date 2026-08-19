from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn, cast

from colortrace_api import Principal, ResponsePlanCoordinator, SimulatorActionCoordinator
from colortrace_grafana_mcp import QueryCatalog, SimulatorActionEvidenceBatch
from colortrace_recovery import (
    DeterministicRecoveryVerifier,
    RecoveryIdentityBoundary,
    RecoveryReadService,
    RecoveryVerificationService,
    SQLiteRecoveryRepository,
    SynchronousRecoveryWorkflowRunner,
)
from colortrace_response_plans import (
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    SQLiteResponsePlanRepository,
)
from colortrace_simulator import DispatchIdentity, SimulatorActionService
from colortrace_simulator.authority import SimulatorAuthorityBoundary, SimulatorExecutorBoundary
from colortrace_simulator.bundle import LocalPublicationPort
from colortrace_simulator.repository import SQLiteSimulatorRepository
from colortrace_vertical_slice import validate_replay

from .campaign import EvaluationError, _verify_plan
from .contracts import strict_json_file
from .evidence import build_action_recovery_evidence

_ISSUER = "https://phase3-evaluation.invalid"
_AUDIENCE = "colortrace-phase3-evaluation"
_CREDENTIAL = "sha256:" + "e" * 64


class _RecordedIncident:
    def __init__(self, replay: Mapping[str, Any]) -> None:
        self._replay = replay

    def replay(self, incident_id: str) -> dict[str, Any]:
        incident = cast(Mapping[str, Any], self._replay["incident"])
        if incident["incident_id"] != incident_id:
            raise EvaluationError("recovery-incident-binding-invalid")
        return dict(self._replay)


class _UnavailableEvidenceCollector:
    def __init__(self, catalog_sha256: str) -> None:
        self._catalog_sha256 = catalog_sha256
        self.calls = 0

    @property
    def simulator_action_catalog_sha256(self) -> str:
        return self._catalog_sha256

    async def collect_simulator_action_projection(
        self, batch: SimulatorActionEvidenceBatch
    ) -> NoReturn:
        del batch
        self.calls += 1
        raise EvaluationError("deliberate-recovery-evidence-unavailable")


def _principal(*, role: str, kind: str, incident_id: str, now: datetime) -> Principal:
    subject = f"phase3-{role.replace('.', '-')}"
    return Principal(
        subject=subject,
        display_name=subject,
        roles=frozenset({role}),
        issuer=_ISSUER,
        audience=_AUDIENCE,
        principal_kind=cast(Any, kind),
        incident_ids=frozenset({incident_id}),
        credential_sha256=_CREDENTIAL,
        expires_at=now + timedelta(hours=1),
    )


def _idempotency(spec_id: str, operation: str) -> str:
    digest = hashlib.sha256(f"{spec_id}:{operation}".encode()).hexdigest()
    return f"phase3-{operation}:{digest}"


def execute_recovery_failure_case(
    *,
    plan: Mapping[str, Any],
    spec_id: str,
    replay_path: Path,
    fixture_bundle: Path,
    run_root: Path,
    query_catalog_path: Path,
) -> dict[str, Any]:
    _verify_plan(plan)
    spec = next(
        (
            item
            for item in cast(list[Mapping[str, Any]], plan["specs"])
            if item["spec_id"] == spec_id
        ),
        None,
    )
    if spec is None or spec["recovery_case"] != "verification-failure":
        raise EvaluationError("recovery-spec-required")
    replay = strict_json_file(replay_path.resolve(strict=True))
    validate_replay(replay)
    packet = cast(Mapping[str, Any], replay["packet"])
    incident = cast(Mapping[str, Any], replay["incident"])
    if packet["status"] != "resolved" or packet["candidate_plan"] is None:
        raise EvaluationError("recovery-action-requires-resolved-investigation")
    incident_id = cast(str, incident["incident_id"])
    incident_version = cast(int, incident["version"])
    root = run_root.resolve(strict=True)
    response_database = root / "response-plans.sqlite3"
    simulator_database = root / "simulator.sqlite3"
    recovery_database = root / "recovery.sqlite3"
    publication_root = root / "publication-workspace"
    if any(
        path.exists()
        for path in (
            response_database,
            simulator_database,
            recovery_database,
            publication_root,
        )
    ):
        raise EvaluationError("recovery-case-already-attempted")

    now = datetime.now(UTC)
    publication = LocalPublicationPort.bootstrap(
        root=publication_root,
        fixture_bundle=fixture_bundle.resolve(strict=True),
    )
    inputs = publication.canonical_plan_inputs()
    identity_boundary = OIDCTrustBoundary(
        trusted_issuers=frozenset({_ISSUER}),
        audience=_AUDIENCE,
    )
    authority_boundary = CanonicalAuthorityBoundary()
    response_repository = SQLiteResponsePlanRepository(
        response_database,
        authority_boundary=authority_boundary,
    )
    simulator_repository = SQLiteSimulatorRepository(simulator_database)
    recovery_repository = SQLiteRecoveryRepository(recovery_database)
    try:
        plans = ResponsePlanCoordinator(
            incident_reader=_RecordedIncident(replay),
            repository=response_repository,
            authority_boundary=authority_boundary,
            identity_boundary=identity_boundary,
        )
        draft = plans.draft(incident_id)
        created = plans.create(
            _principal(role="response-plan.editor", kind="human", incident_id=incident_id, now=now),
            incident_id,
            {
                "expected_incident_version": incident_version,
                "expected_plan_version": 0,
                "response_packet_id": draft["response_packet_id"],
                "response_packet_sha256": draft["response_packet_sha256"],
                "deterministic_scope_sha256": draft["deterministic_scope_sha256"],
                "targets": draft["targets"],
                "exclusions": draft["exclusions"],
                "commands": inputs["commands"],
                "unresolved_acknowledged": False,
                "idempotency_key": _idempotency(spec_id, "create"),
            },
        )
        approval = plans.approve(
            _principal(
                role="response-plan.approver", kind="human", incident_id=incident_id, now=now
            ),
            incident_id,
            {
                "expected_incident_version": incident_version,
                "expected_plan_version": created["version"],
                "expected_plan_sha256": created["plan_sha256"],
                "idempotency_key": _idempotency(spec_id, "approve"),
            },
        )
        if approval["outcome"] != "approved":
            raise EvaluationError("recovery-plan-not-approved")
        dispatcher = _principal(
            role="response-plan.dispatcher", kind="service", incident_id=incident_id, now=now
        )
        authorization = plans.authorize_dispatch(
            dispatcher,
            incident_id,
            {
                "expected_incident_version": incident_version,
                "expected_plan_version": created["version"],
                "expected_plan_sha256": created["plan_sha256"],
                "idempotency_key": _idempotency(spec_id, "authorize"),
            },
        )
        plans.consume_dispatch(
            dispatcher,
            incident_id,
            {
                "authorization_id": authorization["authorization_id"],
                "expected_incident_version": incident_version,
                "expected_plan_version": created["version"],
                "expected_plan_sha256": created["plan_sha256"],
                "expected_task_key": authorization["task_key"],
                "expected_payload_sha256": authorization["payload_sha256"],
                "idempotency_key": _idempotency(spec_id, "consume"),
            },
        )
        identity = DispatchIdentity(
            task_key=cast(str, authorization["task_key"]),
            operation_id=cast(str, authorization["operation_id"]),
            payload_sha256=cast(str, authorization["payload_sha256"]),
        )
        executor_boundary = SimulatorExecutorBoundary()
        action_service = SimulatorActionService(
            repository=simulator_repository,
            dispatch_source=plans,
            authority_boundary=SimulatorAuthorityBoundary(),
            executor_boundary=executor_boundary,
            publication=publication,
        )
        action_coordinator = SimulatorActionCoordinator(
            service=action_service,
            executor_boundary=executor_boundary,
            identity_boundary=identity_boundary,
        )
        action_coordinator.admit(
            _principal(role="simulator.executor", kind="service", incident_id=incident_id, now=now),
            incident_id,
            {
                "schema": "simulator-action-admission-request/v1",
                "task_key": identity.task_key,
                "operation_id": identity.operation_id,
                "payload_sha256": identity.payload_sha256,
            },
        )
        primary = action_service.execute(identity, owner=f"phase3-{spec_id}")
        replayed = action_service.execute(identity, owner=f"phase3-{spec_id}-replay")
        if primary != replayed or primary["status"] != "succeeded":
            raise EvaluationError("recovery-action-replay-invalid")

        catalog = QueryCatalog.load(query_catalog_path.resolve(strict=True))
        collector = _UnavailableEvidenceCollector(catalog.digest)
        recovery_boundary = RecoveryIdentityBoundary(
            trusted_issuers=frozenset({_ISSUER}),
            audience=_AUDIENCE,
        )
        verification = RecoveryVerificationService(
            repository=recovery_repository,
            identity_boundary=recovery_boundary,
        )
        verifier = DeterministicRecoveryVerifier(
            outcomes=simulator_repository,
            publication=publication,
            collector=collector,
            verification=verification,
            reads=RecoveryReadService(recovery_repository),
            evidence_binding={
                "prometheus_datasource_uid": "phase3-unavailable-prometheus",
                "loki_datasource_uid": "phase3-unavailable-loki",
                "tempo_datasource_uid": "phase3-unavailable-tempo",
            },
            evidence_catalog_sha256=catalog.digest,
            heartbeat_seconds=0.1,
            collection_timeout_seconds=1.0,
        )
        recovery_principal = recovery_boundary.bind_verified_claims(
            issuer=_ISSUER,
            subject="phase3-recovery-verifier",
            display_name="Phase 3 recovery verifier",
            audience=_AUDIENCE,
            kind="service",
            roles=frozenset({"recovery.verifier"}),
            incident_ids=frozenset({incident_id}),
            credential_sha256=_CREDENTIAL,
            expires_at=now + timedelta(hours=1),
            credential_verified=True,
            now=now,
        )
        recovery_packet = SynchronousRecoveryWorkflowRunner(verifier).verify(
            recovery_principal,
            incident_id,
            idempotency_key=_idempotency(spec_id, "recovery"),
            expected_incident_version=incident_version,
            expected_outcome_sha256=cast(str, primary["outcome_sha256"]),
        )
        if recovery_packet["status"] != "recovery_unresolved" or collector.calls != 1:
            raise EvaluationError("recovery-failure-not-observed")
        workflow_id = cast(str, recovery_packet["workflow_id"])
    finally:
        recovery_repository.close()
        simulator_repository.close()
        response_repository.close()

    return build_action_recovery_evidence(
        plan=plan,
        spec_id=spec_id,
        response_plan_database=response_database,
        simulator_database=simulator_database,
        recovery_database=recovery_database,
        task_key=identity.task_key,
        operation_id=identity.operation_id,
        payload_sha256=identity.payload_sha256,
        workflow_id=workflow_id,
    )


__all__ = ["execute_recovery_failure_case"]
