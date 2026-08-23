from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections import Counter
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest
from colortrace_api import (
    APPROVAL_REQUEST_SCHEMA,
    CANONICAL_SCENARIO,
    CLOSURE_REQUEST_SCHEMA,
    RESET_REQUEST_SCHEMA,
    RUN_REQUEST_SCHEMA,
    DemoFacade,
    DemoFacadeError,
    Principal,
    RecoveryCoordinator,
    RecoveryVerificationWorker,
    ResponsePlanCoordinator,
    SimulatorActionCoordinator,
    SQLiteDemoRunStore,
    SQLiteRecoveryVerificationTaskStore,
    build_recovery_verification_task,
    create_app,
    create_recovery_worker_app,
)
from colortrace_api.demo_workflow import CanonicalDemoWorkflow
from colortrace_api.recovery_closure import LocalRecoveryClosureFence
from colortrace_api.simulator_runtime import LocalSimulatorRuntime
from colortrace_fixture.fixture import CANONICAL_SEED, build_scenario, validate_existing
from colortrace_grafana_mcp import EvidenceAdapter, OfficialMcpRuntime, QueryCatalog
from colortrace_grafana_mcp import adapter as grafana_adapter
from colortrace_investigation import (
    ColorStateValidatorGateway,
    InvestigationPolicy,
    ModelCall,
    ModelOutput,
)
from colortrace_recovery import (
    DeterministicRecoveryVerifier,
    RecoveryClosureService,
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
from colortrace_simulator.authority import (
    SimulatorAuthorityBoundary,
    SimulatorExecutorBoundary,
)
from colortrace_simulator.bundle import LocalPublicationPort
from colortrace_simulator.repository import SQLiteSimulatorRepository
from colortrace_vertical_slice import SqliteIncidentStore, VerticalSliceApi, VerticalSliceWorker
from fastapi.testclient import TestClient
from mcp import types

BASE = datetime(2026, 8, 14, 12, 0, tzinfo=UTC)
INCIDENT_ID = "incident-recovery-composed"
ISSUER = "https://identity.example.test"
API_AUDIENCE = "colortrace-api"
WORKER_AUDIENCE = "colortrace-recovery-worker"
BINDING = {
    "prometheus_datasource_uid": "prometheus-main",
    "loki_datasource_uid": "loki-main",
    "tempo_datasource_uid": "tempo-main",
}
CATALOG_PATH = Path(__file__).resolve().parents[3] / "config" / "grafana-mcp" / "query-catalog.json"


class StepClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        selected = self.value
        self.value += timedelta(seconds=1)
        return selected


class ManualClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class CanonicalIncidentService:
    def __init__(self) -> None:
        self.version = 7
        self.affected: list[dict[str, str]] = []
        self.safe: list[dict[str, str]] = []
        self.causal_resource_sha256 = ""

    def configure(
        self,
        *,
        affected: list[dict[str, str]],
        safe: list[dict[str, str]],
        causal_resource_sha256: str,
    ) -> None:
        self.affected = affected
        self.safe = safe
        self.causal_resource_sha256 = causal_resource_sha256

    def accept_alert(
        self,
        alert: Mapping[str, Any],
        principal: Principal,
    ) -> dict[str, Any]:
        del alert, principal
        raise AssertionError("not used")

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        del limit, cursor
        return {"schema": "incident-list/v1", "items": [], "next_cursor": None}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == INCIDENT_ID
        return {
            "schema": "incident-view/v1",
            "incident_id": incident_id,
            "status": "resolved",
            "version": self.version,
        }

    def workspace(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == INCIDENT_ID
        return {"schema": "incident-workspace/v1", "incident_id": incident_id}

    def replay(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == INCIDENT_ID
        return {
            "schema": "incident-replay/v1",
            "incident": {
                "incident_id": incident_id,
                "status": "resolved",
                "version": self.version,
            },
            "packet": {
                "packet_id": f"response-packet:{'6' * 64}",
                "incident_id": incident_id,
                "status": "resolved",
                "derivation_sha256": f"sha256:{'6' * 64}",
                "candidate_plan": {"targets": self.affected},
                "scope": {
                    "state": "resolved",
                    "policy": "single-causal-resource-scope/v1",
                    "affected": self.affected,
                    "safe": self.safe,
                    "unknown": [],
                    "reason_codes": [],
                },
                "unresolved_items": [],
            },
            "validator_results": [
                {"scope": {"causal_resource_sha256": self.causal_resource_sha256}}
            ],
        }


def principal(
    *,
    role: str,
    kind: str,
    audience: str = API_AUDIENCE,
    subject: str | None = None,
) -> Principal:
    selected_subject = subject or f"{role}@example.test"
    return Principal(
        subject=selected_subject,
        display_name=selected_subject,
        roles=frozenset({role}),
        issuer=ISSUER,
        audience=audience,
        principal_kind=cast(Any, kind),
        incident_ids=frozenset({INCIDENT_ID}),
        credential_sha256=f"sha256:{'8' * 64}",
        expires_at=BASE + timedelta(days=1),
    )


class TokenVerifier:
    def verify(self, token: str) -> Principal:
        if token == "scheduler":
            return principal(role="recovery.scheduler", kind="service")
        if token == "closer":
            return principal(
                role="recovery.closer",
                kind="human",
                subject="recovery-operator@example.test",
            )
        if token == "worker":
            return principal(
                role="recovery.verifier",
                kind="service",
                audience=WORKER_AUDIENCE,
                subject="recovery-worker@example.test",
            )
        raise ValueError("invalid token")


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def execute_canonical_action(
    tmp_path: Path,
    incidents: CanonicalIncidentService,
    clock: StepClock,
) -> tuple[
    dict[str, Any],
    DispatchIdentity,
    SQLiteSimulatorRepository,
    LocalPublicationPort,
]:
    fixture = tmp_path / "canonical-fixture"
    build_scenario(
        fixture,
        oracle_root=tmp_path / "private-oracle",
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    publication = LocalPublicationPort.bootstrap(
        root=tmp_path / "publication-workspace",
        fixture_bundle=fixture,
        clock=clock,
    )
    inputs = publication.canonical_plan_inputs()
    targets = list(inputs["targets"])
    exclusions = list(inputs["exclusions"])
    incidents.configure(
        affected=[
            {"kind": str(target["kind"]), "id": str(target["id"])}
            for target in targets
            if target["kind"] != "color-resource"
        ],
        safe=[{"kind": str(target["kind"]), "id": str(target["id"])} for target in exclusions],
        causal_resource_sha256=next(
            str(target["id"]) for target in targets if target["kind"] == "color-resource"
        ).removeprefix("sha256:"),
    )
    identity_boundary = OIDCTrustBoundary(
        trusted_issuers=frozenset({ISSUER}),
        audience=API_AUDIENCE,
    )
    plan_authority = CanonicalAuthorityBoundary()
    plans = ResponsePlanCoordinator(
        incident_reader=incidents,
        repository=SQLiteResponsePlanRepository(
            tmp_path / "response-plans.sqlite3",
            authority_boundary=plan_authority,
        ),
        authority_boundary=plan_authority,
        identity_boundary=identity_boundary,
        clock=clock,
    )
    draft = plans.draft(INCIDENT_ID)
    plan = plans.create(
        principal(role="response-plan.editor", kind="human"),
        INCIDENT_ID,
        {
            "expected_incident_version": incidents.version,
            "expected_plan_version": 0,
            "response_packet_id": draft["response_packet_id"],
            "response_packet_sha256": draft["response_packet_sha256"],
            "deterministic_scope_sha256": draft["deterministic_scope_sha256"],
            "targets": draft["targets"],
            "exclusions": draft["exclusions"],
            "commands": inputs["commands"],
            "unresolved_acknowledged": False,
            "idempotency_key": "composed-create-plan",
        },
    )
    plans.approve(
        principal(role="response-plan.approver", kind="human"),
        INCIDENT_ID,
        {
            "expected_incident_version": incidents.version,
            "expected_plan_version": plan["version"],
            "expected_plan_sha256": plan["plan_sha256"],
            "idempotency_key": "composed-approve-plan",
        },
    )
    dispatcher = principal(role="response-plan.dispatcher", kind="service")
    authorization = plans.authorize_dispatch(
        dispatcher,
        INCIDENT_ID,
        {
            "expected_incident_version": incidents.version,
            "expected_plan_version": plan["version"],
            "expected_plan_sha256": plan["plan_sha256"],
            "idempotency_key": "composed-authorize-plan",
        },
    )
    plans.consume_dispatch(
        dispatcher,
        INCIDENT_ID,
        {
            "authorization_id": authorization["authorization_id"],
            "expected_incident_version": incidents.version,
            "expected_plan_version": plan["version"],
            "expected_plan_sha256": plan["plan_sha256"],
            "expected_task_key": authorization["task_key"],
            "expected_payload_sha256": authorization["payload_sha256"],
            "idempotency_key": "composed-consume-plan",
        },
    )
    identity = DispatchIdentity(
        task_key=authorization["task_key"],
        operation_id=authorization["operation_id"],
        payload_sha256=authorization["payload_sha256"],
    )
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.sqlite3")
    executor_boundary = SimulatorExecutorBoundary()
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=plans,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=clock,
        trace_id_factory=iter(f"{index:032x}" for index in range(1, 6)).__next__,
    )
    coordinator = SimulatorActionCoordinator(
        service=service,
        executor_boundary=executor_boundary,
        identity_boundary=identity_boundary,
        clock=clock,
    )
    admission = coordinator.admit(
        principal(role="simulator.executor", kind="service"),
        INCIDENT_ID,
        {
            "schema": "simulator-action-admission-request/v1",
            "task_key": identity.task_key,
            "operation_id": identity.operation_id,
            "payload_sha256": identity.payload_sha256,
        },
    )
    outcome = service.execute(identity, owner="composed-simulator-worker")
    assert admission["action_id"] == outcome["action_id"]
    assert outcome["status"] == "succeeded", outcome["reason_codes"]
    assert repository.outcome(identity) == outcome
    return outcome, identity, repository, publication


def frozen_inventory() -> grafana_adapter.FrozenInventory:
    body = {
        "pins": {
            key: {
                "input": value.input_schema_sha256,
                "annotations": value.annotations_sha256,
            }
            for key, value in grafana_adapter.TOOL_PINS.items()
        }
    }
    return grafana_adapter.FrozenInventory(
        grafana_adapter._prefixed_sha256(grafana_adapter.canonical_json_bytes(body)),
        grafana_adapter.TOOL_PINS,
    )


def action_payload(
    tool: str,
    arguments: Mapping[str, Any],
    batch: grafana_adapter.SimulatorActionEvidenceBatch,
    emitted_at: str,
) -> dict[str, Any]:
    events = grafana_adapter._expected_action_events(batch)

    def flattened(
        event: grafana_adapter._ExpectedActionEvent,
        *,
        normalized: bool,
    ) -> dict[str, Any]:
        values = dict(event.attributes)
        values["telemetry.emitted_at"] = emitted_at
        return {
            (name.replace(".", "_") if normalized else name): (
                grafana_adapter._action_attribute_text(value) if normalized else value
            )
            for name, value in values.items()
        }

    if tool == "query_prometheus":
        return {
            "data": [
                {"metric": flattened(event, normalized=True), "value": [1, "1"]}
                for event in events.values()
                if event.signal == "metric"
            ]
        }
    if tool == "query_loki_logs":
        rows = [
            {
                "timestamp": emitted_at,
                "line": "simulator action observation",
                "labels": {},
                "structuredMetadata": flattened(event, normalized=True),
            }
            for event in events.values()
            if event.signal == "log"
        ]
        return {
            "data": rows,
            "metadata": {
                "linesReturned": len(rows),
                "maxLinesAllowed": 200,
                "resultsTruncated": False,
                "totalLinesScanned": len(rows),
                "startTime": arguments["startRfc3339"],
                "endTime": arguments["endRfc3339"],
            },
        }
    if tool == "tempo_get-trace":
        selected = next(
            event
            for event in events.values()
            if event.signal == "trace" and event.trace_id == arguments["trace_id"]
        )
        return {
            "trace": {
                "traceId": arguments["trace_id"],
                "services": [
                    {
                        "serviceName": "colortrace-simulator",
                        "resource": {},
                        "scopes": [
                            {
                                "name": "colortrace.telemetry",
                                "spans": [
                                    {
                                        "spanId": "2" * 16,
                                        "name": "simulator.action",
                                        "startTimeUnixNano": "1",
                                        "endTimeUnixNano": "2",
                                        "attributes": flattened(selected, normalized=False),
                                        "events": [],
                                        "status": {},
                                    }
                                ],
                            }
                        ],
                    }
                ],
            },
            "metrics": {"inspectedBytes": 1},
            "status": "COMPLETE",
        }
    raise AssertionError(tool)


class FakeOfficialSession:
    def __init__(
        self,
        batch: grafana_adapter.SimulatorActionEvidenceBatch,
        *,
        emitted_at: str,
    ) -> None:
        self.batch = batch
        self.emitted_at = emitted_at
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult:
        assert cursor is None
        return types.ListToolsResult(tools=[])

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> types.CallToolResult:
        assert read_timeout_seconds is not None
        selected_arguments = dict(arguments or {})
        self.calls.append((name, selected_arguments))
        payload = action_payload(name, selected_arguments, self.batch, self.emitted_at)
        return types.CallToolResult(
            _meta=(
                {"encoding": "json", "type": "trace", "version": "2"}
                if name == "tempo_get-trace"
                else None
            ),
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps(payload, sort_keys=True),
                )
            ],
        )


class FakeOfficialSessionFactory:
    def __init__(self, session: FakeOfficialSession) -> None:
        self.session = session
        self.opened = 0
        self.closed = 0

    @asynccontextmanager
    async def __call__(
        self,
        runtime: OfficialMcpRuntime,
    ) -> AsyncIterator[FakeOfficialSession]:
        assert runtime.grafana_url == "https://grafana.invalid"
        self.opened += 1
        try:
            yield self.session
        finally:
            self.closed += 1


def test_canonical_action_evidence_worker_review_and_human_closure_compose(
    tmp_path: Path,
) -> None:
    incidents = CanonicalIncidentService()
    simulator_clock = StepClock(BASE)
    outcome, identity, simulator_repository, publication = execute_canonical_action(
        tmp_path,
        incidents,
        simulator_clock,
    )
    assert len(outcome["command_outcomes"]) == 5
    assert len(outcome["exclusions"]) == 3
    safe_digest = outcome["safe_complement_before_sha256"]
    assert outcome["safe_complement_after_sha256"] == safe_digest
    assert (
        simulator_repository.outcome_for_incident(
            INCIDENT_ID,
            expected_outcome_sha256=outcome["outcome_sha256"],
        )
        == outcome
    )
    assert simulator_repository.outcome(identity) == outcome

    catalog = QueryCatalog.load(CATALOG_PATH)
    preview_snapshot = publication.snapshot_for_recovery(outcome)
    recovery_clock = ManualClock(simulator_clock.value + timedelta(seconds=30))
    preview_batch = grafana_adapter.SimulatorActionEvidenceBatch.from_documents(
        outcome=outcome,
        snapshot=preview_snapshot.to_dict(),
        evidence_request_id=f"recovery-evidence-request:{'a' * 64}",
        evidence_request_sha256=f"sha256:{'a' * 64}",
        catalog_sha256=catalog.digest,
        binding=BINDING,
    )
    completed_at = datetime.fromisoformat(cast(str, outcome["completed_at"]).replace("Z", "+00:00"))
    emitted_at = (
        (completed_at + timedelta(milliseconds=100))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    session = FakeOfficialSession(preview_batch, emitted_at=emitted_at)
    session_factory = FakeOfficialSessionFactory(session)
    adapter = EvidenceAdapter(
        runtime=OfficialMcpRuntime(
            "https://grafana.invalid",
            Path("/private/fake-viewer-token"),
            Path("/usr/local/bin/mcp-grafana"),
            b"fake-viewer-token",
            grafana_adapter._RUNTIME_VERIFICATION,
        ),
        catalog=catalog,
        session_factory=session_factory,
        clock=recovery_clock,
    )

    recovery_repository = SQLiteRecoveryRepository(tmp_path / "recovery.sqlite3")
    worker_boundary = RecoveryIdentityBoundary(
        trusted_issuers=frozenset({ISSUER}),
        audience=WORKER_AUDIENCE,
    )
    verification = RecoveryVerificationService(
        repository=recovery_repository,
        identity_boundary=worker_boundary,
        clock=recovery_clock,
    )
    workflow = DeterministicRecoveryVerifier(
        outcomes=simulator_repository,
        publication=publication,
        collector=adapter,
        verification=verification,
        reads=RecoveryReadService(recovery_repository),
        evidence_binding=BINDING,
        evidence_catalog_sha256=catalog.digest,
        clock=recovery_clock,
        heartbeat_seconds=0.1,
    )
    task_store = SQLiteRecoveryVerificationTaskStore(
        tmp_path / "recovery-tasks.sqlite3",
        clock=recovery_clock,
    )
    public_boundary = RecoveryIdentityBoundary(
        trusted_issuers=frozenset({ISSUER}),
        audience=API_AUDIENCE,
    )
    coordinator = RecoveryCoordinator(
        incident_reader=incidents,
        aggregate_reader=recovery_repository,
        closure_service=RecoveryClosureService(
            repository=recovery_repository,
            identity_boundary=public_boundary,
            clock=recovery_clock,
        ),
        identity_boundary=public_boundary,
        task_dispatcher=task_store,
        closure_fence=LocalRecoveryClosureFence(
            repository=simulator_repository,
            publication=publication,
        ),
        clock=recovery_clock,
    )
    worker = RecoveryVerificationWorker(
        incident_reader=incidents,
        task_store=task_store,
        workflow_runner=SynchronousRecoveryWorkflowRunner(workflow),
        identity_boundary=worker_boundary,
        clock=recovery_clock,
    )
    verifier = TokenVerifier()
    public_client = TestClient(
        create_app(
            incidents,
            token_verifier=verifier,
            recovery=coordinator,
            recovery_verifications=coordinator,
        )
    )
    private_client = TestClient(create_recovery_worker_app(worker, token_verifier=verifier))
    admission_request = {
        "schema": "recovery-verification-admission-request/v1",
        "expected_incident_version": incidents.version,
        "expected_outcome_sha256": outcome["outcome_sha256"],
        "idempotency_key": "composed-recovery-verification",
    }

    first_admission_response = public_client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/recovery/verifications",
        json=admission_request,
        headers=auth("scheduler"),
    )
    duplicate_admission_response = public_client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/recovery/verifications",
        json=admission_request,
        headers=auth("scheduler"),
    )
    assert first_admission_response.status_code == 202
    assert duplicate_admission_response.status_code == 202
    admission = first_admission_response.json()
    assert admission == {
        **build_recovery_verification_task(
            incident_id=INCIDENT_ID,
            expected_incident_version=incidents.version,
            expected_outcome_sha256=outcome["outcome_sha256"],
            idempotency_key="composed-recovery-verification",
        ),
        "schema": "recovery-verification-admission/v1",
        "duplicate": False,
        "state": "queued",
    }
    assert duplicate_admission_response.json() == {**admission, "duplicate": True}
    task = task_store.pending_tasks()[0]
    assert task == {
        key: admission[key]
        for key in (
            "schema",
            "task_key",
            "incident_id",
            "expected_incident_version",
            "expected_outcome_sha256",
            "payload_sha256",
            "idempotency_key",
        )
    } | {"schema": "recovery-verification-task/v1"}

    private_path = f"/private/v1/recovery-verification-tasks/{task['task_key']}"
    with patch.object(
        grafana_adapter,
        "freeze_tool_inventory",
        return_value=frozen_inventory(),
    ):
        completed_response = private_client.post(
            private_path,
            json=task,
            headers=auth("worker"),
        )
        replay_response = private_client.post(
            private_path,
            json=task,
            headers=auth("worker"),
        )

    assert completed_response.status_code == 200, completed_response.json()
    assert replay_response.status_code == 200
    result = completed_response.json()
    assert replay_response.json() == result
    assert result["status"] == "completed"
    assert result["task_key"] == admission["task_key"]
    assert result["payload_sha256"] == admission["payload_sha256"]
    assert result["incident_id"] == INCIDENT_ID
    assert result["expected_incident_version"] == incidents.version
    assert result["expected_outcome_sha256"] == outcome["outcome_sha256"]
    assert session_factory.opened == 1
    assert session_factory.closed == 1
    assert len(session.calls) == 7
    assert Counter(name for name, _arguments in session.calls) == {
        "query_prometheus": 1,
        "query_loki_logs": 1,
        "tempo_get-trace": 5,
    }
    assert {
        arguments["trace_id"] for name, arguments in session.calls if name == "tempo_get-trace"
    } == set(outcome["new_trace_ids"])

    completed_admission = public_client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/recovery/verifications",
        json=admission_request,
        headers=auth("scheduler"),
    )
    assert completed_admission.status_code == 202
    assert completed_admission.json() == {
        **admission,
        "duplicate": True,
        "state": "complete",
    }

    review_response = public_client.get(f"/v1/incidents/{INCIDENT_ID}/recovery")
    assert review_response.status_code == 200
    review = review_response.json()
    assert review["state"] == "recovery_verified"
    assert review["current_incident_version"] == incidents.version
    assert review["packet"]["packet_id"] == result["packet_id"]
    assert review["packet"]["packet_sha256"] == result["packet_sha256"]
    assert review["packet"]["outcome_id"] == outcome["outcome_id"]
    assert review["packet"]["outcome_sha256"] == outcome["outcome_sha256"]
    assert review["snapshot"]["action_outcome"]["action_id"] == outcome["action_id"]
    assert review["snapshot"]["action_outcome"]["outcome_id"] == outcome["outcome_id"]
    assert review["snapshot"]["action_outcome"]["outcome_sha256"] == outcome["outcome_sha256"]
    assert review["snapshot"]["action_outcome"]["safe_complement_before_sha256"] == (safe_digest)
    assert review["snapshot"]["action_outcome"]["safe_complement_after_sha256"] == (safe_digest)
    assert len(review["evidence_records"]) == 21
    assert {record["freshness"] for record in review["evidence_records"]} == {"post-action"}
    assert {record["correlation"]["outcome_id"] for record in review["evidence_records"]} == {
        outcome["outcome_id"]
    }
    assert {record["correlation"]["outcome_sha256"] for record in review["evidence_records"]} == {
        outcome["outcome_sha256"]
    }
    aggregate = recovery_repository.durable_aggregate(review["packet"]["workflow_id"])
    assert len(aggregate["evidence"]) == 21
    assert len({record["evidence_id"] for record in aggregate["evidence"]}) == 21
    assert Counter(record["signal"] for record in aggregate["evidence"]) == {
        "metric": 8,
        "log": 8,
        "trace": 5,
    }

    close_reason = "Fresh recovery evidence and deterministic checks were reviewed."
    recovery_clock.value += timedelta(seconds=1)
    expected_closed_at = recovery_clock.value.isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )
    closure_request = {
        "schema": "recovery-closure-request/v1",
        "expected_incident_version": incidents.version,
        "expected_workflow_version": review["workflow_version"],
        "expected_packet_id": review["packet"]["packet_id"],
        "expected_packet_sha256": review["packet"]["packet_sha256"],
        "expected_outcome_id": outcome["outcome_id"],
        "expected_outcome_sha256": outcome["outcome_sha256"],
        "reason": close_reason,
        "idempotency_key": "composed-human-closure",
    }
    closure_response = public_client.post(
        f"/v1/incidents/{INCIDENT_ID}/recovery/close",
        json=closure_request,
        headers=auth("closer"),
    )
    closure_replay = public_client.post(
        f"/v1/incidents/{INCIDENT_ID}/recovery/close",
        json=closure_request,
        headers=auth("closer"),
    )
    assert closure_response.status_code == 200, closure_response.json()
    assert closure_replay.status_code == 200
    closure = closure_response.json()
    assert closure_replay.json() == closure
    assert closure["actor"] == {
        "issuer": ISSUER,
        "subject": "recovery-operator@example.test",
        "audience": API_AUDIENCE,
        "display_name": "recovery-operator@example.test",
        "kind": "human",
    }
    assert closure["authorized_role"] == "recovery.closer"
    assert closure["closed_at"] == expected_closed_at
    assert closure["reason"] == close_reason
    assert closure["outcome_id"] == outcome["outcome_id"]
    assert closure["outcome_sha256"] == outcome["outcome_sha256"]

    closed_review = public_client.get(f"/v1/incidents/{INCIDENT_ID}/recovery").json()
    assert closed_review["state"] == "closed"
    assert closed_review["closure"] == closure
    closed_event = closed_review["audit_events"][-1]
    assert closed_event["event_type"] == "recovery.closed"
    assert closed_event["occurred_at"] == expected_closed_at
    assert closed_event["actor"]["subject"] == "recovery-operator@example.test"
    assert closed_event["actor"]["kind"] == "human"
    assert closed_event["actor"]["authorized_role"] == "recovery.closer"
    assert closed_event["details"]["reason"] == close_reason

    stale_admission_request = {
        **admission_request,
        "idempotency_key": "composed-stale-verification",
    }
    stale_admission_response = public_client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/recovery/verifications",
        json=stale_admission_request,
        headers=auth("scheduler"),
    )
    assert stale_admission_response.status_code == 202
    stale_admission = stale_admission_response.json()
    stale_task = next(
        pending
        for pending in task_store.pending_tasks()
        if pending["task_key"] == stale_admission["task_key"]
    )
    incidents.version += 1
    stale_response = private_client.post(
        f"/private/v1/recovery-verification-tasks/{stale_task['task_key']}",
        json=stale_task,
        headers=auth("worker"),
    )
    assert stale_response.status_code == 409
    assert stale_response.json() == {"code": "verification-task-expected-version-conflict"}
    assert len(session.calls) == 7


DEMO_RUN_IDS = (
    "demo-run-11111111111111111111111111111111",
    "demo-run-22222222222222222222222222222222",
)
DEMO_INCIDENT_IDS = (
    "incident-demo-11111111111111111111111111111111",
    "incident-demo-22222222222222222222222222222222",
)
DEMO_NONCES = ("n" * 32, "m" * 32)
DEMO_ALERT_BINDING = {**BINDING, "alert_rule_uid": "ct-alert-main"}


def demo_instant(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_demo_correlation(bundle: Path) -> dict[str, str]:
    fixture = json.loads((bundle / "runtime/manifests/fixture-runtime-manifest.json").read_text())
    pointer = next(item for item in fixture["jobs"] if item["job_id"] == "job-b-02")
    job = json.loads((bundle / pointer["manifest"]).read_text())
    return {
        "fixture_id": fixture["fixture_id"],
        "job_id": job["job_id"],
        "worker_id": job["worker_id"],
        "artifact_id": job["output_id"],
        "trace_id": job["trace_id"],
        "config_sha256": job["nominal_config_sha256"],
        "transform_id": job["transform_id"],
    }


class DeterministicCanonicalAlertSource:
    def __init__(
        self,
        correlation: Mapping[str, str],
        investigation_session: InvestigationOfficialSession,
    ) -> None:
        self.correlation = dict(correlation)
        self.investigation_session = investigation_session
        self.emitted: list[dict[str, Any]] = []

    def emit(self, *, run_id: str, incident_id: str) -> Mapping[str, Any]:
        assert incident_id == f"incident-demo-{run_id.removeprefix('demo-run-')}"
        correlation = {**self.correlation, "run_id": run_id}
        self.investigation_session.select_run(run_id)
        value = {
            "schema": "alert-intake/v1",
            "incident_id": incident_id,
            "alert_id": f"alert-{run_id}",
            "alert_started_at": demo_instant(BASE - timedelta(minutes=5)),
            "retrieved_at": demo_instant(BASE),
            "measured_clock_skew_seconds": 0,
            "binding": DEMO_ALERT_BINDING,
            "correlation_keys": correlation,
            "predecessor_event_sha256": None,
        }
        self.emitted.append(value)
        return value


class DeterministicInvestigationModel:
    async def generate(self, call: ModelCall) -> ModelOutput:
        if call.turn_kind == "evidence-selection":
            if call.evidence_tool is not None:
                for query_key in grafana_adapter.QUERY_KEYS[1:]:
                    await call.evidence_tool(cast(Any, query_key))
            body = {
                "schema": "model-selection/v1",
                "hypothesis_keys": [
                    "color-resource-drift",
                    "nominal-config-drift",
                    "unrelated-event",
                    "worker-only-failure",
                ],
                "query_keys": list(grafana_adapter.QUERY_KEYS),
            }
        else:
            body = {
                "schema": "model-advisory/v1",
                "summary": "The cited deterministic result identifies the bounded scope.",
                "evidence_ids": [
                    item
                    for item in call.payload["allowed_evidence_ids"]
                    if isinstance(item, str) and item.startswith("sha256:")
                ][:4],
            }
        return ModelOutput(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
            1_000,
            100,
        )


class InvestigationOfficialSession:
    def __init__(self, correlation: Mapping[str, str]) -> None:
        self.base_correlation = dict(correlation)
        self.correlation = {**self.base_correlation, "run_id": DEMO_RUN_IDS[0]}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def select_run(self, run_id: str) -> None:
        self.correlation = {**self.base_correlation, "run_id": run_id}

    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult:
        assert cursor is None
        return types.ListToolsResult(tools=[])

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> types.CallToolResult:
        assert arguments is not None
        assert read_timeout_seconds == timedelta(seconds=20)
        self.calls.append((name, dict(arguments)))
        event_time = BASE - timedelta(minutes=3)
        if name == "query_prometheus":
            payload: dict[str, Any] = {
                "data": [
                    {
                        "metric": self.correlation,
                        "value": [int(event_time.timestamp()), "1"],
                    }
                ],
                "warnings": [],
            }
        elif name == "query_loki_logs":
            payload = {
                "data": [
                    {
                        "timestamp": demo_instant(event_time),
                        "line": json.dumps(
                            {
                                **self.correlation,
                                "event": "declared-reference-observation",
                            },
                            sort_keys=True,
                        ),
                        "labels": {"service_name": "colortrace-simulator"},
                        "structuredMetadata": self.correlation,
                    }
                ],
                "metadata": {
                    "linesReturned": 1,
                    "maxLinesAllowed": 200,
                    "resultsTruncated": False,
                    "totalLinesScanned": 1,
                    "startTime": arguments["startRfc3339"],
                    "endTime": arguments["endRfc3339"],
                },
            }
        elif name == "tempo_get-trace":
            start = str(int(event_time.timestamp() * 1_000_000_000))
            end = str(int((event_time + timedelta(seconds=1)).timestamp() * 1_000_000_000))
            payload = {
                "trace": {
                    "traceId": self.correlation["trace_id"],
                    "services": [
                        {
                            "serviceName": "colortrace-simulator",
                            "resource": self.correlation,
                            "scopes": [
                                {
                                    "name": "colortrace.telemetry",
                                    "spans": [
                                        {
                                            "spanId": "2" * 16,
                                            "name": "fixture.process",
                                            "startTimeUnixNano": start,
                                            "endTimeUnixNano": end,
                                            "attributes": self.correlation,
                                            "events": [],
                                            "status": {},
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
                "metrics": {"inspectedBytes": 1},
                "status": "COMPLETE",
            }
        elif name == "alerting_manage_rules":
            payload = {
                "uid": arguments["rule_uid"],
                "title": "ColorTrace correlation alert",
                "labels": self.correlation,
                "annotations": {},
                "data": [],
                "alerts": [
                    {
                        "labels": self.correlation,
                        "annotations": {},
                        "state": "firing",
                        "activeAt": demo_instant(event_time),
                        "value": "1",
                    }
                ],
            }
        else:  # pragma: no cover - the query catalog is frozen
            raise AssertionError(name)
        return types.CallToolResult(
            _meta=(
                {"encoding": "json", "type": "trace", "version": "2"}
                if name == "tempo_get-trace"
                else None
            ),
            content=[types.TextContent(type="text", text=json.dumps(payload, sort_keys=True))],
        )


class LateBoundRecoverySession:
    def __init__(
        self,
        *,
        repository: SQLiteSimulatorRepository,
        publication: LocalPublicationPort,
        catalog: QueryCatalog,
    ) -> None:
        self.repository = repository
        self.publication = publication
        self.catalog = catalog
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.incident_id: str | None = None
        self._batch: grafana_adapter.SimulatorActionEvidenceBatch | None = None

    def select_incident(self, incident_id: str) -> None:
        self.incident_id = incident_id
        self._batch = None

    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult:
        assert cursor is None
        return types.ListToolsResult(tools=[])

    def batch(self) -> grafana_adapter.SimulatorActionEvidenceBatch:
        if self._batch is None:
            assert self.incident_id is not None
            outcome = self.repository.outcome_for_incident(self.incident_id)
            assert outcome is not None
            snapshot = self.publication.snapshot_for_recovery(outcome)
            request_digest = hashlib.sha256(self.incident_id.encode()).hexdigest()
            self._batch = grafana_adapter.SimulatorActionEvidenceBatch.from_documents(
                outcome=outcome,
                snapshot=snapshot.to_dict(),
                evidence_request_id=f"recovery-evidence-request:{request_digest}",
                evidence_request_sha256=f"sha256:{request_digest}",
                catalog_sha256=self.catalog.digest,
                binding=BINDING,
            )
        return self._batch

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> types.CallToolResult:
        assert read_timeout_seconds is not None
        selected_arguments = dict(arguments or {})
        self.calls.append((name, selected_arguments))
        batch = self.batch()
        emitted_at = demo_instant(batch.action_completed_at + timedelta(milliseconds=100))
        payload = action_payload(name, selected_arguments, batch, emitted_at)
        return types.CallToolResult(
            _meta=(
                {"encoding": "json", "type": "trace", "version": "2"}
                if name == "tempo_get-trace"
                else None
            ),
            content=[types.TextContent(type="text", text=json.dumps(payload, sort_keys=True))],
        )


def demo_approval(started: Mapping[str, Any]) -> dict[str, Any]:
    approval = cast(Mapping[str, Any], started["approval"])
    return {
        "schema": APPROVAL_REQUEST_SCHEMA,
        "approval_nonce": started["approval_nonce"],
        "approval_phrase": approval["phrase"],
        "expected_run_version": started["version"],
        "expected_incident_version": approval["incident_version"],
        "expected_plan_version": approval["plan_version"],
        "expected_plan_sha256": approval["plan_sha256"],
        "expected_target_sha256": approval["target_sha256"],
        "idempotency_key": f"composed-demo-approve:{started['run_id']}",
    }


def demo_closure(recovered: Mapping[str, Any]) -> dict[str, Any]:
    approval = cast(Mapping[str, Any], recovered["approval"])
    recovery = cast(Mapping[str, Any], recovered["recovery"])
    return {
        "schema": CLOSURE_REQUEST_SCHEMA,
        "expected_run_version": recovered["version"],
        "expected_incident_version": approval["incident_version"],
        "expected_workflow_version": recovery["workflow_version"],
        "expected_packet_id": recovery["packet_id"],
        "expected_packet_sha256": recovery["packet_sha256"],
        "expected_outcome_id": recovery["outcome_id"],
        "expected_outcome_sha256": recovery["outcome_sha256"],
        "reason": "The verified composed recovery evidence was reviewed by a human.",
        "idempotency_key": f"composed-demo-close:{recovered['run_id']}",
    }


def test_demo_facade_composes_alert_through_immutable_closure_receipt(tmp_path: Path) -> None:
    fixture = tmp_path / "canonical-fixture"
    oracle = tmp_path / "private-oracle"
    build_scenario(
        fixture,
        oracle_root=oracle,
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    validate_existing(fixture)
    sealed_oracle = tmp_path / "sealed-offline-oracle"
    oracle.rename(sealed_oracle)
    os.chmod(sealed_oracle, 0)

    clock = StepClock(BASE)
    catalog = QueryCatalog.load(CATALOG_PATH)
    runtime = OfficialMcpRuntime(
        "https://grafana.invalid",
        Path("/private/fake-viewer-token"),
        Path("/usr/local/bin/mcp-grafana"),
        b"fake-viewer-token",
        grafana_adapter._RUNTIME_VERIFICATION,
    )

    async def load_inventory(_session: object) -> grafana_adapter.FrozenInventory:
        return frozen_inventory()

    correlation = canonical_demo_correlation(fixture)
    investigation_session = InvestigationOfficialSession(correlation)
    investigation_factory = FakeOfficialSessionFactory(cast(Any, investigation_session))
    investigation_evidence = EvidenceAdapter(
        runtime=runtime,
        catalog=catalog,
        session_factory=cast(Any, investigation_factory),
        inventory_loader=cast(Any, load_inventory),
        clock=clock,
    )
    incident_database = tmp_path / "incidents.sqlite3"
    incident_store = SqliteIncidentStore(incident_database)
    incidents = VerticalSliceApi(incident_store, clock=clock)
    policy = InvestigationPolicy.load(
        CATALOG_PATH.parents[1] / "investigation" / "investigation-policy.json",
        CATALOG_PATH.parents[1] / "investigation" / "model-profile.json",
    )
    investigation = VerticalSliceWorker(
        incident_store,
        policy=policy,
        model=DeterministicInvestigationModel(),
        evidence=investigation_evidence,
        validator=ColorStateValidatorGateway(),
        clock=clock,
        owner_id="composed-demo-investigator",
    )

    identity_boundary = OIDCTrustBoundary(
        trusted_issuers=frozenset({ISSUER}),
        audience=API_AUDIENCE,
    )
    plan_authority = CanonicalAuthorityBoundary()
    response_plan_database = tmp_path / "response-plans.sqlite3"
    response_plans = ResponsePlanCoordinator(
        incident_reader=incidents,
        repository=SQLiteResponsePlanRepository(
            response_plan_database,
            authority_boundary=plan_authority,
        ),
        authority_boundary=plan_authority,
        identity_boundary=identity_boundary,
        clock=clock,
    )

    publication = LocalPublicationPort.bootstrap(
        root=tmp_path / "publication-workspace",
        fixture_bundle=fixture,
        clock=clock,
    )
    baseline_pointer = (publication.root / "state" / "baseline.json").read_bytes()
    assert (publication.root / "state" / "active.json").read_bytes() == baseline_pointer
    simulator_database = tmp_path / "simulator.sqlite3"
    simulator_repository = SQLiteSimulatorRepository(simulator_database)
    executor_boundary = SimulatorExecutorBoundary()
    trace_ids = iter(f"{index:032x}" for index in range(1, 11))
    simulator_service = SimulatorActionService(
        repository=simulator_repository,
        dispatch_source=response_plans,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=clock,
        trace_id_factory=trace_ids.__next__,
    )
    simulator_runtime = LocalSimulatorRuntime(
        repository=simulator_repository,
        service=simulator_service,
        telemetry_sink=object(),
        recovery_publication=publication,
        poll_seconds=0.01,
    )
    simulator_actions = SimulatorActionCoordinator(
        service=simulator_service,
        executor_boundary=executor_boundary,
        identity_boundary=identity_boundary,
        clock=clock,
    )

    recovery_session = LateBoundRecoverySession(
        repository=simulator_repository,
        publication=publication,
        catalog=catalog,
    )
    recovery_factory = FakeOfficialSessionFactory(cast(Any, recovery_session))
    recovery_evidence = EvidenceAdapter(
        runtime=runtime,
        catalog=catalog,
        session_factory=cast(Any, recovery_factory),
        inventory_loader=cast(Any, load_inventory),
        clock=clock,
    )
    recovery_database = tmp_path / "recovery.sqlite3"
    recovery_repository = SQLiteRecoveryRepository(recovery_database)
    recovery_identity = RecoveryIdentityBoundary(
        trusted_issuers=frozenset({ISSUER}),
        audience=API_AUDIENCE,
    )
    verification = RecoveryVerificationService(
        repository=recovery_repository,
        identity_boundary=recovery_identity,
        clock=clock,
    )
    verifier = DeterministicRecoveryVerifier(
        outcomes=simulator_repository,
        publication=publication,
        collector=recovery_evidence,
        verification=verification,
        reads=RecoveryReadService(recovery_repository),
        evidence_binding=BINDING,
        evidence_catalog_sha256=catalog.digest,
        claim_owner="composed-demo-recovery",
        clock=clock,
        heartbeat_seconds=0.1,
    )
    recovery = RecoveryCoordinator(
        incident_reader=incidents,
        aggregate_reader=recovery_repository,
        closure_service=RecoveryClosureService(
            repository=recovery_repository,
            identity_boundary=recovery_identity,
            clock=clock,
        ),
        identity_boundary=recovery_identity,
        closure_fence=LocalRecoveryClosureFence(
            repository=simulator_repository,
            publication=publication,
        ),
        clock=clock,
    )

    visual_root = tmp_path / "demo-visuals"
    visual_root.mkdir(mode=0o700)
    alert_source = DeterministicCanonicalAlertSource(correlation, investigation_session)
    workflow = CanonicalDemoWorkflow(
        incidents=incidents,
        investigation=investigation,
        response_plans=response_plans,
        simulator_actions=simulator_actions,
        simulator_runtime=simulator_runtime,
        recovery=recovery,
        recovery_runner=SynchronousRecoveryWorkflowRunner(verifier),
        recovery_identity=recovery_identity,
        alert_source=alert_source,
        fixture_bundle=fixture,
        visual_root=visual_root,
        issuer=ISSUER,
        audience=API_AUDIENCE,
        clock=clock,
    )
    facade = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit="a" * 40,
        visual_root=visual_root,
        recovery=recovery,
        scenario_reset=simulator_runtime,
        closure_principal_factory=workflow.closure_principal,
        clock=clock,
        run_id_factory=iter(DEMO_RUN_IDS).__next__,
    )

    def complete_run(index: int) -> tuple[dict[str, Any], dict[str, Any]]:
        run_id = DEMO_RUN_IDS[index]
        incident_id = DEMO_INCIDENT_IDS[index]
        investigation_offset = len(investigation_session.calls)
        recovery_offset = len(recovery_session.calls)
        started = facade.start(
            {
                "schema": RUN_REQUEST_SCHEMA,
                "scenario_id": CANONICAL_SCENARIO,
                "approval_nonce": DEMO_NONCES[index],
                "idempotency_key": f"composed-demo-start-{index + 1}",
            }
        )
        assert started["run_id"] == run_id
        assert started["incident_id"] == incident_id
        assert started["phase"] == "awaiting-approval"
        assert alert_source.emitted[-1] == incidents.replay(incident_id)["alert"]
        assert len(started["investigation"]["evidence"]) == 4
        assert len(started["investigation"]["model_invocations"]) == 2
        assert Counter(
            name for name, _arguments in investigation_session.calls[investigation_offset:]
        ) == {
            "alerting_manage_rules": 1,
            "query_loki_logs": 1,
            "query_prometheus": 1,
            "tempo_get-trace": 1,
        }
        plan_review = response_plans.review(incident_id)
        assert plan_review["state"] == "pending"
        assert plan_review["plan"]["plan_sha256"] == started["approval"]["plan_sha256"]

        recovery_session.select_incident(incident_id)
        recovered = facade.approve(run_id, demo_approval(started))
        assert recovered["phase"] == "awaiting-closure"
        assert recovered["execution"]["action"]["affected_count"] == 4
        assert recovered["execution"]["action"]["safe_count"] == 3
        assert recovered["execution"]["action"]["publication_generation_before"] == 1
        assert recovered["execution"]["action"]["publication_generation_after"] == 2
        assert len(recovered["execution"]["recovery"]["checks"]) == 7
        assert recovered["execution"]["recovery"]["evidence_count"] == 21
        assert response_plans.review(incident_id)["state"] == "approved"
        assert Counter(name for name, _arguments in recovery_session.calls[recovery_offset:]) == {
            "query_prometheus": 1,
            "query_loki_logs": 1,
            "tempo_get-trace": 5,
        }
        aggregate = recovery_repository.durable_aggregate_for_incident(incident_id)
        assert len(aggregate["evidence"]) == 21
        assert Counter(item["signal"] for item in aggregate["evidence"]) == {
            "metric": 8,
            "log": 8,
            "trace": 5,
        }

        closed = facade.close(run_id, demo_closure(recovered))
        assert closed["phase"] == "closed"
        recovery_review = recovery.review(incident_id)
        assert recovery_review["state"] == "closed"
        assert recovery_review["closure"]["actor"]["kind"] == "human"
        receipt = facade.receipt(run_id)
        assert [item["stage"] for item in receipt["proofs"]] == [
            "execution",
            "investigation",
        ]
        assert receipt["bindings"]["closure_id"] == recovery_review["closure"]["closure_id"]
        return closed, receipt

    simulator_runtime.runner.start()
    try:
        first_closed, first_receipt = complete_run(0)
        assert len(alert_source.emitted) == 1
        assert recovery_factory.opened == 1
        assert recovery_factory.closed == 1
        mutated_pointer = (publication.root / "state" / "active.json").read_bytes()
        assert mutated_pointer != baseline_pointer

        with pytest.raises(DemoFacadeError, match="demo-visual-kind-invalid"):
            facade.visual(DEMO_RUN_IDS[0], "oracle")
        reset = facade.reset(
            DEMO_RUN_IDS[0],
            {
                "schema": RESET_REQUEST_SCHEMA,
                "expected_run_version": first_closed["version"],
                "idempotency_key": "composed-demo-reset-first",
            },
        )
        baseline_sha256 = f"sha256:{hashlib.sha256(baseline_pointer).hexdigest()}"
        assert reset["reset"] is True
        assert reset["restoration"]["generation"] == 1
        assert reset["restoration"]["active_pointer_sha256"] == baseline_sha256
        assert reset["restoration"]["previous_pointer_sha256"] == (
            f"sha256:{hashlib.sha256(mutated_pointer).hexdigest()}"
        )
        assert (publication.root / "state" / "active.json").read_bytes() == baseline_pointer
        assert facade.receipt(DEMO_RUN_IDS[0]) == first_receipt

        _second_closed, second_receipt = complete_run(1)
        assert second_receipt["run_id"] == DEMO_RUN_IDS[1]
        assert len(alert_source.emitted) == 2
        assert recovery_factory.opened == 2
        assert recovery_factory.closed == 2
        assert len(investigation_session.calls) == 8
        assert len(recovery_session.calls) == 14
        assert facade.receipt(DEMO_RUN_IDS[0]) == first_receipt
        with sqlite3.connect(simulator_database) as connection:
            action_counts = dict(
                connection.execute(
                    "SELECT incident_id, COUNT(*) FROM simulator_actions GROUP BY incident_id"
                ).fetchall()
            )
            outcome_counts = dict(
                connection.execute(
                    "SELECT actions.incident_id, COUNT(*) "
                    "FROM simulator_action_outcomes AS outcomes "
                    "JOIN simulator_actions AS actions ON actions.action_id = outcomes.action_id "
                    "GROUP BY actions.incident_id"
                ).fetchall()
            )
        assert action_counts == {incident_id: 1 for incident_id in DEMO_INCIDENT_IDS}
        assert outcome_counts == action_counts

        encoded_receipt = json.dumps([first_receipt, second_receipt], sort_keys=True).encode()
        assert str(oracle).encode() not in encoded_receipt
        assert str(sealed_oracle).encode() not in encoded_receipt
        for database in (
            incident_database,
            response_plan_database,
            simulator_database,
            recovery_database,
            tmp_path / "demo.sqlite3",
        ):
            stored = database.read_bytes()
            assert str(oracle).encode() not in stored
            assert str(sealed_oracle).encode() not in stored
    finally:
        simulator_runtime.runner.close()
        simulator_repository.close()
        recovery_repository.close()
        os.chmod(sealed_oracle, 0o700)
