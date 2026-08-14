from __future__ import annotations

import json
from collections import Counter
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from colortrace_api import (
    Principal,
    RecoveryCoordinator,
    RecoveryVerificationWorker,
    ResponsePlanCoordinator,
    SimulatorActionCoordinator,
    SQLiteRecoveryVerificationTaskStore,
    build_recovery_verification_task,
    create_app,
    create_recovery_worker_app,
)
from colortrace_api.recovery_closure import LocalRecoveryClosureFence
from colortrace_fixture.fixture import CANONICAL_SEED, build_scenario
from colortrace_grafana_mcp import EvidenceAdapter, OfficialMcpRuntime, QueryCatalog
from colortrace_grafana_mcp import adapter as grafana_adapter
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
        ),
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
