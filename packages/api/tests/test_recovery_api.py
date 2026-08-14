from __future__ import annotations

import sqlite3
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from colortrace_api import (
    Principal,
    RecoveryCoordinator,
    RecoveryVerificationTaskClaim,
    RecoveryVerificationWorker,
    SQLiteRecoveryVerificationTaskStore,
    build_recovery_verification_task,
    create_app,
    create_local_recovery_verification_boundary,
    create_recovery_worker_app,
)
from colortrace_api.recovery_tasks import build_recovery_verification_result
from colortrace_recovery import RecoveryError, RecoveryIdentityBoundary, RecoveryPrincipal
from fastapi.testclient import TestClient

INCIDENT_ID = "incident-recovery-api"
OUTCOME_SHA256 = f"sha256:{'a' * 64}"


class IncidentReader:
    version = 4

    def replay(self, incident_id: str) -> dict[str, Any]:
        return {
            "schema": "incident-replay/v1",
            "incident": {
                "incident_id": incident_id,
                "version": self.version,
                "status": "resolved",
            },
        }


class AggregateReader:
    def durable_aggregate_for_incident(self, incident_id: str) -> dict[str, Any]:
        target = {
            "schema": "simulator-target/v1",
            "namespace": "colortrace-simulator",
            "kind": "frame",
            "id": "frame-affected-a",
        }
        outcome = {
            "action_started_at": "2026-08-13T12:00:00.000Z",
            "action_id": "simulator-action:api",
            "outcome_id": "simulator-action-outcome:api",
            "outcome_sha256": OUTCOME_SHA256,
            "command_outcomes": [
                {
                    "command_id": "command-frame-a",
                    "target": target,
                }
            ],
            "exclusions": [],
        }
        snapshot = {
            "schema": "recovery-verification-snapshot/v1",
            "snapshot_id": "recovery-snapshot:api",
            "snapshot_sha256": f"sha256:{'b' * 64}",
            "incident_id": incident_id,
            "incident_version": 4,
            "created_at": "2026-08-13T12:00:03.000Z",
            "action_outcome": outcome,
            "active_publication": {},
            "verification_artifacts": [],
        }
        packet = {
            "evaluation_started_at": "2026-08-13T12:00:03.000Z",
            "evaluation_completed_at": "2026-08-13T12:00:04.000Z",
        }
        evidence = {
            "evidence_id": "recovery-evidence:api",
            "evidence_sha256": f"sha256:{'c' * 64}",
            "event_id": "simulator-action-event:api",
            "signal": "metric",
            "subject_kind": "command",
            "subject_id": "command-frame-a",
            "trace_id": "1" * 32,
            "outcome_id": outcome["outcome_id"],
            "outcome_sha256": OUTCOME_SHA256,
            "action_id": outcome["action_id"],
            "operation_id": "dispatch-operation:api",
            "observed_at": "2026-08-13T12:00:02.000Z",
            "emitted_at": "2026-08-13T12:00:02.500Z",
            "retrieved_at": "2026-08-13T12:00:03.500Z",
            "clock_provenance": "otel-collector",
            "clock_skew_milliseconds": 0,
            "truncated": False,
            "source_label": "grafana-mcp",
            "source_envelope": {"secret": "must-not-reach-browser"},
        }
        return {
            "schema": "recovery-durable-aggregate/v1",
            "review": {
                "incident_id": incident_id,
                "workflow_id": "recovery-workflow:api",
                "workflow_version": 1,
                "status": "recovery_verified",
            },
            "snapshot": snapshot,
            "evidence": [evidence],
            "packet": packet,
            "closure": None,
            "audit_events": [],
        }


class ClosureService:
    def __init__(self) -> None:
        self.calls: list[tuple[RecoveryPrincipal, str, Mapping[str, Any]]] = []

    def close(
        self,
        principal: RecoveryPrincipal,
        workflow_id: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((principal, workflow_id, request))
        return {"schema": "recovery-closure-result/v1", "workflow_id": workflow_id}


class ClosureFence:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Mapping[str, Any]]] = []

    @contextmanager
    def guard(
        self,
        *,
        incident_id: str,
        expected_outcome_sha256: str,
        verified_snapshot: Mapping[str, Any],
    ) -> Iterator[None]:
        self.calls.append((incident_id, expected_outcome_sha256, verified_snapshot))
        yield


class WorkflowRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[RecoveryPrincipal, str, int, str, str]] = []

    def verify(
        self,
        principal: RecoveryPrincipal,
        incident_id: str,
        *,
        expected_incident_version: int,
        expected_outcome_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self.calls.append(
            (
                principal,
                incident_id,
                expected_incident_version,
                expected_outcome_sha256,
                idempotency_key,
            )
        )
        packet_sha256 = f"sha256:{'f' * 64}"
        return {
            "schema": "recovery-packet/v1",
            "packet_id": f"recovery-packet:{packet_sha256.removeprefix('sha256:')}",
            "packet_sha256": packet_sha256,
            "incident_id": incident_id,
            "incident_version": expected_incident_version,
            "outcome_sha256": expected_outcome_sha256,
        }


def principal() -> Principal:
    return Principal(
        subject="operator@example.test",
        display_name="Pipeline TD",
        roles=frozenset({"recovery.closer"}),
        issuer="https://identity.example.test",
        audience="colortrace-api",
        principal_kind="human",
        incident_ids=frozenset({INCIDENT_ID}),
        credential_sha256=f"sha256:{'d' * 64}",
        expires_at=datetime(2026, 8, 13, 13, 0, tzinfo=UTC),
    )


def service_principal(
    *,
    roles: frozenset[str],
    audience: str = "colortrace-api",
    incident_ids: frozenset[str] = frozenset({INCIDENT_ID}),
) -> Principal:
    return Principal(
        subject="recovery-worker@example.test",
        display_name="Recovery worker",
        roles=roles,
        issuer="https://identity.example.test",
        audience=audience,
        principal_kind="service",
        incident_ids=incident_ids,
        credential_sha256=f"sha256:{'e' * 64}",
        expires_at=datetime(2026, 8, 13, 13, 0, tzinfo=UTC),
    )


def closure_request() -> dict[str, Any]:
    return {
        "schema": "recovery-closure-request/v1",
        "expected_incident_version": 4,
        "expected_workflow_version": 1,
        "expected_packet_id": "recovery-packet:api",
        "expected_packet_sha256": f"sha256:{'f' * 64}",
        "expected_outcome_id": "simulator-action-outcome:api",
        "expected_outcome_sha256": OUTCOME_SHA256,
        "reason": "Verified recovery reviewed by the incident owner.",
        "idempotency_key": "close-recovery-api",
    }


def coordinator(
    reader: IncidentReader | None = None,
    closure: ClosureService | None = None,
    task_store: SQLiteRecoveryVerificationTaskStore | None = None,
    closure_fence: ClosureFence | None = None,
) -> tuple[RecoveryCoordinator, ClosureService, ClosureFence]:
    selected_closure = closure or ClosureService()
    selected_fence = closure_fence or ClosureFence()
    return (
        RecoveryCoordinator(
            incident_reader=reader or IncidentReader(),
            aggregate_reader=AggregateReader(),
            closure_service=selected_closure,
            identity_boundary=RecoveryIdentityBoundary(
                trusted_issuers=frozenset({"https://identity.example.test"}),
                audience="colortrace-api",
            ),
            task_dispatcher=task_store,
            closure_fence=selected_fence,
            clock=lambda: datetime(2026, 8, 13, 12, 5, tzinfo=UTC),
        ),
        selected_closure,
        selected_fence,
    )


def test_public_review_projects_citations_without_raw_provider_content() -> None:
    subject, _closure, _fence = coordinator()

    review = subject.review(INCIDENT_ID)

    assert review["state"] == "recovery_verified"
    assert review["current_incident_version"] == 4
    assert review["evidence_records"][0]["freshness"] == "post-action"
    assert review["evidence_records"][0]["correlation"]["target"]["id"] == ("frame-affected-a")
    assert "must-not-reach-browser" not in str(review)


def test_closure_rechecks_canonical_version_and_binds_verified_human() -> None:
    reader = IncidentReader()
    subject, closure, fence = coordinator(reader=reader)
    request = closure_request()

    result = subject.close(principal(), INCIDENT_ID, request)

    assert result["workflow_id"] == "recovery-workflow:api"
    assert closure.calls[0][0].kind == "human"
    assert closure.calls[0][0].roles == frozenset({"recovery.closer"})
    assert fence.calls[0][0:2] == (INCIDENT_ID, OUTCOME_SHA256)
    reader.version = 5
    with pytest.raises(RecoveryError, match="closure-expected-version-conflict"):
        subject.close(principal(), INCIDENT_ID, request)
    assert len(closure.calls) == 1
    assert len(fence.calls) == 1


def test_unauthorized_closure_never_enters_currentness_fence() -> None:
    subject, closure, fence = coordinator()

    with pytest.raises(RecoveryError, match="closure-human-required"):
        subject.close(
            service_principal(roles=frozenset({"recovery.closer"})),
            INCIDENT_ID,
            closure_request(),
        )

    assert closure.calls == []
    assert fence.calls == []


def test_closure_fails_closed_without_currentness_fence() -> None:
    selected_closure = ClosureService()
    subject = RecoveryCoordinator(
        incident_reader=IncidentReader(),
        aggregate_reader=AggregateReader(),
        closure_service=selected_closure,  # type: ignore[arg-type]
        identity_boundary=RecoveryIdentityBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-api",
        ),
        clock=lambda: datetime(2026, 8, 13, 12, 5, tzinfo=UTC),
    )

    with pytest.raises(RecoveryError, match="recovery-closure-fence-unavailable"):
        subject.close(principal(), INCIDENT_ID, closure_request())

    assert selected_closure.calls == []


def admission_request(
    *,
    version: int = 4,
    outcome_sha256: str = OUTCOME_SHA256,
    idempotency_key: str = "verify-api-1",
) -> dict[str, Any]:
    return {
        "schema": "recovery-verification-admission-request/v1",
        "expected_incident_version": version,
        "expected_outcome_sha256": outcome_sha256,
        "idempotency_key": idempotency_key,
    }


def test_scheduler_admission_is_durable_idempotent_and_does_not_execute(
    tmp_path: Path,
) -> None:
    reader = IncidentReader()
    store = SQLiteRecoveryVerificationTaskStore(
        tmp_path / "verification-tasks.sqlite3",
        clock=lambda: datetime(2026, 8, 13, 12, 5, tzinfo=UTC),
    )
    subject, _closure, _fence = coordinator(reader=reader, task_store=store)
    scheduler = service_principal(roles=frozenset({"recovery.scheduler"}))

    first = subject.admit_verification(
        scheduler,
        INCIDENT_ID,
        admission_request(),
    )
    duplicate = subject.admit_verification(
        scheduler,
        INCIDENT_ID,
        admission_request(),
    )

    assert first["schema"] == "recovery-verification-admission/v1"
    assert first["state"] == "queued"
    assert first["duplicate"] is False
    assert first["expected_incident_version"] == 4
    assert first["expected_outcome_sha256"] == OUTCOME_SHA256
    assert first["task_key"].startswith("recovery-verification-task:")
    assert first["payload_sha256"].startswith("sha256:")
    assert duplicate == {**first, "duplicate": True}
    assert store.pending_tasks() == [
        {
            key: first[key]
            for key in (
                "schema",
                "task_key",
                "incident_id",
                "expected_incident_version",
                "expected_outcome_sha256",
                "payload_sha256",
                "idempotency_key",
            )
        }
        | {"schema": "recovery-verification-task/v1"}
    ]

    conflicting_task = build_recovery_verification_task(
        incident_id=INCIDENT_ID,
        expected_incident_version=4,
        expected_outcome_sha256=f"sha256:{'b' * 64}",
        idempotency_key="verify-api-1",
    )
    assert conflicting_task["task_key"] == first["task_key"]
    assert conflicting_task["payload_sha256"] != first["payload_sha256"]
    with pytest.raises(RecoveryError, match="verification-task-idempotency-conflict"):
        subject.admit_verification(
            scheduler,
            INCIDENT_ID,
            admission_request(outcome_sha256=f"sha256:{'b' * 64}"),
        )
    with pytest.raises(RecoveryError, match="verification-expected-version-conflict"):
        subject.admit_verification(
            scheduler,
            INCIDENT_ID,
            admission_request(version=3, idempotency_key="verify-version-conflict"),
        )

    with pytest.raises(RecoveryError, match="scheduler-service-required"):
        subject.admit_verification(principal(), INCIDENT_ID, admission_request())
    model = service_principal(roles=frozenset({"recovery.scheduler"}))
    model = Principal(
        subject=model.subject,
        display_name=model.display_name,
        roles=model.roles,
        issuer=model.issuer,
        audience=model.audience,
        principal_kind=cast(Any, "model"),
        incident_ids=model.incident_ids,
        credential_sha256=model.credential_sha256,
        expires_at=model.expires_at,
    )
    with pytest.raises(RecoveryError, match="model-authority-forbidden"):
        subject.admit_verification(model, INCIDENT_ID, admission_request())
    with pytest.raises(RecoveryError, match="scheduler-role-required"):
        subject.admit_verification(
            service_principal(roles=frozenset({"recovery.verifier"})),
            INCIDENT_ID,
            admission_request(),
        )
    with pytest.raises(RecoveryError, match="incident-access-denied"):
        subject.admit_verification(
            service_principal(
                roles=frozenset({"recovery.scheduler"}),
                incident_ids=frozenset(),
            ),
            INCIDENT_ID,
            admission_request(),
        )


class WorkerTokenVerifier:
    def verify(self, token: str) -> Principal:
        if token == "scheduler":
            return service_principal(roles=frozenset({"recovery.scheduler"}))
        if token == "worker":
            return service_principal(
                roles=frozenset({"recovery.verifier"}),
                audience="colortrace-recovery-worker",
            )
        if token == "wrong-audience":
            return service_principal(roles=frozenset({"recovery.verifier"}))
        if token == "wrong-role":
            return service_principal(
                roles=frozenset({"recovery.scheduler"}),
                audience="colortrace-recovery-worker",
            )
        if token == "wrong-scope":
            return service_principal(
                roles=frozenset({"recovery.verifier"}),
                audience="colortrace-recovery-worker",
                incident_ids=frozenset(),
            )
        raise ValueError("invalid")


def test_private_worker_checks_delivery_then_executes_once(tmp_path: Path) -> None:
    reader = IncidentReader()
    workflow = WorkflowRunner()
    boundary = create_local_recovery_verification_boundary(
        task_database_path=tmp_path / "verification-tasks.sqlite3",
        incident_reader=reader,
        workflow_runner=workflow,
        worker_identity_boundary=RecoveryIdentityBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-recovery-worker",
        ),
        clock=lambda: datetime(2026, 8, 13, 12, 5, tzinfo=UTC),
    )
    store = boundary.task_store
    admission, _closure, _fence = coordinator(reader=reader, task_store=store)
    public_client = TestClient(
        create_app(
            cast(Any, reader),
            token_verifier=WorkerTokenVerifier(),
            recovery_verifications=admission,
        )
    )
    admitted_response = public_client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/recovery/verifications",
        json=admission_request(),
        headers={"Authorization": "Bearer scheduler"},
    )
    assert admitted_response.status_code == 202
    admitted = admitted_response.json()
    task = store.pending_tasks()[0]
    private_path = f"/private/v1/recovery-verification-tasks/{admitted['task_key']}"
    assert (
        public_client.post(
            private_path,
            json=task,
            headers={"Authorization": "Bearer worker"},
        ).status_code
        == 404
    )
    private_client = TestClient(
        create_recovery_worker_app(boundary.worker, token_verifier=WorkerTokenVerifier())
    )
    path = private_path

    assert workflow.calls == []
    for token in ("wrong-audience", "wrong-role", "wrong-scope"):
        rejected = private_client.post(
            path,
            json=task,
            headers={"Authorization": f"Bearer {token}"},
        )
        assert rejected.status_code == 403
    tampered = {**task, "expected_outcome_sha256": f"sha256:{'b' * 64}"}
    rejected = private_client.post(
        path,
        json=tampered,
        headers={"Authorization": "Bearer worker"},
    )
    assert rejected.status_code == 409
    assert workflow.calls == []

    completed = private_client.post(
        path,
        json=task,
        headers={"Authorization": "Bearer worker"},
    )
    replay = private_client.post(
        path,
        json=task,
        headers={"Authorization": "Bearer worker"},
    )

    assert completed.status_code == 200
    assert replay.status_code == 200
    assert replay.json() == completed.json()
    assert completed.json()["schema"] == "recovery-verification-task-result/v1"
    assert completed.json()["task_key"] == admitted["task_key"]
    assert completed.json()["payload_sha256"] == admitted["payload_sha256"]
    assert len(workflow.calls) == 1
    bound, incident_id, expected_version, expected_outcome, key = workflow.calls[0]
    assert bound.kind == "service"
    assert bound.roles == frozenset({"recovery.verifier"})
    assert (incident_id, expected_version, expected_outcome, key) == (
        INCIDENT_ID,
        4,
        OUTCOME_SHA256,
        "verify-api-1",
    )


def test_worker_rechecks_current_version_before_claim_or_execution(tmp_path: Path) -> None:
    reader = IncidentReader()
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / "verification-tasks.sqlite3")
    admission, _closure, _fence = coordinator(reader=reader, task_store=store)
    admitted = admission.admit_verification(
        service_principal(roles=frozenset({"recovery.scheduler"})),
        INCIDENT_ID,
        admission_request(),
    )
    task = store.pending_tasks()[0]
    workflow = WorkflowRunner()
    worker = RecoveryVerificationWorker(
        incident_reader=reader,
        task_store=store,
        workflow_runner=workflow,
        identity_boundary=RecoveryIdentityBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-recovery-worker",
        ),
        clock=lambda: datetime(2026, 8, 13, 12, 5, tzinfo=UTC),
    )
    reader.version = 5

    with pytest.raises(RecoveryError, match="verification-task-expected-version-conflict"):
        worker.execute(
            service_principal(
                roles=frozenset({"recovery.verifier"}),
                audience="colortrace-recovery-worker",
            ),
            admitted["task_key"],
            task,
        )
    assert workflow.calls == []


class FailingWorkflowRunner(WorkflowRunner):
    def verify(
        self,
        principal: RecoveryPrincipal,
        incident_id: str,
        *,
        expected_incident_version: int,
        expected_outcome_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self.calls.append(
            (
                principal,
                incident_id,
                expected_incident_version,
                expected_outcome_sha256,
                idempotency_key,
            )
        )
        raise RuntimeError("provider response contained private details")


def test_worker_failure_is_a_bounded_durable_unresolved_replay(tmp_path: Path) -> None:
    reader = IncidentReader()
    store = SQLiteRecoveryVerificationTaskStore(
        tmp_path / "verification-tasks.sqlite3",
        clock=lambda: datetime(2026, 8, 13, 12, 5, tzinfo=UTC),
    )
    admission, _closure, _fence = coordinator(reader=reader, task_store=store)
    admitted = admission.admit_verification(
        service_principal(roles=frozenset({"recovery.scheduler"})),
        INCIDENT_ID,
        admission_request(),
    )
    task = store.pending_tasks()[0]
    workflow = FailingWorkflowRunner()
    worker = RecoveryVerificationWorker(
        incident_reader=reader,
        task_store=store,
        workflow_runner=workflow,
        identity_boundary=RecoveryIdentityBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-recovery-worker",
        ),
        clock=lambda: datetime(2026, 8, 13, 12, 5, tzinfo=UTC),
    )
    private_client = TestClient(
        create_recovery_worker_app(worker, token_verifier=WorkerTokenVerifier())
    )
    path = f"/private/v1/recovery-verification-tasks/{admitted['task_key']}"

    first = private_client.post(
        path,
        json=task,
        headers={"Authorization": "Bearer worker"},
    )
    replay = private_client.post(
        path,
        json=task,
        headers={"Authorization": "Bearer worker"},
    )

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert first.json()["status"] == "unresolved"
    assert first.json()["reason_code"] == "recovery-verification-worker-failed"
    assert first.json()["packet_id"] is None
    assert "private details" not in str(first.json())
    assert len(workflow.calls) == 1
    assert store.pending_tasks() == []


def test_expired_claim_is_reclaimed_and_stale_completion_is_fenced(tmp_path: Path) -> None:
    now = [datetime(2026, 8, 13, 12, 5, tzinfo=UTC)]
    store = SQLiteRecoveryVerificationTaskStore(
        tmp_path / "verification-tasks.sqlite3",
        clock=lambda: now[0],
        claim_lease_seconds=1,
    )
    task = build_recovery_verification_task(
        incident_id=INCIDENT_ID,
        expected_incident_version=4,
        expected_outcome_sha256=OUTCOME_SHA256,
        idempotency_key="verify-claim-recovery",
    )
    store.dispatch(task)
    first = store.claim(task, owner="worker-old")
    assert isinstance(first, RecoveryVerificationTaskClaim)
    with pytest.raises(RecoveryError, match="verification-task-in-progress"):
        store.claim(task, owner="worker-new")
    assert store.pending_tasks() == []

    now[0] += timedelta(seconds=2)
    assert store.pending_tasks() == [task]
    current = store.claim(task, owner="worker-new")
    assert isinstance(current, RecoveryVerificationTaskClaim)
    packet_sha256 = f"sha256:{'f' * 64}"
    result = build_recovery_verification_result(
        task,
        {
            "schema": "recovery-packet/v1",
            "packet_id": f"recovery-packet:{packet_sha256.removeprefix('sha256:')}",
            "packet_sha256": packet_sha256,
            "incident_id": INCIDENT_ID,
            "incident_version": 4,
            "outcome_sha256": OUTCOME_SHA256,
        },
    )

    with pytest.raises(RecoveryError, match="verification-task-claim-fenced"):
        store.complete(first, result)
    assert store.complete(current, result) == result
    assert store.claim(task, owner="worker-replay") == result


def test_task_store_reopens_private_file_and_preserves_task_semantics(tmp_path: Path) -> None:
    database = tmp_path / "verification-tasks.sqlite3"
    task = build_recovery_verification_task(
        incident_id=INCIDENT_ID,
        expected_incident_version=4,
        expected_outcome_sha256=OUTCOME_SHA256,
        idempotency_key="verify-reopen",
    )
    first = SQLiteRecoveryVerificationTaskStore(database)
    admission = first.dispatch(task)

    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    reopened = SQLiteRecoveryVerificationTaskStore(database)
    assert reopened.pending_tasks() == [task]
    assert reopened.dispatch(task) == {**admission, "duplicate": True}

    connection = reopened._connect()
    try:
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert connection.execute("PRAGMA trusted_schema").fetchone()[0] == 0
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
    finally:
        connection.close()


def test_task_store_rejects_insecure_unknown_and_non_regular_paths(tmp_path: Path) -> None:
    insecure = tmp_path / "insecure.sqlite3"
    insecure.touch(mode=0o600)
    insecure.chmod(0o644)
    with pytest.raises(RecoveryError, match="verification-task-store-permissions-invalid"):
        SQLiteRecoveryVerificationTaskStore(insecure)

    unknown = tmp_path / "unknown.sqlite3"
    unknown.touch(mode=0o600)
    unknown.chmod(0o600)
    with pytest.raises(RecoveryError, match="verification-task-store-schema-invalid"):
        SQLiteRecoveryVerificationTaskStore(unknown)

    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"target-must-not-be-opened")
    target.chmod(0o600)
    link = tmp_path / "link.sqlite3"
    link.symlink_to(target)
    with pytest.raises(RecoveryError, match="verification-task-store-path-invalid"):
        SQLiteRecoveryVerificationTaskStore(link)
    assert target.read_bytes() == b"target-must-not-be-opened"

    directory = tmp_path / "directory.sqlite3"
    directory.mkdir()
    with pytest.raises(RecoveryError, match="verification-task-store-path-invalid"):
        SQLiteRecoveryVerificationTaskStore(directory)


def test_open_task_store_rejects_database_path_replacement(tmp_path: Path) -> None:
    database = tmp_path / "verification-tasks.sqlite3"
    store = SQLiteRecoveryVerificationTaskStore(database)
    displaced = tmp_path / "displaced.sqlite3"
    database.rename(displaced)
    database.touch(mode=0o600)
    database.chmod(0o600)

    with pytest.raises(RecoveryError, match="verification-task-store-path-changed"):
        store.pending_tasks()


@pytest.mark.parametrize(
    "tamper_sql",
    (
        "PRAGMA writable_schema = ON;"
        "UPDATE sqlite_master SET sql = replace(sql, "
        "'CHECK(expected_incident_version >= 1)', "
        "'CHECK(expected_incident_version >= 0)') "
        "WHERE type = 'table' AND name = 'recovery_verification_tasks';"
        "PRAGMA writable_schema = OFF;",
        "DROP INDEX recovery_verification_tasks_available;"
        "CREATE INDEX recovery_verification_tasks_available "
        "ON recovery_verification_tasks(status);",
        "DROP TRIGGER recovery_verification_tasks_no_delete;"
        "CREATE TRIGGER recovery_verification_tasks_no_delete "
        "BEFORE DELETE ON recovery_verification_tasks BEGIN SELECT 1; END;",
    ),
    ids=("same-name-table", "same-name-index", "same-name-trigger"),
)
def test_task_store_reopen_rejects_exact_schema_definition_tamper(
    tmp_path: Path,
    tamper_sql: str,
) -> None:
    database = tmp_path / "verification-tasks.sqlite3"
    SQLiteRecoveryVerificationTaskStore(database)
    with sqlite3.connect(database) as connection:
        connection.executescript(tamper_sql)

    with pytest.raises(RecoveryError, match="verification-task-store-schema-invalid"):
        SQLiteRecoveryVerificationTaskStore(database)


@pytest.mark.parametrize("pragma", ("application_id = 0", "user_version = 99"))
def test_task_store_reopen_rejects_database_identity_tamper(
    tmp_path: Path,
    pragma: str,
) -> None:
    database = tmp_path / "verification-tasks.sqlite3"
    SQLiteRecoveryVerificationTaskStore(database)
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA {pragma}")

    with pytest.raises(RecoveryError, match="verification-task-store-schema-invalid"):
        SQLiteRecoveryVerificationTaskStore(database)


def test_task_store_reopen_maps_corruption_to_domain_failure(tmp_path: Path) -> None:
    database = tmp_path / "verification-tasks.sqlite3"
    SQLiteRecoveryVerificationTaskStore(database)
    database.write_bytes(b"not-a-sqlite-database")
    database.chmod(0o600)

    with pytest.raises(RecoveryError, match="verification-task-store-"):
        SQLiteRecoveryVerificationTaskStore(database)


def test_task_store_fails_closed_on_stored_document_tamper(tmp_path: Path) -> None:
    database = tmp_path / "verification-tasks.sqlite3"
    task = build_recovery_verification_task(
        incident_id=INCIDENT_ID,
        expected_incident_version=4,
        expected_outcome_sha256=OUTCOME_SHA256,
        idempotency_key="verify-document-tamper",
    )
    store = SQLiteRecoveryVerificationTaskStore(database)
    store.dispatch(task)
    with sqlite3.connect(database) as connection:
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' "
            "AND name IN ('recovery_verification_tasks_identity_immutable', "
            "'recovery_verification_tasks_valid_transition') ORDER BY name"
        ).fetchall()
        connection.execute("DROP TRIGGER recovery_verification_tasks_identity_immutable")
        connection.execute("DROP TRIGGER recovery_verification_tasks_valid_transition")
        connection.execute(
            "UPDATE recovery_verification_tasks SET task_document = ? WHERE task_key = ?",
            (b'{"schema":1.0}', task["task_key"]),
        )
        for (statement,) in trigger_sql:
            connection.execute(statement)

    reopened = SQLiteRecoveryVerificationTaskStore(database)
    with pytest.raises(RecoveryError, match="stored-verification-task-invalid"):
        reopened.pending_tasks()
