from __future__ import annotations

import base64
import sqlite3
from collections.abc import Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from colortrace_api import (
    CloudTaskAlreadyExists,
    CloudTaskNotFound,
    CloudTaskRequestError,
    CloudTasksPublisherConfig,
    GoogleCloudTasksRestClient,
    GoogleOidcTokenVerifier,
    GoogleServiceIdentity,
    GoogleServiceTokenError,
    RecoveryCloudTasksPublisher,
    RecoveryVerificationWorker,
    ServerOwnedServiceBinding,
    SQLiteRecoveryVerificationTaskStore,
    build_recovery_verification_task,
    cloud_task_id,
    cloud_task_name,
    create_hosted_private_service_apps,
    create_hosted_recovery_worker_app,
    create_hosted_simulator_app,
)
from colortrace_api import recovery_tasks as recovery_task_module
from colortrace_api.google_identity import GoogleIdTokenClaimsVerifier
from colortrace_recovery import RecoveryIdentityBoundary, RecoveryPrincipal
from colortrace_simulator import DispatchIdentity
from colortrace_simulator.authority import ExecutorAuthorization, SimulatorExecutorBoundary
from fastapi import FastAPI
from fastapi.testclient import TestClient

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
ISSUER = "https://accounts.google.com"
RECOVERY_AUDIENCE = "https://recovery-worker.example.test"
SIMULATOR_AUDIENCE = "https://simulator.example.test"
RECOVERY_CALLER = "recovery-tasks@test-project.iam.gserviceaccount.com"
SIMULATOR_CALLER = "simulator-tasks@test-project.iam.gserviceaccount.com"
OTHER_CALLER = "other-invoker@test-project.iam.gserviceaccount.com"
RECOVERY_SUBJECT = "123456789012345678901"
SIMULATOR_SUBJECT = "123456789012345678902"
OTHER_SUBJECT = "123456789012345678999"
QUEUE_PATH = "projects/test-project/locations/us-central1/queues/private-tasks"
INCIDENT_ID = "incident-hosted-task"
OUTCOME_SHA256 = f"sha256:{'a' * 64}"


class StaticClaimsVerifier(GoogleIdTokenClaimsVerifier):
    def __init__(self, claims: Mapping[str, object]) -> None:
        self.claims = dict(claims)
        self.calls: list[tuple[str, str, float]] = []

    def verify(
        self,
        token: str,
        *,
        audience: str,
        clock_skew_seconds: float,
    ) -> Mapping[str, object]:
        self.calls.append((token, audience, clock_skew_seconds))
        return self.claims


def google_claims(**updates: object) -> dict[str, object]:
    values: dict[str, object] = {
        "iss": ISSUER,
        "sub": RECOVERY_SUBJECT,
        "email": RECOVERY_CALLER,
        "email_verified": True,
        "aud": RECOVERY_AUDIENCE,
        "iat": int(NOW.timestamp()) - 1,
        "exp": int(NOW.timestamp()) + 300,
        "roles": ["owner"],
        "incident_ids": ["attacker-selected"],
    }
    values.update(updates)
    return values


def service_identity(
    *,
    email: str = RECOVERY_CALLER,
    audience: str = RECOVERY_AUDIENCE,
    subject: str = RECOVERY_SUBJECT,
) -> GoogleServiceIdentity:
    return GoogleServiceIdentity(
        issuer=ISSUER,
        subject=subject,
        email=email,
        audience=audience,
        credential_sha256=f"sha256:{'d' * 64}",
        expires_at=NOW + timedelta(minutes=5),
    )


class StaticIdentityVerifier:
    def __init__(self, identity: GoogleServiceIdentity) -> None:
        self.identity = identity
        self.tokens: list[str] = []

    def verify(self, token: str) -> GoogleServiceIdentity:
        self.tokens.append(token)
        return self.identity


def recovery_task(*, key: str = "hosted-recovery-idempotency") -> dict[str, Any]:
    return build_recovery_verification_task(
        incident_id=INCIDENT_ID,
        expected_incident_version=4,
        expected_outcome_sha256=OUTCOME_SHA256,
        idempotency_key=key,
    )


def delivery_headers(task_key: str, *, retry: int = 0, execution: int = 0) -> dict[str, str]:
    return {
        "Authorization": "Bearer google-signed-token",
        "X-CloudTasks-QueueName": "private-tasks",
        "X-CloudTasks-TaskName": cloud_task_id(task_key),
        "X-CloudTasks-TaskRetryCount": str(retry),
        "X-CloudTasks-TaskExecutionCount": str(execution),
    }


def test_google_oidc_projects_only_google_service_identity() -> None:
    claims = StaticClaimsVerifier(google_claims())
    verifier = GoogleOidcTokenVerifier(
        audience=RECOVERY_AUDIENCE,
        claims_verifier=claims,
        leeway_seconds=10,
        clock=lambda: NOW,
    )

    identity = verifier.verify("signed-token")

    assert identity.email == RECOVERY_CALLER
    assert identity.audience == RECOVERY_AUDIENCE
    assert not hasattr(identity, "roles")
    assert not hasattr(identity, "incident_ids")
    assert claims.calls == [("signed-token", RECOVERY_AUDIENCE, 10.0)]


@pytest.mark.parametrize(
    "updates",
    [
        {"iss": "https://identity.example.test"},
        {"aud": "https://wrong.example.test"},
        {"email": OTHER_CALLER, "email_verified": False},
        {"sub": "not-numeric"},
        {"exp": int(NOW.timestamp()) - 1},
        {"iat": int(NOW.timestamp()) - 1, "exp": int(NOW.timestamp()) + 7200},
    ],
)
def test_google_oidc_rejects_untrusted_claims_without_detail(
    updates: Mapping[str, object],
) -> None:
    subject = GoogleOidcTokenVerifier(
        audience=RECOVERY_AUDIENCE,
        claims_verifier=StaticClaimsVerifier(google_claims(**updates)),
        leeway_seconds=0,
        clock=lambda: NOW,
    )

    with pytest.raises(
        GoogleServiceTokenError,
        match="^Google service token verification failed$",
    ) as error:
        subject.verify("signed-token")
    assert error.value.__cause__ is None


class FakeCloudTasksClient:
    def __init__(
        self,
        create_outcomes: list[BaseException | None] | None = None,
        lookup_outcomes: list[BaseException | None] | None = None,
    ) -> None:
        self.create_outcomes = [] if create_outcomes is None else list(create_outcomes)
        self.lookup_outcomes = [] if lookup_outcomes is None else list(lookup_outcomes)
        self.requests: list[tuple[str, Mapping[str, Any]]] = []
        self.lookups: list[str] = []

    def create_task(self, *, parent: str, task: Mapping[str, Any]) -> object:
        self.requests.append((parent, task))
        outcome = self.create_outcomes.pop(0) if self.create_outcomes else None
        if outcome is not None:
            raise outcome
        return object()

    def get_task(self, *, name: str) -> object:
        self.lookups.append(name)
        outcome = self.lookup_outcomes.pop(0) if self.lookup_outcomes else CloudTaskNotFound()
        if outcome is not None:
            raise outcome
        return {"name": name}


def publisher(
    store: SQLiteRecoveryVerificationTaskStore,
    client: FakeCloudTasksClient,
    *,
    max_attempts: int = 3,
) -> RecoveryCloudTasksPublisher:
    return RecoveryCloudTasksPublisher(
        outbox=store,
        client=client,
        config=CloudTasksPublisherConfig(
            queue_path=QUEUE_PATH,
            target_base_url=RECOVERY_AUDIENCE,
            oidc_audience=RECOVERY_AUDIENCE,
            oidc_service_account_email=RECOVERY_CALLER,
            max_publish_attempts=max_attempts,
            dispatch_deadline_seconds=600,
        ),
    )


def test_transactional_outbox_publishes_exact_canonical_task(tmp_path: Path) -> None:
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / "tasks.sqlite3", clock=lambda: NOW)
    task = recovery_task()

    first = store.dispatch(task)
    duplicate = store.dispatch(task)

    assert first["duplicate"] is False
    assert duplicate == {**first, "duplicate": True}
    assert store.cloud_task_outbox_state(task["task_key"]) == {
        "task_key": task["task_key"],
        "payload_sha256": task["payload_sha256"],
        "status": "pending",
        "delivery_attempts": 0,
        "cloud_task_name": None,
    }
    client = FakeCloudTasksClient()
    report = publisher(store, client).publish_pending()

    assert (report.reserved, report.enqueued, report.failed) == (1, 1, 0)
    parent, created = client.requests[0]
    assert parent == QUEUE_PATH
    assert created["name"] == cloud_task_name(QUEUE_PATH, task["task_key"])
    request = cast(Mapping[str, Any], created["httpRequest"])
    assert base64.b64decode(request["body"]) == canonical_task_bytes(task)
    assert request["oidcToken"] == {
        "serviceAccountEmail": RECOVERY_CALLER,
        "audience": RECOVERY_AUDIENCE,
    }
    assert store.cloud_task_outbox_state(task["task_key"])["status"] == "enqueued"


def canonical_task_bytes(task: Mapping[str, Any]) -> bytes:
    from colortrace_recovery import canonical_json_bytes

    return canonical_json_bytes(task)


def test_outbox_reconciles_ambiguous_create_and_exhausts_only_after_exact_absence(
    tmp_path: Path,
) -> None:
    ambiguous_store = SQLiteRecoveryVerificationTaskStore(
        tmp_path / "ambiguous.sqlite3",
        clock=lambda: NOW,
    )
    ambiguous_task = recovery_task(key="ambiguous-create")
    ambiguous_store.dispatch(ambiguous_task)
    ambiguous_client = FakeCloudTasksClient(
        [CloudTaskRequestError("response-lost")],
        [None],
    )
    subject = publisher(ambiguous_store, ambiguous_client)

    first = subject.publish_pending()

    assert (first.failed, first.already_exists) == (0, 1)
    assert ambiguous_store.cloud_task_outbox_state(ambiguous_task["task_key"])["status"] == (
        "enqueued"
    )
    assert ambiguous_client.lookups == [ambiguous_client.requests[0][1]["name"]]

    failed_store = SQLiteRecoveryVerificationTaskStore(
        tmp_path / "failed.sqlite3",
        clock=lambda: NOW,
    )
    failed_task = recovery_task(key="bounded-failure")
    failed_store.dispatch(failed_task)
    failing_client = FakeCloudTasksClient(
        [CloudTaskRequestError("one"), CloudTaskRequestError("two")],
        [CloudTaskNotFound(), CloudTaskNotFound(), CloudTaskNotFound()],
    )
    failing = publisher(failed_store, failing_client, max_attempts=2)

    assert failing.publish_pending().failed == 1
    assert failing.publish_pending().failed == 1
    assert failing.publish_pending().reserved == 0
    assert failed_store.cloud_task_outbox_state(failed_task["task_key"])["status"] == ("exhausted")
    assert len(failing_client.requests) == 2
    assert len(failing_client.lookups) == 3


def test_outbox_final_ambiguity_remains_pending_until_exact_task_is_visible(
    tmp_path: Path,
) -> None:
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / "final.sqlite3", clock=lambda: NOW)
    task = recovery_task(key="final-ambiguity")
    store.dispatch(task)
    client = FakeCloudTasksClient(
        [CloudTaskRequestError("response-lost")],
        [CloudTaskRequestError("lookup-unavailable"), None],
    )
    subject = publisher(store, client, max_attempts=1)

    first = subject.publish_pending()
    pending = store.cloud_task_outbox_state(task["task_key"])
    second = subject.publish_pending()

    assert first.failed == 1
    assert pending["status"] == "pending"
    assert pending["delivery_attempts"] == 1
    assert (second.already_exists, second.failed) == (1, 0)
    assert store.cloud_task_outbox_state(task["task_key"])["status"] == "enqueued"
    assert len(client.requests) == 1
    assert client.lookups == [cloud_task_name(QUEUE_PATH, task["task_key"])] * 2


@pytest.mark.parametrize("task_visible", [True, False])
def test_outbox_recovers_a_crash_after_the_final_delivery_reservation(
    tmp_path: Path,
    task_visible: bool,
) -> None:
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / f"crash-{task_visible}.sqlite3")
    task = recovery_task(key=f"crash-{task_visible}")
    store.dispatch(task)
    reserved = store.reserve_cloud_task_deliveries(limit=1, max_attempts=1)
    assert len(reserved) == 1
    lookup = None if task_visible else CloudTaskNotFound()
    client = FakeCloudTasksClient(lookup_outcomes=[lookup])

    report = publisher(store, client, max_attempts=1).publish_pending()

    assert client.requests == []
    assert client.lookups == [cloud_task_name(QUEUE_PATH, task["task_key"])]
    state = store.cloud_task_outbox_state(task["task_key"])
    assert state["status"] == ("enqueued" if task_visible else "exhausted")
    assert (report.already_exists, report.failed) == ((1, 0) if task_visible else (0, 1))


def test_outbox_does_not_hide_programming_errors_as_delivery_failures(tmp_path: Path) -> None:
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / "programming-error.sqlite3")
    task = recovery_task(key="programming-error")
    store.dispatch(task)
    client = FakeCloudTasksClient([AssertionError("broken client")])

    with pytest.raises(AssertionError, match="broken client"):
        publisher(store, client).publish_pending()

    state = store.cloud_task_outbox_state(task["task_key"])
    assert state["status"] == "pending"
    assert state["delivery_attempts"] == 1


def test_v1_task_store_migration_preserves_pending_authorized_tasks(tmp_path: Path) -> None:
    database = tmp_path / "v1-tasks.sqlite3"
    database.touch(mode=0o600)
    task = recovery_task(key="v1-pending")
    timestamp = "2026-08-21T12:00:00.000Z"
    with sqlite3.connect(database) as connection:
        connection.executescript(recovery_task_module._SCHEMA_V1)
        connection.execute(f"PRAGMA application_id = {recovery_task_module._APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 1")
        connection.execute(
            "INSERT INTO recovery_verification_tasks("
            "task_key, idempotency_key, payload_sha256, incident_id, "
            "expected_incident_version, expected_outcome_sha256, task_document, status, "
            "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
            (
                task["task_key"],
                task["idempotency_key"],
                task["payload_sha256"],
                task["incident_id"],
                task["expected_incident_version"],
                task["expected_outcome_sha256"],
                canonical_task_bytes(task),
                timestamp,
                timestamp,
            ),
        )

    store = SQLiteRecoveryVerificationTaskStore(database, clock=lambda: NOW)

    assert store.pending_tasks() == [task]
    assert store.cloud_task_outbox_state(task["task_key"])["status"] == "pending"
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_local_completion_suppresses_a_pending_cloud_delivery(tmp_path: Path) -> None:
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / "local.sqlite3", clock=lambda: NOW)
    task = recovery_task(key="completed-before-publish")
    store.dispatch(task)
    claim = store.claim(task, owner="local-worker")
    assert not isinstance(claim, dict)
    result = recovery_task_module.build_unresolved_recovery_verification_result(
        task,
        reason_code="verification-unresolved",
    )

    store.complete(claim, result)

    assert store.cloud_task_outbox_state(task["task_key"])["status"] == "suppressed"
    assert store.reserve_cloud_task_deliveries(limit=1, max_attempts=3) == []


@dataclass
class HttpResponse:
    status_code: int
    document: object

    def json(self) -> object:
        if isinstance(self.document, BaseException):
            raise self.document
        return self.document


class HttpSession:
    def __init__(
        self,
        *,
        post_response: HttpResponse | BaseException | None = None,
        get_response: HttpResponse | BaseException | None = None,
    ) -> None:
        self.post_response = post_response
        self.get_response = get_response
        self.posts: list[tuple[str, Mapping[str, Any], float]] = []
        self.gets: list[tuple[str, float]] = []

    def post(
        self,
        url: str,
        *,
        json: Mapping[str, Any],
        timeout: float,
    ) -> HttpResponse:
        self.posts.append((url, json, timeout))
        if isinstance(self.post_response, BaseException):
            raise self.post_response
        assert self.post_response is not None
        return self.post_response

    def get(self, url: str, *, timeout: float) -> HttpResponse:
        self.gets.append((url, timeout))
        if isinstance(self.get_response, BaseException):
            raise self.get_response
        assert self.get_response is not None
        return self.get_response


@pytest.mark.parametrize(
    ("status", "canonical_status", "error"),
    [
        (201, None, None),
        (409, "ALREADY_EXISTS", CloudTaskAlreadyExists),
        (409, "ABORTED", CloudTaskRequestError),
        (409, None, CloudTaskRequestError),
        (500, "INTERNAL", CloudTaskRequestError),
    ],
)
def test_cloud_tasks_rest_client_classifies_only_expected_responses(
    status: int,
    canonical_status: str | None,
    error: type[CloudTaskRequestError] | None,
) -> None:
    task = recovery_task(key="rest-create")
    name = cloud_task_name(QUEUE_PATH, task["task_key"])
    document: object
    if status in {200, 201}:
        document = {"name": name}
    else:
        document = {"error": {"status": canonical_status}} if canonical_status else {}
    session = HttpSession(post_response=HttpResponse(status, document))
    client = GoogleCloudTasksRestClient(session=session, timeout_seconds=7)
    cloud_task = {"name": name}

    if error is None:
        client.create_task(parent=QUEUE_PATH, task=cloud_task)
    else:
        with pytest.raises(error) as caught:
            client.create_task(parent=QUEUE_PATH, task=cloud_task)
        if error is CloudTaskRequestError:
            assert type(caught.value) is CloudTaskRequestError
    assert session.posts == [
        (
            f"https://cloudtasks.googleapis.com/v2/{QUEUE_PATH}/tasks",
            {"task": cloud_task},
            7.0,
        )
    ]


def test_cloud_tasks_rest_client_validates_success_and_lookup_names() -> None:
    expected = cloud_task_name(QUEUE_PATH, recovery_task(key="rest-names")["task_key"])
    wrong = cloud_task_name(QUEUE_PATH, recovery_task(key="wrong-name")["task_key"])
    create_session = HttpSession(post_response=HttpResponse(201, {"name": wrong}))

    with pytest.raises(CloudTaskRequestError, match="cloud-task-create-response-invalid"):
        GoogleCloudTasksRestClient(session=create_session).create_task(
            parent=QUEUE_PATH,
            task={"name": expected},
        )

    lookup_session = HttpSession(get_response=HttpResponse(200, {"name": wrong}))
    with pytest.raises(CloudTaskRequestError, match="cloud-task-get-response-invalid"):
        GoogleCloudTasksRestClient(session=lookup_session).get_task(name=expected)


@pytest.mark.parametrize(
    ("status", "canonical_status", "error"),
    [
        (200, None, None),
        (404, "NOT_FOUND", CloudTaskNotFound),
        (404, "PERMISSION_DENIED", CloudTaskRequestError),
        (503, "UNAVAILABLE", CloudTaskRequestError),
    ],
)
def test_cloud_tasks_rest_client_gets_only_an_exact_canonical_task(
    status: int,
    canonical_status: str | None,
    error: type[CloudTaskRequestError] | None,
) -> None:
    expected = cloud_task_name(QUEUE_PATH, recovery_task(key="rest-get")["task_key"])
    document: object
    if status == 200:
        document = {"name": expected}
    else:
        document = {"error": {"status": canonical_status}}
    session = HttpSession(get_response=HttpResponse(status, document))
    client = GoogleCloudTasksRestClient(session=session, timeout_seconds=9)

    if error is None:
        client.get_task(name=expected)
    else:
        with pytest.raises(error) as caught:
            client.get_task(name=expected)
        if error is CloudTaskRequestError:
            assert type(caught.value) is CloudTaskRequestError
    assert session.gets == [(f"https://cloudtasks.googleapis.com/v2/{expected}", 9.0)]


@pytest.mark.parametrize("method", ["create", "get"])
def test_cloud_tasks_rest_client_bounds_transport_failures(method: str) -> None:
    expected = cloud_task_name(QUEUE_PATH, recovery_task(key=f"transport-{method}")["task_key"])
    session = HttpSession(
        post_response=OSError("network unavailable"),
        get_response=OSError("network unavailable"),
    )
    client = GoogleCloudTasksRestClient(session=session)

    with pytest.raises(CloudTaskRequestError, match=f"cloud-task-{method}-request-failed"):
        if method == "create":
            client.create_task(parent=QUEUE_PATH, task={"name": expected})
        else:
            client.get_task(name=expected)


class IncidentReader:
    def __init__(self) -> None:
        self.version = 4

    def replay(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == INCIDENT_ID
        return {
            "schema": "incident-replay/v1",
            "incident": {
                "incident_id": incident_id,
                "status": "resolved",
                "version": self.version,
            },
        }


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


def hosted_recovery_app(
    tmp_path: Path,
    *,
    caller: GoogleServiceIdentity | None = None,
) -> tuple[FastAPI, SQLiteRecoveryVerificationTaskStore, IncidentReader, WorkflowRunner]:
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / "worker.sqlite3", clock=lambda: NOW)
    reader = IncidentReader()
    workflow = WorkflowRunner()
    worker = RecoveryVerificationWorker(
        incident_reader=reader,
        task_store=store,
        workflow_runner=workflow,
        identity_boundary=RecoveryIdentityBoundary(
            trusted_issuers=frozenset({ISSUER}),
            audience=RECOVERY_AUDIENCE,
        ),
        clock=lambda: NOW,
    )
    app = create_hosted_recovery_worker_app(
        worker,
        identity_verifier=StaticIdentityVerifier(caller or service_identity()),
        service_binding=ServerOwnedServiceBinding(
            caller_email=RECOVERY_CALLER,
            caller_subject=RECOVERY_SUBJECT,
            audience=RECOVERY_AUDIENCE,
            role="recovery.verifier",
        ),
        queue_path=QUEUE_PATH,
        max_delivery_attempts=5,
    )
    return app, store, reader, workflow


def test_hosted_worker_binds_server_authority_and_replays_once(tmp_path: Path) -> None:
    app, store, _reader, workflow = hosted_recovery_app(tmp_path)
    task = recovery_task()
    store.dispatch(task)
    path = f"/private/v1/recovery-verification-tasks/{task['task_key']}"

    with TestClient(app) as client:
        first = client.post(path, json=task, headers=delivery_headers(task["task_key"]))
        replay = client.post(
            path,
            json=task,
            headers=delivery_headers(task["task_key"], retry=1, execution=1),
        )

    assert first.status_code == 200
    assert replay.status_code == 200
    assert replay.json() == first.json()
    assert len(workflow.calls) == 1
    principal, incident, version, outcome, key = workflow.calls[0]
    assert principal.roles == frozenset({"recovery.verifier"})
    assert principal.incident_ids == frozenset({INCIDENT_ID})
    assert (incident, version, outcome, key) == (
        INCIDENT_ID,
        4,
        OUTCOME_SHA256,
        "hosted-recovery-idempotency",
    )


@pytest.mark.parametrize(
    ("caller", "headers_update", "body_update", "status"),
    [
        (service_identity(email=OTHER_CALLER), {}, {}, 401),
        (service_identity(subject=OTHER_SUBJECT), {}, {}, 401),
        (service_identity(audience="https://wrong.example.test"), {}, {}, 401),
        (service_identity(), {"X-CloudTasks-TaskName": "wrong"}, {}, 403),
        (service_identity(), {"X-CloudTasks-TaskRetryCount": "5"}, {}, 403),
        (service_identity(), {}, {"roles": ["owner"]}, 400),
        (service_identity(), {}, {"payload_sha256": f"sha256:{'b' * 64}"}, 409),
    ],
)
def test_hosted_worker_rejects_untrusted_authority_and_delivery_metadata(
    tmp_path: Path,
    caller: GoogleServiceIdentity,
    headers_update: Mapping[str, str],
    body_update: Mapping[str, Any],
    status: int,
) -> None:
    app, store, _reader, workflow = hosted_recovery_app(tmp_path, caller=caller)
    task = recovery_task()
    store.dispatch(task)
    headers = {**delivery_headers(task["task_key"]), **headers_update}
    body = {**task, **body_update}

    response = TestClient(app).post(
        f"/private/v1/recovery-verification-tasks/{task['task_key']}",
        json=body,
        headers=headers,
    )

    assert response.status_code == status
    assert workflow.calls == []


def test_hosted_worker_rejects_untracked_and_stale_tasks_before_execution(
    tmp_path: Path,
) -> None:
    app, store, reader, workflow = hosted_recovery_app(tmp_path)
    tracked = recovery_task()
    store.dispatch(tracked)
    reader.version = 5

    stale = TestClient(app).post(
        f"/private/v1/recovery-verification-tasks/{tracked['task_key']}",
        json=tracked,
        headers=delivery_headers(tracked["task_key"]),
    )
    reader.version = 4
    untracked = recovery_task(key="untracked-task")
    missing = TestClient(app).post(
        f"/private/v1/recovery-verification-tasks/{untracked['task_key']}",
        json=untracked,
        headers=delivery_headers(untracked["task_key"]),
    )

    assert stale.status_code == 409
    assert missing.status_code == 404
    assert workflow.calls == []


@dataclass(frozen=True)
class ResolvedAction:
    identity: DispatchIdentity
    incident_id: str
    incident_version: int


class AuthorityResolver:
    def __init__(self, action: ResolvedAction) -> None:
        self.action = action
        self.identities: list[DispatchIdentity] = []

    def resolve(self, identity: DispatchIdentity) -> Any:
        self.identities.append(identity)
        return self.action


class SimulatorService:
    def __init__(self, boundary: SimulatorExecutorBoundary, action: ResolvedAction) -> None:
        self.boundary = boundary
        self.action = action
        self.admissions = 0
        self.executions = 0
        self.outcome: dict[str, Any] | None = None

    def _record(self, schema: str) -> dict[str, Any]:
        return {
            "schema": schema,
            "task_key": self.action.identity.task_key,
            "operation_id": self.action.identity.operation_id,
            "payload_sha256": self.action.identity.payload_sha256,
            "incident_id": self.action.incident_id,
            "incident_version": self.action.incident_version,
        }

    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> Mapping[str, Any]:
        assert identity == self.action.identity
        self.boundary.assert_authorized(executor, incident_id=self.action.incident_id)
        self.admissions += 1
        return self._record("simulator-action-admission/v1")

    def execute(
        self,
        identity: DispatchIdentity,
        *,
        owner: str,
        observe_terminal: bool = True,
    ) -> Mapping[str, Any]:
        assert identity == self.action.identity
        assert owner == "hosted-simulator-worker"
        assert observe_terminal is True
        if self.outcome is None:
            self.executions += 1
            self.outcome = self._record("simulator-action-outcome/v1")
        return self.outcome


def simulator_task(identity: DispatchIdentity, *, version: int = 7) -> dict[str, Any]:
    return {
        "schema": "simulator-action-task/v1",
        "task_key": identity.task_key,
        "operation_id": identity.operation_id,
        "payload_sha256": identity.payload_sha256,
        "expected_incident_version": version,
    }


@pytest.mark.parametrize(
    ("simulator_email", "simulator_subject", "error"),
    [
        (RECOVERY_CALLER, SIMULATOR_SUBJECT, "caller identities must be separate"),
        (SIMULATOR_CALLER, RECOVERY_SUBJECT, "caller subjects must be separate"),
    ],
)
def test_hosted_composition_requires_separate_service_identities(
    simulator_email: str,
    simulator_subject: str,
    error: str,
) -> None:
    with pytest.raises(ValueError, match=error):
        create_hosted_private_service_apps(
            recovery_worker=cast(Any, object()),
            recovery_identity_verifier=StaticIdentityVerifier(service_identity()),
            recovery_service_binding=ServerOwnedServiceBinding(
                caller_email=RECOVERY_CALLER,
                caller_subject=RECOVERY_SUBJECT,
                audience=RECOVERY_AUDIENCE,
                role="recovery.verifier",
            ),
            recovery_queue_path=QUEUE_PATH,
            recovery_max_delivery_attempts=5,
            simulator_service=cast(Any, object()),
            simulator_authority_resolver=cast(Any, object()),
            simulator_executor_boundary=SimulatorExecutorBoundary(),
            simulator_identity_verifier=StaticIdentityVerifier(
                service_identity(
                    email=simulator_email,
                    audience=SIMULATOR_AUDIENCE,
                    subject=simulator_subject,
                )
            ),
            simulator_service_binding=ServerOwnedServiceBinding(
                caller_email=simulator_email,
                caller_subject=simulator_subject,
                audience=SIMULATOR_AUDIENCE,
                role="simulator.executor",
            ),
            simulator_queue_path=(
                "projects/test-project/locations/us-central1/queues/simulator-tasks"
            ),
            simulator_max_delivery_attempts=5,
        )


def test_hosted_simulator_derives_object_scope_and_replays_terminal_outcome() -> None:
    identity = DispatchIdentity(
        task_key=f"dispatch-task:{'1' * 64}",
        operation_id=f"dispatch-operation:{'2' * 64}",
        payload_sha256=f"sha256:{'3' * 64}",
    )
    action = ResolvedAction(identity, INCIDENT_ID, 7)
    boundary = SimulatorExecutorBoundary()
    service = SimulatorService(boundary, action)
    resolver = AuthorityResolver(action)
    lifecycle: list[str] = []

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Any:
        lifecycle.append("start")
        yield
        lifecycle.append("stop")

    app = create_hosted_simulator_app(
        service,
        authority_resolver=cast(Any, resolver),
        executor_boundary=boundary,
        identity_verifier=StaticIdentityVerifier(
            service_identity(
                email=SIMULATOR_CALLER,
                audience=SIMULATOR_AUDIENCE,
                subject=SIMULATOR_SUBJECT,
            )
        ),
        service_binding=ServerOwnedServiceBinding(
            caller_email=SIMULATOR_CALLER,
            caller_subject=SIMULATOR_SUBJECT,
            audience=SIMULATOR_AUDIENCE,
            role="simulator.executor",
        ),
        queue_path=QUEUE_PATH,
        max_delivery_attempts=5,
        lifespan=lifespan,
    )
    path = f"/private/v1/simulator-action-tasks/{identity.task_key}"

    with TestClient(app) as client:
        first = client.post(
            path,
            json=simulator_task(identity),
            headers=delivery_headers(identity.task_key),
        )
        replay = client.post(
            path,
            json=simulator_task(identity),
            headers=delivery_headers(identity.task_key, retry=1, execution=1),
        )

    assert first.status_code == 200
    assert replay.json() == first.json()
    assert service.admissions == 2
    assert service.executions == 1
    assert resolver.identities == [identity, identity]
    assert lifecycle == ["start", "stop"]


@pytest.mark.parametrize(
    ("version", "extra", "header_task", "status"),
    [
        (8, {}, None, 409),
        (7, {"incident_id": "attacker-selected"}, None, 400),
        (7, {"operation_id": 1}, None, 400),
        (7, {}, "wrong-task", 403),
    ],
)
def test_hosted_simulator_fails_closed_before_admission(
    version: int,
    extra: Mapping[str, Any],
    header_task: str | None,
    status: int,
) -> None:
    identity = DispatchIdentity(
        task_key=f"dispatch-task:{'1' * 64}",
        operation_id=f"dispatch-operation:{'2' * 64}",
        payload_sha256=f"sha256:{'3' * 64}",
    )
    action = ResolvedAction(identity, INCIDENT_ID, 7)
    boundary = SimulatorExecutorBoundary()
    service = SimulatorService(boundary, action)
    app = create_hosted_simulator_app(
        service,
        authority_resolver=cast(Any, AuthorityResolver(action)),
        executor_boundary=boundary,
        identity_verifier=StaticIdentityVerifier(
            service_identity(
                email=SIMULATOR_CALLER,
                audience=SIMULATOR_AUDIENCE,
                subject=SIMULATOR_SUBJECT,
            )
        ),
        service_binding=ServerOwnedServiceBinding(
            caller_email=SIMULATOR_CALLER,
            caller_subject=SIMULATOR_SUBJECT,
            audience=SIMULATOR_AUDIENCE,
            role="simulator.executor",
        ),
        queue_path=QUEUE_PATH,
        max_delivery_attempts=5,
    )
    headers = delivery_headers(identity.task_key)
    if header_task is not None:
        headers["X-CloudTasks-TaskName"] = header_task

    response = TestClient(app).post(
        f"/private/v1/simulator-action-tasks/{identity.task_key}",
        json={**simulator_task(identity, version=version), **extra},
        headers=headers,
    )

    assert response.status_code == status
    assert service.admissions == 0
    assert service.executions == 0
