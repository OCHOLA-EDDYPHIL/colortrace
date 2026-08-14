from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from colortrace_api import Principal, SimulatorActionCoordinator, create_app
from colortrace_response_plans import OIDCTrustBoundary
from colortrace_simulator import DispatchIdentity
from colortrace_simulator.authority import ExecutorAuthorization, SimulatorExecutorBoundary
from colortrace_simulator.repository import SimulatorRepositoryError
from fastapi.testclient import TestClient

NOW = datetime(2026, 8, 13, 21, 0, tzinfo=UTC)
INCIDENT_ID = "incident-simulator-action"


class IncidentService:
    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]:
        raise AssertionError("not used")

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        raise AssertionError("not used")

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")

    def replay(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")

    def workspace(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")


class Verifier:
    def verify(self, token: str) -> Principal:
        role, kind, incidents, expires_at = {
            "executor": (
                "simulator.executor",
                "service",
                frozenset({INCIDENT_ID}),
                NOW + timedelta(hours=1),
            ),
            "dispatcher": (
                "response-plan.dispatcher",
                "service",
                frozenset({INCIDENT_ID}),
                NOW + timedelta(hours=1),
            ),
            "human": (
                "simulator.executor",
                "human",
                frozenset({INCIDENT_ID}),
                NOW + timedelta(hours=1),
            ),
            "other": (
                "simulator.executor",
                "service",
                frozenset({"incident-other"}),
                NOW + timedelta(hours=1),
            ),
            "expired": (
                "simulator.executor",
                "service",
                frozenset({INCIDENT_ID}),
                NOW - timedelta(seconds=1),
            ),
        }[token]
        return Principal(
            subject=f"{token}@example.test",
            display_name=token,
            roles=frozenset({role}),
            issuer="https://identity.example.test",
            audience="colortrace-api",
            principal_kind=kind,  # type: ignore[arg-type]
            incident_ids=incidents,
            credential_sha256=f"sha256:{'8' * 64}",
            expires_at=expires_at,
        )


class AdmissionService:
    def __init__(self) -> None:
        self.calls: list[tuple[DispatchIdentity, ExecutorAuthorization]] = []
        self.failure: str | None = None
        self.invalid_response = False

    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> dict[str, Any]:
        self.calls.append((identity, executor))
        if self.failure is not None:
            raise SimulatorRepositoryError(self.failure)
        if self.invalid_response:
            return {"schema": "simulator-action-admission/v1"}
        return {
            "schema": "simulator-action-admission/v1",
            "admission_id": f"simulator-admission:{'5' * 64}",
            "action_id": f"simulator-action:{'4' * 64}",
            "task_key": identity.task_key,
            "operation_id": identity.operation_id,
            "payload_sha256": identity.payload_sha256,
            "dispatch_bundle_sha256": f"sha256:{'6' * 64}",
            "incident_id": INCIDENT_ID,
            "incident_version": 7,
            "plan_id": f"response-plan:{'7' * 64}",
            "plan_version": 3,
            "plan_sha256": f"sha256:{'8' * 64}",
            "approval_id": f"plan-decision:{'9' * 64}",
            "approval_sha256": f"sha256:{'a' * 64}",
            "authorization_id": f"dispatch-authorization:{'b' * 64}",
            "authorization_sha256": f"sha256:{'c' * 64}",
            "consumption_id": f"dispatch-consumption:{'d' * 64}",
            "consumption_sha256": f"sha256:{'e' * 64}",
            "executor_actor": {
                "issuer": "https://identity.example.test",
                "subject": "executor@example.test",
                "audience": "colortrace-api",
                "kind": "service",
            },
            "admitted_at": "2026-08-13T21:00:00.000Z",
            "admission_sha256": f"sha256:{'f' * 64}",
        }


def request_body() -> dict[str, str]:
    return {
        "schema": "simulator-action-admission-request/v1",
        "task_key": f"dispatch-task:{'1' * 64}",
        "operation_id": f"dispatch-operation:{'2' * 64}",
        "payload_sha256": f"sha256:{'3' * 64}",
    }


def configured_client() -> tuple[TestClient, AdmissionService, SimulatorExecutorBoundary]:
    admission = AdmissionService()
    executor_boundary = SimulatorExecutorBoundary()
    coordinator = SimulatorActionCoordinator(
        service=admission,
        executor_boundary=executor_boundary,
        identity_boundary=OIDCTrustBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-api",
        ),
        clock=lambda: NOW,
    )
    return (
        TestClient(
            create_app(
                IncidentService(),
                token_verifier=Verifier(),
                simulator_actions=coordinator,
            )
        ),
        admission,
        executor_boundary,
    )


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_exact_service_admission_is_accepted_and_path_scoped() -> None:
    client, admission, boundary = configured_client()
    first = client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions",
        json=request_body(),
        headers=headers("executor"),
    )
    replay = client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions",
        json=request_body(),
        headers=headers("executor"),
    )
    assert first.status_code == 202
    assert replay.json() == first.json()
    assert admission.calls[0][0] == DispatchIdentity(
        task_key=request_body()["task_key"],
        operation_id=request_body()["operation_id"],
        payload_sha256=request_body()["payload_sha256"],
    )
    assert (
        boundary.assert_authorized(admission.calls[0][1], incident_id=INCIDENT_ID)["subject"]
        == "executor@example.test"
    )


def test_authentication_authority_and_idor_denials_never_call_service() -> None:
    client, admission, _boundary = configured_client()
    path = f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions"
    cases = (
        ({}, 401, "authentication-required"),
        (headers("dispatcher"), 403, "executor-role-required"),
        (headers("human"), 403, "executor-service-required"),
        (headers("other"), 403, "executor-incident-denied"),
        (headers("expired"), 401, "principal-credential-expired"),
    )
    for selected_headers, status, code in cases:
        response = client.post(path, json=request_body(), headers=selected_headers)
        assert response.status_code == status
        assert response.json() == {"code": code}
    assert admission.calls == []


def test_request_shape_and_repository_conflict_fail_closed() -> None:
    client, admission, _boundary = configured_client()
    path = f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions"
    for body in (
        {**request_body(), "command": "rerender all"},
        {key: value for key, value in request_body().items() if key != "payload_sha256"},
        {**request_body(), "schema": "simulator-action/v0"},
    ):
        response = client.post(path, json=body, headers=headers("executor"))
        assert response.status_code == 400
        assert response.json() == {"code": "admission-request-invalid"}
    assert admission.calls == []

    admission.failure = "idempotency-conflict"
    conflict = client.post(path, json=request_body(), headers=headers("executor"))
    assert conflict.status_code == 409
    assert conflict.json() == {"code": "idempotency-conflict"}

    admission.failure = None
    admission.invalid_response = True
    invalid_response = client.post(path, json=request_body(), headers=headers("executor"))
    assert invalid_response.status_code == 409
    assert invalid_response.json() == {"code": "admission-response-invalid"}
