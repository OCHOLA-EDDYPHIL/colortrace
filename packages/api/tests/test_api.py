from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from colortrace_api import OidcVerificationError, Principal, StoredIncidentService, create_app
from colortrace_recovery import RecoveryError
from colortrace_vertical_slice import SliceContractError, SqliteIncidentStore
from fastapi.testclient import TestClient


class FakeService:
    last_page: tuple[int, str | None] | None = None
    last_principal: Principal | None = None

    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]:
        self.last_principal = principal
        return {"schema": "incident-accepted/v1", "incident_id": alert["incident_id"]}

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        self.last_page = (limit, cursor)
        if cursor == "invalid":
            raise SliceContractError("incident-cursor-invalid")
        return {
            "schema": "incident-list/v1",
            "items": [],
            "next_cursor": None,
        }

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        if incident_id == "missing":
            raise SliceContractError("incident-not-found")
        return {"schema": "incident-view/v1", "incident_id": incident_id}

    def replay(self, incident_id: str) -> dict[str, Any]:
        if incident_id == "pending":
            raise SliceContractError("incident-incomplete")
        return {"schema": "incident-replay/v1", "incident_id": incident_id}

    def workspace(self, incident_id: str) -> dict[str, Any]:
        return {"schema": "incident-workspace-source/v1", "incident_id": incident_id}


class IdentityBearingService(FakeService):
    def workspace(self, incident_id: str) -> dict[str, Any]:
        return {
            "schema": "incident-workspace-source/v1",
            "incident_id": incident_id,
            "credential_sha256": f"sha256:{'f' * 64}",
            "human_events": [
                {
                    "actor": {
                        "subject": "operator@example.test",
                        "display_name": '<img src=x onerror="globalThis.compromised=true">',
                        "issuer": "https://identity.example.test/tenant",
                        "audience": "colortrace-api",
                        "principal_kind": "human",
                    }
                }
            ],
        }


class FailingService(FakeService):
    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        del limit, cursor
        raise RuntimeError("sensitive storage detail")


class FakeVerifier:
    def verify(self, token: str) -> Principal:
        if token == "oidc-failure":
            raise OidcVerificationError
        if token != "valid-token":
            raise ValueError("invalid")
        return Principal(
            "operator@example.test",
            "Pipeline TD",
            frozenset({"pipeline_td"}),
            "https://identity.example.test/tenant",
            "colortrace-api",
            "human",
            frozenset({"incident-new", "incident-api-human"}),
            f"sha256:{'a' * 64}",
            datetime.now(UTC) + timedelta(minutes=5),
        )


class FakeRecovery:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Mapping[str, Any], Principal | None]] = []

    def review(self, incident_id: str) -> dict[str, Any]:
        self.calls.append(("review", incident_id, {}, None))
        return {"schema": "recovery-review/v1", "incident_id": incident_id}

    def close(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.calls.append(("close", incident_id, body, principal))
        return {"schema": "recovery-closure-result/v1", "incident_id": incident_id}


class UnavailableClosureRecovery(FakeRecovery):
    def close(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        del principal, incident_id, body
        raise RecoveryError("recovery-closure-fence-unavailable")


def client() -> TestClient:
    return TestClient(create_app(FakeService(), token_verifier=FakeVerifier()))


def admission_alert() -> dict[str, Any]:
    return {
        "schema": "alert-intake/v1",
        "incident_id": "incident-api-human",
        "alert_id": "alert-api-human",
        "alert_started_at": "2026-08-13T11:59:00.000Z",
        "retrieved_at": "2026-08-13T12:00:00.000Z",
        "measured_clock_skew_seconds": 0,
        "binding": {
            "prometheus_datasource_uid": "prometheus-main",
            "loki_datasource_uid": "loki-main",
            "tempo_datasource_uid": "tempo-main",
            "alert_rule_uid": "alert-main",
        },
        "correlation_keys": {
            "fixture_id": "fixture-api",
            "run_id": "run-api",
            "job_id": "job-api",
            "worker_id": "worker-api",
            "artifact_id": "artifact-api",
            "trace_id": "1" * 32,
            "config_sha256": "2" * 64,
            "transform_id": "transform-api",
        },
        "predecessor_event_sha256": None,
    }


def test_public_incident_reads_and_bounded_list() -> None:
    service = FakeService()
    api_client = TestClient(create_app(service, token_verifier=FakeVerifier()))
    response = api_client.get("/v1/incidents", params={"limit": 10})
    assert response.status_code == 200
    assert response.json() == {
        "schema": "incident-list/v1",
        "items": [],
        "next_cursor": None,
    }
    assert service.last_page == (10, None)
    assert api_client.get("/v1/incidents/example").status_code == 200
    assert api_client.get("/v1/incidents/example/workspace").status_code == 200


def test_public_projection_removes_credentials_and_preserves_audit_attribution() -> None:
    api_client = TestClient(create_app(IdentityBearingService()))

    response = api_client.get("/v1/incidents/example/workspace")

    assert response.status_code == 200
    assert "credential_sha256" not in response.json()
    assert response.json()["human_events"][0]["actor"] == {
        "subject": "operator@example.test",
        "display_name": '<img src=x onerror="globalThis.compromised=true">',
        "issuer": "https://identity.example.test/tenant",
        "audience": "colortrace-api",
        "principal_kind": "human",
    }


def test_recovery_read_and_closure_are_separate_from_unconfigured_task_admission() -> None:
    recovery = FakeRecovery()
    api_client = TestClient(
        create_app(FakeService(), token_verifier=FakeVerifier(), recovery=recovery)
    )
    trigger = {
        "schema": "recovery-verification-admission-request/v1",
        "expected_incident_version": 4,
        "expected_outcome_sha256": f"sha256:{'a' * 64}",
        "idempotency_key": "verify-1",
    }
    closure = {"schema": "recovery-closure-request/v1"}

    assert api_client.get("/v1/incidents/incident-api-human/recovery").status_code == 200
    assert (
        api_client.post(
            "/internal/v1/incidents/incident-api-human/recovery/verifications",
            json=trigger,
        ).status_code
        == 401
    )
    assert (
        api_client.post("/v1/incidents/incident-api-human/recovery/close", json=closure).status_code
        == 401
    )
    headers = {"Authorization": "Bearer valid-token"}
    assert (
        api_client.post(
            "/internal/v1/incidents/incident-api-human/recovery/verifications",
            json=trigger,
            headers=headers,
        ).status_code
        == 503
    )
    assert (
        api_client.post(
            "/v1/incidents/incident-api-human/recovery/close",
            json=closure,
            headers=headers,
        ).status_code
        == 200
    )
    assert [call[0] for call in recovery.calls] == ["review", "close"]


def test_recovery_closure_without_authoritative_fence_is_service_unavailable() -> None:
    api_client = TestClient(
        create_app(
            FakeService(),
            token_verifier=FakeVerifier(),
            recovery=UnavailableClosureRecovery(),
        )
    )

    response = api_client.post(
        "/v1/incidents/incident-api-human/recovery/close",
        json={"schema": "recovery-closure-request/v1"},
        headers={"Authorization": "Bearer valid-token"},
    )

    assert response.status_code == 503
    assert response.json() == {"code": "recovery-closure-fence-unavailable"}


def test_incident_mutation_requires_a_verified_operator() -> None:
    service = FakeService()
    api_client = TestClient(create_app(service, token_verifier=FakeVerifier()))

    unauthenticated = api_client.post("/v1/incidents", json={"incident_id": "incident-new"})
    authenticated = api_client.post(
        "/v1/incidents",
        json={"incident_id": "incident-new"},
        headers={"Authorization": "Bearer valid-token"},
    )

    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {"code": "authentication-required"}
    assert authenticated.status_code == 202
    assert authenticated.json() == {
        "schema": "incident-accepted/v1",
        "incident_id": "incident-new",
    }
    assert service.last_principal is not None
    assert service.last_principal.subject == "operator@example.test"
    assert service.last_principal.principal_kind == "human"


def test_cookie_only_intake_is_rejected_before_service_dispatch() -> None:
    service = FakeService()
    api_client = TestClient(create_app(service, token_verifier=FakeVerifier()))

    response = api_client.post(
        "/v1/incidents",
        json={"incident_id": "incident-new"},
        headers={"Cookie": "session=ambient-credential"},
    )

    assert response.status_code == 401
    assert response.json() == {"code": "authentication-required"}
    assert service.last_principal is None


def test_verified_human_admission_persists_one_bound_audit_event(
    tmp_path: Path,
) -> None:
    store = SqliteIncidentStore(tmp_path / "api-human.sqlite3")
    service = StoredIncidentService(
        store,
        clock=lambda: datetime(2026, 8, 13, 12, 0, tzinfo=UTC),
    )
    api_client = TestClient(create_app(service, token_verifier=FakeVerifier()))
    headers = {"Authorization": "Bearer valid-token"}

    first = api_client.post("/v1/incidents", json=admission_alert(), headers=headers)
    duplicate = api_client.post("/v1/incidents", json=admission_alert(), headers=headers)
    workspace = api_client.get("/v1/incidents/incident-api-human/workspace")

    assert first.status_code == 202
    assert duplicate.status_code == 202
    assert duplicate.json()["duplicate"] is True
    assert workspace.status_code == 200
    events = workspace.json()["human_events"]
    assert len(events) == 1
    assert events[0]["incident_id"] == "incident-api-human"
    assert events[0]["actor"] == {
        "subject": "operator@example.test",
        "display_name": "Pipeline TD",
        "issuer": "https://identity.example.test/tenant",
        "audience": "colortrace-api",
        "principal_kind": "human",
    }


def test_runnable_boundary_sets_strict_security_and_cache_headers() -> None:
    response = client().get("/v1/incidents")

    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    assert response.headers["permissions-policy"] == (
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    )
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_uncaught_error_is_generic_and_retains_security_headers() -> None:
    response = TestClient(
        create_app(FailingService()),
        raise_server_exceptions=False,
    ).get("/v1/incidents")

    assert response.status_code == 500
    assert response.json() == {"code": "internal-server-error"}
    assert "sensitive storage detail" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"] == (
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    assert response.headers["x-content-type-options"] == "nosniff"


def test_contract_errors_are_typed_without_internal_details() -> None:
    missing = client().get("/v1/incidents/missing")
    assert missing.status_code == 404
    assert missing.json() == {"code": "incident-not-found"}
    pending = client().get("/v1/incidents/pending/replay")
    assert pending.status_code == 409
    assert pending.json() == {"code": "incident-incomplete"}
    cursor = client().get("/v1/incidents", params={"cursor": "invalid"})
    assert cursor.status_code == 400
    assert cursor.json() == {"code": "incident-cursor-invalid"}


def test_session_requires_a_verified_bearer_token() -> None:
    unauthenticated = client().get("/v1/session")
    assert unauthenticated.status_code == 401
    assert unauthenticated.json() == {"code": "authentication-required"}
    assert client().get("/v1/session", headers={"Authorization": "Bearer wrong"}).status_code == 401
    oidc_failure = client().get(
        "/v1/session",
        headers={"Authorization": "Bearer oidc-failure"},
    )
    assert oidc_failure.status_code == 401
    assert oidc_failure.json() == {"code": "authentication-invalid"}
    response = client().get("/v1/session", headers={"Authorization": "Bearer valid-token"})
    assert response.status_code == 200
    assert response.json() == {
        "schema": "operator-session/v1",
        "subject": "operator@example.test",
        "display_name": "Pipeline TD",
        "roles": ["pipeline_td"],
        "issuer": "https://identity.example.test/tenant",
        "audience": "colortrace-api",
        "principal_kind": "human",
    }


def test_list_limit_is_rejected_outside_the_contract() -> None:
    below = client().get("/v1/incidents", params={"limit": 0})
    above = client().get("/v1/incidents", params={"limit": 51})
    long_cursor = client().get("/v1/incidents", params={"cursor": "x" * 513})
    for response in (below, above, long_cursor):
        assert response.status_code == 422
        assert response.json() == {"code": "request-invalid"}
