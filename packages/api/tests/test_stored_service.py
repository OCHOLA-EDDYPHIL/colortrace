from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, cast

import pytest
from colortrace_api import Principal, PrincipalKind, StoredIncidentService, create_app
from colortrace_vertical_slice import SliceContractError
from fastapi.testclient import TestClient

PENDING_ID = "incident-pending"
READY_ID = "incident-ready"

PENDING_SUMMARY: dict[str, Any] = {
    "schema": "incident-summary/v1",
    "incident_id": PENDING_ID,
    "alert_id": "alert-pending",
    "status": "running",
    "version": 2,
    "trace_id": "1" * 32,
    "packet_id": None,
    "created_at": "2026-08-13T06:30:00.000Z",
    "updated_at": "2026-08-13T06:31:00.000Z",
    "delayed": True,
    "missing": ["validator-result", "response-packet"],
}

READY_SUMMARY: dict[str, Any] = {
    "schema": "incident-summary/v1",
    "incident_id": READY_ID,
    "alert_id": "alert-ready",
    "status": "resolved",
    "version": 3,
    "trace_id": "2" * 32,
    "packet_id": f"response-packet:{'a' * 64}",
    "created_at": "2026-08-13T06:20:00.000Z",
    "updated_at": "2026-08-13T06:29:00.000Z",
    "delayed": False,
    "missing": [],
}


def incident_view(summary: Mapping[str, Any]) -> dict[str, Any]:
    pending = summary["packet_id"] is None
    return {
        "schema": "incident-view/v1",
        "incident": {
            "schema": "incident-record/v1",
            "incident_id": summary["incident_id"],
            "alert_id": summary["alert_id"],
            "status": summary["status"],
            "version": summary["version"],
            "alert_sha256": f"sha256:{'b' * 64}",
            "trace_id": summary["trace_id"],
            "packet_id": summary["packet_id"],
            "created_at": summary["created_at"],
            "updated_at": summary["updated_at"],
        },
        "task": {
            "schema": "incident-task/v1",
            "task_id": f"task:{'c' * 64}",
            "incident_id": summary["incident_id"],
            "expected_incident_version": 1,
            "alert_sha256": f"sha256:{'b' * 64}",
            "trace_id": summary["trace_id"],
            "status": "running" if pending else "complete",
            "packet_id": summary["packet_id"],
            "created_at": summary["created_at"],
            "updated_at": summary["updated_at"],
        },
        "packet": None if pending else {"packet_id": summary["packet_id"]},
    }


PENDING_WORKSPACE: dict[str, Any] = {
    "schema": "incident-workspace-source/v1",
    "view": incident_view(PENDING_SUMMARY),
    "replay_state": "pending",
    "human_events": [],
    "replay": None,
}

READY_REPLAY: dict[str, Any] = {
    "schema": "incident-replay/v1",
    "incident": incident_view(READY_SUMMARY)["incident"],
    "task": incident_view(READY_SUMMARY)["task"],
    "packet": incident_view(READY_SUMMARY)["packet"],
}

READY_WORKSPACE: dict[str, Any] = {
    "schema": "incident-workspace-source/v1",
    "view": incident_view(READY_SUMMARY),
    "replay_state": "ready",
    "human_events": [],
    "replay": READY_REPLAY,
}


@dataclass(frozen=True, slots=True)
class Accepted:
    value: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return dict(self.value)


class RecordingStore:
    def __init__(self) -> None:
        self.list_calls: list[tuple[int, str | None, str]] = []
        self.accept_times: list[str] = []
        self.accept_actors: list[Mapping[str, Any] | None] = []
        self.replay_calls: list[str] = []

    def accept_alert(
        self,
        alert: Mapping[str, Any],
        *,
        now: str,
        human_actor: Mapping[str, Any] | None = None,
    ) -> Accepted:
        self.accept_times.append(now)
        self.accept_actors.append(human_actor)
        return Accepted({"schema": "incident-accepted/v1", "incident_id": alert["incident_id"]})

    def list_incidents(
        self,
        *,
        limit: int,
        cursor: str | None,
        now: str,
    ) -> dict[str, Any]:
        self.list_calls.append((limit, cursor, now))
        return {
            "schema": "incident-list/v1",
            "items": [PENDING_SUMMARY, READY_SUMMARY],
            "next_cursor": "authoritative-next-cursor",
        }

    def incident_view(self, incident_id: str) -> dict[str, Any]:
        return PENDING_WORKSPACE["view"] if incident_id == PENDING_ID else READY_WORKSPACE["view"]

    def replay(self, incident_id: str) -> dict[str, Any]:
        self.replay_calls.append(incident_id)
        if incident_id == PENDING_ID:
            raise SliceContractError("incident-incomplete")
        return READY_REPLAY

    def incident_workspace(self, incident_id: str) -> dict[str, Any]:
        if incident_id == PENDING_ID:
            return PENDING_WORKSPACE
        if incident_id == READY_ID:
            return READY_WORKSPACE
        raise SliceContractError("incident-not-found")


def clock() -> datetime:
    return datetime(
        2026,
        8,
        13,
        12,
        1,
        2,
        345_678,
        tzinfo=timezone(timedelta(hours=5, minutes=30)),
    )


def test_list_preserves_authoritative_delayed_and_missing_state() -> None:
    store = RecordingStore()
    api_client = TestClient(create_app(StoredIncidentService(store, clock=clock)))

    response = api_client.get(
        "/v1/incidents",
        params={"limit": 2, "cursor": "current-page"},
    )

    assert response.status_code == 200
    assert response.json() == {
        "schema": "incident-list/v1",
        "items": [PENDING_SUMMARY, READY_SUMMARY],
        "next_cursor": "authoritative-next-cursor",
    }
    assert store.list_calls == [(2, "current-page", "2026-08-13T06:31:02.345Z")]


def test_pending_workspace_never_fabricates_or_loads_replay() -> None:
    store = RecordingStore()
    api_client = TestClient(create_app(StoredIncidentService(store, clock=clock)))

    workspace = api_client.get(f"/v1/incidents/{PENDING_ID}/workspace")

    assert workspace.status_code == 200
    assert workspace.json() == PENDING_WORKSPACE
    assert workspace.json()["replay_state"] == "pending"
    assert workspace.json()["replay"] is None
    assert store.replay_calls == []

    replay = api_client.get(f"/v1/incidents/{PENDING_ID}/replay")
    assert replay.status_code == 409
    assert replay.json() == {"code": "incident-incomplete"}
    assert store.replay_calls == [PENDING_ID]


def test_ready_workspace_returns_the_atomic_store_shape_without_extra_reads() -> None:
    store = RecordingStore()
    api_client = TestClient(create_app(StoredIncidentService(store, clock=clock)))

    response = api_client.get(f"/v1/incidents/{READY_ID}/workspace")

    assert response.status_code == 200
    assert response.json() == READY_WORKSPACE
    assert response.json()["replay"] == READY_REPLAY
    assert store.replay_calls == []


def test_accept_alert_uses_the_same_normalized_utc_clock() -> None:
    store = RecordingStore()
    service = StoredIncidentService(store, clock=clock)

    principal = Principal(
        "operator@example.test",
        "Pipeline TD",
        frozenset({"pipeline_td"}),
        "https://identity.example.test/tenant",
        "colortrace-api",
        "human",
        frozenset({"incident-new"}),
        f"sha256:{'a' * 64}",
        datetime.now(UTC) + timedelta(minutes=5),
    )
    assert service.accept_alert({"incident_id": "incident-new"}, principal) == {
        "schema": "incident-accepted/v1",
        "incident_id": "incident-new",
    }
    assert store.accept_times == ["2026-08-13T06:31:02.345Z"]
    assert store.accept_actors == [
        {
            "subject": "operator@example.test",
            "display_name": "Pipeline TD",
            "issuer": "https://identity.example.test/tenant",
            "audience": "colortrace-api",
            "principal_kind": "human",
        }
    ]


def test_service_admission_does_not_fabricate_a_human_actor() -> None:
    store = RecordingStore()
    service = StoredIncidentService(store, clock=clock)
    principal = Principal(
        "automation@example.test",
        "Alert bridge",
        frozenset({"incident.admitter"}),
        "https://identity.example.test/tenant",
        "colortrace-api",
        "service",
        frozenset({"incident-service"}),
        f"sha256:{'a' * 64}",
        datetime.now(UTC) + timedelta(minutes=5),
    )

    service.accept_alert({"incident_id": "incident-service"}, principal)

    assert store.accept_actors == [None]


@pytest.mark.parametrize(
    ("principal_kind", "roles", "incident_ids", "expires_at", "code"),
    [
        (
            "human",
            frozenset({"incident.admitter"}),
            frozenset({"incident-new"}),
            None,
            "incident-intake-role-required",
        ),
        (
            "service",
            frozenset({"pipeline_td"}),
            frozenset({"incident-new"}),
            None,
            "incident-intake-role-required",
        ),
        (
            "human",
            frozenset({"pipeline_td"}),
            frozenset({"incident-other"}),
            None,
            "incident-access-denied",
        ),
        (
            "service",
            frozenset({"incident.admitter"}),
            frozenset({"incident-new"}),
            datetime(2026, 8, 13, 6, 31, 2, tzinfo=UTC),
            "principal-credential-expired",
        ),
        (
            cast(PrincipalKind, "robot"),
            frozenset({"pipeline_td"}),
            frozenset({"incident-new"}),
            None,
            "incident-intake-kind-invalid",
        ),
    ],
)
def test_intake_authority_fails_before_store_mutation(
    principal_kind: PrincipalKind,
    roles: frozenset[str],
    incident_ids: frozenset[str],
    expires_at: datetime | None,
    code: str,
) -> None:
    store = RecordingStore()
    service = StoredIncidentService(store, clock=clock)
    principal = Principal(
        "principal@example.test",
        "Intake principal",
        roles,
        "https://identity.example.test/tenant",
        "colortrace-api",
        principal_kind,
        incident_ids,
        f"sha256:{'a' * 64}",
        expires_at or datetime(2026, 8, 13, 7, 0, tzinfo=UTC),
    )

    with pytest.raises(SliceContractError, match=code):
        service.accept_alert({"incident_id": "incident-new"}, principal)

    assert store.accept_times == []
    assert store.accept_actors == []


def test_naive_clock_is_rejected_instead_of_assuming_a_timezone() -> None:
    store = RecordingStore()
    service = StoredIncidentService(store, clock=lambda: datetime(2026, 8, 13, 12, 0))

    try:
        service.list_incidents(limit=1, cursor=None)
    except ValueError as error:
        assert str(error) == "stored service clock must return an aware datetime"
    else:
        raise AssertionError("naive clock was accepted")
