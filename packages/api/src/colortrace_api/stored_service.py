from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from colortrace_vertical_slice import SliceContractError

from .auth import Principal

HUMAN_INTAKE_ROLE = "pipeline_td"
SERVICE_INTAKE_ROLE = "incident.admitter"


class AcceptedIncidentRecord(Protocol):
    def to_dict(self) -> dict[str, Any]: ...


class StoredIncidentStore(Protocol):
    def accept_alert(
        self,
        alert: Mapping[str, Any],
        *,
        now: str,
        human_actor: Mapping[str, Any] | None = None,
    ) -> AcceptedIncidentRecord: ...

    def list_incidents(
        self,
        *,
        limit: int,
        cursor: str | None,
        now: str,
    ) -> dict[str, Any]: ...

    def incident_view(self, incident_id: str) -> dict[str, Any]: ...

    def replay(self, incident_id: str) -> dict[str, Any]: ...

    def incident_workspace(self, incident_id: str) -> dict[str, Any]: ...


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("stored service clock must return an aware datetime")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class StoredIncidentService:
    def __init__(
        self,
        store: StoredIncidentStore,
        *,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._store = store
        self._clock = clock

    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]:
        now = self._clock()
        now_value = _utc_timestamp(now)
        incident_id = alert.get("incident_id")
        if (
            not isinstance(incident_id, str)
            or not incident_id
            or incident_id != incident_id.strip()
            or len(incident_id) > 256
        ):
            raise SliceContractError("alert-invalid")
        if (
            principal.expires_at.tzinfo is None
            or principal.expires_at.utcoffset() is None
            or principal.expires_at <= now.astimezone(UTC)
        ):
            raise SliceContractError("principal-credential-expired")
        if incident_id not in principal.incident_ids:
            raise SliceContractError("incident-access-denied")
        human_actor = None
        if principal.principal_kind == "human":
            if HUMAN_INTAKE_ROLE not in principal.roles:
                raise SliceContractError("incident-intake-role-required")
            human_actor = {
                "subject": principal.subject,
                "display_name": principal.display_name,
                "issuer": principal.issuer,
                "audience": principal.audience,
                "principal_kind": principal.principal_kind,
            }
        elif principal.principal_kind == "service":
            if SERVICE_INTAKE_ROLE not in principal.roles:
                raise SliceContractError("incident-intake-role-required")
        else:
            raise SliceContractError("incident-intake-kind-invalid")
        return self._store.accept_alert(
            alert,
            now=now_value,
            human_actor=human_actor,
        ).to_dict()

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        return self._store.list_incidents(
            limit=limit,
            cursor=cursor,
            now=_utc_timestamp(self._clock()),
        )

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return self._store.incident_view(incident_id)

    def replay(self, incident_id: str) -> dict[str, Any]:
        return self._store.replay(incident_id)

    def workspace(self, incident_id: str) -> dict[str, Any]:
        return self._store.incident_workspace(incident_id)
