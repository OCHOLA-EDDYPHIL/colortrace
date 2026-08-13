from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from colortrace_response_plans import OIDCTrustBoundary, VerifiedPrincipal
from colortrace_simulator import DispatchIdentity
from colortrace_simulator.authority import (
    ExecutorAuthorization,
    SimulatorAuthorityError,
    SimulatorExecutorBoundary,
)

from .auth import Principal


def _utc_now() -> datetime:
    return datetime.now(UTC)


class SimulatorAdmissionService(Protocol):
    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> dict[str, Any]: ...


class SimulatorActionCoordinator:
    """Service-only HTTP adapter for an opaque consumed-dispatch identity."""

    def __init__(
        self,
        *,
        service: SimulatorAdmissionService,
        executor_boundary: SimulatorExecutorBoundary,
        identity_boundary: OIDCTrustBoundary,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._service = service
        self._executor_boundary = executor_boundary
        self._identity_boundary = identity_boundary
        self._clock = clock

    def _principal(self, principal: Principal) -> VerifiedPrincipal:
        return self._identity_boundary.bind_verified_claims(
            issuer=principal.issuer,
            subject=principal.subject,
            audience=principal.audience,
            kind=principal.principal_kind,
            roles=principal.roles,
            incident_ids=principal.incident_ids,
            credential_sha256=principal.credential_sha256,
            expires_at=principal.expires_at,
            credential_verified=True,
            now=self._clock(),
        )

    def admit(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        fields = {"schema", "task_key", "operation_id", "payload_sha256"}
        if set(body) != fields or body.get("schema") != "simulator-action-admission-request/v1":
            raise SimulatorAuthorityError("admission-request-invalid")
        verified = self._principal(principal)
        executor = self._executor_boundary.bind_verified_service(
            incident_id=incident_id,
            actor=verified.actor(),
            roles=tuple(verified.roles),
            incident_ids=tuple(verified.incident_ids),
            identity_verified=True,
        )
        values = (body.get("task_key"), body.get("operation_id"), body.get("payload_sha256"))
        if any(not isinstance(value, str) for value in values):
            raise SimulatorAuthorityError("admission-request-invalid")
        return self._service.admit(
            DispatchIdentity(
                task_key=cast(str, values[0]),
                operation_id=cast(str, values[1]),
                payload_sha256=cast(str, values[2]),
            ),
            executor=executor,
        )


class SimulatorActionApi(Protocol):
    def admit(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]: ...


__all__ = ["SimulatorActionApi", "SimulatorActionCoordinator"]
