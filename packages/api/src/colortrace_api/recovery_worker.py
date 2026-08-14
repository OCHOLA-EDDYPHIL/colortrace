from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from colortrace_recovery import RecoveryError, RecoveryIdentityBoundary, RecoveryPrincipal
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .auth import Principal, TokenVerifier
from .recovery_tasks import (
    RecoveryVerificationTaskClaim,
    RecoveryVerificationTaskStore,
    SQLiteRecoveryVerificationTaskStore,
    build_recovery_verification_result,
    build_unresolved_recovery_verification_result,
    validate_recovery_verification_task,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class CanonicalIncidentReader(Protocol):
    def replay(self, incident_id: str) -> dict[str, Any]: ...


class RecoveryWorkflowRunner(Protocol):
    def verify(
        self,
        principal: RecoveryPrincipal,
        incident_id: str,
        *,
        expected_incident_version: int,
        expected_outcome_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]: ...


class RecoveryVerificationWorker:
    def __init__(
        self,
        *,
        incident_reader: CanonicalIncidentReader,
        task_store: RecoveryVerificationTaskStore,
        workflow_runner: RecoveryWorkflowRunner,
        identity_boundary: RecoveryIdentityBoundary,
        claim_owner: str = "recovery-verification-worker",
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._incident_reader = incident_reader
        self._task_store = task_store
        self._workflow_runner = workflow_runner
        self._identity_boundary = identity_boundary
        self._claim_owner = claim_owner
        self._clock = clock

    def _principal(self, principal: Principal) -> RecoveryPrincipal:
        return self._identity_boundary.bind_verified_claims(
            issuer=principal.issuer,
            subject=principal.subject,
            display_name=principal.display_name,
            audience=principal.audience,
            kind=principal.principal_kind,
            roles=principal.roles,
            incident_ids=principal.incident_ids,
            credential_sha256=principal.credential_sha256,
            expires_at=principal.expires_at,
            credential_verified=True,
            now=self._clock(),
        )

    def _assert_current(self, incident_id: str, expected_version: int) -> None:
        replay = self._incident_reader.replay(incident_id)
        incident = replay.get("incident")
        if (
            replay.get("schema") != "incident-replay/v1"
            or not isinstance(incident, Mapping)
            or incident.get("incident_id") != incident_id
            or incident.get("status") not in {"resolved", "unresolved"}
        ):
            raise RecoveryError("canonical-incident-invalid")
        current = incident.get("version")
        if not isinstance(current, int) or isinstance(current, bool) or current < 1:
            raise RecoveryError("canonical-incident-invalid")
        if current != expected_version:
            raise RecoveryError("verification-task-expected-version-conflict")

    def execute(
        self,
        principal: Principal,
        task_key: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        task = validate_recovery_verification_task(body)
        if task_key != task["task_key"]:
            raise RecoveryError("verification-task-key-conflict")
        verified = self._principal(principal)
        self._identity_boundary.assert_verifier(
            verified,
            incident_id=task["incident_id"],
            now=self._clock(),
        )
        self._assert_current(task["incident_id"], task["expected_incident_version"])
        claim_or_result = self._task_store.claim(task, owner=self._claim_owner)
        if isinstance(claim_or_result, dict):
            return claim_or_result
        if not isinstance(claim_or_result, RecoveryVerificationTaskClaim):
            raise RecoveryError("verification-task-claim-invalid")
        try:
            packet = self._workflow_runner.verify(
                verified,
                task["incident_id"],
                expected_incident_version=task["expected_incident_version"],
                expected_outcome_sha256=task["expected_outcome_sha256"],
                idempotency_key=task["idempotency_key"],
            )
            result = build_recovery_verification_result(task, packet)
        except Exception as error:
            code = getattr(error, "code", None)
            reason = (
                code
                if isinstance(code, str) and re.fullmatch(r"[a-z][a-z0-9-]{1,63}", code) is not None
                else "recovery-verification-worker-failed"
            )
            result = build_unresolved_recovery_verification_result(
                task,
                reason_code=reason,
            )
        return self._task_store.complete(claim_or_result, result)


def _status_for_recovery_error(code: str) -> int:
    if code in {"authentication-required", "principal-credential-expired"}:
        return 401
    if code in {
        "incident-access-denied",
        "model-authority-forbidden",
        "principal-audience-untrusted",
        "principal-issuer-untrusted",
        "principal-trust-boundary-mismatch",
        "verifier-role-required",
        "verifier-service-required",
    }:
        return 403
    if code == "verification-task-not-found":
        return 404
    if code.endswith("-invalid"):
        return 400
    return 409


def create_recovery_worker_app(
    worker: RecoveryVerificationWorker,
    *,
    token_verifier: TokenVerifier,
) -> FastAPI:
    app = FastAPI(
        title="ColorTrace Recovery Worker",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.exception_handler(RecoveryError)
    async def handle_recovery_error(_request: Any, error: RecoveryError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_recovery_error(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(HTTPException)
    async def handle_http_error(_request: Any, error: HTTPException) -> JSONResponse:
        detail = error.detail
        if isinstance(detail, dict) and isinstance(detail.get("code"), str):
            return JSONResponse(status_code=error.status_code, content={"code": detail["code"]})
        return JSONResponse(status_code=error.status_code, content={"code": "request-rejected"})

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation(
        _request: Any,
        _error: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"code": "request-invalid"})

    def current_principal(authorization: str | None = Header(default=None)) -> Principal:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail={"code": "authentication-required"},
            )
        token = authorization.removeprefix("Bearer ")
        if not token:
            raise HTTPException(status_code=401, detail={"code": "authentication-invalid"})
        try:
            return token_verifier.verify(token)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=401,
                detail={"code": "authentication-invalid"},
            ) from None

    principal_dependency = Depends(current_principal)

    @app.post("/private/v1/recovery-verification-tasks/{task_key}")
    def execute_recovery_verification_task(
        task_key: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return worker.execute(principal, task_key, body)

    return app


@dataclass(frozen=True, slots=True)
class LocalRecoveryVerificationBoundary:
    task_store: SQLiteRecoveryVerificationTaskStore
    worker: RecoveryVerificationWorker


def create_local_recovery_verification_boundary(
    *,
    task_database_path: str | Path,
    incident_reader: CanonicalIncidentReader,
    workflow_runner: RecoveryWorkflowRunner,
    worker_identity_boundary: RecoveryIdentityBoundary,
    claim_owner: str = "recovery-verification-worker",
    clock: Callable[[], datetime] = _utc_now,
) -> LocalRecoveryVerificationBoundary:
    store = SQLiteRecoveryVerificationTaskStore(task_database_path, clock=clock)
    return LocalRecoveryVerificationBoundary(
        task_store=store,
        worker=RecoveryVerificationWorker(
            incident_reader=incident_reader,
            task_store=store,
            workflow_runner=workflow_runner,
            identity_boundary=worker_identity_boundary,
            claim_owner=claim_owner,
            clock=clock,
        ),
    )


__all__ = [
    "CanonicalIncidentReader",
    "LocalRecoveryVerificationBoundary",
    "RecoveryVerificationWorker",
    "RecoveryWorkflowRunner",
    "create_local_recovery_verification_boundary",
    "create_recovery_worker_app",
]
