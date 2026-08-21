from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from colortrace_recovery import RecoveryError
from colortrace_response_plans import ResponsePlanError
from colortrace_simulator import BoundSimulatorAction, DispatchIdentity, StoredDispatchSource
from colortrace_simulator.authority import (
    ExecutorAuthorization,
    SimulatorAuthorityBoundary,
    SimulatorAuthorityError,
    SimulatorExecutorBoundary,
    require_identity,
)
from colortrace_simulator.repository import SimulatorRepositoryError
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.types import Lifespan

from .cloud_tasks import (
    CloudTaskPublishError,
    validate_cloud_tasks_delivery_config,
    verify_cloud_tasks_delivery,
)
from .google_identity import (
    GoogleServiceIdentity,
    GoogleServiceIdentityVerifier,
    GoogleServiceTokenError,
    ServerOwnedServiceBinding,
)
from .recovery_tasks import validate_recovery_verification_task
from .recovery_worker import RecoveryVerificationWorker

_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SIMULATOR_TASK_FIELDS = frozenset(
    {
        "schema",
        "task_key",
        "operation_id",
        "payload_sha256",
        "expected_incident_version",
    }
)


class HostedTaskServiceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class SimulatorTaskService(Protocol):
    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> Mapping[str, Any]: ...

    def execute(
        self,
        identity: DispatchIdentity,
        *,
        owner: str,
        observe_terminal: bool = True,
    ) -> Mapping[str, Any]: ...


class SimulatorTaskAuthorityResolver(Protocol):
    def resolve(self, identity: DispatchIdentity) -> BoundSimulatorAction: ...


class CanonicalSimulatorTaskResolver:
    def __init__(
        self,
        *,
        dispatch_source: StoredDispatchSource,
        authority_boundary: SimulatorAuthorityBoundary,
    ) -> None:
        self._dispatch_source = dispatch_source
        self._authority_boundary = authority_boundary

    def resolve(self, identity: DispatchIdentity) -> BoundSimulatorAction:
        proof = self._dispatch_source.load_current_consumed(identity)
        return self._authority_boundary.bind(identity, proof).action


@dataclass(frozen=True, slots=True)
class HostedPrivateServiceApps:
    recovery_worker: FastAPI
    simulator: FastAPI


def _authorization_token(value: str | None) -> str:
    if value is None or not value.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"code": "authentication-required"})
    token = value.removeprefix("Bearer ")
    if not token or len(token) > 16_384 or any(character.isspace() for character in token):
        raise HTTPException(status_code=401, detail={"code": "authentication-invalid"})
    return token


def _identity(
    authorization: str | None,
    verifier: GoogleServiceIdentityVerifier,
) -> GoogleServiceIdentity:
    token = _authorization_token(authorization)
    try:
        return verifier.verify(token)
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail={"code": "authentication-invalid"}) from None


def _domain_status(code: str) -> int:
    if code.endswith("-not-found"):
        return 404
    if code.endswith("-invalid") or code in {
        "admission-request-invalid",
        "dispatch-operation-id-invalid",
        "dispatch-payload-invalid",
        "dispatch-task-key-invalid",
        "schema-validation",
    }:
        return 400
    if code in {
        "executor-authority-boundary-mismatch",
        "executor-incident-denied",
        "executor-role-required",
        "executor-service-required",
        "incident-access-denied",
        "principal-audience-untrusted",
        "principal-issuer-untrusted",
        "principal-trust-boundary-mismatch",
        "verifier-role-required",
        "verifier-service-required",
    }:
        return 403
    return 409


def _create_private_app(
    title: str,
    *,
    lifespan: Lifespan[FastAPI] | None,
) -> FastAPI:
    app = FastAPI(
        title=title,
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def harden_response(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        try:
            response = await call_next(request)
        except Exception:
            response = JSONResponse(status_code=500, content={"code": "internal-server-error"})
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.exception_handler(GoogleServiceTokenError)
    async def handle_service_identity(
        _request: Any,
        _error: GoogleServiceTokenError,
    ) -> JSONResponse:
        return JSONResponse(status_code=401, content={"code": "authentication-invalid"})

    @app.exception_handler(CloudTaskPublishError)
    async def handle_delivery_metadata(
        _request: Any,
        _error: CloudTaskPublishError,
    ) -> JSONResponse:
        return JSONResponse(status_code=403, content={"code": "cloud-task-delivery-invalid"})

    @app.exception_handler(HostedTaskServiceError)
    async def handle_hosted_task_error(
        _request: Any,
        error: HostedTaskServiceError,
    ) -> JSONResponse:
        status = 500 if error.code.endswith("-response-invalid") else _domain_status(error.code)
        return JSONResponse(status_code=status, content={"code": error.code})

    @app.exception_handler(RecoveryError)
    async def handle_recovery_error(_request: Any, error: RecoveryError) -> JSONResponse:
        return JSONResponse(
            status_code=_domain_status(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(ResponsePlanError)
    async def handle_response_plan_error(_request: Any, error: ResponsePlanError) -> JSONResponse:
        return JSONResponse(
            status_code=_domain_status(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(SimulatorAuthorityError)
    async def handle_simulator_authority(
        _request: Any,
        error: SimulatorAuthorityError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=_domain_status(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(SimulatorRepositoryError)
    async def handle_simulator_repository(
        _request: Any,
        error: SimulatorRepositoryError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=_domain_status(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(HTTPException)
    async def handle_http_error(_request: Any, error: HTTPException) -> JSONResponse:
        detail = error.detail
        if isinstance(detail, Mapping) and isinstance(detail.get("code"), str):
            return JSONResponse(status_code=error.status_code, content={"code": detail["code"]})
        return JSONResponse(status_code=error.status_code, content={"code": "request-rejected"})

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation(
        _request: Any,
        _error: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"code": "request-invalid"})

    return app


def create_hosted_recovery_worker_app(
    worker: RecoveryVerificationWorker,
    *,
    identity_verifier: GoogleServiceIdentityVerifier,
    service_binding: ServerOwnedServiceBinding,
    queue_path: str,
    max_delivery_attempts: int,
    lifespan: Lifespan[FastAPI] | None = None,
) -> FastAPI:
    if service_binding.role != "recovery.verifier":
        raise ValueError("recovery worker binding role is invalid")
    validate_cloud_tasks_delivery_config(
        queue_path=queue_path,
        max_delivery_attempts=max_delivery_attempts,
    )
    app = _create_private_app("ColorTrace Hosted Recovery Worker", lifespan=lifespan)

    @app.post("/private/v1/recovery-verification-tasks/{task_key}")
    def execute_recovery_verification_task(
        task_key: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None, alias="Authorization"),
        queue_name: str | None = Header(default=None, alias="X-CloudTasks-QueueName"),
        task_name: str | None = Header(default=None, alias="X-CloudTasks-TaskName"),
        retry_count: str | None = Header(default=None, alias="X-CloudTasks-TaskRetryCount"),
        execution_count: str | None = Header(
            default=None,
            alias="X-CloudTasks-TaskExecutionCount",
        ),
    ) -> dict[str, Any]:
        caller = _identity(authorization, identity_verifier)
        task = validate_recovery_verification_task(body)
        if task_key != task["task_key"]:
            raise RecoveryError("verification-task-key-conflict")
        verify_cloud_tasks_delivery(
            queue_path=queue_path,
            task_key=task_key,
            max_delivery_attempts=max_delivery_attempts,
            queue_name_header=queue_name,
            task_name_header=task_name,
            retry_count_header=retry_count,
            execution_count_header=execution_count,
        )
        principal = service_binding.bind(
            caller,
            incident_id=cast(str, task["incident_id"]),
        )
        return worker.execute(principal, task_key, task)

    return app


def _simulator_task(body: Mapping[str, Any], *, task_key: str) -> tuple[DispatchIdentity, int]:
    if set(body) != _SIMULATOR_TASK_FIELDS or body.get("schema") != "simulator-action-task/v1":
        raise HostedTaskServiceError("simulator-task-invalid")
    expected_version = body.get("expected_incident_version")
    if (
        not isinstance(expected_version, int)
        or isinstance(expected_version, bool)
        or expected_version < 1
    ):
        raise HostedTaskServiceError("simulator-task-expected-version-invalid")
    task_key_value = body.get("task_key")
    operation_id = body.get("operation_id")
    payload_sha256 = body.get("payload_sha256")
    if not all(isinstance(value, str) for value in (task_key_value, operation_id, payload_sha256)):
        raise HostedTaskServiceError("simulator-task-invalid")
    identity = DispatchIdentity(
        task_key=cast(str, task_key_value),
        operation_id=cast(str, operation_id),
        payload_sha256=cast(str, payload_sha256),
    )
    require_identity(identity)
    if identity.task_key != task_key:
        raise HostedTaskServiceError("simulator-task-key-conflict")
    return identity, expected_version


def _assert_simulator_response(
    value: Mapping[str, Any],
    *,
    identity: DispatchIdentity,
    incident_id: str,
    incident_version: int,
    admission: bool,
) -> dict[str, Any]:
    expected = {
        "task_key": identity.task_key,
        "operation_id": identity.operation_id,
        "payload_sha256": identity.payload_sha256,
        "incident_id": incident_id,
        "incident_version": incident_version,
    }
    if any(value.get(key) != child for key, child in expected.items()):
        suffix = "admission" if admission else "outcome"
        raise HostedTaskServiceError(f"simulator-{suffix}-response-invalid")
    return dict(value)


def create_hosted_simulator_app(
    service: SimulatorTaskService,
    *,
    authority_resolver: SimulatorTaskAuthorityResolver,
    executor_boundary: SimulatorExecutorBoundary,
    identity_verifier: GoogleServiceIdentityVerifier,
    service_binding: ServerOwnedServiceBinding,
    queue_path: str,
    max_delivery_attempts: int,
    claim_owner: str = "hosted-simulator-worker",
    lifespan: Lifespan[FastAPI] | None = None,
) -> FastAPI:
    if service_binding.role != "simulator.executor":
        raise ValueError("simulator binding role is invalid")
    validate_cloud_tasks_delivery_config(
        queue_path=queue_path,
        max_delivery_attempts=max_delivery_attempts,
    )
    if _OWNER.fullmatch(claim_owner) is None:
        raise ValueError("claim_owner is invalid")
    app = _create_private_app("ColorTrace Hosted Simulator", lifespan=lifespan)

    @app.post("/private/v1/simulator-action-tasks/{task_key}")
    def execute_simulator_action_task(
        task_key: str,
        body: dict[str, Any],
        authorization: str | None = Header(default=None, alias="Authorization"),
        queue_name: str | None = Header(default=None, alias="X-CloudTasks-QueueName"),
        task_name: str | None = Header(default=None, alias="X-CloudTasks-TaskName"),
        retry_count: str | None = Header(default=None, alias="X-CloudTasks-TaskRetryCount"),
        execution_count: str | None = Header(
            default=None,
            alias="X-CloudTasks-TaskExecutionCount",
        ),
    ) -> dict[str, Any]:
        caller = _identity(authorization, identity_verifier)
        dispatch_identity, expected_version = _simulator_task(body, task_key=task_key)
        verify_cloud_tasks_delivery(
            queue_path=queue_path,
            task_key=task_key,
            max_delivery_attempts=max_delivery_attempts,
            queue_name_header=queue_name,
            task_name_header=task_name,
            retry_count_header=retry_count,
            execution_count_header=execution_count,
        )
        action = authority_resolver.resolve(dispatch_identity)
        if action.identity != dispatch_identity:
            raise HostedTaskServiceError("simulator-task-authority-response-invalid")
        if action.incident_version != expected_version:
            raise HostedTaskServiceError("simulator-task-expected-version-conflict")
        principal = service_binding.bind(caller, incident_id=action.incident_id)
        executor = executor_boundary.bind_verified_service(
            incident_id=action.incident_id,
            actor={
                "issuer": principal.issuer,
                "subject": principal.subject,
                "audience": principal.audience,
                "kind": principal.principal_kind,
            },
            roles=tuple(principal.roles),
            incident_ids=tuple(principal.incident_ids),
            identity_verified=True,
        )
        admission = service.admit(dispatch_identity, executor=executor)
        _assert_simulator_response(
            admission,
            identity=dispatch_identity,
            incident_id=action.incident_id,
            incident_version=action.incident_version,
            admission=True,
        )
        outcome = service.execute(
            dispatch_identity,
            owner=claim_owner,
            observe_terminal=True,
        )
        return _assert_simulator_response(
            outcome,
            identity=dispatch_identity,
            incident_id=action.incident_id,
            incident_version=action.incident_version,
            admission=False,
        )

    return app


def create_hosted_private_service_apps(
    *,
    recovery_worker: RecoveryVerificationWorker,
    recovery_identity_verifier: GoogleServiceIdentityVerifier,
    recovery_service_binding: ServerOwnedServiceBinding,
    recovery_queue_path: str,
    recovery_max_delivery_attempts: int,
    simulator_service: SimulatorTaskService,
    simulator_authority_resolver: SimulatorTaskAuthorityResolver,
    simulator_executor_boundary: SimulatorExecutorBoundary,
    simulator_identity_verifier: GoogleServiceIdentityVerifier,
    simulator_service_binding: ServerOwnedServiceBinding,
    simulator_queue_path: str,
    simulator_max_delivery_attempts: int,
    simulator_claim_owner: str = "hosted-simulator-worker",
    recovery_lifespan: Lifespan[FastAPI] | None = None,
    simulator_lifespan: Lifespan[FastAPI] | None = None,
) -> HostedPrivateServiceApps:
    if recovery_service_binding.caller_email == simulator_service_binding.caller_email:
        raise ValueError("hosted service caller identities must be separate")
    if recovery_service_binding.audience == simulator_service_binding.audience:
        raise ValueError("hosted service audiences must be separate")
    if recovery_queue_path == simulator_queue_path:
        raise ValueError("hosted service queues must be separate")
    return HostedPrivateServiceApps(
        recovery_worker=create_hosted_recovery_worker_app(
            recovery_worker,
            identity_verifier=recovery_identity_verifier,
            service_binding=recovery_service_binding,
            queue_path=recovery_queue_path,
            max_delivery_attempts=recovery_max_delivery_attempts,
            lifespan=recovery_lifespan,
        ),
        simulator=create_hosted_simulator_app(
            simulator_service,
            authority_resolver=simulator_authority_resolver,
            executor_boundary=simulator_executor_boundary,
            identity_verifier=simulator_identity_verifier,
            service_binding=simulator_service_binding,
            queue_path=simulator_queue_path,
            max_delivery_attempts=simulator_max_delivery_attempts,
            claim_owner=simulator_claim_owner,
            lifespan=simulator_lifespan,
        ),
    )


__all__ = [
    "CanonicalSimulatorTaskResolver",
    "HostedPrivateServiceApps",
    "HostedTaskServiceError",
    "SimulatorTaskAuthorityResolver",
    "SimulatorTaskService",
    "create_hosted_recovery_worker_app",
    "create_hosted_private_service_apps",
    "create_hosted_simulator_app",
]
