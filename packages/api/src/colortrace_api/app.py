from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any, Protocol
from urllib.parse import urlsplit

from colortrace_recovery import RecoveryError
from colortrace_response_plans import ResponsePlanError
from colortrace_simulator.authority import SimulatorAuthorityError
from colortrace_simulator.repository import SimulatorRepositoryError
from colortrace_vertical_slice import SliceContractError
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.types import Lifespan

from .auth import Principal, TokenVerifier
from .demo_facade import DemoApi, DemoFacadeError
from .recovery import RecoveryApi, RecoveryVerificationAdmissionApi
from .response_plans import ResponsePlanApi
from .simulator_actions import SimulatorActionApi


class IncidentService(Protocol):
    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]: ...

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]: ...

    def get_incident(self, incident_id: str) -> dict[str, Any]: ...

    def replay(self, incident_id: str) -> dict[str, Any]: ...

    def workspace(self, incident_id: str) -> dict[str, Any]: ...


class IncidentReadService(Protocol):
    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]: ...

    def get_incident(self, incident_id: str) -> dict[str, Any]: ...

    def replay(self, incident_id: str) -> dict[str, Any]: ...

    def workspace(self, incident_id: str) -> dict[str, Any]: ...


class ResponsePlanReadService(Protocol):
    def draft(self, incident_id: str) -> dict[str, Any]: ...

    def review(self, incident_id: str) -> dict[str, Any]: ...


class RecoveryReadService(Protocol):
    def review(self, incident_id: str) -> dict[str, Any]: ...


def _problem(status: int, code: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code})


def _status_for_error(code: str) -> int:
    if code == "principal-credential-expired":
        return 401
    if code in {
        "incident-access-denied",
        "incident-intake-kind-invalid",
        "incident-intake-role-required",
    }:
        return 403
    if code in {"incident-not-found", "task-not-found"}:
        return 404
    if code in {
        "idempotency-conflict",
        "incident-version-conflict",
        "incident-incomplete",
        "task-complete",
        "task-in-progress",
    }:
        return 409
    if code == "incident-cursor-invalid":
        return 400
    if code.endswith("-invalid") or code in {"alert-invalid", "identifier-invalid"}:
        return 400
    return 409


def _public_projection(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _public_projection(child)
            for key, child in value.items()
            if key != "credential_sha256"
        }
    if isinstance(value, list):
        return [_public_projection(child) for child in value]
    if isinstance(value, tuple):
        return [_public_projection(child) for child in value]
    return value


def _public_document(value: Mapping[str, Any]) -> dict[str, Any]:
    projected = _public_projection(value)
    if not isinstance(projected, dict):  # pragma: no cover - mapping always projects to a dict
        raise TypeError("public-projection-invalid")
    return projected


def _status_for_plan_error(code: str) -> int:
    if code in {"authentication-required", "principal-credential-expired"}:
        return 401
    if code in {
        "human-approval-required",
        "incident-access-denied",
        "model-authority-forbidden",
        "role-required",
        "service-identity-required",
    }:
        return 403
    if code in {
        "dispatch-authorization-not-found",
        "incident-not-found",
        "plan-not-found",
        "response-packet-not-found",
    }:
        return 404
    if code.endswith("-invalid") or code.startswith("schema-validation"):
        return 400
    return 409


def _status_for_simulator_error(code: str) -> int:
    if code in {
        "executor-authority-boundary-mismatch",
        "executor-incident-denied",
        "executor-role-required",
        "executor-service-required",
    }:
        return 403
    if code in {
        "admission-request-invalid",
        "dispatch-identity-invalid",
        "dispatch-operation-id-invalid",
        "dispatch-payload-invalid",
        "dispatch-task-key-invalid",
        "schema-validation",
    }:
        return 400
    return 409


def _status_for_recovery_error(code: str) -> int:
    if code in {"authentication-required", "principal-credential-expired"}:
        return 401
    if code in {
        "closure-human-required",
        "closer-role-required",
        "incident-access-denied",
        "model-authority-forbidden",
        "principal-audience-untrusted",
        "principal-issuer-untrusted",
        "principal-trust-boundary-mismatch",
        "scheduler-role-required",
        "scheduler-service-required",
        "verifier-role-required",
        "verifier-service-required",
    }:
        return 403
    if code in {
        "recovery-attempt-not-found",
        "recovery-workflow-not-found",
        "verification-task-not-found",
    }:
        return 404
    if code in {
        "recovery-closure-fence-unavailable",
        "recovery-verification-dispatcher-unavailable",
        "verification-dispatch-response-invalid",
    }:
        return 503
    if code.endswith("-invalid") or code.startswith("schema-"):
        return 400
    return 409


def _status_for_demo_error(code: str) -> int:
    if code in {"demo-run-not-found", "demo-visual-not-found"}:
        return 404
    if code in {"demo-store-unavailable", "demo-visual-unavailable"}:
        return 503
    if code.endswith("-invalid") or code in {
        "demo-request-invalid",
        "demo-scenario-invalid",
    }:
        return 400
    return 409


def _guard_demo_mutation(request: Request) -> None:
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise _problem(415, "demo-content-type-invalid")
    raw_length = request.headers.get("content-length")
    if raw_length is not None:
        try:
            length = int(raw_length)
        except ValueError:
            raise _problem(400, "demo-content-length-invalid") from None
        if length < 0 or length > 16_384:
            raise _problem(413, "demo-request-too-large")
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        raise _problem(403, "demo-origin-denied")
    origin = request.headers.get("origin")
    if origin is None:
        return
    parsed = urlsplit(origin)
    host = request.headers.get("host")
    if parsed.scheme not in {"http", "https"} or parsed.netloc != host or parsed.path:
        raise _problem(403, "demo-origin-denied")


def _reject_demo_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise DemoFacadeError("demo-request-invalid")
        value[key] = child
    return value


def _reject_demo_constant(_value: str) -> None:
    raise DemoFacadeError("demo-request-invalid")


async def _read_demo_body(request: Request) -> dict[str, Any]:
    _guard_demo_mutation(request)
    raw = await request.body()
    if not raw or len(raw) > 16_384:
        raise _problem(413, "demo-request-too-large")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_demo_duplicate_pairs,
            parse_constant=_reject_demo_constant,
        )
    except DemoFacadeError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise DemoFacadeError("demo-request-invalid") from None
    if not isinstance(value, dict):
        raise DemoFacadeError("demo-request-invalid")
    return value


def create_read_only_app(
    service: IncidentReadService,
    *,
    response_plans: ResponsePlanReadService,
    recovery: RecoveryReadService,
    readiness: Callable[[], bool] | None = None,
    lifespan: Lifespan[FastAPI] | None = None,
) -> FastAPI:
    app = FastAPI(
        title="ColorTrace Hosted Read API",
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
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
        )
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.exception_handler(SliceContractError)
    async def handle_contract_error(_request: Any, error: SliceContractError) -> JSONResponse:
        return JSONResponse(status_code=_status_for_error(error.code), content={"code": error.code})

    @app.exception_handler(ResponsePlanError)
    async def handle_plan_error(_request: Any, error: ResponsePlanError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_plan_error(error.code),
            content={"code": error.code},
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

    @app.get("/health/startup", include_in_schema=False)
    def startup_health() -> dict[str, str]:
        if readiness is not None and not readiness():
            raise _problem(503, "hosted-read-not-ready")
        return {"status": "ready"}

    @app.get("/health/live", include_in_schema=False)
    def liveness_health() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/v1/incidents")
    def list_incidents(
        limit: int = Query(default=25, ge=1, le=50),
        cursor: str | None = Query(default=None, min_length=1, max_length=512),
    ) -> dict[str, Any]:
        return _public_document(service.list_incidents(limit=limit, cursor=cursor))

    @app.get("/v1/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict[str, Any]:
        return _public_document(service.get_incident(incident_id))

    @app.get("/v1/incidents/{incident_id}/replay")
    def replay_incident(incident_id: str) -> dict[str, Any]:
        return _public_document(service.replay(incident_id))

    @app.get("/v1/incidents/{incident_id}/workspace")
    def get_workspace(incident_id: str) -> dict[str, Any]:
        return _public_document(service.workspace(incident_id))

    @app.get("/v1/incidents/{incident_id}/response-plan/draft")
    def get_response_plan_draft(incident_id: str) -> dict[str, Any]:
        return _public_document(response_plans.draft(incident_id))

    @app.get("/v1/incidents/{incident_id}/response-plan")
    def get_response_plan(incident_id: str) -> dict[str, Any]:
        return _public_document(response_plans.review(incident_id))

    @app.get("/v1/incidents/{incident_id}/recovery")
    def get_recovery(incident_id: str) -> dict[str, Any]:
        return _public_document(recovery.review(incident_id))

    return app


def create_app(
    service: IncidentService,
    *,
    token_verifier: TokenVerifier | None = None,
    response_plans: ResponsePlanApi | None = None,
    simulator_actions: SimulatorActionApi | None = None,
    recovery: RecoveryApi | None = None,
    recovery_verifications: RecoveryVerificationAdmissionApi | None = None,
    demo: DemoApi | None = None,
    lifespan: Lifespan[FastAPI] | None = None,
) -> FastAPI:
    app = FastAPI(
        title="ColorTrace Incident API",
        version="2.0.0",
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
            response = JSONResponse(
                status_code=500,
                content={"code": "internal-server-error"},
            )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
        )
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.exception_handler(SliceContractError)
    async def handle_contract_error(_request: Any, error: SliceContractError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_error(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(ResponsePlanError)
    async def handle_plan_error(_request: Any, error: ResponsePlanError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_plan_error(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(SimulatorAuthorityError)
    async def handle_simulator_authority_error(
        _request: Any, error: SimulatorAuthorityError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_simulator_error(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(SimulatorRepositoryError)
    async def handle_simulator_repository_error(
        _request: Any, error: SimulatorRepositoryError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_simulator_error(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(RecoveryError)
    async def handle_recovery_error(_request: Any, error: RecoveryError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_recovery_error(error.code),
            content={"code": error.code},
        )

    @app.exception_handler(DemoFacadeError)
    async def handle_demo_error(_request: Any, error: DemoFacadeError) -> JSONResponse:
        return JSONResponse(
            status_code=_status_for_demo_error(error.code),
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
            raise _problem(401, "authentication-required")
        token = authorization.removeprefix("Bearer ")
        if not token or token_verifier is None:
            raise _problem(401, "authentication-invalid")
        try:
            return token_verifier.verify(token)
        except (TypeError, ValueError):
            raise _problem(401, "authentication-invalid") from None

    principal_dependency = Depends(current_principal)
    demo_body_dependency = Depends(_read_demo_body)

    @app.get("/health/startup", include_in_schema=False)
    def startup_health() -> dict[str, str]:
        return {"status": "ready"}

    @app.get("/health/live", include_in_schema=False)
    def liveness_health() -> dict[str, str]:
        return {"status": "alive"}

    def plan_api() -> ResponsePlanApi:
        if response_plans is None:
            raise _problem(404, "response-plan-unavailable")
        return response_plans

    def simulator_api() -> SimulatorActionApi:
        if simulator_actions is None:
            raise _problem(404, "simulator-actions-unavailable")
        return simulator_actions

    def recovery_api() -> RecoveryApi:
        if recovery is None:
            raise _problem(404, "recovery-unavailable")
        return recovery

    def recovery_verification_api() -> RecoveryVerificationAdmissionApi:
        if recovery_verifications is None:
            raise _problem(503, "recovery-verification-dispatcher-unavailable")
        return recovery_verifications

    def demo_api() -> DemoApi:
        if demo is None:
            raise _problem(404, "demo-unavailable")
        return demo

    @app.post("/v1/incidents", status_code=202)
    def create_incident(
        alert: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return service.accept_alert(alert, principal)

    @app.get("/v1/incidents")
    def list_incidents(
        limit: int = Query(default=25, ge=1, le=50),
        cursor: str | None = Query(default=None, min_length=1, max_length=512),
    ) -> dict[str, Any]:
        return _public_document(service.list_incidents(limit=limit, cursor=cursor))

    @app.get("/v1/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict[str, Any]:
        return _public_document(service.get_incident(incident_id))

    @app.get("/v1/incidents/{incident_id}/replay")
    def replay_incident(incident_id: str) -> dict[str, Any]:
        return _public_document(service.replay(incident_id))

    @app.get("/v1/incidents/{incident_id}/workspace")
    def get_workspace(incident_id: str) -> dict[str, Any]:
        return _public_document(service.workspace(incident_id))

    @app.get("/v1/incidents/{incident_id}/response-plan/draft")
    def get_response_plan_draft(incident_id: str) -> dict[str, Any]:
        return _public_document(plan_api().draft(incident_id))

    @app.get("/v1/incidents/{incident_id}/response-plan")
    def get_response_plan(incident_id: str) -> dict[str, Any]:
        return _public_document(plan_api().review(incident_id))

    @app.post("/v1/incidents/{incident_id}/response-plan", status_code=201)
    def create_response_plan(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return plan_api().create(principal, incident_id, body)

    @app.put("/v1/incidents/{incident_id}/response-plan")
    def edit_response_plan(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return plan_api().edit(principal, incident_id, body)

    @app.post("/v1/incidents/{incident_id}/response-plan/approve")
    def approve_response_plan(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return plan_api().approve(principal, incident_id, body)

    @app.post("/v1/incidents/{incident_id}/response-plan/reject")
    def reject_response_plan(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return plan_api().reject(principal, incident_id, body)

    @app.post("/v1/incidents/{incident_id}/response-plan/dispatch-authorizations")
    def authorize_response_plan_dispatch(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return plan_api().authorize_dispatch(principal, incident_id, body)

    @app.post("/v1/incidents/{incident_id}/response-plan/dispatch-consumptions")
    def consume_response_plan_dispatch(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return plan_api().consume_dispatch(principal, incident_id, body)

    @app.post("/internal/v1/incidents/{incident_id}/simulator-actions", status_code=202)
    def admit_simulator_action(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return simulator_api().admit(principal, incident_id, body)

    @app.get("/v1/incidents/{incident_id}/recovery")
    def get_recovery(incident_id: str) -> dict[str, Any]:
        return _public_document(recovery_api().review(incident_id))

    @app.post("/internal/v1/incidents/{incident_id}/recovery/verifications", status_code=202)
    def admit_recovery_verification(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return recovery_verification_api().admit_verification(principal, incident_id, body)

    @app.post("/v1/incidents/{incident_id}/recovery/close")
    def close_recovery(
        incident_id: str,
        body: dict[str, Any],
        principal: Principal = principal_dependency,
    ) -> dict[str, Any]:
        return recovery_api().close(principal, incident_id, body)

    @app.get("/v1/session")
    def get_session(principal: Principal = principal_dependency) -> dict[str, Any]:
        return {
            "schema": "operator-session/v1",
            "subject": principal.subject,
            "display_name": principal.display_name,
            "roles": sorted(principal.roles),
            "issuer": principal.issuer,
            "audience": principal.audience,
            "principal_kind": principal.principal_kind,
        }

    @app.post("/v1/demo/runs", status_code=201)
    def start_demo_run(body: dict[str, Any] = demo_body_dependency) -> dict[str, Any]:
        return demo_api().start(body)

    @app.get("/v1/demo/runs/{run_id}")
    def get_demo_run(run_id: str) -> dict[str, Any]:
        return demo_api().get(run_id)

    @app.post("/v1/demo/runs/{run_id}/approve")
    def approve_demo_run(
        run_id: str, body: dict[str, Any] = demo_body_dependency
    ) -> dict[str, Any]:
        return demo_api().approve(run_id, body)

    @app.post("/v1/demo/runs/{run_id}/close")
    def close_demo_run(run_id: str, body: dict[str, Any] = demo_body_dependency) -> dict[str, Any]:
        return demo_api().close(run_id, body)

    @app.post("/v1/demo/runs/{run_id}/reset")
    def reset_demo_run(run_id: str, body: dict[str, Any] = demo_body_dependency) -> dict[str, Any]:
        return demo_api().reset(run_id, body)

    @app.get("/v1/demo/runs/{run_id}/receipt")
    def get_demo_receipt(run_id: str) -> dict[str, Any]:
        return demo_api().receipt(run_id)

    @app.get("/v1/demo/runs/{run_id}/visuals/{kind}")
    def get_demo_visual(run_id: str, kind: str) -> Response:
        visual = demo_api().visual(run_id, kind)
        return Response(
            content=visual.content,
            media_type=visual.media_type,
            headers={"X-Content-SHA256": visual.sha256},
        )

    return app
