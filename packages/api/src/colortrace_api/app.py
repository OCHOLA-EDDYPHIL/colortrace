from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

from colortrace_response_plans import ResponsePlanError
from colortrace_vertical_slice import SliceContractError
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from .auth import Principal, TokenVerifier
from .response_plans import ResponsePlanApi


class IncidentService(Protocol):
    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]: ...

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]: ...

    def get_incident(self, incident_id: str) -> dict[str, Any]: ...

    def replay(self, incident_id: str) -> dict[str, Any]: ...

    def workspace(self, incident_id: str) -> dict[str, Any]: ...


def _problem(status: int, code: str) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code})


def _status_for_error(code: str) -> int:
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


def create_app(
    service: IncidentService,
    *,
    token_verifier: TokenVerifier | None = None,
    response_plans: ResponsePlanApi | None = None,
) -> FastAPI:
    app = FastAPI(
        title="ColorTrace Incident API",
        version="2.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

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

    def plan_api() -> ResponsePlanApi:
        if response_plans is None:
            raise _problem(404, "response-plan-unavailable")
        return response_plans

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
        return service.list_incidents(limit=limit, cursor=cursor)

    @app.get("/v1/incidents/{incident_id}")
    def get_incident(incident_id: str) -> dict[str, Any]:
        return service.get_incident(incident_id)

    @app.get("/v1/incidents/{incident_id}/replay")
    def replay_incident(incident_id: str) -> dict[str, Any]:
        return service.replay(incident_id)

    @app.get("/v1/incidents/{incident_id}/workspace")
    def get_workspace(incident_id: str) -> dict[str, Any]:
        return service.workspace(incident_id)

    @app.get("/v1/incidents/{incident_id}/response-plan/draft")
    def get_response_plan_draft(incident_id: str) -> dict[str, Any]:
        return plan_api().draft(incident_id)

    @app.get("/v1/incidents/{incident_id}/response-plan")
    def get_response_plan(incident_id: str) -> dict[str, Any]:
        return plan_api().review(incident_id)

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

    return app
