from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from colortrace_recovery import (
    RecoveryClosureService,
    RecoveryIdentityBoundary,
    SQLiteRecoveryRepository,
)
from colortrace_response_plans import (
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    SQLiteResponsePlanRepository,
)
from colortrace_simulator import SimulatorActionService, StoredDispatchSource
from colortrace_simulator.authority import SimulatorAuthorityBoundary, SimulatorExecutorBoundary
from colortrace_simulator.bundle import LocalPublicationPort
from colortrace_simulator.repository import SQLiteSimulatorRepository
from colortrace_telemetry import ActionOtelSink, emit_action_outcome
from colortrace_vertical_slice import SqliteIncidentStore
from fastapi import FastAPI

from .app import create_app
from .oidc import HttpsJwksResolver, JwksResolver, OidcTokenVerifier
from .recovery import RecoveryCoordinator
from .recovery_closure import LocalRecoveryClosureFence
from .recovery_tasks import SQLiteRecoveryVerificationTaskStore
from .response_plans import ResponsePlanCoordinator
from .simulator_actions import SimulatorActionCoordinator
from .simulator_runtime import LocalSimulatorRuntime
from .stored_service import StoredIncidentService, StoredIncidentStore

DATABASE_PATH_ENV = "COLORTRACE_DATABASE_PATH"
RESPONSE_PLAN_DATABASE_PATH_ENV = "COLORTRACE_RESPONSE_PLAN_DATABASE_PATH"
RECOVERY_DATABASE_PATH_ENV = "COLORTRACE_RECOVERY_DATABASE_PATH"
RECOVERY_TASK_DATABASE_PATH_ENV = "COLORTRACE_RECOVERY_TASK_DATABASE_PATH"
OIDC_ISSUER_ENV = "COLORTRACE_OIDC_ISSUER"
OIDC_AUDIENCE_ENV = "COLORTRACE_OIDC_AUDIENCE"
OIDC_JWKS_URI_ENV = "COLORTRACE_OIDC_JWKS_URI"
OIDC_LEEWAY_SECONDS_ENV = "COLORTRACE_OIDC_LEEWAY_SECONDS"
SIMULATOR_MODE_ENV = "COLORTRACE_SIMULATOR_MODE"
SIMULATOR_DATABASE_PATH_ENV = "COLORTRACE_SIMULATOR_DATABASE_PATH"
SIMULATOR_WORKSPACE_PATH_ENV = "COLORTRACE_SIMULATOR_WORKSPACE_PATH"
SIMULATOR_FIXTURE_BUNDLE_PATH_ENV = "COLORTRACE_SIMULATOR_FIXTURE_BUNDLE_PATH"
_SIMULATOR_PATH_ENVIRONMENTS = (
    SIMULATOR_DATABASE_PATH_ENV,
    SIMULATOR_WORKSPACE_PATH_ENV,
    SIMULATOR_FIXTURE_BUNDLE_PATH_ENV,
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


class ApiRuntimeConfigurationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class StoreFactory(Protocol):
    def __call__(self, path: Path) -> object: ...


class ResolverFactory(Protocol):
    def __call__(self, jwks_uri: str) -> JwksResolver: ...


class LocalSimulatorRuntimeFactory(Protocol):
    def __call__(
        self,
        *,
        database_path: Path,
        workspace_path: Path,
        fixture_bundle_path: Path,
        dispatch_source: StoredDispatchSource,
        executor_boundary: SimulatorExecutorBoundary,
        clock: Callable[[], datetime] | None,
    ) -> LocalSimulatorRuntime: ...


@dataclass(frozen=True, slots=True)
class ApiRuntimeConfig:
    database_path: Path
    response_plan_database_path: Path
    recovery_database_path: Path
    oidc_issuer: str
    oidc_audience: str
    oidc_jwks_uri: str
    recovery_task_database_path: Path | None = None
    oidc_leeway_seconds: float = 30.0
    simulator_mode: Literal["disabled", "local"] = "disabled"
    simulator_database_path: Path | None = None
    simulator_workspace_path: Path | None = None
    simulator_fixture_bundle_path: Path | None = None

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> ApiRuntimeConfig:
        database_path = _database_path(_required(environment, DATABASE_PATH_ENV))
        response_plan_database_path = _database_path(
            _required(environment, RESPONSE_PLAN_DATABASE_PATH_ENV)
        )
        recovery_database_path = _database_path(_required(environment, RECOVERY_DATABASE_PATH_ENV))
        recovery_task_value = environment.get(RECOVERY_TASK_DATABASE_PATH_ENV)
        recovery_task_database_path = (
            None if recovery_task_value is None else _database_path(recovery_task_value)
        )
        database_paths = tuple(
            path
            for path in (
                database_path,
                response_plan_database_path,
                recovery_database_path,
                recovery_task_database_path,
            )
            if path is not None
        )
        if len(set(database_paths)) != len(database_paths):
            raise ApiRuntimeConfigurationError("database-path-overlap")
        issuer = _required(environment, OIDC_ISSUER_ENV)
        audience = _required(environment, OIDC_AUDIENCE_ENV)
        jwks_uri = _required(environment, OIDC_JWKS_URI_ENV)
        leeway_value = environment.get(OIDC_LEEWAY_SECONDS_ENV, "30")
        try:
            leeway = float(leeway_value)
        except (TypeError, ValueError):
            raise ApiRuntimeConfigurationError("oidc-leeway-invalid") from None
        simulator_mode, simulator_paths = _simulator_environment(environment)
        return cls(
            database_path=database_path,
            response_plan_database_path=response_plan_database_path,
            recovery_database_path=recovery_database_path,
            recovery_task_database_path=recovery_task_database_path,
            oidc_issuer=issuer,
            oidc_audience=audience,
            oidc_jwks_uri=jwks_uri,
            oidc_leeway_seconds=leeway,
            simulator_mode=simulator_mode,
            simulator_database_path=simulator_paths[0],
            simulator_workspace_path=simulator_paths[1],
            simulator_fixture_bundle_path=simulator_paths[2],
        )


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if value is None or not value or value != value.strip() or "\x00" in value:
        raise ApiRuntimeConfigurationError(f"{name.lower()}-missing-or-invalid")
    return value


def _database_path(value: str | Path) -> Path:
    if len(str(value)) > 4_096:
        raise ApiRuntimeConfigurationError("database-path-invalid")
    path = Path(value)
    if not path.is_absolute() or path == Path(path.anchor) or path.name in {"", ".", ".."}:
        raise ApiRuntimeConfigurationError("database-path-invalid")
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        raise ApiRuntimeConfigurationError("database-path-invalid") from None
    if not parent.is_dir() or path.parent.is_symlink() or path.parent != parent:
        raise ApiRuntimeConfigurationError("database-path-invalid")
    return path


def _directory_path(value: str | Path, *, must_exist: bool) -> Path:
    if len(str(value)) > 4_096:
        raise ApiRuntimeConfigurationError("simulator-path-invalid")
    path = Path(value)
    if not path.is_absolute() or path == Path(path.anchor) or path.name in {"", ".", ".."}:
        raise ApiRuntimeConfigurationError("simulator-path-invalid")
    try:
        parent = path.parent.resolve(strict=True)
        if path.parent.is_symlink() or path.parent != parent or not parent.is_dir():
            raise OSError
        if path.exists():
            resolved = path.resolve(strict=True)
            if path.is_symlink() or resolved != path or not path.is_dir():
                raise OSError
        elif must_exist:
            raise OSError
    except OSError:
        raise ApiRuntimeConfigurationError("simulator-path-invalid") from None
    return path


def _simulator_environment(
    environment: Mapping[str, str],
) -> tuple[Literal["disabled", "local"], tuple[Path | None, Path | None, Path | None]]:
    mode = environment.get(SIMULATOR_MODE_ENV, "disabled")
    configured_paths = any(name in environment for name in _SIMULATOR_PATH_ENVIRONMENTS)
    if mode == "disabled":
        if configured_paths:
            raise ApiRuntimeConfigurationError("simulator-configuration-invalid")
        return "disabled", (None, None, None)
    if mode != "local":
        raise ApiRuntimeConfigurationError("simulator-mode-invalid")
    database = _database_path(_required(environment, SIMULATOR_DATABASE_PATH_ENV))
    workspace = _directory_path(
        _required(environment, SIMULATOR_WORKSPACE_PATH_ENV),
        must_exist=False,
    )
    fixture_bundle = _directory_path(
        _required(environment, SIMULATOR_FIXTURE_BUNDLE_PATH_ENV),
        must_exist=True,
    )
    return "local", (database, workspace, fixture_bundle)


def _local_simulator_paths(config: ApiRuntimeConfig) -> tuple[Path, Path, Path] | None:
    values = (
        config.simulator_database_path,
        config.simulator_workspace_path,
        config.simulator_fixture_bundle_path,
    )
    if config.simulator_mode == "disabled":
        if any(value is not None for value in values):
            raise ApiRuntimeConfigurationError("simulator-configuration-invalid")
        return None
    if config.simulator_mode != "local" or any(value is None for value in values):
        raise ApiRuntimeConfigurationError("simulator-configuration-invalid")
    database = _database_path(cast(Path, values[0]))
    workspace = _directory_path(cast(Path, values[1]), must_exist=False)
    fixture_bundle = _directory_path(cast(Path, values[2]), must_exist=True)
    incident_database = _database_path(config.database_path)
    response_plan_database = _database_path(config.response_plan_database_path)
    recovery_database = _database_path(config.recovery_database_path)
    recovery_task_database = (
        None
        if config.recovery_task_database_path is None
        else _database_path(config.recovery_task_database_path)
    )
    paths = (
        incident_database,
        response_plan_database,
        recovery_database,
        recovery_task_database,
        database,
        workspace,
        fixture_bundle,
    )
    selected_paths = tuple(path for path in paths if path is not None)
    for index, left in enumerate(selected_paths):
        for right in selected_paths[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                raise ApiRuntimeConfigurationError("simulator-path-overlap")
    return database, workspace, fixture_bundle


def _sqlite_store(path: Path) -> object:
    return SqliteIncidentStore(path)


def _https_resolver(jwks_uri: str) -> JwksResolver:
    return HttpsJwksResolver(jwks_uri)


def _stored_incident_store(value: object) -> StoredIncidentStore:
    required = (
        "accept_alert",
        "list_incidents",
        "incident_view",
        "replay",
        "incident_workspace",
    )
    try:
        compatible = all(callable(getattr(value, name, None)) for name in required)
    except Exception:
        compatible = False
    if not compatible:
        raise ApiRuntimeConfigurationError("incident-store-incompatible")
    return cast(StoredIncidentStore, value)


def _local_simulator_runtime(
    *,
    database_path: Path,
    workspace_path: Path,
    fixture_bundle_path: Path,
    dispatch_source: StoredDispatchSource,
    executor_boundary: SimulatorExecutorBoundary,
    clock: Callable[[], datetime] | None,
) -> LocalSimulatorRuntime:
    repository = SQLiteSimulatorRepository(database_path)
    telemetry_sink: ActionOtelSink | None = None
    try:
        selected_clock = _utc_now if clock is None else clock
        publication = LocalPublicationPort.bootstrap(
            root=workspace_path,
            fixture_bundle=fixture_bundle_path,
            clock=selected_clock,
        )
        sink = ActionOtelSink()
        telemetry_sink = sink

        def observe(outcome: Mapping[str, Any]) -> object:
            return emit_action_outcome(outcome, sink, clock=selected_clock)

        service = SimulatorActionService(
            repository=repository,
            dispatch_source=dispatch_source,
            authority_boundary=SimulatorAuthorityBoundary(),
            executor_boundary=executor_boundary,
            publication=publication,
            terminal_observer=observe,
            clock=selected_clock,
        )
        return LocalSimulatorRuntime(
            repository=repository,
            service=service,
            telemetry_sink=sink,
            recovery_publication=publication,
        )
    except Exception:
        try:
            if telemetry_sink is not None:
                telemetry_sink.shutdown()
        finally:
            repository.close()
        raise


def create_runtime_app(
    config: ApiRuntimeConfig,
    *,
    store_factory: StoreFactory = _sqlite_store,
    resolver_factory: ResolverFactory = _https_resolver,
    local_simulator_factory: LocalSimulatorRuntimeFactory = _local_simulator_runtime,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    selected_clock = _utc_now if clock is None else clock
    database_path = _database_path(config.database_path)
    database_paths = (
        database_path,
        _database_path(config.response_plan_database_path),
        _database_path(config.recovery_database_path),
        *(
            ()
            if config.recovery_task_database_path is None
            else (_database_path(config.recovery_task_database_path),)
        ),
    )
    if len(set(database_paths)) != len(database_paths):
        raise ApiRuntimeConfigurationError("database-path-overlap")
    local_simulator_paths = _local_simulator_paths(config)
    try:
        HttpsJwksResolver.validate_uri(config.oidc_jwks_uri)
        resolver = resolver_factory(config.oidc_jwks_uri)
        if not callable(getattr(resolver, "resolve", None)):
            raise TypeError("resolver is incompatible")
        verifier = OidcTokenVerifier(
            issuer=config.oidc_issuer,
            audience=config.oidc_audience,
            resolver=resolver,
            leeway_seconds=config.oidc_leeway_seconds,
        )
    except Exception:
        raise ApiRuntimeConfigurationError("oidc-configuration-invalid") from None
    try:
        store = _stored_incident_store(store_factory(database_path))
    except ApiRuntimeConfigurationError:
        raise
    except Exception:
        raise ApiRuntimeConfigurationError("database-path-invalid") from None
    service = (
        StoredIncidentService(store) if clock is None else StoredIncidentService(store, clock=clock)
    )
    authority_boundary = CanonicalAuthorityBoundary()
    try:
        response_plan_repository = SQLiteResponsePlanRepository(
            _database_path(config.response_plan_database_path),
            authority_boundary=authority_boundary,
        )
        identity_boundary = OIDCTrustBoundary(
            trusted_issuers=frozenset({config.oidc_issuer}),
            audience=config.oidc_audience,
        )
        response_plans = ResponsePlanCoordinator(
            incident_reader=service,
            repository=response_plan_repository,
            authority_boundary=authority_boundary,
            identity_boundary=identity_boundary,
            **({} if clock is None else {"clock": clock}),
        )
    except Exception:
        raise ApiRuntimeConfigurationError("response-plan-configuration-invalid") from None
    recovery_task_store: SQLiteRecoveryVerificationTaskStore | None = None
    if config.recovery_task_database_path is not None:
        try:
            recovery_task_store = SQLiteRecoveryVerificationTaskStore(
                _database_path(config.recovery_task_database_path),
                clock=selected_clock,
            )
        except Exception:
            raise ApiRuntimeConfigurationError("recovery-task-configuration-invalid") from None
    try:
        recovery_repository = SQLiteRecoveryRepository(
            _database_path(config.recovery_database_path)
        )
        recovery_identity_boundary = RecoveryIdentityBoundary(
            trusted_issuers=frozenset({config.oidc_issuer}),
            audience=config.oidc_audience,
        )
    except Exception:
        raise ApiRuntimeConfigurationError("recovery-configuration-invalid") from None
    local_simulator: LocalSimulatorRuntime | None = None
    simulator_actions: SimulatorActionCoordinator | None = None
    if local_simulator_paths is not None:
        executor_boundary = SimulatorExecutorBoundary()
        try:
            local_simulator = local_simulator_factory(
                database_path=local_simulator_paths[0],
                workspace_path=local_simulator_paths[1],
                fixture_bundle_path=local_simulator_paths[2],
                dispatch_source=response_plans,
                executor_boundary=executor_boundary,
                clock=clock,
            )
        except Exception:
            raise ApiRuntimeConfigurationError("simulator-configuration-invalid") from None
        simulator_actions = SimulatorActionCoordinator(
            service=local_simulator.admission_service,
            executor_boundary=executor_boundary,
            identity_boundary=identity_boundary,
            **({} if clock is None else {"clock": clock}),
        )
    closure_fence = None
    if (
        local_simulator is not None
        and isinstance(local_simulator.repository, SQLiteSimulatorRepository)
        and local_simulator.recovery_publication is not None
    ):
        closure_fence = LocalRecoveryClosureFence(
            repository=local_simulator.repository,
            publication=local_simulator.recovery_publication,
        )
    recovery = RecoveryCoordinator(
        incident_reader=service,
        aggregate_reader=recovery_repository,
        closure_service=RecoveryClosureService(
            repository=recovery_repository,
            identity_boundary=recovery_identity_boundary,
            clock=selected_clock,
        ),
        identity_boundary=recovery_identity_boundary,
        task_dispatcher=recovery_task_store,
        closure_fence=closure_fence,
        clock=selected_clock,
    )
    app = create_app(
        service,
        token_verifier=verifier,
        response_plans=response_plans,
        simulator_actions=simulator_actions,
        recovery=recovery,
        recovery_verifications=None if recovery_task_store is None else recovery,
        lifespan=None if local_simulator is None else local_simulator.lifespan,
    )
    app.state.local_simulator_runtime = local_simulator
    app.state.recovery_repository = recovery_repository
    app.state.recovery_verification_task_store = recovery_task_store
    return app


def create_application(
    environment: Mapping[str, str] | None = None,
    *,
    store_factory: StoreFactory = _sqlite_store,
    resolver_factory: ResolverFactory = _https_resolver,
    local_simulator_factory: LocalSimulatorRuntimeFactory = _local_simulator_runtime,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    config = ApiRuntimeConfig.from_environment(os.environ if environment is None else environment)
    return create_runtime_app(
        config,
        store_factory=store_factory,
        resolver_factory=resolver_factory,
        local_simulator_factory=local_simulator_factory,
        clock=clock,
    )
