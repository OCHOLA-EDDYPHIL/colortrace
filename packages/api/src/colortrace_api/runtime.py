from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

from colortrace_vertical_slice import SqliteIncidentStore
from fastapi import FastAPI

from .app import create_app
from .oidc import HttpsJwksResolver, JwksResolver, OidcTokenVerifier
from .stored_service import StoredIncidentService, StoredIncidentStore

DATABASE_PATH_ENV = "COLORTRACE_DATABASE_PATH"
OIDC_ISSUER_ENV = "COLORTRACE_OIDC_ISSUER"
OIDC_AUDIENCE_ENV = "COLORTRACE_OIDC_AUDIENCE"
OIDC_JWKS_URI_ENV = "COLORTRACE_OIDC_JWKS_URI"
OIDC_LEEWAY_SECONDS_ENV = "COLORTRACE_OIDC_LEEWAY_SECONDS"


class ApiRuntimeConfigurationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class StoreFactory(Protocol):
    def __call__(self, path: Path) -> object: ...


class ResolverFactory(Protocol):
    def __call__(self, jwks_uri: str) -> JwksResolver: ...


@dataclass(frozen=True, slots=True)
class ApiRuntimeConfig:
    database_path: Path
    oidc_issuer: str
    oidc_audience: str
    oidc_jwks_uri: str
    oidc_leeway_seconds: float = 30.0

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> ApiRuntimeConfig:
        database_path = _database_path(_required(environment, DATABASE_PATH_ENV))
        issuer = _required(environment, OIDC_ISSUER_ENV)
        audience = _required(environment, OIDC_AUDIENCE_ENV)
        jwks_uri = _required(environment, OIDC_JWKS_URI_ENV)
        leeway_value = environment.get(OIDC_LEEWAY_SECONDS_ENV, "30")
        try:
            leeway = float(leeway_value)
        except (TypeError, ValueError):
            raise ApiRuntimeConfigurationError("oidc-leeway-invalid") from None
        return cls(
            database_path=database_path,
            oidc_issuer=issuer,
            oidc_audience=audience,
            oidc_jwks_uri=jwks_uri,
            oidc_leeway_seconds=leeway,
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


def create_runtime_app(
    config: ApiRuntimeConfig,
    *,
    store_factory: StoreFactory = _sqlite_store,
    resolver_factory: ResolverFactory = _https_resolver,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    database_path = _database_path(config.database_path)
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
    return create_app(service, token_verifier=verifier)


def create_application(
    environment: Mapping[str, str] | None = None,
    *,
    store_factory: StoreFactory = _sqlite_store,
    resolver_factory: ResolverFactory = _https_resolver,
    clock: Callable[[], datetime] | None = None,
) -> FastAPI:
    config = ApiRuntimeConfig.from_environment(os.environ if environment is None else environment)
    return create_runtime_app(
        config,
        store_factory=store_factory,
        resolver_factory=resolver_factory,
        clock=clock,
    )
