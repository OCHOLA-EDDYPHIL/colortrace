from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Protocol, cast

import uvicorn
from colortrace_persistence import (
    CanonicalPostgresStore,
    CloudSqlConnectionFactory,
    MetadataSnapshot,
    PersistenceError,
    PostgresMigrationRunner,
    PostgresReaderVerifier,
    PostgresRoleBootstrapper,
)
from colortrace_recovery import RecoveryError
from colortrace_response_plans import ResponsePlanError
from colortrace_vertical_slice import SliceContractError
from fastapi import FastAPI
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError, ValidationError  # type: ignore[import-untyped]

from .app import create_read_only_app

CLOUD_SQL_INSTANCE_ENV = "COLORTRACE_CLOUD_SQL_INSTANCE"
CLOUD_SQL_DATABASE_ENV = "COLORTRACE_CLOUD_SQL_DATABASE"
POSTGRES_ADMIN_USER_ENV = "COLORTRACE_POSTGRES_ADMIN_USER"
POSTGRES_ADMIN_PASSWORD_FILE_ENV = "COLORTRACE_POSTGRES_ADMIN_PASSWORD_FILE"
POSTGRES_MIGRATION_ROLE_ENV = "COLORTRACE_POSTGRES_MIGRATION_ROLE"
POSTGRES_RUNTIME_ROLE_ENV = "COLORTRACE_POSTGRES_RUNTIME_ROLE"
POSTGRES_API_ROLE_ENV = "COLORTRACE_POSTGRES_API_ROLE"
FIXTURE_SHA256_ENV = "COLORTRACE_FIXTURE_SHA256"
BIND_HOST_ENV = "COLORTRACE_BIND_HOST"
PORT_ENV = "PORT"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9-]+:[A-Za-z0-9-]+$")
_DATABASE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")
_ROLE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}$")
_ASSET_NAME = "hosted-read-projection-v1.json"
_SCHEMA_NAME = "hosted-read-projection-v1.schema.json"
_READY_RECORD_ID = "hosted-readiness:synthetic-hosted-read-v1"
_MAX_ASSET_BYTES = 131_072
_MAX_SECRET_BYTES = 16_384


class HostedReadConfigurationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ClosableConnectionFactory(Protocol):
    def connect(self) -> Any: ...

    def close(self) -> None: ...


class IamFactoryBuilder(Protocol):
    def __call__(
        self,
        *,
        instance_connection_name: str,
        database: str,
        user: str,
    ) -> ClosableConnectionFactory: ...


class PasswordFactoryBuilder(Protocol):
    def __call__(
        self,
        *,
        instance_connection_name: str,
        database: str,
        user: str,
        password: str,
    ) -> ClosableConnectionFactory: ...


def _required(environment: Mapping[str, str], name: str, *, maximum: int = 4096) -> str:
    value = environment.get(name)
    if (
        value is None
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HostedReadConfigurationError(f"{name.lower()}-missing-or-invalid")
    return value


def _match(value: str, pattern: re.Pattern[str], code: str) -> str:
    if pattern.fullmatch(value) is None:
        raise HostedReadConfigurationError(code)
    return value


def _roles(environment: Mapping[str, str]) -> tuple[str, str, str]:
    migration = _match(
        _required(environment, POSTGRES_MIGRATION_ROLE_ENV, maximum=63),
        _ROLE,
        "postgres-migration-role-invalid",
    )
    runtime = _match(
        _required(environment, POSTGRES_RUNTIME_ROLE_ENV, maximum=63),
        _ROLE,
        "postgres-runtime-role-invalid",
    )
    api = _match(
        _required(environment, POSTGRES_API_ROLE_ENV, maximum=63),
        _ROLE,
        "postgres-api-role-invalid",
    )
    if len({migration, runtime, api}) != 3:
        raise HostedReadConfigurationError("postgres-role-separation-invalid")
    return migration, runtime, api


def _database(environment: Mapping[str, str]) -> tuple[str, str]:
    instance = _match(
        _required(environment, CLOUD_SQL_INSTANCE_ENV, maximum=256),
        _INSTANCE,
        "cloud-sql-instance-invalid",
    )
    database = _match(
        _required(environment, CLOUD_SQL_DATABASE_ENV, maximum=63),
        _DATABASE,
        "cloud-sql-database-invalid",
    )
    return instance, database


def _fixture_digest(environment: Mapping[str, str]) -> str:
    return _match(
        _required(environment, FIXTURE_SHA256_ENV, maximum=71),
        _DIGEST,
        "hosted-fixture-digest-invalid",
    )


@dataclass(frozen=True, slots=True)
class HostedServeConfig:
    instance_connection_name: str
    database: str
    api_role: str
    fixture_sha256: str
    host: str
    port: int

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> HostedServeConfig:
        instance, database = _database(environment)
        api_role = _match(
            _required(environment, POSTGRES_API_ROLE_ENV, maximum=63),
            _ROLE,
            "postgres-api-role-invalid",
        )
        host = environment.get(BIND_HOST_ENV, "127.0.0.1")
        if host not in {"0.0.0.0", "127.0.0.1"}:
            raise HostedReadConfigurationError("bind-host-invalid")
        port_value = environment.get(PORT_ENV, "8000")
        if not port_value.isdecimal() or not 1 <= (port := int(port_value)) <= 65_535:
            raise HostedReadConfigurationError("bind-port-invalid")
        return cls(instance, database, api_role, _fixture_digest(environment), host, port)


@dataclass(frozen=True, slots=True)
class HostedMigrationConfig:
    instance_connection_name: str
    database: str
    migration_role: str
    runtime_role: str
    api_role: str
    fixture_sha256: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> HostedMigrationConfig:
        instance, database = _database(environment)
        migration, runtime, api = _roles(environment)
        return cls(instance, database, migration, runtime, api, _fixture_digest(environment))


@dataclass(frozen=True, slots=True)
class HostedBootstrapConfig:
    instance_connection_name: str
    database: str
    admin_user: str
    admin_password_file: Path
    migration_role: str
    runtime_role: str
    api_role: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> HostedBootstrapConfig:
        instance, database = _database(environment)
        migration, runtime, api = _roles(environment)
        admin = _match(
            _required(environment, POSTGRES_ADMIN_USER_ENV, maximum=63),
            _ROLE,
            "postgres-admin-role-invalid",
        )
        if admin in {migration, runtime, api}:
            raise HostedReadConfigurationError("postgres-role-separation-invalid")
        path_value = _required(environment, POSTGRES_ADMIN_PASSWORD_FILE_ENV)
        path = Path(path_value)
        if not path.is_absolute() or path == Path(path.anchor):
            raise HostedReadConfigurationError("postgres-admin-password-file-invalid")
        return cls(instance, database, admin, path, migration, runtime, api)


@dataclass(frozen=True, slots=True)
class FixtureAsset:
    document: dict[str, Any]
    sha256: str

    @property
    def incident_id(self) -> str:
        return cast(str, self.document["incident_id"])


@dataclass(frozen=True, slots=True)
class SeedReport:
    fixture_id: str
    fixture_sha256: str
    fixture_record_version: int
    readiness_record_version: int


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _asset_bytes(name: str) -> bytes:
    value = files("colortrace_api").joinpath("assets", name).read_bytes()
    if not value or len(value) > _MAX_ASSET_BYTES:
        raise HostedReadConfigurationError("hosted-fixture-asset-invalid")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate-key")
        document[key] = value
    return document


def _json_object(value: bytes, *, code: str) -> dict[str, Any]:
    try:
        document = json.loads(value.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, ValueError):
        raise HostedReadConfigurationError(code) from None
    if not isinstance(document, dict):
        raise HostedReadConfigurationError(code)
    return cast(dict[str, Any], document)


def _validate_fixture_semantics(document: Mapping[str, Any]) -> None:
    incident_id = document.get("incident_id")
    summary = cast(Mapping[str, Any], document.get("summary"))
    view = cast(Mapping[str, Any], document.get("view"))
    workspace = cast(Mapping[str, Any], document.get("workspace"))
    incident = cast(Mapping[str, Any], view.get("incident"))
    task = cast(Mapping[str, Any], view.get("task"))
    if (
        summary.get("incident_id") != incident_id
        or incident.get("incident_id") != incident_id
        or task.get("incident_id") != incident_id
        or workspace.get("view") != view
        or summary.get("alert_id") != incident.get("alert_id")
        or summary.get("trace_id") != incident.get("trace_id")
        or incident.get("trace_id") != task.get("trace_id")
        or incident.get("alert_sha256") != task.get("alert_sha256")
        or summary.get("version") != incident.get("version")
        or task.get("expected_incident_version") != incident.get("version")
    ):
        raise HostedReadConfigurationError("hosted-fixture-binding-invalid")


def load_fixture(expected_sha256: str) -> FixtureAsset:
    expected = _match(expected_sha256, _DIGEST, "hosted-fixture-digest-invalid")
    asset_bytes = _asset_bytes(_ASSET_NAME)
    if _sha256(asset_bytes) != expected:
        raise HostedReadConfigurationError("hosted-fixture-digest-mismatch")
    document = _json_object(asset_bytes, code="hosted-fixture-asset-invalid")
    schema = _json_object(_asset_bytes(_SCHEMA_NAME), code="hosted-fixture-schema-invalid")
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
    except (SchemaError, ValidationError):
        raise HostedReadConfigurationError("hosted-fixture-contract-invalid") from None
    _validate_fixture_semantics(document)
    return FixtureAsset(document=document, sha256=expected)


def bundled_fixture_digest() -> str:
    return _sha256(_asset_bytes(_ASSET_NAME))


def _sentinel(asset: FixtureAsset, fixture: MetadataSnapshot) -> dict[str, Any]:
    return {
        "schema": "hosted-readiness-sentinel/v1",
        "fixture_id": asset.document["fixture_id"],
        "fixture_record_id": fixture.record_id,
        "fixture_record_version": fixture.version,
        "fixture_document_sha256": fixture.document_sha256,
        "fixture_chain_sha256": fixture.chain_sha256,
        "fixture_sha256": asset.sha256,
    }


def _load_seeded_fixture(
    store: CanonicalPostgresStore,
    asset: FixtureAsset,
) -> tuple[MetadataSnapshot, MetadataSnapshot]:
    try:
        readiness = store.read(_READY_RECORD_ID)
        fixture = store.read(asset.incident_id)
    except PersistenceError:
        raise HostedReadConfigurationError("hosted-readiness-sentinel-invalid") from None
    if dict(fixture.document) != asset.document or dict(readiness.document) != _sentinel(
        asset, fixture
    ):
        raise HostedReadConfigurationError("hosted-readiness-sentinel-invalid")
    return fixture, readiness


def seed_fixture(store: CanonicalPostgresStore, expected_sha256: str) -> SeedReport:
    asset = load_fixture(expected_sha256)
    fixture = store.create(
        asset.incident_id,
        asset.document,
        idempotency_key=f"hosted-fixture:{asset.sha256}",
    )
    readiness = store.create(
        _READY_RECORD_ID,
        _sentinel(asset, fixture),
        idempotency_key=f"hosted-readiness:{asset.sha256}",
    )
    fixture, readiness = _load_seeded_fixture(store, asset)
    return SeedReport(
        fixture_id=cast(str, asset.document["fixture_id"]),
        fixture_sha256=asset.sha256,
        fixture_record_version=fixture.version,
        readiness_record_version=readiness.version,
    )


class HostedProjectionService:
    def __init__(self) -> None:
        self._document: dict[str, Any] | None = None

    @property
    def ready(self) -> bool:
        return self._document is not None

    def install(self, document: Mapping[str, Any]) -> None:
        if self._document is not None:
            raise HostedReadConfigurationError("hosted-projection-already-loaded")
        self._document = copy.deepcopy(dict(document))

    def _fixture(self, incident_id: str | None = None) -> dict[str, Any]:
        if self._document is None:
            raise HostedReadConfigurationError("hosted-projection-not-loaded")
        if incident_id is not None and incident_id != self._document["incident_id"]:
            raise SliceContractError("incident-not-found")
        return self._document

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 50:
            raise SliceContractError("incident-limit-invalid")
        if cursor is not None:
            raise SliceContractError("incident-cursor-invalid")
        return {
            "schema": "incident-list/v1",
            "items": [copy.deepcopy(self._fixture()["summary"])],
            "next_cursor": None,
        }

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return copy.deepcopy(cast(dict[str, Any], self._fixture(incident_id)["view"]))

    def replay(self, incident_id: str) -> dict[str, Any]:
        replay = self._fixture(incident_id)["replay"]
        if replay is None:
            raise SliceContractError("incident-incomplete")
        return copy.deepcopy(cast(dict[str, Any], replay))

    def workspace(self, incident_id: str) -> dict[str, Any]:
        return copy.deepcopy(cast(dict[str, Any], self._fixture(incident_id)["workspace"]))

    def draft(self, incident_id: str) -> dict[str, Any]:
        draft = self._fixture(incident_id)["response_plan_draft"]
        if draft is None:
            raise ResponsePlanError("response-plan-unavailable")
        return copy.deepcopy(cast(dict[str, Any], draft))

    def review(self, incident_id: str) -> dict[str, Any]:
        plan = self._fixture(incident_id)["response_plan"]
        if plan is None:
            raise ResponsePlanError("plan-not-found")
        return copy.deepcopy(cast(dict[str, Any], plan))

    def review_recovery(self, incident_id: str) -> dict[str, Any]:
        recovery = self._fixture(incident_id)["recovery"]
        if recovery is None:
            raise RecoveryError("recovery-workflow-not-found")
        return copy.deepcopy(cast(dict[str, Any], recovery))


@dataclass(frozen=True, slots=True)
class _RecoveryProjection:
    service: HostedProjectionService

    def review(self, incident_id: str) -> dict[str, Any]:
        return self.service.review_recovery(incident_id)


def create_hosted_read_app(
    config: HostedServeConfig,
    *,
    factory_builder: IamFactoryBuilder = CloudSqlConnectionFactory.private_iam,
) -> FastAPI:
    asset = load_fixture(config.fixture_sha256)
    factory = factory_builder(
        instance_connection_name=config.instance_connection_name,
        database=config.database,
        user=config.api_role,
    )
    store = CanonicalPostgresStore(factory, namespace="incident")
    service = HostedProjectionService()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            PostgresReaderVerifier(
                factory,
                database=config.database,
                reader_role=config.api_role,
            ).validate()
            fixture, _readiness = _load_seeded_fixture(store, asset)
            service.install(fixture.document)
            yield
        finally:
            factory.close()

    app = create_read_only_app(
        service,
        response_plans=service,
        recovery=_RecoveryProjection(service),
        readiness=lambda: service.ready,
        lifespan=lifespan,
    )
    app.state.hosted_projection_service = service
    return app


def create_application(environment: Mapping[str, str] | None = None) -> FastAPI:
    config = HostedServeConfig.from_environment(os.environ if environment is None else environment)
    return create_hosted_read_app(config)


def _read_admin_password(path: Path) -> str:
    try:
        information = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.geteuid()
            or stat.S_IMODE(information.st_mode) & 0o077
            or not 0 < information.st_size <= _MAX_SECRET_BYTES
        ):
            raise OSError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                opened.st_dev != information.st_dev
                or opened.st_ino != information.st_ino
                or not stat.S_ISREG(opened.st_mode)
                or stat.S_IMODE(opened.st_mode) & 0o077
            ):
                raise OSError
            value = handle.read(_MAX_SECRET_BYTES + 1)
    except OSError:
        raise HostedReadConfigurationError("postgres-admin-password-file-invalid") from None
    try:
        password = value.decode("utf-8")
    except UnicodeError:
        raise HostedReadConfigurationError("postgres-admin-password-file-invalid") from None
    if (
        not password
        or len(value) > _MAX_SECRET_BYTES
        or password != password.strip()
        or any(character.isspace() for character in password)
        or any(ord(character) < 32 or ord(character) == 127 for character in password)
    ):
        raise HostedReadConfigurationError("postgres-admin-password-file-invalid")
    return password


def bootstrap_database(
    config: HostedBootstrapConfig,
    *,
    factory_builder: PasswordFactoryBuilder = CloudSqlConnectionFactory.private_password,
) -> None:
    password = _read_admin_password(config.admin_password_file)
    factory = factory_builder(
        instance_connection_name=config.instance_connection_name,
        database=config.database,
        user=config.admin_user,
        password=password,
    )
    try:
        PostgresRoleBootstrapper(
            factory,
            database=config.database,
            admin_role=config.admin_user,
            migration_role=config.migration_role,
            runtime_role=config.runtime_role,
            reader_role=config.api_role,
        ).apply()
    finally:
        factory.close()


def migrate_and_seed(
    config: HostedMigrationConfig,
    *,
    factory_builder: IamFactoryBuilder = CloudSqlConnectionFactory.private_iam,
) -> SeedReport:
    factory = factory_builder(
        instance_connection_name=config.instance_connection_name,
        database=config.database,
        user=config.migration_role,
    )
    try:
        PostgresMigrationRunner(
            factory,
            migration_role=config.migration_role,
            runtime_role=config.runtime_role,
            reader_role=config.api_role,
        ).apply_all()
        store = CanonicalPostgresStore(factory, namespace="incident")
        return seed_fixture(store, config.fixture_sha256)
    finally:
        factory.close()


def main(
    arguments: list[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> None:
    selected = sys.argv[1:] if arguments is None else arguments
    values = os.environ if environment is None else environment
    if selected == ["serve"]:
        config = HostedServeConfig.from_environment(values)
        uvicorn.run(
            "colortrace_api.hosted_read:create_application",
            factory=True,
            host=config.host,
            port=config.port,
        )
        return
    if selected == ["bootstrap"]:
        bootstrap_database(HostedBootstrapConfig.from_environment(values))
        return
    if selected == ["migrate-seed"]:
        migrate_and_seed(HostedMigrationConfig.from_environment(values))
        return
    raise HostedReadConfigurationError("hosted-command-invalid")


if __name__ == "__main__":
    main()
