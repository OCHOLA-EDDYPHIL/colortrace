from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from colortrace_api.app import create_read_only_app
from colortrace_api.hosted_read import (
    BIND_HOST_ENV,
    CLOUD_SQL_DATABASE_ENV,
    CLOUD_SQL_INSTANCE_ENV,
    FIXTURE_SHA256_ENV,
    PORT_ENV,
    POSTGRES_ADMIN_PASSWORD_FILE_ENV,
    POSTGRES_ADMIN_USER_ENV,
    POSTGRES_API_ROLE_ENV,
    POSTGRES_MIGRATION_ROLE_ENV,
    POSTGRES_RUNTIME_ROLE_ENV,
    HostedBootstrapConfig,
    HostedProjectionService,
    HostedReadConfigurationError,
    HostedServeConfig,
    _load_seeded_fixture,
    _RecoveryProjection,
    bootstrap_database,
    bundled_fixture_digest,
    create_hosted_read_app,
    load_fixture,
    main,
    seed_fixture,
)
from colortrace_persistence import MetadataSnapshot
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

_EXPECTED_FIXTURE_DIGEST = "sha256:2a98862b9fd923466b86fe23624c255df9243014b96232efaf279a344b398873"


def _environment() -> dict[str, str]:
    return {
        CLOUD_SQL_INSTANCE_ENV: "project:us-central1:colortrace-staging",
        CLOUD_SQL_DATABASE_ENV: "colortrace",
        POSTGRES_MIGRATION_ROLE_ENV: "colortrace-migration@project.iam",
        POSTGRES_RUNTIME_ROLE_ENV: "colortrace-worker@project.iam",
        POSTGRES_API_ROLE_ENV: "colortrace-api@project.iam",
        FIXTURE_SHA256_ENV: _EXPECTED_FIXTURE_DIGEST,
        BIND_HOST_ENV: "0.0.0.0",
        PORT_ENV: "8080",
    }


def _canonical_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


class MemoryStore:
    def __init__(self) -> None:
        self.records: dict[str, MetadataSnapshot] = {}
        self.idempotency: dict[str, tuple[str, MetadataSnapshot]] = {}

    def create(
        self,
        record_id: str,
        document: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> MetadataSnapshot:
        canonical = _canonical_digest(document)
        existing = self.idempotency.get(idempotency_key)
        if existing is not None:
            request_digest, snapshot = existing
            if request_digest != canonical:
                raise AssertionError("idempotency conflict")
            return snapshot
        if record_id in self.records:
            raise AssertionError("record conflict")
        snapshot = MetadataSnapshot(
            namespace="incident",
            record_id=record_id,
            version=1,
            document=dict(document),
            document_sha256=canonical,
            chain_sha256=f"sha256:{hashlib.sha256(record_id.encode()).hexdigest()}",
        )
        self.records[record_id] = snapshot
        self.idempotency[idempotency_key] = (canonical, snapshot)
        return snapshot

    def read(self, record_id: str) -> MetadataSnapshot:
        return self.records[record_id]


def _contract(name: str) -> Draft202012Validator:
    root = Path(__file__).parents[2] / "contracts" / "openapi.json"
    openapi = json.loads(root.read_text(encoding="utf-8"))
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": f"#/components/schemas/{name}",
        "components": openapi["components"],
    }
    return Draft202012Validator(schema, format_checker=FormatChecker())


def test_tracked_fixture_has_exact_digest_synthetic_provenance_and_contract() -> None:
    assert bundled_fixture_digest() == _EXPECTED_FIXTURE_DIGEST

    asset = load_fixture(_EXPECTED_FIXTURE_DIGEST)

    assert asset.document["provenance"] == {
        "classification": "synthetic",
        "origin": "tracked-project-fixture",
        "generator": "deterministic-static-v1",
    }
    with pytest.raises(HostedReadConfigurationError, match="^hosted-fixture-digest-mismatch$"):
        load_fixture(f"sha256:{'0' * 64}")


def test_seed_is_idempotent_and_readiness_sentinel_binds_current_record() -> None:
    store = MemoryStore()

    first = seed_fixture(store, _EXPECTED_FIXTURE_DIGEST)  # type: ignore[arg-type]
    second = seed_fixture(store, _EXPECTED_FIXTURE_DIGEST)  # type: ignore[arg-type]

    assert first == second
    assert first.fixture_record_version == 1
    assert first.readiness_record_version == 1
    asset = load_fixture(_EXPECTED_FIXTURE_DIGEST)
    fixture, readiness = _load_seeded_fixture(store, asset)  # type: ignore[arg-type]
    assert readiness.document["fixture_document_sha256"] == fixture.document_sha256
    assert readiness.document["fixture_chain_sha256"] == fixture.chain_sha256

    store.records[asset.incident_id] = MetadataSnapshot(
        namespace="incident",
        record_id=asset.incident_id,
        version=2,
        document={"tampered": True},
        document_sha256=f"sha256:{'0' * 64}",
        chain_sha256=f"sha256:{'1' * 64}",
    )
    with pytest.raises(HostedReadConfigurationError, match="^hosted-readiness-sentinel-invalid$"):
        _load_seeded_fixture(store, asset)  # type: ignore[arg-type]


def test_read_only_app_has_exact_get_inventory_and_contract_responses() -> None:
    asset = load_fixture(_EXPECTED_FIXTURE_DIGEST)
    service = HostedProjectionService()
    service.install(asset.document)
    app = create_read_only_app(
        service,
        response_plans=service,
        recovery=_RecoveryProjection(service),
        readiness=lambda: service.ready,
    )
    inventory = {
        (route.path, tuple(sorted(route.methods or ())))
        for route in app.routes
        if isinstance(route, APIRoute)
    }
    assert inventory == {
        ("/health/live", ("GET",)),
        ("/health/startup", ("GET",)),
        ("/v1/incidents", ("GET",)),
        ("/v1/incidents/{incident_id}", ("GET",)),
        ("/v1/incidents/{incident_id}/recovery", ("GET",)),
        ("/v1/incidents/{incident_id}/replay", ("GET",)),
        ("/v1/incidents/{incident_id}/response-plan", ("GET",)),
        ("/v1/incidents/{incident_id}/response-plan/draft", ("GET",)),
        ("/v1/incidents/{incident_id}/workspace", ("GET",)),
    }

    client = TestClient(app)
    incident_id = asset.incident_id
    responses = (
        (client.get("/v1/incidents"), "IncidentList"),
        (client.get(f"/v1/incidents/{incident_id}"), "IncidentView"),
        (client.get(f"/v1/incidents/{incident_id}/workspace"), "IncidentWorkspaceSource"),
    )
    for response, schema in responses:
        assert response.status_code == 200
        _contract(schema).validate(response.json())
        assert response.headers["cache-control"] == "no-store"

    assert client.get(f"/v1/incidents/{incident_id}/replay").json() == {
        "code": "incident-incomplete"
    }
    assert client.get(f"/v1/incidents/{incident_id}/response-plan/draft").status_code == 409
    assert client.get(f"/v1/incidents/{incident_id}/response-plan").status_code == 404
    assert client.get(f"/v1/incidents/{incident_id}/recovery").status_code == 404
    assert client.get("/v1/incidents/unknown").status_code == 404
    assert client.post("/v1/incidents", json={}).status_code == 405
    assert client.get("/v1/session").status_code == 404
    assert client.get("/internal/v1/incidents/example/simulator-actions").status_code == 404


def test_read_only_startup_probe_fails_until_projection_is_loaded() -> None:
    service = HostedProjectionService()
    app = create_read_only_app(
        service,
        response_plans=service,
        recovery=_RecoveryProjection(service),
        readiness=lambda: service.ready,
    )

    response = TestClient(app).get("/health/startup")

    assert response.status_code == 503
    assert response.json() == {"code": "hosted-read-not-ready"}


def test_hosted_app_validates_reader_binding_and_closes_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = MemoryStore()
    seed_fixture(store, _EXPECTED_FIXTURE_DIGEST)  # type: ignore[arg-type]
    calls: list[tuple[str, str]] = []

    class Factory:
        closed = False

        def close(self) -> None:
            self.closed = True

    factory = Factory()

    def build(**values: str) -> Factory:
        assert values == {
            "instance_connection_name": "project:us-central1:colortrace-staging",
            "database": "colortrace",
            "user": "colortrace-api@project.iam",
        }
        return factory

    class Verifier:
        def __init__(self, _factory: object, *, database: str, reader_role: str) -> None:
            calls.append((database, reader_role))

        def validate(self) -> None:
            calls.append(("validated", "validated"))

    monkeypatch.setattr(
        "colortrace_api.hosted_read.HostedProjectionPostgresStore", lambda *_a, **_k: store
    )
    monkeypatch.setattr("colortrace_api.hosted_read.PostgresReaderVerifier", Verifier)
    app = create_hosted_read_app(
        HostedServeConfig.from_environment(_environment()),
        factory_builder=build,  # type: ignore[arg-type]
    )

    with TestClient(app) as client:
        assert client.get("/health/startup").status_code == 200
        assert client.get("/v1/incidents").status_code == 200

    assert calls == [
        ("colortrace", "colortrace-api@project.iam"),
        ("validated", "validated"),
    ]
    assert factory.closed is True


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({CLOUD_SQL_INSTANCE_ENV: "public-host"}, "cloud-sql-instance-invalid"),
        ({FIXTURE_SHA256_ENV: "latest"}, "hosted-fixture-digest-invalid"),
        ({POSTGRES_API_ROLE_ENV: "bad role"}, "postgres-api-role-invalid"),
        ({PORT_ENV: "0"}, "bind-port-invalid"),
    ],
)
def test_serve_configuration_fails_closed(change: dict[str, str], code: str) -> None:
    environment = {**_environment(), **change}

    with pytest.raises(HostedReadConfigurationError, match=f"^{code}$"):
        HostedServeConfig.from_environment(environment)


def test_bootstrap_reads_private_file_and_never_places_password_in_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password_path = tmp_path / "postgres-admin"
    password_path.write_text("synthetic-admin-password", encoding="utf-8")
    password_path.chmod(0o600)
    environment = {
        **_environment(),
        POSTGRES_ADMIN_USER_ENV: "postgres",
        POSTGRES_ADMIN_PASSWORD_FILE_ENV: str(password_path),
    }
    config = HostedBootstrapConfig.from_environment(environment)
    calls: list[dict[str, str]] = []

    class Factory:
        closed = False

        def close(self) -> None:
            self.closed = True

    factory = Factory()

    def build(**values: str) -> Factory:
        calls.append(values)
        return factory

    class Bootstrapper:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def apply(self) -> None:
            pass

    monkeypatch.setattr("colortrace_api.hosted_read.PostgresRoleBootstrapper", Bootstrapper)

    bootstrap_database(config, factory_builder=build)  # type: ignore[arg-type]

    assert calls == [
        {
            "instance_connection_name": "project:us-central1:colortrace-staging",
            "database": "colortrace",
            "user": "postgres",
            "password": "synthetic-admin-password",
        }
    ]
    assert factory.closed is True
    assert "synthetic-admin-password" not in repr(config)


def test_bootstrap_rejects_nonprivate_or_linked_password_file(tmp_path: Path) -> None:
    password_path = tmp_path / "postgres-admin"
    password_path.write_text("synthetic-admin-password", encoding="utf-8")
    password_path.chmod(0o644)
    environment = {
        **_environment(),
        POSTGRES_ADMIN_USER_ENV: "postgres",
        POSTGRES_ADMIN_PASSWORD_FILE_ENV: str(password_path),
    }

    with pytest.raises(
        HostedReadConfigurationError,
        match="^postgres-admin-password-file-invalid$",
    ):
        bootstrap_database(HostedBootstrapConfig.from_environment(environment))

    password_path.chmod(0o600)
    link = tmp_path / "postgres-admin-link"
    link.symlink_to(password_path)
    environment[POSTGRES_ADMIN_PASSWORD_FILE_ENV] = str(link)
    with pytest.raises(
        HostedReadConfigurationError,
        match="^postgres-admin-password-file-invalid$",
    ):
        bootstrap_database(HostedBootstrapConfig.from_environment(environment))


def test_module_cli_admits_only_explicit_serve_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def run(application: str, **options: object) -> None:
        calls.append((application, options))

    monkeypatch.setattr("colortrace_api.hosted_read.uvicorn.run", run)

    main(["serve"], _environment())

    assert calls == [
        (
            "colortrace_api.hosted_read:create_application",
            {"factory": True, "host": "0.0.0.0", "port": 8080},
        )
    ]
    for arguments in ([], ["api"], ["serve", "extra"]):
        with pytest.raises(HostedReadConfigurationError, match="^hosted-command-invalid$"):
            main(arguments, _environment())
