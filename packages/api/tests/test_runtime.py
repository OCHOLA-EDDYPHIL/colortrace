from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from colortrace_api import (
    ApiRuntimeConfig,
    ApiRuntimeConfigurationError,
    build_recovery_verification_task,
    create_application,
    create_runtime_app,
)
from colortrace_api.__main__ import main
from colortrace_vertical_slice import SliceContractError, SqliteIncidentStore
from fastapi.testclient import TestClient
from jwt import PyJWK

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True, slots=True)
class Accepted:
    incident_id: str

    def to_dict(self) -> dict[str, Any]:
        return {"schema": "incident-accepted/v1", "incident_id": self.incident_id}


class FactoryStore:
    def __init__(self) -> None:
        self.list_times: list[str] = []
        self.accepted: list[str] = []

    def accept_alert(
        self,
        alert: Mapping[str, Any],
        *,
        now: str,
        human_actor: Mapping[str, Any] | None = None,
    ) -> Accepted:
        assert human_actor is None
        self.accepted.append(now)
        return Accepted(str(alert["incident_id"]))

    def list_incidents(
        self,
        *,
        limit: int,
        cursor: str | None,
        now: str,
    ) -> dict[str, Any]:
        self.list_times.append(now)
        return {"schema": "incident-list/v1", "items": [], "next_cursor": None}

    def incident_view(self, incident_id: str) -> dict[str, Any]:
        raise SliceContractError("incident-not-found")

    def replay(self, incident_id: str) -> dict[str, Any]:
        raise SliceContractError("incident-not-found")

    def incident_workspace(self, incident_id: str) -> dict[str, Any]:
        raise SliceContractError("incident-not-found")


class NeverResolver:
    def resolve(self, kid: str) -> PyJWK:
        raise AssertionError(f"unexpected JWKS resolution for {kid}")


def environment(database_path: Path) -> dict[str, str]:
    return {
        "COLORTRACE_DATABASE_PATH": str(database_path),
        "COLORTRACE_RESPONSE_PLAN_DATABASE_PATH": str(
            database_path.with_name(f"{database_path.stem}-response-plans.sqlite3")
        ),
        "COLORTRACE_RECOVERY_DATABASE_PATH": str(
            database_path.with_name(f"{database_path.stem}-recovery.sqlite3")
        ),
        "COLORTRACE_OIDC_ISSUER": "https://identity.example.test/tenant",
        "COLORTRACE_OIDC_AUDIENCE": "colortrace-api",
        "COLORTRACE_OIDC_JWKS_URI": "https://identity.example.test/jwks",
        "COLORTRACE_OIDC_LEEWAY_SECONDS": "15",
    }


def canonical_demo_environment(tmp_path: Path) -> dict[str, str]:
    values = environment(tmp_path / "incidents.sqlite3")
    fixture = tmp_path / "fixture"
    manifest = fixture / "runtime" / "manifests" / "fixture-runtime-manifest.json"
    receipt = fixture / "reports" / "generation-receipt.json"
    manifest.parent.mkdir(parents=True)
    receipt.parent.mkdir(parents=True)
    manifest.write_bytes(b'{"schema":"fixture-runtime-manifest/v1"}\n')
    digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    receipt.write_text(
        json.dumps(
            {
                "fixture_runtime_manifest": "runtime/manifests/fixture-runtime-manifest.json",
                "fixture_runtime_manifest_sha256": digest,
            }
        ),
        encoding="utf-8",
    )
    ca_file = tmp_path / "grafana-ca.pem"
    token_file = tmp_path / "grafana-token"
    binary = tmp_path / "mcp-grafana"
    build_binding = tmp_path / "build-binding.json"
    ca_file.write_text("synthetic-ca", encoding="utf-8")
    token_file.write_text("synthetic-token", encoding="utf-8")
    token_file.chmod(0o600)
    binary.write_text("synthetic-binary", encoding="utf-8")
    binary.chmod(0o555)
    build_binding.write_text(
        json.dumps(
            {
                "schema": "colortrace-runtime-build-binding/v1",
                "source_commit": "a" * 40,
                "source_tree": "b" * 40,
            }
        ),
        encoding="utf-8",
    )
    values.update(
        {
            "COLORTRACE_SIMULATOR_MODE": "local",
            "COLORTRACE_SIMULATOR_DATABASE_PATH": str(tmp_path / "simulator.sqlite3"),
            "COLORTRACE_SIMULATOR_WORKSPACE_PATH": str(tmp_path / "simulator-workspace"),
            "COLORTRACE_SIMULATOR_FIXTURE_BUNDLE_PATH": str(fixture),
            "COLORTRACE_DEMO_MODE": "canonical",
            "COLORTRACE_DEMO_DATABASE_PATH": str(tmp_path / "demo.sqlite3"),
            "COLORTRACE_DEMO_VISUAL_ROOT": str(tmp_path / "demo-visuals"),
            "COLORTRACE_DEMO_CONFIG_PATH": str(
                REPOSITORY_ROOT / "config" / "demo" / "local-demo.json"
            ),
            "COLORTRACE_SOURCE_COMMIT": "a" * 40,
            "COLORTRACE_SOURCE_TREE": "b" * 40,
            "COLORTRACE_RUNTIME_IMAGE": f"registry.example.test/colortrace@sha256:{'c' * 64}",
            "COLORTRACE_PUBLIC_URL": "https://demo.example.test",
            "COLORTRACE_STAGING_GENERATION": "generation-1",
            "COLORTRACE_VERTEX_PROJECT_ID": "colortrace-project",
            "COLORTRACE_VERTEX_LOCATION": "global",
            "COLORTRACE_GRAFANA_URL": "https://grafana.internal.test",
            "COLORTRACE_GRAFANA_CA_FILE": str(ca_file),
            "COLORTRACE_GRAFANA_TOKEN_FILE": str(token_file),
            "COLORTRACE_MCP_BINARY": str(binary),
            "COLORTRACE_MCP_LOCK_PATH": str(
                REPOSITORY_ROOT / "config" / "grafana-mcp" / "mcp-grafana.lock.json"
            ),
            "COLORTRACE_QUERY_CATALOG_PATH": str(
                REPOSITORY_ROOT / "config" / "grafana-mcp" / "query-catalog.json"
            ),
            "COLORTRACE_INVESTIGATION_POLICY_PATH": str(
                REPOSITORY_ROOT / "config" / "investigation" / "investigation-policy.json"
            ),
            "COLORTRACE_MODEL_PROFILE_PATH": str(
                REPOSITORY_ROOT / "config" / "investigation" / "model-profile.json"
            ),
            "COLORTRACE_BUILD_BINDING_PATH": str(build_binding),
            "COLORTRACE_FIXTURE_BUNDLE_SHA256": f"sha256:{digest}",
            "OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel-lgtm:4318",
        }
    )
    return values


def fixed_clock() -> datetime:
    return datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


def test_environment_factory_composes_public_reads_without_auth_bypass(tmp_path: Path) -> None:
    store = FactoryStore()
    store_paths: list[Path] = []
    resolver_uris: list[str] = []

    def store_factory(path: Path) -> object:
        store_paths.append(path)
        return store

    def resolver_factory(uri: str) -> NeverResolver:
        resolver_uris.append(uri)
        return NeverResolver()

    app = create_application(
        environment(tmp_path / "incidents.sqlite3"),
        store_factory=store_factory,
        resolver_factory=resolver_factory,
        clock=fixed_clock,
    )
    api_client = TestClient(app)

    public_list = api_client.get("/v1/incidents")
    assert public_list.status_code == 200
    assert public_list.json() == {
        "schema": "incident-list/v1",
        "items": [],
        "next_cursor": None,
    }
    assert api_client.get("/v1/incidents/missing").status_code == 404
    assert api_client.get("/v1/incidents/missing/workspace").status_code == 404
    assert api_client.get("/v1/session").status_code == 401
    assert api_client.post("/v1/incidents", json={"incident_id": "blocked"}).status_code == 401
    assert store.accepted == []
    assert store.list_times == ["2026-08-13T12:00:00.000Z"]
    assert store_paths == [tmp_path / "incidents.sqlite3"]
    assert resolver_uris == ["https://identity.example.test/jwks"]
    assert app.state.recovery_verification_task_store is None


def test_explicit_recovery_task_database_composes_durable_admission(tmp_path: Path) -> None:
    values = environment(tmp_path / "incidents.sqlite3")
    task_path = tmp_path / "recovery-tasks.sqlite3"
    values["COLORTRACE_RECOVERY_TASK_DATABASE_PATH"] = str(task_path)
    config = ApiRuntimeConfig.from_environment(values)

    app = create_runtime_app(
        config,
        store_factory=lambda _path: FactoryStore(),
        resolver_factory=lambda _uri: NeverResolver(),
        clock=fixed_clock,
    )
    task = build_recovery_verification_task(
        incident_id="incident-runtime-recovery",
        expected_incident_version=1,
        expected_outcome_sha256=f"sha256:{'a' * 64}",
        idempotency_key="runtime-recovery-task",
    )

    first = app.state.recovery_verification_task_store.dispatch(task)
    duplicate = app.state.recovery_verification_task_store.dispatch(task)

    assert config.recovery_task_database_path == task_path
    assert task_path.is_file()
    assert first["duplicate"] is False
    assert duplicate == {**first, "duplicate": True}


@pytest.mark.parametrize(
    "missing",
    [
        "COLORTRACE_DATABASE_PATH",
        "COLORTRACE_RESPONSE_PLAN_DATABASE_PATH",
        "COLORTRACE_RECOVERY_DATABASE_PATH",
        "COLORTRACE_OIDC_ISSUER",
        "COLORTRACE_OIDC_AUDIENCE",
        "COLORTRACE_OIDC_JWKS_URI",
    ],
)
def test_factory_fails_closed_when_required_environment_is_missing(
    tmp_path: Path,
    missing: str,
) -> None:
    values = environment(tmp_path / "incidents.sqlite3")
    values.pop(missing)

    with pytest.raises(ApiRuntimeConfigurationError) as error:
        create_application(values, store_factory=lambda _path: FactoryStore())
    assert "https://identity.example.test" not in str(error.value)


@pytest.mark.parametrize(
    ("field", "value", "expected_code"),
    [
        ("COLORTRACE_DATABASE_PATH", "relative.sqlite3", "database-path-invalid"),
        (
            "COLORTRACE_RESPONSE_PLAN_DATABASE_PATH",
            "relative.sqlite3",
            "database-path-invalid",
        ),
        ("COLORTRACE_RECOVERY_DATABASE_PATH", "relative.sqlite3", "database-path-invalid"),
        (
            "COLORTRACE_RECOVERY_TASK_DATABASE_PATH",
            "relative.sqlite3",
            "database-path-invalid",
        ),
        (
            "COLORTRACE_OIDC_ISSUER",
            "http://identity.example.test/tenant",
            "oidc-configuration-invalid",
        ),
        (
            "COLORTRACE_OIDC_JWKS_URI",
            "http://identity.example.test/jwks",
            "oidc-configuration-invalid",
        ),
        ("COLORTRACE_OIDC_LEEWAY_SECONDS", "121", "oidc-configuration-invalid"),
        ("COLORTRACE_OIDC_LEEWAY_SECONDS", "not-a-number", "oidc-leeway-invalid"),
    ],
)
def test_factory_rejects_invalid_database_and_oidc_configuration(
    tmp_path: Path,
    field: str,
    value: str,
    expected_code: str,
) -> None:
    values = environment(tmp_path / "incidents.sqlite3")
    values[field] = value

    with pytest.raises(ApiRuntimeConfigurationError) as error:
        create_application(values, store_factory=lambda _path: FactoryStore())
    assert error.value.code == expected_code
    assert value not in str(error.value)


def test_factory_rejects_store_without_authoritative_read_methods(tmp_path: Path) -> None:
    config = ApiRuntimeConfig.from_environment(environment(tmp_path / "incidents.sqlite3"))

    with pytest.raises(ApiRuntimeConfigurationError) as error:
        create_runtime_app(config, store_factory=lambda _path: object())
    assert error.value.code == "incident-store-incompatible"


def test_factory_rejects_overlapping_authority_databases(tmp_path: Path) -> None:
    values = environment(tmp_path / "incidents.sqlite3")
    values["COLORTRACE_RECOVERY_DATABASE_PATH"] = values["COLORTRACE_RESPONSE_PLAN_DATABASE_PATH"]

    with pytest.raises(ApiRuntimeConfigurationError) as error:
        ApiRuntimeConfig.from_environment(values)
    assert error.value.code == "database-path-overlap"


def test_canonical_demo_environment_binds_deployment_inputs(tmp_path: Path) -> None:
    values = canonical_demo_environment(tmp_path)

    config = ApiRuntimeConfig.from_environment(values)

    assert config.simulator_mode == "local"
    assert config.simulator_fixture_bundle_path == tmp_path / "fixture"
    assert config.demo is not None
    assert config.demo.database_path == tmp_path / "demo.sqlite3"
    assert config.demo.visual_root == tmp_path / "demo-visuals"
    assert config.demo.source_commit == "a" * 40
    assert config.demo.source_tree == "b" * 40
    assert config.demo.fixture_bundle_sha256 == values["COLORTRACE_FIXTURE_BUNDLE_SHA256"]
    assert config.demo.grafana_ca_file == tmp_path / "grafana-ca.pem"
    assert config.demo.otlp_endpoint == "http://otel-lgtm:4318"


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ({"COLORTRACE_SIMULATOR_MODE": "disabled"}, "simulator-configuration-invalid"),
        ({"COLORTRACE_VERTEX_LOCATION": "us-central1"}, "demo-vertex-location-invalid"),
        (
            {"COLORTRACE_FIXTURE_BUNDLE_SHA256": f"sha256:{'f' * 64}"},
            "demo-fixture-digest-conflict",
        ),
        ({"COLORTRACE_PUBLIC_URL": "http://demo.example.test"}, "demo-public-url-invalid"),
    ],
)
def test_canonical_demo_environment_rejects_drift(
    tmp_path: Path,
    mutation: Mapping[str, str],
    code: str,
) -> None:
    values = canonical_demo_environment(tmp_path)
    values.update(mutation)

    with pytest.raises(ApiRuntimeConfigurationError) as error:
        ApiRuntimeConfig.from_environment(values)

    assert error.value.code == code


def test_default_sqlite_composition_when_read_methods_are_available(tmp_path: Path) -> None:
    config = ApiRuntimeConfig.from_environment(environment(tmp_path / "real.sqlite3"))
    required = ("list_incidents", "incident_workspace")

    if not all(callable(getattr(SqliteIncidentStore, name, None)) for name in required):
        with pytest.raises(ApiRuntimeConfigurationError) as error:
            create_runtime_app(config)
        assert error.value.code == "incident-store-incompatible"
        return

    api_client = TestClient(create_runtime_app(config))
    incident_list = api_client.get("/v1/incidents")
    assert incident_list.status_code == 200
    assert incident_list.json() == {
        "schema": "incident-list/v1",
        "items": [],
        "next_cursor": None,
    }
    missing = api_client.get("/v1/incidents/missing/workspace")
    assert missing.status_code == 404
    assert missing.json() == {"code": "incident-not-found"}


def test_module_cli_constructs_application_before_uvicorn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    application = object()

    async def verify_inventory() -> None:
        calls.append("inventory-verified")

    def create(environment: Mapping[str, str]) -> object:
        assert environment == {}
        asyncio.run(verify_inventory())
        calls.append("application-created")
        return application

    def run(selected: object, **options: object) -> None:
        assert selected is application
        assert options == {"host": "127.0.0.1", "port": 8000}
        calls.append("uvicorn-started")

    monkeypatch.setattr("colortrace_api.__main__.create_application", create)
    monkeypatch.setattr(uvicorn, "run", run)
    main({})

    assert calls == ["inventory-verified", "application-created", "uvicorn-started"]


def test_module_cli_fails_before_uvicorn_when_application_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def create(environment: Mapping[str, str]) -> object:
        assert environment == {}
        raise ApiRuntimeConfigurationError("demo-runtime-configuration-invalid")

    def run(application: object, **options: object) -> None:
        raise AssertionError("Uvicorn must not start for an invalid application")

    monkeypatch.setattr("colortrace_api.__main__.create_application", create)
    monkeypatch.setattr(uvicorn, "run", run)

    with pytest.raises(ApiRuntimeConfigurationError) as error:
        main({})

    assert str(error.value) == "demo-runtime-configuration-invalid"


def test_module_cli_accepts_the_cloud_run_bind_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, dict[str, object]]] = []
    application = object()
    environment = {"COLORTRACE_BIND_HOST": "0.0.0.0", "PORT": "8080"}

    def create(selected: Mapping[str, str]) -> object:
        assert selected == environment
        return application

    monkeypatch.setattr("colortrace_api.__main__.create_application", create)
    monkeypatch.setattr(
        uvicorn, "run", lambda selected, **options: calls.append((selected, options))
    )
    main(environment)

    assert calls == [
        (
            application,
            {"host": "0.0.0.0", "port": 8080},
        )
    ]


@pytest.mark.parametrize(
    "environment",
    [
        {"COLORTRACE_BIND_HOST": "example.test"},
        {"PORT": "0"},
        {"PORT": "65536"},
        {"PORT": "eight-thousand"},
    ],
)
def test_module_cli_rejects_unbounded_bind_configuration(
    monkeypatch: pytest.MonkeyPatch,
    environment: dict[str, str],
) -> None:
    monkeypatch.setattr(uvicorn, "run", lambda *_args, **_kwargs: None)

    with pytest.raises(ValueError, match="bind-(?:host|port)-invalid"):
        main(environment)
