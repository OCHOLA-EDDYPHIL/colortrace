from __future__ import annotations

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
    create_application,
    create_runtime_app,
)
from colortrace_api.__main__ import main
from colortrace_vertical_slice import SliceContractError, SqliteIncidentStore
from fastapi.testclient import TestClient
from jwt import PyJWK


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
        "COLORTRACE_OIDC_ISSUER": "https://identity.example.test/tenant",
        "COLORTRACE_OIDC_AUDIENCE": "colortrace-api",
        "COLORTRACE_OIDC_JWKS_URI": "https://identity.example.test/jwks",
        "COLORTRACE_OIDC_LEEWAY_SECONDS": "15",
    }


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


@pytest.mark.parametrize(
    "missing",
    [
        "COLORTRACE_DATABASE_PATH",
        "COLORTRACE_RESPONSE_PLAN_DATABASE_PATH",
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


def test_module_cli_uses_the_fail_closed_uvicorn_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def run(application: str, **options: object) -> None:
        calls.append((application, options))

    monkeypatch.setattr(uvicorn, "run", run)
    main()

    assert calls == [
        (
            "colortrace_api.runtime:create_application",
            {"factory": True, "host": "127.0.0.1", "port": 8000},
        )
    ]
