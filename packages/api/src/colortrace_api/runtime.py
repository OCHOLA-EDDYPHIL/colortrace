from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import os
import re
import secrets
import stat
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

from colortrace_grafana_mcp import EvidenceAdapter, OfficialMcpRuntime, QueryCatalog
from colortrace_investigation import (
    AdkVertexGateway,
    ColorStateValidatorGateway,
    InvestigationPolicy,
)
from colortrace_recovery import (
    DeterministicRecoveryVerifier,
    RecoveryClosureService,
    RecoveryIdentityBoundary,
    RecoveryReadService,
    RecoveryVerificationService,
    SQLiteRecoveryRepository,
    SynchronousRecoveryWorkflowRunner,
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
from colortrace_vertical_slice import SqliteIncidentStore, VerticalSliceApi, VerticalSliceWorker
from fastapi import FastAPI
from starlette.types import Lifespan

from .app import create_app
from .demo_facade import (
    APPROVAL_PHRASE,
    BUILD_PROVENANCE_SCHEMA,
    CANONICAL_SCENARIO,
    DemoFacade,
    SQLiteDemoRunStore,
)
from .demo_workflow import (
    CanonicalDemoWorkflow,
    GrafanaMcpAlertProbe,
    LiveCanonicalAlertSource,
)
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
DEMO_MODE_ENV = "COLORTRACE_DEMO_MODE"
DEMO_DATABASE_PATH_ENV = "COLORTRACE_DEMO_DATABASE_PATH"
DEMO_VISUAL_ROOT_ENV = "COLORTRACE_DEMO_VISUAL_ROOT"
DEMO_CONFIG_PATH_ENV = "COLORTRACE_DEMO_CONFIG_PATH"
SOURCE_COMMIT_ENV = "COLORTRACE_SOURCE_COMMIT"
SOURCE_TREE_ENV = "COLORTRACE_SOURCE_TREE"
RUNTIME_IMAGE_ENV = "COLORTRACE_RUNTIME_IMAGE"
PUBLIC_URL_ENV = "COLORTRACE_PUBLIC_URL"
STAGING_GENERATION_ENV = "COLORTRACE_STAGING_GENERATION"
VERTEX_PROJECT_ID_ENV = "COLORTRACE_VERTEX_PROJECT_ID"
VERTEX_LOCATION_ENV = "COLORTRACE_VERTEX_LOCATION"
GRAFANA_URL_ENV = "COLORTRACE_GRAFANA_URL"
GRAFANA_CA_FILE_ENV = "COLORTRACE_GRAFANA_CA_FILE"
GRAFANA_TOKEN_FILE_ENV = "COLORTRACE_GRAFANA_TOKEN_FILE"
MCP_BINARY_ENV = "COLORTRACE_MCP_BINARY"
MCP_LOCK_PATH_ENV = "COLORTRACE_MCP_LOCK_PATH"
QUERY_CATALOG_PATH_ENV = "COLORTRACE_QUERY_CATALOG_PATH"
INVESTIGATION_POLICY_PATH_ENV = "COLORTRACE_INVESTIGATION_POLICY_PATH"
MODEL_PROFILE_PATH_ENV = "COLORTRACE_MODEL_PROFILE_PATH"
FIXTURE_BUNDLE_SHA256_ENV = "COLORTRACE_FIXTURE_BUNDLE_SHA256"
OTLP_ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_ENDPOINT"
BUILD_BINDING_PATH_ENV = "COLORTRACE_BUILD_BINDING_PATH"
DEFAULT_BUILD_BINDING_PATH = "/opt/colortrace-config/build-binding.json"
_DEMO_ENVIRONMENTS = (
    DEMO_DATABASE_PATH_ENV,
    DEMO_VISUAL_ROOT_ENV,
    DEMO_CONFIG_PATH_ENV,
    SOURCE_COMMIT_ENV,
    SOURCE_TREE_ENV,
    RUNTIME_IMAGE_ENV,
    PUBLIC_URL_ENV,
    STAGING_GENERATION_ENV,
    VERTEX_PROJECT_ID_ENV,
    VERTEX_LOCATION_ENV,
    GRAFANA_URL_ENV,
    GRAFANA_CA_FILE_ENV,
    GRAFANA_TOKEN_FILE_ENV,
    MCP_BINARY_ENV,
    MCP_LOCK_PATH_ENV,
    QUERY_CATALOG_PATH_ENV,
    INVESTIGATION_POLICY_PATH_ENV,
    MODEL_PROFILE_PATH_ENV,
    FIXTURE_BUNDLE_SHA256_ENV,
    BUILD_BINDING_PATH_ENV,
)

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DEMO_CONFIG_FIELDS = frozenset(
    {
        "schema",
        "incident_id",
        "incident_version",
        "fixture_variant",
        "fixture_seed",
        "issuer",
        "audience",
        "approval_phrase",
    }
)
_EVIDENCE_BINDING = {
    "prometheus_datasource_uid": "prometheus",
    "loki_datasource_uid": "loki",
    "tempo_datasource_uid": "tempo",
}
_ALERT_RULE_UID = "ct-declared-reference-divergence-v1"


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
        otlp_endpoint: str | None,
        clock: Callable[[], datetime] | None,
    ) -> LocalSimulatorRuntime: ...


@dataclass(frozen=True, slots=True)
class CanonicalDemoRuntimeConfig:
    database_path: Path
    visual_root: Path
    config_path: Path
    source_commit: str
    source_tree: str
    runtime_image: str
    public_url: str
    staging_generation: str
    vertex_project_id: str
    vertex_location: str
    grafana_url: str
    grafana_ca_file: Path
    grafana_token_file: Path
    mcp_binary: Path
    mcp_lock_path: Path
    query_catalog_path: Path
    investigation_policy_path: Path
    model_profile_path: Path
    build_binding_path: Path
    fixture_bundle_sha256: str
    otlp_endpoint: str


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
    demo: CanonicalDemoRuntimeConfig | None = None

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
        demo = _demo_environment(environment, fixture_bundle=simulator_paths[2])
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
            demo=demo,
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


def _regular_file(value: str | Path, *, code: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or len(str(path)) > 4_096:
        raise ApiRuntimeConfigurationError(code)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        raise ApiRuntimeConfigurationError(code) from None
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        raise ApiRuntimeConfigurationError(code)
    return path


def _origin(value: str, *, schemes: frozenset[str], code: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in schemes
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ApiRuntimeConfigurationError(code)
    return value.rstrip("/")


def _fixture_manifest_sha256(fixture_bundle: Path) -> str:
    manifest = _regular_file(
        fixture_bundle / "runtime" / "manifests" / "fixture-runtime-manifest.json",
        code="demo-fixture-invalid",
    )
    receipt_path = _regular_file(
        fixture_bundle / "reports" / "generation-receipt.json",
        code="demo-fixture-invalid",
    )
    try:
        raw = manifest.read_bytes()
        receipt_raw = receipt_path.read_bytes()
        receipt = json.loads(receipt_raw)
    except (OSError, UnicodeError, ValueError):
        raise ApiRuntimeConfigurationError("demo-fixture-invalid") from None
    digest = hashlib.sha256(raw).hexdigest()
    if (
        not isinstance(receipt, dict)
        or receipt.get("fixture_runtime_manifest")
        != "runtime/manifests/fixture-runtime-manifest.json"
        or receipt.get("fixture_runtime_manifest_sha256") != digest
    ):
        raise ApiRuntimeConfigurationError("demo-fixture-invalid")
    return f"sha256:{digest}"


def _file_sha256(path: Path) -> str:
    try:
        return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    except OSError:
        raise ApiRuntimeConfigurationError("demo-provenance-invalid") from None


def _strict_json_file(path: Path, *, code: str) -> dict[str, Any]:
    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        selected: dict[str, Any] = {}
        for key, child in pairs:
            if key in selected:
                raise ValueError("duplicate key")
            selected[key] = child
        return selected

    try:
        raw = path.read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
    except (OSError, UnicodeError, ValueError):
        raise ApiRuntimeConfigurationError(code) from None
    if not isinstance(value, dict):
        raise ApiRuntimeConfigurationError(code)
    return cast(dict[str, Any], value)


def _validate_demo_config(path: Path) -> None:
    value = _strict_json_file(path, code="demo-config-invalid")
    if (
        set(value) != _DEMO_CONFIG_FIELDS
        or value.get("schema") != "colortrace-local-demo-config/v1"
        or value.get("fixture_variant") != "canonical"
        or value.get("fixture_seed") != CANONICAL_SCENARIO
        or value.get("approval_phrase") != APPROVAL_PHRASE
    ):
        raise ApiRuntimeConfigurationError("demo-config-invalid")


def _validate_build_binding(path: Path, *, source_commit: str, source_tree: str) -> None:
    value = _strict_json_file(path, code="demo-build-binding-invalid")
    if value != {
        "schema": "colortrace-runtime-build-binding/v1",
        "source_commit": source_commit,
        "source_tree": source_tree,
    }:
        raise ApiRuntimeConfigurationError("demo-build-binding-invalid")


def _prepare_private_directory(path: Path) -> Path:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    except OSError:
        raise ApiRuntimeConfigurationError("demo-visual-root-invalid") from None
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        raise ApiRuntimeConfigurationError("demo-visual-root-invalid") from None
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ApiRuntimeConfigurationError("demo-visual-root-invalid")
    return path


def _demo_build_provenance(
    config: CanonicalDemoRuntimeConfig,
    *,
    inventory: Mapping[str, Any],
    catalog: QueryCatalog,
    policy: InvestigationPolicy,
) -> dict[str, Any]:
    lock = _strict_json_file(config.mcp_lock_path, code="demo-mcp-lock-invalid")
    profile = _strict_json_file(config.model_profile_path, code="demo-model-profile-invalid")
    inventory_version = inventory.get("inventory_version")
    if not isinstance(inventory_version, str) or _DIGEST.fullmatch(inventory_version) is None:
        raise ApiRuntimeConfigurationError("demo-mcp-inventory-invalid")
    expected_versions = {
        "google-adk": profile.get("google_adk_version"),
        "google-genai": profile.get("google_genai_version"),
        "mcp": lock.get("mcp_sdk_version"),
    }
    versions: dict[str, str] = {}
    for distribution, expected in expected_versions.items():
        try:
            observed = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            raise ApiRuntimeConfigurationError("demo-package-version-invalid") from None
        if observed != expected:
            raise ApiRuntimeConfigurationError("demo-package-version-invalid")
        versions[distribution] = observed
    binary_sha256 = _file_sha256(config.mcp_binary)
    if binary_sha256.removeprefix("sha256:") != lock.get("binary_sha256"):
        raise ApiRuntimeConfigurationError("demo-mcp-binary-invalid")
    return {
        "schema": BUILD_PROVENANCE_SCHEMA,
        "source_commit": config.source_commit,
        "source_tree": config.source_tree,
        "runtime_image": config.runtime_image,
        "public_url": config.public_url,
        "staging_generation": config.staging_generation,
        "fixture_manifest_sha256": config.fixture_bundle_sha256,
        "configuration": {
            "demo_sha256": _file_sha256(config.config_path),
            "build_binding_sha256": _file_sha256(config.build_binding_path),
            "investigation_policy_sha256": policy.digest,
            "model_profile_sha256": policy.model_profile_digest,
            "query_catalog_sha256": catalog.digest,
        },
        "model": {
            "provider": profile.get("provider"),
            "framework": profile.get("framework"),
            "model": profile.get("model"),
            "location": profile.get("location"),
            "versions": versions,
        },
        "mcp": {
            "source_commit": lock.get("source_commit"),
            "source_version": lock.get("release_version"),
            "binary_sha256": binary_sha256,
            "inventory_sha256": inventory_version,
            "transport": lock.get("mcp_transport"),
            "write_tools_enabled": lock.get("write_tools_enabled"),
        },
    }


def _demo_environment(
    environment: Mapping[str, str],
    *,
    fixture_bundle: Path | None,
) -> CanonicalDemoRuntimeConfig | None:
    mode = environment.get(DEMO_MODE_ENV, "disabled")
    if mode == "disabled":
        if any(name in environment for name in _DEMO_ENVIRONMENTS):
            raise ApiRuntimeConfigurationError("demo-configuration-invalid")
        return None
    if mode != "canonical" or fixture_bundle is None:
        raise ApiRuntimeConfigurationError("demo-configuration-invalid")
    commit = _required(environment, SOURCE_COMMIT_ENV)
    tree = _required(environment, SOURCE_TREE_ENV)
    image = _required(environment, RUNTIME_IMAGE_ENV)
    generation = _required(environment, STAGING_GENERATION_ENV)
    fixture_digest = _required(environment, FIXTURE_BUNDLE_SHA256_ENV)
    if (
        _HEX40.fullmatch(commit) is None
        or _HEX40.fullmatch(tree) is None
        or _IMAGE.fullmatch(image) is None
        or _IDENTIFIER.fullmatch(generation) is None
        or _DIGEST.fullmatch(fixture_digest) is None
    ):
        raise ApiRuntimeConfigurationError("demo-build-binding-invalid")
    observed_fixture_digest = _fixture_manifest_sha256(fixture_bundle)
    if not secrets.compare_digest(observed_fixture_digest, fixture_digest):
        raise ApiRuntimeConfigurationError("demo-fixture-digest-conflict")
    config_path = _regular_file(
        _required(environment, DEMO_CONFIG_PATH_ENV), code="demo-config-invalid"
    )
    _validate_demo_config(config_path)
    build_binding_path = _regular_file(
        environment.get(BUILD_BINDING_PATH_ENV, DEFAULT_BUILD_BINDING_PATH),
        code="demo-build-binding-invalid",
    )
    _validate_build_binding(
        build_binding_path,
        source_commit=commit,
        source_tree=tree,
    )
    vertex_location = _required(environment, VERTEX_LOCATION_ENV)
    if vertex_location != "global":
        raise ApiRuntimeConfigurationError("demo-vertex-location-invalid")
    return CanonicalDemoRuntimeConfig(
        database_path=_database_path(_required(environment, DEMO_DATABASE_PATH_ENV)),
        visual_root=_directory_path(_required(environment, DEMO_VISUAL_ROOT_ENV), must_exist=False),
        config_path=config_path,
        source_commit=commit,
        source_tree=tree,
        runtime_image=image,
        public_url=_origin(
            _required(environment, PUBLIC_URL_ENV),
            schemes=frozenset({"https"}),
            code="demo-public-url-invalid",
        ),
        staging_generation=generation,
        vertex_project_id=_required(environment, VERTEX_PROJECT_ID_ENV),
        vertex_location=vertex_location,
        grafana_url=_origin(
            _required(environment, GRAFANA_URL_ENV),
            schemes=frozenset({"https"}),
            code="demo-grafana-url-invalid",
        ),
        grafana_ca_file=_regular_file(
            _required(environment, GRAFANA_CA_FILE_ENV), code="demo-grafana-ca-invalid"
        ),
        grafana_token_file=_regular_file(
            _required(environment, GRAFANA_TOKEN_FILE_ENV), code="demo-grafana-token-invalid"
        ),
        mcp_binary=_regular_file(
            environment.get(MCP_BINARY_ENV, "/usr/local/bin/mcp-grafana"),
            code="demo-mcp-binary-invalid",
        ),
        mcp_lock_path=_regular_file(
            _required(environment, MCP_LOCK_PATH_ENV), code="demo-mcp-lock-invalid"
        ),
        query_catalog_path=_regular_file(
            _required(environment, QUERY_CATALOG_PATH_ENV), code="demo-query-catalog-invalid"
        ),
        investigation_policy_path=_regular_file(
            _required(environment, INVESTIGATION_POLICY_PATH_ENV),
            code="demo-investigation-policy-invalid",
        ),
        model_profile_path=_regular_file(
            _required(environment, MODEL_PROFILE_PATH_ENV), code="demo-model-profile-invalid"
        ),
        build_binding_path=build_binding_path,
        fixture_bundle_sha256=fixture_digest,
        otlp_endpoint=_origin(
            _required(environment, OTLP_ENDPOINT_ENV),
            schemes=frozenset({"http", "https"}),
            code="demo-otlp-endpoint-invalid",
        ),
    )


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
    otlp_endpoint: str | None,
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
        sink = ActionOtelSink() if otlp_endpoint is None else ActionOtelSink(otlp_endpoint)
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


def _validate_demo_runtime_config(
    config: CanonicalDemoRuntimeConfig,
    *,
    fixture_bundle: Path,
) -> None:
    if (
        _HEX40.fullmatch(config.source_commit) is None
        or _HEX40.fullmatch(config.source_tree) is None
        or _IMAGE.fullmatch(config.runtime_image) is None
        or _IDENTIFIER.fullmatch(config.staging_generation) is None
        or _DIGEST.fullmatch(config.fixture_bundle_sha256) is None
        or config.vertex_location != "global"
    ):
        raise ApiRuntimeConfigurationError("demo-build-binding-invalid")
    _database_path(config.database_path)
    _directory_path(config.visual_root, must_exist=False)
    _origin(config.public_url, schemes=frozenset({"https"}), code="demo-public-url-invalid")
    _origin(config.grafana_url, schemes=frozenset({"https"}), code="demo-grafana-url-invalid")
    _origin(
        config.otlp_endpoint,
        schemes=frozenset({"http", "https"}),
        code="demo-otlp-endpoint-invalid",
    )
    for path, code in (
        (config.config_path, "demo-config-invalid"),
        (config.grafana_ca_file, "demo-grafana-ca-invalid"),
        (config.grafana_token_file, "demo-grafana-token-invalid"),
        (config.mcp_binary, "demo-mcp-binary-invalid"),
        (config.mcp_lock_path, "demo-mcp-lock-invalid"),
        (config.query_catalog_path, "demo-query-catalog-invalid"),
        (config.investigation_policy_path, "demo-investigation-policy-invalid"),
        (config.model_profile_path, "demo-model-profile-invalid"),
        (config.build_binding_path, "demo-build-binding-invalid"),
    ):
        _regular_file(path, code=code)
    _validate_demo_config(config.config_path)
    _validate_build_binding(
        config.build_binding_path,
        source_commit=config.source_commit,
        source_tree=config.source_tree,
    )
    observed = _fixture_manifest_sha256(fixture_bundle)
    if not secrets.compare_digest(observed, config.fixture_bundle_sha256):
        raise ApiRuntimeConfigurationError("demo-fixture-digest-conflict")


def _compose_canonical_demo(
    config: CanonicalDemoRuntimeConfig,
    *,
    incident_store: object,
    response_plans: ResponsePlanCoordinator,
    simulator_actions: SimulatorActionCoordinator | None,
    local_simulator: LocalSimulatorRuntime | None,
    recovery: RecoveryCoordinator,
    recovery_repository: SQLiteRecoveryRepository,
    recovery_identity_boundary: RecoveryIdentityBoundary,
    fixture_bundle: Path,
    issuer: str,
    audience: str,
    clock: Callable[[], datetime],
) -> tuple[DemoFacade, CanonicalDemoWorkflow]:
    _validate_demo_runtime_config(config, fixture_bundle=fixture_bundle)
    if (
        not isinstance(incident_store, SqliteIncidentStore)
        or simulator_actions is None
        or local_simulator is None
        or not isinstance(local_simulator.repository, SQLiteSimulatorRepository)
        or not isinstance(local_simulator.recovery_publication, LocalPublicationPort)
    ):
        raise ApiRuntimeConfigurationError("demo-runtime-incompatible")
    try:
        runtime = OfficialMcpRuntime.verify(
            grafana_url=config.grafana_url,
            token_file=config.grafana_token_file,
            binary=config.mcp_binary,
            lock_path=config.mcp_lock_path,
            tls_ca_file=config.grafana_ca_file,
        )
        catalog = QueryCatalog.load(config.query_catalog_path)
        policy = InvestigationPolicy.load(
            config.investigation_policy_path,
            config.model_profile_path,
        )
        evidence = EvidenceAdapter(runtime=runtime, catalog=catalog, clock=clock)
        inventory = asyncio.run(evidence.verify_inventory()).to_dict()
        model = AdkVertexGateway(project_id=config.vertex_project_id)
        incidents = VerticalSliceApi(incident_store, clock=clock)
        investigation = VerticalSliceWorker(
            incident_store,
            policy=policy,
            model=model,
            evidence=cast(Any, evidence),
            validator=ColorStateValidatorGateway(),
            clock=clock,
            owner_id=f"demo-investigator:{config.staging_generation}",
        )
        verification = RecoveryVerificationService(
            repository=recovery_repository,
            identity_boundary=recovery_identity_boundary,
            clock=clock,
        )
        verifier = DeterministicRecoveryVerifier(
            outcomes=local_simulator.repository,
            publication=local_simulator.recovery_publication,
            collector=evidence,
            verification=verification,
            reads=RecoveryReadService(recovery_repository),
            evidence_binding=_EVIDENCE_BINDING,
            evidence_catalog_sha256=catalog.digest,
            claim_owner=f"demo-recovery:{config.staging_generation}",
            clock=clock,
        )
        visual_root = _prepare_private_directory(config.visual_root)
        workflow = CanonicalDemoWorkflow(
            incidents=incidents,
            investigation=investigation,
            response_plans=response_plans,
            simulator_actions=simulator_actions,
            simulator_runtime=local_simulator,
            recovery=recovery,
            recovery_runner=SynchronousRecoveryWorkflowRunner(verifier),
            recovery_identity=recovery_identity_boundary,
            alert_source=LiveCanonicalAlertSource(
                fixture_bundle=fixture_bundle,
                otlp_endpoint=config.otlp_endpoint,
                evidence_binding=_EVIDENCE_BINDING,
                alert_rule_uid=_ALERT_RULE_UID,
                alert_probe=GrafanaMcpAlertProbe(evidence=evidence, clock=clock),
            ),
            fixture_bundle=fixture_bundle,
            visual_root=visual_root,
            issuer=issuer,
            audience=audience,
            clock=clock,
        )
        provenance = _demo_build_provenance(
            config,
            inventory=inventory,
            catalog=catalog,
            policy=policy,
        )
        facade = DemoFacade(
            store=SQLiteDemoRunStore(config.database_path),
            workflow=workflow,
            source_commit=config.source_commit,
            visual_root=visual_root,
            build_provenance=provenance,
            recovery=recovery,
            scenario_reset=local_simulator,
            closure_principal_factory=workflow.closure_principal,
            clock=clock,
            reconcile_on_startup=False,
        )
    except ApiRuntimeConfigurationError:
        raise
    except Exception:
        raise ApiRuntimeConfigurationError("demo-runtime-configuration-invalid") from None
    return facade, workflow


def _runtime_lifespan(
    local_simulator: LocalSimulatorRuntime,
    demo_facade: DemoFacade | None,
) -> Lifespan[FastAPI]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with local_simulator.lifespan(app):
            if demo_facade is not None:
                demo_facade.reconcile_startup()
            yield

    return lifespan


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
    if config.demo is not None:
        if local_simulator_paths is None:
            raise ApiRuntimeConfigurationError("demo-runtime-incompatible")
        _validate_demo_runtime_config(
            config.demo,
            fixture_bundle=local_simulator_paths[2],
        )
        demo_paths = (
            *database_paths,
            *local_simulator_paths,
            _database_path(config.demo.database_path),
            _directory_path(config.demo.visual_root, must_exist=False),
        )
        for index, left in enumerate(demo_paths):
            for right in demo_paths[index + 1 :]:
                if left == right or left in right.parents or right in left.parents:
                    raise ApiRuntimeConfigurationError("demo-path-overlap")
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
        raw_store = store_factory(database_path)
        store = _stored_incident_store(raw_store)
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
                otlp_endpoint=None if config.demo is None else config.demo.otlp_endpoint,
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
    demo_facade: DemoFacade | None = None
    demo_workflow: CanonicalDemoWorkflow | None = None
    if config.demo is not None:
        if local_simulator_paths is None:
            raise ApiRuntimeConfigurationError("demo-runtime-incompatible")
        demo_facade, demo_workflow = _compose_canonical_demo(
            config.demo,
            incident_store=raw_store,
            response_plans=response_plans,
            simulator_actions=simulator_actions,
            local_simulator=local_simulator,
            recovery=recovery,
            recovery_repository=recovery_repository,
            recovery_identity_boundary=recovery_identity_boundary,
            fixture_bundle=local_simulator_paths[2],
            issuer=config.oidc_issuer,
            audience=config.oidc_audience,
            clock=selected_clock,
        )
    app = create_app(
        service,
        token_verifier=verifier,
        response_plans=response_plans,
        simulator_actions=simulator_actions,
        recovery=recovery,
        recovery_verifications=None if recovery_task_store is None else recovery,
        demo=demo_facade,
        lifespan=(
            None if local_simulator is None else _runtime_lifespan(local_simulator, demo_facade)
        ),
    )
    app.state.local_simulator_runtime = local_simulator
    app.state.recovery_repository = recovery_repository
    app.state.recovery_verification_task_store = recovery_task_store
    app.state.demo_facade = demo_facade
    app.state.demo_workflow = demo_workflow
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
