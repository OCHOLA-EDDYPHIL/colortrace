from __future__ import annotations

import asyncio
import hashlib
import hmac
import importlib.metadata
import json
import os
import re
import stat
import subprocess
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import McpError
from referencing import Registry, Resource

MCP_GRAFANA_VERSION = "1.1.0"
MCP_GRAFANA_SOURCE_COMMIT = "007e8d82154899a28e19e8dfe9c2bb4452c5211a"
MCP_GRAFANA_SOURCE_TREE = "c46260d808548ab15b35cdfe6ee49f1c5d73be66"
MCP_GRAFANA_SOURCE_ARCHIVE_SHA256 = (
    "91bdd1dece9d4aaaf9b5bda899d64f36ca65a37fd7511acbd6d69cd1c6ddbb59"
)
MCP_GRAFANA_SOURCE_MODULE_SUM = "h1:O0AvTJ37TTLsGhAFlvnOg4AmSIshkZomGaLE4ruYSxs="
MCP_GRAFANA_BINARY_SHA256 = "5f6b1492ff35f92506e17310b3ea8b689c3f04c1fe0f6d4cc0a1f6e50bd52d93"
MCP_SDK_VERSION = "1.29.0"
MCP_SDK_WHEEL_SHA256 = "f5a075bb611f23d6f4d080c6a1699fa62772eebc562ba9e66b306ddde1c755f7"
MCP_PROTOCOL_VERSION = "2025-06-18"
PRODUCER_VERSION = "grafana-mcp-evidence-adapter/v1"
QUERY_CATALOG_VERSION = "grafana-evidence-query-catalog/v1"
EVIDENCE_ENVELOPE_VERSION = "evidence-envelope/v1"

BUILTIN_ANNOTATIONS_SHA256 = "ae78503371695cf7d7b89784165a967b2135219ecf6527f06a2c1c73d05c6ae6"
TEMPO_REMOTE_INPUT_SCHEMA_SHA256 = (
    "ad8e3f9d880c4fbad2cd30556efbac3a188e4db6377c6b63b48e252cd20216bc"
)
TEMPO_REMOTE_ANNOTATIONS_SHA256 = "2e7fcf324b2df2692aecf8a5e83d1c37d2768dd32128caf778a19c3603ed8e0e"
TEMPO_LOCAL_INPUT_SCHEMA_SHA256 = "e5ea1423dd591f7f5b20541ef24c36fbd348ab9d66d963216ffe337b1f9731b9"

CORRELATION_FIELDS = (
    "fixture_id",
    "run_id",
    "job_id",
    "worker_id",
    "artifact_id",
    "trace_id",
    "config_sha256",
    "transform_id",
)
QUERY_KEYS = (
    "alert.rule",
    "log.correlated-events",
    "metric.correlated-observations",
    "trace.by-id",
)
SIMULATOR_ACTION_QUERY_KEYS = (
    "metric.simulator-action-observations",
    "log.simulator-action-events",
    "trace.simulator-action-command",
)
MCP_ENABLED_CATEGORIES = ("alerting", "prometheus", "loki", "datasource", "proxied")
MCP_GRAFANA_TIMEOUT_SECONDS = 15
MCP_CLIENT_TIMEOUT_SECONDS = 20

_SCHEMA_ROOT = Path(__file__).parent / "schemas"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_UID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PREFIXED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_AUTH_SCHEME_START = re.compile(r"(?i)\b(?:bearer|basic)\s+")
_TEXT_ASSIGNMENT = re.compile(r"(?i)\b(?P<key>[a-z0-9][a-z0-9._-]{0,255})[\"']?\s*[=:]\s*")
_MAX_EMBEDDED_JSON_BYTES = 65_536
_MAX_REDACTION_DEPTH = 64
_SIMULATOR_ACTION_BATCH_VERIFICATION = object()


def _normalized_key(value: str) -> str:
    separated = _CAMEL_BOUNDARY.sub("_", value)
    return re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")


def _normalized_prefix(value: str) -> str:
    separated = _CAMEL_BOUNDARY.sub("_", value)
    return re.sub(r"[^a-z0-9]+", "_", separated.lower()).lstrip("_")


class AdapterError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_json_bytes(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, float):
            raise TypeError("floating-point values are not canonical")
        if isinstance(item, Mapping):
            normalized: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("canonical object keys must be strings")
                normalized[key] = normalize(child)
            return normalized
        elif isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        return item

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    return value


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(child) for child in value]
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _prefixed_sha256(value: bytes) -> str:
    return f"sha256:{_sha256(value)}"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(token: str) -> None:
    raise ValueError(f"non-finite JSON token: {token}")


def strict_json_bytes(data: bytes) -> Any:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=Decimal,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise AdapterError("malformed_json") from error
    return _normalize_decimals(value)


def strict_json_file(path: Path) -> dict[str, Any]:
    try:
        value = strict_json_bytes(path.read_bytes())
    except OSError as error:
        raise AdapterError("configuration_unavailable") from error
    if not isinstance(value, dict):
        raise AdapterError("configuration_malformed")
    return value


def _normalize_decimals(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError as error:
            raise AdapterError("malformed_json") from error
        return value
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            _normalize_decimals(key)
            normalized[key] = _normalize_decimals(child)
        return normalized
    if isinstance(value, list):
        return [_normalize_decimals(child) for child in value]
    return value


@cache
def _schema_registry() -> tuple[Registry[Any], Mapping[str, Mapping[str, Any]]]:
    schemas: dict[str, Mapping[str, Any]] = {}
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted(_SCHEMA_ROOT.glob("*.schema.json")):
        schema = strict_json_file(path)
        Draft202012Validator.check_schema(schema)
        identifier = schema.get("$id")
        if not isinstance(identifier, str):
            raise AdapterError("schema_registry")
        schemas[path.name] = schema
        resources.append((identifier, Resource.from_contents(schema)))
        resources.append((path.name, Resource.from_contents(schema)))
    return Registry().with_resources(resources), schemas


@cache
def _schema_validator(name: str) -> Draft202012Validator:
    registry, schemas = _schema_registry()
    try:
        schema = schemas[name]
    except KeyError as error:
        raise AdapterError("schema_registry") from error
    return Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())


def _validate_schema(name: str, value: Mapping[str, Any]) -> None:
    try:
        _schema_validator(name).validate(dict(value))
    except ValidationError as error:
        raise AdapterError("schema_validation") from error


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AdapterError("invalid_time_range") from error
    if parsed.tzinfo is None:
        raise AdapterError("invalid_time_range")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class ToolPin:
    name: str
    input_schema_sha256: str
    annotations_sha256: str
    idempotent: bool
    model_input_schema_sha256: str | None = None


TOOL_PINS: Mapping[str, ToolPin] = MappingProxyType(
    {
        "alerting_manage_rules": ToolPin(
            "alerting_manage_rules",
            "2b754cb5d162ff10f321ec75bd834c786eb06bacb97227b1d20294c4044073da",
            BUILTIN_ANNOTATIONS_SHA256,
            True,
        ),
        "query_loki_logs": ToolPin(
            "query_loki_logs",
            "e5a02f614b8a077b43dfc3913cdb34ea7494fa48bb4374849940a3751b5f1bd9",
            BUILTIN_ANNOTATIONS_SHA256,
            True,
        ),
        "query_prometheus": ToolPin(
            "query_prometheus",
            "01fc673f0fda526cecfc78baa5531f892ddd13abf0fc817172cf3ec55ed6b437",
            BUILTIN_ANNOTATIONS_SHA256,
            True,
        ),
        "tempo_get-trace": ToolPin(
            "tempo_get-trace",
            TEMPO_REMOTE_INPUT_SCHEMA_SHA256,
            TEMPO_REMOTE_ANNOTATIONS_SHA256,
            False,
            TEMPO_LOCAL_INPUT_SCHEMA_SHA256,
        ),
    }
)


def tempo_model_input_schema() -> dict[str, Any]:
    schema = {
        "type": "object",
        "properties": {
            "trace_id": {
                "type": "string",
                "pattern": "^[0-9a-f]{32}$",
            }
        },
        "required": ["trace_id"],
        "additionalProperties": False,
    }
    if _sha256(canonical_json_bytes(schema)) != TEMPO_LOCAL_INPUT_SCHEMA_SHA256:
        raise AdapterError("local_tempo_schema_drift")
    return schema


@dataclass(frozen=True, slots=True)
class FrozenInventory:
    version: str
    tools: Mapping[str, ToolPin]

    def to_dict(self) -> dict[str, Any]:
        selected = {
            name: {
                "input_schema_sha256": pin.input_schema_sha256,
                "annotations_sha256": pin.annotations_sha256,
                "idempotent": pin.idempotent,
                "model_input_schema_sha256": pin.model_input_schema_sha256,
            }
            for name, pin in sorted(self.tools.items())
        }
        return {
            "schema": "grafana-mcp-tool-inventory/v1",
            "server_version": MCP_GRAFANA_VERSION,
            "server_commit": MCP_GRAFANA_SOURCE_COMMIT,
            "binary_sha256": MCP_GRAFANA_BINARY_SHA256,
            "mcp_sdk_version": MCP_SDK_VERSION,
            "mcp_protocol_version": MCP_PROTOCOL_VERSION,
            "selected_tools": selected,
            "inventory_version": self.version,
        }


def _annotation_payload(tool: types.Tool) -> dict[str, bool | None]:
    annotations = tool.annotations
    if annotations is None:
        raise AdapterError("tool_inventory_drift")
    return {
        "readOnlyHint": annotations.readOnlyHint,
        "destructiveHint": annotations.destructiveHint,
        "idempotentHint": annotations.idempotentHint,
        "openWorldHint": annotations.openWorldHint,
    }


def freeze_tool_inventory(tools: Sequence[types.Tool]) -> FrozenInventory:
    by_name: dict[str, types.Tool] = {}
    for tool in tools:
        if not isinstance(tool.name, str) or not tool.name or tool.name in by_name:
            raise AdapterError("tool_inventory_drift")
        by_name[tool.name] = tool
    if any(name not in by_name for name in TOOL_PINS):
        raise AdapterError("tool_inventory_drift")

    selected: dict[str, ToolPin] = {}
    for name, pin in TOOL_PINS.items():
        tool = by_name[name]
        input_digest = _sha256(canonical_json_bytes(tool.inputSchema))
        annotation_payload = _annotation_payload(tool)
        annotation_digest = _sha256(canonical_json_bytes(annotation_payload))
        expected_annotations = {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": pin.idempotent,
            "openWorldHint": False,
        }
        if (
            input_digest != pin.input_schema_sha256
            or annotation_digest != pin.annotations_sha256
            or annotation_payload != expected_annotations
            or tool.outputSchema is not None
        ):
            raise AdapterError("tool_inventory_drift")
        selected[name] = pin

    tempo_schema = tempo_model_input_schema()
    if set(tempo_schema["properties"]) != {"trace_id"}:
        raise AdapterError("local_tempo_schema_drift")
    inventory_body = {
        "server_version": MCP_GRAFANA_VERSION,
        "server_commit": MCP_GRAFANA_SOURCE_COMMIT,
        "binary_sha256": MCP_GRAFANA_BINARY_SHA256,
        "mcp_sdk_version": MCP_SDK_VERSION,
        "mcp_protocol_version": MCP_PROTOCOL_VERSION,
        "selected_tools": {
            name: {
                "input_schema_sha256": pin.input_schema_sha256,
                "annotations_sha256": pin.annotations_sha256,
                "idempotent": pin.idempotent,
                "model_input_schema_sha256": pin.model_input_schema_sha256,
            }
            for name, pin in sorted(selected.items())
        },
    }
    return FrozenInventory(
        _prefixed_sha256(canonical_json_bytes(inventory_body)), MappingProxyType(selected)
    )


_EXPECTED_LOCK = {
    "schema": "mcp-grafana-runtime-lock/v2",
    "source_repository": "https://github.com/grafana/mcp-grafana",
    "source_commit": MCP_GRAFANA_SOURCE_COMMIT,
    "source_tree": MCP_GRAFANA_SOURCE_TREE,
    "source_archive": (
        f"https://codeload.github.com/grafana/mcp-grafana/tar.gz/{MCP_GRAFANA_SOURCE_COMMIT}"
    ),
    "source_archive_sha256": MCP_GRAFANA_SOURCE_ARCHIVE_SHA256,
    "source_module": "github.com/grafana/mcp-grafana",
    "source_module_version": "v1.1.0",
    "source_module_sum": MCP_GRAFANA_SOURCE_MODULE_SUM,
    "release_version": MCP_GRAFANA_VERSION,
    "build_module_sha256": "bec38d3e8473226980e03364209db2a3180782d1f531ede5cb52983c5c9721cc",
    "build_sum_sha256": "a793edc44adea4185d8bdef99e522bce47b3341d45d0d4b88723390169bb8f45",
    "build_list_sha256": "29f223acc1d2d9ac9e136d246d934e3c3130d1a57eed002f97a680b20b8050ed",
    "toolchain_image": (
        "golang@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83"
    ),
    "toolchain_version": "go1.26.6",
    "build_target": "github.com/grafana/mcp-grafana/cmd/mcp-grafana",
    "build_flags": [
        "-trimpath",
        "-buildvcs=false",
        "-mod=readonly",
        ("-ldflags=-s -w -buildid= -X github.com/grafana/mcp-grafana.version=1.1.0"),
    ],
    "security_dependency_changes": [
        {"module": "golang.org/x/net", "upstream": "v0.55.0", "selected": "v0.56.0"},
        {"module": "golang.org/x/sync", "upstream": "v0.20.0", "selected": "v0.21.0"},
        {"module": "golang.org/x/sys", "upstream": "v0.45.0", "selected": "v0.46.0"},
        {"module": "golang.org/x/text", "upstream": "v0.37.0", "selected": "v0.39.0"},
        {
            "module": "google.golang.org/genproto/googleapis/api",
            "upstream": "v0.0.0-20260401024825-9d38bb4040a9",
            "selected": "v0.0.0-20260414002931-afd174a4e478",
        },
        {
            "module": "google.golang.org/genproto/googleapis/rpc",
            "upstream": "v0.0.0-20260401024825-9d38bb4040a9",
            "selected": "v0.0.0-20260414002931-afd174a4e478",
        },
        {
            "module": "google.golang.org/grpc",
            "upstream": "v1.80.0",
            "selected": "v1.82.1",
        },
    ],
    "binary_sha256": MCP_GRAFANA_BINARY_SHA256,
    "mcp_sdk_version": MCP_SDK_VERSION,
    "mcp_sdk_wheel_sha256": MCP_SDK_WHEEL_SHA256,
    "mcp_protocol_version": MCP_PROTOCOL_VERSION,
    "mcp_transport": "stdio",
    "write_tools_enabled": False,
    "enabled_tool_categories": list(MCP_ENABLED_CATEGORIES),
}
_RUNTIME_VERIFICATION = object()


@dataclass(frozen=True, slots=True)
class OfficialMcpRuntime:
    grafana_url: str
    token_file: Path
    binary: Path
    token: bytes = field(repr=False)
    _verification: object = field(default=None, repr=False, compare=False)

    @classmethod
    def verify(
        cls,
        *,
        grafana_url: str,
        token_file: Path,
        binary: Path,
        lock_path: Path,
    ) -> OfficialMcpRuntime:
        lock = strict_json_file(lock_path.resolve(strict=True))
        if lock != _EXPECTED_LOCK:
            raise AdapterError("runtime_lock_drift")
        if importlib.metadata.version("mcp") != MCP_SDK_VERSION:
            raise AdapterError("mcp_sdk_drift")
        parsed = urlsplit(grafana_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise AdapterError("grafana_origin_invalid")
        cls._validate_regular_file(binary, private=False)
        if not os.access(binary, os.X_OK) or _file_sha256(binary) != MCP_GRAFANA_BINARY_SHA256:
            raise AdapterError("mcp_binary_drift")
        try:
            completed = subprocess.run(
                [str(binary), "--version"],
                check=True,
                capture_output=True,
                timeout=5,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise AdapterError("mcp_binary_unavailable") from error
        if completed.stdout.decode("utf-8", errors="strict").strip() != MCP_GRAFANA_VERSION:
            raise AdapterError("mcp_binary_drift")

        token = cls._read_token_file(token_file)
        return cls(
            grafana_url.rstrip("/"),
            token_file,
            binary,
            token,
            _RUNTIME_VERIFICATION,
        )

    @classmethod
    def _read_token_file(cls, token_file: Path) -> bytes:
        cls._validate_regular_file(token_file, private=True)
        try:
            token = token_file.read_bytes()
        except OSError as error:
            raise AdapterError("credential_file_invalid") from error
        if (
            not 0 < len(token) <= 16_384
            or token != token.strip()
            or any(chr(byte).isspace() for byte in token)
        ):
            raise AdapterError("credential_file_invalid")
        return token

    def assert_unchanged(self) -> None:
        if self._verification is not _RUNTIME_VERIFICATION:
            raise AdapterError("runtime_unverified")
        self._validate_regular_file(self.binary, private=False)
        if (
            not os.access(self.binary, os.X_OK)
            or _file_sha256(self.binary) != MCP_GRAFANA_BINARY_SHA256
        ):
            raise AdapterError("mcp_binary_drift")
        current_token = self._read_token_file(self.token_file)
        if not hmac.compare_digest(current_token, self.token):
            raise AdapterError("credential_file_changed")

    @staticmethod
    def _validate_regular_file(path: Path, *, private: bool) -> None:
        if not path.is_absolute():
            raise AdapterError("runtime_path_invalid")
        try:
            info = path.lstat()
        except OSError as error:
            raise AdapterError("runtime_path_invalid") from error
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
            raise AdapterError("runtime_path_invalid")
        if private and info.st_mode & 0o077:
            raise AdapterError("credential_file_permissions")


@dataclass(frozen=True, slots=True)
class QuerySpec:
    key: str
    tool: str
    result_kind: str
    maximum_bytes: int
    maximum_items: int
    retry_policy: str


_EXPECTED_SPECS = {
    "alert.rule": {
        "tool": "alerting_manage_rules",
        "result_kind": "alert",
        "maximum_bytes": 262_144,
        "maximum_items": 100,
        "retry_policy": "one-trusted-transient",
    },
    "log.correlated-events": {
        "tool": "query_loki_logs",
        "result_kind": "log",
        "maximum_bytes": 262_144,
        "maximum_items": 200,
        "retry_policy": "one-trusted-transient",
    },
    "metric.correlated-observations": {
        "tool": "query_prometheus",
        "result_kind": "metric",
        "maximum_bytes": 262_144,
        "maximum_items": 500,
        "retry_policy": "one-trusted-transient",
    },
    "trace.by-id": {
        "tool": "tempo_get-trace",
        "result_kind": "trace",
        "maximum_bytes": 2_097_152,
        "maximum_items": 1,
        "retry_policy": "never",
    },
}
_EXPECTED_SIMULATOR_ACTION_SPECS = {
    "log.simulator-action-events": {
        "tool": "query_loki_logs",
        "result_kind": "log",
        "maximum_bytes": 262_144,
        "maximum_items": 200,
        "retry_policy": "one-trusted-transient",
    },
    "metric.simulator-action-observations": {
        "tool": "query_prometheus",
        "result_kind": "metric",
        "maximum_bytes": 262_144,
        "maximum_items": 500,
        "retry_policy": "one-trusted-transient",
    },
    "trace.simulator-action-command": {
        "tool": "tempo_get-trace",
        "result_kind": "trace",
        "maximum_bytes": 2_097_152,
        "maximum_items": 1,
        "retry_policy": "never",
    },
}
_EXPECTED_LIMITS = {
    "maximum_calls": 8,
    "maximum_calls_in_flight": 2,
    "call_timeout_seconds": 20,
    "maximum_window_seconds": 600,
    "maximum_model_visible_bytes": 1_048_576,
    "maximum_excerpt_characters": 4096,
}
_EXPECTED_REDACTED_KEYS = (
    "api-key",
    "api_key",
    "authorization",
    "client_secret",
    "cookie",
    "credential",
    "grafana_service_account_token",
    "password",
    "secret",
    "set-cookie",
    "token",
)
_EXPECTED_REDACTED_LABEL_PREFIXES = (
    "cloud_account",
    "cloud_availability_zone",
    "host_",
    "k8s_",
    "process_",
    "service_instance",
    "user_",
)


@dataclass(frozen=True, slots=True)
class QueryCatalog:
    version: str
    digest: str
    specs: Mapping[str, QuerySpec]
    simulator_action_specs: Mapping[str, QuerySpec]
    redacted_keys: frozenset[str]
    redacted_label_prefixes: tuple[str, ...]

    @classmethod
    def load(cls, path: Path) -> QueryCatalog:
        document = strict_json_file(path.resolve(strict=True))
        if set(document) != {
            "schema",
            "templates",
            "simulator_action_templates",
            "limits",
            "redacted_keys",
            "redacted_label_prefixes",
        }:
            raise AdapterError("query_catalog_drift")
        if (
            document.get("schema") != QUERY_CATALOG_VERSION
            or document.get("templates") != _EXPECTED_SPECS
            or document.get("simulator_action_templates") != _EXPECTED_SIMULATOR_ACTION_SPECS
            or document.get("limits") != _EXPECTED_LIMITS
            or document.get("redacted_keys") != list(_EXPECTED_REDACTED_KEYS)
            or document.get("redacted_label_prefixes") != list(_EXPECTED_REDACTED_LABEL_PREFIXES)
        ):
            raise AdapterError("query_catalog_drift")
        redacted_keys = document.get("redacted_keys")
        redacted_prefixes = document.get("redacted_label_prefixes")
        if (
            not isinstance(redacted_keys, list)
            or not redacted_keys
            or any(not isinstance(item, str) or not item for item in redacted_keys)
            or not isinstance(redacted_prefixes, list)
            or not redacted_prefixes
            or any(not isinstance(item, str) or not item for item in redacted_prefixes)
        ):
            raise AdapterError("query_catalog_drift")
        specs = {
            key: QuerySpec(key=key, **cast(dict[str, Any], value))
            for key, value in _EXPECTED_SPECS.items()
        }
        simulator_action_specs = {
            key: QuerySpec(key=key, **cast(dict[str, Any], value))
            for key, value in _EXPECTED_SIMULATOR_ACTION_SPECS.items()
        }
        return cls(
            QUERY_CATALOG_VERSION,
            _prefixed_sha256(canonical_json_bytes(document)),
            MappingProxyType(specs),
            MappingProxyType(simulator_action_specs),
            frozenset(_normalized_key(item) for item in redacted_keys),
            tuple(_normalized_prefix(item) for item in redacted_prefixes),
        )


@dataclass(frozen=True, slots=True)
class EvidenceBatch:
    request_id: str
    incident_id: str
    query_keys: tuple[str, ...]
    window_start: datetime
    window_end: datetime
    binding: Mapping[str, str]
    correlation_keys: Mapping[str, str]
    predecessor_event_sha256: str | None

    def __post_init__(self) -> None:
        try:
            binding = _plain_json(self.binding)
            correlation = _plain_json(self.correlation_keys)
            if not isinstance(binding, dict) or not isinstance(correlation, dict):
                raise TypeError("batch maps must be objects")
            object.__setattr__(self, "query_keys", tuple(self.query_keys))
            object.__setattr__(self, "binding", _freeze_json(binding))
            object.__setattr__(self, "correlation_keys", _freeze_json(correlation))
        except Exception:
            raise AdapterError("request_invalid") from None

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> EvidenceBatch:
        _validate_schema("evidence-request-v1.schema.json", value)
        window = cast(Mapping[str, str], value["window"])
        start = _parse_timestamp(window["start"])
        end = _parse_timestamp(window["end"])
        if end < start or end - start > timedelta(seconds=600):
            raise AdapterError("invalid_time_range")
        correlation = cast(Mapping[str, str], value["correlation_keys"])
        if tuple(correlation) != CORRELATION_FIELDS and set(correlation) != set(CORRELATION_FIELDS):
            raise AdapterError("correlation_invalid")
        return cls(
            request_id=cast(str, value["request_id"]),
            incident_id=cast(str, value["incident_id"]),
            query_keys=tuple(cast(list[str], value["query_keys"])),
            window_start=start,
            window_end=end,
            binding=cast(
                Mapping[str, str],
                _freeze_json(dict(cast(Mapping[str, str], value["binding"]))),
            ),
            correlation_keys=cast(
                Mapping[str, str],
                _freeze_json({name: correlation[name] for name in CORRELATION_FIELDS}),
            ),
            predecessor_event_sha256=cast(str | None, value["predecessor_event_sha256"]),
        )

    @classmethod
    def from_file(cls, path: Path) -> EvidenceBatch:
        return cls.from_mapping(strict_json_file(path.resolve(strict=True)))


@dataclass(frozen=True, slots=True)
class SimulatorActionEvidenceBatch:
    request_id: str
    evidence_request_id: str
    evidence_request_sha256: str
    catalog_sha256: str
    incident_id: str
    outcome_id: str
    outcome_sha256: str
    snapshot_id: str
    snapshot_sha256: str
    action_id: str
    operation_id: str
    action_started_at: datetime
    action_completed_at: datetime
    snapshot_observed_at: datetime
    binding: Mapping[str, str]
    trace_ids: tuple[str, ...]
    predecessor_event_sha256: str | None
    _verification: object = field(repr=False, compare=False)
    _outcome: Mapping[str, Any] = field(repr=False, compare=False)
    _snapshot: Mapping[str, Any] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        try:
            binding = _plain_json(self.binding)
            outcome = _plain_json(self._outcome)
            snapshot = _plain_json(self._snapshot)
            if (
                not isinstance(binding, dict)
                or not isinstance(outcome, dict)
                or not isinstance(snapshot, dict)
            ):
                raise TypeError("batch authority must contain objects")
            object.__setattr__(self, "binding", _freeze_json(binding))
            object.__setattr__(self, "trace_ids", tuple(self.trace_ids))
            object.__setattr__(self, "_outcome", _freeze_json(outcome))
            object.__setattr__(self, "_snapshot", _freeze_json(snapshot))
        except Exception:
            raise AdapterError("action_request_invalid") from None

    @property
    def window_start(self) -> datetime:
        return self.action_started_at

    @property
    def window_end(self) -> datetime:
        return self.snapshot_observed_at

    @property
    def correlation_keys(self) -> Mapping[str, str]:
        return MappingProxyType(
            {
                "action_id": self.action_id,
                "incident_id": self.incident_id,
                "operation_id": self.operation_id,
                "outcome_id": self.outcome_id,
                "outcome_sha256": self.outcome_sha256,
                "snapshot_id": self.snapshot_id,
                "snapshot_sha256": self.snapshot_sha256,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "simulator-action-evidence-request/v1",
            "request_id": self.request_id,
            "evidence_request_id": self.evidence_request_id,
            "evidence_request_sha256": self.evidence_request_sha256,
            "catalog_sha256": self.catalog_sha256,
            "incident_id": self.incident_id,
            "outcome_id": self.outcome_id,
            "outcome_sha256": self.outcome_sha256,
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
            "action_id": self.action_id,
            "operation_id": self.operation_id,
            "action_started_at": _timestamp(self.action_started_at),
            "action_completed_at": _timestamp(self.action_completed_at),
            "snapshot_observed_at": _timestamp(self.snapshot_observed_at),
            "binding": dict(self.binding),
            "trace_ids": list(self.trace_ids),
            "predecessor_event_sha256": self.predecessor_event_sha256,
        }

    @classmethod
    def from_documents(
        cls,
        *,
        outcome: Mapping[str, Any],
        snapshot: Mapping[str, Any],
        binding: Mapping[str, str],
        evidence_request_id: str,
        evidence_request_sha256: str,
        catalog_sha256: str,
        predecessor_event_sha256: str | None = None,
    ) -> SimulatorActionEvidenceBatch:
        try:
            outcome_value = _plain_json(outcome)
            snapshot_value = _plain_json(snapshot)
            if not isinstance(outcome_value, dict) or not isinstance(snapshot_value, dict):
                raise TypeError("authority documents must be objects")
            outcome_body = {
                key: child
                for key, child in outcome_value.items()
                if key not in {"outcome_id", "outcome_sha256"}
            }
            outcome_sha256 = _prefixed_sha256(canonical_json_bytes(outcome_body))
            snapshot_body = {
                key: child
                for key, child in snapshot_value.items()
                if key not in {"snapshot_id", "snapshot_sha256"}
            }
            snapshot_sha256 = _prefixed_sha256(canonical_json_bytes(snapshot_body))
            if (
                outcome_value.get("schema") != "simulator-action-outcome/v1"
                or outcome_value.get("status") != "succeeded"
                or outcome_value.get("reason_codes") != []
                or outcome_value.get("outcome_sha256") != outcome_sha256
                or outcome_value.get("outcome_id")
                != f"simulator-action-outcome:{outcome_sha256.removeprefix('sha256:')}"
                or snapshot_value.get("schema") != "simulator-recovery-snapshot/v1"
                or snapshot_value.get("snapshot_sha256") != snapshot_sha256
                or snapshot_value.get("snapshot_id")
                != f"simulator-recovery-snapshot:{snapshot_sha256.removeprefix('sha256:')}"
            ):
                raise ValueError("authority digest invalid")
            for name in (
                "outcome_id",
                "outcome_sha256",
                "action_id",
                "incident_id",
                "operation_id",
            ):
                if snapshot_value.get(name) != outcome_value.get(name):
                    raise ValueError("snapshot outcome binding invalid")
            if (
                snapshot_value.get("action_started_at") != outcome_value.get("action_started_at")
                or snapshot_value.get("action_completed_at") != outcome_value.get("completed_at")
                or snapshot_value.get("targets") != outcome_value.get("targets")
                or snapshot_value.get("exclusions") != outcome_value.get("exclusions")
                or snapshot_value.get("command_outcomes") != outcome_value.get("command_outcomes")
                or snapshot_value.get("recomputed_safe_complement_sha256")
                != outcome_value.get("safe_complement_after_sha256")
            ):
                raise ValueError("snapshot outcome projection invalid")
            active = snapshot_value.get("active_publication")
            if not isinstance(active, dict) or (
                active.get("pointer_sha256")
                != outcome_value.get("active_publication_pointer_sha256")
                or active.get("runtime_manifest_sha256")
                != outcome_value.get("active_runtime_manifest_sha256")
                or active.get("candidate_tree_sha256") != outcome_value.get("candidate_tree_sha256")
            ):
                raise ValueError("active publication binding invalid")
            traces = outcome_value.get("new_trace_ids")
            if (
                not isinstance(traces, list)
                or len(traces) != 5
                or traces != sorted(set(traces))
                or any(
                    not isinstance(value, str) or _TRACE_ID.fullmatch(value) is None
                    for value in traces
                )
            ):
                raise ValueError("trace authority invalid")
            started = _parse_timestamp(cast(str, outcome_value["action_started_at"]))
            completed = _parse_timestamp(cast(str, outcome_value["completed_at"]))
            promoted = _parse_timestamp(cast(str, outcome_value["publication_promoted_at"]))
            observed = _parse_timestamp(cast(str, snapshot_value["observed_at"]))
            if (
                not started < promoted <= completed <= observed
                or observed <= started
                or observed - started > timedelta(seconds=600)
            ):
                raise ValueError("action evidence timing invalid")
            identity = {
                "schema": "simulator-action-evidence-request-identity/v1",
                "evidence_request_id": evidence_request_id,
                "evidence_request_sha256": evidence_request_sha256,
                "catalog_sha256": catalog_sha256,
                "outcome_sha256": outcome_sha256,
                "snapshot_sha256": snapshot_sha256,
            }
            request_sha256 = _prefixed_sha256(canonical_json_bytes(identity))
            batch = cls(
                request_id=f"simulator-action-evidence:{request_sha256.removeprefix('sha256:')}",
                evidence_request_id=evidence_request_id,
                evidence_request_sha256=evidence_request_sha256,
                catalog_sha256=catalog_sha256,
                incident_id=cast(str, outcome_value["incident_id"]),
                outcome_id=cast(str, outcome_value["outcome_id"]),
                outcome_sha256=outcome_sha256,
                snapshot_id=cast(str, snapshot_value["snapshot_id"]),
                snapshot_sha256=snapshot_sha256,
                action_id=cast(str, outcome_value["action_id"]),
                operation_id=cast(str, outcome_value["operation_id"]),
                action_started_at=started,
                action_completed_at=completed,
                snapshot_observed_at=observed,
                binding=binding,
                trace_ids=tuple(cast(list[str], traces)),
                predecessor_event_sha256=predecessor_event_sha256,
                _verification=_SIMULATOR_ACTION_BATCH_VERIFICATION,
                _outcome=outcome_value,
                _snapshot=snapshot_value,
            )
            _validate_simulator_action_batch(batch)
            return batch
        except AdapterError:
            raise
        except Exception:
            raise AdapterError("action_request_invalid") from None


def _snapshot_batch(batch: EvidenceBatch) -> EvidenceBatch:
    try:
        snapshot = EvidenceBatch(
            request_id=batch.request_id,
            incident_id=batch.incident_id,
            query_keys=tuple(batch.query_keys),
            window_start=batch.window_start,
            window_end=batch.window_end,
            binding=cast(Mapping[str, str], _plain_json(batch.binding)),
            correlation_keys=cast(Mapping[str, str], _plain_json(batch.correlation_keys)),
            predecessor_event_sha256=batch.predecessor_event_sha256,
        )
    except AdapterError:
        raise
    except Exception:
        raise AdapterError("request_invalid") from None
    _validate_batch(snapshot)
    return snapshot


@dataclass(frozen=True, slots=True)
class BoundCall:
    spec: QuerySpec
    arguments: Mapping[str, Any]
    model_visible_arguments: tuple[str, ...] = ()
    correlation_keys: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class AttemptRequest:
    query_key: str
    tool: str
    attempt: int
    retry: bool
    normalized_arguments: Mapping[str, Any]
    arguments_sha256: str


@dataclass(frozen=True, slots=True)
class AttemptRecord:
    query_key: str
    tool: str
    attempt: int
    retry: bool
    normalized_arguments: Mapping[str, Any]
    arguments_sha256: str
    started_at: str
    completed_at: str
    outcome: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_key": self.query_key,
            "tool": self.tool,
            "attempt": self.attempt,
            "retry": self.retry,
            "normalized_arguments": _plain_json(self.normalized_arguments),
            "arguments_sha256": self.arguments_sha256,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "outcome": self.outcome,
        }


AttemptAuthorizer = Callable[[AttemptRequest], Awaitable[bool]]


@dataclass(frozen=True, slots=True)
class ExecutionControls:
    shared_limiter: asyncio.Semaphore | None = None
    attempt_authorizer: AttemptAuthorizer | None = None

    async def authorize(self, request: AttemptRequest) -> bool:
        if self.attempt_authorizer is None:
            return True
        try:
            return await self.attempt_authorizer(request)
        except asyncio.CancelledError:
            raise
        except Exception:
            return False


def _validate_batch(batch: EvidenceBatch) -> None:
    if (
        not isinstance(batch.request_id, str)
        or not _IDENTIFIER.fullmatch(batch.request_id)
        or not isinstance(batch.incident_id, str)
        or not _IDENTIFIER.fullmatch(batch.incident_id)
    ):
        raise AdapterError("request_invalid")
    if (
        not 1 <= len(batch.query_keys) <= 8
        or any(not isinstance(key, str) for key in batch.query_keys)
        or len(set(batch.query_keys)) != len(batch.query_keys)
        or any(key not in QUERY_KEYS for key in batch.query_keys)
    ):
        raise AdapterError("query_not_allowed")
    if (
        not isinstance(batch.window_start, datetime)
        or not isinstance(batch.window_end, datetime)
        or batch.window_start.utcoffset() is None
        or batch.window_end.utcoffset() is None
        or batch.window_end < batch.window_start
        or batch.window_end - batch.window_start > timedelta(seconds=600)
    ):
        raise AdapterError("invalid_time_range")
    expected_binding = {
        "prometheus_datasource_uid",
        "loki_datasource_uid",
        "tempo_datasource_uid",
        "alert_rule_uid",
    }
    if set(batch.binding) != expected_binding or any(
        not isinstance(value, str) or not _UID.fullmatch(value) for value in batch.binding.values()
    ):
        raise AdapterError("binding_invalid")
    if set(batch.correlation_keys) != set(CORRELATION_FIELDS) or any(
        not isinstance(value, str) or not _IDENTIFIER.fullmatch(value)
        for value in batch.correlation_keys.values()
    ):
        raise AdapterError("correlation_invalid")
    if not _TRACE_ID.fullmatch(batch.correlation_keys["trace_id"]) or not _DIGEST.fullmatch(
        batch.correlation_keys["config_sha256"]
    ):
        raise AdapterError("correlation_invalid")
    if batch.predecessor_event_sha256 is not None and (
        not isinstance(batch.predecessor_event_sha256, str)
        or not _PREFIXED_DIGEST.fullmatch(batch.predecessor_event_sha256)
    ):
        raise AdapterError("request_invalid")


def _validate_simulator_action_batch(batch: SimulatorActionEvidenceBatch) -> None:
    if batch._verification is not _SIMULATOR_ACTION_BATCH_VERIFICATION:
        raise AdapterError("action_request_unverified")
    _validate_schema("simulator-action-evidence-request-v1.schema.json", batch.to_dict())
    identity = {
        "schema": "simulator-action-evidence-request-identity/v1",
        "evidence_request_id": batch.evidence_request_id,
        "evidence_request_sha256": batch.evidence_request_sha256,
        "catalog_sha256": batch.catalog_sha256,
        "outcome_sha256": batch.outcome_sha256,
        "snapshot_sha256": batch.snapshot_sha256,
    }
    request_sha256 = _prefixed_sha256(canonical_json_bytes(identity))
    if (
        batch.request_id != f"simulator-action-evidence:{request_sha256.removeprefix('sha256:')}"
        or batch.evidence_request_id
        != (f"recovery-evidence-request:{batch.evidence_request_sha256.removeprefix('sha256:')}")
        or batch.trace_ids != tuple(sorted(set(batch.trace_ids)))
        or len(batch.trace_ids) != 5
        or batch.action_completed_at < batch.action_started_at
        or batch.snapshot_observed_at < batch.action_completed_at
        or batch.snapshot_observed_at <= batch.action_started_at
        or batch.snapshot_observed_at - batch.action_started_at > timedelta(seconds=600)
    ):
        raise AdapterError("action_request_invalid")
    expected_binding = {
        "prometheus_datasource_uid",
        "loki_datasource_uid",
        "tempo_datasource_uid",
    }
    if set(batch.binding) != expected_binding or any(
        not isinstance(value, str) or _UID.fullmatch(value) is None
        for value in batch.binding.values()
    ):
        raise AdapterError("binding_invalid")
    if batch.predecessor_event_sha256 is not None and (
        not isinstance(batch.predecessor_event_sha256, str)
        or _PREFIXED_DIGEST.fullmatch(batch.predecessor_event_sha256) is None
    ):
        raise AdapterError("action_request_invalid")
    outcome = _plain_json(batch._outcome)
    snapshot = _plain_json(batch._snapshot)
    if not isinstance(outcome, dict) or not isinstance(snapshot, dict):
        raise AdapterError("action_request_invalid")
    outcome_body = {
        key: child for key, child in outcome.items() if key not in {"outcome_id", "outcome_sha256"}
    }
    snapshot_body = {
        key: child
        for key, child in snapshot.items()
        if key not in {"snapshot_id", "snapshot_sha256"}
    }
    if (
        _prefixed_sha256(canonical_json_bytes(outcome_body)) != batch.outcome_sha256
        or _prefixed_sha256(canonical_json_bytes(snapshot_body)) != batch.snapshot_sha256
        or outcome.get("outcome_id") != batch.outcome_id
        or snapshot.get("snapshot_id") != batch.snapshot_id
        or outcome.get("action_id") != batch.action_id
        or outcome.get("operation_id") != batch.operation_id
        or outcome.get("incident_id") != batch.incident_id
    ):
        raise AdapterError("action_request_invalid")
    commands = outcome.get("command_outcomes")
    exclusions = outcome.get("exclusions")
    targets = outcome.get("targets")
    if (
        not isinstance(commands, list)
        or len(commands) != 5
        or not isinstance(exclusions, list)
        or len(exclusions) != 3
        or not isinstance(targets, list)
        or len(targets) != 5
    ):
        raise AdapterError("action_request_invalid")
    command_ids: list[str] = []
    command_traces: list[str] = []
    for command in commands:
        if not isinstance(command, dict) or not isinstance(command.get("target"), dict):
            raise AdapterError("action_request_invalid")
        command_id = command.get("command_id")
        trace_id = command.get("trace_id")
        if (
            not isinstance(command_id, str)
            or _IDENTIFIER.fullmatch(command_id) is None
            or not isinstance(trace_id, str)
            or _TRACE_ID.fullmatch(trace_id) is None
        ):
            raise AdapterError("action_request_invalid")
        command_ids.append(command_id)
        command_traces.append(trace_id)
    exclusion_ids = [child.get("id") if isinstance(child, dict) else None for child in exclusions]
    if (
        command_ids != sorted(set(command_ids))
        or sorted(command_traces) != list(batch.trace_ids)
        or any(
            not isinstance(child, str) or _IDENTIFIER.fullmatch(child) is None
            for child in exclusion_ids
        )
        or len(set(cast(list[str], exclusion_ids))) != 3
    ):
        raise AdapterError("action_request_invalid")


def _label_selector(correlation: Mapping[str, str]) -> str:
    values: list[str] = []
    for name in CORRELATION_FIELDS:
        value = correlation[name]
        if not _IDENTIFIER.fullmatch(value):
            raise AdapterError("correlation_invalid")
        values.append(f'{name}="{value}"')
    return ",".join(values)


def _bind_call(catalog: QueryCatalog, batch: EvidenceBatch, key: str) -> BoundCall:
    try:
        spec = catalog.specs[key]
    except KeyError as error:
        raise AdapterError("query_not_allowed") from error
    start = _timestamp(batch.window_start)
    end = _timestamp(batch.window_end)
    correlation = batch.correlation_keys
    binding = batch.binding
    if key == "alert.rule":
        arguments: Mapping[str, Any] = {
            "operation": "get",
            "rule_uid": binding["alert_rule_uid"],
            "limit_alerts": 100,
        }
    elif key == "metric.correlated-observations":
        arguments = {
            "datasourceUid": binding["prometheus_datasource_uid"],
            "expr": (
                "colortrace_declared_reference_observations_total"
                f"{{{_label_selector(correlation)}}}"
            ),
            "queryType": "instant",
            "endTime": end,
        }
    elif key == "log.correlated-events":
        arguments = {
            "datasourceUid": binding["loki_datasource_uid"],
            "logql": (
                '{service_name="colortrace-simulator"} '
                f'| fixture_id="{correlation["fixture_id"]}" '
                f'| run_id="{correlation["run_id"]}" '
                f'| job_id="{correlation["job_id"]}"'
            ),
            "queryType": "range",
            "startRfc3339": start,
            "endRfc3339": end,
            "direction": "forward",
            "limit": 200,
        }
    elif key == "trace.by-id":
        arguments = {
            "trace_id": correlation["trace_id"],
            "datasourceUid": binding["tempo_datasource_uid"],
        }
    else:  # pragma: no cover
        raise AdapterError("query_not_allowed")
    return BoundCall(spec, cast(Mapping[str, Any], _freeze_json(arguments)))


def _bind_simulator_action_calls(
    catalog: QueryCatalog, batch: SimulatorActionEvidenceBatch
) -> tuple[BoundCall, ...]:
    """Bind the fixed recovery evidence query set without caller-supplied query text."""

    _validate_simulator_action_batch(batch)
    started = _timestamp(batch.action_started_at)
    observed = _timestamp(batch.snapshot_observed_at)
    labels = {
        "action_action_id": batch.action_id,
        "action_incident_id": batch.incident_id,
        "action_operation_id": batch.operation_id,
        "action_outcome_sha256": batch.outcome_sha256,
    }
    selector = ",".join(f'{name}="{value}"' for name, value in labels.items())
    base_correlation = dict(batch.correlation_keys)

    metric = BoundCall(
        catalog.simulator_action_specs["metric.simulator-action-observations"],
        cast(
            Mapping[str, Any],
            _freeze_json(
                {
                    "datasourceUid": batch.binding["prometheus_datasource_uid"],
                    "expr": f"colortrace_simulator_action_observations_total{{{selector}}}",
                    "queryType": "instant",
                    "endTime": observed,
                }
            ),
        ),
        correlation_keys=cast(Mapping[str, str], _freeze_json(base_correlation)),
    )
    log_filters = " ".join(f'| {name}="{value}"' for name, value in labels.items())
    log = BoundCall(
        catalog.simulator_action_specs["log.simulator-action-events"],
        cast(
            Mapping[str, Any],
            _freeze_json(
                {
                    "datasourceUid": batch.binding["loki_datasource_uid"],
                    "logql": f'{{service_name="colortrace-simulator"}} {log_filters}',
                    "queryType": "range",
                    "startRfc3339": started,
                    "endRfc3339": observed,
                    "direction": "forward",
                    "limit": 200,
                }
            ),
        ),
        correlation_keys=cast(Mapping[str, str], _freeze_json(base_correlation)),
    )
    traces = tuple(
        BoundCall(
            catalog.simulator_action_specs["trace.simulator-action-command"],
            cast(
                Mapping[str, Any],
                _freeze_json(
                    {
                        "trace_id": trace_id,
                        "datasourceUid": batch.binding["tempo_datasource_uid"],
                    }
                ),
            ),
            correlation_keys=cast(
                Mapping[str, str],
                _freeze_json({**base_correlation, "trace_id": trace_id}),
            ),
        )
        for trace_id in batch.trace_ids
    )
    bound = (metric, log, *traces)
    if len(bound) != 7:
        raise AdapterError("action_query_set_invalid")
    return bound


class McpSession(Protocol):
    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult: ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> types.CallToolResult: ...


SessionFactory = Callable[[OfficialMcpRuntime], AbstractAsyncContextManager[McpSession]]
InventoryLoader = Callable[[McpSession], Awaitable[FrozenInventory]]


@asynccontextmanager
async def _official_session_transport(runtime: OfficialMcpRuntime) -> AsyncIterator[McpSession]:
    runtime.assert_unchanged()
    parameters = StdioServerParameters(
        command=str(runtime.binary),
        args=[
            "--transport=stdio",
            "--disable-write",
            f"--enabled-tools={','.join(MCP_ENABLED_CATEGORIES)}",
            f"--grafana-timeout={MCP_GRAFANA_TIMEOUT_SECONDS}s",
            "--max-loki-log-limit=200",
            "--log-level=error",
        ],
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "GRAFANA_URL": runtime.grafana_url,
            "GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE": str(runtime.token_file),
        },
    )
    with Path(os.devnull).open("w", encoding="utf-8") as error_log:
        async with stdio_client(parameters, errlog=error_log) as (read, write):
            async with ClientSession(
                read,
                write,
                read_timeout_seconds=timedelta(seconds=MCP_CLIENT_TIMEOUT_SECONDS),
                client_info=types.Implementation(name="colortrace-grafana-evidence", version="1"),
            ) as session:
                initialize = types.InitializeRequest(
                    params=types.InitializeRequestParams(
                        protocolVersion=MCP_PROTOCOL_VERSION,
                        capabilities=types.ClientCapabilities(),
                        clientInfo=types.Implementation(
                            name="colortrace-grafana-evidence", version="1"
                        ),
                    )
                )
                result = await session.send_request(
                    types.ClientRequest(initialize), types.InitializeResult
                )
                if (
                    result.protocolVersion != MCP_PROTOCOL_VERSION
                    or result.serverInfo.version != MCP_GRAFANA_VERSION
                ):
                    raise AdapterError("mcp_handshake_drift")
                await session.send_notification(
                    types.ClientNotification(types.InitializedNotification())
                )
                yield cast(McpSession, session)


@asynccontextmanager
async def official_session(runtime: OfficialMcpRuntime) -> AsyncIterator[McpSession]:
    try:
        async with _official_session_transport(runtime) as session:
            yield session
    except asyncio.CancelledError:
        raise
    except AdapterError:
        raise
    except Exception:
        raise AdapterError("mcp_session_failure") from None


async def _list_all_tools(session: McpSession) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    seen_cursors: set[str] = set()
    for _ in range(4):
        result = await session.list_tools(cursor)
        tools.extend(result.tools)
        if len(tools) > 512:
            raise AdapterError("tool_inventory_drift")
        cursor = result.nextCursor
        if cursor is None:
            return tools
        if cursor in seen_cursors:
            raise AdapterError("tool_inventory_drift")
        seen_cursors.add(cursor)
    raise AdapterError("tool_inventory_drift")


async def _load_inventory(session: McpSession) -> FrozenInventory:
    try:
        tools = await asyncio.wait_for(_list_all_tools(session), timeout=MCP_CLIENT_TIMEOUT_SECONDS)
        return freeze_tool_inventory(tools)
    except asyncio.CancelledError:
        raise
    except TimeoutError:
        raise AdapterError("tool_inventory_timeout") from None
    except AdapterError:
        raise
    except Exception:
        raise AdapterError("tool_inventory_unavailable") from None


@dataclass(slots=True)
class _CallBudget:
    maximum_calls: int = 8
    maximum_in_flight: int = 2
    calls_used: int = 0
    in_flight: int = 0
    maximum_observed_in_flight: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def reserve(self) -> bool:
        async with self.lock:
            if self.calls_used >= self.maximum_calls:
                return False
            self.calls_used += 1
            return True

    async def entered(self) -> None:
        async with self.lock:
            self.in_flight += 1
            self.maximum_observed_in_flight = max(self.maximum_observed_in_flight, self.in_flight)
            if self.in_flight > self.maximum_in_flight:
                raise AdapterError("concurrency_budget")

    async def exited(self) -> None:
        async with self.lock:
            self.in_flight -= 1


@dataclass(slots=True)
class _RetryBudget:
    maximum_retries: int = 1
    retries_used: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def reserve(self) -> bool:
        async with self.lock:
            if self.retries_used >= self.maximum_retries:
                return False
            self.retries_used += 1
            return True


@dataclass(frozen=True, slots=True)
class _RawCollection:
    bound: BoundCall
    retrieved_at: datetime
    attempts: int
    retries: int
    content: Any
    error_code: str | None
    attempt_records: tuple[AttemptRecord, ...]


def _provider_error_code(result: types.CallToolResult, token: bytes) -> str:
    chunks: list[str] = []
    remaining = 65_536
    for item in result.content:
        if not isinstance(item, types.TextContent) or remaining <= 0:
            continue
        chunk = item.text[:remaining]
        chunks.append(chunk)
        remaining -= len(chunk)
    try:
        raw = "\n".join(chunks).encode("utf-8")[:65_536]
    except UnicodeError:
        return "provider_error"
    if token in raw:
        return "credential_exposure"
    text = raw.decode("utf-8", errors="ignore").lower()
    if any(marker in text for marker in ("unauthorized", "unauthenticated", "status 401", " 401")):
        return "authentication"
    if any(marker in text for marker in ("forbidden", "permission denied", "status 403", " 403")):
        return "authorization"
    if any(marker in text for marker in ("timed out", "timeout", "deadline exceeded")):
        return "timeout"
    return "provider_error"


def _extract_success(
    result: types.CallToolResult,
    bound: BoundCall,
    *,
    token: bytes,
    catalog: QueryCatalog,
) -> Any:
    if result.isError:
        raise AdapterError(_provider_error_code(result, token))
    expected_meta = (
        {"encoding": "json", "type": "trace", "version": "2"}
        if bound.spec.result_kind == "trace"
        else None
    )
    if (
        result.structuredContent is not None
        or result.meta != expected_meta
        or len(result.content) != 1
    ):
        raise AdapterError("malformed_result")
    content = result.content[0]
    if not isinstance(content, types.TextContent):
        raise AdapterError("malformed_result")
    serialized_content = content.model_dump(by_alias=True, exclude_none=True)
    if set(serialized_content) != {"type", "text"}:
        raise AdapterError("malformed_result")
    try:
        raw = content.text.encode("utf-8")
    except UnicodeError as error:
        raise AdapterError("malformed_result") from error
    if token in raw:
        raise AdapterError("credential_exposure")
    if len(raw) > bound.spec.maximum_bytes:
        raise AdapterError("oversized_result")
    try:
        payload = strict_json_bytes(raw)
    except AdapterError as error:
        raise AdapterError("malformed_result") from error
    _validate_provider_payload(bound, payload)
    redacted = _redact(payload, catalog)
    if len(canonical_json_bytes(redacted)) > bound.spec.maximum_bytes:
        raise AdapterError("oversized_result")
    return redacted


def _string_map(value: Any) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str) and isinstance(child, str) for key, child in value.items()
    )


def _nonnegative_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_provider_payload(bound: BoundCall, payload: Any) -> None:
    if not isinstance(payload, dict):
        raise AdapterError("malformed_result")
    spec = bound.spec
    if spec.result_kind == "metric":
        rows = payload.get("data")
        warnings = payload.get("warnings", [])
        if (
            not isinstance(rows, list)
            or not isinstance(warnings, list)
            or any(not isinstance(item, str) for item in warnings)
        ):
            raise AdapterError("malformed_result")
        if warnings:
            raise AdapterError("incomplete_result")
        if len(rows) > spec.maximum_items:
            raise AdapterError("oversized_result")
        for row in rows:
            if not isinstance(row, dict) or not _string_map(row.get("metric")):
                raise AdapterError("malformed_result")
            sample = row.get("value")
            if (
                not isinstance(sample, list)
                or len(sample) != 2
                or not isinstance(sample[0], (int, str))
                or isinstance(sample[0], bool)
                or not isinstance(sample[1], str)
                or not sample[1]
            ):
                raise AdapterError("malformed_result")
        return
    if spec.result_kind == "log":
        rows = payload.get("data")
        metadata = payload.get("metadata")
        if not isinstance(rows, list) or not isinstance(metadata, dict):
            raise AdapterError("malformed_result")
        if len(rows) > spec.maximum_items:
            raise AdapterError("oversized_result")
        if metadata.get("resultsTruncated") is not False:
            raise AdapterError("oversized_result")
        if (
            not _nonnegative_integer(metadata.get("linesReturned"))
            or metadata["linesReturned"] != len(rows)
            or not _nonnegative_integer(metadata.get("maxLinesAllowed"))
            or not _nonnegative_integer(metadata.get("totalLinesScanned"))
            or not isinstance(metadata.get("startTime"), str)
            or not isinstance(metadata.get("endTime"), str)
        ):
            raise AdapterError("malformed_result")
        if (
            metadata["maxLinesAllowed"] != bound.arguments["limit"]
            or metadata["startTime"] != bound.arguments["startRfc3339"]
            or metadata["endTime"] != bound.arguments["endRfc3339"]
        ):
            raise AdapterError("incomplete_result")
        for row in rows:
            if (
                not isinstance(row, dict)
                or not isinstance(row.get("timestamp"), str)
                or not isinstance(row.get("line"), str)
                or not _string_map(row.get("labels"))
                or not _string_map(row.get("structuredMetadata"))
            ):
                raise AdapterError("malformed_result")
        return
    if spec.result_kind == "trace":
        trace = payload.get("trace")
        metrics = payload.get("metrics")
        if (
            payload.get("status") != "COMPLETE"
            or not isinstance(trace, dict)
            or trace.get("traceId") != bound.arguments["trace_id"]
            or not isinstance(trace.get("services"), list)
            or not trace["services"]
            or not isinstance(metrics, dict)
            or not _nonnegative_integer(metrics.get("inspectedBytes"))
        ):
            raise AdapterError("malformed_result")
        for service in trace["services"]:
            if (
                not isinstance(service, dict)
                or not isinstance(service.get("serviceName"), str)
                or not _string_map(service.get("resource"))
                or not isinstance(service.get("scopes"), list)
                or not service["scopes"]
            ):
                raise AdapterError("malformed_result")
            for scope in service["scopes"]:
                if (
                    not isinstance(scope, dict)
                    or not isinstance(scope.get("name"), str)
                    or not isinstance(scope.get("spans"), list)
                    or not scope["spans"]
                ):
                    raise AdapterError("malformed_result")
                for span in scope["spans"]:
                    if (
                        not isinstance(span, dict)
                        or not isinstance(span.get("spanId"), str)
                        or not isinstance(span.get("name"), str)
                        or not isinstance(span.get("startTimeUnixNano"), str)
                        or not isinstance(span.get("endTimeUnixNano"), str)
                        or not isinstance(span.get("attributes"), dict)
                        or ("events" in span and not isinstance(span.get("events"), list))
                        or not isinstance(span.get("status"), dict)
                    ):
                        raise AdapterError("malformed_result")
        return
    if spec.result_kind == "alert":
        alerts = payload.get("alerts")
        if (
            not isinstance(alerts, list)
            or payload.get("uid") != bound.arguments["rule_uid"]
            or not isinstance(payload.get("title"), str)
            or not _string_map(payload.get("labels"))
            or not _string_map(payload.get("annotations"))
            or not isinstance(payload.get("data"), list)
            or any(not isinstance(item, dict) for item in payload["data"])
        ):
            raise AdapterError("malformed_result")
        if len(alerts) > spec.maximum_items:
            raise AdapterError("oversized_result")
        for alert in alerts:
            if (
                not isinstance(alert, dict)
                or not _string_map(alert.get("labels"))
                or not _string_map(alert.get("annotations"))
                or not isinstance(alert.get("state"), str)
                or not isinstance(alert.get("activeAt"), str)
                or not isinstance(alert.get("value"), str)
            ):
                raise AdapterError("malformed_result")
        return
    raise AdapterError("malformed_result")


def _is_sensitive_key(value: str, catalog: QueryCatalog) -> bool:
    normalized = _normalized_key(value)
    padded = f"_{normalized}_"
    aliases = catalog.redacted_keys | frozenset(f"{key}s" for key in catalog.redacted_keys)
    if any(f"_{alias}_" in padded for alias in aliases):
        return True
    collapsed = normalized.replace("_", "")
    for alias in aliases:
        collapsed_alias = alias.replace("_", "")
        if (
            collapsed == collapsed_alias
            or collapsed.endswith(collapsed_alias)
            or ("_" in alias and collapsed_alias in collapsed)
        ):
            return True
    return any(normalized.startswith(prefix) for prefix in catalog.redacted_label_prefixes)


def _sensitive_text_start(value: str, catalog: QueryCatalog) -> int | None:
    scheme = _AUTH_SCHEME_START.search(value)
    earliest = None if scheme is None else scheme.start()
    for assignment in _TEXT_ASSIGNMENT.finditer(value):
        if earliest is not None and assignment.start() >= earliest:
            break
        if _is_sensitive_key(assignment.group("key"), catalog):
            earliest = assignment.start()
            break
    return earliest


def _redact_text(value: str, catalog: QueryCatalog, *, depth: int) -> str:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        return "[REDACTED]"
    stripped = value.lstrip()
    json_like = stripped.startswith(("{", "[", '"'))
    if json_like and len(encoded) > _MAX_EMBEDDED_JSON_BYTES:
        return "[REDACTED]"
    if json_like:
        try:
            structured = strict_json_bytes(encoded)
            if isinstance(structured, (dict, list, str)):
                redacted = _redact(structured, catalog, _depth=depth + 1)
                return canonical_json_bytes(redacted).decode("utf-8")
        except (AdapterError, RecursionError, TypeError, UnicodeError):
            pass
    sensitive_start = _sensitive_text_start(value, catalog)
    if sensitive_start is None:
        return value
    return f"{value[:sensitive_start]}[REDACTED]"


def _redact(value: Any, catalog: QueryCatalog, *, _depth: int = 0) -> Any:
    if _depth >= _MAX_REDACTION_DEPTH:
        return "[REDACTED]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        attribute_key = value.get("key")
        redact_attribute_value = isinstance(attribute_key, str) and _is_sensitive_key(
            attribute_key, catalog
        )
        for key, child in value.items():
            if _is_sensitive_key(key, catalog) or (redact_attribute_value and key != "key"):
                result[key] = "[REDACTED]"
            else:
                result[key] = _redact(child, catalog, _depth=_depth + 1)
        return result
    if isinstance(value, list):
        return [_redact(child, catalog, _depth=_depth + 1) for child in value]
    if isinstance(value, str):
        return _redact_text(value, catalog, depth=_depth)
    return value


async def _collect_one(
    session: McpSession,
    bound: BoundCall,
    *,
    runtime: OfficialMcpRuntime,
    catalog: QueryCatalog,
    local_limiter: asyncio.Semaphore,
    controls: ExecutionControls,
    budget: _CallBudget,
    clock: Callable[[], datetime],
    retry_budget: _RetryBudget | None = None,
) -> _RawCollection:
    attempts = 0
    retries = 0
    attempt_records: list[AttemptRecord] = []
    while True:
        arguments = cast(dict[str, Any], _plain_json(bound.arguments))
        arguments_digest = _prefixed_sha256(canonical_json_bytes(arguments))
        request = AttemptRequest(
            query_key=bound.spec.key,
            tool=bound.spec.tool,
            attempt=attempts + 1,
            retry=retries > 0,
            normalized_arguments=cast(Mapping[str, Any], _freeze_json(arguments)),
            arguments_sha256=arguments_digest,
        )
        if not await controls.authorize(request):
            return _RawCollection(
                bound,
                clock(),
                attempts,
                retries,
                None,
                "budget_exhausted",
                tuple(attempt_records),
            )
        if not await budget.reserve():
            return _RawCollection(
                bound,
                clock(),
                attempts,
                retries,
                None,
                "budget_exhausted",
                tuple(attempt_records),
            )
        attempts += 1
        arguments = cast(dict[str, Any], _plain_json(request.normalized_arguments))
        if _prefixed_sha256(canonical_json_bytes(arguments)) != request.arguments_sha256:
            raise AdapterError("argument_drift")
        transient_code: str | None = None
        terminal_code: str | None = None
        started_at = clock()

        async def invoke(call_arguments: dict[str, Any]) -> types.CallToolResult | None:
            nonlocal terminal_code, transient_code
            async with local_limiter:
                await budget.entered()
                try:
                    return await asyncio.wait_for(
                        session.call_tool(
                            bound.spec.tool,
                            call_arguments,
                            read_timeout_seconds=timedelta(seconds=MCP_CLIENT_TIMEOUT_SECONDS),
                        ),
                        timeout=MCP_CLIENT_TIMEOUT_SECONDS,
                    )
                except asyncio.CancelledError:
                    raise
                except TimeoutError:
                    transient_code = "timeout"
                except McpError as error:
                    if error.error.code == 408:
                        transient_code = "timeout"
                    elif error.error.code == 401:
                        terminal_code = "authentication"
                    elif error.error.code == 403:
                        terminal_code = "authorization"
                    elif error.error.code == types.CONNECTION_CLOSED:
                        terminal_code = "transport"
                    else:
                        terminal_code = "provider_error"
                except (BrokenPipeError, ConnectionError, EOFError, OSError):
                    terminal_code = "transport"
                except Exception:
                    terminal_code = "provider_error"
                finally:
                    await budget.exited()
            return None

        if controls.shared_limiter is None:
            result = await invoke(arguments)
        else:
            async with controls.shared_limiter:
                result = await invoke(arguments)
        completed_at = clock()
        if terminal_code is not None:
            attempt_records.append(
                AttemptRecord(
                    request.query_key,
                    request.tool,
                    request.attempt,
                    request.retry,
                    request.normalized_arguments,
                    request.arguments_sha256,
                    _timestamp(started_at),
                    _timestamp(completed_at),
                    terminal_code,
                )
            )
            return _RawCollection(
                bound,
                completed_at,
                attempts,
                retries,
                None,
                terminal_code,
                tuple(attempt_records),
            )
        if transient_code is not None:
            attempt_records.append(
                AttemptRecord(
                    request.query_key,
                    request.tool,
                    request.attempt,
                    request.retry,
                    request.normalized_arguments,
                    request.arguments_sha256,
                    _timestamp(started_at),
                    _timestamp(completed_at),
                    transient_code,
                )
            )
            if bound.spec.retry_policy == "one-trusted-transient" and retries == 0:
                if retry_budget is not None and not await retry_budget.reserve():
                    return _RawCollection(
                        bound,
                        completed_at,
                        attempts,
                        retries,
                        None,
                        "budget_exhausted",
                        tuple(attempt_records),
                    )
                retries += 1
                continue
            return _RawCollection(
                bound,
                completed_at,
                attempts,
                retries,
                None,
                transient_code,
                tuple(attempt_records),
            )
        if result is None:  # pragma: no cover
            raise AdapterError("transport")
        try:
            payload = _extract_success(result, bound, token=runtime.token, catalog=catalog)
        except AdapterError as error:
            code = error.code
            if code not in {
                "authentication",
                "authorization",
                "credential_exposure",
                "incomplete_result",
                "malformed_result",
                "oversized_result",
                "provider_error",
                "timeout",
            }:
                code = "provider_error"
            attempt_records.append(
                AttemptRecord(
                    request.query_key,
                    request.tool,
                    request.attempt,
                    request.retry,
                    request.normalized_arguments,
                    request.arguments_sha256,
                    _timestamp(started_at),
                    _timestamp(completed_at),
                    code,
                )
            )
            if (
                code == "timeout"
                and bound.spec.retry_policy == "one-trusted-transient"
                and retries == 0
            ):
                if retry_budget is not None and not await retry_budget.reserve():
                    return _RawCollection(
                        bound,
                        completed_at,
                        attempts,
                        retries,
                        None,
                        "budget_exhausted",
                        tuple(attempt_records),
                    )
                retries += 1
                continue
            return _RawCollection(
                bound,
                completed_at,
                attempts,
                retries,
                None,
                code,
                tuple(attempt_records),
            )
        attempt_records.append(
            AttemptRecord(
                request.query_key,
                request.tool,
                request.attempt,
                request.retry,
                request.normalized_arguments,
                request.arguments_sha256,
                _timestamp(started_at),
                _timestamp(completed_at),
                "collected",
            )
        )
        return _RawCollection(
            bound,
            completed_at,
            attempts,
            retries,
            payload,
            None,
            tuple(attempt_records),
        )


_ACTION_METRIC_LABELS = MappingProxyType(
    {
        "action.action_id": "action_action_id",
        "action.incident_id": "action_incident_id",
        "action.operation_id": "action_operation_id",
        "action.outcome_sha256": "action_outcome_sha256",
    }
)


def _action_expected_values(batch: SimulatorActionEvidenceBatch) -> Mapping[str, str]:
    return MappingProxyType(
        {
            "action.action_id": batch.action_id,
            "action.incident_id": batch.incident_id,
            "action.operation_id": batch.operation_id,
            "action.outcome_sha256": batch.outcome_sha256,
        }
    )


def _validate_action_observation_time(value: Any, batch: SimulatorActionEvidenceBatch) -> None:
    if not isinstance(value, str):
        raise AdapterError("malformed_result")
    try:
        observed = _parse_timestamp(value)
    except AdapterError:
        raise AdapterError("malformed_result") from None
    if observed <= batch.action_started_at or observed > batch.snapshot_observed_at:
        raise AdapterError("pre_action_evidence")


def _validate_loki_row_time(value: Any, batch: SimulatorActionEvidenceBatch) -> None:
    if isinstance(value, str) and re.fullmatch(r'"[0-9]{19}"', value):
        nanoseconds = int(value[1:-1])
        epoch = datetime(1970, 1, 1, tzinfo=UTC)

        def epoch_nanoseconds(timestamp: datetime) -> int:
            delta = timestamp - epoch
            return (
                delta.days * 86_400 + delta.seconds
            ) * 1_000_000_000 + delta.microseconds * 1_000

        if not (
            epoch_nanoseconds(batch.action_started_at)
            < nanoseconds
            <= epoch_nanoseconds(batch.snapshot_observed_at)
        ):
            raise AdapterError("pre_action_evidence")
        return
    _validate_action_observation_time(value, batch)


def _validate_simulator_action_collection(
    raw: _RawCollection, batch: SimulatorActionEvidenceBatch
) -> None:
    if raw.error_code is not None:
        return
    payload = raw.content
    if not isinstance(payload, dict):  # already structurally checked; fail closed on drift
        raise AdapterError("malformed_result")
    expected = _action_expected_values(batch)
    if raw.bound.spec.result_kind == "metric":
        rows = payload.get("data")
        if not isinstance(rows, list) or not rows:
            raise AdapterError("incomplete_result")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("metric"), dict):
                raise AdapterError("malformed_result")
            labels = cast(dict[str, Any], row["metric"])
            if any(
                labels.get(metric_name) != expected[attribute_name]
                for attribute_name, metric_name in _ACTION_METRIC_LABELS.items()
            ):
                raise AdapterError("incomplete_result")
            _validate_action_observation_time(labels.get("telemetry_observed_at"), batch)
        return
    if raw.bound.spec.result_kind == "log":
        rows = payload.get("data")
        if not isinstance(rows, list) or not rows:
            raise AdapterError("incomplete_result")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("structuredMetadata"), dict):
                raise AdapterError("malformed_result")
            metadata = cast(dict[str, Any], row["structuredMetadata"])
            if any(
                metadata.get(metric_name) != expected[attribute_name]
                for attribute_name, metric_name in _ACTION_METRIC_LABELS.items()
            ):
                raise AdapterError("incomplete_result")
            _validate_action_observation_time(metadata.get("telemetry_observed_at"), batch)
            _validate_loki_row_time(row.get("timestamp"), batch)
        return
    if raw.bound.spec.result_kind == "trace":
        trace = payload.get("trace")
        if not isinstance(trace, dict):
            raise AdapterError("malformed_result")
        matched = 0
        correlation_names = {*expected, "telemetry.observed_at"}
        services = trace.get("services")
        if not isinstance(services, list):
            raise AdapterError("malformed_result")
        for service in services:
            if not isinstance(service, dict) or not isinstance(service.get("scopes"), list):
                raise AdapterError("malformed_result")
            for scope in service["scopes"]:
                if not isinstance(scope, dict) or not isinstance(scope.get("spans"), list):
                    raise AdapterError("malformed_result")
                for span in scope["spans"]:
                    if not isinstance(span, dict) or not isinstance(span.get("attributes"), dict):
                        raise AdapterError("malformed_result")
                    attributes = cast(dict[str, Any], span["attributes"])
                    if correlation_names.isdisjoint(attributes):
                        continue
                    if any(attributes.get(name) != value for name, value in expected.items()):
                        raise AdapterError("incomplete_result")
                    _validate_action_observation_time(
                        attributes.get("telemetry.observed_at"), batch
                    )
                    matched += 1
        if matched == 0:
            raise AdapterError("incomplete_result")
        return
    raise AdapterError("malformed_result")


def _with_collection_error(raw: _RawCollection, code: str) -> _RawCollection:
    records = list(raw.attempt_records)
    if records:
        last = records[-1]
        records[-1] = AttemptRecord(
            query_key=last.query_key,
            tool=last.tool,
            attempt=last.attempt,
            retry=last.retry,
            normalized_arguments=last.normalized_arguments,
            arguments_sha256=last.arguments_sha256,
            started_at=last.started_at,
            completed_at=last.completed_at,
            outcome=code,
        )
    return _RawCollection(
        bound=raw.bound,
        retrieved_at=raw.retrieved_at,
        attempts=raw.attempts,
        retries=raw.retries,
        content=None,
        error_code=code,
        attempt_records=tuple(records),
    )


def _build_envelope(
    raw: _RawCollection,
    *,
    batch: EvidenceBatch | SimulatorActionEvidenceBatch,
    catalog: QueryCatalog,
    inventory: FrozenInventory,
    predecessor: str | None,
) -> dict[str, Any]:
    content = None if raw.error_code is not None else _redact(raw.content, catalog)
    content_bytes = canonical_json_bytes(content)
    display = ""
    if content is not None:
        display = content_bytes.decode("utf-8")[:4096]
    pin = inventory.tools[raw.bound.spec.tool]
    body: dict[str, Any] = {
        "schema": EVIDENCE_ENVELOPE_VERSION,
        "incident_id": batch.incident_id,
        "request_id": batch.request_id,
        "source": {
            "kind": "grafana-mcp",
            "server": "mcp-grafana",
            "server_version": MCP_GRAFANA_VERSION,
            "server_commit": MCP_GRAFANA_SOURCE_COMMIT,
            "binary_sha256": MCP_GRAFANA_BINARY_SHA256,
            "mcp_sdk_version": MCP_SDK_VERSION,
            "mcp_protocol_version": MCP_PROTOCOL_VERSION,
            "tool": raw.bound.spec.tool,
            "tool_input_schema_sha256": pin.input_schema_sha256,
            "tool_annotations_sha256": pin.annotations_sha256,
            "inventory_version": inventory.version,
        },
        "observation": {
            "kind": "grafana-mcp-query",
            "query_key": raw.bound.spec.key,
            "catalog_version": catalog.version,
            "catalog_sha256": catalog.digest,
            "normalized_arguments": _plain_json(raw.bound.arguments),
            "model_visible_arguments": list(raw.bound.model_visible_arguments),
            "fixed_time_range": {
                "start": _timestamp(batch.window_start),
                "end": _timestamp(batch.window_end),
            },
        },
        "timing": {
            "source_time": None,
            "event_time": None,
            "retrieved_at": _timestamp(raw.retrieved_at),
            "freshness": "unresolved",
        },
        "content_sha256": _prefixed_sha256(content_bytes),
        "content": content,
        "display_excerpt": display,
        "correlation_keys": dict(raw.bound.correlation_keys or batch.correlation_keys),
        "collection": {
            "outcome": "error" if raw.error_code is not None else "collected",
            "attempts": raw.attempts,
            "retries": raw.retries,
            "error": (
                None if raw.error_code is None else {"code": raw.error_code, "retryable": False}
            ),
        },
        "trust": "untrusted-provider-data",
        "producer_version": PRODUCER_VERSION,
        "predecessor_event_sha256": predecessor,
    }
    event_digest = _prefixed_sha256(canonical_json_bytes(body))
    envelope = {
        **body,
        "evidence_id": event_digest,
        "event_sha256": event_digest,
    }
    validate_evidence_envelope(envelope)
    return envelope


def validate_evidence_envelope(value: Mapping[str, Any]) -> None:
    _validate_schema("evidence-envelope-v1.schema.json", value)
    content_digest = _prefixed_sha256(canonical_json_bytes(value.get("content")))
    if value.get("content_sha256") != content_digest:
        raise AdapterError("envelope_digest")
    body = {
        key: child for key, child in value.items() if key not in {"evidence_id", "event_sha256"}
    }
    event_digest = _prefixed_sha256(canonical_json_bytes(body))
    if value.get("evidence_id") != event_digest or value.get("event_sha256") != event_digest:
        raise AdapterError("envelope_digest")


@dataclass(frozen=True, slots=True)
class BatchResult:
    inventory: FrozenInventory
    envelopes: tuple[Mapping[str, Any], ...]
    tool_calls_used: int
    maximum_calls_in_flight_observed: int
    attempts: tuple[AttemptRecord, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "grafana-evidence-batch-result/v1",
            "inventory": self.inventory.to_dict(),
            "tool_calls_used": self.tool_calls_used,
            "maximum_calls_in_flight_observed": self.maximum_calls_in_flight_observed,
            "attempts": [attempt.to_dict() for attempt in self.attempts],
            "envelopes": [dict(envelope) for envelope in self.envelopes],
        }


class EvidenceCollectionSession:
    def __init__(
        self,
        *,
        session: McpSession,
        runtime: OfficialMcpRuntime,
        catalog: QueryCatalog,
        batch: EvidenceBatch,
        inventory: FrozenInventory,
        controls: ExecutionControls,
        clock: Callable[[], datetime],
    ) -> None:
        self._session = session
        self._runtime = runtime
        self._catalog = catalog
        self._batch = batch
        self._inventory = inventory
        self._controls = controls
        self._clock = clock
        self._budget = _CallBudget(maximum_calls=8, maximum_in_flight=1)
        self._local_limiter = asyncio.Semaphore(1)
        self._raw_results: list[_RawCollection] = []
        self._envelopes: list[Mapping[str, Any]] = []
        self._seen: set[str] = set()
        self._in_flight = False
        self._closed = False
        self._predecessor = batch.predecessor_event_sha256

    @property
    def query_keys(self) -> tuple[str, ...]:
        return tuple(
            cast(str, envelope["observation"]["query_key"]) for envelope in self._envelopes
        )

    async def collect(self, query_key: str) -> Mapping[str, Any]:
        if self._closed:
            raise AdapterError("collection_session_closed")
        if self._in_flight:
            raise AdapterError("parallel_query")
        if (
            not isinstance(query_key, str)
            or query_key not in self._batch.query_keys
            or query_key not in QUERY_KEYS
        ):
            raise AdapterError("query_not_allowed")
        if query_key in self._seen:
            raise AdapterError("duplicate_query")

        self._in_flight = True
        self._seen.add(query_key)
        try:
            bound = _bind_call(self._catalog, self._batch, query_key)
            raw = await _collect_one(
                self._session,
                bound,
                runtime=self._runtime,
                catalog=self._catalog,
                local_limiter=self._local_limiter,
                controls=self._controls,
                budget=self._budget,
                clock=self._clock,
            )
            envelope = _build_envelope(
                raw,
                batch=self._batch,
                catalog=self._catalog,
                inventory=self._inventory,
                predecessor=self._predecessor,
            )
            self._raw_results.append(raw)
            self._envelopes.append(envelope)
            self._predecessor = cast(str, envelope["event_sha256"])
            return envelope
        finally:
            self._in_flight = False

    def result(self) -> BatchResult:
        return BatchResult(
            self._inventory,
            tuple(self._envelopes),
            self._budget.calls_used,
            self._budget.maximum_observed_in_flight,
            tuple(attempt for raw in self._raw_results for attempt in raw.attempt_records),
        )

    def close(self) -> None:
        self._closed = True


_ACTION_CORRELATION_ATTRIBUTES = (
    "outcome_id",
    "outcome_sha256",
    "admission_id",
    "admission_sha256",
    "action_id",
    "task_key",
    "operation_id",
    "payload_sha256",
    "fixture_id",
    "incident_id",
    "incident_version",
    "plan_id",
    "plan_version",
    "plan_sha256",
    "approval_id",
    "approval_sha256",
    "consumption_id",
    "consumption_sha256",
    "dispatch_bundle_sha256",
    "action_envelope_sha256",
    "publication_intent_id",
    "publication_intent_sha256",
    "publication_receipt_id",
    "publication_receipt_sha256",
)
_ACTION_PUBLICATION_ATTRIBUTES = (
    "publication_intent_id",
    "publication_intent_sha256",
    "publication_receipt_id",
    "publication_receipt_sha256",
    "predecessor_publication_pointer_sha256",
    "predecessor_publication_generation",
    "candidate_publication_pointer_sha256",
    "candidate_publication_generation",
    "source_generation",
    "candidate_generation",
    "source_batch_id",
    "source_batch_sha256",
    "candidate_fixture_manifest_sha256",
    "candidate_runtime_manifest_sha256",
    "candidate_lineage_manifest_sha256",
    "declared_resource_manifest_sha256",
    "active_publication_pointer_sha256",
    "active_runtime_manifest_sha256",
    "preservation_manifest_sha256",
    "safe_complement_before_sha256",
    "safe_complement_after_sha256",
    "safe_complement_proof_sha256",
    "candidate_seal_sha256",
    "candidate_tree_sha256",
    "publication_promoted_at",
)


@dataclass(frozen=True, slots=True)
class NormalizedActionObservation(Mapping[str, Any]):
    event_id: str
    signal: Literal["metric", "log", "trace"]
    subject_kind: Literal["command", "safe"]
    subject_id: str
    trace_id: str | None
    outcome_id: str
    outcome_sha256: str
    action_id: str
    operation_id: str
    observed_at: str
    emitted_at: str
    retrieved_at: str
    clock_provenance: str
    clock_skew_milliseconds: int
    truncated: bool
    source_label: str
    source_envelope: Mapping[str, Any]

    def __post_init__(self) -> None:
        envelope = _plain_json(self.source_envelope)
        if not isinstance(envelope, dict):
            raise AdapterError("action_observation_malformed")
        object.__setattr__(self, "source_envelope", _freeze_json(envelope))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "signal": self.signal,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "trace_id": self.trace_id,
            "outcome_id": self.outcome_id,
            "outcome_sha256": self.outcome_sha256,
            "action_id": self.action_id,
            "operation_id": self.operation_id,
            "observed_at": self.observed_at,
            "emitted_at": self.emitted_at,
            "retrieved_at": self.retrieved_at,
            "clock_provenance": self.clock_provenance,
            "clock_skew_milliseconds": self.clock_skew_milliseconds,
            "truncated": self.truncated,
            "source_label": self.source_label,
            "source_envelope": _plain_json(self.source_envelope),
        }

    def __getitem__(self, key: str) -> Any:
        try:
            return self.to_dict()[key]
        except KeyError:
            raise KeyError(key) from None

    def __iter__(self) -> Any:
        return iter(self.to_dict())

    def __len__(self) -> int:
        return 17


@dataclass(frozen=True, slots=True)
class SimulatorActionEvidenceProjection:
    request_id: str
    evidence_request_id: str
    evidence_request_sha256: str
    catalog_sha256: str
    incident_id: str
    outcome_id: str
    outcome_sha256: str
    snapshot_id: str
    snapshot_sha256: str
    action_id: str
    operation_id: str
    completed_at: datetime
    observations: tuple[NormalizedActionObservation, ...]

    def __post_init__(self) -> None:
        if self.completed_at.tzinfo is None:
            raise AdapterError("action_collection_clock_invalid")
        object.__setattr__(self, "completed_at", self.completed_at.astimezone(UTC))
        object.__setattr__(self, "observations", tuple(self.observations))

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "evidence_request_id": self.evidence_request_id,
            "evidence_request_sha256": self.evidence_request_sha256,
            "catalog_sha256": self.catalog_sha256,
            "incident_id": self.incident_id,
            "outcome_id": self.outcome_id,
            "outcome_sha256": self.outcome_sha256,
            "snapshot_id": self.snapshot_id,
            "snapshot_sha256": self.snapshot_sha256,
            "action_id": self.action_id,
            "operation_id": self.operation_id,
            "completed_at": _timestamp(self.completed_at),
            "observations": [value.to_dict() for value in self.observations],
        }


@dataclass(frozen=True, slots=True)
class _ExpectedActionEvent:
    signal: str
    event_id: str
    subject_kind: str
    subject_id: str
    trace_id: str | None
    attributes: Mapping[str, Any]


def _stable_action_event_id(*, outcome_sha256: str, signal: str, subject: Mapping[str, Any]) -> str:
    identity = {
        "schema": "simulator-action-telemetry-event-identity/v1",
        "outcome_sha256": outcome_sha256,
        "signal": signal,
        "subject": dict(subject),
    }
    return f"simulator-action-event:{_sha256(canonical_json_bytes(identity))}"


def _expected_action_events(
    batch: SimulatorActionEvidenceBatch,
) -> Mapping[tuple[str, str], _ExpectedActionEvent]:
    outcome = batch._outcome
    common: dict[str, Any] = {
        "telemetry.contract": "simulator-action-telemetry-event/v1",
        "telemetry.phase": "execution",
        "telemetry.observed_at": outcome["completed_at"],
        "action.started_at": outcome["action_started_at"],
        "action.completed_at": outcome["completed_at"],
    }
    for name in _ACTION_CORRELATION_ATTRIBUTES:
        value = outcome[name]
        if value is not None:
            common[f"action.{name}"] = value
    for name in _ACTION_PUBLICATION_ATTRIBUTES:
        common[f"publication.{name}"] = outcome[name]

    expected: dict[tuple[str, str], _ExpectedActionEvent] = {}
    commands = cast(tuple[Mapping[str, Any], ...], outcome["command_outcomes"])
    for command in commands:
        command_id = cast(str, command["command_id"])
        trace_id = cast(str, command["trace_id"])
        target = cast(Mapping[str, Any], command["target"])
        for signal in ("metric", "log", "trace"):
            event_id = _stable_action_event_id(
                outcome_sha256=batch.outcome_sha256,
                signal=signal,
                subject={"command_id": command_id},
            )
            attributes = {
                **common,
                "telemetry.event_id": event_id,
                "action.trace_id": trace_id,
                "observation.contract": "simulator-command-observation/v1",
                "observation.scope": "affected",
                "command.id": command_id,
                "command.result_kind": command["result_kind"],
                **{f"target.{name}": target[name] for name in ("namespace", "kind", "id")},
            }
            for prefix in ("before", "after"):
                state = cast(Mapping[str, Any], command[prefix])
                attributes.update({f"{prefix}.{name}": value for name, value in state.items()})
            expected[(signal, event_id)] = _ExpectedActionEvent(
                signal,
                event_id,
                "command",
                command_id,
                trace_id,
                cast(Mapping[str, Any], _freeze_json(attributes)),
            )

    exclusions = cast(tuple[Mapping[str, Any], ...], outcome["exclusions"])
    for target in exclusions:
        target_id = cast(str, target["id"])
        for signal in ("metric", "log"):
            event_id = _stable_action_event_id(
                outcome_sha256=batch.outcome_sha256,
                signal=signal,
                subject={"target": _plain_json(target)},
            )
            attributes = {
                **common,
                "telemetry.event_id": event_id,
                "observation.contract": "simulator-safe-preservation-observation/v1",
                "observation.scope": "safe",
                **{f"target.{name}": target[name] for name in ("namespace", "kind", "id")},
                "safe.unchanged": True,
                "safe.preservation_manifest_sha256": outcome["preservation_manifest_sha256"],
                "safe.complement_before_sha256": outcome["safe_complement_before_sha256"],
                "safe.complement_after_sha256": outcome["safe_complement_after_sha256"],
                "safe.complement_proof_sha256": outcome["safe_complement_proof_sha256"],
            }
            expected[(signal, event_id)] = _ExpectedActionEvent(
                signal,
                event_id,
                "safe",
                target_id,
                None,
                cast(Mapping[str, Any], _freeze_json(attributes)),
            )
    if len(expected) != 21:
        raise AdapterError("action_observation_authority_invalid")
    return MappingProxyType(expected)


def _action_attribute_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    raise AdapterError("action_observation_malformed")


def _action_attribute(attributes: Mapping[str, Any], name: str, *, normalized: bool) -> str:
    provider_name = name.replace(".", "_") if normalized else name
    if provider_name not in attributes:
        raise AdapterError("action_observation_incomplete")
    return _action_attribute_text(attributes[provider_name])


def _project_action_attributes(
    *,
    signal: str,
    attributes: Mapping[str, Any],
    envelope: Mapping[str, Any],
    batch: SimulatorActionEvidenceBatch,
    expected: Mapping[tuple[str, str], _ExpectedActionEvent],
) -> NormalizedActionObservation:
    normalized = signal != "trace"
    event_id = _action_attribute(attributes, "telemetry.event_id", normalized=normalized)
    authority = expected.get((signal, event_id))
    if authority is None:
        raise AdapterError("action_observation_correlation_mismatch")
    expected_attributes = authority.attributes
    if signal == "metric":
        expected_attributes = {
            name: value
            for name, value in authority.attributes.items()
            if not name.startswith("publication.")
        }
    for name, value in expected_attributes.items():
        if _action_attribute(attributes, name, normalized=normalized) != _action_attribute_text(
            value
        ):
            raise AdapterError("action_observation_correlation_mismatch")
    emitted_at = _action_attribute(attributes, "telemetry.emitted_at", normalized=normalized)
    try:
        observed = _parse_timestamp(
            _action_attribute(attributes, "telemetry.observed_at", normalized=normalized)
        )
        emitted = _parse_timestamp(emitted_at)
        retrieved = _parse_timestamp(cast(str, envelope["timing"]["retrieved_at"]))
    except (AdapterError, KeyError, TypeError):
        raise AdapterError("action_observation_malformed") from None
    if (
        observed <= batch.action_started_at
        or emitted < observed
        or emitted > batch.snapshot_observed_at
    ):
        raise AdapterError("pre_action_evidence")
    source_envelope = _plain_json(envelope)
    if not isinstance(source_envelope, dict):  # pragma: no cover - Mapping input guarantees this
        raise AdapterError("action_observation_malformed")
    return NormalizedActionObservation(
        event_id=authority.event_id,
        signal=cast(Literal["metric", "log", "trace"], authority.signal),
        subject_kind=cast(Literal["command", "safe"], authority.subject_kind),
        subject_id=authority.subject_id,
        trace_id=authority.trace_id,
        outcome_id=batch.outcome_id,
        outcome_sha256=batch.outcome_sha256,
        action_id=batch.action_id,
        operation_id=batch.operation_id,
        observed_at=_timestamp(observed),
        emitted_at=_timestamp(emitted),
        retrieved_at=_timestamp(retrieved),
        clock_provenance="local-host-utc",
        clock_skew_milliseconds=0,
        truncated=False,
        source_label=f"grafana.{signal}",
        source_envelope=source_envelope,
    )


def normalize_simulator_action_observations(
    batch: SimulatorActionEvidenceBatch,
    envelopes: Sequence[Mapping[str, Any]],
    *,
    catalog: QueryCatalog,
) -> tuple[NormalizedActionObservation, ...]:
    """Project exactly 21 canonical recovery observations from the fixed seven envelopes."""

    _validate_simulator_action_batch(batch)
    if len(envelopes) != 7:
        raise AdapterError("action_evidence_set_incomplete")
    bound_calls = _bind_simulator_action_calls(catalog, batch)
    expected = _expected_action_events(batch)
    accepted: dict[str, tuple[bytes, NormalizedActionObservation]] = {}
    predecessor = batch.predecessor_event_sha256

    for envelope, bound in zip(envelopes, bound_calls, strict=True):
        validate_evidence_envelope(envelope)
        try:
            observation = cast(Mapping[str, Any], envelope["observation"])
            collection = cast(Mapping[str, Any], envelope["collection"])
            if collection["outcome"] != "collected" or collection["error"] is not None:
                raise AdapterError("action_evidence_unresolved")
            if (
                envelope["incident_id"] != batch.incident_id
                or envelope["request_id"] != batch.request_id
                or envelope["predecessor_event_sha256"] != predecessor
                or envelope["correlation_keys"]
                != dict(bound.correlation_keys or batch.correlation_keys)
                or observation["query_key"] != bound.spec.key
                or observation["normalized_arguments"] != dict(bound.arguments)
            ):
                raise AdapterError("action_evidence_binding_invalid")
            content = envelope["content"]
            if not isinstance(content, Mapping):
                raise AdapterError("action_evidence_unresolved")
            retrieved_at = envelope["timing"]["retrieved_at"]
            if not isinstance(retrieved_at, str):
                raise AdapterError("action_evidence_binding_invalid")
        except KeyError:
            raise AdapterError("action_evidence_binding_invalid") from None
        predecessor = cast(str, envelope["event_sha256"])

        candidates: list[tuple[str, Mapping[str, Any]]] = []
        if bound.spec.result_kind == "metric":
            rows = content.get("data")
            if not isinstance(rows, list):
                raise AdapterError("action_observation_malformed")
            for row in rows:
                if not isinstance(row, Mapping) or not isinstance(row.get("metric"), Mapping):
                    raise AdapterError("action_observation_malformed")
                candidates.append(("metric", cast(Mapping[str, Any], row["metric"])))
        elif bound.spec.result_kind == "log":
            rows = content.get("data")
            metadata = content.get("metadata")
            if (
                not isinstance(rows, list)
                or not isinstance(metadata, Mapping)
                or metadata.get("resultsTruncated") is not False
            ):
                raise AdapterError("action_observation_malformed")
            for row in rows:
                if not isinstance(row, Mapping) or not isinstance(
                    row.get("structuredMetadata"), Mapping
                ):
                    raise AdapterError("action_observation_malformed")
                candidates.append(("log", cast(Mapping[str, Any], row["structuredMetadata"])))
        elif bound.spec.result_kind == "trace":
            trace = content.get("trace")
            if (
                not isinstance(trace, Mapping)
                or trace.get("traceId") != bound.arguments["trace_id"]
            ):
                raise AdapterError("action_observation_malformed")
            services = trace.get("services")
            if not isinstance(services, list):
                raise AdapterError("action_observation_malformed")
            for service in services:
                if not isinstance(service, Mapping) or not isinstance(service.get("scopes"), list):
                    raise AdapterError("action_observation_malformed")
                for scope in service["scopes"]:
                    if not isinstance(scope, Mapping) or not isinstance(scope.get("spans"), list):
                        raise AdapterError("action_observation_malformed")
                    for span in scope["spans"]:
                        if not isinstance(span, Mapping) or not isinstance(
                            span.get("attributes"), Mapping
                        ):
                            raise AdapterError("action_observation_malformed")
                        attributes = cast(Mapping[str, Any], span["attributes"])
                        if "telemetry.event_id" in attributes:
                            candidates.append(("trace", attributes))
        else:  # pragma: no cover - action catalog has only these kinds
            raise AdapterError("action_evidence_binding_invalid")

        if not candidates:
            raise AdapterError("action_observation_incomplete")
        for signal, attributes in candidates:
            projected = _project_action_attributes(
                signal=signal,
                attributes=attributes,
                envelope=envelope,
                batch=batch,
                expected=expected,
            )
            if signal == "trace" and projected["trace_id"] != bound.arguments["trace_id"]:
                raise AdapterError("action_observation_correlation_mismatch")
            event_id = cast(str, projected["event_id"])
            encoded = canonical_json_bytes(projected)
            previous = accepted.get(event_id)
            if previous is None:
                accepted[event_id] = (encoded, projected)
            elif not hmac.compare_digest(previous[0], encoded):
                raise AdapterError("action_observation_event_conflict")

    values = tuple(
        child[1]
        for child in sorted(
            accepted.values(),
            key=lambda child: (
                {"metric": 0, "log": 1, "trace": 2}[cast(str, child[1]["signal"])],
                cast(str, child[1]["event_id"]),
            ),
        )
    )
    counts = {
        signal: sum(1 for child in values if child["signal"] == signal)
        for signal in ("metric", "log", "trace")
    }
    if len(values) != 21 or counts != {"metric": 8, "log": 8, "trace": 5}:
        raise AdapterError("action_observation_set_incomplete")
    return values


class EvidenceAdapter:
    def __init__(
        self,
        *,
        runtime: OfficialMcpRuntime,
        catalog: QueryCatalog,
        session_factory: SessionFactory = official_session,
        inventory_loader: InventoryLoader | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if runtime._verification is not _RUNTIME_VERIFICATION:
            raise AdapterError("runtime_unverified")
        self._runtime = runtime
        self._catalog = catalog
        self._session_factory = session_factory
        self._inventory_loader = inventory_loader
        self._clock = clock or (lambda: datetime.now(UTC))

    async def _inventory(self, session: McpSession) -> FrozenInventory:
        loader = _load_inventory if self._inventory_loader is None else self._inventory_loader
        return await loader(session)

    @property
    def simulator_action_catalog_sha256(self) -> str:
        """Exact immutable catalog authorized for simulator-action collection."""

        return self._catalog.digest

    async def verify_inventory(self) -> FrozenInventory:
        try:
            async with self._session_factory(self._runtime) as session:
                return await self._inventory(session)
        except asyncio.CancelledError:
            raise
        except AdapterError:
            raise
        except Exception:
            raise AdapterError("mcp_session_failure") from None

    @asynccontextmanager
    async def open_collection(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> AsyncIterator[EvidenceCollectionSession]:
        snapshot = _snapshot_batch(batch)
        current = self._clock().astimezone(UTC)
        if snapshot.window_end > current + timedelta(seconds=5):
            raise AdapterError("invalid_time_range")
        execution_controls = controls or ExecutionControls()
        async with self._session_factory(self._runtime) as session:
            inventory = await self._inventory(session)
            collection = EvidenceCollectionSession(
                session=session,
                runtime=self._runtime,
                catalog=self._catalog,
                batch=snapshot,
                inventory=inventory,
                controls=execution_controls,
                clock=self._clock,
            )
            try:
                yield collection
            finally:
                collection.close()

    def normalize_simulator_action_observations(
        self,
        batch: SimulatorActionEvidenceBatch,
        envelopes: Sequence[Mapping[str, Any]],
    ) -> tuple[NormalizedActionObservation, ...]:
        return normalize_simulator_action_observations(
            batch,
            envelopes,
            catalog=self._catalog,
        )

    async def collect(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> BatchResult:
        snapshot = _snapshot_batch(batch)
        current = self._clock().astimezone(UTC)
        if snapshot.window_end > current + timedelta(seconds=5):
            raise AdapterError("invalid_time_range")
        bound_calls = [_bind_call(self._catalog, snapshot, key) for key in snapshot.query_keys]
        if len(bound_calls) > 8:
            raise AdapterError("call_budget")
        budget = _CallBudget()
        local_limiter = asyncio.Semaphore(2)
        execution_controls = controls or ExecutionControls()
        try:
            async with self._session_factory(self._runtime) as session:
                inventory = await self._inventory(session)
                raw_results = await asyncio.gather(
                    *(
                        _collect_one(
                            session,
                            bound,
                            runtime=self._runtime,
                            catalog=self._catalog,
                            local_limiter=local_limiter,
                            controls=execution_controls,
                            budget=budget,
                            clock=self._clock,
                        )
                        for bound in bound_calls
                    )
                )
        except asyncio.CancelledError:
            raise
        except AdapterError:
            raise
        except Exception:
            raise AdapterError("mcp_session_failure") from None
        envelopes: list[Mapping[str, Any]] = []
        predecessor = snapshot.predecessor_event_sha256
        for raw in raw_results:
            envelope = _build_envelope(
                raw,
                batch=snapshot,
                catalog=self._catalog,
                inventory=inventory,
                predecessor=predecessor,
            )
            envelopes.append(envelope)
            predecessor = cast(str, envelope["event_sha256"])
        return BatchResult(
            inventory,
            tuple(envelopes),
            budget.calls_used,
            budget.maximum_observed_in_flight,
            tuple(attempt for raw in raw_results for attempt in raw.attempt_records),
        )

    async def collect_simulator_action(
        self,
        batch: SimulatorActionEvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> BatchResult:
        """Collect the fixed seven-query evidence set for one validated simulator action."""

        _validate_simulator_action_batch(batch)
        if batch.catalog_sha256 != self._catalog.digest:
            raise AdapterError("action_catalog_binding_invalid")
        current = self._clock().astimezone(UTC)
        if batch.snapshot_observed_at > current + timedelta(seconds=5):
            raise AdapterError("invalid_time_range")
        bound_calls = _bind_simulator_action_calls(self._catalog, batch)
        budget = _CallBudget(maximum_calls=8, maximum_in_flight=2)
        retry_budget = _RetryBudget(maximum_retries=1)
        local_limiter = asyncio.Semaphore(2)
        execution_controls = controls or ExecutionControls()
        try:
            async with self._session_factory(self._runtime) as session:
                inventory = await self._inventory(session)
                collected = await asyncio.gather(
                    *(
                        _collect_one(
                            session,
                            bound,
                            runtime=self._runtime,
                            catalog=self._catalog,
                            local_limiter=local_limiter,
                            controls=execution_controls,
                            budget=budget,
                            clock=self._clock,
                            retry_budget=retry_budget,
                        )
                        for bound in bound_calls
                    )
                )
        except asyncio.CancelledError:
            raise
        except AdapterError:
            raise
        except Exception:
            raise AdapterError("mcp_session_failure") from None

        raw_results: list[_RawCollection] = []
        for raw in collected:
            try:
                _validate_simulator_action_collection(raw, batch)
            except AdapterError as error:
                if error.code not in {
                    "incomplete_result",
                    "malformed_result",
                    "pre_action_evidence",
                }:
                    raise
                raw = _with_collection_error(raw, error.code)
            raw_results.append(raw)

        envelopes: list[Mapping[str, Any]] = []
        predecessor = batch.predecessor_event_sha256
        for raw in raw_results:
            envelope = _build_envelope(
                raw,
                batch=batch,
                catalog=self._catalog,
                inventory=inventory,
                predecessor=predecessor,
            )
            envelopes.append(envelope)
            predecessor = cast(str, envelope["event_sha256"])
        return BatchResult(
            inventory,
            tuple(envelopes),
            budget.calls_used,
            budget.maximum_observed_in_flight,
            tuple(attempt for raw in raw_results for attempt in raw.attempt_records),
        )

    async def collect_simulator_action_projection(
        self,
        batch: SimulatorActionEvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> SimulatorActionEvidenceProjection:
        result = await self.collect_simulator_action(batch, controls=controls)
        observations = self.normalize_simulator_action_observations(batch, result.envelopes)
        completed_at = self._clock()
        if completed_at.tzinfo is None:
            raise AdapterError("action_collection_clock_invalid")
        completed_at = completed_at.astimezone(UTC)
        if any(_parse_timestamp(value.retrieved_at) > completed_at for value in observations):
            raise AdapterError("action_collection_clock_invalid")
        return SimulatorActionEvidenceProjection(
            request_id=batch.request_id,
            evidence_request_id=batch.evidence_request_id,
            evidence_request_sha256=batch.evidence_request_sha256,
            catalog_sha256=batch.catalog_sha256,
            incident_id=batch.incident_id,
            outcome_id=batch.outcome_id,
            outcome_sha256=batch.outcome_sha256,
            snapshot_id=batch.snapshot_id,
            snapshot_sha256=batch.snapshot_sha256,
            action_id=batch.action_id,
            operation_id=batch.operation_id,
            completed_at=completed_at,
            observations=observations,
        )
