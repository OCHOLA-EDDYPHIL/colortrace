from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

SCHEMA_ROOT = Path(__file__).parent / "schemas"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ContractError(ValueError):
    pass


def canonical_json_bytes(value: Any) -> bytes:
    def reject(child: Any) -> None:
        if isinstance(child, float):
            raise ContractError("floating-point-values-prohibited")
        if isinstance(child, Mapping):
            for key, item in child.items():
                if not isinstance(key, str):
                    raise ContractError("non-string-key")
                reject(item)
        elif isinstance(child, (list, tuple)):
            for item in child:
                reject(item)

    reject(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def prefixed_sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return f"sha256:{digest.hexdigest()}"


def strict_json_file(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in pairs:
            if key in result:
                raise ContractError("duplicate-json-key")
            result[key] = child
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("invalid-json") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != raw.rstrip(b"\n"):
        raise ContractError("non-canonical-json")
    return cast(dict[str, Any], value)


def validate_schema(name: str, value: Mapping[str, Any]) -> None:
    schema = json.loads((SCHEMA_ROOT / name).read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        raise ContractError(f"schema-invalid:{name}:{errors[0].json_path}")


def write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    data = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ContractError("output-exists") from error
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def require_digest(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ContractError(code)
    return value
