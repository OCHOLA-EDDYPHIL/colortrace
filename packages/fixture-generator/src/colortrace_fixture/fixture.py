"""Deterministic synthetic incident fixture generation and evaluation."""

from __future__ import annotations

import argparse
import binascii
import ctypes
import hashlib
import json
import math
import os
import resource
import stat
import struct
import subprocess
import sys
import tempfile
import zlib
from array import array
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any, cast

import PyOpenColorIO as ocio  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, ValidationError  # type: ignore[import-untyped]

if __package__:
    from .reference_media import (
        REFERENCE_MEDIA_MANIFEST,
        fetch_reference_media,
        load_reference_media_manifest,
        verify_reference_media,
    )
else:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from colortrace_fixture.reference_media import (  # noqa: E402
        REFERENCE_MEDIA_MANIFEST,
        fetch_reference_media,
        load_reference_media_manifest,
        verify_reference_media,
    )

WIDTH = 512
HEIGHT = 288
CHANNELS = 3
PIXELS = WIDTH * HEIGHT
FLOAT_HEADER = struct.pack(">II", WIDTH, HEIGHT) + b"RGBF32BE\x00"
FIXTURE_ID = "ct-shadowed-lut-v1"
FIXTURE_VERSION = "colortrace-fixture/v1"
RUNTIME_MANIFEST_VERSION = "fixture-runtime-manifest/v1"
RESOURCE_MANIFEST_VERSION = "resolved-resource-manifest/v1"
LINEAGE_VERSION = "artifact-lineage/v1"
COMPARISON_VERSION = "declared-reference-comparison/v1"
VALIDATOR_REPORT_VERSION = "fixture-validator-report/v1"
VALIDATOR_RECEIPT_VERSION = "validator-receipt/v1"
ORACLE_VERSION = "fixture-oracle/v1"
GENERATED_CHART_VERSION = "generated-chart/v1"
FROZEN_PLATE_VERSION = "frozen-vertex-gemini-plate/v1"
SOURCE_SET_VERSION = "mixed-source-set/v1"
GENERATOR_VERSION = SOURCE_SET_VERSION
FLOAT_BUFFER_VERSION = "rgb-float32-buffer/v1"
DERIVATIVE_VERSION = "lossless-float-copy/v1"
DISPLAY_VERSION = "supplementary-display-png/v1"
OCIO_VERSION = "2.5.2"
OCIO_WHEEL_SHA256 = "3d0ab1c398d560513c651c7b9c676e68f264a63b97e29fec21722d4270f865aa"
FROZEN_CHART2_SHA256 = "7500776f9b97942cdea7ab429dcb95b4d7f916d5bd06b4ce2fb19912e2f4724a"
FROZEN_CHART2_GENERATION_SHA256 = "a6054b66a458c77eff808364b785dc104e7592844fac88338c85dc7fe89a96d6"
CANONICAL_SEED = "ct-shadowed-lut-v1:canonical"
PERMUTED_SEED = "ct-shadowed-lut-v1:hidden-a"
CANONICAL_DIGESTS_SHA256 = "34c91bd84d6d84a7c3ea27dcce0bb492f7efa5567af66e86d66027c289c151b4"
CANONICAL_PREVALIDATION_TREE_SHA256 = (
    "cb66a010391c5f0aa333d9224ce605fe98a8a07cd75c93d41fa4bdd5f58742b8"
)
CANONICAL_PREVALIDATION_DIRECTORIES_SHA256 = (
    "da498138ffdb297d06d06997e502b5adae80fd8a481ab1f2fe6f54ef6f3ff845"
)
CANONICAL_WORKER_TREE_SHA256 = "539e318c5f9a3091e250ee4dbc894b97b3a688af0afa5bf001d9326a3fa37180"
CANONICAL_WORKER_DIRECTORIES_SHA256 = (
    "6a0cff9e08502992ea48ee8d69c47ab8f4a669c255bc4dae2d2b57ad2e74d793"
)
CANONICAL_BUILD_UID = 65534
CANONICAL_BUILD_GID = 65534
FIXED_T0 = "2026-08-11T00:00:00Z"
CONFIG_NAME = "config.ocio"
LUT_LOGICAL_PATH = "luts/show_look.cube"
SCHEMA_ROOT = Path(__file__).parent / "schemas"
ASSET_ROOT = Path(__file__).parent / "assets"
FROZEN_CHART2_PATH = ASSET_ROOT / "chart-02.rgb16be"
FROZEN_CHART2_GENERATION_PATH = ASSET_ROOT / "chart-02-generation.json"
SOURCE_PIXEL_MAGIC = b"RGB16BE"
SOURCE_PIXEL_HEADER_SIZE = struct.calcsize(">II") + len(SOURCE_PIXEL_MAGIC)
SOURCE_PIXEL_BYTE_LENGTH = SOURCE_PIXEL_HEADER_SIZE + PIXELS * CHANNELS * 2
SCHEMA_FILES = {
    "artifact-lineage/v1": "artifact-lineage-v1.schema.json",
    "declared-approved-resources/v1": "declared-approved-resources-v1.schema.json",
    "declared-reference/v1": "declared-reference-v1.schema.json",
    "fixture-job/v1": "fixture-job-v1.schema.json",
    "fixture-oracle/v1": "fixture-oracle-v1.schema.json",
    "fixture-build-provenance/v1": "fixture-build-provenance-v1.schema.json",
    "fixture-provenance/v1": "fixture-provenance-v1.schema.json",
    "fixture-runtime-manifest/v1": "fixture-runtime-manifest-v1.schema.json",
    "fixture-telemetry/v1": "fixture-telemetry-v1.schema.json",
    "frozen-source-generation/v1": "frozen-source-generation-v1.schema.json",
    VALIDATOR_REPORT_VERSION: "fixture-validator-report-v1.schema.json",
    "generated-source/v1": "generated-source-v1.schema.json",
    "resolved-resource-manifest/v1": "resolved-resource-manifest-v1.schema.json",
    VALIDATOR_RECEIPT_VERSION: "validator-receipt-v1.schema.json",
}

PALETTE = (
    (0, 0, 0),
    (65535, 65535, 65535),
    (65535, 8192, 8192),
    (8192, 65535, 8192),
    (8192, 8192, 65535),
    (65535, 49152, 8192),
    (8192, 57344, 65535),
    (49152, 8192, 57344),
)

MANIFEST_PATH_KEYS = frozenset(
    {
        "buffer",
        "config",
        "declared_reference_manifest",
        "display",
        "display_png",
        "fixture_runtime_manifest",
        "manifest",
        "output_buffer",
        "path",
        "report",
        "resource_manifest",
        "source_manifest",
        "stored_png",
    }
)
RUNTIME_RELATIVE_PATH_KEYS = frozenset({"config_root_relative_path", "resolved_root_relative_path"})

CANONICAL_VALIDATOR_OUTPUTS = frozenset(
    {
        "reports/diffs/job-a-01.png",
        "reports/diffs/job-a-02.png",
        "reports/diffs/job-b-01.png",
        "reports/diffs/job-b-02.png",
        "reports/diffs/job-b-03.png",
        "reports/diffs/job-b-04.png",
        "reports/validator-invocation-receipt.json",
        "reports/validator-receipt.json",
        "reports/validator-report.json",
    }
)

CONFIG_TEXT = """ocio_profile_version: 2

environment: {}
search_path: luts
strictparsing: true
family_separator: /
luma: [0.2126, 0.7152, 0.0722]

roles:
  default: fixture_input
  scene_linear: fixture_input

file_rules:
  - !<Rule> {name: Default, colorspace: fixture_input}

displays:
  fixture:
    - !<View> {name: Raw, colorspace: fixture_output}
active_displays: [fixture]
active_views: [Raw]

colorspaces:
  - !<ColorSpace>
    name: fixture_input
    family: fixture
    bitdepth: 32f
    isdata: false
    allocation: uniform

  - !<ColorSpace>
    name: fixture_output
    family: fixture
    bitdepth: 32f
    isdata: false
    allocation: uniform
    from_scene_reference: !<FileTransform> {src: show_look.cube, interpolation: tetrahedral}
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    """Emit JCS-compatible JSON for this harness' ASCII-key, no-float values."""

    def reject_float(item: Any) -> None:
        if isinstance(item, float):
            raise TypeError("manifest floats must be encoded as decimal strings")
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("manifest keys must be strings")
                reject_float(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                reject_float(child)

    reject_float(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_bytes(path: Path, data: bytes, mode: int = 0o600) -> str:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(mode)
    return sha256_bytes(data)


def write_json(path: Path, value: Any, mode: int = 0o600) -> str:
    return write_bytes(path, canonical_json_bytes(value), mode)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def checked_relative_path(root: Path, value: str, *, base: Path | None = None) -> Path:
    if not value or "\\" in value or "$" in value:
        raise ValueError(f"unsafe manifest path: {value!r}")
    logical = PurePosixPath(value)
    if logical.is_absolute() or any(part in ("", ".", "..") for part in logical.parts):
        raise ValueError(f"unsafe manifest path: {value!r}")
    root = root.resolve()
    candidate = (base or root).joinpath(*logical.parts)
    resolved_parent = candidate.parent.resolve(strict=True)
    try:
        resolved_parent.relative_to(root)
    except ValueError as error:
        raise ValueError(f"manifest path escapes bundle: {value!r}") from error
    if candidate.exists() or candidate.is_symlink():
        if candidate.is_symlink():
            raise ValueError(f"manifest path is a symlink: {value!r}")
        resolved = candidate.resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as error:
            raise ValueError(f"manifest path escapes bundle: {value!r}") from error
        if resolved.stat().st_nlink != 1:
            raise ValueError(f"manifest path is hard-linked: {value!r}")
    return candidate


def _walk_manifest_paths(value: Any) -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in MANIFEST_PATH_KEYS | RUNTIME_RELATIVE_PATH_KEYS and isinstance(child, str):
                yield key, child
            yield from _walk_manifest_paths(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_manifest_paths(child)


def audit_bundle_paths(bundle_root: Path, oracle_path: Path | None = None) -> None:
    bundle_root = bundle_root.resolve(strict=True)
    folded: dict[str, str] = {}
    inodes: dict[tuple[int, int], str] = {}
    files = sorted(item for item in bundle_root.rglob("*") if item.is_file() or item.is_symlink())
    if oracle_path is not None:
        files.append(oracle_path)
    for path in files:
        if path.is_symlink():
            raise ValueError(f"symlink prohibited: {path}")
        if not path.is_file():
            raise ValueError(f"non-regular artifact prohibited: {path}")
        relative = (
            path.relative_to(bundle_root).as_posix()
            if path.is_relative_to(bundle_root)
            else f"oracle:{path.name}"
        )
        folded_path = relative.casefold()
        if folded_path in folded and folded[folded_path] != relative:
            raise ValueError(f"case-alias paths prohibited: {folded[folded_path]!r}, {relative!r}")
        folded[folded_path] = relative
        stat_result = path.stat()
        if path.is_relative_to(bundle_root / "runtime") or path.is_relative_to(
            bundle_root / "references"
        ):
            if stat.S_IMODE(stat_result.st_mode) & 0o222:
                raise ValueError(f"mutable runtime/reference input prohibited: {relative}")
        if stat_result.st_nlink != 1:
            raise ValueError(f"hard-linked artifact prohibited: {relative}")
        inode = (stat_result.st_dev, stat_result.st_ino)
        if inode in inodes:
            raise ValueError(f"cross-root hard link prohibited: {inodes[inode]!r}, {relative!r}")
        inodes[inode] = relative
    for path in sorted(bundle_root.rglob("*.json")):
        document = read_json(path)
        for key, value in _walk_manifest_paths(document):
            base = bundle_root / "runtime" if key in RUNTIME_RELATIVE_PATH_KEYS else bundle_root
            checked_relative_path(bundle_root, value, base=base)


def finalize_bundle_inputs(bundle_root: Path) -> None:
    for subtree in (bundle_root / "runtime", bundle_root / "references"):
        for path in sorted(subtree.rglob("*"), reverse=True):
            path.chmod(0o555 if path.is_dir() else 0o444)
        subtree.chmod(0o555)


@cache
def contract_validators() -> dict[str, Draft202012Validator]:
    validators: dict[str, Draft202012Validator] = {}
    for schema_name, filename in SCHEMA_FILES.items():
        schema = read_json(SCHEMA_ROOT / filename)
        Draft202012Validator.check_schema(schema)
        validators[schema_name] = Draft202012Validator(schema)
    return validators


def validate_contract_document(document: dict[str, Any]) -> None:
    schema_name = document.get("schema")
    if not isinstance(schema_name, str) or schema_name not in SCHEMA_FILES:
        raise ValueError("document does not declare a registered fixture schema")
    try:
        contract_validators()[schema_name].validate(document)
    except ValidationError as error:
        raise ValueError(f"{schema_name} schema validation failed: {error.message}") from error


def validate_contract_instances(bundle_root: Path, oracle_path: Path | None = None) -> None:
    validators = contract_validators()
    paths = list(bundle_root.rglob("*.json"))
    if oracle_path is not None:
        paths.append(oracle_path)
    for path in sorted(paths):
        document = read_json(path)
        if isinstance(document, dict) and document.get("schema") in validators:
            validate_contract_document(document)


def enter_bundle_landlock(bundle_root: Path) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    create_ruleset = 444
    add_rule = 445
    restrict_self = 446
    abi = syscall(create_ruleset, 0, 0, 1)
    if abi < 1:
        error = ctypes.get_errno()
        raise OSError(error, "Landlock is unavailable")

    class RulesetAttr(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class PathBeneathAttr(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    handled_access = (1 << 13) - 1
    ruleset_attr = RulesetAttr(handled_access)
    ruleset_fd = syscall(create_ruleset, ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), 0)
    if ruleset_fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, "cannot create Landlock ruleset")
    bundle_fd = os.open(bundle_root, os.O_PATH | os.O_CLOEXEC)
    reports_fd = os.open(bundle_root / "reports", os.O_PATH | os.O_CLOEXEC)
    try:
        for parent_fd, allowed_access in (
            (bundle_fd, (1 << 0) | (1 << 2) | (1 << 3)),
            (reports_fd, handled_access),
        ):
            path_attr = PathBeneathAttr(allowed_access, parent_fd)
            if syscall(add_rule, ruleset_fd, 1, ctypes.byref(path_attr), 0) != 0:
                error = ctypes.get_errno()
                raise OSError(error, "cannot add Landlock path rule")
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "cannot enable no_new_privs")
        if syscall(restrict_self, ruleset_fd, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "cannot enforce Landlock ruleset")
    finally:
        os.close(bundle_fd)
        os.close(reports_fd)
        os.close(ruleset_fd)
    return int(abi)


def fmt(value: float) -> str:
    return format(value, ".12g")


def stable_key(seed: str, namespace: str, item: str) -> bytes:
    return hashlib.sha256(
        seed.encode("utf-8") + b"\x00" + namespace.encode("utf-8") + b"\x00" + item.encode("utf-8")
    ).digest()


def stable_order(seed: str, namespace: str, items: Iterable[str]) -> list[str]:
    return sorted(items, key=lambda item: (stable_key(seed, namespace, item), item))


def changed_order[T](seed: str, namespace: str, items: Iterable[T]) -> list[T]:
    original = list(items)
    ordered = sorted(
        original,
        key=lambda item: (stable_key(seed, namespace, str(item)), str(item)),
    )
    return list(reversed(ordered)) if ordered == original else ordered


def opaque_id(seed: str, namespace: str, role: str) -> str:
    material = (seed + chr(0) + namespace + chr(0) + role).encode()
    return f"{namespace}-{hashlib.sha256(material).hexdigest()[:12]}"


def trace_id(seed: str, role: str) -> str:
    value = stable_key(seed, "trace", role).hex()[:32]
    if value == "0" * 32:
        raise RuntimeError("trace identifier must be nonzero")
    return value


def stable_processor_identity(
    config_sha256: str, transform: str, resource_sha256: str | None
) -> str:
    return sha256_bytes(
        canonical_json_bytes(
            {
                "ocio_version": OCIO_VERSION,
                "config_sha256": config_sha256,
                "transform_id": transform,
                "resolved_resource_sha256": resource_sha256,
            }
        )
    )


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF)
    )


def png16_bytes(samples: array[int]) -> bytes:
    if samples.typecode != "H" or len(samples) != PIXELS * CHANNELS:
        raise ValueError("expected RGB16 sample array")
    rows = bytearray()
    stride = WIDTH * CHANNELS
    for y in range(HEIGHT):
        rows.append(0)
        row = array("H", samples[y * stride : (y + 1) * stride])
        if sys.byteorder == "little":
            row.byteswap()
        rows.extend(row.tobytes())
    ihdr = struct.pack(">IIBBBBB", WIDTH, HEIGHT, 16, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + png_chunk(b"IEND", b"")
    )


def source_pixel_bytes(samples: array[int]) -> bytes:
    values = array("H", samples)
    if sys.byteorder == "little":
        values.byteswap()
    return struct.pack(">II", WIDTH, HEIGHT) + SOURCE_PIXEL_MAGIC + values.tobytes()


def _strict_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate key in {label}: {key!r}")
            result[key] = value
        return result

    try:
        document = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON in {label}") from error
    if not isinstance(document, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return document


def _validate_frozen_chart2_record(document: dict[str, Any], asset_sha256: str) -> None:
    validate_contract_document(document)
    prompt = document["prompt"]
    for text_key, digest_key in (
        ("text", "sha256"),
        ("effective_text", "effective_sha256"),
        ("visual_exclusions", "visual_exclusions_sha256"),
    ):
        if sha256_bytes(prompt[text_key].encode("utf-8")) != prompt[digest_key]:
            raise ValueError(f"frozen chart-02 {text_key} hash mismatch")

    candidates = document["candidates"]
    if [candidate["index"] for candidate in candidates] != [1, 2, 3]:
        raise ValueError("frozen chart-02 candidates must have ordered indices 1, 2, 3")
    for field in ("seed", "raw_png_sha256", "canonical_rgb16be_sha256"):
        if len({candidate[field] for candidate in candidates}) != 3:
            raise ValueError(f"frozen chart-02 candidates must have unique {field} values")
    selected = [candidate for candidate in candidates if candidate["selected"]]
    if len(selected) != 1:
        raise ValueError("frozen chart-02 must have exactly one selected candidate")
    selected_candidate = selected[0]
    selection = document["selection"]
    if selected_candidate["index"] != selection["selected_candidate_index"]:
        raise ValueError("frozen chart-02 selected candidate index mismatch")
    if (
        selected_candidate["canonical_rgb16be_sha256"] != asset_sha256
        or selection["asset"]["sha256"] != asset_sha256
        or asset_sha256 != FROZEN_CHART2_SHA256
    ):
        raise ValueError("frozen chart-02 selected asset hash mismatch")
    if any(
        candidate["approved_self_comparison"]["state"] != "reference_match"
        or candidate["shadowed_comparison"]["state"] != "reference_mismatch"
        for candidate in candidates
    ):
        raise ValueError("frozen chart-02 deterministic color gate failed")
    for candidate in candidates:
        approved = candidate["approved_self_comparison"]
        shadowed = candidate["shadowed_comparison"]
        if (
            Decimal(approved["maximum_absolute_channel_error"]) > Decimal("0.000001")
            or Decimal(approved["rmse"]) > Decimal("0.0000005")
            or Decimal(shadowed["maximum_absolute_channel_error"]) <= Decimal("0.0001")
            or Decimal(shadowed["fraction_pixels_at_or_above_0_02"]) < Decimal("0.10")
            or Decimal(shadowed["nearest_rank_p95"]) < Decimal("0.04")
        ):
            raise ValueError("frozen chart-02 deterministic color metrics fail policy")
    if (
        selection["visual_approval"]["approved"] is not True
        or selection["license_decision"]["approved"] is not True
        or selection["license_decision"]["license"] != "Apache-2.0"
        or document["terms_review"]["approved_for_apache_2_0_inclusion"] is not True
    ):
        raise ValueError("frozen chart-02 approval or license gate is not satisfied")


def load_frozen_chart2_samples(
    asset_path: Path = FROZEN_CHART2_PATH,
    generation_path: Path = FROZEN_CHART2_GENERATION_PATH,
) -> array[int]:
    for path, label in (
        (asset_path, "frozen chart-02 asset"),
        (generation_path, "frozen chart-02 generation record"),
    ):
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError(f"{label} must be one regular, non-linked file")

    generation_bytes = generation_path.read_bytes()
    if sha256_bytes(generation_bytes) != FROZEN_CHART2_GENERATION_SHA256:
        raise ValueError("frozen chart-02 generation record hash mismatch")
    generation = _strict_json_object(generation_bytes, label="frozen chart-02 generation record")

    data = asset_path.read_bytes()
    if len(data) != SOURCE_PIXEL_BYTE_LENGTH:
        raise ValueError("frozen chart-02 asset length mismatch")
    width, height = struct.unpack(">II", data[:8])
    if (width, height) != (WIDTH, HEIGHT) or data[8:SOURCE_PIXEL_HEADER_SIZE] != SOURCE_PIXEL_MAGIC:
        raise ValueError("frozen chart-02 asset header mismatch")
    asset_sha256 = sha256_bytes(data)
    _validate_frozen_chart2_record(generation, asset_sha256)
    if generation["selection"]["asset"]["byte_length"] != len(data):
        raise ValueError("frozen chart-02 recorded byte length mismatch")

    samples = array("H")
    samples.frombytes(data[SOURCE_PIXEL_HEADER_SIZE:])
    if sys.byteorder == "little":
        samples.byteswap()
    if len(samples) != PIXELS * CHANNELS:
        raise ValueError("frozen chart-02 sample count mismatch")
    if any(sample % 257 for sample in samples):
        raise ValueError("frozen chart-02 samples are not exact RGB8-to-RGB16 promotions")
    if source_pixel_bytes(samples) != data:
        raise ValueError("frozen chart-02 asset is not canonical RGB16BE")
    return samples


def chart_samples(chart_id: str) -> array[int]:
    chart = int(chart_id.split("-")[-1])
    if chart not in (1, 2, 3, 4):
        raise ValueError(chart_id)
    if chart == 2:
        return load_frozen_chart2_samples()
    values = array("H")
    append = values.append
    for y in range(HEIGHT):
        v = (65535 * y + 143) // 287
        for x in range(WIDTH):
            u = (65535 * x + 255) // 511
            n = (u + v) // 2
            q = ((x // 64) + 2 * (y // 48)) % 8
            if chart == 1:
                pixel = (u, v, n)
            elif chart == 3:
                pixel = PALETTE[q]
            else:
                pixel = (n, n, n) if q % 2 == 0 else (65535 - n,) * 3
            for channel in pixel:
                append(channel)
    return values


def source_to_float(samples: array[int]) -> array[float]:
    return array("f", (sample / 65535.0 for sample in samples))


def canonical_float_bytes(values: array[float]) -> bytes:
    if values.typecode != "f" or len(values) != PIXELS * CHANNELS:
        raise ValueError("expected packed RGB float32 array")
    normalized = array("f")
    append = normalized.append
    for value in values:
        if not math.isfinite(value):
            raise ValueError("non-finite float buffer")
        append(0.0 if value == 0.0 else value)
    if sys.byteorder == "little":
        normalized.byteswap()
    return FLOAT_HEADER + normalized.tobytes()


def read_float_buffer(path: Path) -> array[float]:
    data = path.read_bytes()
    if not data.startswith(FLOAT_HEADER):
        raise ValueError(f"invalid float buffer header: {path}")
    payload = data[len(FLOAT_HEADER) :]
    if len(payload) != PIXELS * CHANNELS * 4:
        raise ValueError(f"invalid float buffer length: {path}")
    values = array("f")
    values.frombytes(payload)
    if sys.byteorder == "little":
        values.byteswap()
    if any(not math.isfinite(value) for value in values):
        raise ValueError(f"non-finite float buffer: {path}")
    return values


def display_samples(values: array[float]) -> array[int]:
    result = array("H")
    append = result.append
    for value in values:
        clamped = min(1.0, max(0.0, float(value)))
        append(int(math.floor(clamped * 65535.0 + 0.5)))
    return result


def diff_samples(output: array[float], reference: array[float]) -> array[int]:
    result = array("H")
    append = result.append
    for i in range(0, len(output), 3):
        difference = max(abs(float(output[i + c]) - float(reference[i + c])) for c in range(3))
        intensity = min(1.0, difference / 0.16)
        red = int(math.floor(intensity * 65535.0 + 0.5))
        green = int(math.floor(max(0.0, 1.0 - intensity) * intensity * 32768.0 + 0.5))
        append(red)
        append(green)
        append(0)
    return result


def compare_buffers(output: array[float], reference: array[float]) -> dict[str, Any]:
    if len(output) != len(reference) or len(output) != PIXELS * CHANNELS:
        return {"state": "unresolved", "reason": "dimension-or-channel-mismatch"}
    per_pixel: list[float] = []
    squares: list[float] = []
    for i in range(0, len(output), 3):
        differences = [abs(float(output[i + c]) - float(reference[i + c])) for c in range(3)]
        per_pixel.append(max(differences))
        squares.extend(value * value for value in differences)
    ordered = sorted(per_pixel)
    maximum = ordered[-1]
    p95 = ordered[math.ceil(0.95 * len(ordered)) - 1]
    fraction = sum(value >= 0.02 for value in per_pixel) / len(per_pixel)
    rmse = math.sqrt(math.fsum(squares) / len(squares))
    if maximum <= 0.000001 and rmse <= 0.0000005:
        state = "reference_match"
    elif maximum > 0.0001 and fraction >= 0.10 and p95 >= 0.04:
        state = "reference_mismatch"
    else:
        state = "unresolved"
    return {
        "state": state,
        "maximum_absolute_channel_error": fmt(maximum),
        "rmse": fmt(rmse),
        "fraction_pixels_at_or_above_0_02": fmt(fraction),
        "nearest_rank_p95": fmt(p95),
        "pixels": PIXELS,
        "policy": COMPARISON_VERSION,
    }


def lut_bytes(kind: str) -> bytes:
    if kind not in ("approved", "shadowed"):
        raise ValueError(kind)
    quantizer = Decimal("0.0000000001")

    def decimal_text(value: Decimal) -> str:
        return format(value.quantize(quantizer, rounding=ROUND_HALF_EVEN), "f")

    lines = [
        f'TITLE "ColorTrace {"approved " if kind == "approved" else ""}generated LUT"',
        "LUT_3D_SIZE 17",
        "DOMAIN_MIN 0.0 0.0 0.0",
        "DOMAIN_MAX 1.0 1.0 1.0",
    ]
    zero = Decimal(0)
    one = Decimal(1)

    def clamp(value: Decimal) -> Decimal:
        return max(zero, min(one, value))

    for b in range(17):
        B = Decimal(b) / Decimal(16)
        for g in range(17):
            G = Decimal(g) / Decimal(16)
            for r in range(17):
                R = Decimal(r) / Decimal(16)
                if kind == "approved":
                    output = (R, G, B)
                else:
                    output = (
                        clamp(Decimal("1.08") * R + Decimal("0.04") * B),
                        clamp(Decimal("0.90") * G + Decimal("0.02") * R),
                        clamp(Decimal("0.78") * B + Decimal("0.06") * G),
                    )
                lines.append(" ".join(decimal_text(value) for value in output))
    return ("\n".join(lines) + "\n").encode("ascii")


@dataclass(frozen=True)
class WorkerInfo:
    worker: str
    root: Path
    config_path: Path
    lut_path: Path
    config_sha256: str
    lut_sha256: str
    config_cache_id: str
    resolved_lut: str


def prepare_worker(runtime: Path, worker: str, lut: bytes) -> WorkerInfo:
    root = runtime / "workers" / worker
    config_path = root / "config" / CONFIG_NAME
    lut_path = root / "config" / "luts" / "show_look.cube"
    config_sha = write_bytes(config_path, CONFIG_TEXT.encode("utf-8"), 0o444)
    lut_sha = write_bytes(lut_path, lut, 0o444)
    if config_path.is_symlink() or lut_path.is_symlink():
        raise RuntimeError("symlink prohibited")
    if config_path.stat().st_nlink != 1 or lut_path.stat().st_nlink != 1:
        raise RuntimeError("cross-root hard link prohibited")
    ocio.ClearAllCaches()
    config = ocio.Config.CreateFromFile(str(config_path))
    config.validate()
    context = config.getCurrentContext()
    resolved = Path(context.resolveFileLocation("show_look.cube")).resolve()
    expected = lut_path.resolve()
    if resolved != expected or not resolved.is_relative_to(root.resolve()):
        raise RuntimeError(f"unexpected resource resolution: {resolved} != {expected}")
    return WorkerInfo(
        worker=worker,
        root=root,
        config_path=config_path,
        lut_path=lut_path,
        config_sha256=config_sha,
        lut_sha256=lut_sha,
        config_cache_id=config.getCacheID(),
        resolved_lut=rel(resolved, runtime),
    )


def apply_ocio(
    config_path: Path, transform: str, source: array[float]
) -> tuple[array[float], dict[str, str]]:
    ocio.ClearAllCaches()
    config = ocio.Config.CreateFromFile(str(config_path))
    config.validate()
    if transform == "look/main/v1":
        processor = config.getProcessor("fixture_input", "fixture_output")
    elif transform == "identity/v1":
        processor = config.getProcessor("fixture_input", "fixture_input")
    else:
        raise ValueError(transform)
    cpu = processor.getDefaultCPUProcessor()
    # PackedImageDesc's Python binding requires NumPy.  Keep this disposable
    # proof dependency-free by applying the real OCIO CPU processor per RGB
    # pixel; applyRGB returns the processor's float32 result.
    output = array("f")
    append = output.append
    for index in range(0, len(source), CHANNELS):
        processed = cpu.applyRGB((source[index], source[index + 1], source[index + 2]))
        append(processed[0])
        append(processed[1])
        append(processed[2])
    return output, {
        "config_cache_id": config.getCacheID(),
        "processor_cache_id": processor.getCacheID(),
        "cpu_processor_cache_id": cpu.getCacheID(),
    }


def job_roles(permuted: bool, seed: str) -> tuple[list[dict[str, Any]], str, str]:
    base: list[dict[str, Any]] = [
        {
            "role": "a1",
            "worker": "A",
            "source": "chart-01",
            "transform": "look/main/v1",
            "offset": 0,
        },
        {
            "role": "a2",
            "worker": "A",
            "source": "chart-02",
            "transform": "look/main/v1",
            "offset": 25,
        },
        {
            "role": "b1",
            "worker": "B",
            "source": "chart-01",
            "transform": "look/main/v1",
            "offset": 10,
        },
        {
            "role": "b2",
            "worker": "B",
            "source": "chart-02",
            "transform": "look/main/v1",
            "offset": 40,
        },
        {
            "role": "b3",
            "worker": "B",
            "source": "chart-03",
            "transform": "look/main/v1",
            "offset": 55,
        },
        {
            "role": "b4",
            "worker": "B",
            "source": "chart-04",
            "transform": "identity/v1",
            "offset": 10,
        },
    ]
    if not permuted:
        ids = {
            item["role"]: f"job-{item['worker'].lower()}-{int(item['role'][1:]):02d}"
            for item in base
        }
        derivative_parent = "b2"
        event_affected_role = "b1"
    else:
        ids = {item["role"]: opaque_id(seed, "job", item["role"]) for item in base}
        affected_sources = changed_order(
            seed, "affected-sources", ["chart-01", "chart-02", "chart-03"]
        )
        a_sources = changed_order(seed, "a-sources", ["chart-01", "chart-02"])
        for item, source in zip(
            [x for x in base if x["role"] in ("b1", "b2", "b3")],
            affected_sources,
            strict=True,
        ):
            item["source"] = source
        for item, source in zip(
            [x for x in base if x["role"] in ("a1", "a2")], a_sources, strict=True
        ):
            item["source"] = source
        derivative_parent = stable_order(seed, "derivative-parent", ["b1", "b2", "b3"])[0]
        event_affected_role = stable_order(seed, "event-overlap", ["b1", "b2", "b3"])[0]
        permuted_offsets = changed_order(seed, "schedule", [5, 20, 35, 50, 65, 80])
        for item, offset in zip(base, permuted_offsets, strict=True):
            item["offset"] = offset
        affected_offset = next(
            item["offset"] for item in base if item["role"] == event_affected_role
        )
        next(item for item in base if item["role"] == "b4")["offset"] = affected_offset
    jobs = []
    for item in base:
        jobs.append(
            {**item, "job_id": ids[item["role"]], "output_id": f"output-{ids[item['role']]}"}
        )
    derivative_parent_id = next(
        item["job_id"] for item in jobs if item["role"] == derivative_parent
    )
    event_affected_id = next(item["job_id"] for item in jobs if item["role"] == event_affected_role)
    return jobs, derivative_parent_id, event_affected_id


def reference_id(source: str, transform: str) -> str:
    suffix = "look" if transform == "look/main/v1" else "identity"
    return f"reference-{source}-{suffix}"


def build_scenario(
    scenario_root: Path,
    *,
    oracle_root: Path | None = None,
    variant_id: str,
    seed: str,
    permuted: bool = False,
    omit_resource_role: str | None = None,
    omit_reference_role: str | None = None,
) -> dict[str, Any]:
    scenario_root = scenario_root.resolve()
    oracle_root = (
        oracle_root.resolve()
        if oracle_root
        else scenario_root.parent / f"{scenario_root.name}-oracle"
    )
    if (
        scenario_root == oracle_root
        or scenario_root in oracle_root.parents
        or oracle_root in scenario_root.parents
    ):
        raise ValueError("runtime bundle and oracle roots must be separate, non-nested paths")
    if scenario_root.exists() or oracle_root.exists():
        raise FileExistsError(scenario_root if scenario_root.exists() else oracle_root)
    for name in ("runtime", "references", "reports"):
        (scenario_root / name).mkdir(parents=True, mode=0o700)
    oracle_root.mkdir(parents=True, mode=0o700)
    runtime = scenario_root / "runtime"
    references = scenario_root / "references"
    reports = scenario_root / "reports"

    approved_lut = lut_bytes("approved")
    shadowed_lut = lut_bytes("shadowed")
    worker_ids = (
        {"A": opaque_id(seed, "worker", "A"), "B": opaque_id(seed, "worker", "B")}
        if permuted
        else {"A": "A", "B": "B"}
    )
    workers = {
        "A": prepare_worker(runtime, worker_ids["A"], approved_lut),
        "B": prepare_worker(runtime, worker_ids["B"], shadowed_lut),
    }
    if workers["A"].config_sha256 != workers["B"].config_sha256:
        raise RuntimeError("worker configs are not byte-identical")
    if workers["A"].lut_sha256 == workers["B"].lut_sha256:
        raise RuntimeError("worker LUTs unexpectedly match")
    provenance_assets: list[dict[str, Any]] = []
    for worker in workers.values():
        provenance_assets.extend(
            [
                {
                    "asset_id": f"config-{worker.worker}",
                    "asset_kind": "ocio-config",
                    "path": rel(worker.config_path, scenario_root),
                    "sha256": worker.config_sha256,
                    "generator": "fixture-ocio-config/v1",
                    "license": "Apache-2.0",
                },
                {
                    "asset_id": f"lut-{worker.worker}",
                    "asset_kind": "generated-lut",
                    "path": rel(worker.lut_path, scenario_root),
                    "sha256": worker.lut_sha256,
                    "generator": "generated-lut/v1",
                    "license": "Apache-2.0",
                },
            ]
        )

    source_floats: dict[str, array[float]] = {}
    source_index: list[dict[str, Any]] = []
    source_ids = {
        chart: (chart if not permuted else opaque_id(seed, "source", chart))
        for chart in ("chart-01", "chart-02", "chart-03", "chart-04")
    }
    for chart in ("chart-01", "chart-02", "chart-03", "chart-04"):
        source_id = source_ids[chart]
        source_generator = FROZEN_PLATE_VERSION if chart == "chart-02" else GENERATED_CHART_VERSION
        source_provenance = (
            "frozen-build-time-output-apache-2.0"
            if chart == "chart-02"
            else "generated-for-colortrace-apache-2.0"
        )
        samples = chart_samples(chart)
        source_floats[chart] = source_to_float(samples)
        png_path = runtime / "sources" / f"{source_id}.png"
        png_digest = write_bytes(png_path, png16_bytes(samples))
        pixel_digest = sha256_bytes(source_pixel_bytes(samples))
        provenance_assets.extend(
            [
                {
                    "asset_id": f"source-pixels-{source_id}",
                    "asset_kind": "canonical-source-pixels",
                    "sha256": pixel_digest,
                    "generator": source_generator,
                    "license": "Apache-2.0",
                },
                {
                    "asset_id": f"source-png-{source_id}",
                    "asset_kind": "source-display-png",
                    "path": rel(png_path, scenario_root),
                    "sha256": png_digest,
                    "generator": source_generator,
                    "license": "Apache-2.0",
                },
            ]
        )
        source_manifest = {
            "schema": "generated-source/v1",
            "source_id": source_id,
            "artifact_id": f"source-{source_id}",
            "generator": source_generator,
            "width": WIDTH,
            "height": HEIGHT,
            "channels": "RGB16",
            "canonical_pixel_sha256": pixel_digest,
            "stored_png_sha256": png_digest,
            "stored_png": rel(png_path, scenario_root),
            "provenance": source_provenance,
        }
        if chart == "chart-02":
            source_manifest["generation_record_sha256"] = FROZEN_CHART2_GENERATION_SHA256
        manifest_path = runtime / "manifests" / "sources" / f"{source_id}.json"
        manifest_digest = write_json(manifest_path, source_manifest)
        source_index.append(
            {
                "source_id": source_id,
                "manifest": rel(manifest_path, scenario_root),
                "sha256": manifest_digest,
            }
        )

    references_needed = {
        ("chart-01", "look/main/v1"),
        ("chart-02", "look/main/v1"),
        ("chart-03", "look/main/v1"),
        ("chart-04", "identity/v1"),
    }
    jobs, derivative_parent_job, event_affected_job = job_roles(permuted, seed)
    omitted_reference_id = None
    if omit_reference_role:
        target = next(job for job in jobs if job["role"] == omit_reference_role)
        omitted_reference_id = reference_id(source_ids[target["source"]], target["transform"])

    reference_index: dict[str, dict[str, Any]] = {}
    for source, transform in sorted(references_needed):
        public_source_id = source_ids[source]
        ref_id = reference_id(public_source_id, transform)
        if ref_id == omitted_reference_id:
            continue
        output, _raw_processor_cache = apply_ocio(
            workers["A"].config_path, transform, source_floats[source]
        )
        buffer_path = references / "buffers" / f"{ref_id}.rgbf32"
        buffer_digest = write_bytes(buffer_path, canonical_float_bytes(output))
        display_path = references / "display" / f"{ref_id}.png"
        display_digest = write_bytes(display_path, png16_bytes(display_samples(output)))
        provenance_assets.extend(
            [
                {
                    "asset_id": f"reference-buffer-{ref_id}",
                    "asset_kind": "authoritative-reference-buffer",
                    "path": rel(buffer_path, scenario_root),
                    "sha256": buffer_digest,
                    "generator": f"OpenColorIO-{OCIO_VERSION}",
                    "license": "Apache-2.0",
                },
                {
                    "asset_id": f"reference-display-{ref_id}",
                    "asset_kind": "supplementary-reference-display",
                    "path": rel(display_path, scenario_root),
                    "sha256": display_digest,
                    "generator": DISPLAY_VERSION,
                    "license": "Apache-2.0",
                },
            ]
        )
        manifest = {
            "schema": "declared-reference/v1",
            "reference_id": ref_id,
            "source_id": public_source_id,
            "transform_id": transform,
            "authority": "fixture-color-qc-declaration",
            "buffer_format": FLOAT_BUFFER_VERSION,
            "buffer": rel(buffer_path, scenario_root),
            "buffer_sha256": buffer_digest,
            "display": rel(display_path, scenario_root),
            "display_sha256": display_digest,
            "display_authoritative": False,
            "ocio_version": ocio.__version__,
            "processor_identity_sha256": stable_processor_identity(
                workers["A"].config_sha256,
                transform,
                workers["A"].lut_sha256 if transform == "look/main/v1" else None,
            ),
            "resolved_resource_sha256": workers["A"].lut_sha256
            if transform == "look/main/v1"
            else None,
        }
        manifest_path = references / "manifests" / f"{ref_id}.json"
        manifest_digest = write_json(manifest_path, manifest)
        reference_index[ref_id] = {
            "manifest": rel(manifest_path, scenario_root),
            "sha256": manifest_digest,
            "buffer_sha256": buffer_digest,
        }

    declared_resources = {
        "schema": "declared-approved-resources/v1",
        "logical_path": LUT_LOGICAL_PATH,
        "approved_lut_sha256": workers["A"].lut_sha256,
        "nominal_config_sha256": workers["A"].config_sha256,
        "ocio_version": ocio.__version__,
    }
    declared_resources_path = references / "manifests" / "declared-approved-resources.json"
    declared_resources_digest = write_json(declared_resources_path, declared_resources)

    job_index: list[dict[str, Any]] = []
    role_to_job: dict[str, str] = {}
    job_to_output: dict[str, str] = {}
    run_id = "run-canonical" if not permuted else opaque_id(seed, "run", variant_id)
    for job in jobs:
        role_to_job[job["role"]] = job["job_id"]
        job_to_output[job["job_id"]] = job["output_id"]
        worker = workers[job["worker"]]
        before_config = sha256_file(worker.config_path)
        before_lut = sha256_file(worker.lut_path)
        output, _raw_processor_cache = apply_ocio(
            worker.config_path, job["transform"], source_floats[job["source"]]
        )
        after_config = sha256_file(worker.config_path)
        after_lut = sha256_file(worker.lut_path)
        if (before_config, before_lut) != (after_config, after_lut):
            raise RuntimeError("input mutation during OCIO processing")
        output_path = runtime / "outputs" / f"{job['output_id']}.rgbf32"
        output_digest = write_bytes(output_path, canonical_float_bytes(output))
        display_path = runtime / "display" / f"{job['output_id']}.png"
        display_digest = write_bytes(display_path, png16_bytes(display_samples(output)))
        provenance_assets.extend(
            [
                {
                    "asset_id": job["output_id"],
                    "asset_kind": "authoritative-render-output",
                    "path": rel(output_path, scenario_root),
                    "sha256": output_digest,
                    "generator": f"OpenColorIO-{OCIO_VERSION}",
                    "license": "Apache-2.0",
                },
                {
                    "asset_id": f"display-{job['output_id']}",
                    "asset_kind": "supplementary-output-display",
                    "path": rel(display_path, scenario_root),
                    "sha256": display_digest,
                    "generator": DISPLAY_VERSION,
                    "license": "Apache-2.0",
                },
            ]
        )

        resources = []
        if job["transform"] == "look/main/v1":
            resources.append(
                {
                    "logical_path": LUT_LOGICAL_PATH,
                    "resolved_root_relative_path": worker.resolved_lut,
                    "sha256": worker.lut_sha256,
                    "size": worker.lut_path.stat().st_size,
                    "read_only": (stat.S_IMODE(worker.lut_path.stat().st_mode) & 0o222) == 0,
                }
            )
        resource_manifest = {
            "schema": RESOURCE_MANIFEST_VERSION,
            "job_id": job["job_id"],
            "run_id": run_id,
            "worker_id": worker.worker,
            "nominal_config_sha256": worker.config_sha256,
            "config_root_relative_path": rel(worker.config_path, runtime),
            "transform_id": job["transform"],
            "ordered_resources": resources,
            "captured_before_and_after_processing": True,
            "inputs_unchanged": True,
        }
        resource_path = runtime / "manifests" / "resources" / f"resource-{job['job_id']}.json"
        resource_digest = sha256_bytes(canonical_json_bytes(resource_manifest))
        if job["role"] != omit_resource_role:
            write_json(resource_path, resource_manifest)

        public_source_id = source_ids[job["source"]]
        ref_id = reference_id(public_source_id, job["transform"])
        reference_pointer = reference_index.get(ref_id)
        job_manifest = {
            "schema": "fixture-job/v1",
            "fixture_id": FIXTURE_ID,
            "fixture_version": FIXTURE_VERSION,
            "variant_id": variant_id,
            "seed_sha256": sha256_bytes(seed.encode("utf-8")),
            "job_id": job["job_id"],
            "run_id": run_id,
            "worker_id": worker.worker,
            "source_id": public_source_id,
            "shot_id": (
                f"shot-{public_source_id}"
                if not permuted
                else opaque_id(seed, "shot", job["source"])
            ),
            "frame_id": (
                f"frame-{job['role']}-0101"
                if not permuted
                else opaque_id(seed, "frame", job["role"])
            ),
            "correlation_id": (
                f"correlation-{job['job_id']}"
                if not permuted
                else opaque_id(seed, "correlation", job["role"])
            ),
            "trace_id": trace_id(seed, job["role"]),
            "transform_id": job["transform"],
            "start_offset_seconds": job["offset"],
            "duration_seconds": 10,
            "process_outcome": "success",
            "exit_code": 0,
            "ocio_version": ocio.__version__,
            "processor_identity_sha256": stable_processor_identity(
                worker.config_sha256,
                job["transform"],
                worker.lut_sha256 if job["transform"] == "look/main/v1" else None,
            ),
            "nominal_config_sha256": worker.config_sha256,
            "resource_manifest": rel(resource_path, scenario_root),
            "resource_manifest_sha256": resource_digest,
            "source_manifest": next(
                item["manifest"] for item in source_index if item["source_id"] == public_source_id
            ),
            "output_id": job["output_id"],
            "output_buffer": rel(output_path, scenario_root),
            "output_buffer_sha256": output_digest,
            "display_png": rel(display_path, scenario_root),
            "display_png_sha256": display_digest,
            "display_authoritative": False,
            "declared_reference_id": ref_id,
            "declared_reference_manifest": f"references/manifests/{ref_id}.json",
            "declared_reference_manifest_sha256": reference_pointer["sha256"]
            if reference_pointer
            else None,
        }
        job_manifest_path = runtime / "manifests" / "jobs" / f"{job['job_id']}.json"
        job_manifest_digest = write_json(job_manifest_path, job_manifest)
        job_index.append(
            {
                "job_id": job["job_id"],
                "manifest": rel(job_manifest_path, scenario_root),
                "sha256": job_manifest_digest,
            }
        )

    parent_output = job_to_output[derivative_parent_job]
    parent_path = runtime / "outputs" / f"{parent_output}.rgbf32"
    derivative_id = (
        "artifact-b-02-derivative" if not permuted else opaque_id(seed, "artifact", "derivative")
    )
    derivative_path = runtime / "outputs" / f"{derivative_id}.rgbf32"
    derivative_digest = write_bytes(derivative_path, parent_path.read_bytes())
    derivative_display = runtime / "display" / f"{derivative_id}.png"
    derivative_display_digest = write_bytes(
        derivative_display, png16_bytes(display_samples(read_float_buffer(parent_path)))
    )
    provenance_assets.extend(
        [
            {
                "asset_id": derivative_id,
                "asset_kind": "lossless-derivative",
                "path": rel(derivative_path, scenario_root),
                "sha256": derivative_digest,
                "generator": DERIVATIVE_VERSION,
                "license": "Apache-2.0",
            },
            {
                "asset_id": f"display-{derivative_id}",
                "asset_kind": "supplementary-derivative-display",
                "path": rel(derivative_display, scenario_root),
                "sha256": derivative_display_digest,
                "generator": DISPLAY_VERSION,
                "license": "Apache-2.0",
            },
        ]
    )
    render_edges = [
        {
            "edge_type": "source-to-render/v1",
            "parent_artifact_id": f"source-{source_ids[job['source']]}",
            "child_artifact_id": job["output_id"],
            "job_id": job["job_id"],
            "correlation_id": (
                f"correlation-{job['job_id']}"
                if not permuted
                else opaque_id(seed, "correlation", job["role"])
            ),
        }
        for job in jobs
    ]
    lineage = {
        "schema": LINEAGE_VERSION,
        "edges": render_edges
        + [
            {
                "edge_type": "lossless-derivative/v1",
                "parent_artifact_id": parent_output,
                "child_artifact_id": derivative_id,
            }
        ],
        "artifacts": [
            *[
                {
                    "artifact_id": job["output_id"],
                    "artifact_type": "authoritative-render-output",
                    "job_id": job["job_id"],
                }
                for job in jobs
            ],
            {
                "artifact_id": derivative_id,
                "artifact_type": "lossless-derivative",
                "buffer": rel(derivative_path, scenario_root),
                "sha256": derivative_digest,
                "display": rel(derivative_display, scenario_root),
                "display_sha256": derivative_display_digest,
                "generator": DERIVATIVE_VERSION,
            },
        ],
    }
    lineage_path = runtime / "manifests" / "lineage.json"
    lineage_digest = write_json(lineage_path, lineage)

    safe_b_job = role_to_job["b4"]
    event_id = "distractor-01" if not permuted else opaque_id(seed, "event", "distractor-01")
    telemetry = {
        "schema": "fixture-telemetry/v1",
        "events": [
            {
                "event_id": event_id,
                "worker_id": workers["B"].worker,
                "start_offset_seconds": next(
                    job["offset"] for job in jobs if job["job_id"] == event_affected_job
                )
                - 2,
                "duration_seconds": 15,
                "overlapping_job_ids": [event_affected_job, safe_b_job],
                "measurements": {"worker.cpu.utilization": "0.94", "render.queue_wait_ms": "1800"},
                "resource_edges": [],
                "lineage_edges": [],
                "output_mutation": False,
            }
        ],
    }
    telemetry_path = runtime / "manifests" / "telemetry.json"
    telemetry_digest = write_json(telemetry_path, telemetry)

    provenance = {
        "schema": "fixture-provenance/v1",
        "generated_assets_license": "Apache-2.0",
        "assets": sorted(provenance_assets, key=lambda item: item["asset_id"]),
        "proprietary_assets": [],
        "third_party": [
            {
                "name": "OpenColorIO",
                "version": OCIO_VERSION,
                "license": "BSD-3-Clause",
                "source": "https://pypi.org/project/OpenColorIO/2.5.2/",
                "accessed": "2026-08-11",
                "wheel_sha256": OCIO_WHEEL_SHA256,
            }
        ],
    }
    provenance_path = runtime / "manifests" / "provenance.json"
    provenance_digest = write_json(provenance_path, provenance)

    fixture_manifest = {
        "schema": RUNTIME_MANIFEST_VERSION,
        "fixture_id": FIXTURE_ID,
        "fixture_version": FIXTURE_VERSION,
        "variant_id": variant_id,
        "run_id": run_id,
        "seed_sha256": sha256_bytes(seed.encode("utf-8")),
        "schedule_origin": FIXED_T0,
        "source_set_generator": SOURCE_SET_VERSION,
        "float_buffer": FLOAT_BUFFER_VERSION,
        "comparison_policy": COMPARISON_VERSION,
        "ocio_version": ocio.__version__,
        "worker_configs": [
            {
                "worker_id": value.worker,
                "config_sha256": value.config_sha256,
                "config": rel(value.config_path, scenario_root),
            }
            for key, value in sorted(workers.items())
        ],
        "sources": source_index,
        "jobs": job_index,
        "lineage": {"manifest": rel(lineage_path, scenario_root), "sha256": lineage_digest},
        "telemetry": {"manifest": rel(telemetry_path, scenario_root), "sha256": telemetry_digest},
        "provenance": {
            "manifest": rel(provenance_path, scenario_root),
            "sha256": provenance_digest,
        },
        "declared_resources": {
            "manifest": rel(declared_resources_path, scenario_root),
            "sha256": declared_resources_digest,
        },
    }
    fixture_manifest_path = runtime / "manifests" / "fixture-runtime-manifest.json"
    fixture_manifest_digest = write_json(fixture_manifest_path, fixture_manifest)

    directly_affected_roles = {"b1", "b2", "b3"}
    expected_affected_jobs = sorted(role_to_job[role] for role in directly_affected_roles)
    expected_safe_jobs = sorted(role_to_job[role] for role in {"a1", "a2", "b4"})
    oracle = {
        "schema": ORACLE_VERSION,
        "fixture_id": FIXTURE_ID,
        "variant_id": variant_id,
        "seed": seed,
        "role_to_job_id": role_to_job,
        "directly_affected_jobs": expected_affected_jobs,
        "safe_jobs": expected_safe_jobs,
        "affected_derivatives": [derivative_id],
        "causal_resource_sha256": workers["B"].lut_sha256,
        "approved_resource_sha256": workers["A"].lut_sha256,
        "non_causal_event_id": event_id,
        "rejected_causes": [
            {
                "cause_kind": "nominal-config",
                "sha256": workers["A"].config_sha256,
            },
            {"cause_kind": "worker-alone", "worker_id": workers["B"].worker},
            {"cause_kind": "distractor", "event_id": event_id},
        ],
        "expected_unresolved_jobs": sorted(
            role_to_job[role]
            for role in (omit_resource_role, omit_reference_role)
            if role is not None
        ),
    }
    oracle_path = oracle_root / "fixture-oracle.json"
    write_json(oracle_path, oracle, 0o400)
    oracle_root.chmod(0o700)

    generation_receipt = {
        "scenario": variant_id,
        "variant_id": variant_id,
        "fixture_runtime_manifest": rel(fixture_manifest_path, scenario_root),
        "fixture_runtime_manifest_sha256": fixture_manifest_digest,
        "config_sha256_equal": workers["A"].config_sha256 == workers["B"].config_sha256,
        "config_sha256": workers["A"].config_sha256,
        "worker_resource_sha256": [
            {"worker_id": worker.worker, "sha256": worker.lut_sha256}
            for worker in sorted(workers.values(), key=lambda item: item.worker)
        ],
        "lut_sha256_different": workers["A"].lut_sha256 != workers["B"].lut_sha256,
        "ocio_version": ocio.__version__,
        "jobs": len(jobs),
    }
    write_json(reports / "generation-receipt.json", generation_receipt)
    validate_contract_instances(scenario_root, oracle_path)
    finalize_bundle_inputs(scenario_root)
    audit_bundle_paths(scenario_root, oracle_path)
    return {
        "fixture_manifest": fixture_manifest_path,
        "oracle": oracle_path,
        "jobs": jobs,
        "derivative_id": derivative_id,
        "event_id": event_id,
    }


def verify_manifest_pointer(
    scenario_root: Path, pointer: dict[str, Any]
) -> tuple[dict[str, Any] | None, str | None]:
    path = checked_relative_path(scenario_root, pointer["manifest"])
    if not path.exists():
        return None, "missing-manifest"
    if sha256_file(path) != pointer["sha256"]:
        return None, "manifest-digest-mismatch"
    return read_json(path), None


def validate_existing(scenario_root: Path) -> dict[str, Any]:
    runtime = scenario_root / "runtime"
    reports = scenario_root / "reports"
    oracle_probe = scenario_root / "oracle" / "fixture-oracle.json"
    oracle_visible = oracle_probe.exists()
    if oracle_visible:
        raise RuntimeError("oracle must not be inside the runtime bundle")

    fixture_path = runtime / "manifests" / "fixture-runtime-manifest.json"
    fixture = read_json(fixture_path)
    declared_pointer = fixture["declared_resources"]
    declared, declared_error = verify_manifest_pointer(scenario_root, declared_pointer)
    if declared_error:
        raise RuntimeError(declared_error)
    assert declared is not None
    audit_bundle_paths(scenario_root)

    jobs: dict[str, dict[str, Any]] = {}
    output_states: dict[str, str] = {}
    evidence: dict[str, list[str]] = {}
    diff_index: list[dict[str, Any]] = []
    for pointer in fixture["jobs"]:
        job, job_error = verify_manifest_pointer(scenario_root, pointer)
        if job_error:
            raise RuntimeError(f"job manifest invalid: {job_error}")
        assert job is not None
        job_id = job["job_id"]
        reasons: list[str] = []
        resource_path = checked_relative_path(scenario_root, job["resource_manifest"])
        resource = None
        if not resource_path.exists():
            reasons.append("missing-resolved-resource-manifest")
        elif sha256_file(resource_path) != job["resource_manifest_sha256"]:
            reasons.append("resolved-resource-manifest-digest-mismatch")
        else:
            resource = read_json(resource_path)
            config_path = checked_relative_path(
                scenario_root,
                resource["config_root_relative_path"],
                base=runtime,
            )
            worker_root = runtime / "workers" / job["worker_id"]
            if not config_path.is_relative_to(worker_root):
                raise ValueError("config path crosses worker root")
            if sha256_file(config_path) != resource["nominal_config_sha256"]:
                reasons.append("nominal-config-digest-mismatch")
            for resolved_resource in resource["ordered_resources"]:
                resolved_path = checked_relative_path(
                    scenario_root,
                    resolved_resource["resolved_root_relative_path"],
                    base=runtime,
                )
                if not resolved_path.is_relative_to(worker_root):
                    raise ValueError("resolved resource crosses worker root")
                if sha256_file(resolved_path) != resolved_resource["sha256"]:
                    reasons.append("resolved-resource-digest-mismatch")

        output_path = checked_relative_path(scenario_root, job["output_buffer"])
        reference_manifest_path = checked_relative_path(
            scenario_root, job["declared_reference_manifest"]
        )
        comparison: dict[str, Any]
        if not output_path.exists() or sha256_file(output_path) != job["output_buffer_sha256"]:
            reasons.append("missing-or-digest-invalid-output-buffer")
            comparison = {"state": "unresolved", "reason": reasons[-1]}
        elif not reference_manifest_path.exists():
            reasons.append("missing-declared-reference")
            comparison = {"state": "unresolved", "reason": reasons[-1]}
        else:
            reference_manifest = read_json(reference_manifest_path)
            if (
                not job["declared_reference_manifest_sha256"]
                or sha256_file(reference_manifest_path) != job["declared_reference_manifest_sha256"]
            ):
                reasons.append("declared-reference-manifest-digest-mismatch")
            reference_path = checked_relative_path(scenario_root, reference_manifest["buffer"])
            if reasons:
                comparison = {"state": "unresolved", "reason": reasons[-1]}
            elif (
                not reference_path.exists()
                or sha256_file(reference_path) != reference_manifest["buffer_sha256"]
            ):
                reasons.append("missing-or-digest-invalid-reference-buffer")
                comparison = {"state": "unresolved", "reason": reasons[-1]}
            else:
                try:
                    output_values = read_float_buffer(output_path)
                    reference_values = read_float_buffer(reference_path)
                    comparison = compare_buffers(output_values, reference_values)
                    diff_path = reports / "diffs" / f"{job_id}.png"
                    diff_digest = write_bytes(
                        diff_path, png16_bytes(diff_samples(output_values, reference_values))
                    )
                    diff_index.append(
                        {
                            "job_id": job_id,
                            "path": rel(diff_path, scenario_root),
                            "sha256": diff_digest,
                            "authoritative": False,
                        }
                    )
                except (ValueError, OSError) as exc:
                    reasons.append("malformed-or-non-finite-float-buffer")
                    comparison = {"state": "unresolved", "reason": reasons[-1], "detail": str(exc)}

        state = "unresolved" if reasons else comparison["state"]
        jobs[job_id] = {
            "job_id": job_id,
            "worker_id": job["worker_id"],
            "output_id": job["output_id"],
            "transform_id": job["transform_id"],
            "nominal_config_sha256": job["nominal_config_sha256"],
            "state": state,
            "comparison": comparison,
            "reasons": reasons,
            "resource_manifest_sha256": job["resource_manifest_sha256"]
            if resource is not None
            else None,
            "resolved_resource_sha256": (
                resource["ordered_resources"][0]["sha256"]
                if resource and resource["ordered_resources"]
                else None
            ),
            "evidence": [pointer["sha256"], job["output_buffer_sha256"]],
        }
        output_states[job["output_id"]] = comparison["state"]
        evidence[job_id] = jobs[job_id]["evidence"]

    lineage_pointer = fixture["lineage"]
    lineage, lineage_error = verify_manifest_pointer(scenario_root, lineage_pointer)
    if lineage_error:
        raise RuntimeError(lineage_error)
    assert lineage is not None
    derivatives: dict[str, dict[str, Any]] = {}
    for edge in lineage["edges"]:
        if edge["edge_type"] != "lossless-derivative/v1":
            continue
        parent_state = output_states.get(edge["parent_artifact_id"], "unresolved")
        derivatives[edge["child_artifact_id"]] = {
            "artifact_id": edge["child_artifact_id"],
            "parent_artifact_id": edge["parent_artifact_id"],
            "state": parent_state,
            "policy": "exact-lineage-propagation/v1",
            "evidence": [lineage_pointer["sha256"]],
        }

    telemetry_pointer = fixture["telemetry"]
    telemetry, telemetry_error = verify_manifest_pointer(scenario_root, telemetry_pointer)
    if telemetry_error:
        raise RuntimeError(telemetry_error)
    assert telemetry is not None
    event_results = []
    for event in telemetry["events"]:
        event_results.append(
            {
                "event_id": event["event_id"],
                "overlapping_job_ids": sorted(event["overlapping_job_ids"]),
                "resource_edges": event["resource_edges"],
                "lineage_edges": event["lineage_edges"],
                "output_mutation": event["output_mutation"],
                "evidence": [telemetry_pointer["sha256"]],
            }
        )

    report = {
        "schema": VALIDATOR_REPORT_VERSION,
        "fixture_id": fixture["fixture_id"],
        "variant_id": fixture["variant_id"],
        "ocio_version": ocio.__version__,
        "comparison_policy": COMPARISON_VERSION,
        "jobs": [jobs[key] for key in sorted(jobs)],
        "derivatives": [derivatives[key] for key in sorted(derivatives)],
        "telemetry_events": event_results,
        "diff_images": sorted(diff_index, key=lambda item: item["job_id"]),
    }
    report_path = reports / "validator-report.json"
    validate_contract_document(report)
    report_digest = write_json(report_path, report)
    stored_report = read_json(report_path)
    if not isinstance(stored_report, dict):
        raise ValueError("persisted validator report is not an object")
    validate_contract_document(stored_report)
    receipt = {
        "schema": VALIDATOR_RECEIPT_VERSION,
        "report": rel(report_path, scenario_root),
        "report_sha256": report_digest,
        "truth_material_inside_runtime_bundle": oracle_visible,
    }
    validate_contract_document(receipt)
    receipt_path = reports / "validator-receipt.json"
    write_json(receipt_path, receipt)
    stored_receipt = read_json(receipt_path)
    if not isinstance(stored_receipt, dict):
        raise ValueError("persisted validator receipt is not an object")
    validate_contract_document(stored_receipt)
    return report


def run_isolated_validator(script: Path, scenario_root: Path, python: Path) -> dict[str, Any]:
    reports_root = scenario_root / "reports"
    descriptor, probe_name = tempfile.mkstemp(
        prefix=".validator-boundary-", dir=scenario_root.parent
    )
    os.write(descriptor, b"neutral filesystem boundary probe")
    os.close(descriptor)
    probe_path = Path(probe_name)
    command = [
        str(python),
        str(script),
        "validate-worker",
        "--scenario",
        str(scenario_root),
        "--denied-probe",
        str(probe_path),
    ]
    child_environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if any("oracle" in item.casefold() for item in command) or any(
        "oracle" in item.casefold() for item in child_environment.values()
    ):
        raise RuntimeError("validator invocation contains oracle material")
    try:
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=300,
            env=child_environment,
        )
    finally:
        probe_path.unlink(missing_ok=True)
    if completed.returncode != 0:
        raise RuntimeError(f"isolated validator failed: {completed.stderr or completed.stdout}")
    receipt = read_json(reports_root / "landlock-receipt.json")
    if receipt["filesystem_scope"] != "runtime-bundle-only" or receipt["landlock_abi"] < 1:
        raise RuntimeError("validator did not establish the required Landlock boundary")
    write_json(
        reports_root / "validator-invocation-receipt.json",
        _validator_invocation_document(child_environment),
    )
    return cast(dict[str, Any], read_json(reports_root / "validator-report.json"))


def validate_landlocked_worker(scenario_root: Path, denied_probe: Path) -> dict[str, Any]:
    scenario_root = scenario_root.resolve(strict=True)
    # Load trusted package schemas before Landlock intentionally removes package-file access.
    contract_validators()
    abi = enter_bundle_landlock(scenario_root)
    try:
        denied_probe.read_bytes()
    except PermissionError:
        outside_bundle_read_denied = True
    else:
        raise RuntimeError("Landlock allowed a read outside the runtime bundle")
    immutable_probe = scenario_root / "runtime" / "manifests" / "fixture-runtime-manifest.json"
    try:
        descriptor = os.open(immutable_probe, os.O_WRONLY)
    except PermissionError:
        immutable_inputs_enforced = True
    else:
        os.close(descriptor)
        raise RuntimeError("Landlock allowed a write handle to immutable runtime input")
    report = validate_existing(scenario_root)
    write_json(
        scenario_root / "reports" / "landlock-receipt.json",
        {
            "schema": "validator-landlock-receipt/v1",
            "filesystem_scope": "runtime-bundle-only",
            "landlock_abi": abi,
            "outside_bundle_read_denied": outside_bundle_read_denied,
            "runtime_inputs_read_only": immutable_inputs_enforced,
            "reports_write_scope": True,
        },
    )
    return report


def _validator_invocation_document(child_environment: dict[str, str]) -> dict[str, Any]:
    return {
        "schema": "validator-invocation-receipt/v1",
        "argv_contains_oracle_material": False,
        "environment_contains_oracle_material": False,
        "environment_keys": sorted(child_environment),
        "external_probe_kind": "neutral-sentinel",
        "external_probe_retained": False,
    }


def _canonical_directory_set(files: dict[str, str]) -> set[str]:
    directories = {"runtime", "references", "reports"}
    for relative in files:
        logical = PurePosixPath(relative)
        if logical.is_absolute() or any(part in ("", ".", "..") for part in logical.parts):
            raise ValueError(f"unsafe canonical digest path: {relative!r}")
        for parent in logical.parents:
            if parent != PurePosixPath("."):
                directories.add(parent.as_posix())
    return directories


def _exact_bundle_tree(bundle_root: Path) -> tuple[dict[str, str], set[str]]:
    files: dict[str, str] = {}
    directories: set[str] = set()
    for path in sorted(bundle_root.rglob("*")):
        relative = path.relative_to(bundle_root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(f"symlink prohibited in canonical bundle: {relative}")
        if any("oracle" in part.casefold() for part in PurePosixPath(relative).parts):
            raise ValueError(f"oracle-named path prohibited in canonical bundle: {relative}")
        if stat.S_ISDIR(mode):
            directories.add(relative)
        elif stat.S_ISREG(mode):
            files[relative] = sha256_file(path)
        else:
            raise ValueError(f"special file prohibited in canonical bundle: {relative}")
    return files, directories


def _assert_exact_canonical_tree(bundle_root: Path, expected_files: dict[str, str]) -> None:
    actual_files, actual_directories = _exact_bundle_tree(bundle_root)
    expected_directories = _canonical_directory_set(expected_files)
    if actual_files != expected_files:
        missing = sorted(set(expected_files) - set(actual_files))
        extra = sorted(set(actual_files) - set(expected_files))
        changed = sorted(
            path
            for path in set(actual_files) & set(expected_files)
            if actual_files[path] != expected_files[path]
        )
        raise RuntimeError(
            "canonical bundle file map mismatch: "
            f"missing={missing!r}, extra={extra!r}, changed={changed!r}"
        )
    if actual_directories != expected_directories:
        missing = sorted(expected_directories - actual_directories)
        extra = sorted(actual_directories - expected_directories)
        raise RuntimeError(
            f"canonical bundle directory map mismatch: missing={missing!r}, extra={extra!r}"
        )


def _assert_canonical_tree_seal(
    bundle_root: Path, *, files_sha256: str, directories_sha256: str
) -> None:
    files, directories = _exact_bundle_tree(bundle_root)
    if sha256_bytes(canonical_json_bytes(files)) != files_sha256:
        raise RuntimeError("canonical bundle file-map seal mismatch")
    if sha256_bytes(canonical_json_bytes(sorted(directories))) != directories_sha256:
        raise RuntimeError("canonical bundle directory-map seal mismatch")


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_canonical_digests(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
        raise ValueError("canonical digest manifest must be one regular, non-linked file")
    if sha256_file(path) != CANONICAL_DIGESTS_SHA256:
        raise RuntimeError("canonical digest manifest does not match the checked-in contract")
    document = read_json(path)
    expected_keys = {
        "schema",
        "files",
        "fixture_id",
        "fixture_version",
        "generator_version",
        "ocio_version",
        "oracle_sha256",
        "seed",
        "source_pixel_sha256",
        "tree_sha256",
    }
    if not isinstance(document, dict) or set(document) != expected_keys:
        raise ValueError("canonical digest manifest has an unexpected shape")
    metadata = {
        "schema": "fixture-canonical-digests/v1",
        "fixture_id": FIXTURE_ID,
        "fixture_version": FIXTURE_VERSION,
        "generator_version": GENERATOR_VERSION,
        "ocio_version": OCIO_VERSION,
        "seed": CANONICAL_SEED,
    }
    if any(document[key] != value for key, value in metadata.items()):
        raise ValueError("canonical digest manifest metadata mismatch")
    files = document["files"]
    source_pixels = document["source_pixel_sha256"]
    if (
        not isinstance(files, dict)
        or len(files) != 65
        or not all(isinstance(key, str) and _is_sha256(value) for key, value in files.items())
        or not isinstance(source_pixels, dict)
        or set(source_pixels) != {"chart-01", "chart-02", "chart-03", "chart-04"}
        or not all(_is_sha256(value) for value in source_pixels.values())
        or not _is_sha256(document["oracle_sha256"])
        or not _is_sha256(document["tree_sha256"])
    ):
        raise ValueError("canonical digest manifest contains invalid digests")
    if set(files) & CANONICAL_VALIDATOR_OUTPUTS != CANONICAL_VALIDATOR_OUTPUTS:
        raise ValueError("canonical digest manifest omits required validator outputs")
    tree_sha256 = sha256_bytes(canonical_json_bytes(files))
    if tree_sha256 != document["tree_sha256"]:
        raise ValueError("canonical digest manifest tree hash mismatch")
    return cast(dict[str, Any], document)


def _assert_canonical_input_metadata(scenario_root: Path) -> None:
    fixture = read_json(scenario_root / "runtime/manifests/fixture-runtime-manifest.json")
    expected = {
        "schema": RUNTIME_MANIFEST_VERSION,
        "fixture_id": FIXTURE_ID,
        "fixture_version": FIXTURE_VERSION,
        "variant_id": "canonical",
        "seed_sha256": sha256_bytes(CANONICAL_SEED.encode("utf-8")),
        "source_set_generator": SOURCE_SET_VERSION,
        "comparison_policy": COMPARISON_VERSION,
        "ocio_version": OCIO_VERSION,
    }
    if not isinstance(fixture, dict) or any(
        fixture.get(key) != value for key, value in expected.items()
    ):
        raise RuntimeError("canonical fixture metadata mismatch")
    if len(fixture.get("jobs", [])) != 6:
        raise RuntimeError("canonical fixture must contain exactly six jobs")
    generation = read_json(scenario_root / "reports/generation-receipt.json")
    if (
        not isinstance(generation, dict)
        or generation.get("scenario") != "canonical"
        or generation.get("variant_id") != "canonical"
        or generation.get("jobs") != 6
        or generation.get("ocio_version") != OCIO_VERSION
        or generation.get("config_sha256_equal") is not True
        or generation.get("lut_sha256_different") is not True
    ):
        raise RuntimeError("canonical generation receipt metadata mismatch")


def _assert_canonical_input_permissions(
    scenario_root: Path, *, require_root_ownership: bool
) -> None:
    scenario_stat = scenario_root.stat()
    if any(
        name in {"system.posix_acl_access", "system.posix_acl_default"}
        for name in os.listxattr(scenario_root, follow_symlinks=False)
    ):
        raise RuntimeError("canonical bundle root has a POSIX ACL")
    if require_root_ownership:
        if scenario_root.parent != Path("/tmp"):
            raise RuntimeError("privilege-separated canonical assembly must be rooted in /tmp")
        if scenario_stat.st_uid != 0 or scenario_stat.st_gid != 0:
            raise RuntimeError("privilege-separated canonical bundle must be root-owned")
        if stat.S_IMODE(scenario_stat.st_mode) & 0o022:
            raise RuntimeError("privilege-separated canonical bundle root is group/world-writable")
        parent_mode = scenario_root.parent.stat().st_mode
        if not stat.S_ISDIR(parent_mode) or not (parent_mode & stat.S_ISVTX):
            raise RuntimeError("privilege-separated canonical assembly requires a sticky parent")
    for subtree in (scenario_root / "runtime", scenario_root / "references"):
        for path in (subtree, *sorted(subtree.rglob("*"))):
            path_stat = path.lstat()
            if stat.S_IMODE(path_stat.st_mode) & 0o222:
                raise RuntimeError(f"canonical input path is writable: {path}")
            if require_root_ownership and (path_stat.st_uid != 0 or path_stat.st_gid != 0):
                raise RuntimeError(f"canonical input path is not root-owned: {path}")
            extended_attributes = os.listxattr(path, follow_symlinks=False)
            if any(
                name in {"system.posix_acl_access", "system.posix_acl_default"}
                for name in extended_attributes
            ):
                raise RuntimeError(f"canonical input path has a POSIX ACL: {path}")


def _assert_canonical_report_prestate(reports_root: Path, *, require_root_ownership: bool) -> None:
    generation = reports_root / "generation-receipt.json"
    for path, expected_mode in ((reports_root, 0o700), (generation, 0o600)):
        path_stat = path.lstat()
        if path.is_symlink() or (
            path == generation and (not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1)
        ):
            raise RuntimeError(f"unsafe canonical report pre-state: {path}")
        if stat.S_IMODE(path_stat.st_mode) != expected_mode:
            raise RuntimeError(f"canonical report pre-state mode mismatch: {path}")
        if require_root_ownership and (path_stat.st_uid != 0 or path_stat.st_gid != 0):
            raise RuntimeError(f"canonical report pre-state is not root-owned: {path}")
        if any(
            name in {"system.posix_acl_access", "system.posix_acl_default"}
            for name in os.listxattr(path, follow_symlinks=False)
        ):
            raise RuntimeError(f"canonical report pre-state has a POSIX ACL: {path}")


def _assert_canonical_report_semantics(report: dict[str, Any]) -> None:
    if (
        report.get("schema") != VALIDATOR_REPORT_VERSION
        or report.get("fixture_id") != FIXTURE_ID
        or report.get("variant_id") != "canonical"
        or report.get("ocio_version") != OCIO_VERSION
        or report.get("comparison_policy") != COMPARISON_VERSION
    ):
        raise RuntimeError("canonical validator report metadata mismatch")
    expected_states = {
        "job-a-01": "reference_match",
        "job-a-02": "reference_match",
        "job-b-01": "reference_mismatch",
        "job-b-02": "reference_mismatch",
        "job-b-03": "reference_mismatch",
        "job-b-04": "reference_match",
    }
    jobs = report.get("jobs")
    if not isinstance(jobs, list) or len(jobs) != 6:
        raise RuntimeError("canonical validator report must contain exactly six jobs")
    actual_states = {
        item.get("job_id"): item.get("state")
        for item in jobs
        if isinstance(item, dict) and item.get("reasons") == []
    }
    if actual_states != expected_states or any(item.get("state") == "unresolved" for item in jobs):
        raise RuntimeError("canonical validator report job-state mismatch")
    derivatives = report.get("derivatives")
    if not isinstance(derivatives, list) or len(derivatives) != 1:
        raise RuntimeError("canonical validator report derivative mismatch")
    derivative = derivatives[0]
    if (
        derivative.get("artifact_id") != "artifact-b-02-derivative"
        or derivative.get("parent_artifact_id") != "output-job-b-02"
        or derivative.get("state") != "reference_mismatch"
        or derivative.get("policy") != "exact-lineage-propagation/v1"
    ):
        raise RuntimeError("canonical validator report derivative mismatch")
    events = report.get("telemetry_events")
    if not isinstance(events, list) or len(events) != 1:
        raise RuntimeError("canonical validator report telemetry mismatch")
    event = events[0]
    if (
        event.get("event_id") != "distractor-01"
        or event.get("overlapping_job_ids") != ["job-b-01", "job-b-04"]
        or event.get("resource_edges") != []
        or event.get("lineage_edges") != []
        or event.get("output_mutation") is not False
    ):
        raise RuntimeError("canonical validator report telemetry mismatch")
    diff_images = report.get("diff_images")
    if (
        not isinstance(diff_images, list)
        or len(diff_images) != 6
        or {
            (item.get("job_id"), item.get("path"), item.get("authoritative"))
            for item in diff_images
            if isinstance(item, dict)
        }
        != {(job_id, f"reports/diffs/{job_id}.png", False) for job_id in expected_states}
    ):
        raise RuntimeError("canonical validator report diff-image mismatch")


def _assert_absent_canonical_oracle_roots(
    scenario_root: Path, absent_oracle_roots: tuple[Path, ...]
) -> None:
    if scenario_root.name not in {"colortrace-fixture-a", "colortrace-fixture-b"}:
        raise ValueError("canonical build scenario must use the fixed A/B assembly names")
    scenario_parent = scenario_root.parent.resolve(strict=True)
    expected = {
        scenario_parent / "colortrace-oracle-a",
        scenario_parent / "colortrace-oracle-b",
    }
    supplied: set[Path] = set()
    for candidate in absent_oracle_roots:
        absolute = candidate if candidate.is_absolute() else Path.cwd() / candidate
        supplied.add(absolute.parent.resolve(strict=True) / absolute.name)
    if supplied != expected:
        raise ValueError("both fixed sibling oracle roots must be declared absent")
    for candidate in sorted(expected):
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        raise RuntimeError(f"oracle root must be absent: {candidate}")


def _normalize_canonical_report_outputs(reports_root: Path, *, uid: int, gid: int) -> None:
    diff_root = reports_root / "diffs"
    diff_stat = diff_root.lstat()
    if not stat.S_ISDIR(diff_stat.st_mode) or stat.S_ISLNK(diff_stat.st_mode):
        raise RuntimeError("canonical diff output is not a real directory")
    output_paths = [
        reports_root.parent / relative for relative in sorted(CANONICAL_VALIDATOR_OUTPUTS)
    ]
    for path in output_paths:
        path_stat = path.lstat()
        if not stat.S_ISREG(path_stat.st_mode) or path_stat.st_nlink != 1:
            raise RuntimeError(f"unsafe canonical validator output: {path}")
    if (diff_stat.st_uid, diff_stat.st_gid) != (uid, gid):
        os.chown(diff_root, uid, gid, follow_symlinks=False)
    os.chmod(diff_root, 0o700, follow_symlinks=False)
    for path in output_paths:
        path_stat = path.lstat()
        if (path_stat.st_uid, path_stat.st_gid) != (uid, gid):
            os.chown(path, uid, gid, follow_symlinks=False)
        os.chmod(path, 0o600, follow_symlinks=False)


def _set_opened_identity(
    descriptor: int, *, uid: int, gid: int, mode: int, allow_chown: bool
) -> None:
    current = os.fstat(descriptor)
    if allow_chown and (current.st_uid, current.st_gid) != (uid, gid):
        os.fchown(descriptor, uid, gid)
    os.fchmod(descriptor, mode)


def _enable_no_new_privs() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "cannot enable no_new_privs")
    if libc.prctl(39, 0, 0, 0, 0) != 1:
        error = ctypes.get_errno()
        raise OSError(error, "cannot verify no_new_privs")


def _assert_worker_process_boundary() -> None:
    status = {
        key: value.strip()
        for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines()
        if ":" in line
        for key, value in (line.split(":", maxsplit=1),)
    }
    if int(status.get("CapEff", "1"), 16) != 0:
        raise RuntimeError("canonical build validator worker retained effective capabilities")
    if status.get("NoNewPrivs") != "1":
        raise RuntimeError("canonical build validator worker did not retain no_new_privs")
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    if resource.getrlimit(resource.RLIMIT_NPROC) != (0, 0):
        raise RuntimeError("canonical build validator worker can create descendant processes")


def validate_canonical_build_worker(
    scenario_root: Path, denied_probe: Path, *, privilege_separated: bool
) -> dict[str, Any]:
    scenario_root = scenario_root.resolve(strict=True)
    if os.geteuid() == 0 or os.getegid() == 0:
        raise RuntimeError("canonical build validator worker must be unprivileged")
    if privilege_separated and (
        os.getresuid() != (CANONICAL_BUILD_UID,) * 3
        or os.getresgid() != (CANONICAL_BUILD_GID,) * 3
        or os.getgroups()
    ):
        raise RuntimeError("canonical build validator worker identity mismatch")
    _enable_no_new_privs()
    _assert_worker_process_boundary()
    _assert_canonical_input_permissions(scenario_root, require_root_ownership=privilege_separated)
    if privilege_separated and stat.S_IMODE(scenario_root.stat().st_mode) != 0o555:
        raise RuntimeError("canonical build validator bundle root is not sealed")
    reports_root = scenario_root / "reports"
    generation = reports_root / "generation-receipt.json"
    expected_uid = CANONICAL_BUILD_UID if privilege_separated else os.geteuid()
    expected_gid = CANONICAL_BUILD_GID if privilege_separated else os.getegid()
    for path, expected_mode in ((reports_root, 0o700), (generation, 0o600)):
        path_stat = path.lstat()
        if (
            (path_stat.st_uid, path_stat.st_gid) != (expected_uid, expected_gid)
            or stat.S_IMODE(path_stat.st_mode) != expected_mode
            or (path == generation and path_stat.st_nlink != 1)
        ):
            raise RuntimeError(f"canonical build validator report boundary mismatch: {path}")
    derived_oracle_roots = (
        scenario_root.parent / "colortrace-oracle-a",
        scenario_root.parent / "colortrace-oracle-b",
    )
    _assert_absent_canonical_oracle_roots(scenario_root, derived_oracle_roots)
    audit_bundle_paths(scenario_root)
    _assert_canonical_tree_seal(
        scenario_root,
        files_sha256=CANONICAL_PREVALIDATION_TREE_SHA256,
        directories_sha256=CANONICAL_PREVALIDATION_DIRECTORIES_SHA256,
    )
    _assert_canonical_input_metadata(scenario_root)
    try:
        denied_probe.read_bytes()
    except PermissionError:
        pass
    else:
        raise RuntimeError("canonical build validator read the neutral external probe")
    immutable_probe = scenario_root / "runtime/manifests/fixture-runtime-manifest.json"
    try:
        descriptor = os.open(immutable_probe, os.O_WRONLY)
    except PermissionError:
        pass
    else:
        os.close(descriptor)
        raise RuntimeError("canonical build validator opened an immutable input for writing")
    report = validate_existing(scenario_root)
    _assert_canonical_report_semantics(report)
    audit_bundle_paths(scenario_root)
    _assert_canonical_tree_seal(
        scenario_root,
        files_sha256=CANONICAL_WORKER_TREE_SHA256,
        directories_sha256=CANONICAL_WORKER_DIRECTORIES_SHA256,
    )
    _assert_absent_canonical_oracle_roots(scenario_root, derived_oracle_roots)
    return report


def run_canonical_build_validator(
    script: Path,
    scenario_root: Path,
    python: Path,
    canonical_digests: Path,
    absent_oracle_roots: tuple[Path, ...],
    *,
    require_privilege_drop: bool,
) -> dict[str, Any]:
    supplied_root = scenario_root.absolute()
    if supplied_root.is_symlink():
        raise ValueError("canonical build scenario root must not be a symlink")
    scenario_root = supplied_root.resolve(strict=True)
    if not scenario_root.is_dir():
        raise ValueError("canonical build scenario root must be a directory")
    golden = _load_canonical_digests(canonical_digests)
    golden_files = cast(dict[str, str], golden["files"])
    prevalidation_files = {
        path: digest
        for path, digest in golden_files.items()
        if path not in CANONICAL_VALIDATOR_OUTPUTS
    }
    worker_files = {
        path: digest
        for path, digest in golden_files.items()
        if path != "reports/validator-invocation-receipt.json"
    }
    _assert_absent_canonical_oracle_roots(scenario_root, absent_oracle_roots)
    audit_bundle_paths(scenario_root)
    _assert_exact_canonical_tree(scenario_root, prevalidation_files)
    _assert_canonical_input_metadata(scenario_root)
    _assert_canonical_input_permissions(
        scenario_root, require_root_ownership=require_privilege_drop
    )
    reports_root = scenario_root / "reports"
    _assert_canonical_report_prestate(reports_root, require_root_ownership=require_privilege_drop)

    parent_uid = os.geteuid()
    if require_privilege_drop:
        if parent_uid != 0:
            raise RuntimeError("--require-privilege-drop requires a root build parent")
        child_identity: dict[str, Any] = {
            "user": CANONICAL_BUILD_UID,
            "group": CANONICAL_BUILD_GID,
            "extra_groups": (),
        }
    else:
        if parent_uid == 0:
            raise RuntimeError("root canonical build validation requires --require-privilege-drop")
        child_identity = {}
    if require_privilege_drop:
        for trusted_path in (script.resolve(strict=True), python.resolve(strict=True)):
            trusted_stat = trusted_path.stat()
            if trusted_stat.st_uid != 0 or stat.S_IMODE(trusted_stat.st_mode) & 0o022:
                raise RuntimeError(
                    f"canonical validator executable is not root-controlled: {trusted_path}"
                )

    child_environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    descriptor, probe_name = tempfile.mkstemp(
        prefix=".validator-boundary-", dir=scenario_root.parent
    )
    probe_path = Path(probe_name)
    os.write(descriptor, b"neutral filesystem boundary probe")
    os.fchmod(descriptor, 0)
    os.close(descriptor)
    command = [
        str(python),
        str(script),
        "validate-canonical-build-worker",
        "--scenario",
        str(scenario_root),
        "--denied-probe",
        str(probe_path),
        "--privilege-separated" if require_privilege_drop else "--functional-nonroot",
    ]
    open_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    scenario_fd = os.open(scenario_root, open_flags | os.O_DIRECTORY)
    reports_fd = os.open(reports_root, open_flags | os.O_DIRECTORY)
    generation_fd = os.open(reports_root / "generation-receipt.json", open_flags)
    scenario_original = os.fstat(scenario_fd)
    reports_original = os.fstat(reports_fd)
    generation_original = os.fstat(generation_fd)
    reports_prepared = False
    try:
        if any("oracle" in item.casefold() for item in command) or any(
            "oracle" in item.casefold() for item in child_environment.values()
        ):
            raise RuntimeError("canonical validator worker invocation contains oracle material")
        reports_prepared = True
        _set_opened_identity(
            reports_fd,
            uid=CANONICAL_BUILD_UID if require_privilege_drop else reports_original.st_uid,
            gid=CANONICAL_BUILD_GID if require_privilege_drop else reports_original.st_gid,
            mode=0o700,
            allow_chown=require_privilege_drop,
        )
        _set_opened_identity(
            generation_fd,
            uid=CANONICAL_BUILD_UID if require_privilege_drop else generation_original.st_uid,
            gid=CANONICAL_BUILD_GID if require_privilege_drop else generation_original.st_gid,
            mode=0o600,
            allow_chown=require_privilege_drop,
        )
        os.fchmod(scenario_fd, 0o555)
        completed = subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            timeout=300,
            env=child_environment,
            start_new_session=True,
            umask=0o077,
            **child_identity,
        )
        probe_path.unlink()
        _set_opened_identity(
            reports_fd,
            uid=reports_original.st_uid,
            gid=reports_original.st_gid,
            mode=stat.S_IMODE(reports_original.st_mode),
            allow_chown=require_privilege_drop,
        )
        _set_opened_identity(
            generation_fd,
            uid=generation_original.st_uid,
            gid=generation_original.st_gid,
            mode=stat.S_IMODE(generation_original.st_mode),
            allow_chown=require_privilege_drop,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"canonical build validator failed: {completed.stderr or completed.stdout}"
            )
        _assert_absent_canonical_oracle_roots(scenario_root, absent_oracle_roots)
        audit_bundle_paths(scenario_root)
        _assert_exact_canonical_tree(scenario_root, worker_files)
        report = cast(dict[str, Any], read_json(reports_root / "validator-report.json"))
        _assert_canonical_report_semantics(report)
        receipt = read_json(reports_root / "validator-receipt.json")
        if (
            not isinstance(receipt, dict)
            or receipt.get("report") != "reports/validator-report.json"
            or receipt.get("report_sha256") != sha256_file(reports_root / "validator-report.json")
            or receipt.get("truth_material_inside_runtime_bundle") is not False
        ):
            raise RuntimeError("canonical validator receipt mismatch")
        write_json(
            reports_root / "validator-invocation-receipt.json",
            _validator_invocation_document(child_environment),
        )
        audit_bundle_paths(scenario_root)
        _assert_exact_canonical_tree(scenario_root, golden_files)
        if sha256_bytes(canonical_json_bytes(golden_files)) != golden["tree_sha256"]:
            raise RuntimeError("canonical validated tree hash mismatch")
        _assert_absent_canonical_oracle_roots(scenario_root, absent_oracle_roots)
        _normalize_canonical_report_outputs(
            reports_root, uid=reports_original.st_uid, gid=reports_original.st_gid
        )
        return report
    finally:
        probe_path.unlink(missing_ok=True)
        try:
            if reports_prepared:
                _set_opened_identity(
                    reports_fd,
                    uid=reports_original.st_uid,
                    gid=reports_original.st_gid,
                    mode=stat.S_IMODE(reports_original.st_mode),
                    allow_chown=require_privilege_drop,
                )
                _set_opened_identity(
                    generation_fd,
                    uid=generation_original.st_uid,
                    gid=generation_original.st_gid,
                    mode=stat.S_IMODE(generation_original.st_mode),
                    allow_chown=require_privilege_drop,
                )
        finally:
            try:
                _set_opened_identity(
                    scenario_fd,
                    uid=scenario_original.st_uid,
                    gid=scenario_original.st_gid,
                    mode=stat.S_IMODE(scenario_original.st_mode),
                    allow_chown=False,
                )
            finally:
                os.close(generation_fd)
                os.close(reports_fd)
                os.close(scenario_fd)


def scan_oracle_leaks(
    scenario_root: Path, oracle_path: Path, oracle: dict[str, Any]
) -> dict[str, Any]:
    forbidden = {
        oracle["seed"],
        oracle_path.parent.as_posix(),
        "directly_affected_jobs",
        "safe_jobs",
        "expected_unresolved_jobs",
        "role_to_job_id",
        "non_causal_event_id",
        "shadowed_lut_sha256",
        "causal_resource_sha256",
        "oracle_sha256",
        "fixture-oracle/v1",
        canonical_json_bytes(oracle["directly_affected_jobs"]).decode("utf-8"),
        canonical_json_bytes(oracle["safe_jobs"]).decode("utf-8"),
        canonical_json_bytes(oracle["role_to_job_id"]).decode("utf-8"),
    }
    findings = []
    for path in sorted(item for item in scenario_root.rglob("*") if item.is_file()):
        data = path.read_bytes()
        for token in sorted(forbidden):
            if token and token.encode("utf-8") in data:
                findings.append(
                    {
                        "path": rel(path, scenario_root),
                        "token_sha256": sha256_bytes(token.encode()),
                    }
                )
    return {
        "schema": "oracle-leak-scan/v1",
        "scanned_roots": ["."],
        "forbidden_token_count": len(forbidden),
        "findings": findings,
        "pass": not findings,
    }


def evaluate_scenario(
    scenario_root: Path, oracle_path: Path, report: dict[str, Any]
) -> dict[str, Any]:
    oracle = read_json(oracle_path)
    actual_affected = sorted(
        job["job_id"] for job in report["jobs"] if job["state"] == "reference_mismatch"
    )
    actual_safe = sorted(
        job["job_id"] for job in report["jobs"] if job["state"] == "reference_match"
    )
    actual_unresolved = sorted(
        job["job_id"] for job in report["jobs"] if job["state"] == "unresolved"
    )
    actual_derivatives = sorted(
        item["artifact_id"]
        for item in report["derivatives"]
        if item["state"] == "reference_mismatch"
    )
    expected_unresolved = sorted(oracle["expected_unresolved_jobs"])
    if expected_unresolved:
        pass_scope = all(job_id in actual_unresolved for job_id in expected_unresolved)
        expected_affected_for_case = sorted(
            set(oracle["directly_affected_jobs"]) - set(expected_unresolved)
        )
    else:
        pass_scope = True
        expected_affected_for_case = sorted(oracle["directly_affected_jobs"])
    affected_tp = len(set(actual_affected) & set(expected_affected_for_case))
    affected_precision = (
        affected_tp / len(actual_affected)
        if actual_affected
        else (1.0 if not expected_affected_for_case else 0.0)
    )
    affected_recall = (
        affected_tp / len(expected_affected_for_case) if expected_affected_for_case else 1.0
    )
    safe_tp = len(set(actual_safe) & set(oracle["safe_jobs"]))
    safe_precision = safe_tp / len(actual_safe) if actual_safe else 0.0
    safe_recall = safe_tp / len(oracle["safe_jobs"])
    leak_scan = scan_oracle_leaks(scenario_root, oracle_path, oracle)
    evaluation_root = oracle_path.parent
    leak_scan_path = evaluation_root / "oracle-leak-scan.json"
    leak_scan_digest = write_json(leak_scan_path, leak_scan)
    affected_resources = {
        item["resolved_resource_sha256"]
        for item in report["jobs"]
        if item["job_id"] in oracle["directly_affected_jobs"]
    }
    cause_pass = affected_resources == {oracle["causal_resource_sha256"]}
    jobs_by_id = {item["job_id"]: item for item in report["jobs"]}
    event_pass = any(
        item["event_id"] == oracle["non_causal_event_id"]
        and not item["resource_edges"]
        and not item["lineage_edges"]
        and item["output_mutation"] is False
        and {jobs_by_id[job_id]["state"] for job_id in item["overlapping_job_ids"]}
        == {"reference_match", "reference_mismatch"}
        for item in report["telemetry_events"]
    )
    derivative_pass = (
        actual_derivatives == sorted(oracle["affected_derivatives"])
        if not expected_unresolved
        else True
    )
    rejected_cause_checks: dict[str, bool] = {}
    for cause in oracle["rejected_causes"]:
        kind = cause["cause_kind"]
        if kind == "nominal-config":
            matching = [
                item for item in report["jobs"] if item["nominal_config_sha256"] == cause["sha256"]
            ]
            rejected_cause_checks[kind] = {item["state"] for item in matching} == {
                "reference_match",
                "reference_mismatch",
            }
        elif kind == "worker-alone":
            matching = [item for item in report["jobs"] if item["worker_id"] == cause["worker_id"]]
            rejected_cause_checks[kind] = {item["state"] for item in matching} == {
                "reference_match",
                "reference_mismatch",
            }
        elif kind == "distractor":
            rejected_cause_checks[kind] = (
                event_pass and cause["event_id"] == oracle["non_causal_event_id"]
            )
        else:
            rejected_cause_checks[kind] = False
    overall = (
        pass_scope
        and affected_precision == 1.0
        and affected_recall == 1.0
        and safe_precision == 1.0
        and safe_recall == 1.0
        and cause_pass
        and event_pass
        and derivative_pass
        and all(rejected_cause_checks.values())
        and leak_scan["pass"]
        and read_json(scenario_root / "reports" / "landlock-receipt.json")[
            "outside_bundle_read_denied"
        ]
    )
    evaluation = {
        "schema": "fixture-evaluation/v1",
        "scenario": scenario_root.name,
        "variant_id": oracle["variant_id"],
        "actual": {
            "affected_jobs": actual_affected,
            "safe_jobs": actual_safe,
            "unresolved_jobs": actual_unresolved,
            "affected_derivatives": actual_derivatives,
        },
        "metrics": {
            "affected_precision": fmt(affected_precision),
            "affected_recall": fmt(affected_recall),
            "safe_precision": fmt(safe_precision),
            "safe_recall": fmt(safe_recall),
        },
        "checks": {
            "expected_unresolved": pass_scope,
            "causal_resource": cause_pass,
            "non_causal_event_rejected": event_pass,
            "derivative_scope": derivative_pass,
            "rejected_causes": rejected_cause_checks,
            "validator_filesystem_isolated": read_json(
                scenario_root / "reports" / "landlock-receipt.json"
            )["outside_bundle_read_denied"],
            "oracle_leak_scan": leak_scan["pass"],
        },
        "oracle_leak_scan_sha256": leak_scan_digest,
        "pass": overall,
    }
    evaluation_path = evaluation_root / "evaluation-report.json"
    evaluation_digest = write_json(evaluation_path, evaluation)
    return {"report": evaluation, "path": evaluation_path, "sha256": evaluation_digest}


def deterministic_tree_index(root: Path, subtrees: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    operational_receipts = {"reports/landlock-receipt.json"}
    for subtree in subtrees:
        base = root / subtree
        for path in sorted(item for item in base.rglob("*") if item.is_file()):
            key = f"{subtree}/{path.relative_to(base).as_posix()}"
            if key not in operational_receipts:
                result[key] = sha256_file(path)
    return result


def write_case(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    digest = write_json(path, value)
    return {"case": value["case"], "path": path.as_posix(), "sha256": digest, "pass": value["pass"]}


def run_all(output: Path, script: Path, python: Path) -> None:
    if output.exists():
        raise FileExistsError(f"refusing to overwrite evidence root: {output}")
    output.mkdir(parents=True, mode=0o700)
    scenarios_root = output / "scenarios"
    oracles_root = output / "oracles"
    cases_root = output / "cases"
    cases_root.mkdir(parents=True, mode=0o700)
    scenario_specs: list[tuple[str, dict[str, Any]]] = [
        ("canonical", dict(variant_id="canonical", seed=CANONICAL_SEED)),
        ("permuted", dict(variant_id="hidden-a", seed=PERMUTED_SEED, permuted=True)),
        (
            "missing-manifest",
            dict(
                variant_id="missing-resource-manifest", seed=CANONICAL_SEED, omit_resource_role="b2"
            ),
        ),
        (
            "missing-reference",
            dict(variant_id="missing-reference", seed=CANONICAL_SEED, omit_reference_role="b3"),
        ),
        ("repeat-canonical", dict(variant_id="canonical", seed=CANONICAL_SEED)),
    ]
    results: dict[str, dict[str, Any]] = {}
    for name, kwargs in scenario_specs:
        root = scenarios_root / name
        generated = build_scenario(root, oracle_root=oracles_root / name, **kwargs)
        report = run_isolated_validator(script, root, python)
        evaluation = evaluate_scenario(root, generated["oracle"], report)
        results[name] = {"root": root, "report": report, "evaluation": evaluation}

    case_index = []
    for name in ("canonical", "permuted", "missing-manifest", "missing-reference"):
        evaluation = results[name]["evaluation"]
        case_index.append(
            write_case(
                cases_root / f"{name}.json",
                {
                    "schema": "fixture-case/v1",
                    "case": name,
                    "scenario": f"scenarios/{name}",
                    "evaluation_report": f"oracles/{name}/evaluation-report.json",
                    "evaluation_sha256": evaluation["sha256"],
                    "pass": evaluation["report"]["pass"],
                },
            )
        )

    canonical_report = results["canonical"]["report"]
    safe_b = next(
        job
        for job in canonical_report["jobs"]
        if job["worker_id"] == "B" and job["transform_id"] == "identity/v1"
    )
    case_index.append(
        write_case(
            cases_root / "safe-on-b.json",
            {
                "schema": "fixture-case/v1",
                "case": "safe-on-b",
                "job_id": safe_b["job_id"],
                "state": safe_b["state"],
                "comparison": safe_b["comparison"],
                "resolved_resource_sha256": safe_b["resolved_resource_sha256"],
                "pass": safe_b["state"] == "reference_match"
                and safe_b["resolved_resource_sha256"] is None,
            },
        )
    )
    event = canonical_report["telemetry_events"][0]
    case_index.append(
        write_case(
            cases_root / "distractor.json",
            {
                "schema": "fixture-case/v1",
                "case": "distractor",
                "event": event,
                "pass": event["event_id"] == "distractor-01"
                and not event["resource_edges"]
                and not event["lineage_edges"]
                and event["output_mutation"] is False,
            },
        )
    )

    canonical_index = deterministic_tree_index(
        results["canonical"]["root"], ("runtime", "references", "reports")
    )
    repeat_index = deterministic_tree_index(
        results["repeat-canonical"]["root"], ("runtime", "references", "reports")
    )
    reproducibility_differences = sorted(
        key
        for key in set(canonical_index) | set(repeat_index)
        if canonical_index.get(key) != repeat_index.get(key)
    )
    repeat_case = {
        "schema": "fixture-case/v1",
        "case": "repeated-seed",
        "canonical_files": len(canonical_index),
        "repeat_files": len(repeat_index),
        "differences": reproducibility_differences,
        "canonical_tree_digest": sha256_bytes(canonical_json_bytes(canonical_index)),
        "repeat_tree_digest": sha256_bytes(canonical_json_bytes(repeat_index)),
        "pass": not reproducibility_differences,
    }
    case_index.append(write_case(cases_root / "repeated-seed.json", repeat_case))

    namespace_receipts = [
        read_json(results[name]["root"] / "reports" / "landlock-receipt.json")
        for name, _ in scenario_specs
    ]
    oracle_checks = [
        results[name]["evaluation"]["report"]["checks"]["oracle_leak_scan"]
        for name, _ in scenario_specs
    ]
    oracle_case = {
        "schema": "fixture-case/v1",
        "case": "oracle-separation",
        "namespace_receipts": len(namespace_receipts),
        "all_outside_reads_denied": all(
            item["outside_bundle_read_denied"] for item in namespace_receipts
        ),
        "all_runtime_reference_scans_clean": all(oracle_checks),
        "pass": all(item["outside_bundle_read_denied"] for item in namespace_receipts)
        and all(oracle_checks),
    }
    case_index.append(write_case(cases_root / "oracle-separation.json", oracle_case))

    generation = read_json(results["canonical"]["root"] / "reports" / "generation-receipt.json")
    real_ocio_case = {
        "schema": "fixture-case/v1",
        "case": "real-ocio-resources",
        "ocio_version": generation["ocio_version"],
        "config_sha256": generation["config_sha256"],
        "config_sha256_equal": generation["config_sha256_equal"],
        "worker_resource_sha256": generation["worker_resource_sha256"],
        "lut_sha256_different": generation["lut_sha256_different"],
        "pass": generation["ocio_version"] == OCIO_VERSION
        and generation["config_sha256_equal"]
        and generation["lut_sha256_different"],
    }
    case_index.append(write_case(cases_root / "real-ocio-resources.json", real_ocio_case))

    summary = {
        "schema": "fixture-reproducibility-report/v1",
        "fixture": FIXTURE_ID,
        "fixture_version": FIXTURE_VERSION,
        "ocio_version": ocio.__version__,
        "python_version": sys.version.split()[0],
        "cases": sorted(case_index, key=lambda item: item["case"]),
        "case_count": len(case_index),
        "all_cases_pass": all(item["pass"] for item in case_index),
    }
    write_json(output / "summary.json", summary)
    if not summary["all_cases_pass"]:
        raise RuntimeError("one or more fixture cases failed")


def reindex(fixture_root: Path) -> None:
    index_path = fixture_root / "SHA256SUMS.json"
    records = []
    for path in sorted(
        item for item in fixture_root.rglob("*") if item.is_file() and item != index_path
    ):
        records.append(
            {
                "path": path.relative_to(fixture_root).as_posix(),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
        )
    write_json(
        index_path,
        {"schema": "fixture-file-index/v1", "files": records, "file_count": len(records)},
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="colortrace-fixture")
    sub = parser.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate")
    generate.add_argument("--bundle", type=Path, required=True)
    generate.add_argument("--oracle", type=Path, required=True)
    generate.add_argument("--variant", default="canonical")
    generate.add_argument("--seed", default=CANONICAL_SEED)
    generate.add_argument("--permuted", action="store_true")
    generate.add_argument("--omit-resource-role", choices=("a1", "a2", "b1", "b2", "b3", "b4"))
    generate.add_argument("--omit-reference-role", choices=("a1", "a2", "b1", "b2", "b3", "b4"))
    run = sub.add_parser("run")
    run.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--scenario", type=Path, required=True)
    validate_worker = sub.add_parser("validate-worker", help=argparse.SUPPRESS)
    validate_worker.add_argument("--scenario", type=Path, required=True)
    validate_worker.add_argument("--denied-probe", type=Path, required=True)
    canonical_build = sub.add_parser("validate-canonical-build", help=argparse.SUPPRESS)
    canonical_build.add_argument("--scenario", type=Path, required=True)
    canonical_build.add_argument("--canonical-digests", type=Path, required=True)
    canonical_build.add_argument("--absent-oracle-root", type=Path, action="append", required=True)
    canonical_build.add_argument("--require-privilege-drop", action="store_true", required=True)
    canonical_worker = sub.add_parser("validate-canonical-build-worker", help=argparse.SUPPRESS)
    canonical_worker.add_argument("--scenario", type=Path, required=True)
    canonical_worker.add_argument("--denied-probe", type=Path, required=True)
    canonical_worker_mode = canonical_worker.add_mutually_exclusive_group(required=True)
    canonical_worker_mode.add_argument("--privilege-separated", action="store_true")
    canonical_worker_mode.add_argument("--functional-nonroot", action="store_true")
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--scenario", type=Path, required=True)
    evaluate.add_argument("--oracle", type=Path, required=True)
    index = sub.add_parser("reindex")
    index.add_argument("--root", type=Path, required=True)
    reference_fetch = sub.add_parser("reference-fetch")
    reference_fetch.add_argument("--cache", type=Path, required=True)
    reference_fetch.add_argument("--manifest", type=Path, default=REFERENCE_MEDIA_MANIFEST)
    reference_verify = sub.add_parser("reference-verify")
    reference_verify.add_argument("--cache", type=Path, required=True)
    reference_verify.add_argument("--manifest", type=Path, default=REFERENCE_MEDIA_MANIFEST)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if ocio.__version__ != OCIO_VERSION:
        raise RuntimeError(f"OpenColorIO version mismatch: {ocio.__version__}")
    script = Path(__file__).resolve()
    # Preserve the virtual-environment executable path; resolving the symlink
    # would bypass its site-packages inside the validator namespace.
    python = Path(sys.executable)
    if args.command == "generate":
        build_scenario(
            args.bundle,
            oracle_root=args.oracle,
            variant_id=args.variant,
            seed=args.seed,
            permuted=args.permuted,
            omit_resource_role=args.omit_resource_role,
            omit_reference_role=args.omit_reference_role,
        )
    elif args.command == "run":
        run_all(args.output.resolve(), script, python)
    elif args.command == "validate":
        run_isolated_validator(script, args.scenario.resolve(), python)
    elif args.command == "validate-worker":
        validate_landlocked_worker(args.scenario, args.denied_probe)
    elif args.command == "validate-canonical-build":
        run_canonical_build_validator(
            script,
            args.scenario,
            python,
            args.canonical_digests,
            tuple(args.absent_oracle_root),
            require_privilege_drop=args.require_privilege_drop,
        )
    elif args.command == "validate-canonical-build-worker":
        validate_canonical_build_worker(
            args.scenario,
            args.denied_probe,
            privilege_separated=args.privilege_separated,
        )
    elif args.command == "evaluate":
        report = read_json(args.scenario.resolve() / "reports" / "validator-report.json")
        evaluate_scenario(args.scenario.resolve(), args.oracle.resolve(), report)
    elif args.command == "reindex":
        reindex(args.root.resolve())
    elif args.command == "reference-fetch":
        manifest = load_reference_media_manifest(args.manifest)
        print(json.dumps(fetch_reference_media(args.cache, manifest).to_dict(), sort_keys=True))
    elif args.command == "reference-verify":
        manifest = load_reference_media_manifest(args.manifest)
        print(json.dumps(verify_reference_media(args.cache, manifest).to_dict(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
