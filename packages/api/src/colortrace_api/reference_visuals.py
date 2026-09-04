from __future__ import annotations

import hashlib
import json
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast

REFERENCE_PREVIEW_MANIFEST_VERSION = "reference-preview-manifest/v1"
ReferenceVisualKind = Literal["expected", "observed", "recovered", "diff"]

REFERENCE_PREVIEW_ROOT = Path(__file__).with_name("reference_previews")
REFERENCE_PREVIEW_MANIFEST_PATH = REFERENCE_PREVIEW_ROOT / "manifest.json"

_VISUAL_KINDS: tuple[ReferenceVisualKind, ...] = (
    "expected",
    "observed",
    "recovered",
    "diff",
)
_SCENARIO_IDS = frozenset(
    {
        "tos-resource-resolution-drift-v1",
        "tos-config-rollout-drift-v1",
        "tos-stale-derivative-cache-v1",
    }
)
_ROOT_KEYS = frozenset(
    {
        "schema",
        "reference_manifest_sha256",
        "generator",
        "scenarios",
        "worker_receipts",
        "manifest_sha256",
    }
)
_SCENARIO_KEYS = frozenset({"served_artifact_id", "visuals"})
_VISUAL_KEYS = frozenset(
    {
        "display_transform",
        "filename",
        "height",
        "media_type",
        "pixel_evidence",
        "representation",
        "sha256",
        "source_artifact_ids",
        "source_canonical_pixel_sha256",
        "source_output_sha256",
        "source_receipt_sha256",
        "source_relation",
        "width",
    }
)
_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "job_id",
        "scenario_id",
        "incident_class",
        "trace_id",
        "worker_id",
        "artifact_id",
        "source_sha256",
        "config_sha256",
        "resource_sha256",
        "effective_generation",
        "cache_key",
        "output_relative_path",
        "output_sha256",
        "canonical_pixel_sha256",
        "width",
        "height",
        "channels",
        "pixel_work",
        "bytes_read",
        "bytes_written",
        "cpu_nanoseconds",
        "wall_nanoseconds",
        "dependencies",
        "receipt_sha256",
    }
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_MANIFEST_BYTES = 128 * 1024
_MAX_PREVIEW_BYTES = 2 * 1024 * 1024


class ReferencePreviewError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value)).hexdigest()}"


def _content_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _digest_sequence(value: Any, *, size: int) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) != size
        or any(not isinstance(child, str) or _DIGEST.fullmatch(child) is None for child in value)
    ):
        raise ReferencePreviewError("reference-preview-manifest-invalid")
    return tuple(value)


def _identifier_sequence(value: Any, *, size: int) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) != size
        or any(
            not isinstance(child, str) or _IDENTIFIER.fullmatch(child) is None for child in value
        )
    ):
        raise ReferencePreviewError("reference-preview-manifest-invalid")
    return tuple(value)


def _read_png(path: Path, *, expected_width: int, expected_height: int) -> bytes:
    try:
        metadata = path.lstat()
        content = path.read_bytes()
    except OSError as error:
        raise ReferencePreviewError("reference-preview-unavailable") from error
    if (
        path.is_symlink()
        or not path.is_file()
        or metadata.st_nlink != 1
        or not 1 <= len(content) <= _MAX_PREVIEW_BYTES
        or not content.startswith(_PNG_SIGNATURE)
        or len(content) < 24
        or content[12:16] != b"IHDR"
        or struct.unpack(">II", content[16:24]) != (expected_width, expected_height)
    ):
        raise ReferencePreviewError("reference-preview-file-invalid")
    return content


def _validate_receipts(value: Any) -> Mapping[str, Mapping[str, Any]]:
    if not isinstance(value, dict) or not value:
        raise ReferencePreviewError("reference-preview-receipts-invalid")
    result: dict[str, Mapping[str, Any]] = {}
    for key, receipt in value.items():
        if (
            not isinstance(key, str)
            or _DIGEST.fullmatch(key) is None
            or not isinstance(receipt, dict)
            or set(receipt) != _RECEIPT_KEYS
            or receipt.get("schema") != "reference-render-receipt/v1"
        ):
            raise ReferencePreviewError("reference-preview-receipts-invalid")
        body = {name: child for name, child in receipt.items() if name != "receipt_sha256"}
        if (
            receipt.get("receipt_sha256") != key
            or key != _digest(body)
            or receipt.get("dependencies") != {"openimageio": "3.1.17.0", "opencolorio": "2.5.2"}
        ):
            raise ReferencePreviewError("reference-preview-receipts-invalid")
        result[key] = MappingProxyType(dict(receipt))
    return MappingProxyType(result)


@dataclass(frozen=True, slots=True)
class ReferencePreviewAsset:
    kind: ReferenceVisualKind
    content: bytes
    media_type: Literal["image/png"]
    sha256: str
    representation: Literal["open-film-preview-png/v1", "open-film-difference-png/v1"]
    pixel_evidence: Literal[True]
    width: int
    height: int
    served_artifact_id: str
    source_artifact_ids: tuple[str, ...]
    source_relation: str
    source_receipt_sha256: tuple[str, ...]
    source_output_sha256: tuple[str, ...]
    source_canonical_pixel_sha256: tuple[str, ...]

    def descriptor(self, *, scenario_id: str) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "href": f"/v1/demo/scenarios/{scenario_id}/visuals/{self.kind}",
            "content_sha256": self.sha256,
            "representation": self.representation,
            "pixel_evidence": self.pixel_evidence,
            "width": self.width,
            "height": self.height,
            "served_artifact_id": self.served_artifact_id,
            "source_artifact_ids": list(self.source_artifact_ids),
            "source_relation": self.source_relation,
            "source_receipt_sha256": list(self.source_receipt_sha256),
            "source_output_sha256": list(self.source_output_sha256),
            "source_canonical_pixel_sha256": list(self.source_canonical_pixel_sha256),
        }


@dataclass(frozen=True, slots=True)
class ReferencePreviewCatalog:
    reference_manifest_sha256: str
    manifest_sha256: str
    display_transform: str
    scenarios: Mapping[str, Mapping[ReferenceVisualKind, ReferencePreviewAsset]]

    def visual(self, scenario_id: str, kind: str) -> ReferencePreviewAsset:
        try:
            return self.scenarios[scenario_id][cast(ReferenceVisualKind, kind)]
        except KeyError:
            raise ReferencePreviewError("reference-preview-not-found") from None


def _validate_visual(
    *,
    scenario_id: str,
    served_artifact_id: str,
    kind: ReferenceVisualKind,
    value: Any,
    asset_root: Path,
    receipts: Mapping[str, Mapping[str, Any]],
) -> ReferencePreviewAsset:
    if not isinstance(value, dict) or set(value) != _VISUAL_KEYS:
        raise ReferencePreviewError("reference-preview-manifest-invalid")
    source_count = 2 if kind == "diff" else 1
    receipt_ids = _digest_sequence(value["source_receipt_sha256"], size=source_count)
    output_ids = _digest_sequence(value["source_output_sha256"], size=source_count)
    pixel_ids = _digest_sequence(value["source_canonical_pixel_sha256"], size=source_count)
    artifact_ids = _identifier_sequence(value["source_artifact_ids"], size=source_count)
    filename = value.get("filename")
    width = value.get("width")
    height = value.get("height")
    relation = value.get("source_relation")
    representation = value.get("representation")
    expected_representation = (
        "open-film-difference-png/v1" if kind == "diff" else "open-film-preview-png/v1"
    )
    expected_relation = (
        "amplified-absolute-display-difference-8x"
        if kind == "diff"
        else "stale-parent"
        if scenario_id == "tos-stale-derivative-cache-v1" and kind == "observed"
        else "current"
    )
    if (
        not isinstance(filename, str)
        or Path(filename).name != filename
        or not isinstance(width, int)
        or isinstance(width, bool)
        or not isinstance(height, int)
        or isinstance(height, bool)
        or (width, height) != (960, 506)
        or value.get("media_type") != "image/png"
        or value.get("pixel_evidence") is not True
        or representation != expected_representation
        or relation != expected_relation
        or value.get("display_transform") != "linear-to-srgb"
        or not isinstance(value.get("sha256"), str)
        or _DIGEST.fullmatch(value["sha256"]) is None
    ):
        raise ReferencePreviewError("reference-preview-manifest-invalid")
    source_receipts: list[Mapping[str, Any]] = []
    for receipt_id, output_id, pixel_id, artifact_id in zip(
        receipt_ids,
        output_ids,
        pixel_ids,
        artifact_ids,
        strict=True,
    ):
        receipt = receipts.get(receipt_id)
        if (
            receipt is None
            or receipt.get("scenario_id") != scenario_id
            or receipt.get("artifact_id") != artifact_id
            or receipt.get("output_sha256") != output_id
            or receipt.get("canonical_pixel_sha256") != pixel_id
        ):
            raise ReferencePreviewError("reference-preview-receipt-binding-invalid")
        source_receipts.append(receipt)
    if (
        kind != "diff"
        and relation == "current"
        and artifact_ids != (served_artifact_id,)
        or kind == "observed"
        and relation == "stale-parent"
        and artifact_ids == (served_artifact_id,)
    ):
        raise ReferencePreviewError("reference-preview-artifact-binding-invalid")
    content = _read_png(asset_root / filename, expected_width=width, expected_height=height)
    if _content_digest(content) != value["sha256"]:
        raise ReferencePreviewError("reference-preview-digest-mismatch")
    return ReferencePreviewAsset(
        kind=kind,
        content=content,
        media_type="image/png",
        sha256=value["sha256"],
        representation=cast(
            Literal["open-film-preview-png/v1", "open-film-difference-png/v1"],
            representation,
        ),
        pixel_evidence=True,
        width=width,
        height=height,
        served_artifact_id=served_artifact_id,
        source_artifact_ids=artifact_ids,
        source_relation=cast(str, relation),
        source_receipt_sha256=receipt_ids,
        source_output_sha256=output_ids,
        source_canonical_pixel_sha256=pixel_ids,
    )


def load_reference_preview_catalog(
    *,
    expected_reference_manifest_sha256: str,
    manifest_path: Path = REFERENCE_PREVIEW_MANIFEST_PATH,
    asset_root: Path = REFERENCE_PREVIEW_ROOT,
) -> ReferencePreviewCatalog:
    try:
        metadata = manifest_path.lstat()
        raw = manifest_path.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReferencePreviewError("reference-preview-manifest-invalid") from error
    if (
        manifest_path.is_symlink()
        or not manifest_path.is_file()
        or metadata.st_nlink != 1
        or not 1 <= len(raw) <= _MAX_MANIFEST_BYTES
        or not isinstance(document, dict)
        or set(document) != _ROOT_KEYS
        or document.get("schema") != REFERENCE_PREVIEW_MANIFEST_VERSION
        or document.get("reference_manifest_sha256") != expected_reference_manifest_sha256
    ):
        raise ReferencePreviewError("reference-preview-manifest-invalid")
    body = {key: value for key, value in document.items() if key != "manifest_sha256"}
    if document.get("manifest_sha256") != _digest(body):
        raise ReferencePreviewError("reference-preview-manifest-digest-mismatch")
    generator = document.get("generator")
    scenarios = document.get("scenarios")
    if (
        generator
        != {
            "difference_scale": 8,
            "display_transform": "linear-to-srgb",
            "height": 506,
            "openimageio": "3.1.17.0",
            "width": 960,
        }
        or not isinstance(scenarios, dict)
        or set(scenarios) != _SCENARIO_IDS
    ):
        raise ReferencePreviewError("reference-preview-manifest-invalid")
    receipts = _validate_receipts(document.get("worker_receipts"))
    parsed_scenarios: dict[str, Mapping[ReferenceVisualKind, ReferencePreviewAsset]] = {}
    referenced_receipts: set[str] = set()
    for scenario_id in sorted(scenarios):
        scenario = scenarios[scenario_id]
        if not isinstance(scenario, dict) or set(scenario) != _SCENARIO_KEYS:
            raise ReferencePreviewError("reference-preview-manifest-invalid")
        served_artifact_id = scenario.get("served_artifact_id")
        visuals = scenario.get("visuals")
        if (
            not isinstance(served_artifact_id, str)
            or _IDENTIFIER.fullmatch(served_artifact_id) is None
            or not isinstance(visuals, dict)
            or set(visuals) != set(_VISUAL_KINDS)
        ):
            raise ReferencePreviewError("reference-preview-manifest-invalid")
        parsed: dict[ReferenceVisualKind, ReferencePreviewAsset] = {}
        for kind in _VISUAL_KINDS:
            asset = _validate_visual(
                scenario_id=scenario_id,
                served_artifact_id=served_artifact_id,
                kind=kind,
                value=visuals[kind],
                asset_root=asset_root,
                receipts=receipts,
            )
            parsed[kind] = asset
            referenced_receipts.update(asset.source_receipt_sha256)
        if (
            parsed["expected"].sha256 != parsed["recovered"].sha256
            or parsed["expected"].source_canonical_pixel_sha256
            != parsed["recovered"].source_canonical_pixel_sha256
            or parsed["expected"].source_canonical_pixel_sha256
            == parsed["observed"].source_canonical_pixel_sha256
            or parsed["diff"].source_receipt_sha256
            != (
                *parsed["expected"].source_receipt_sha256,
                *parsed["observed"].source_receipt_sha256,
            )
        ):
            raise ReferencePreviewError("reference-preview-equivalence-invalid")
        parsed_scenarios[scenario_id] = MappingProxyType(parsed)
    if referenced_receipts != set(receipts):
        raise ReferencePreviewError("reference-preview-receipts-invalid")
    return ReferencePreviewCatalog(
        reference_manifest_sha256=expected_reference_manifest_sha256,
        manifest_sha256=cast(str, document["manifest_sha256"]),
        display_transform="linear-to-srgb",
        scenarios=MappingProxyType(parsed_scenarios),
    )


__all__ = [
    "REFERENCE_PREVIEW_MANIFEST_PATH",
    "REFERENCE_PREVIEW_MANIFEST_VERSION",
    "REFERENCE_PREVIEW_ROOT",
    "ReferencePreviewAsset",
    "ReferencePreviewCatalog",
    "ReferencePreviewError",
    "ReferenceVisualKind",
    "load_reference_preview_catalog",
]
