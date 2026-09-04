from __future__ import annotations

import ctypes
import hashlib
import json
import os
import stat
import struct
import sys
import tempfile
from argparse import ArgumentParser
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

import OpenImageIO as oiio
from colortrace_api.reference_visuals import (
    REFERENCE_PREVIEW_MANIFEST_PATH,
    REFERENCE_PREVIEW_ROOT,
    ReferencePreviewCatalog,
    load_reference_preview_catalog,
)
from colortrace_fixture import (
    ReferenceFrame,
    load_reference_media_manifest,
    materialize_reference_color_variants,
    reference_render_job,
    reference_scenarios,
)
from colortrace_simulator.reference_worker import execute_reference_render_job

from .contracts import canonical_json_bytes

ReferenceRenderer = Callable[..., dict[str, Any]]
PreviewAssetBuilder = Callable[..., Mapping[str, bytes]]

_OPENIMAGEIO_VERSION = "3.1.17.0"
_PREVIEW_WIDTH = 960
_PREVIEW_HEIGHT = 506
_DIFFERENCE_SCALE = 8.0
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_PREVIEW_BYTES = 2 * 1024 * 1024
_AT_FDCWD = -100
_RENAME_EXCHANGE = 2

_PREVIEW_ARTIFACTS: Mapping[str, tuple[str, str]] = {
    "tos-resource-resolution-drift-v1": (
        "frame:03_2a:00000",
        "frame:03_2a:00000",
    ),
    "tos-config-rollout-drift-v1": (
        "frame:03_2a:00000",
        "frame:03_2a:00000",
    ),
    "tos-stale-derivative-cache-v1": (
        "frame:03_2a:00003",
        "frame:03_2a:00002",
    ),
}
_MODES = ("expected", "observed", "recovered")
PreviewMode = Literal["expected", "observed", "recovered"]


class ReferencePreviewRefreshError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _FileSnapshot:
    name: str
    device: int
    inode: int
    mode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    sha256: str


@dataclass(frozen=True, slots=True)
class _AssetSetSnapshot:
    device: int
    inode: int
    mode: int
    entries: tuple[_FileSnapshot, ...]

    @property
    def names(self) -> frozenset[str]:
        return frozenset(entry.name for entry in self.entries)

    def file_mode(self, name: str) -> int:
        for entry in self.entries:
            if entry.name == name:
                return stat.S_IMODE(entry.mode)
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe")


@dataclass(frozen=True, slots=True)
class _DecodedDisplay:
    image: oiio.ImageBuf
    source_decoded_pixel_sha256: str


def _content_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _update_decoded_pixel_digest(digest: Any, rows: Any) -> None:
    for row in rows:
        digest.update(row.astype(">f4", copy=False).tobytes(order="C"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-render-output-invalid") from error
    return f"sha256:{digest.hexdigest()}"


def _drop_file_cache(path: Path) -> None:
    advice = getattr(os, "POSIX_FADV_DONTNEED", None)
    posix_fadvise = getattr(os, "posix_fadvise", None)
    if advice is None or posix_fadvise is None:
        return
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        posix_fadvise(descriptor, 0, 0, advice)
    except OSError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _artifact_id(frame: ReferenceFrame) -> str:
    return f"frame:{frame.sequence_id}:{frame.frame:05d}"


def _reference_frames() -> Mapping[str, ReferenceFrame]:
    manifest = load_reference_media_manifest()
    return {
        _artifact_id(frame): frame for sequence in manifest.sequences for frame in sequence.frames
    }


def _trace_id(scenario_id: str, mode: str) -> str:
    return hashlib.sha256(f"reference-preview\0{scenario_id}\0{mode}".encode()).hexdigest()[:32]


def _receipt_matches_job(receipt: Mapping[str, Any], job: Mapping[str, Any]) -> bool:
    source = cast(Mapping[str, Any], job["source"])
    color = cast(Mapping[str, Any], job["color"])
    runtime = cast(Mapping[str, Any], job["runtime"])
    output = cast(Mapping[str, Any], job["output"])
    receipt_id = receipt.get("receipt_sha256")
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    return (
        receipt.get("schema") == "reference-render-receipt/v1"
        and isinstance(receipt_id, str)
        and receipt_id == _content_digest(canonical_json_bytes(receipt_body))
        and receipt.get("job_id") == job["job_id"]
        and receipt.get("scenario_id") == job["scenario_id"]
        and receipt.get("incident_class") == job["incident_class"]
        and receipt.get("trace_id") == job["trace_id"]
        and receipt.get("worker_id") == job["worker_id"]
        and receipt.get("artifact_id") == job["artifact_id"]
        and receipt.get("source_sha256") == source["sha256"]
        and receipt.get("config_sha256") == color["config_sha256"]
        and receipt.get("resource_sha256") == color["resource_sha256"]
        and receipt.get("effective_generation") == runtime["effective_generation"]
        and receipt.get("cache_key") == runtime["cache_key"]
        and receipt.get("output_relative_path") == output["relative_path"]
        and receipt.get("bytes_read") == source["byte_length"]
        and (receipt.get("width"), receipt.get("height"), receipt.get("channels"))
        == (4096, 2160, 3)
        and receipt.get("pixel_work") == 8_847_360
        and receipt.get("dependencies")
        == {"openimageio": _OPENIMAGEIO_VERSION, "opencolorio": "2.5.2"}
    )


def _render_jobs(
    *,
    source_root: Path,
    work_root: Path,
    renderer: ReferenceRenderer,
) -> Mapping[tuple[str, str], Mapping[str, Any]]:
    manifest = load_reference_media_manifest()
    scenarios = reference_scenarios(manifest)
    frames = _reference_frames()
    variants = materialize_reference_color_variants(work_root / "config")
    output_root = work_root / "output"
    receipts: dict[tuple[str, str], Mapping[str, Any]] = {}
    for scenario_id in sorted(_PREVIEW_ARTIFACTS):
        scenario = scenarios[scenario_id]
        expected_artifact_id, observed_artifact_id = _PREVIEW_ARTIFACTS[scenario_id]
        if (
            expected_artifact_id not in scenario.affected_artifact_ids
            or (
                scenario_id == "tos-stale-derivative-cache-v1"
                and observed_artifact_id not in scenario.protected_artifact_ids
            )
            or (
                scenario_id != "tos-stale-derivative-cache-v1"
                and observed_artifact_id not in scenario.affected_artifact_ids
            )
        ):
            raise ReferencePreviewRefreshError("reference-preview-selection-invalid")
        for mode in _MODES:
            selected_artifact_id = (
                observed_artifact_id if mode == "observed" else expected_artifact_id
            )
            try:
                frame = frames[selected_artifact_id]
            except KeyError as error:
                raise ReferencePreviewRefreshError("reference-preview-selection-invalid") from error
            job = reference_render_job(
                frame=frame,
                scenario=scenario,
                variants=variants,
                mode=cast(PreviewMode, mode),
                trace_id=_trace_id(scenario_id, mode),
            )
            if scenario_id == "tos-stale-derivative-cache-v1" and mode == "observed":
                job["output"]["relative_path"] = (
                    f"{scenario_id}/observed-stale-parent/{frame.sequence_id}/{frame.filename}"
                )
            receipt = renderer(
                job,
                source_root=source_root,
                config_root=work_root / "config",
                output_root=output_root,
            )
            if not _receipt_matches_job(receipt, job):
                raise ReferencePreviewRefreshError("reference-preview-receipt-job-mismatch")
            receipts[(scenario_id, mode)] = receipt
    return receipts


def _safe_output_path(output_root: Path, receipt: Mapping[str, Any]) -> Path:
    relative_value = receipt.get("output_relative_path")
    if not isinstance(relative_value, str):
        raise ReferencePreviewRefreshError("reference-preview-render-output-invalid")
    relative = Path(relative_value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ReferencePreviewRefreshError("reference-preview-render-output-invalid")
    try:
        root = output_root.resolve(strict=True)
        candidate = output_root / relative
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        metadata = resolved.lstat()
    except (OSError, ValueError) as error:
        raise ReferencePreviewRefreshError("reference-preview-render-output-invalid") from error
    if (
        candidate.absolute() != resolved
        or candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != receipt.get("bytes_written")
        or _sha256_file(resolved) != receipt.get("output_sha256")
    ):
        raise ReferencePreviewRefreshError("reference-preview-render-output-invalid")
    return resolved


def _require_image(image: oiio.ImageBuf, code: str) -> oiio.ImageBuf:
    if not image.initialized or image.has_error:
        image.geterror()
        raise ReferencePreviewRefreshError(code)
    return image


def _display_image(
    *,
    output_root: Path,
    receipt: Mapping[str, Any],
    width: int = _PREVIEW_WIDTH,
    height: int = _PREVIEW_HEIGHT,
) -> _DecodedDisplay:
    if oiio.VERSION_STRING != _OPENIMAGEIO_VERSION:
        raise ReferencePreviewRefreshError("reference-preview-openimageio-version-mismatch")
    path = _safe_output_path(output_root, receipt)
    try:
        source = _require_image(oiio.ImageBuf(str(path)), "reference-preview-render-output-invalid")
        spec = source.spec()
        if (
            spec.width != receipt.get("width")
            or spec.height != receipt.get("height")
            or spec.nchannels != receipt.get("channels")
            or spec.nchannels != 3
            or (spec.x, spec.y, spec.z, spec.depth) != (0, 0, 0, 1)
            or tuple(spec.channelnames) != ("R", "G", "B")
            or spec.format != oiio.HALF
        ):
            raise ReferencePreviewRefreshError("reference-preview-render-output-invalid")
        pixels = source.get_pixels(oiio.FLOAT)
        if pixels is None:
            raise ReferencePreviewRefreshError("reference-preview-render-output-invalid")
        decoded_digest = hashlib.sha256()
        _update_decoded_pixel_digest(decoded_digest, pixels)
        del pixels
        display = _require_image(
            oiio.ImageBufAlgo.colorconvert(
                source,
                "linear",
                "sRGB",
                unpremult=True,
                nthreads=1,
            ),
            "reference-preview-display-transform-failed",
        )
        roi = oiio.ROI(0, width, 0, height, 0, 1, 0, 3)
        resized = _require_image(
            oiio.ImageBufAlgo.resize(
                display,
                "lanczos3",
                0.0,
                roi,
                nthreads=1,
            ),
            "reference-preview-resize-failed",
        )
        clamped = _require_image(
            oiio.ImageBufAlgo.clamp(
                resized,
                (0.0, 0.0, 0.0),
                (1.0, 1.0, 1.0),
                nthreads=1,
            ),
            "reference-preview-clamp-failed",
        )
        source.clear()
        display.clear()
        resized.clear()
        oiio.ImageCache().invalidate(str(path), force=True)
        return _DecodedDisplay(
            image=clamped,
            source_decoded_pixel_sha256=f"sha256:{decoded_digest.hexdigest()}",
        )
    except ReferencePreviewRefreshError:
        raise
    except Exception as error:
        raise ReferencePreviewRefreshError("reference-preview-generation-failed") from error
    finally:
        _drop_file_cache(path)


def _difference_image(
    expected: oiio.ImageBuf,
    observed: oiio.ImageBuf,
) -> oiio.ImageBuf:
    try:
        difference = _require_image(
            oiio.ImageBufAlgo.absdiff(expected, observed, nthreads=1),
            "reference-preview-difference-failed",
        )
        amplified = _require_image(
            oiio.ImageBufAlgo.mul(
                difference,
                (_DIFFERENCE_SCALE, _DIFFERENCE_SCALE, _DIFFERENCE_SCALE, 1.0),
                nthreads=1,
            ),
            "reference-preview-difference-failed",
        )
        return _require_image(
            oiio.ImageBufAlgo.clamp(
                amplified,
                (0.0, 0.0, 0.0),
                (1.0, 1.0, 1.0),
                nthreads=1,
            ),
            "reference-preview-difference-failed",
        )
    except ReferencePreviewRefreshError:
        raise
    except Exception as error:
        raise ReferencePreviewRefreshError("reference-preview-difference-failed") from error


def _encode_png(image: oiio.ImageBuf, path: Path) -> bytes:
    try:
        spec = image.spec()
        if (spec.width, spec.height, spec.nchannels) != (
            _PREVIEW_WIDTH,
            _PREVIEW_HEIGHT,
            3,
        ):
            raise ReferencePreviewRefreshError("reference-preview-encode-layout-invalid")
        pixels = image.get_pixels(oiio.FLOAT)
        if pixels is None:
            raise ReferencePreviewRefreshError("reference-preview-encode-failed")
        clean_spec = oiio.ImageSpec(_PREVIEW_WIDTH, _PREVIEW_HEIGHT, 3, oiio.FLOAT)
        clean_spec.channelnames = ("R", "G", "B")
        clean_spec.attribute("oiio:ColorSpace", "sRGB")
        clean = oiio.ImageBuf(clean_spec)
        roi = oiio.ROI(0, _PREVIEW_WIDTH, 0, _PREVIEW_HEIGHT, 0, 1, 0, 3)
        if not clean.set_pixels(roi, pixels):
            raise ReferencePreviewRefreshError("reference-preview-encode-failed")
        clean.set_write_format(oiio.UINT8)
        if path.exists():
            raise ReferencePreviewRefreshError("reference-preview-encode-failed")
        if not clean.write(str(path)):
            clean.geterror()
            raise ReferencePreviewRefreshError("reference-preview-encode-failed")
        content = path.read_bytes()
        if (
            not 1 <= len(content) <= _MAX_PREVIEW_BYTES
            or not content.startswith(_PNG_SIGNATURE)
            or len(content) < 24
            or content[12:16] != b"IHDR"
            or struct.unpack(">II", content[16:24]) != (_PREVIEW_WIDTH, _PREVIEW_HEIGHT)
        ):
            raise ReferencePreviewRefreshError("reference-preview-encode-failed")
        return content
    except ReferencePreviewRefreshError:
        raise
    except Exception as error:
        raise ReferencePreviewRefreshError("reference-preview-encode-failed") from error


def _preview_filenames(template: Mapping[str, Any]) -> Mapping[tuple[str, str], str]:
    try:
        scenarios = cast(Mapping[str, Any], template["scenarios"])
        filenames = {
            (scenario_id, kind): cast(str, scenario["visuals"][kind]["filename"])
            for scenario_id, scenario in scenarios.items()
            for kind in ("expected", "observed", "recovered", "diff")
        }
    except (KeyError, TypeError) as error:
        raise ReferencePreviewRefreshError("reference-preview-manifest-invalid") from error
    if (
        len(filenames) != 12
        or len(set(filenames.values())) != 12
        or any(Path(name).name != name or not name.endswith(".png") for name in filenames.values())
    ):
        raise ReferencePreviewRefreshError("reference-preview-manifest-invalid")
    return filenames


def _build_preview_assets(
    *,
    template: Mapping[str, Any],
    receipts: Mapping[tuple[str, str], Mapping[str, Any]],
    output_root: Path,
    work_root: Path,
) -> Mapping[str, bytes]:
    filenames = _preview_filenames(template)
    encode_root = work_root / "encoded"
    try:
        encode_root.mkdir(mode=0o700)
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-generation-failed") from error
    assets: dict[str, bytes] = {}
    for scenario_id in sorted(_PREVIEW_ARTIFACTS):
        displays = {
            mode: _display_image(
                output_root=output_root,
                receipt=receipts[(scenario_id, mode)],
            )
            for mode in _MODES
        }
        for mode in _MODES:
            filename = filenames[(scenario_id, mode)]
            assets[filename] = _encode_png(displays[mode].image, encode_root / filename)
        if (
            displays["expected"].source_decoded_pixel_sha256
            != displays["recovered"].source_decoded_pixel_sha256
        ):
            raise ReferencePreviewRefreshError("reference-preview-recovery-decoded-pixels-mismatch")
        if (
            assets[filenames[(scenario_id, "expected")]]
            != assets[filenames[(scenario_id, "recovered")]]
        ):
            raise ReferencePreviewRefreshError("reference-preview-recovery-preview-mismatch")
        difference = _difference_image(
            displays["expected"].image,
            displays["observed"].image,
        )
        filename = filenames[(scenario_id, "diff")]
        assets[filename] = _encode_png(difference, encode_root / filename)
    if set(assets) != set(filenames.values()):
        raise ReferencePreviewRefreshError("reference-preview-generation-failed")
    return assets


def _rebind_manifest(
    template: Mapping[str, Any],
    receipts: Mapping[tuple[str, str], Mapping[str, Any]],
    assets: Mapping[str, bytes],
) -> dict[str, Any]:
    document = deepcopy(dict(template))
    scenarios = cast(dict[str, Any], document["scenarios"])
    receipt_index: dict[str, Mapping[str, Any]] = {}
    for scenario_id in sorted(_PREVIEW_ARTIFACTS):
        expected_artifact_id, observed_artifact_id = _PREVIEW_ARTIFACTS[scenario_id]
        scenario = cast(dict[str, Any], scenarios[scenario_id])
        if scenario.get("served_artifact_id") != expected_artifact_id:
            raise ReferencePreviewRefreshError("reference-preview-selection-invalid")
        visuals = cast(dict[str, dict[str, Any]], scenario["visuals"])
        selected: dict[str, tuple[Mapping[str, Any], ...]] = {
            "expected": (receipts[(scenario_id, "expected")],),
            "observed": (receipts[(scenario_id, "observed")],),
            "recovered": (receipts[(scenario_id, "recovered")],),
            "diff": (
                receipts[(scenario_id, "expected")],
                receipts[(scenario_id, "observed")],
            ),
        }
        expected_ids = {
            "expected": (expected_artifact_id,),
            "observed": (observed_artifact_id,),
            "recovered": (expected_artifact_id,),
            "diff": (expected_artifact_id, observed_artifact_id),
        }
        for kind, selected_receipts in selected.items():
            visual = visuals[kind]
            artifact_ids = tuple(
                cast(str, receipt.get("artifact_id")) for receipt in selected_receipts
            )
            canonical_pixels = tuple(
                cast(str, receipt.get("canonical_pixel_sha256")) for receipt in selected_receipts
            )
            filename = cast(str, visual.get("filename"))
            if (
                artifact_ids != expected_ids[kind]
                or tuple(visual["source_artifact_ids"]) != artifact_ids
                or tuple(visual["source_canonical_pixel_sha256"]) != canonical_pixels
                or filename not in assets
            ):
                raise ReferencePreviewRefreshError("reference-preview-pixel-lineage-changed")
            visual["source_receipt_sha256"] = [
                receipt["receipt_sha256"] for receipt in selected_receipts
            ]
            visual["source_output_sha256"] = [
                receipt["output_sha256"] for receipt in selected_receipts
            ]
            visual["source_canonical_pixel_sha256"] = list(canonical_pixels)
            visual["sha256"] = _content_digest(assets[filename])
        expected = receipts[(scenario_id, "expected")]
        recovered = receipts[(scenario_id, "recovered")]
        if expected.get("canonical_pixel_sha256") != recovered.get("canonical_pixel_sha256"):
            raise ReferencePreviewRefreshError("reference-preview-recovery-output-mismatch")
        for mode in _MODES:
            receipt = receipts[(scenario_id, mode)]
            receipt_id = receipt.get("receipt_sha256")
            if not isinstance(receipt_id, str) or receipt_id in receipt_index:
                raise ReferencePreviewRefreshError("reference-preview-receipt-invalid")
            receipt_index[receipt_id] = receipt
    document["worker_receipts"] = receipt_index
    document.pop("manifest_sha256", None)
    document["manifest_sha256"] = (
        f"sha256:{hashlib.sha256(canonical_json_bytes(document)).hexdigest()}"
    )
    return document


def _snapshot_asset_set(asset_root: Path) -> _AssetSetSnapshot:
    try:
        resolved = asset_root.resolve(strict=True)
        root_before = asset_root.lstat()
        children = sorted(asset_root.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe") from error
    if (
        resolved != asset_root.absolute()
        or asset_root.is_symlink()
        or not stat.S_ISDIR(root_before.st_mode)
    ):
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe")
    entries: list[_FileSnapshot] = []
    for path in children:
        try:
            before = path.lstat()
            content = path.read_bytes()
            after = path.lstat()
        except OSError as error:
            raise ReferencePreviewRefreshError("reference-preview-assets-unsafe") from error
        if (
            path.is_symlink()
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        ):
            raise ReferencePreviewRefreshError("reference-preview-assets-unsafe")
        entries.append(
            _FileSnapshot(
                name=path.name,
                device=before.st_dev,
                inode=before.st_ino,
                mode=before.st_mode,
                links=before.st_nlink,
                size=before.st_size,
                modified_ns=before.st_mtime_ns,
                changed_ns=before.st_ctime_ns,
                sha256=_content_digest(content),
            )
        )
    try:
        root_after = asset_root.lstat()
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe") from error
    if (
        root_before.st_dev,
        root_before.st_ino,
        root_before.st_mode,
        root_before.st_mtime_ns,
        root_before.st_ctime_ns,
    ) != (
        root_after.st_dev,
        root_after.st_ino,
        root_after.st_mode,
        root_after.st_mtime_ns,
        root_after.st_ctime_ns,
    ):
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe")
    return _AssetSetSnapshot(
        device=root_before.st_dev,
        inode=root_before.st_ino,
        mode=root_before.st_mode,
        entries=tuple(entries),
    )


def _write_file(path: Path, content: bytes, mode: int) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, mode, follow_symlinks=False)
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-stage-write-failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        os.fsync(descriptor)
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-stage-write-failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _stage_candidate(
    *,
    stage_root: Path,
    snapshot: _AssetSetSnapshot,
    manifest: bytes,
    assets: Mapping[str, bytes],
) -> None:
    expected_names = frozenset({"manifest.json", *assets})
    if snapshot.names != expected_names:
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe")
    try:
        os.chmod(stage_root, stat.S_IMODE(snapshot.mode))
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-stage-write-failed") from error
    for filename in sorted(assets):
        _write_file(stage_root / filename, assets[filename], snapshot.file_mode(filename))
    _write_file(
        stage_root / "manifest.json",
        manifest,
        snapshot.file_mode("manifest.json"),
    )
    _fsync_directory(stage_root)


def _atomic_exchange(left: Path, right: Path) -> None:
    if left.parent != right.parent:
        raise ReferencePreviewRefreshError("reference-preview-atomic-exchange-unavailable")
    library = ctypes.CDLL(None, use_errno=True)
    exchange: Any = getattr(library, "renameat2", None)
    if exchange is None:
        raise ReferencePreviewRefreshError("reference-preview-atomic-exchange-unavailable")
    exchange.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    exchange.restype = ctypes.c_int
    result = exchange(
        _AT_FDCWD,
        os.fsencode(left),
        _AT_FDCWD,
        os.fsencode(right),
        _RENAME_EXCHANGE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise ReferencePreviewRefreshError(
            "reference-preview-atomic-exchange-unavailable"
        ) from OSError(error_number, os.strerror(error_number))
    _fsync_directory(left.parent)


def _install_candidate(
    *,
    asset_root: Path,
    stage_root: Path,
    original: _AssetSetSnapshot,
    expected_reference_manifest_sha256: str,
) -> ReferencePreviewCatalog:
    if _snapshot_asset_set(asset_root) != original:
        raise ReferencePreviewRefreshError("reference-preview-assets-concurrent-change")
    _atomic_exchange(asset_root, stage_root)
    try:
        return load_reference_preview_catalog(
            expected_reference_manifest_sha256=expected_reference_manifest_sha256,
            manifest_path=asset_root / "manifest.json",
            asset_root=asset_root,
        )
    except Exception as install_error:
        try:
            _atomic_exchange(asset_root, stage_root)
            if _snapshot_asset_set(asset_root) != original:
                raise ReferencePreviewRefreshError("reference-preview-rollback-failed")
        except Exception as rollback_error:
            if isinstance(rollback_error, ReferencePreviewRefreshError) and (
                rollback_error.code == "reference-preview-rollback-failed"
            ):
                raise
            raise ReferencePreviewRefreshError(
                "reference-preview-rollback-failed"
            ) from rollback_error
        raise ReferencePreviewRefreshError(
            "reference-preview-install-validation-failed"
        ) from install_error


def _load_template(manifest_path: Path) -> tuple[bytes, Mapping[str, Any]]:
    try:
        original = manifest_path.read_bytes()
        template = json.loads(original.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReferencePreviewRefreshError("reference-preview-manifest-invalid") from error
    if not isinstance(template, Mapping):
        raise ReferencePreviewRefreshError("reference-preview-manifest-invalid")
    return original, template


def refresh_reference_previews(
    *,
    source_root: Path,
    manifest_path: Path = REFERENCE_PREVIEW_MANIFEST_PATH,
    asset_root: Path = REFERENCE_PREVIEW_ROOT,
    write: bool = False,
    renderer: ReferenceRenderer = execute_reference_render_job,
    asset_builder: PreviewAssetBuilder = _build_preview_assets,
) -> dict[str, Any]:
    if manifest_path.absolute() != (asset_root / "manifest.json").absolute():
        raise ReferencePreviewRefreshError("reference-preview-asset-layout-invalid")
    reference_manifest = load_reference_media_manifest()
    current_catalog = load_reference_preview_catalog(
        expected_reference_manifest_sha256=reference_manifest.manifest_sha256,
        manifest_path=manifest_path,
        asset_root=asset_root,
    )
    original_manifest, template = _load_template(manifest_path)
    filenames = _preview_filenames(template)
    original_snapshot = _snapshot_asset_set(asset_root)
    if original_snapshot.names != frozenset({"manifest.json", *filenames.values()}):
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe")

    with tempfile.TemporaryDirectory(
        prefix="colortrace-reference-previews-build-",
        ignore_cleanup_errors=True,
    ) as directory:
        work_root = Path(directory)
        receipts = _render_jobs(
            source_root=source_root,
            work_root=work_root,
            renderer=renderer,
        )
        assets = dict(
            asset_builder(
                template=template,
                receipts=receipts,
                output_root=work_root / "output",
                work_root=work_root,
            )
        )
        if set(assets) != set(filenames.values()):
            raise ReferencePreviewRefreshError("reference-preview-generation-failed")
        document = _rebind_manifest(template, receipts, assets)
        encoded_manifest = canonical_json_bytes(document) + b"\n"

    try:
        stage_parent = asset_root.parent.resolve(strict=True)
    except OSError as error:
        raise ReferencePreviewRefreshError("reference-preview-assets-unsafe") from error
    with tempfile.TemporaryDirectory(
        prefix=f".{asset_root.name}.candidate-",
        dir=stage_parent,
        ignore_cleanup_errors=True,
    ) as directory:
        stage_root = Path(directory)
        _stage_candidate(
            stage_root=stage_root,
            snapshot=original_snapshot,
            manifest=encoded_manifest,
            assets=assets,
        )
        candidate_catalog = load_reference_preview_catalog(
            expected_reference_manifest_sha256=reference_manifest.manifest_sha256,
            manifest_path=stage_root / "manifest.json",
            asset_root=stage_root,
        )
        if _snapshot_asset_set(asset_root) != original_snapshot:
            raise ReferencePreviewRefreshError("reference-preview-assets-concurrent-change")
        changed_assets = sorted(
            filename
            for filename, content in assets.items()
            if (asset_root / filename).read_bytes() != content
        )
        if not write:
            if changed_assets:
                raise ReferencePreviewRefreshError("reference-preview-assets-stale")
            verified_catalog = load_reference_preview_catalog(
                expected_reference_manifest_sha256=reference_manifest.manifest_sha256,
                manifest_path=manifest_path,
                asset_root=asset_root,
            )
            if _snapshot_asset_set(asset_root) != original_snapshot:
                raise ReferencePreviewRefreshError("reference-preview-assets-concurrent-change")
            installed = False
        else:
            verified_catalog = _install_candidate(
                asset_root=asset_root,
                stage_root=stage_root,
                original=original_snapshot,
                expected_reference_manifest_sha256=reference_manifest.manifest_sha256,
            )
            installed = True

    result_catalog = verified_catalog if write else current_catalog
    return {
        "schema": "reference-preview-generation/v1",
        "mode": "write" if write else "check",
        "asset_set_installed": installed,
        "reference_manifest_sha256": result_catalog.reference_manifest_sha256,
        "preview_manifest_sha256": result_catalog.manifest_sha256,
        "candidate_preview_manifest_sha256": candidate_catalog.manifest_sha256,
        "scenario_count": len(result_catalog.scenarios),
        "worker_receipt_count": len(document["worker_receipts"]),
        "png_asset_count": len(assets),
        "png_content_changed": bool(changed_assets),
        "manifest_content_changed": encoded_manifest != original_manifest,
    }


def refresh_reference_preview_manifest(
    *,
    source_root: Path,
    manifest_path: Path = REFERENCE_PREVIEW_MANIFEST_PATH,
    asset_root: Path = REFERENCE_PREVIEW_ROOT,
    write: bool = False,
    renderer: ReferenceRenderer = execute_reference_render_job,
    asset_builder: PreviewAssetBuilder = _build_preview_assets,
) -> dict[str, Any]:
    return refresh_reference_previews(
        source_root=source_root,
        manifest_path=manifest_path,
        asset_root=asset_root,
        write=write,
        renderer=renderer,
        asset_builder=asset_builder,
    )


def main() -> None:
    parser = ArgumentParser(prog="colortrace-reference-previews")
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=REFERENCE_PREVIEW_MANIFEST_PATH,
    )
    parser.add_argument("--asset-root", type=Path, default=REFERENCE_PREVIEW_ROOT)
    parser.add_argument(
        "--write",
        action="store_true",
        help="atomically install the regenerated PNGs and receipt-bound manifest",
    )
    arguments = parser.parse_args()
    try:
        result = refresh_reference_previews(
            source_root=arguments.source_root,
            manifest_path=arguments.manifest_path,
            asset_root=arguments.asset_root,
            write=arguments.write,
        )
    except Exception as error:
        code = (
            error.code
            if isinstance(error, ReferencePreviewRefreshError)
            else "reference-preview-refresh-failed"
        )
        print(code, file=sys.stderr)
        raise SystemExit(2) from error
    print(canonical_json_bytes(result).decode("utf-8"))


__all__ = [
    "ReferencePreviewRefreshError",
    "refresh_reference_preview_manifest",
    "refresh_reference_previews",
]


if __name__ == "__main__":
    main()
