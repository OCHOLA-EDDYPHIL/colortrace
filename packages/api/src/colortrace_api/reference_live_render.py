from __future__ import annotations

import hashlib
import json
import re
import stat
import struct
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast

from colortrace_fixture import (
    load_reference_media_manifest,
    materialize_reference_color_variants,
    reference_render_job,
    reference_scenarios,
)

from .reference_visuals import ReferencePreviewCatalog, load_reference_preview_catalog

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_PREVIEW_WIDTH = 960
_PREVIEW_HEIGHT = 506
_MAX_PREVIEW_BYTES = 5 * 1024 * 1024
_SOURCE_ARTIFACTS: Mapping[str, str] = {
    "tos-resource-resolution-drift-v1": "frame:03_2a:00000",
    "tos-config-rollout-drift-v1": "frame:03_2a:00000",
    "tos-stale-derivative-cache-v1": "frame:03_2a:00003",
}


class ReferenceLiveRenderError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ReferenceLiveRenderResult:
    document: Mapping[str, Any]
    png: bytes


class ReferenceLiveRenderer(Protocol):
    def render(
        self,
        *,
        scenario_id: str,
        request_id: str,
        action_intent: Mapping[str, Any],
        approval: Mapping[str, Any],
    ) -> ReferenceLiveRenderResult: ...


ReferenceWorker = Callable[..., dict[str, Any]]
ReferencePreviewEncoder = Callable[..., bytes]


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise ReferenceLiveRenderError("reference-live-render-output-invalid") from error
    return f"sha256:{digest.hexdigest()}"


def _safe_output_path(output_root: Path, receipt: Mapping[str, Any]) -> Path:
    relative_value = receipt.get("output_relative_path")
    if not isinstance(relative_value, str):
        raise ReferenceLiveRenderError("reference-live-render-output-invalid")
    relative = Path(relative_value)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise ReferenceLiveRenderError("reference-live-render-output-invalid")
    try:
        root = output_root.resolve(strict=True)
        candidate = output_root / relative
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        metadata = resolved.lstat()
    except (OSError, ValueError) as error:
        raise ReferenceLiveRenderError("reference-live-render-output-invalid") from error
    if (
        candidate.absolute() != resolved
        or candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != receipt.get("bytes_written")
        or _sha256_file(resolved) != receipt.get("output_sha256")
    ):
        raise ReferenceLiveRenderError("reference-live-render-output-invalid")
    return resolved


def encode_reference_live_preview(
    *,
    output_root: Path,
    receipt: Mapping[str, Any],
) -> bytes:
    try:
        import OpenImageIO as oiio
    except ImportError as error:
        raise ReferenceLiveRenderError("reference-live-render-dependency-unavailable") from error
    path = _safe_output_path(output_root, receipt)
    image: Any = None
    display: Any = None
    resized: Any = None
    clamped: Any = None
    encoded: Any = None
    try:
        image = oiio.ImageBuf(str(path))
        spec = image.spec()
        if (
            not image.initialized
            or image.has_error
            or spec.width != receipt.get("width")
            or spec.height != receipt.get("height")
            or spec.nchannels != receipt.get("channels")
            or spec.nchannels != 3
        ):
            raise ReferenceLiveRenderError("reference-live-render-output-invalid")
        display = oiio.ImageBufAlgo.colorconvert(
            image,
            "linear",
            "sRGB",
            unpremult=True,
            nthreads=1,
        )
        roi = oiio.ROI(0, _PREVIEW_WIDTH, 0, _PREVIEW_HEIGHT, 0, 1, 0, 3)
        resized = oiio.ImageBufAlgo.resize(display, "lanczos3", 0.0, roi, nthreads=1)
        clamped = oiio.ImageBufAlgo.clamp(
            resized,
            (0.0, 0.0, 0.0),
            (1.0, 1.0, 1.0),
            nthreads=1,
        )
        pixels = clamped.get_pixels(oiio.FLOAT)
        if pixels is None:
            raise ReferenceLiveRenderError("reference-live-render-preview-invalid")
        clean_spec = oiio.ImageSpec(_PREVIEW_WIDTH, _PREVIEW_HEIGHT, 3, oiio.FLOAT)
        clean_spec.channelnames = ("R", "G", "B")
        clean_spec.attribute("oiio:ColorSpace", "sRGB")
        encoded = oiio.ImageBuf(clean_spec)
        if not encoded.set_pixels(roi, pixels):
            raise ReferenceLiveRenderError("reference-live-render-preview-invalid")
        encoded.set_write_format(oiio.UINT8)
        preview_path = output_root / "verified-recovery.png"
        if preview_path.exists() or not encoded.write(str(preview_path)):
            raise ReferenceLiveRenderError("reference-live-render-preview-invalid")
        content = preview_path.read_bytes()
    except ReferenceLiveRenderError:
        raise
    except Exception as error:
        raise ReferenceLiveRenderError("reference-live-render-preview-invalid") from error
    finally:
        for buffer in (image, display, resized, clamped, encoded):
            if buffer is not None:
                buffer.clear()
        try:
            oiio.ImageCache().invalidate(str(path), force=True)
        except Exception:
            pass
    if (
        not 1 <= len(content) <= _MAX_PREVIEW_BYTES
        or not content.startswith(_PNG_SIGNATURE)
        or len(content) < 24
        or content[12:16] != b"IHDR"
        or struct.unpack(">II", content[16:24]) != (_PREVIEW_WIDTH, _PREVIEW_HEIGHT)
    ):
        raise ReferenceLiveRenderError("reference-live-render-preview-invalid")
    return content


class LocalReferenceLiveRenderer:
    def __init__(
        self,
        *,
        source_root: Path,
        work_root: Path,
        source_revision: str,
        source_tree: str,
        runtime_image: str,
        previews: ReferencePreviewCatalog | None = None,
        worker: ReferenceWorker | None = None,
        preview_encoder: ReferencePreviewEncoder = encode_reference_live_preview,
    ) -> None:
        if (
            not source_root.is_absolute()
            or not work_root.is_absolute()
            or _IMAGE.fullmatch(runtime_image) is None
            or re.fullmatch(r"[0-9a-f]{40}", source_revision) is None
            or re.fullmatch(r"[0-9a-f]{40}", source_tree) is None
        ):
            raise ReferenceLiveRenderError("reference-live-render-configuration-invalid")
        try:
            source_resolved = source_root.resolve(strict=True)
            source_metadata = source_root.lstat()
            work_resolved = work_root.resolve(strict=True)
            work_metadata = work_root.lstat()
        except OSError as error:
            raise ReferenceLiveRenderError("reference-live-render-configuration-invalid") from error
        if (
            source_resolved != source_root
            or source_root.is_symlink()
            or not stat.S_ISDIR(source_metadata.st_mode)
            or source_metadata.st_mode & 0o022
            or work_resolved != work_root
            or work_root.is_symlink()
            or not stat.S_ISDIR(work_metadata.st_mode)
            or stat.S_IMODE(work_metadata.st_mode) & 0o077
        ):
            raise ReferenceLiveRenderError("reference-live-render-configuration-invalid")
        manifest = load_reference_media_manifest()
        self._frames = {
            f"frame:{frame.sequence_id}:{frame.frame:05d}": frame
            for sequence in manifest.sequences
            for frame in sequence.frames
        }
        self._scenarios = reference_scenarios(manifest)
        self._previews = previews or load_reference_preview_catalog(
            expected_reference_manifest_sha256=manifest.manifest_sha256
        )
        self._source_root = source_root
        self._work_root = work_root
        self._source_revision = source_revision
        self._source_tree = source_tree
        self._runtime_image = runtime_image
        self._worker = worker
        self._preview_encoder = preview_encoder

    def render(
        self,
        *,
        scenario_id: str,
        request_id: str,
        action_intent: Mapping[str, Any],
        approval: Mapping[str, Any],
    ) -> ReferenceLiveRenderResult:
        try:
            scenario = self._scenarios[scenario_id]
            artifact_id = _SOURCE_ARTIFACTS[scenario_id]
            frame = self._frames[artifact_id]
            expected = self._previews.visual(scenario_id, "recovered")
            approval_id = cast(str, approval["approval_id"])
            approval_sha256 = cast(str, approval["approval_sha256"])
            action_intent_id = cast(str, action_intent["action_intent_id"])
            action_intent_sha256 = cast(str, action_intent["derivation_sha256"])
        except (KeyError, TypeError) as error:
            raise ReferenceLiveRenderError("reference-live-render-binding-invalid") from error
        if any(
            _DIGEST.fullmatch(value) is None for value in (approval_sha256, action_intent_sha256)
        ):
            raise ReferenceLiveRenderError("reference-live-render-binding-invalid")
        binding = hashlib.sha256(
            f"{scenario_id}\0{request_id}\0{approval_id}\0{action_intent_id}".encode()
        ).hexdigest()
        try:
            with tempfile.TemporaryDirectory(
                prefix="render-",
                dir=self._work_root,
            ) as selected:
                root = Path(selected)
                root.chmod(0o700)
                config_root = root / "config"
                output_root = root / "output"
                variants = materialize_reference_color_variants(config_root)
                job = reference_render_job(
                    frame=frame,
                    scenario=scenario,
                    variants=variants,
                    mode="recovered",
                    trace_id=binding[:32],
                )
                job["job_id"] = f"live-{binding[:40]}"
                job["worker_id"] = "single-host-worker"
                job["output"]["relative_path"] = f"live/{binding}.exr"
                if self._worker is None:
                    from colortrace_simulator.reference_worker import (
                        ReferenceExecutionIdentity,
                        execute_reference_render_job,
                    )

                    worker = execute_reference_render_job
                else:
                    from colortrace_simulator.reference_worker import ReferenceExecutionIdentity

                    worker = self._worker
                identity = ReferenceExecutionIdentity(
                    mode="container",
                    source_revision=self._source_revision,
                    source_tree=self._source_tree,
                    container_image_digest=self._runtime_image.rsplit("@", 1)[1],
                )
                receipt = worker(
                    job,
                    source_root=self._source_root,
                    config_root=config_root,
                    output_root=output_root,
                    execution_identity=identity,
                )
                if (
                    receipt.get("schema") != "reference-render-receipt/v2"
                    or receipt.get("job_sha256") != _digest(job)
                    or receipt.get("execution_identity") != identity.to_dict()
                    or receipt.get("execution_identity_sha256") != identity.sha256
                    or receipt.get("scenario_id") != scenario_id
                    or receipt.get("artifact_id") != artifact_id
                    or receipt.get("source_sha256") != frame.sha256
                    or receipt.get("canonical_pixel_sha256")
                    != expected.source_canonical_pixel_sha256[0]
                    or receipt.get("receipt_sha256")
                    != _digest(
                        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
                    )
                ):
                    raise ReferenceLiveRenderError("reference-live-render-receipt-invalid")
                png = self._preview_encoder(output_root=output_root, receipt=receipt)
        except ReferenceLiveRenderError:
            raise
        except Exception as error:
            raise ReferenceLiveRenderError("reference-live-render-failed") from error
        body = {
            "schema": "reference-live-render/v1",
            "scenario_id": scenario_id,
            "request_id": request_id,
            "action_intent_id": action_intent_id,
            "action_intent_sha256": action_intent_sha256,
            "approval_id": approval_id,
            "approval_sha256": approval_sha256,
            "execution_target": "single-host-simulator-worker",
            "source_artifact_id": artifact_id,
            "source_sha256": frame.sha256,
            "job_sha256": receipt["job_sha256"],
            "worker_receipt_sha256": receipt["receipt_sha256"],
            "output_sha256": receipt["output_sha256"],
            "canonical_pixel_sha256": receipt["canonical_pixel_sha256"],
            "expected_canonical_pixel_sha256": expected.source_canonical_pixel_sha256[0],
            "output_equivalent": True,
            "visual_content_sha256": _content_digest(png),
            "visual_width": _PREVIEW_WIDTH,
            "visual_height": _PREVIEW_HEIGHT,
            "dependencies": dict(cast(Mapping[str, str], receipt["dependencies"])),
            "wall_nanoseconds": receipt["wall_nanoseconds"],
        }
        return ReferenceLiveRenderResult(
            document={**body, "live_render_sha256": _digest(body)},
            png=png,
        )


__all__ = [
    "LocalReferenceLiveRenderer",
    "ReferenceLiveRenderError",
    "ReferenceLiveRenderer",
    "ReferenceLiveRenderResult",
    "encode_reference_live_preview",
]
