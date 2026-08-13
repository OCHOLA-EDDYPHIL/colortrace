from __future__ import annotations

import binascii
import hashlib
import os
import stat
import struct
import sys
import zlib
from array import array
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import PyOpenColorIO as ocio  # type: ignore[import-untyped]
from colortrace_fixture.fixture import (  # type: ignore[import-untyped]
    CHANNELS,
    HEIGHT,
    OCIO_VERSION,
    WIDTH,
    apply_ocio,
    canonical_float_bytes,
    display_samples,
    png16_bytes,
    source_pixel_bytes,
    stable_processor_identity,
)


class RendererError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            break
        digest.update(block)
        offset += len(block)
    return f"sha256:{digest.hexdigest()}"


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_regular_at(root_fd: int, relative: Path, root_metadata: os.stat_result) -> int:
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise RendererError("render-input-path-invalid")
    directory_fd = os.dup(root_fd)
    try:
        for part in relative.parts[:-1]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
            metadata = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_dev != root_metadata.st_dev
                or metadata.st_uid != root_metadata.st_uid
            ):
                raise RendererError("render-input-boundary-invalid")
        file_fd = os.open(
            relative.parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
    except OSError as error:
        raise RendererError("render-input-unavailable") from error
    finally:
        os.close(directory_fd)
    metadata = os.fstat(file_fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_dev != root_metadata.st_dev
        or metadata.st_uid != root_metadata.st_uid
    ):
        os.close(file_fd)
        raise RendererError("render-input-not-private-regular-file")
    return file_fd


@dataclass(frozen=True, slots=True)
class _OpenedConfigInputs:
    root: Path
    config_path: Path
    lut_path: Path
    root_fd: int
    config_fd: int
    lut_fd: int
    config_identity: tuple[int, int, int, int, int]
    lut_identity: tuple[int, int, int, int, int]


@contextmanager
def _open_config_inputs(
    root: Path,
    config_path: Path,
    lut_path: Path,
) -> Iterator[_OpenedConfigInputs]:
    private_root = Path(os.path.abspath(root))
    config = Path(os.path.abspath(config_path))
    lut = Path(os.path.abspath(lut_path))
    try:
        if stat.S_ISLNK(private_root.lstat().st_mode):
            raise RendererError("render-config-root-link-prohibited")
        config_relative = config.relative_to(private_root)
        lut_relative = lut.relative_to(private_root)
        root_fd = os.open(
            private_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except (OSError, ValueError) as error:
        raise RendererError("render-config-root-invalid") from error
    root_metadata = os.fstat(root_fd)
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_mode & 0o077
        or root_metadata.st_uid != os.getuid()
    ):
        os.close(root_fd)
        raise RendererError("render-config-root-not-private")
    config_fd = -1
    lut_fd = -1
    try:
        config_fd = _open_regular_at(root_fd, config_relative, root_metadata)
        lut_fd = _open_regular_at(root_fd, lut_relative, root_metadata)
        opened = _OpenedConfigInputs(
            root=private_root,
            config_path=config,
            lut_path=lut,
            root_fd=root_fd,
            config_fd=config_fd,
            lut_fd=lut_fd,
            config_identity=_identity(os.fstat(config_fd)),
            lut_identity=_identity(os.fstat(lut_fd)),
        )
        yield opened
    finally:
        if config_fd >= 0:
            os.close(config_fd)
        if lut_fd >= 0:
            os.close(lut_fd)
        os.close(root_fd)


@dataclass(frozen=True, slots=True)
class VerifiedPrivateConfigRoot:
    root: Path
    config_path: Path
    lut_path: Path
    config_sha256: str
    resource_sha256: str

    @classmethod
    def verify(
        cls,
        *,
        root: Path,
        config_path: Path,
        lut_path: Path,
        expected_config_sha256: str,
        expected_resource_sha256: str,
    ) -> VerifiedPrivateConfigRoot:
        with _open_config_inputs(root, config_path, lut_path) as opened:
            if _sha256_fd(opened.config_fd) != expected_config_sha256:
                raise RendererError("render-config-digest-mismatch")
            if _sha256_fd(opened.lut_fd) != expected_resource_sha256:
                raise RendererError("render-resource-digest-mismatch")
            if ocio.__version__ != OCIO_VERSION:
                raise RendererError("render-ocio-version-mismatch")

            ocio.ClearAllCaches()
            try:
                configuration = ocio.Config.CreateFromFile(str(opened.config_path))
                configuration.validate()
                resolved = Path(
                    os.path.abspath(
                        configuration.getCurrentContext().resolveFileLocation("show_look.cube")
                    )
                )
                resolved_relative = resolved.relative_to(opened.root)
                resolved_fd = _open_regular_at(
                    opened.root_fd,
                    resolved_relative,
                    os.fstat(opened.root_fd),
                )
            except Exception as error:
                raise RendererError("render-ocio-config-invalid") from error
            try:
                if (
                    resolved != opened.lut_path
                    or _identity(os.fstat(resolved_fd))[:2] != opened.lut_identity[:2]
                ):
                    raise RendererError("render-resource-resolution-mismatch")
            finally:
                os.close(resolved_fd)
            if _identity(os.fstat(opened.config_fd)) != opened.config_identity:
                raise RendererError("render-config-changed-during-verification")
            if _identity(os.fstat(opened.lut_fd)) != opened.lut_identity:
                raise RendererError("render-resource-changed-during-verification")
        return cls(
            root=Path(os.path.abspath(root)),
            config_path=Path(os.path.abspath(config_path)),
            lut_path=Path(os.path.abspath(lut_path)),
            config_sha256=expected_config_sha256,
            resource_sha256=expected_resource_sha256,
        )


@dataclass(frozen=True, slots=True)
class FrameRenderRequest:
    frame_id: str
    job_id: str
    source_id: str
    source_png: bytes
    source_png_sha256: str
    canonical_pixel_sha256: str
    transform_id: str
    trace_id: str


@dataclass(frozen=True, slots=True)
class RenderedFrame:
    frame_id: str
    job_id: str
    trace_id: str
    output_buffer: bytes
    output_sha256: str
    display_png: bytes
    display_sha256: str
    processor_identity_sha256: str


def decode_generated_source_png(value: bytes) -> array[int]:
    if not value.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RendererError("source-png-signature-invalid")
    offset = 8
    seen_ihdr = False
    seen_iend = False
    compressed = bytearray()
    stride = WIDTH * CHANNELS * 2
    expected_size = HEIGHT * (stride + 1)
    maximum_compressed_size = expected_size + expected_size // 1000 + 64
    while offset < len(value):
        if len(value) - offset < 12:
            raise RendererError("source-png-truncated")
        length = struct.unpack(">I", value[offset : offset + 4])[0]
        kind = value[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(value):
            raise RendererError("source-png-truncated")
        payload = value[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", value[offset + 8 + length : end])[0]
        if binascii.crc32(kind + payload) & 0xFFFFFFFF != expected_crc:
            raise RendererError("source-png-crc-invalid")
        if kind == b"IHDR":
            if (
                seen_ihdr
                or offset != 8
                or payload != struct.pack(">IIBBBBB", WIDTH, HEIGHT, 16, 2, 0, 0, 0)
            ):
                raise RendererError("source-png-header-invalid")
            seen_ihdr = True
        elif kind == b"IDAT":
            if not seen_ihdr or seen_iend:
                raise RendererError("source-png-chunk-order-invalid")
            if len(compressed) + len(payload) > maximum_compressed_size:
                raise RendererError("source-png-compressed-size-invalid")
            compressed.extend(payload)
        elif kind == b"IEND":
            if payload or not seen_ihdr or seen_iend or end != len(value):
                raise RendererError("source-png-end-invalid")
            seen_iend = True
        else:
            raise RendererError("source-png-chunk-prohibited")
        offset = end
    if not seen_ihdr or not seen_iend or not compressed:
        raise RendererError("source-png-structure-invalid")
    try:
        decompressor = zlib.decompressobj()
        rows = decompressor.decompress(bytes(compressed), expected_size + 1)
    except zlib.error as error:
        raise RendererError("source-png-compression-invalid") from error
    if (
        len(rows) != expected_size
        or decompressor.unconsumed_tail
        or decompressor.unused_data
        or not decompressor.eof
    ):
        raise RendererError("source-png-size-invalid")
    samples = array("H")
    for row_index in range(HEIGHT):
        start = row_index * (stride + 1)
        if rows[start] != 0:
            raise RendererError("source-png-filter-prohibited")
        row = array("H")
        row.frombytes(rows[start + 1 : start + 1 + stride])
        if sys.byteorder == "little":
            row.byteswap()
        samples.extend(row)
    if len(samples) != WIDTH * HEIGHT * CHANNELS:
        raise RendererError("source-png-samples-invalid")
    return samples


class OcioRenderer:
    def render_frame(
        self,
        config: VerifiedPrivateConfigRoot,
        request: FrameRenderRequest,
    ) -> RenderedFrame:
        if request.transform_id != "look/main/v1":
            raise RendererError("render-transform-prohibited")
        if sha256_bytes(request.source_png) != request.source_png_sha256:
            raise RendererError("source-png-digest-mismatch")
        if len(request.trace_id) != 32 or any(
            character not in "0123456789abcdef" for character in request.trace_id
        ):
            raise RendererError("render-trace-id-invalid")
        samples = decode_generated_source_png(request.source_png)
        if (
            f"sha256:{hashlib.sha256(source_pixel_bytes(samples)).hexdigest()}"
            != request.canonical_pixel_sha256
        ):
            raise RendererError("source-pixel-digest-mismatch")
        source = array("f", (sample / 65535.0 for sample in samples))
        with _open_config_inputs(config.root, config.config_path, config.lut_path) as opened:
            if _sha256_fd(opened.config_fd) != config.config_sha256:
                raise RendererError("render-config-digest-mismatch")
            if _sha256_fd(opened.lut_fd) != config.resource_sha256:
                raise RendererError("render-resource-digest-mismatch")
            try:
                rendered, _cache_ids = apply_ocio(
                    opened.config_path,
                    request.transform_id,
                    source,
                )
            except Exception as error:
                raise RendererError("ocio-render-failed") from error
            if _identity(os.fstat(opened.config_fd)) != opened.config_identity:
                raise RendererError("render-config-changed")
            if _identity(os.fstat(opened.lut_fd)) != opened.lut_identity:
                raise RendererError("render-resource-changed")
        output = canonical_float_bytes(rendered)
        display = png16_bytes(display_samples(rendered))
        processor_identity = stable_processor_identity(
            config.config_sha256.removeprefix("sha256:"),
            request.transform_id,
            config.resource_sha256.removeprefix("sha256:"),
        )
        return RenderedFrame(
            frame_id=request.frame_id,
            job_id=request.job_id,
            trace_id=request.trace_id,
            output_buffer=output,
            output_sha256=sha256_bytes(output),
            display_png=display,
            display_sha256=sha256_bytes(display),
            processor_identity_sha256=f"sha256:{processor_identity}",
        )


__all__ = [
    "FrameRenderRequest",
    "OcioRenderer",
    "RenderedFrame",
    "RendererError",
    "VerifiedPrivateConfigRoot",
    "decode_generated_source_png",
    "sha256_bytes",
]
