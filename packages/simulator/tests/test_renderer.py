from __future__ import annotations

import binascii
import os
import struct
import zlib
from pathlib import Path

import pytest
from colortrace_fixture.fixture import (  # type: ignore[import-untyped]
    CHANNELS,
    HEIGHT,
    WIDTH,
    chart_samples,
    lut_bytes,
    png16_bytes,
    prepare_worker,
)
from colortrace_simulator.renderer import (
    RendererError,
    VerifiedPrivateConfigRoot,
    decode_generated_source_png,
)


def _chunk(kind: bytes, payload: bytes, *, crc_offset: int = 0) -> bytes:
    crc = (binascii.crc32(kind + payload) + crc_offset) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def _png(compressed: bytes, *, corrupt_idat_crc: bool = False) -> bytes:
    header = struct.pack(">IIBBBBB", WIDTH, HEIGHT, 16, 2, 0, 0, 0)
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _chunk(b"IHDR", header),
            _chunk(b"IDAT", compressed, crc_offset=1 if corrupt_idat_crc else 0),
            _chunk(b"IEND", b""),
        )
    )


def _raw_rows() -> bytes:
    stride = WIDTH * CHANNELS * 2
    return b"".join(b"\x00" + bytes(stride) for _ in range(HEIGHT))


def test_strict_decoder_accepts_only_canonical_generated_png() -> None:
    samples = chart_samples("chart-01")
    decoded = decode_generated_source_png(png16_bytes(samples))
    assert list(decoded) == list(samples)


def test_strict_decoder_rejects_crc_corruption() -> None:
    with pytest.raises(RendererError, match="source-png-crc-invalid"):
        decode_generated_source_png(_png(zlib.compress(_raw_rows()), corrupt_idat_crc=True))


@pytest.mark.parametrize(
    "compressed",
    [
        zlib.compress(_raw_rows() + b"\x00"),
        zlib.compress(_raw_rows()) + zlib.compress(b"trailing-stream"),
    ],
)
def test_strict_decoder_bounds_decompression_and_rejects_trailing_streams(
    compressed: bytes,
) -> None:
    with pytest.raises(RendererError, match="source-png-size-invalid"):
        decode_generated_source_png(_png(compressed))


def test_strict_decoder_rejects_oversized_compressed_input_before_inflation() -> None:
    expected_size = HEIGHT * (WIDTH * CHANNELS * 2 + 1)
    maximum = expected_size + expected_size // 1000 + 64
    with pytest.raises(RendererError, match="source-png-compressed-size-invalid"):
        decode_generated_source_png(_png(b"x" * (maximum + 1)))


@pytest.mark.parametrize("link_kind", ["config", "lut"])
def test_private_config_verification_rejects_symlink_substitution(
    tmp_path: Path,
    link_kind: str,
) -> None:
    worker = prepare_worker(tmp_path / "runtime", "A", lut_bytes("approved"))
    config_root = worker.config_path.parent
    config_root.chmod(0o700)
    worker.lut_path.parent.chmod(0o700)
    target = worker.config_path if link_kind == "config" else worker.lut_path
    real = target.with_name(f"{target.name}.real")
    target.rename(real)
    os.symlink(real.name, target)

    with pytest.raises(RendererError):
        VerifiedPrivateConfigRoot.verify(
            root=config_root,
            config_path=worker.config_path,
            lut_path=worker.lut_path,
            expected_config_sha256=f"sha256:{worker.config_sha256}",
            expected_resource_sha256=f"sha256:{worker.lut_sha256}",
        )
