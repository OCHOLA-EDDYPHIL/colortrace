from __future__ import annotations

import hashlib
import io
from pathlib import Path
from urllib.request import Request

import pytest
from colortrace_fixture.reference_media import (
    ReferenceFrame,
    ReferenceMediaError,
    ReferenceMediaManifest,
    ReferenceSequence,
    fetch_reference_media,
    load_reference_media_manifest,
    reference_manifest_identity,
    verify_reference_media,
)


def _record_digest(sequence_id: str, frames: tuple[bytes, ...]) -> str:
    records = []
    for index, value in enumerate(frames):
        filename = f"{sequence_id}_{index:05d}.exr"
        digest = hashlib.sha256(value).hexdigest()
        records.append(f"{filename}\t{len(value)}\t{digest}\n".encode("ascii"))
    return f"sha256:{hashlib.sha256(b''.join(records)).hexdigest()}"


def _manifest(
    frames: dict[str, tuple[bytes, ...]],
    *,
    source_notice: bytes = b"Tears of Steel test attribution notice\n",
) -> ReferenceMediaManifest:
    sequences = tuple(
        ReferenceSequence(
            sequence_id=sequence_id,
            base_url=f"https://media.xiph.org/tearsofsteel/linear-exr/{sequence_id}/",
            first_frame=0,
            last_frame=len(values) - 1,
            frame_count=len(values),
            total_bytes=sum(len(value) for value in values),
            record_set_sha256=_record_digest(sequence_id, values),
            frames=tuple(
                ReferenceFrame(
                    sequence_id=sequence_id,
                    frame=index,
                    filename=f"{sequence_id}_{index:05d}.exr",
                    url=(
                        "https://media.xiph.org/tearsofsteel/linear-exr/"
                        f"{sequence_id}/{sequence_id}_{index:05d}.exr"
                    ),
                    byte_length=len(value),
                    sha256=f"sha256:{hashlib.sha256(value).hexdigest()}",
                )
                for index, value in enumerate(values)
            ),
        )
        for sequence_id, values in frames.items()
    )
    return ReferenceMediaManifest(
        collection_id="test-reference-set",
        title="Test reference set",
        attribution="Test fixture",
        license_spdx="CC-BY-3.0",
        license_url="https://creativecommons.org/licenses/by/3.0/",
        source_notice_url="https://media.xiph.org/tearsofsteel/linear-exr/README.txt",
        source_notice_sha256=f"sha256:{hashlib.sha256(source_notice).hexdigest()}",
        sequences=sequences,
        manifest_sha256=f"sha256:{'1' * 64}",
    )


def test_shipped_reference_manifest_pins_two_open_film_sequences() -> None:
    manifest = load_reference_media_manifest()
    assert manifest.collection_id == "tears-of-steel-linear-exr-240-v1"
    assert manifest.license_spdx == "CC-BY-3.0"
    assert manifest.frame_count == 240
    assert [sequence.sequence_id for sequence in manifest.sequences] == ["03_2a", "04_5f"]
    assert all(sequence.frame_count == 120 for sequence in manifest.sequences)
    assert all(sequence.record_set_sha256.startswith("sha256:") for sequence in manifest.sequences)
    identity = reference_manifest_identity(manifest)
    assert identity["frame_count"] == 240
    assert identity["total_bytes"] == 12_748_595_280


def test_fetch_and_verify_reference_media_are_content_bound(tmp_path: Path) -> None:
    frames = {"03_2a": (b"first", b"second"), "04_5f": (b"third", b"fourth")}
    source_notice = b"Tears of Steel test attribution notice\n"
    manifest = _manifest(frames, source_notice=source_notice)
    content = {
        (
            "https://media.xiph.org/tearsofsteel/linear-exr/"
            f"{sequence_id}/{sequence_id}_{index:05d}.exr"
        ): value
        for sequence_id, values in frames.items()
        for index, value in enumerate(values)
    }
    content[manifest.source_notice_url] = source_notice

    def open_fixture(request: Request) -> io.BytesIO:
        return io.BytesIO(content[request.full_url])

    receipt = fetch_reference_media(tmp_path / "reference-cache", manifest, opener=open_fixture)
    assert receipt.frame_count == 4
    assert receipt.license_spdx == "CC-BY-3.0"
    assert receipt.source_notice_sha256 == manifest.source_notice_sha256
    assert receipt.total_bytes == sum(len(item) for values in frames.values() for item in values)
    assert receipt.sequence_record_set_sha256 == {
        sequence.sequence_id: sequence.record_set_sha256 for sequence in manifest.sequences
    }
    assert verify_reference_media(tmp_path / "reference-cache", manifest) == receipt


def test_fetch_rejects_changed_source_notice_before_media_download(tmp_path: Path) -> None:
    frames = {"03_2a": (b"first",), "04_5f": (b"second",)}
    manifest = _manifest(frames)

    def open_changed_notice(_request: Request) -> io.BytesIO:
        return io.BytesIO(b"changed notice")

    with pytest.raises(ReferenceMediaError, match="reference-source-notice-digest-mismatch"):
        fetch_reference_media(tmp_path / "reference-cache", manifest, opener=open_changed_notice)


def test_fetch_rejects_oversized_frame_without_retaining_partial_data(tmp_path: Path) -> None:
    source_notice = b"Tears of Steel test attribution notice\n"
    frames = {"03_2a": (b"first",), "04_5f": (b"second",)}
    manifest = _manifest(frames, source_notice=source_notice)

    def open_oversized(request: Request) -> io.BytesIO:
        if request.full_url == manifest.source_notice_url:
            return io.BytesIO(source_notice)
        return io.BytesIO(frames["03_2a"][0] + b"unexpected")

    root = tmp_path / "reference-cache"
    with pytest.raises(ReferenceMediaError, match="reference-frame-digest-mismatch"):
        fetch_reference_media(root, manifest, opener=open_oversized)

    assert not list(root.rglob("*.exr"))


def test_reference_media_rejects_symlinked_cache_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    cache = tmp_path / "reference-cache"
    cache.symlink_to(target, target_is_directory=True)

    with pytest.raises(ReferenceMediaError, match="reference-cache-unsafe"):
        verify_reference_media(
            cache,
            _manifest({"03_2a": (b"first",), "04_5f": (b"second",)}),
        )


def test_reference_media_verification_rejects_changed_frame(tmp_path: Path) -> None:
    frames = {"03_2a": (b"first",), "04_5f": (b"second",)}
    manifest = _manifest(frames)
    root = tmp_path / "reference-cache"
    for sequence_id, values in frames.items():
        sequence_root = root / sequence_id
        sequence_root.mkdir(parents=True)
        (sequence_root / f"{sequence_id}_00000.exr").write_bytes(values[0])
    (root / "04_5f" / "04_5f_00000.exr").write_bytes(b"changed")
    with pytest.raises(ReferenceMediaError, match="reference-frame-digest-mismatch"):
        verify_reference_media(root, manifest)


def test_reference_media_verification_rejects_symlink(tmp_path: Path) -> None:
    frames = {"03_2a": (b"first",), "04_5f": (b"second",)}
    manifest = _manifest(frames)
    root = tmp_path / "reference-cache"
    outside = tmp_path / "outside.exr"
    outside.write_bytes(b"first")
    (root / "03_2a").mkdir(parents=True)
    (root / "03_2a" / "03_2a_00000.exr").symlink_to(outside)
    (root / "04_5f").mkdir()
    (root / "04_5f" / "04_5f_00000.exr").write_bytes(b"second")
    with pytest.raises(ReferenceMediaError, match="reference-frame-unsafe"):
        verify_reference_media(root, manifest)


def test_reference_media_verification_rejects_symlinked_sequence_directory(
    tmp_path: Path,
) -> None:
    frames = {"03_2a": (b"first",), "04_5f": (b"second",)}
    manifest = _manifest(frames)
    root = tmp_path / "reference-cache"
    root.mkdir()
    outside = tmp_path / "outside-sequence"
    outside.mkdir()
    (outside / "03_2a_00000.exr").write_bytes(b"first")
    (root / "03_2a").symlink_to(outside, target_is_directory=True)
    (root / "04_5f").mkdir()
    (root / "04_5f" / "04_5f_00000.exr").write_bytes(b"second")

    with pytest.raises(ReferenceMediaError, match="reference-frame-unsafe"):
        verify_reference_media(root, manifest)
