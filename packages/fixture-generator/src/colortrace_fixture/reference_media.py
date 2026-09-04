from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, BinaryIO, Protocol, cast
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

_SOURCE_REFERENCE_MEDIA_MANIFEST = (
    Path(__file__).resolve().parents[2] / "fixtures" / "tears-of-steel-reference.json"
)
_PACKAGED_REFERENCE_MEDIA_MANIFEST = Path(__file__).parent / "reference" / "manifest.json"
REFERENCE_MEDIA_MANIFEST = (
    _SOURCE_REFERENCE_MEDIA_MANIFEST
    if _SOURCE_REFERENCE_MEDIA_MANIFEST.is_file()
    else _PACKAGED_REFERENCE_MEDIA_MANIFEST
)
REFERENCE_MEDIA_SCHEMA = (
    Path(__file__).parent / "schemas" / "open-film-reference-set-v1.schema.json"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEQUENCE = re.compile(r"^[0-9]{2}_[0-9][a-z]$")


class ReferenceMediaError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class UrlResponse(Protocol):
    def __enter__(self) -> BinaryIO: ...

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None: ...


UrlOpener = Callable[[Request], UrlResponse]


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = child
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class ReferenceFrame:
    sequence_id: str
    frame: int
    filename: str
    url: str
    byte_length: int
    sha256: str


@dataclass(frozen=True, slots=True)
class ReferenceSequence:
    sequence_id: str
    base_url: str
    first_frame: int
    last_frame: int
    frame_count: int
    total_bytes: int
    record_set_sha256: str
    frames: tuple[ReferenceFrame, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "frames", tuple(self.frames))


@dataclass(frozen=True, slots=True)
class ReferenceMediaManifest:
    collection_id: str
    title: str
    attribution: str
    license_spdx: str
    license_url: str
    source_notice_url: str
    source_notice_sha256: str
    sequences: tuple[ReferenceSequence, ...]
    manifest_sha256: str

    @property
    def frame_count(self) -> int:
        return sum(sequence.frame_count for sequence in self.sequences)

    @property
    def total_bytes(self) -> int:
        return sum(sequence.total_bytes for sequence in self.sequences)


@dataclass(frozen=True, slots=True)
class ReferenceMediaVerification:
    collection_id: str
    manifest_sha256: str
    license_spdx: str
    source_notice_sha256: str
    cache_root: str
    frame_count: int
    total_bytes: int
    sequence_record_set_sha256: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "sequence_record_set_sha256",
            MappingProxyType(dict(self.sequence_record_set_sha256)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "open-film-reference-verification/v1",
            "collection_id": self.collection_id,
            "manifest_sha256": self.manifest_sha256,
            "license_spdx": self.license_spdx,
            "source_notice_sha256": self.source_notice_sha256,
            "cache_root": self.cache_root,
            "frame_count": self.frame_count,
            "total_bytes": self.total_bytes,
            "sequence_record_set_sha256": dict(self.sequence_record_set_sha256),
        }


def load_reference_media_manifest(
    path: Path = REFERENCE_MEDIA_MANIFEST,
) -> ReferenceMediaManifest:
    try:
        raw = path.resolve(strict=True).read_bytes()
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("floating point")),
            parse_constant=_reject_nonfinite,
        )
        schema = json.loads(REFERENCE_MEDIA_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
        raise ReferenceMediaError("reference-manifest-invalid") from error
    if not isinstance(value, dict):
        raise ReferenceMediaError("reference-manifest-invalid")
    sequences: list[ReferenceSequence] = []
    manifest_root = path.resolve(strict=True).parent
    for item in cast(list[dict[str, Any]], value["sequences"]):
        sequence_id = cast(str, item["sequence_id"])
        base_url = cast(str, item["base_url"])
        parsed = urlsplit(base_url)
        if (
            _SEQUENCE.fullmatch(sequence_id) is None
            or parsed.scheme != "https"
            or parsed.netloc != "media.xiph.org"
            or parsed.path != f"/tearsofsteel/linear-exr/{sequence_id}/"
            or parsed.query
            or parsed.fragment
        ):
            raise ReferenceMediaError("reference-source-invalid")
        records_relative = Path(cast(str, item["records_path"]))
        if records_relative.is_absolute() or ".." in records_relative.parts:
            raise ReferenceMediaError("reference-manifest-invalid")
        records_path = manifest_root / records_relative
        try:
            records_bytes = records_path.resolve(strict=True).read_bytes()
        except OSError as error:
            raise ReferenceMediaError("reference-records-unavailable") from error
        record_set_sha256 = cast(str, item["record_set_sha256"])
        if f"sha256:{hashlib.sha256(records_bytes).hexdigest()}" != record_set_sha256:
            raise ReferenceMediaError("reference-records-digest-mismatch")
        frames: list[ReferenceFrame] = []
        try:
            for index, line in enumerate(records_bytes.decode("ascii").splitlines()):
                filename, raw_length, frame_sha256 = line.split("\t")
                expected_filename = f"{sequence_id}_{index:05d}.exr"
                if (
                    filename != expected_filename
                    or re.fullmatch(r"[0-9a-f]{64}", frame_sha256) is None
                ):
                    raise ValueError("invalid frame record")
                frames.append(
                    ReferenceFrame(
                        sequence_id=sequence_id,
                        frame=index,
                        filename=filename,
                        url=urljoin(base_url, filename),
                        byte_length=int(raw_length),
                        sha256=f"sha256:{frame_sha256}",
                    )
                )
        except (UnicodeError, ValueError) as error:
            raise ReferenceMediaError("reference-records-invalid") from error
        sequence = ReferenceSequence(
            sequence_id=sequence_id,
            base_url=base_url,
            first_frame=cast(int, item["first_frame"]),
            last_frame=cast(int, item["last_frame"]),
            frame_count=cast(int, item["frame_count"]),
            total_bytes=cast(int, item["total_bytes"]),
            record_set_sha256=record_set_sha256,
            frames=tuple(frames),
        )
        if (
            sequence.frame_count != sequence.last_frame - sequence.first_frame + 1
            or len(sequence.frames) != sequence.frame_count
            or tuple(frame.frame for frame in sequence.frames)
            != tuple(range(sequence.first_frame, sequence.last_frame + 1))
            or sum(frame.byte_length for frame in sequence.frames) != sequence.total_bytes
            or _DIGEST.fullmatch(sequence.record_set_sha256) is None
        ):
            raise ReferenceMediaError("reference-manifest-invalid")
        sequences.append(sequence)
    if len({sequence.sequence_id for sequence in sequences}) != len(sequences):
        raise ReferenceMediaError("reference-manifest-invalid")
    return ReferenceMediaManifest(
        collection_id=cast(str, value["collection_id"]),
        title=cast(str, value["title"]),
        attribution=cast(str, value["attribution"]),
        license_spdx=cast(str, value["license"]["spdx"]),
        license_url=cast(str, value["license"]["url"]),
        source_notice_url=cast(str, value["source_notice_url"]),
        source_notice_sha256=cast(str, value["source_notice_sha256"]),
        sequences=tuple(sequences),
        manifest_sha256=f"sha256:{hashlib.sha256(raw).hexdigest()}",
    )


def _safe_cache_root(cache_root: Path) -> Path:
    absolute = cache_root if cache_root.is_absolute() else Path.cwd() / cache_root
    if ".." in absolute.parts or absolute.is_symlink():
        raise ReferenceMediaError("reference-cache-unsafe")
    resolved = absolute.resolve(strict=False)
    if (
        resolved != absolute.absolute()
        or resolved == Path(resolved.anchor)
        or len(resolved.parts) < 3
    ):
        raise ReferenceMediaError("reference-cache-unsafe")
    try:
        resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
        metadata = resolved.lstat()
    except OSError as error:
        raise ReferenceMediaError("reference-cache-unsafe") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ReferenceMediaError("reference-cache-unsafe")
    return resolved


def _sequence_records(root: Path, sequence: ReferenceSequence) -> tuple[bytes, int]:
    sequence_root = root / sequence.sequence_id
    try:
        sequence_metadata = sequence_root.lstat()
        resolved_sequence = sequence_root.resolve(strict=True)
    except OSError as error:
        raise ReferenceMediaError("reference-frame-missing") from error
    if (
        resolved_sequence != sequence_root
        or not resolved_sequence.is_relative_to(root)
        or stat.S_ISLNK(sequence_metadata.st_mode)
        or not stat.S_ISDIR(sequence_metadata.st_mode)
    ):
        raise ReferenceMediaError("reference-frame-unsafe")
    records: list[bytes] = []
    total_bytes = 0
    for frame in sequence.frames:
        path = sequence_root / frame.filename
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ReferenceMediaError("reference-frame-missing") from error
        if (
            resolved != path
            or not resolved.is_relative_to(root)
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise ReferenceMediaError("reference-frame-unsafe")
        digest = _sha256_file(path)
        if metadata.st_size != frame.byte_length or f"sha256:{digest}" != frame.sha256:
            raise ReferenceMediaError("reference-frame-digest-mismatch")
        total_bytes += metadata.st_size
        records.append(f"{frame.filename}\t{metadata.st_size}\t{digest}\n".encode("ascii"))
    return b"".join(records), total_bytes


def verify_reference_media(
    cache_root: Path,
    manifest: ReferenceMediaManifest | None = None,
) -> ReferenceMediaVerification:
    selected = manifest or load_reference_media_manifest()
    root = _safe_cache_root(cache_root)
    observed: dict[str, str] = {}
    total_bytes = 0
    for sequence in selected.sequences:
        records, sequence_bytes = _sequence_records(root, sequence)
        digest = f"sha256:{hashlib.sha256(records).hexdigest()}"
        if digest != sequence.record_set_sha256 or sequence_bytes != sequence.total_bytes:
            raise ReferenceMediaError("reference-sequence-digest-mismatch")
        observed[sequence.sequence_id] = digest
        total_bytes += sequence_bytes
    return ReferenceMediaVerification(
        collection_id=selected.collection_id,
        manifest_sha256=selected.manifest_sha256,
        license_spdx=selected.license_spdx,
        source_notice_sha256=selected.source_notice_sha256,
        cache_root=root.as_posix(),
        frame_count=selected.frame_count,
        total_bytes=total_bytes,
        sequence_record_set_sha256=observed,
    )


def _default_open(request: Request) -> UrlResponse:
    return cast(UrlResponse, urlopen(request, timeout=60))  # noqa: S310


def _verify_source_notice(manifest: ReferenceMediaManifest, opener: UrlOpener) -> None:
    request = Request(
        manifest.source_notice_url,
        headers={"User-Agent": "ColorTrace-reference-fetch/1"},
    )
    try:
        with opener(request) as response:
            final_url = getattr(
                response,
                "geturl",
                lambda url=manifest.source_notice_url: url,
            )()
            notice = response.read(65_537)
    except Exception as error:
        if isinstance(error, ReferenceMediaError):
            raise
        raise ReferenceMediaError("reference-source-notice-unavailable") from error
    if final_url != manifest.source_notice_url:
        raise ReferenceMediaError("reference-source-redirected")
    if (
        not notice
        or len(notice) > 65_536
        or f"sha256:{hashlib.sha256(notice).hexdigest()}" != manifest.source_notice_sha256
    ):
        raise ReferenceMediaError("reference-source-notice-digest-mismatch")


def fetch_reference_media(
    cache_root: Path,
    manifest: ReferenceMediaManifest | None = None,
    *,
    opener: UrlOpener = _default_open,
) -> ReferenceMediaVerification:
    selected = manifest or load_reference_media_manifest()
    root = _safe_cache_root(cache_root)
    _verify_source_notice(selected, opener)
    for sequence in selected.sequences:
        sequence_root = root / sequence.sequence_id
        sequence_root.mkdir(mode=0o700, exist_ok=True)
        if sequence_root.is_symlink():
            raise ReferenceMediaError("reference-cache-unsafe")
        for frame in sequence.frames:
            target = sequence_root / frame.filename
            if target.exists():
                if target.is_symlink() or not target.is_file():
                    raise ReferenceMediaError("reference-frame-unsafe")
                continue
            request = Request(frame.url, headers={"User-Agent": "ColorTrace-reference-fetch/1"})
            temporary: Path | None = None
            try:
                descriptor, name = tempfile.mkstemp(
                    prefix=f".{frame.filename}.", suffix=".part", dir=sequence_root
                )
                temporary = Path(name)
                with os.fdopen(descriptor, "wb") as output, opener(request) as response:
                    final_url = getattr(response, "geturl", lambda url=frame.url: url)()
                    if final_url != frame.url:
                        raise ReferenceMediaError("reference-source-redirected")
                    remaining = frame.byte_length + 1
                    while remaining and (block := response.read(min(1024 * 1024, remaining))):
                        output.write(block)
                        remaining -= len(block)
                    output.flush()
                    os.fsync(output.fileno())
                os.chmod(temporary, 0o600)
                if (
                    temporary.stat().st_size != frame.byte_length
                    or f"sha256:{_sha256_file(temporary)}" != frame.sha256
                ):
                    raise ReferenceMediaError("reference-frame-digest-mismatch")
                temporary.replace(target)
            except Exception as error:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
                if isinstance(error, ReferenceMediaError):
                    raise
                raise ReferenceMediaError("reference-download-failed") from error
    return verify_reference_media(root, selected)


def reference_manifest_identity(
    manifest: ReferenceMediaManifest | None = None,
) -> Mapping[str, Any]:
    selected = manifest or load_reference_media_manifest()
    value = {
        "schema": "open-film-reference-identity/v1",
        "collection_id": selected.collection_id,
        "manifest_sha256": selected.manifest_sha256,
        "frame_count": selected.frame_count,
        "total_bytes": selected.total_bytes,
        "license_spdx": selected.license_spdx,
        "source_notice_sha256": selected.source_notice_sha256,
        "sequence_record_set_sha256": {
            sequence.sequence_id: sequence.record_set_sha256 for sequence in selected.sequences
        },
    }
    return cast(Mapping[str, Any], MappingProxyType(value))


__all__ = [
    "REFERENCE_MEDIA_MANIFEST",
    "ReferenceFrame",
    "ReferenceMediaError",
    "ReferenceMediaManifest",
    "ReferenceMediaVerification",
    "ReferenceSequence",
    "fetch_reference_media",
    "load_reference_media_manifest",
    "reference_manifest_identity",
    "verify_reference_media",
]
