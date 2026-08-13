from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import cache
from pathlib import Path, PurePosixPath
from typing import Any, cast

from colortrace_fixture.fixture import OCIO_VERSION  # type: ignore[import-untyped]
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

from .models import (
    ActionSnapshot,
    BoundSimulatorAction,
    PreparedPublication,
    PromotionResult,
    PublicationOperationState,
)
from .renderer import (
    FrameRenderRequest,
    OcioRenderer,
    VerifiedPrivateConfigRoot,
    sha256_bytes,
)

SCHEMA_ROOT = Path(__file__).parent / "schemas"
SCHEMA_FILES = {
    "simulator-source-batch/v1": "simulator-source-batch-v1.schema.json",
    "simulator-runtime-manifest/v1": "simulator-runtime-manifest-v1.schema.json",
    "simulator-fixture-manifest/v1": "simulator-fixture-manifest-v1.schema.json",
    "simulator-safe-complement/v1": "simulator-safe-complement-v1.schema.json",
    "simulator-preservation-manifest/v1": "simulator-preservation-manifest-v1.schema.json",
    "simulator-safe-complement-proof/v1": "simulator-safe-complement-proof-v1.schema.json",
    "simulator-candidate-seal/v1": "simulator-candidate-seal-v1.schema.json",
    "simulator-publication-pointer/v1": "simulator-publication-pointer-v1.schema.json",
}

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_PUBLICATION = re.compile(r"^publication:[0-9a-f]{64}$")
_SOURCE_BATCH = re.compile(r"^source-batch:[0-9a-f]{64}$")


class SimulatorBundleError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(token: str) -> None:
    raise ValueError(f"non-finite JSON value: {token}")


def _strict_json(value: bytes) -> Any:
    try:
        return json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("floating-point value")),
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SimulatorBundleError("malformed-json") from error


def canonical_json_bytes(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, float):
            raise SimulatorBundleError("floating-point-json-prohibited")
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise SimulatorBundleError("json-key-invalid")
                result[key] = normalize(child)
            return result
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if item is None or isinstance(item, (str, int, bool)):
            return item
        raise SimulatorBundleError("json-value-invalid")

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _document_digest(value: Mapping[str, Any]) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _plain_document(value: Mapping[str, Any]) -> dict[str, Any]:
    parsed = _strict_json(canonical_json_bytes(value))
    if not isinstance(parsed, dict):
        raise SimulatorBundleError("document-invalid")
    return cast(dict[str, Any], parsed)


def _prefixed_digest(value: object, *, code: str = "digest-invalid") -> str:
    if not isinstance(value, str):
        raise SimulatorBundleError(code)
    digest = value if value.startswith("sha256:") else f"sha256:{value}"
    if _DIGEST.fullmatch(digest) is None:
        raise SimulatorBundleError(code)
    return digest


def _identifier(value: object, *, code: str = "identifier-invalid") -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SimulatorBundleError(code)
    return value


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or not value.isascii():
        raise SimulatorBundleError("path-invalid")
    if "\\" in value or "$" in value or any(ord(character) < 32 for character in value):
        raise SimulatorBundleError("path-invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SimulatorBundleError("path-invalid")
    if any(len(part) > 255 for part in path.parts) or len(value) > 512:
        raise SimulatorBundleError("path-invalid")
    return value


def _path_parts(value: str) -> tuple[str, ...]:
    return tuple(PurePosixPath(_relative_path(value)).parts)


@cache
def _validators() -> Mapping[str, Draft202012Validator]:
    validators: dict[str, Draft202012Validator] = {}
    for schema_name, filename in SCHEMA_FILES.items():
        raw = (SCHEMA_ROOT / filename).read_bytes()
        document = _strict_json(raw)
        if not isinstance(document, dict):
            raise SimulatorBundleError("schema-invalid")
        Draft202012Validator.check_schema(document)
        validators[schema_name] = Draft202012Validator(
            document,
            format_checker=FormatChecker(),
        )
    return validators


def _validate_document(value: Mapping[str, Any]) -> None:
    schema = value.get("schema")
    if not isinstance(schema, str) or schema not in _validators():
        raise SimulatorBundleError("schema-unknown")
    try:
        _validators()[schema].validate(dict(value))
    except ValidationError as error:
        raise SimulatorBundleError("schema-validation") from error


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise SimulatorBundleError("timestamp-invalid")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _read_all(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        try:
            block = os.read(fd, 1024 * 1024)
        except InterruptedError:
            continue
        if not block:
            return b"".join(chunks)
        chunks.append(block)


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise SimulatorBundleError("short-write")
        offset += written


@contextmanager
def _directory_fd(root_fd: int, parts: Sequence[str]) -> Any:
    current = os.dup(root_fd)
    try:
        for part in parts:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        yield current
    finally:
        os.close(current)


class _SecureTree:
    def __init__(self, root: Path) -> None:
        try:
            self.root = root.resolve(strict=True)
            self.fd = os.open(
                self.root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as error:
            raise SimulatorBundleError("tree-unavailable") from error
        metadata = os.fstat(self.fd)
        if not stat.S_ISDIR(metadata.st_mode):
            os.close(self.fd)
            raise SimulatorBundleError("tree-not-directory")
        self.device = metadata.st_dev

    def close(self) -> None:
        os.close(self.fd)

    def __enter__(self) -> _SecureTree:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def read(self, relative: str) -> bytes:
        parts = _path_parts(relative)
        try:
            with _directory_fd(self.fd, parts[:-1]) as parent_fd:
                file_fd = os.open(
                    parts[-1],
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
                try:
                    before = os.fstat(file_fd)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_nlink != 1
                        or before.st_dev != self.device
                    ):
                        raise SimulatorBundleError("file-boundary-invalid")
                    value = _read_all(file_fd)
                    after = os.fstat(file_fd)
                    if (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    ) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ):
                        raise SimulatorBundleError("file-changed-during-read")
                    return value
                finally:
                    os.close(file_fd)
        except OSError as error:
            raise SimulatorBundleError("file-unavailable") from error


def _audit_tree(root: Path) -> list[str]:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise SimulatorBundleError("tree-unavailable") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise SimulatorBundleError("tree-boundary-invalid")
    folded: dict[str, str] = {}
    inodes: dict[tuple[int, int], str] = {}
    files: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        _relative_path(relative)
        folded_relative = relative.casefold()
        if folded_relative in folded and folded[folded_relative] != relative:
            raise SimulatorBundleError("case-alias-path")
        folded[folded_relative] = relative
        metadata = path.lstat()
        if path.is_symlink() or metadata.st_dev != root_metadata.st_dev:
            raise SimulatorBundleError("tree-link-or-mount-prohibited")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise SimulatorBundleError("tree-nonregular-prohibited")
        identity = (metadata.st_dev, metadata.st_ino)
        if identity in inodes:
            raise SimulatorBundleError("tree-hardlink-prohibited")
        inodes[identity] = relative
        files.append(relative)
    return files


def _read_relative(root: Path, relative: str) -> bytes:
    with _SecureTree(root) as tree:
        return tree.read(relative)


def _read_document(root: Path, relative: str, *, schema: str | None = None) -> dict[str, Any]:
    raw = _read_relative(root, relative)
    value = _strict_json(raw)
    if not isinstance(value, dict):
        raise SimulatorBundleError("document-invalid")
    document = cast(dict[str, Any], value)
    if raw != canonical_json_bytes(document):
        raise SimulatorBundleError("document-not-canonical")
    if schema is not None:
        if document.get("schema") != schema:
            raise SimulatorBundleError("document-schema-mismatch")
        if schema in SCHEMA_FILES:
            _validate_document(document)
    return document


def _ensure_parent(root: Path, relative: str) -> Path:
    parts = _path_parts(relative)
    current = root
    for part in parts[:-1]:
        current = current / part
        if current.exists():
            metadata = current.lstat()
            if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise SimulatorBundleError("write-parent-invalid")
        else:
            current.mkdir(mode=0o700)
    return current


def _write_relative(root: Path, relative: str, value: bytes) -> None:
    parent = _ensure_parent(root, relative)
    name = _path_parts(relative)[-1]
    temporary = f".{name}.{secrets.token_hex(8)}.tmp"
    parent_fd = os.open(
        parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        file_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            _write_all(file_fd, value)
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as error:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass
        raise SimulatorBundleError("file-write-failed") from error
    finally:
        os.close(parent_fd)


def _write_document(root: Path, relative: str, value: Mapping[str, Any]) -> str:
    document = _plain_document(value)
    if document.get("schema") in SCHEMA_FILES:
        _validate_document(document)
    raw = canonical_json_bytes(document)
    _write_relative(root, relative, raw)
    return sha256_bytes(raw)


def _copy_relative(source: Path, source_relative: str, target: Path, target_relative: str) -> None:
    _write_relative(target, target_relative, _read_relative(source, source_relative))


def _fsync_tree(root: Path) -> None:
    directories = sorted(
        [root, *(path for path in root.rglob("*") if path.is_dir())],
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        fd = os.open(
            directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _freeze_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o500 if path.is_dir() else 0o400)
    root.chmod(0o500)
    _fsync_tree(root)


def _rename_frozen_tree(source: Path, target: Path) -> None:
    """Rename a sealed tree on filesystems that require write access to its root."""

    source.chmod(0o700)
    try:
        os.rename(source, target)
    except BaseException:
        source.chmod(0o500)
        raise
    target.chmod(0o500)


def _remove_tree(root: Path) -> None:
    """Remove one exact tree without following attacker-controlled links."""

    try:
        parent_fd = os.open(
            root.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError:
        return
    try:
        try:
            root_metadata = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(root_metadata.st_mode):
            os.unlink(root.name, dir_fd=parent_fd)
            return
        try:
            root_fd = os.open(
                root.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError as error:
            raise SimulatorBundleError("cleanup-boundary-invalid") from error

        def clear(directory_fd: int) -> None:
            os.fchmod(directory_fd, 0o700)
            with os.scandir(directory_fd) as entries:
                names = sorted(entry.name for entry in entries)
            for name in names:
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                        dir_fd=directory_fd,
                    )
                    try:
                        clear(child_fd)
                    finally:
                        os.close(child_fd)
                    os.rmdir(name, dir_fd=directory_fd)
                else:
                    os.unlink(name, dir_fd=directory_fd)

        try:
            clear(root_fd)
        finally:
            os.close(root_fd)
        os.rmdir(root.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _tree_digest(root: Path, *, excluded: frozenset[str] = frozenset()) -> str:
    entries: list[dict[str, Any]] = []
    for relative in _audit_tree(root):
        if relative in excluded:
            continue
        value = _read_relative(root, relative)
        entries.append({"path": relative, "sha256": sha256_bytes(value), "size": len(value)})
    return sha256_bytes(canonical_json_bytes(entries))


def _data_file(path: str, value: bytes, kind: str) -> dict[str, Any]:
    return {"path": path, "sha256": sha256_bytes(value), "size": len(value), "kind": kind}


@dataclass(frozen=True, slots=True)
class _ActiveContext:
    pointer: dict[str, Any]
    pointer_sha256: str
    publication_root: Path
    fixture: dict[str, Any]
    runtime: dict[str, Any]
    lineage: dict[str, Any]
    source_batch_root: Path
    source_batch: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _ResolvedAction:
    quarantine_command: dict[str, Any]
    frame_pairs: tuple[tuple[dict[str, Any], dict[str, Any]], ...]
    derivative_command: dict[str, Any]
    derivative_record: dict[str, Any]
    resource_record: dict[str, Any]
    mutable_entries: tuple[dict[str, Any], ...]
    mutable_paths: frozenset[str]
    target_invariants: tuple[dict[str, Any], ...]
    quarantine_path: str


class LocalPublicationPort:
    def __init__(
        self,
        root: Path,
        *,
        renderer: OcioRenderer | None = None,
        clock: Callable[[], datetime] = _default_clock,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        try:
            supplied_metadata = root.lstat()
            if stat.S_ISLNK(supplied_metadata.st_mode):
                raise SimulatorBundleError("workspace-link-prohibited")
            self.root = root.resolve(strict=True)
        except OSError as error:
            raise SimulatorBundleError("workspace-unavailable") from error
        metadata = self.root.lstat()
        if self.root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise SimulatorBundleError("workspace-invalid")
        if metadata.st_uid != os.getuid():
            raise SimulatorBundleError("workspace-owner-invalid")
        if metadata.st_mode & 0o077:
            raise SimulatorBundleError("workspace-not-private")
        self.renderer = renderer or OcioRenderer()
        self.clock = clock
        self.fault_hook = fault_hook or (lambda _point: None)
        for name in ("source-batches", "staging", "publications", "state"):
            path = self.root / name
            if not path.exists():
                path.mkdir(mode=0o700)
            child_metadata = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_uid != metadata.st_uid
                or child_metadata.st_dev != metadata.st_dev
                or child_metadata.st_mode & 0o077
            ):
                raise SimulatorBundleError("workspace-layout-invalid")
        lock_path = self.root / "state" / "publication.lock"
        if not lock_path.exists():
            fd = os.open(
                lock_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            os.close(fd)
        lock_metadata = lock_path.lstat()
        if (
            lock_path.is_symlink()
            or not stat.S_ISREG(lock_metadata.st_mode)
            or lock_metadata.st_nlink != 1
            or lock_metadata.st_uid != metadata.st_uid
            or lock_metadata.st_dev != metadata.st_dev
            or lock_metadata.st_mode & 0o077
        ):
            raise SimulatorBundleError("workspace-lock-invalid")

    @classmethod
    def bootstrap(
        cls,
        *,
        root: Path,
        fixture_bundle: Path,
        renderer: OcioRenderer | None = None,
        clock: Callable[[], datetime] = _default_clock,
        fault_hook: Callable[[str], None] | None = None,
    ) -> LocalPublicationPort:
        try:
            root_metadata = root.lstat()
        except FileNotFoundError:
            root.mkdir(parents=True, mode=0o700)
        else:
            if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
                raise SimulatorBundleError("workspace-link-prohibited")
        port = cls(root, renderer=renderer, clock=clock, fault_hook=fault_hook)
        with port._publication_lock():
            active = port.root / "state" / "active.json"
            if active.exists():
                port._load_active_context()
                return port
            batch_root, batch, batch_sha256 = port._admit_source_batch(fixture_bundle)
            pointer = port._build_initial_publication(batch_root, batch, batch_sha256)
            port._write_active_pointer(pointer)
            port.fault_hook("bootstrap-pointer-durable")
        return port

    @contextmanager
    def _publication_lock(self) -> Any:
        fd = os.open(
            self.root / "state" / "publication.lock",
            os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _batch_root(self, source_batch_id: str) -> Path:
        if _SOURCE_BATCH.fullmatch(source_batch_id) is None:
            raise SimulatorBundleError("source-batch-id-invalid")
        return self.root / "source-batches" / f"sb-{source_batch_id.removeprefix('source-batch:')}"

    def _publication_root(self, publication_id: str) -> Path:
        if _PUBLICATION.fullmatch(publication_id) is None:
            raise SimulatorBundleError("publication-id-invalid")
        return self.root / "publications" / f"pub-{publication_id.removeprefix('publication:')}"

    def _admit_source_batch(self, fixture_bundle: Path) -> tuple[Path, dict[str, Any], str]:
        try:
            source_root = fixture_bundle.resolve(strict=True)
        except OSError as error:
            raise SimulatorBundleError("fixture-bundle-unavailable") from error
        if (source_root / "oracle").exists():
            raise SimulatorBundleError("oracle-in-runtime-bundle")
        for subtree in (source_root / "runtime", source_root / "references"):
            _audit_tree(subtree)
        fixture_relative = "runtime/manifests/fixture-runtime-manifest.json"
        fixture = _read_document(source_root, fixture_relative)
        if fixture.get("schema") != "fixture-runtime-manifest/v1":
            raise SimulatorBundleError("fixture-manifest-invalid")
        if fixture.get("ocio_version") != OCIO_VERSION:
            raise SimulatorBundleError("fixture-ocio-version-mismatch")
        fixture_raw = _read_relative(source_root, fixture_relative)
        fixture_sha256 = sha256_bytes(fixture_raw)
        identity = {
            "schema": "simulator-source-batch-identity/v1",
            "fixture_id": fixture.get("fixture_id"),
            "variant_id": fixture.get("variant_id"),
            "run_id": fixture.get("run_id"),
            "source_fixture_manifest_sha256": fixture_sha256,
        }
        source_batch_id = (
            f"source-batch:{hashlib.sha256(canonical_json_bytes(identity)).hexdigest()}"
        )
        final_root = self._batch_root(source_batch_id)
        if final_root.exists():
            batch = _read_document(
                final_root,
                "source-batch.json",
                schema="simulator-source-batch/v1",
            )
            return final_root, batch, sha256_bytes(_read_relative(final_root, "source-batch.json"))

        stage = self.root / "staging" / f"source-{secrets.token_hex(16)}"
        stage.mkdir(mode=0o700)
        try:
            manifest_paths = {fixture_relative}
            data_paths: set[str] = set()

            declared_pointer = cast(Mapping[str, Any], fixture["declared_resources"])
            declared_relative = _relative_path(declared_pointer["manifest"])
            manifest_paths.add(declared_relative)
            declared_raw = _read_relative(source_root, declared_relative)
            declared_sha256 = sha256_bytes(declared_raw)
            if declared_sha256 != _prefixed_digest(declared_pointer["sha256"]):
                raise SimulatorBundleError("declared-resource-pointer-mismatch")
            declared = _strict_json(declared_raw)
            if (
                not isinstance(declared, dict)
                or declared.get("schema") != "declared-approved-resources/v1"
            ):
                raise SimulatorBundleError("declared-resource-manifest-invalid")
            approved_sha256 = _prefixed_digest(declared.get("approved_lut_sha256"))

            lineage_pointer = cast(Mapping[str, Any], fixture["lineage"])
            lineage_relative = _relative_path(lineage_pointer["manifest"])
            manifest_paths.add(lineage_relative)
            lineage_raw = _read_relative(source_root, lineage_relative)
            lineage_sha256 = sha256_bytes(lineage_raw)
            if lineage_sha256 != _prefixed_digest(lineage_pointer["sha256"]):
                raise SimulatorBundleError("lineage-pointer-mismatch")
            lineage = _strict_json(lineage_raw)
            if not isinstance(lineage, dict) or lineage.get("schema") != "artifact-lineage/v1":
                raise SimulatorBundleError("lineage-manifest-invalid")

            sources: list[dict[str, Any]] = []
            for pointer in sorted(
                cast(list[dict[str, Any]], fixture["sources"]),
                key=lambda item: cast(str, item["source_id"]),
            ):
                manifest_relative = _relative_path(pointer["manifest"])
                manifest_raw = _read_relative(source_root, manifest_relative)
                if sha256_bytes(manifest_raw) != _prefixed_digest(pointer["sha256"]):
                    raise SimulatorBundleError("source-manifest-pointer-mismatch")
                manifest = _strict_json(manifest_raw)
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("schema") != "generated-source/v1"
                ):
                    raise SimulatorBundleError("source-manifest-invalid")
                manifest_paths.add(manifest_relative)
                png_relative = _relative_path(manifest["stored_png"])
                data_paths.add(png_relative)
                png_raw = _read_relative(source_root, png_relative)
                if sha256_bytes(png_raw) != _prefixed_digest(manifest["stored_png_sha256"]):
                    raise SimulatorBundleError("source-png-pointer-mismatch")
                sources.append(
                    {
                        "source_id": manifest["source_id"],
                        "manifest_path": f"fixture/{manifest_relative}",
                        "manifest_sha256": sha256_bytes(manifest_raw),
                        "png_path": f"fixture/{png_relative}",
                        "png_sha256": sha256_bytes(png_raw),
                        "canonical_pixel_sha256": _prefixed_digest(
                            manifest["canonical_pixel_sha256"]
                        ),
                        "width": manifest["width"],
                        "height": manifest["height"],
                        "channels": manifest["channels"],
                    }
                )

            jobs: list[dict[str, Any]] = []
            authorized_resource_paths: set[str] = set()
            reference_manifests: dict[str, dict[str, Any]] = {}
            for pointer in sorted(
                cast(list[dict[str, Any]], fixture["jobs"]),
                key=lambda item: cast(str, item["job_id"]),
            ):
                manifest_relative = _relative_path(pointer["manifest"])
                manifest_raw = _read_relative(source_root, manifest_relative)
                if sha256_bytes(manifest_raw) != _prefixed_digest(pointer["sha256"]):
                    raise SimulatorBundleError("job-manifest-pointer-mismatch")
                job = _strict_json(manifest_raw)
                if not isinstance(job, dict) or job.get("schema") != "fixture-job/v1":
                    raise SimulatorBundleError("job-manifest-invalid")
                manifest_paths.add(manifest_relative)
                source_record = next(
                    (source for source in sources if source["source_id"] == job.get("source_id")),
                    None,
                )
                if (
                    source_record is None
                    or f"fixture/{_relative_path(job['source_manifest'])}"
                    != source_record["manifest_path"]
                ):
                    raise SimulatorBundleError("job-source-binding-mismatch")
                resource_relative = _relative_path(job["resource_manifest"])
                manifest_paths.add(resource_relative)
                resource_raw = _read_relative(source_root, resource_relative)
                if sha256_bytes(resource_raw) != _prefixed_digest(job["resource_manifest_sha256"]):
                    raise SimulatorBundleError("job-resource-pointer-mismatch")
                resource = _strict_json(resource_raw)
                if (
                    not isinstance(resource, dict)
                    or resource.get("schema") != "resolved-resource-manifest/v1"
                    or resource.get("job_id") != job.get("job_id")
                    or resource.get("worker_id") != job.get("worker_id")
                ):
                    raise SimulatorBundleError("job-resource-manifest-invalid")
                config_relative = f"runtime/{_relative_path(resource['config_root_relative_path'])}"
                data_paths.add(config_relative)
                config_raw = _read_relative(source_root, config_relative)
                if sha256_bytes(config_raw) != _prefixed_digest(resource["nominal_config_sha256"]):
                    raise SimulatorBundleError("resource-config-pointer-mismatch")
                for resource_entry in cast(list[dict[str, Any]], resource["ordered_resources"]):
                    resource_path = (
                        f"runtime/{_relative_path(resource_entry['resolved_root_relative_path'])}"
                    )
                    resource_bytes = _read_relative(source_root, resource_path)
                    if (
                        sha256_bytes(resource_bytes) != _prefixed_digest(resource_entry["sha256"])
                        or len(resource_bytes) != resource_entry["size"]
                    ):
                        raise SimulatorBundleError("resource-file-pointer-mismatch")
                    data_paths.add(resource_path)
                    authorized_resource_paths.add(resource_path)

                output_relative = _relative_path(job["output_buffer"])
                display_relative = _relative_path(job["display_png"])
                output_raw = _read_relative(source_root, output_relative)
                display_raw = _read_relative(source_root, display_relative)
                if sha256_bytes(output_raw) != _prefixed_digest(
                    job["output_buffer_sha256"]
                ) or sha256_bytes(display_raw) != _prefixed_digest(job["display_png_sha256"]):
                    raise SimulatorBundleError("job-output-binding-mismatch")
                data_paths.update((output_relative, display_relative))

                reference_relative = _relative_path(job["declared_reference_manifest"])
                manifest_paths.add(reference_relative)
                reference_raw = _read_relative(source_root, reference_relative)
                if sha256_bytes(reference_raw) != _prefixed_digest(
                    job["declared_reference_manifest_sha256"]
                ):
                    raise SimulatorBundleError("job-reference-pointer-mismatch")
                reference = _strict_json(reference_raw)
                if (
                    not isinstance(reference, dict)
                    or reference.get("schema") != "declared-reference/v1"
                    or reference.get("reference_id") != job.get("declared_reference_id")
                ):
                    raise SimulatorBundleError("reference-manifest-invalid")
                prior_reference = reference_manifests.setdefault(reference_relative, reference)
                if prior_reference != reference:
                    raise SimulatorBundleError("reference-manifest-conflict")
                reference_buffer = _relative_path(reference["buffer"])
                reference_display = _relative_path(reference["display"])
                reference_buffer_raw = _read_relative(source_root, reference_buffer)
                reference_display_raw = _read_relative(source_root, reference_display)
                if sha256_bytes(reference_buffer_raw) != _prefixed_digest(
                    reference["buffer_sha256"]
                ) or sha256_bytes(reference_display_raw) != _prefixed_digest(
                    reference["display_sha256"]
                ):
                    raise SimulatorBundleError("reference-file-pointer-mismatch")
                data_paths.update((reference_buffer, reference_display))
                jobs.append(
                    {
                        "job_id": job["job_id"],
                        "frame_id": job["frame_id"],
                        "output_id": job["output_id"],
                        "worker_id": job["worker_id"],
                        "source_id": job["source_id"],
                        "transform_id": job["transform_id"],
                        "manifest_path": f"fixture/{manifest_relative}",
                        "manifest_sha256": sha256_bytes(manifest_raw),
                        "resource_manifest_path": f"fixture/{resource_relative}",
                        "resource_manifest_sha256": sha256_bytes(resource_raw),
                    }
                )

            derivative_artifacts = [
                item
                for item in cast(list[dict[str, Any]], lineage["artifacts"])
                if item.get("artifact_type") == "lossless-derivative"
            ]
            if len(derivative_artifacts) != 1:
                raise SimulatorBundleError("derivative-topology-invalid")
            derivative = derivative_artifacts[0]
            derivative_buffer = _relative_path(derivative["buffer"])
            derivative_display = _relative_path(derivative["display"])
            derivative_buffer_raw = _read_relative(source_root, derivative_buffer)
            derivative_display_raw = _read_relative(source_root, derivative_display)
            if sha256_bytes(derivative_buffer_raw) != _prefixed_digest(
                derivative["sha256"]
            ) or sha256_bytes(derivative_display_raw) != _prefixed_digest(
                derivative["display_sha256"]
            ):
                raise SimulatorBundleError("derivative-file-pointer-mismatch")
            data_paths.update((derivative_buffer, derivative_display))
            derivatives = [
                {
                    "artifact_id": derivative["artifact_id"],
                    "buffer_path": f"fixture/{derivative_buffer}",
                    "buffer_sha256": _prefixed_digest(derivative["sha256"]),
                    "display_path": f"fixture/{derivative_display}",
                    "display_sha256": _prefixed_digest(derivative["display_sha256"]),
                }
            ]

            worker_config_paths: set[str] = set()
            for worker in cast(list[dict[str, Any]], fixture["worker_configs"]):
                config_relative = _relative_path(worker["config"])
                config_raw = _read_relative(source_root, config_relative)
                if sha256_bytes(config_raw) != _prefixed_digest(worker["config_sha256"]):
                    raise SimulatorBundleError("worker-config-pointer-mismatch")
                worker_config_paths.add(config_relative)
                data_paths.add(config_relative)
            if not worker_config_paths:
                raise SimulatorBundleError("worker-configs-empty")

            approved_candidates = sorted(
                path
                for path in authorized_resource_paths
                if sha256_bytes(_read_relative(source_root, path)) == approved_sha256
            )
            if len(approved_candidates) != 1:
                raise SimulatorBundleError("approved-resource-ambiguous")
            approved_bytes = _read_relative(source_root, approved_candidates[0])
            approved_object_path = f"objects/sha256/{approved_sha256.removeprefix('sha256:')}"

            provenance_pointer = cast(Mapping[str, Any], fixture["provenance"])
            provenance_relative = _relative_path(provenance_pointer["manifest"])
            manifest_paths.add(provenance_relative)
            provenance_raw = _read_relative(source_root, provenance_relative)
            if sha256_bytes(provenance_raw) != _prefixed_digest(provenance_pointer["sha256"]):
                raise SimulatorBundleError("provenance-pointer-mismatch")
            provenance = _strict_json(provenance_raw)
            if (
                not isinstance(provenance, dict)
                or provenance.get("schema") != "fixture-provenance/v1"
                or provenance.get("proprietary_assets") != []
            ):
                raise SimulatorBundleError("provenance-manifest-invalid")
            provenance_paths: set[str] = set()
            for asset in cast(list[dict[str, Any]], provenance["assets"]):
                if "path" not in asset:
                    continue
                asset_path = _relative_path(asset["path"])
                if asset_path in provenance_paths:
                    raise SimulatorBundleError("provenance-path-duplicate")
                asset_raw = _read_relative(source_root, asset_path)
                if sha256_bytes(asset_raw) != _prefixed_digest(asset["sha256"]):
                    raise SimulatorBundleError("provenance-asset-mismatch")
                provenance_paths.add(asset_path)
            if provenance_paths != data_paths:
                raise SimulatorBundleError("provenance-file-closure-mismatch")

            telemetry_pointer = cast(Mapping[str, Any], fixture["telemetry"])
            telemetry_relative = _relative_path(telemetry_pointer["manifest"])
            manifest_paths.add(telemetry_relative)
            telemetry_raw = _read_relative(source_root, telemetry_relative)
            if sha256_bytes(telemetry_raw) != _prefixed_digest(telemetry_pointer["sha256"]):
                raise SimulatorBundleError("telemetry-pointer-mismatch")
            telemetry = _strict_json(telemetry_raw)
            if not isinstance(telemetry, dict) or telemetry.get("schema") != "fixture-telemetry/v1":
                raise SimulatorBundleError("telemetry-manifest-invalid")

            actual_fixture_files = {
                f"runtime/{relative}" for relative in _audit_tree(source_root / "runtime")
            } | {f"references/{relative}" for relative in _audit_tree(source_root / "references")}
            allowed_fixture_files = manifest_paths | data_paths
            if actual_fixture_files != allowed_fixture_files:
                raise SimulatorBundleError("fixture-file-closure-mismatch")
            for relative in sorted(allowed_fixture_files):
                _copy_relative(source_root, relative, stage, f"fixture/{relative}")
            _write_relative(stage, approved_object_path, approved_bytes)

            files: list[dict[str, Any]] = []
            for relative in _audit_tree(stage):
                if relative == "source-batch.json":
                    continue
                raw = _read_relative(stage, relative)
                files.append(
                    {
                        "path": relative,
                        "sha256": sha256_bytes(raw),
                        "size": len(raw),
                        "kind": "approved-object"
                        if relative.startswith("objects/")
                        else (
                            "reference" if relative.startswith("fixture/references/") else "runtime"
                        ),
                    }
                )
            batch = {
                "schema": "simulator-source-batch/v1",
                "source_batch_id": source_batch_id,
                "fixture_id": fixture["fixture_id"],
                "fixture_version": fixture["fixture_version"],
                "variant_id": fixture["variant_id"],
                "run_id": fixture["run_id"],
                "source_fixture_manifest": {
                    "path": f"fixture/{fixture_relative}",
                    "sha256": fixture_sha256,
                },
                "ocio_version": OCIO_VERSION,
                "declared_resource_manifest": {
                    "path": f"fixture/{declared_relative}",
                    "sha256": declared_sha256,
                    "logical_path": declared["logical_path"],
                    "approved_resource_sha256": approved_sha256,
                    "nominal_config_sha256": _prefixed_digest(declared["nominal_config_sha256"]),
                },
                "lineage": {
                    "path": f"fixture/{lineage_relative}",
                    "sha256": lineage_sha256,
                },
                "sources": sources,
                "jobs": jobs,
                "derivatives": derivatives,
                "approved_resource": {
                    "path": approved_object_path,
                    "sha256": approved_sha256,
                    "size": len(approved_bytes),
                },
                "files": sorted(files, key=lambda item: cast(str, item["path"])),
            }
            batch_sha256 = _write_document(stage, "source-batch.json", batch)
            _audit_tree(stage)
            _freeze_tree(stage)
            _rename_frozen_tree(stage, final_root)
            parent_fd = os.open(
                final_root.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self.fault_hook("source-batch-durable")
            return final_root, batch, batch_sha256
        except BaseException:
            _remove_tree(stage)
            raise

    def _build_initial_publication(
        self,
        batch_root: Path,
        batch: Mapping[str, Any],
        batch_sha256: str,
    ) -> dict[str, Any]:
        fixture_pointer = cast(Mapping[str, Any], batch["source_fixture_manifest"])
        fixture = _read_document(batch_root, cast(str, fixture_pointer["path"]))
        source_fixture_sha256 = _prefixed_digest(fixture_pointer["sha256"])
        lineage_pointer = cast(Mapping[str, Any], batch["lineage"])
        source_lineage = _read_document(batch_root, cast(str, lineage_pointer["path"]))
        declared = cast(Mapping[str, Any], batch["declared_resource_manifest"])
        stage = self.root / "staging" / f"bootstrap-{secrets.token_hex(16)}"
        stage.mkdir(mode=0o700)
        files: list[dict[str, Any]] = []
        try:
            indexed_jobs = {
                cast(str, item["job_id"]): cast(Mapping[str, Any], item)
                for item in cast(list[dict[str, Any]], batch["jobs"])
            }
            job_documents: dict[str, dict[str, Any]] = {
                job_id: _read_document(batch_root, cast(str, item["manifest_path"]))
                for job_id, item in indexed_jobs.items()
            }
            resource_documents: dict[str, dict[str, Any]] = {
                job_id: _read_document(batch_root, cast(str, item["resource_manifest_path"]))
                for job_id, item in indexed_jobs.items()
            }
            source_documents = {
                cast(str, item["source_id"]): cast(Mapping[str, Any], item)
                for item in cast(list[dict[str, Any]], batch["sources"])
            }

            resources: list[dict[str, Any]] = []
            worker_configs = sorted(
                cast(list[dict[str, Any]], fixture["worker_configs"]),
                key=lambda item: cast(str, item["worker_id"]),
            )
            for index, worker in enumerate(worker_configs, start=1):
                worker_id = cast(str, worker["worker_id"])
                config_source = f"fixture/{_relative_path(worker['config'])}"
                config_bytes = _read_relative(batch_root, config_source)
                config_sha256 = sha256_bytes(config_bytes)
                if config_sha256 != _prefixed_digest(worker["config_sha256"]):
                    raise SimulatorBundleError("worker-config-pointer-mismatch")
                config_path = f"runtime/workers/w{index:04d}/config/config.ocio"
                _write_relative(stage, config_path, config_bytes)
                files.append(_data_file(config_path, config_bytes, "config"))
                worker_resource_documents = [
                    resource
                    for job_id, resource in resource_documents.items()
                    if job_documents[job_id]["worker_id"] == worker_id
                    and cast(list[Any], resource["ordered_resources"])
                ]
                if not worker_resource_documents:
                    raise SimulatorBundleError("worker-resource-unavailable")
                resource_entries = {
                    canonical_json_bytes(cast(Mapping[str, Any], resource["ordered_resources"][0]))
                    for resource in worker_resource_documents
                }
                if len(resource_entries) != 1:
                    raise SimulatorBundleError("worker-resource-ambiguous")
                source_resource = cast(
                    Mapping[str, Any],
                    worker_resource_documents[0]["ordered_resources"][0],
                )
                source_resource_path = (
                    "fixture/runtime/"
                    f"{_relative_path(source_resource['resolved_root_relative_path'])}"
                )
                resource_bytes = _read_relative(batch_root, source_resource_path)
                resource_sha256 = sha256_bytes(resource_bytes)
                if resource_sha256 != _prefixed_digest(source_resource["sha256"]):
                    raise SimulatorBundleError("worker-resource-pointer-mismatch")
                resource_path = f"runtime/workers/w{index:04d}/config/luts/show_look.cube"
                _write_relative(stage, resource_path, resource_bytes)
                files.append(_data_file(resource_path, resource_bytes, "resource"))
                resources.append(
                    {
                        "worker_id": worker_id,
                        "config_path": config_path,
                        "config_sha256": config_sha256,
                        "logical_path": "luts/show_look.cube",
                        "resource_path": resource_path,
                        "resource_sha256": resource_sha256,
                        "resource_size": len(resource_bytes),
                        "trace_id": None,
                        "last_operation_id": None,
                    }
                )

            render_edges = {
                cast(str, edge["child_artifact_id"]): cast(Mapping[str, Any], edge)
                for edge in cast(list[dict[str, Any]], source_lineage["edges"])
                if edge.get("edge_type") == "source-to-render/v1"
            }
            frames: list[dict[str, Any]] = []
            for index, job_id in enumerate(sorted(job_documents), start=1):
                job = job_documents[job_id]
                output_source = f"fixture/{_relative_path(job['output_buffer'])}"
                display_source = f"fixture/{_relative_path(job['display_png'])}"
                output_bytes = _read_relative(batch_root, output_source)
                display_bytes = _read_relative(batch_root, display_source)
                output_sha256 = sha256_bytes(output_bytes)
                display_sha256 = sha256_bytes(display_bytes)
                if output_sha256 != _prefixed_digest(job["output_buffer_sha256"]):
                    raise SimulatorBundleError("job-output-pointer-mismatch")
                if display_sha256 != _prefixed_digest(job["display_png_sha256"]):
                    raise SimulatorBundleError("job-display-pointer-mismatch")
                output_path = f"runtime/frames/f{index:04d}/output.rgbf32"
                display_path = f"runtime/frames/f{index:04d}/display.png"
                _write_relative(stage, output_path, output_bytes)
                _write_relative(stage, display_path, display_bytes)
                files.extend(
                    (
                        _data_file(output_path, output_bytes, "frame-output"),
                        _data_file(display_path, display_bytes, "frame-display"),
                    )
                )
                resource = resource_documents[job_id]
                ordered_resources = cast(list[dict[str, Any]], resource["ordered_resources"])
                source = source_documents[cast(str, job["source_id"])]
                reference_manifest_path = (
                    f"fixture/{_relative_path(job['declared_reference_manifest'])}"
                )
                reference_manifest = _read_document(batch_root, reference_manifest_path)
                reference_buffer_path = f"fixture/{_relative_path(reference_manifest['buffer'])}"
                reference_buffer = _read_relative(batch_root, reference_buffer_path)
                reference_buffer_sha256 = sha256_bytes(reference_buffer)
                if reference_buffer_sha256 != _prefixed_digest(reference_manifest["buffer_sha256"]):
                    raise SimulatorBundleError("reference-buffer-pointer-mismatch")
                edge = render_edges.get(cast(str, job["output_id"]))
                if edge is None or edge.get("job_id") != job_id:
                    raise SimulatorBundleError("job-lineage-binding-mismatch")
                frames.append(
                    {
                        "frame_id": job["frame_id"],
                        "job_id": job_id,
                        "output_id": job["output_id"],
                        "worker_id": job["worker_id"],
                        "source_id": job["source_id"],
                        "transform_id": job["transform_id"],
                        "source_manifest_path": source["manifest_path"],
                        "source_manifest_sha256": source["manifest_sha256"],
                        "source_png_path": source["png_path"],
                        "source_png_sha256": source["png_sha256"],
                        "canonical_pixel_sha256": source["canonical_pixel_sha256"],
                        "config_sha256": _prefixed_digest(job["nominal_config_sha256"]),
                        "resource_sha256": _prefixed_digest(ordered_resources[0]["sha256"])
                        if ordered_resources
                        else None,
                        "output_path": output_path,
                        "output_sha256": output_sha256,
                        "output_size": len(output_bytes),
                        "display_path": display_path,
                        "display_sha256": display_sha256,
                        "display_size": len(display_bytes),
                        "declared_reference_manifest_path": reference_manifest_path,
                        "declared_reference_manifest_sha256": _prefixed_digest(
                            job["declared_reference_manifest_sha256"]
                        ),
                        "reference_buffer_path": reference_buffer_path,
                        "reference_buffer_sha256": reference_buffer_sha256,
                        "lineage_parent_artifact_id": edge["parent_artifact_id"],
                        "trace_id": job["trace_id"],
                        "last_operation_id": None,
                    }
                )

            derivative_edges = [
                edge
                for edge in cast(list[dict[str, Any]], source_lineage["edges"])
                if edge.get("edge_type") == "lossless-derivative/v1"
            ]
            derivative_artifacts = [
                artifact
                for artifact in cast(list[dict[str, Any]], source_lineage["artifacts"])
                if artifact.get("artifact_type") == "lossless-derivative"
            ]
            if len(derivative_edges) != 1 or len(derivative_artifacts) != 1:
                raise SimulatorBundleError("derivative-topology-invalid")
            derivative_edge = derivative_edges[0]
            derivative_artifact = derivative_artifacts[0]
            if derivative_edge["child_artifact_id"] != derivative_artifact["artifact_id"]:
                raise SimulatorBundleError("derivative-lineage-binding-mismatch")
            derivative_source = cast(Mapping[str, Any], batch["derivatives"][0])
            derivative_bytes = _read_relative(
                batch_root, cast(str, derivative_source["buffer_path"])
            )
            derivative_display_bytes = _read_relative(
                batch_root, cast(str, derivative_source["display_path"])
            )
            derivative_path = "runtime/derivatives/d0001/output.rgbf32"
            derivative_display_path = "runtime/derivatives/d0001/display.png"
            _write_relative(stage, derivative_path, derivative_bytes)
            _write_relative(stage, derivative_display_path, derivative_display_bytes)
            files.extend(
                (
                    _data_file(derivative_path, derivative_bytes, "derivative-output"),
                    _data_file(
                        derivative_display_path,
                        derivative_display_bytes,
                        "derivative-display",
                    ),
                )
            )
            parent_frame = next(
                (
                    frame
                    for frame in frames
                    if frame["output_id"] == derivative_edge["parent_artifact_id"]
                ),
                None,
            )
            if parent_frame is None:
                raise SimulatorBundleError("derivative-parent-unavailable")
            derivatives = [
                {
                    "artifact_id": derivative_artifact["artifact_id"],
                    "parent_artifact_id": derivative_edge["parent_artifact_id"],
                    "parent_job_id": parent_frame["job_id"],
                    "buffer_path": derivative_path,
                    "buffer_sha256": sha256_bytes(derivative_bytes),
                    "buffer_size": len(derivative_bytes),
                    "display_path": derivative_display_path,
                    "display_sha256": sha256_bytes(derivative_display_bytes),
                    "display_size": len(derivative_display_bytes),
                    "trace_id": parent_frame["trace_id"],
                    "last_operation_id": None,
                }
            ]

            lineage = copy.deepcopy(source_lineage)
            active_derivative = next(
                artifact
                for artifact in cast(list[dict[str, Any]], lineage["artifacts"])
                if artifact.get("artifact_type") == "lossless-derivative"
            )
            active_derivative.update(
                {
                    "buffer": derivative_path,
                    "sha256": sha256_bytes(derivative_bytes).removeprefix("sha256:"),
                    "display": derivative_display_path,
                    "display_sha256": sha256_bytes(derivative_display_bytes).removeprefix(
                        "sha256:"
                    ),
                }
            )
            lineage_sha256 = _write_document(stage, "manifests/lineage.json", lineage)
            lineage_raw = _read_relative(stage, "manifests/lineage.json")
            files.append(_data_file("manifests/lineage.json", lineage_raw, "lineage"))

            runtime = {
                "schema": "simulator-runtime-manifest/v1",
                "fixture_id": batch["fixture_id"],
                "generation": 1,
                "source_batch_id": batch["source_batch_id"],
                "source_batch_sha256": batch_sha256,
                "source_fixture_manifest_sha256": source_fixture_sha256,
                "previous_runtime_manifest_sha256": None,
                "declared_resource_manifest_sha256": declared["sha256"],
                "ocio_version": OCIO_VERSION,
                "resources": sorted(resources, key=lambda item: cast(str, item["worker_id"])),
                "frames": sorted(frames, key=lambda item: cast(str, item["frame_id"])),
                "derivatives": derivatives,
                "lineage": {"path": "manifests/lineage.json", "sha256": lineage_sha256},
                "files": sorted(files, key=lambda item: cast(str, item["path"])),
            }
            runtime_sha256 = _write_document(stage, "manifests/runtime.json", runtime)
            fixture_manifest = {
                "schema": "simulator-fixture-manifest/v1",
                "fixture_id": batch["fixture_id"],
                "fixture_version": batch["fixture_version"],
                "generation": 1,
                "source_batch_id": batch["source_batch_id"],
                "source_batch_sha256": batch_sha256,
                "source_fixture_manifest_sha256": source_fixture_sha256,
                "runtime_manifest_sha256": runtime_sha256,
                "lineage_manifest_sha256": lineage_sha256,
                "declared_resource_manifest_sha256": declared["sha256"],
                "ocio_version": OCIO_VERSION,
            }
            fixture_manifest_sha256 = _write_document(
                stage, "manifests/fixture.json", fixture_manifest
            )
            publication_identity = {
                "schema": "simulator-publication-identity/v1",
                "fixture_manifest_sha256": fixture_manifest_sha256,
                "runtime_manifest_sha256": runtime_sha256,
                "lineage_manifest_sha256": lineage_sha256,
                "generation": 1,
            }
            publication_id = (
                "publication:"
                f"{hashlib.sha256(canonical_json_bytes(publication_identity)).hexdigest()}"
            )
            pointer = {
                "schema": "simulator-publication-pointer/v1",
                "namespace": "colortrace-simulator",
                "publication_id": publication_id,
                "fixture_id": batch["fixture_id"],
                "generation": 1,
                "source_batch_id": batch["source_batch_id"],
                "source_batch_sha256": batch_sha256,
                "fixture_manifest_sha256": fixture_manifest_sha256,
                "runtime_manifest_sha256": runtime_sha256,
                "lineage_manifest_sha256": lineage_sha256,
                "declared_resource_manifest_sha256": declared["sha256"],
                "ocio_version": OCIO_VERSION,
                "candidate_seal_sha256": None,
                "previous_pointer_sha256": None,
                "operation_id": None,
                "prepared_at": _timestamp(self.clock()),
            }
            _validate_document(pointer)
            _audit_tree(stage)
            _freeze_tree(stage)
            final_root = self._publication_root(publication_id)
            if final_root.exists():
                raise SimulatorBundleError("bootstrap-publication-conflict")
            _rename_frozen_tree(stage, final_root)
            parent_fd = os.open(
                final_root.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            self.fault_hook("bootstrap-publication-durable")
            return pointer
        except BaseException:
            _remove_tree(stage)
            raise

    def _write_active_pointer(self, pointer: Mapping[str, Any]) -> str:
        _validate_document(pointer)
        raw = canonical_json_bytes(pointer)
        state = self.root / "state"
        state_fd = os.open(
            state,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        temporary = f".active.{secrets.token_hex(8)}.tmp"
        try:
            file_fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=state_fd,
            )
            try:
                _write_all(file_fd, raw)
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
            self.fault_hook("active-pointer-temp-durable")
            os.replace(temporary, "active.json", src_dir_fd=state_fd, dst_dir_fd=state_fd)
            self.fault_hook("active-pointer-replaced")
            os.fsync(state_fd)
        except OSError as error:
            try:
                os.unlink(temporary, dir_fd=state_fd)
            except OSError:
                pass
            raise SimulatorBundleError("active-pointer-write-failed") from error
        finally:
            os.close(state_fd)
        return sha256_bytes(raw)

    def _load_active_context(self) -> _ActiveContext:
        pointer = _read_document(
            self.root / "state",
            "active.json",
            schema="simulator-publication-pointer/v1",
        )
        pointer_raw = _read_relative(self.root / "state", "active.json")
        pointer_sha256 = sha256_bytes(pointer_raw)
        publication_root = self._publication_root(cast(str, pointer["publication_id"]))
        actual_files = set(_audit_tree(publication_root))
        fixture = _read_document(
            publication_root,
            "manifests/fixture.json",
            schema="simulator-fixture-manifest/v1",
        )
        runtime = _read_document(
            publication_root,
            "manifests/runtime.json",
            schema="simulator-runtime-manifest/v1",
        )
        lineage_path = _relative_path(cast(Mapping[str, Any], runtime["lineage"])["path"])
        lineage = _read_document(publication_root, lineage_path)
        fixture_sha256 = sha256_bytes(_read_relative(publication_root, "manifests/fixture.json"))
        runtime_sha256 = sha256_bytes(_read_relative(publication_root, "manifests/runtime.json"))
        lineage_sha256 = sha256_bytes(_read_relative(publication_root, lineage_path))
        expected_bindings = {
            "fixture_manifest_sha256": fixture_sha256,
            "runtime_manifest_sha256": runtime_sha256,
            "lineage_manifest_sha256": lineage_sha256,
        }
        if any(pointer[key] != value for key, value in expected_bindings.items()):
            raise SimulatorBundleError("active-pointer-binding-mismatch")
        if (
            fixture["runtime_manifest_sha256"] != runtime_sha256
            or fixture["lineage_manifest_sha256"] != lineage_sha256
            or runtime["lineage"]["sha256"] != lineage_sha256
            or fixture["generation"] != pointer["generation"]
            or runtime["generation"] != pointer["generation"]
        ):
            raise SimulatorBundleError("active-generation-binding-mismatch")
        expected_data_files: set[str] = set()
        for item in cast(list[dict[str, Any]], runtime["files"]):
            relative = _relative_path(item["path"])
            raw = _read_relative(publication_root, relative)
            if (
                sha256_bytes(raw) != _prefixed_digest(item["sha256"])
                or len(raw) != item["size"]
                or relative in expected_data_files
            ):
                raise SimulatorBundleError("runtime-file-binding-mismatch")
            expected_data_files.add(relative)
        baseline_controls = {
            "manifests/runtime.json",
            "manifests/fixture.json",
        }
        candidate_controls = baseline_controls | {
            "manifests/preservation.json",
            "manifests/safe-complement.json",
            "manifests/safe-complement-proof.json",
            "manifests/candidate-seal.json",
            "manifests/candidate-pointer.json",
        }
        if pointer["candidate_seal_sha256"] is None:
            if (
                pointer["generation"] != 1
                or pointer["operation_id"] is not None
                or pointer["previous_pointer_sha256"] is not None
            ):
                raise SimulatorBundleError("baseline-pointer-invalid")
            expected_publication_files = expected_data_files | baseline_controls
        else:
            prepared = self._prepared_from_root(
                publication_root,
                f"publications/{publication_root.name}",
            )
            if (
                prepared.candidate_pointer != pointer
                or prepared.candidate_pointer_sha256 != pointer_sha256
                or prepared.candidate_seal_sha256 != pointer["candidate_seal_sha256"]
                or prepared.candidate_generation != pointer["generation"]
            ):
                raise SimulatorBundleError("active-candidate-binding-mismatch")
            expected_publication_files = expected_data_files | candidate_controls
        if actual_files != expected_publication_files:
            raise SimulatorBundleError("publication-file-inventory-mismatch")
        source_batch_root = self._batch_root(cast(str, pointer["source_batch_id"]))
        source_batch = _read_document(
            source_batch_root,
            "source-batch.json",
            schema="simulator-source-batch/v1",
        )
        source_batch_sha256 = sha256_bytes(_read_relative(source_batch_root, "source-batch.json"))
        if (
            source_batch_sha256 != pointer["source_batch_sha256"]
            or source_batch_sha256 != runtime["source_batch_sha256"]
            or source_batch_sha256 != fixture["source_batch_sha256"]
        ):
            raise SimulatorBundleError("source-batch-binding-mismatch")
        expected_batch_files = {"source-batch.json"}
        for item in cast(list[dict[str, Any]], source_batch["files"]):
            relative = _relative_path(item["path"])
            raw = _read_relative(source_batch_root, relative)
            if sha256_bytes(raw) != item["sha256"] or len(raw) != item["size"]:
                raise SimulatorBundleError("source-batch-file-binding-mismatch")
            expected_batch_files.add(relative)
        if set(_audit_tree(source_batch_root)) != expected_batch_files:
            raise SimulatorBundleError("source-batch-inventory-mismatch")
        if (
            fixture["source_fixture_manifest_sha256"]
            != source_batch["source_fixture_manifest"]["sha256"]
            or pointer["declared_resource_manifest_sha256"]
            != source_batch["declared_resource_manifest"]["sha256"]
        ):
            raise SimulatorBundleError("fixture-source-binding-mismatch")
        return _ActiveContext(
            pointer=pointer,
            pointer_sha256=pointer_sha256,
            publication_root=publication_root,
            fixture=fixture,
            runtime=runtime,
            lineage=lineage,
            source_batch_root=source_batch_root,
            source_batch=source_batch,
        )

    @staticmethod
    def _command_intent(commands: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for command in commands:
            value = _plain_document(command)
            value.pop("action_envelope", None)
            result.append(value)
        return sorted(result, key=lambda item: cast(str, item.get("command_id", "")))

    @staticmethod
    def _target_identity(target: Mapping[str, Any]) -> tuple[str, str, str]:
        if (
            target.get("schema") != "simulator-target/v1"
            or target.get("namespace") != "colortrace-simulator"
        ):
            raise SimulatorBundleError("target-namespace-invalid")
        kind = cast(str, target.get("kind"))
        identifier = _identifier(target.get("id"), code="target-id-invalid")
        if kind not in {"color-resource", "frame", "derivative"}:
            raise SimulatorBundleError("target-kind-invalid")
        return "colortrace-simulator", kind, identifier

    def _resolve_action(
        self,
        runtime: Mapping[str, Any],
        commands: Sequence[Mapping[str, Any]],
    ) -> _ResolvedAction:
        command_values = [_plain_document(command) for command in commands]
        if len(command_values) != 5:
            raise SimulatorBundleError("command-profile-invalid")
        identifiers = [command.get("command_id") for command in command_values]
        if any(not isinstance(item, str) for item in identifiers) or len(set(identifiers)) != 5:
            raise SimulatorBundleError("command-id-invalid")
        quarantine_commands = [
            command
            for command in command_values
            if command.get("schema") == "simulator-quarantine-command/v1"
        ]
        rerender_commands = [
            command
            for command in command_values
            if command.get("schema") == "simulator-targeted-rerender-command/v1"
        ]
        if len(quarantine_commands) != 1 or len(rerender_commands) != 4:
            raise SimulatorBundleError("command-profile-invalid")
        quarantine = quarantine_commands[0]
        quarantine_target = cast(Mapping[str, Any], quarantine.get("target"))
        if self._target_identity(quarantine_target)[1] != "color-resource":
            raise SimulatorBundleError("quarantine-target-invalid")
        expected_resource = _prefixed_digest(quarantine.get("expected_resource_sha256"))
        if quarantine_target.get("id") != expected_resource:
            raise SimulatorBundleError("quarantine-resource-binding")
        if quarantine.get("mode") != "quarantine-and-install-approved-replacement":
            raise SimulatorBundleError("quarantine-mode-invalid")

        frames_by_id = {
            cast(str, frame["frame_id"]): frame
            for frame in cast(list[dict[str, Any]], runtime["frames"])
        }
        derivatives_by_id = {
            cast(str, derivative["artifact_id"]): derivative
            for derivative in cast(list[dict[str, Any]], runtime["derivatives"])
        }
        frame_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        derivative_pair: tuple[dict[str, Any], dict[str, Any]] | None = None
        for command in rerender_commands:
            target = cast(Mapping[str, Any], command.get("target"))
            _, kind, target_id = self._target_identity(target)
            if kind == "frame":
                frame = frames_by_id.get(target_id)
                if frame is None:
                    raise SimulatorBundleError("frame-target-unavailable")
                expected = {
                    "job_id": frame["job_id"],
                    "transform_id": frame["transform_id"],
                    "source_id": frame["source_id"],
                    "source_manifest_sha256": frame["source_manifest_sha256"],
                    "source_png_sha256": frame["source_png_sha256"],
                    "expected_config_sha256": frame["config_sha256"],
                    "expected_output_sha256": frame["output_sha256"],
                    "expected_display_sha256": frame["display_sha256"],
                    "lineage_parent_artifact_id": frame["lineage_parent_artifact_id"],
                }
                if any(command.get(key) != value for key, value in expected.items()):
                    raise SimulatorBundleError("frame-command-binding-mismatch")
                if (
                    frame["transform_id"] != "look/main/v1"
                    or frame["resource_sha256"] != expected_resource
                ):
                    raise SimulatorBundleError("frame-command-not-causal")
                frame_pairs.append((command, frame))
            elif kind == "derivative":
                derivative = derivatives_by_id.get(target_id)
                if derivative is None or derivative_pair is not None:
                    raise SimulatorBundleError("derivative-target-invalid")
                derivative_pair = (command, derivative)
            else:
                raise SimulatorBundleError("rerender-target-invalid")
        if len(frame_pairs) != 3 or derivative_pair is None:
            raise SimulatorBundleError("command-profile-invalid")
        frame_pairs.sort(key=lambda pair: cast(str, pair[0]["command_id"]))
        workers = {cast(str, frame["worker_id"]) for _, frame in frame_pairs}
        if len(workers) != 1:
            raise SimulatorBundleError("frame-worker-conflict")
        resource_records = [
            resource
            for resource in cast(list[dict[str, Any]], runtime["resources"])
            if resource["worker_id"] in workers and resource["resource_sha256"] == expected_resource
        ]
        if len(resource_records) != 1:
            raise SimulatorBundleError("causal-resource-ambiguous")
        resource_record = resource_records[0]

        derivative_command, derivative = derivative_pair
        parent_frame = next(
            (
                frame
                for _, frame in frame_pairs
                if frame["output_id"] == derivative["parent_artifact_id"]
            ),
            None,
        )
        if parent_frame is None:
            raise SimulatorBundleError("derivative-parent-not-targeted")
        derivative_expected = {
            "job_id": parent_frame["job_id"],
            "transform_id": parent_frame["transform_id"],
            "source_id": parent_frame["source_id"],
            "source_manifest_sha256": parent_frame["source_manifest_sha256"],
            "source_png_sha256": parent_frame["source_png_sha256"],
            "expected_config_sha256": parent_frame["config_sha256"],
            "expected_derivative_sha256": derivative["buffer_sha256"],
            "expected_derivative_display_sha256": derivative["display_sha256"],
            "lineage_parent_artifact_id": derivative["parent_artifact_id"],
        }
        if any(derivative_command.get(key) != value for key, value in derivative_expected.items()):
            raise SimulatorBundleError("derivative-command-binding-mismatch")

        mutable_entries: list[dict[str, Any]] = [
            {
                "kind": "resource",
                "id": expected_resource,
                "path": resource_record["resource_path"],
                "sha256": resource_record["resource_sha256"],
                "size": resource_record["resource_size"],
            }
        ]
        for _command, frame in frame_pairs:
            mutable_entries.extend(
                (
                    {
                        "kind": "frame-output",
                        "id": frame["frame_id"],
                        "path": frame["output_path"],
                        "sha256": frame["output_sha256"],
                        "size": frame["output_size"],
                    },
                    {
                        "kind": "frame-display",
                        "id": frame["frame_id"],
                        "path": frame["display_path"],
                        "sha256": frame["display_sha256"],
                        "size": frame["display_size"],
                    },
                )
            )
        mutable_entries.extend(
            (
                {
                    "kind": "derivative-output",
                    "id": derivative["artifact_id"],
                    "path": derivative["buffer_path"],
                    "sha256": derivative["buffer_sha256"],
                    "size": derivative["buffer_size"],
                },
                {
                    "kind": "derivative-display",
                    "id": derivative["artifact_id"],
                    "path": derivative["display_path"],
                    "sha256": derivative["display_sha256"],
                    "size": derivative["display_size"],
                },
            )
        )
        mutable_entries.sort(key=lambda item: (cast(str, item["path"]), cast(str, item["kind"])))
        mutable_paths = frozenset(cast(str, item["path"]) for item in mutable_entries)

        resource_invariant = {
            key: value
            for key, value in resource_record.items()
            if key not in {"resource_sha256", "resource_size", "trace_id", "last_operation_id"}
        }
        invariants: list[dict[str, Any]] = [
            {
                "kind": "resource",
                "id": expected_resource,
                "record_sha256": sha256_bytes(canonical_json_bytes(resource_invariant)),
            }
        ]
        for _command, frame in frame_pairs:
            invariant = {
                key: value
                for key, value in frame.items()
                if key
                not in {
                    "output_sha256",
                    "output_size",
                    "display_sha256",
                    "display_size",
                    "resource_sha256",
                    "trace_id",
                    "last_operation_id",
                    "processor_identity_sha256",
                }
            }
            invariants.append(
                {
                    "kind": "frame",
                    "id": frame["frame_id"],
                    "record_sha256": sha256_bytes(canonical_json_bytes(invariant)),
                }
            )
        derivative_invariant = {
            key: value
            for key, value in derivative.items()
            if key
            not in {
                "buffer_sha256",
                "buffer_size",
                "display_sha256",
                "display_size",
                "trace_id",
                "last_operation_id",
            }
        }
        invariants.append(
            {
                "kind": "derivative",
                "id": derivative["artifact_id"],
                "record_sha256": sha256_bytes(canonical_json_bytes(derivative_invariant)),
            }
        )
        quarantine_path = (
            f"runtime/quarantine/sha256/{expected_resource.removeprefix('sha256:')}.cube"
        )
        return _ResolvedAction(
            quarantine_command=quarantine,
            frame_pairs=tuple(frame_pairs),
            derivative_command=derivative_command,
            derivative_record=derivative,
            resource_record=resource_record,
            mutable_entries=tuple(mutable_entries),
            mutable_paths=mutable_paths,
            target_invariants=tuple(
                sorted(
                    invariants, key=lambda item: (cast(str, item["kind"]), cast(str, item["id"]))
                )
            ),
            quarantine_path=quarantine_path,
        )

    def _safe_complement(
        self,
        runtime: Mapping[str, Any],
        resolved: _ResolvedAction,
    ) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        for item in cast(list[dict[str, Any]], runtime["files"]):
            if (
                item["path"] in resolved.mutable_paths
                or item["path"] == "manifests/lineage.json"
                or item["path"] == resolved.quarantine_path
            ):
                continue
            files.append(
                {
                    "kind": item["kind"],
                    "id": item["path"],
                    "path": item["path"],
                    "sha256": item["sha256"],
                    "size": item["size"],
                }
            )
        targeted_frames = {frame["frame_id"] for _, frame in resolved.frame_pairs}
        records: list[dict[str, Any]] = []
        for resource in cast(list[dict[str, Any]], runtime["resources"]):
            if resource["worker_id"] == resolved.resource_record["worker_id"]:
                continue
            records.append(
                {
                    "kind": "resource",
                    "id": resource["worker_id"],
                    "record_sha256": sha256_bytes(canonical_json_bytes(resource)),
                }
            )
        for frame in cast(list[dict[str, Any]], runtime["frames"]):
            if frame["frame_id"] in targeted_frames:
                continue
            records.append(
                {
                    "kind": "frame",
                    "id": frame["frame_id"],
                    "record_sha256": sha256_bytes(canonical_json_bytes(frame)),
                }
            )
        return {
            "schema": "simulator-safe-complement/v1",
            "fixture_id": runtime["fixture_id"],
            "source_batch_id": runtime["source_batch_id"],
            "source_batch_sha256": runtime["source_batch_sha256"],
            "files": sorted(files, key=lambda item: cast(str, item["path"])),
            "records": sorted(
                records,
                key=lambda item: (cast(str, item["kind"]), cast(str, item["id"])),
            ),
        }

    def _action_documents(
        self,
        context: _ActiveContext,
        commands: Sequence[Mapping[str, Any]],
        targets: Sequence[Mapping[str, Any]],
        exclusions: Sequence[Mapping[str, Any]],
    ) -> tuple[_ResolvedAction, dict[str, Any], str, dict[str, Any], str]:
        resolved = self._resolve_action(context.runtime, commands)
        command_targets = {
            self._target_identity(cast(Mapping[str, Any], command["target"]))
            for command in commands
        }
        target_set = {self._target_identity(target) for target in targets}
        exclusion_set = {self._target_identity(target) for target in exclusions}
        if command_targets != target_set or target_set & exclusion_set:
            raise SimulatorBundleError("target-command-binding-mismatch")
        safe_target_ids = {
            cast(str, frame["frame_id"])
            for frame in cast(list[dict[str, Any]], context.runtime["frames"])
            if frame["frame_id"] not in {item[1] for item in target_set}
        }
        if any(
            kind != "frame" or identifier not in safe_target_ids
            for _, kind, identifier in exclusion_set
        ):
            raise SimulatorBundleError("exclusion-binding-mismatch")
        safe = self._safe_complement(context.runtime, resolved)
        _validate_document(safe)
        safe_sha256 = _document_digest(safe)
        command_intent = self._command_intent(commands)
        preservation = {
            "schema": "simulator-preservation-manifest/v1",
            "fixture_id": context.runtime["fixture_id"],
            "baseline_pointer_sha256": context.pointer_sha256,
            "baseline_generation": context.pointer["generation"],
            "fixture_manifest_sha256": context.pointer["fixture_manifest_sha256"],
            "runtime_manifest_sha256": context.pointer["runtime_manifest_sha256"],
            "lineage_manifest_sha256": context.pointer["lineage_manifest_sha256"],
            "command_intent_sha256": sha256_bytes(canonical_json_bytes(command_intent)),
            "targets_sha256": sha256_bytes(canonical_json_bytes(list(targets))),
            "exclusions_sha256": sha256_bytes(canonical_json_bytes(list(exclusions))),
            "mutable_entries": list(resolved.mutable_entries),
            "metadata_reseal_paths": [
                "manifests/fixture.json",
                "manifests/lineage.json",
                "manifests/runtime.json",
            ],
            "allowed_additions": [
                {
                    "kind": "quarantine",
                    "path": resolved.quarantine_path,
                    "sha256": resolved.resource_record["resource_sha256"],
                }
            ],
            "target_invariants": list(resolved.target_invariants),
            "safe_complement_sha256": safe_sha256,
        }
        _validate_document(preservation)
        return resolved, safe, safe_sha256, preservation, _document_digest(preservation)

    def plan_bindings(
        self,
        *,
        commands: Sequence[Mapping[str, Any]],
        targets: Sequence[Mapping[str, Any]],
        exclusions: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        context = self._load_active_context()
        resolved, safe, safe_sha256, preservation, preservation_sha256 = self._action_documents(
            context,
            commands,
            targets,
            exclusions,
        )
        declared = cast(Mapping[str, Any], context.source_batch["declared_resource_manifest"])
        envelope = {
            "schema": "simulator-action-envelope/v1",
            "fixture_id": context.pointer["fixture_id"],
            "fixture_manifest_sha256": context.pointer["fixture_manifest_sha256"],
            "fixture_generation": context.pointer["generation"],
            "source_batch_id": context.pointer["source_batch_id"],
            "source_batch_sha256": context.pointer["source_batch_sha256"],
            "runtime_manifest_sha256": context.pointer["runtime_manifest_sha256"],
            "runtime_generation": context.pointer["generation"],
            "expected_publication_pointer_sha256": context.pointer_sha256,
            "expected_publication_generation": context.pointer["generation"],
            "expected_resource_sha256": resolved.resource_record["resource_sha256"],
            "replacement_resource_logical_path": "luts/show_look.cube",
            "replacement_resource_sha256": declared["approved_resource_sha256"],
            "declared_resource_manifest_sha256": declared["sha256"],
            "ocio_version": OCIO_VERSION,
            "preservation_manifest_sha256": preservation_sha256,
            "safe_complement_sha256": safe_sha256,
            "lineage_manifest_sha256": context.pointer["lineage_manifest_sha256"],
            "lineage_generation": context.pointer["generation"],
        }
        return {
            "envelope": envelope,
            "preservation_manifest": preservation,
            "safe_complement_manifest": safe,
        }

    def canonical_plan_inputs(self) -> dict[str, Any]:
        context = self._load_active_context()
        declared = cast(Mapping[str, Any], context.source_batch["declared_resource_manifest"])
        approved_sha256 = cast(str, declared["approved_resource_sha256"])
        candidate_resources = [
            resource
            for resource in cast(list[dict[str, Any]], context.runtime["resources"])
            if resource["resource_sha256"] != approved_sha256
        ]
        if len(candidate_resources) != 1:
            raise SimulatorBundleError("canonical-causal-resource-ambiguous")
        causal = candidate_resources[0]
        affected_frames = sorted(
            (
                frame
                for frame in cast(list[dict[str, Any]], context.runtime["frames"])
                if frame["resource_sha256"] == causal["resource_sha256"]
                and frame["transform_id"] == "look/main/v1"
            ),
            key=lambda frame: cast(str, frame["frame_id"]),
        )
        if len(affected_frames) != 3:
            raise SimulatorBundleError("canonical-affected-frame-topology-invalid")
        derivative = cast(dict[str, Any], context.runtime["derivatives"][0])
        parent_frame = next(
            (
                frame
                for frame in affected_frames
                if frame["output_id"] == derivative["parent_artifact_id"]
            ),
            None,
        )
        if parent_frame is None:
            raise SimulatorBundleError("canonical-derivative-parent-invalid")

        def target(kind: str, identifier: str) -> dict[str, str]:
            return {
                "schema": "simulator-target/v1",
                "namespace": "colortrace-simulator",
                "kind": kind,
                "id": identifier,
            }

        resource_target = target("color-resource", cast(str, causal["resource_sha256"]))
        frame_targets = [target("frame", cast(str, frame["frame_id"])) for frame in affected_frames]
        derivative_target = target("derivative", cast(str, derivative["artifact_id"]))
        targets: list[dict[str, str]] = [resource_target, *frame_targets, derivative_target]
        affected_ids = {cast(str, frame["frame_id"]) for frame in affected_frames}
        exclusions = [
            target("frame", cast(str, frame["frame_id"]))
            for frame in sorted(
                cast(list[dict[str, Any]], context.runtime["frames"]),
                key=lambda frame: cast(str, frame["frame_id"]),
            )
            if frame["frame_id"] not in affected_ids
        ]

        def command_id(prefix: str, identifier: str) -> str:
            suffix = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:16]
            return f"{prefix}-{suffix}"

        commands: list[dict[str, Any]] = [
            {
                "schema": "simulator-quarantine-command/v1",
                "command_id": command_id("quarantine-resource", resource_target["id"]),
                "namespace": "colortrace-simulator",
                "target": resource_target,
                "expected_resource_sha256": causal["resource_sha256"],
                "mode": "quarantine-and-install-approved-replacement",
            }
        ]
        for frame, frame_target in zip(affected_frames, frame_targets, strict=True):
            commands.append(
                {
                    "schema": "simulator-targeted-rerender-command/v1",
                    "command_id": command_id("rerender-frame", frame_target["id"]),
                    "namespace": "colortrace-simulator",
                    "target": frame_target,
                    "job_id": frame["job_id"],
                    "transform_id": frame["transform_id"],
                    "source_id": frame["source_id"],
                    "source_manifest_sha256": frame["source_manifest_sha256"],
                    "source_png_sha256": frame["source_png_sha256"],
                    "expected_config_sha256": frame["config_sha256"],
                    "expected_output_sha256": frame["output_sha256"],
                    "expected_display_sha256": frame["display_sha256"],
                    "lineage_parent_artifact_id": frame["lineage_parent_artifact_id"],
                }
            )
        commands.append(
            {
                "schema": "simulator-targeted-rerender-command/v1",
                "command_id": command_id("rerender-derivative", derivative_target["id"]),
                "namespace": "colortrace-simulator",
                "target": derivative_target,
                "job_id": parent_frame["job_id"],
                "transform_id": parent_frame["transform_id"],
                "source_id": parent_frame["source_id"],
                "source_manifest_sha256": parent_frame["source_manifest_sha256"],
                "source_png_sha256": parent_frame["source_png_sha256"],
                "expected_config_sha256": parent_frame["config_sha256"],
                "expected_derivative_sha256": derivative["buffer_sha256"],
                "expected_derivative_display_sha256": derivative["display_sha256"],
                "lineage_parent_artifact_id": derivative["parent_artifact_id"],
            }
        )
        bindings = self.plan_bindings(
            commands=commands,
            targets=targets,
            exclusions=exclusions,
        )
        envelope = cast(Mapping[str, Any], bindings["envelope"])
        typed_commands = [{**command, "action_envelope": envelope} for command in commands]
        return {
            "targets": targets,
            "exclusions": exclusions,
            "commands": typed_commands,
            **bindings,
        }

    def snapshot_for_action(self, action: BoundSimulatorAction) -> ActionSnapshot:
        context = self._load_active_context()
        if not action.commands:
            raise SimulatorBundleError("commands-empty")
        envelopes = {
            canonical_json_bytes(command.get("action_envelope")) for command in action.commands
        }
        if len(envelopes) != 1:
            raise SimulatorBundleError("action-envelope-conflict")
        envelope_value = action.commands[0].get("action_envelope")
        if not isinstance(envelope_value, Mapping):
            raise SimulatorBundleError("action-envelope-invalid")
        envelope = cast(Mapping[str, Any], envelope_value)
        if sha256_bytes(canonical_json_bytes(envelope)) != action.action_envelope_sha256:
            raise SimulatorBundleError("action-envelope-digest-mismatch")
        if sha256_bytes(canonical_json_bytes(list(action.commands))) != action.commands_sha256:
            raise SimulatorBundleError("commands-digest-mismatch")
        if sha256_bytes(canonical_json_bytes(list(action.targets))) != action.targets_sha256:
            raise SimulatorBundleError("targets-digest-mismatch")
        if sha256_bytes(canonical_json_bytes(list(action.exclusions))) != action.exclusions_sha256:
            raise SimulatorBundleError("exclusions-digest-mismatch")
        _resolved, safe, safe_sha256, preservation, preservation_sha256 = self._action_documents(
            context,
            action.commands,
            action.targets,
            action.exclusions,
        )
        expected = {
            "fixture_id": context.pointer["fixture_id"],
            "fixture_manifest_sha256": context.pointer["fixture_manifest_sha256"],
            "fixture_generation": context.pointer["generation"],
            "source_batch_id": context.pointer["source_batch_id"],
            "source_batch_sha256": context.pointer["source_batch_sha256"],
            "runtime_manifest_sha256": context.pointer["runtime_manifest_sha256"],
            "runtime_generation": context.pointer["generation"],
            "expected_publication_pointer_sha256": context.pointer_sha256,
            "expected_publication_generation": context.pointer["generation"],
            "declared_resource_manifest_sha256": context.pointer[
                "declared_resource_manifest_sha256"
            ],
            "ocio_version": OCIO_VERSION,
            "preservation_manifest_sha256": preservation_sha256,
            "safe_complement_sha256": safe_sha256,
            "lineage_manifest_sha256": context.pointer["lineage_manifest_sha256"],
            "lineage_generation": context.pointer["generation"],
        }
        if any(envelope.get(key) != value for key, value in expected.items()):
            raise SimulatorBundleError("action-envelope-stale")
        declared = cast(Mapping[str, Any], context.source_batch["declared_resource_manifest"])
        if (
            envelope.get("replacement_resource_logical_path") != "luts/show_look.cube"
            or envelope.get("replacement_resource_sha256") != declared["approved_resource_sha256"]
            or envelope.get("expected_resource_sha256")
            == envelope.get("replacement_resource_sha256")
        ):
            raise SimulatorBundleError("replacement-resource-binding-mismatch")
        return ActionSnapshot(
            action=action,
            predecessor_pointer=context.pointer,
            predecessor_pointer_sha256=context.pointer_sha256,
            predecessor_generation=cast(int, context.pointer["generation"]),
            source_batch_id=cast(str, context.pointer["source_batch_id"]),
            source_batch_sha256=cast(str, context.pointer["source_batch_sha256"]),
            fixture_manifest_sha256=cast(str, context.pointer["fixture_manifest_sha256"]),
            runtime_manifest_sha256=cast(str, context.pointer["runtime_manifest_sha256"]),
            lineage_manifest_sha256=cast(str, context.pointer["lineage_manifest_sha256"]),
            declared_resource_manifest_sha256=cast(
                str, context.pointer["declared_resource_manifest_sha256"]
            ),
            preservation_manifest=preservation,
            preservation_manifest_sha256=preservation_sha256,
            safe_complement_manifest=safe,
            safe_complement_before_sha256=safe_sha256,
        )

    @staticmethod
    def _replace_file_entry(
        files: list[dict[str, Any]],
        *,
        path: str,
        value: bytes,
        kind: str,
    ) -> None:
        files[:] = [item for item in files if item["path"] != path]
        files.append(_data_file(path, value, kind))
        files.sort(key=lambda item: cast(str, item["path"]))

    def _candidate_invariants(
        self,
        runtime: Mapping[str, Any],
        resolved: _ResolvedAction,
    ) -> tuple[dict[str, Any], ...]:
        target_frame_ids = {frame["frame_id"] for _, frame in resolved.frame_pairs}
        values: list[dict[str, Any]] = []
        resource = next(
            item
            for item in cast(list[dict[str, Any]], runtime["resources"])
            if item["worker_id"] == resolved.resource_record["worker_id"]
        )
        resource_projection = {
            key: value
            for key, value in resource.items()
            if key not in {"resource_sha256", "resource_size", "trace_id", "last_operation_id"}
        }
        values.append(
            {
                "kind": "resource",
                "id": resolved.resource_record["resource_sha256"],
                "record_sha256": sha256_bytes(canonical_json_bytes(resource_projection)),
            }
        )
        for frame in cast(list[dict[str, Any]], runtime["frames"]):
            if frame["frame_id"] not in target_frame_ids:
                continue
            projection = {
                key: value
                for key, value in frame.items()
                if key
                not in {
                    "output_sha256",
                    "output_size",
                    "display_sha256",
                    "display_size",
                    "resource_sha256",
                    "trace_id",
                    "last_operation_id",
                    "processor_identity_sha256",
                }
            }
            values.append(
                {
                    "kind": "frame",
                    "id": frame["frame_id"],
                    "record_sha256": sha256_bytes(canonical_json_bytes(projection)),
                }
            )
        derivative = next(
            item
            for item in cast(list[dict[str, Any]], runtime["derivatives"])
            if item["artifact_id"] == resolved.derivative_record["artifact_id"]
        )
        derivative_projection = {
            key: value
            for key, value in derivative.items()
            if key
            not in {
                "buffer_sha256",
                "buffer_size",
                "display_sha256",
                "display_size",
                "trace_id",
                "last_operation_id",
            }
        }
        values.append(
            {
                "kind": "derivative",
                "id": derivative["artifact_id"],
                "record_sha256": sha256_bytes(canonical_json_bytes(derivative_projection)),
            }
        )
        return tuple(
            sorted(values, key=lambda item: (cast(str, item["kind"]), cast(str, item["id"])))
        )

    def prepare(
        self,
        snapshot: ActionSnapshot,
        trace_ids: Mapping[str, str],
    ) -> PreparedPublication:
        operation_id = _identifier(
            snapshot.action.identity.operation_id,
            code="operation-id-invalid",
        )
        command_ids = {cast(str, command["command_id"]) for command in snapshot.action.commands}
        if set(trace_ids) != command_ids:
            raise SimulatorBundleError("trace-id-command-binding-mismatch")
        trace_values = list(trace_ids.values())
        if len(set(trace_values)) != 5 or any(
            _TRACE_ID.fullmatch(value) is None for value in trace_values
        ):
            raise SimulatorBundleError("trace-id-invalid")
        existing = self.inspect_operation(operation_id)
        if existing.prepared is not None:
            return existing.prepared
        context = self._load_active_context()
        if (
            context.pointer_sha256 != snapshot.predecessor_pointer_sha256
            or context.pointer["generation"] != snapshot.predecessor_generation
            or context.pointer != snapshot.predecessor_pointer
        ):
            raise SimulatorBundleError("snapshot-stale")
        resolved, safe_before, safe_before_sha256, preservation, preservation_sha256 = (
            self._action_documents(
                context,
                snapshot.action.commands,
                snapshot.action.targets,
                snapshot.action.exclusions,
            )
        )
        if (
            safe_before_sha256 != snapshot.safe_complement_before_sha256
            or preservation_sha256 != snapshot.preservation_manifest_sha256
            or preservation != snapshot.preservation_manifest
            or safe_before != snapshot.safe_complement_manifest
        ):
            raise SimulatorBundleError("snapshot-document-mismatch")
        old_trace_ids = {
            cast(str, item["trace_id"])
            for collection in ("resources", "frames", "derivatives")
            for item in cast(list[dict[str, Any]], context.runtime[collection])
            if item.get("trace_id") is not None
        }
        if old_trace_ids & set(trace_values):
            raise SimulatorBundleError("trace-id-not-fresh")

        candidate_token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        candidate_ref = f"staging/prep-{candidate_token}"
        stage = self.root / candidate_ref
        if stage.exists():
            raise SimulatorBundleError("candidate-ref-conflict")
        stage.mkdir(parents=True, mode=0o700)
        prepared_at = _timestamp(self.clock())
        try:
            for item in cast(list[dict[str, Any]], context.runtime["files"]):
                relative = _relative_path(item["path"])
                _copy_relative(context.publication_root, relative, stage, relative)
            self.fault_hook("candidate-copied")

            candidate_runtime = copy.deepcopy(context.runtime)
            candidate_runtime["generation"] = snapshot.predecessor_generation + 1
            candidate_runtime["previous_runtime_manifest_sha256"] = context.pointer[
                "runtime_manifest_sha256"
            ]
            candidate_files = cast(list[dict[str, Any]], candidate_runtime["files"])
            resource_record = next(
                resource
                for resource in cast(list[dict[str, Any]], candidate_runtime["resources"])
                if resource["worker_id"] == resolved.resource_record["worker_id"]
            )
            old_resource = _read_relative(stage, cast(str, resource_record["resource_path"]))
            if sha256_bytes(old_resource) != resource_record["resource_sha256"]:
                raise SimulatorBundleError("candidate-resource-drift")
            _write_relative(stage, resolved.quarantine_path, old_resource)
            self._replace_file_entry(
                candidate_files,
                path=resolved.quarantine_path,
                value=old_resource,
                kind="quarantine",
            )
            approved_pointer = cast(Mapping[str, Any], context.source_batch["approved_resource"])
            approved_bytes = _read_relative(
                context.source_batch_root,
                cast(str, approved_pointer["path"]),
            )
            approved_sha256 = sha256_bytes(approved_bytes)
            envelope = cast(Mapping[str, Any], snapshot.action.commands[0]["action_envelope"])
            if (
                approved_sha256 != approved_pointer["sha256"]
                or approved_sha256 != envelope["replacement_resource_sha256"]
            ):
                raise SimulatorBundleError("approved-resource-drift")
            resource_path = cast(str, resource_record["resource_path"])
            _write_relative(stage, resource_path, approved_bytes)
            self._replace_file_entry(
                candidate_files,
                path=resource_path,
                value=approved_bytes,
                kind="resource",
            )
            resource_record["resource_sha256"] = approved_sha256
            resource_record["resource_size"] = len(approved_bytes)
            resource_record["trace_id"] = trace_ids[
                cast(str, resolved.quarantine_command["command_id"])
            ]
            resource_record["last_operation_id"] = operation_id
            self.fault_hook("candidate-resource-replaced")

            config_root_path = (stage / resource_path).parent.parent
            verified_config = VerifiedPrivateConfigRoot.verify(
                root=config_root_path,
                config_path=stage / cast(str, resource_record["config_path"]),
                lut_path=stage / resource_path,
                expected_config_sha256=cast(str, resource_record["config_sha256"]),
                expected_resource_sha256=approved_sha256,
            )
            candidate_frames = {
                cast(str, frame["frame_id"]): frame
                for frame in cast(list[dict[str, Any]], candidate_runtime["frames"])
            }
            command_results: list[dict[str, Any]] = [
                {
                    "schema": "simulator-command-result/v1",
                    "command_id": resolved.quarantine_command["command_id"],
                    "result_kind": "quarantine",
                    "target": resolved.quarantine_command["target"],
                    "trace_id": trace_ids[cast(str, resolved.quarantine_command["command_id"])],
                    "before": {"resource_sha256": resolved.resource_record["resource_sha256"]},
                    "after": {"resource_sha256": approved_sha256},
                }
            ]
            for command, baseline_frame in resolved.frame_pairs:
                frame = candidate_frames[cast(str, baseline_frame["frame_id"])]
                source_png = _read_relative(
                    context.source_batch_root,
                    cast(str, frame["source_png_path"]),
                )
                rendered = self.renderer.render_frame(
                    verified_config,
                    FrameRenderRequest(
                        frame_id=cast(str, frame["frame_id"]),
                        job_id=cast(str, frame["job_id"]),
                        source_id=cast(str, frame["source_id"]),
                        source_png=source_png,
                        source_png_sha256=cast(str, frame["source_png_sha256"]),
                        canonical_pixel_sha256=cast(str, frame["canonical_pixel_sha256"]),
                        transform_id=cast(str, frame["transform_id"]),
                        trace_id=trace_ids[cast(str, command["command_id"])],
                    ),
                )
                reference_bytes = _read_relative(
                    context.source_batch_root,
                    cast(str, frame["reference_buffer_path"]),
                )
                if (
                    sha256_bytes(reference_bytes) != frame["reference_buffer_sha256"]
                    or rendered.output_sha256 != frame["reference_buffer_sha256"]
                ):
                    raise SimulatorBundleError("candidate-reference-integrity-mismatch")
                _write_relative(stage, cast(str, frame["output_path"]), rendered.output_buffer)
                _write_relative(stage, cast(str, frame["display_path"]), rendered.display_png)
                self._replace_file_entry(
                    candidate_files,
                    path=cast(str, frame["output_path"]),
                    value=rendered.output_buffer,
                    kind="frame-output",
                )
                self._replace_file_entry(
                    candidate_files,
                    path=cast(str, frame["display_path"]),
                    value=rendered.display_png,
                    kind="frame-display",
                )
                frame["resource_sha256"] = approved_sha256
                frame["output_sha256"] = rendered.output_sha256
                frame["output_size"] = len(rendered.output_buffer)
                frame["display_sha256"] = rendered.display_sha256
                frame["display_size"] = len(rendered.display_png)
                frame["trace_id"] = rendered.trace_id
                frame["last_operation_id"] = operation_id
                frame["processor_identity_sha256"] = rendered.processor_identity_sha256
                command_results.append(
                    {
                        "schema": "simulator-command-result/v1",
                        "command_id": command["command_id"],
                        "result_kind": "frame",
                        "target": command["target"],
                        "trace_id": rendered.trace_id,
                        "before": {
                            "output_sha256": baseline_frame["output_sha256"],
                            "display_sha256": baseline_frame["display_sha256"],
                        },
                        "after": {
                            "output_sha256": rendered.output_sha256,
                            "display_sha256": rendered.display_sha256,
                        },
                    }
                )
                self.fault_hook(f"candidate-frame-rendered:{frame['frame_id']}")

            candidate_derivative = cast(dict[str, Any], candidate_runtime["derivatives"][0])
            parent = next(
                frame
                for frame in cast(list[dict[str, Any]], candidate_runtime["frames"])
                if frame["output_id"] == candidate_derivative["parent_artifact_id"]
            )
            derivative_bytes = _read_relative(stage, cast(str, parent["output_path"]))
            derivative_display = _read_relative(stage, cast(str, parent["display_path"]))
            _write_relative(
                stage,
                cast(str, candidate_derivative["buffer_path"]),
                derivative_bytes,
            )
            _write_relative(
                stage,
                cast(str, candidate_derivative["display_path"]),
                derivative_display,
            )
            self._replace_file_entry(
                candidate_files,
                path=cast(str, candidate_derivative["buffer_path"]),
                value=derivative_bytes,
                kind="derivative-output",
            )
            self._replace_file_entry(
                candidate_files,
                path=cast(str, candidate_derivative["display_path"]),
                value=derivative_display,
                kind="derivative-display",
            )
            derivative_trace_id = trace_ids[cast(str, resolved.derivative_command["command_id"])]
            candidate_derivative["buffer_sha256"] = sha256_bytes(derivative_bytes)
            candidate_derivative["buffer_size"] = len(derivative_bytes)
            candidate_derivative["display_sha256"] = sha256_bytes(derivative_display)
            candidate_derivative["display_size"] = len(derivative_display)
            candidate_derivative["trace_id"] = derivative_trace_id
            candidate_derivative["last_operation_id"] = operation_id
            command_results.append(
                {
                    "schema": "simulator-command-result/v1",
                    "command_id": resolved.derivative_command["command_id"],
                    "result_kind": "derivative",
                    "target": resolved.derivative_command["target"],
                    "trace_id": derivative_trace_id,
                    "before": {
                        "derivative_sha256": resolved.derivative_record["buffer_sha256"],
                        "derivative_display_sha256": resolved.derivative_record["display_sha256"],
                    },
                    "after": {
                        "derivative_sha256": candidate_derivative["buffer_sha256"],
                        "derivative_display_sha256": candidate_derivative["display_sha256"],
                    },
                }
            )
            self.fault_hook("candidate-derivative-built")

            candidate_lineage = copy.deepcopy(context.lineage)
            lineage_derivative = next(
                artifact
                for artifact in cast(list[dict[str, Any]], candidate_lineage["artifacts"])
                if artifact.get("artifact_id") == candidate_derivative["artifact_id"]
            )
            lineage_derivative.update(
                {
                    "buffer": candidate_derivative["buffer_path"],
                    "sha256": cast(str, candidate_derivative["buffer_sha256"]).removeprefix(
                        "sha256:"
                    ),
                    "display": candidate_derivative["display_path"],
                    "display_sha256": cast(
                        str, candidate_derivative["display_sha256"]
                    ).removeprefix("sha256:"),
                }
            )
            lineage_sha256 = _write_document(
                stage,
                "manifests/lineage.json",
                candidate_lineage,
            )
            lineage_raw = _read_relative(stage, "manifests/lineage.json")
            self._replace_file_entry(
                candidate_files,
                path="manifests/lineage.json",
                value=lineage_raw,
                kind="lineage",
            )
            candidate_runtime["lineage"] = {
                "path": "manifests/lineage.json",
                "sha256": lineage_sha256,
            }
            if (
                self._candidate_invariants(candidate_runtime, resolved)
                != resolved.target_invariants
            ):
                raise SimulatorBundleError("candidate-target-invariant-drift")
            safe_after = self._safe_complement(candidate_runtime, resolved)
            safe_after_sha256 = _document_digest(safe_after)
            if safe_after_sha256 != safe_before_sha256 or safe_after != safe_before:
                raise SimulatorBundleError("safe-complement-changed")
            runtime_sha256 = _write_document(
                stage,
                "manifests/runtime.json",
                candidate_runtime,
            )
            fixture_manifest = {
                "schema": "simulator-fixture-manifest/v1",
                "fixture_id": candidate_runtime["fixture_id"],
                "fixture_version": context.fixture["fixture_version"],
                "generation": candidate_runtime["generation"],
                "source_batch_id": candidate_runtime["source_batch_id"],
                "source_batch_sha256": candidate_runtime["source_batch_sha256"],
                "source_fixture_manifest_sha256": candidate_runtime[
                    "source_fixture_manifest_sha256"
                ],
                "runtime_manifest_sha256": runtime_sha256,
                "lineage_manifest_sha256": lineage_sha256,
                "declared_resource_manifest_sha256": candidate_runtime[
                    "declared_resource_manifest_sha256"
                ],
                "ocio_version": OCIO_VERSION,
            }
            fixture_manifest_sha256 = _write_document(
                stage,
                "manifests/fixture.json",
                fixture_manifest,
            )
            _write_document(stage, "manifests/preservation.json", preservation)
            _write_document(stage, "manifests/safe-complement.json", safe_before)
            safe_proof = {
                "schema": "simulator-safe-complement-proof/v1",
                "preservation_manifest_sha256": preservation_sha256,
                "before_sha256": safe_before_sha256,
                "after_sha256": safe_after_sha256,
                "byte_identical": True,
            }
            safe_proof_sha256 = _write_document(
                stage,
                "manifests/safe-complement-proof.json",
                safe_proof,
            )
            command_results.sort(key=lambda item: cast(str, item["command_id"]))
            quarantine = {
                "schema": "simulator-quarantine-result/v1",
                "logical_path": "luts/show_look.cube",
                "source_generation": snapshot.predecessor_generation,
                "resource_sha256": resolved.resource_record["resource_sha256"],
                "replacement_sha256": approved_sha256,
                "quarantine_path": resolved.quarantine_path,
                "size": len(old_resource),
            }
            candidate_tree_sha256 = _tree_digest(stage)
            publication_identity = {
                "schema": "simulator-publication-identity/v1",
                "operation_id": operation_id,
                "predecessor_pointer_sha256": snapshot.predecessor_pointer_sha256,
                "runtime_manifest_sha256": runtime_sha256,
                "lineage_manifest_sha256": lineage_sha256,
                "candidate_tree_sha256": candidate_tree_sha256,
            }
            publication_id = (
                "publication:"
                f"{hashlib.sha256(canonical_json_bytes(publication_identity)).hexdigest()}"
            )
            seal = {
                "schema": "simulator-candidate-seal/v1",
                "operation_id": operation_id,
                "publication_id": publication_id,
                "predecessor_pointer": snapshot.predecessor_pointer,
                "predecessor_pointer_sha256": snapshot.predecessor_pointer_sha256,
                "predecessor_generation": snapshot.predecessor_generation,
                "candidate_generation": snapshot.predecessor_generation + 1,
                "source_batch_id": snapshot.source_batch_id,
                "source_batch_sha256": snapshot.source_batch_sha256,
                "fixture_manifest_sha256": fixture_manifest_sha256,
                "runtime_manifest_sha256": runtime_sha256,
                "lineage_manifest_sha256": lineage_sha256,
                "declared_resource_manifest_sha256": snapshot.declared_resource_manifest_sha256,
                "preservation_manifest_sha256": preservation_sha256,
                "safe_complement_before_sha256": safe_before_sha256,
                "safe_complement_after_sha256": safe_after_sha256,
                "safe_complement_proof_sha256": safe_proof_sha256,
                "commands_sha256": snapshot.action.commands_sha256,
                "targets_sha256": snapshot.action.targets_sha256,
                "exclusions_sha256": snapshot.action.exclusions_sha256,
                "candidate_tree_sha256": candidate_tree_sha256,
                "quarantine": quarantine,
                "command_results": command_results,
                "prepared_at": prepared_at,
            }
            candidate_seal_sha256 = _write_document(
                stage,
                "manifests/candidate-seal.json",
                seal,
            )
            candidate_pointer = {
                "schema": "simulator-publication-pointer/v1",
                "namespace": "colortrace-simulator",
                "publication_id": publication_id,
                "fixture_id": candidate_runtime["fixture_id"],
                "generation": candidate_runtime["generation"],
                "source_batch_id": snapshot.source_batch_id,
                "source_batch_sha256": snapshot.source_batch_sha256,
                "fixture_manifest_sha256": fixture_manifest_sha256,
                "runtime_manifest_sha256": runtime_sha256,
                "lineage_manifest_sha256": lineage_sha256,
                "declared_resource_manifest_sha256": snapshot.declared_resource_manifest_sha256,
                "ocio_version": OCIO_VERSION,
                "candidate_seal_sha256": candidate_seal_sha256,
                "previous_pointer_sha256": snapshot.predecessor_pointer_sha256,
                "operation_id": operation_id,
                "prepared_at": prepared_at,
            }
            candidate_pointer_sha256 = _write_document(
                stage,
                "manifests/candidate-pointer.json",
                candidate_pointer,
            )
            _audit_tree(stage)
            _freeze_tree(stage)
            self.fault_hook("candidate-sealed")
            return PreparedPublication(
                operation_id=operation_id,
                publication_id=publication_id,
                predecessor_pointer=snapshot.predecessor_pointer,
                predecessor_pointer_sha256=snapshot.predecessor_pointer_sha256,
                predecessor_generation=snapshot.predecessor_generation,
                candidate_generation=snapshot.predecessor_generation + 1,
                source_batch_id=snapshot.source_batch_id,
                source_batch_sha256=snapshot.source_batch_sha256,
                candidate_fixture_manifest_sha256=fixture_manifest_sha256,
                candidate_runtime_manifest_sha256=runtime_sha256,
                candidate_lineage_manifest_sha256=lineage_sha256,
                declared_resource_manifest_sha256=snapshot.declared_resource_manifest_sha256,
                preservation_manifest_sha256=preservation_sha256,
                safe_complement_before_sha256=safe_before_sha256,
                safe_complement_after_sha256=safe_after_sha256,
                safe_complement_proof_sha256=safe_proof_sha256,
                candidate_seal_sha256=candidate_seal_sha256,
                candidate_tree_sha256=candidate_tree_sha256,
                candidate_ref=candidate_ref,
                quarantine=quarantine,
                command_results=tuple(command_results),
                candidate_pointer=candidate_pointer,
                candidate_pointer_sha256=candidate_pointer_sha256,
                prepared_at=prepared_at,
            )
        except BaseException:
            _remove_tree(stage)
            raise

    def _prepared_from_root(self, root: Path, candidate_ref: str) -> PreparedPublication:
        seal = _read_document(
            root,
            "manifests/candidate-seal.json",
            schema="simulator-candidate-seal/v1",
        )
        pointer = _read_document(
            root,
            "manifests/candidate-pointer.json",
            schema="simulator-publication-pointer/v1",
        )
        fixture = _read_document(
            root,
            "manifests/fixture.json",
            schema="simulator-fixture-manifest/v1",
        )
        runtime = _read_document(
            root,
            "manifests/runtime.json",
            schema="simulator-runtime-manifest/v1",
        )
        lineage_path = _relative_path(cast(Mapping[str, Any], runtime["lineage"])["path"])
        lineage = _read_document(root, lineage_path)
        if lineage.get("schema") != "artifact-lineage/v1":
            raise SimulatorBundleError("candidate-lineage-invalid")
        seal_sha256 = sha256_bytes(_read_relative(root, "manifests/candidate-seal.json"))
        pointer_sha256 = sha256_bytes(_read_relative(root, "manifests/candidate-pointer.json"))
        preservation = _read_document(
            root,
            "manifests/preservation.json",
            schema="simulator-preservation-manifest/v1",
        )
        safe = _read_document(
            root,
            "manifests/safe-complement.json",
            schema="simulator-safe-complement/v1",
        )
        safe_proof = _read_document(
            root,
            "manifests/safe-complement-proof.json",
            schema="simulator-safe-complement-proof/v1",
        )
        preservation_sha256 = sha256_bytes(_read_relative(root, "manifests/preservation.json"))
        safe_sha256 = sha256_bytes(_read_relative(root, "manifests/safe-complement.json"))
        safe_proof_sha256 = sha256_bytes(
            _read_relative(root, "manifests/safe-complement-proof.json")
        )
        fixture_sha256 = sha256_bytes(_read_relative(root, "manifests/fixture.json"))
        runtime_sha256 = sha256_bytes(_read_relative(root, "manifests/runtime.json"))
        lineage_sha256 = sha256_bytes(_read_relative(root, lineage_path))
        predecessor = cast(Mapping[str, Any], seal["predecessor_pointer"])
        if (
            pointer["candidate_seal_sha256"] != seal_sha256
            or pointer["publication_id"] != seal["publication_id"]
            or pointer["operation_id"] != seal["operation_id"]
            or pointer["generation"] != seal["candidate_generation"]
            or pointer["source_batch_id"] != seal["source_batch_id"]
            or pointer["source_batch_sha256"] != seal["source_batch_sha256"]
            or pointer["fixture_manifest_sha256"] != seal["fixture_manifest_sha256"]
            or pointer["runtime_manifest_sha256"] != seal["runtime_manifest_sha256"]
            or pointer["lineage_manifest_sha256"] != seal["lineage_manifest_sha256"]
            or pointer["declared_resource_manifest_sha256"]
            != seal["declared_resource_manifest_sha256"]
            or pointer["previous_pointer_sha256"] != seal["predecessor_pointer_sha256"]
            or pointer["prepared_at"] != seal["prepared_at"]
            or seal["candidate_generation"] != seal["predecessor_generation"] + 1
            or predecessor.get("generation") != seal["predecessor_generation"]
            or sha256_bytes(canonical_json_bytes(predecessor)) != seal["predecessor_pointer_sha256"]
        ):
            raise SimulatorBundleError("candidate-pointer-binding-mismatch")
        if (
            fixture_sha256 != seal["fixture_manifest_sha256"]
            or runtime_sha256 != seal["runtime_manifest_sha256"]
            or lineage_sha256 != seal["lineage_manifest_sha256"]
            or preservation_sha256 != seal["preservation_manifest_sha256"]
            or safe_sha256 != seal["safe_complement_before_sha256"]
            or safe_sha256 != seal["safe_complement_after_sha256"]
            or safe_proof_sha256 != seal["safe_complement_proof_sha256"]
            or safe_proof["preservation_manifest_sha256"] != preservation_sha256
            or safe_proof["before_sha256"] != safe_sha256
            or safe_proof["after_sha256"] != safe_sha256
            or safe_proof["byte_identical"] is not True
            or preservation["baseline_pointer_sha256"] != seal["predecessor_pointer_sha256"]
            or preservation["baseline_generation"] != seal["predecessor_generation"]
            or safe["fixture_id"] != preservation["fixture_id"]
            or safe["source_batch_id"] != seal["source_batch_id"]
            or safe["source_batch_sha256"] != seal["source_batch_sha256"]
        ):
            raise SimulatorBundleError("candidate-control-binding-mismatch")
        if (
            fixture["fixture_id"] != pointer["fixture_id"]
            or runtime["fixture_id"] != pointer["fixture_id"]
            or fixture["generation"] != seal["candidate_generation"]
            or runtime["generation"] != seal["candidate_generation"]
            or fixture["runtime_manifest_sha256"] != runtime_sha256
            or fixture["lineage_manifest_sha256"] != lineage_sha256
            or runtime["lineage"]["sha256"] != lineage_sha256
            or runtime["previous_runtime_manifest_sha256"]
            != predecessor.get("runtime_manifest_sha256")
            or fixture["source_batch_id"] != seal["source_batch_id"]
            or runtime["source_batch_id"] != seal["source_batch_id"]
            or fixture["source_batch_sha256"] != seal["source_batch_sha256"]
            or runtime["source_batch_sha256"] != seal["source_batch_sha256"]
            or fixture["declared_resource_manifest_sha256"]
            != seal["declared_resource_manifest_sha256"]
            or runtime["declared_resource_manifest_sha256"]
            != seal["declared_resource_manifest_sha256"]
            or fixture["ocio_version"] != OCIO_VERSION
            or pointer["ocio_version"] != OCIO_VERSION
        ):
            raise SimulatorBundleError("candidate-manifest-binding-mismatch")
        tree_sha256 = _tree_digest(
            root,
            excluded=frozenset(
                {
                    "manifests/candidate-seal.json",
                    "manifests/candidate-pointer.json",
                }
            ),
        )
        if tree_sha256 != seal["candidate_tree_sha256"]:
            raise SimulatorBundleError("candidate-tree-digest-mismatch")
        return PreparedPublication(
            operation_id=cast(str, seal["operation_id"]),
            publication_id=cast(str, seal["publication_id"]),
            predecessor_pointer=cast(Mapping[str, Any], seal["predecessor_pointer"]),
            predecessor_pointer_sha256=cast(str, seal["predecessor_pointer_sha256"]),
            predecessor_generation=cast(int, seal["predecessor_generation"]),
            candidate_generation=cast(int, seal["candidate_generation"]),
            source_batch_id=cast(str, seal["source_batch_id"]),
            source_batch_sha256=cast(str, seal["source_batch_sha256"]),
            candidate_fixture_manifest_sha256=cast(str, seal["fixture_manifest_sha256"]),
            candidate_runtime_manifest_sha256=cast(str, seal["runtime_manifest_sha256"]),
            candidate_lineage_manifest_sha256=cast(str, seal["lineage_manifest_sha256"]),
            declared_resource_manifest_sha256=cast(str, seal["declared_resource_manifest_sha256"]),
            preservation_manifest_sha256=cast(str, seal["preservation_manifest_sha256"]),
            safe_complement_before_sha256=cast(str, seal["safe_complement_before_sha256"]),
            safe_complement_after_sha256=cast(str, seal["safe_complement_after_sha256"]),
            safe_complement_proof_sha256=cast(str, seal["safe_complement_proof_sha256"]),
            candidate_seal_sha256=seal_sha256,
            candidate_tree_sha256=tree_sha256,
            candidate_ref=candidate_ref,
            quarantine=cast(Mapping[str, Any], seal["quarantine"]),
            command_results=tuple(cast(list[Mapping[str, Any]], seal["command_results"])),
            candidate_pointer=pointer,
            candidate_pointer_sha256=pointer_sha256,
            prepared_at=cast(str, seal["prepared_at"]),
        )

    def _conflict_promotion(
        self,
        prepared: PreparedPublication,
        context: _ActiveContext,
    ) -> PromotionResult:
        return PromotionResult(
            state="conflict",
            before_pointer_sha256=context.pointer_sha256,
            before_generation=cast(int, context.pointer["generation"]),
            after_pointer_sha256=context.pointer_sha256,
            after_generation=cast(int, context.pointer["generation"]),
            pointer_changed=False,
            recovered=False,
            promoted_at=None,
            observed_at=_timestamp(self.clock()),
        )

    def compare_and_swap(self, prepared: PreparedPublication) -> PromotionResult:
        _identifier(prepared.operation_id, code="operation-id-invalid")
        with self._publication_lock():
            context = self._load_active_context()
            if (
                context.pointer_sha256 == prepared.candidate_pointer_sha256
                and context.pointer.get("operation_id") == prepared.operation_id
            ):
                return PromotionResult(
                    state="already-promoted",
                    before_pointer_sha256=context.pointer_sha256,
                    before_generation=cast(int, context.pointer["generation"]),
                    after_pointer_sha256=context.pointer_sha256,
                    after_generation=cast(int, context.pointer["generation"]),
                    pointer_changed=False,
                    recovered=True,
                    promoted_at=cast(str, context.pointer["prepared_at"]),
                    observed_at=_timestamp(self.clock()),
                )
            if (
                context.pointer_sha256 != prepared.predecessor_pointer_sha256
                or context.pointer["generation"] != prepared.predecessor_generation
                or context.pointer != prepared.predecessor_pointer
            ):
                return self._conflict_promotion(prepared, context)
            stage = self.root / prepared.candidate_ref
            publication = self._publication_root(prepared.publication_id)
            if stage.exists():
                verified = self._prepared_from_root(stage, prepared.candidate_ref)
                if verified != prepared:
                    raise SimulatorBundleError("prepared-candidate-mismatch")
                if publication.exists():
                    raise SimulatorBundleError("publication-collision")
                _rename_frozen_tree(stage, publication)
                publications_fd = os.open(
                    publication.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(publications_fd)
                finally:
                    os.close(publications_fd)
                self.fault_hook("candidate-publication-durable")
            elif publication.exists():
                verified = self._prepared_from_root(
                    publication,
                    f"publications/{publication.name}",
                )
                if (
                    verified.operation_id != prepared.operation_id
                    or verified.candidate_pointer_sha256 != prepared.candidate_pointer_sha256
                    or verified.candidate_seal_sha256 != prepared.candidate_seal_sha256
                ):
                    raise SimulatorBundleError("sealed-publication-mismatch")
            else:
                raise SimulatorBundleError("prepared-candidate-unavailable")
            changed_sha256 = self._write_active_pointer(prepared.candidate_pointer)
            if changed_sha256 != prepared.candidate_pointer_sha256:
                raise SimulatorBundleError("candidate-pointer-digest-mismatch")
            self.fault_hook("candidate-promotion-durable")
            promoted_at = _timestamp(self.clock())
            return PromotionResult(
                state="promoted",
                before_pointer_sha256=prepared.predecessor_pointer_sha256,
                before_generation=prepared.predecessor_generation,
                after_pointer_sha256=prepared.candidate_pointer_sha256,
                after_generation=prepared.candidate_generation,
                pointer_changed=True,
                recovered=False,
                promoted_at=promoted_at,
                observed_at=promoted_at,
            )

    def inspect_operation(self, operation_id: str) -> PublicationOperationState:
        operation = _identifier(operation_id, code="operation-id-invalid")
        context = self._load_active_context()
        if context.pointer.get("operation_id") == operation:
            publication = context.publication_root
            prepared = self._prepared_from_root(
                publication,
                f"publications/{publication.name}",
            )
            promotion = PromotionResult(
                state="already-promoted",
                before_pointer_sha256=context.pointer_sha256,
                before_generation=cast(int, context.pointer["generation"]),
                after_pointer_sha256=context.pointer_sha256,
                after_generation=cast(int, context.pointer["generation"]),
                pointer_changed=False,
                recovered=True,
                promoted_at=cast(str, context.pointer["prepared_at"]),
                observed_at=_timestamp(self.clock()),
            )
            return PublicationOperationState(
                state="promoted",
                prepared=prepared,
                promotion=promotion,
            )
        token = hashlib.sha256(operation.encode("utf-8")).hexdigest()
        stage = self.root / "staging" / f"prep-{token}"
        if stage.exists():
            prepared = self._prepared_from_root(stage, f"staging/{stage.name}")
            if prepared.operation_id != operation:
                raise SimulatorBundleError("operation-stage-binding-mismatch")
            if (
                context.pointer_sha256 != prepared.predecessor_pointer_sha256
                or context.pointer["generation"] != prepared.predecessor_generation
                or context.pointer != prepared.predecessor_pointer
            ):
                return PublicationOperationState(
                    state="conflict",
                    prepared=prepared,
                    promotion=self._conflict_promotion(prepared, context),
                )
            return PublicationOperationState(state="staged", prepared=prepared, promotion=None)
        for publication in sorted((self.root / "publications").glob("pub-*")):
            seal_path = publication / "manifests" / "candidate-seal.json"
            if not seal_path.exists():
                continue
            seal = _read_document(
                publication,
                "manifests/candidate-seal.json",
                schema="simulator-candidate-seal/v1",
            )
            if seal.get("operation_id") != operation:
                continue
            prepared = self._prepared_from_root(
                publication,
                f"publications/{publication.name}",
            )
            if context.pointer_sha256 != prepared.predecessor_pointer_sha256:
                return PublicationOperationState(
                    state="conflict",
                    prepared=prepared,
                    promotion=self._conflict_promotion(prepared, context),
                )
            return PublicationOperationState(state="sealed", prepared=prepared, promotion=None)
        return PublicationOperationState(state="not-found", prepared=None, promotion=None)

    def discard(self, prepared: PreparedPublication) -> None:
        with self._publication_lock():
            context = self._load_active_context()
            if (
                context.pointer.get("operation_id") == prepared.operation_id
                or context.pointer.get("publication_id") == prepared.publication_id
            ):
                raise SimulatorBundleError("active-publication-discard-prohibited")
            allowed = {
                f"staging/prep-{hashlib.sha256(prepared.operation_id.encode('utf-8')).hexdigest()}",
                f"publications/pub-{prepared.publication_id.removeprefix('publication:')}",
            }
            if prepared.candidate_ref not in allowed:
                raise SimulatorBundleError("candidate-ref-invalid")
            target = self.root / prepared.candidate_ref
            if target.exists():
                verified = self._prepared_from_root(target, prepared.candidate_ref)
                if (
                    verified.operation_id != prepared.operation_id
                    or verified.candidate_seal_sha256 != prepared.candidate_seal_sha256
                ):
                    raise SimulatorBundleError("discard-candidate-mismatch")
                _remove_tree(target)
                parent_fd = os.open(
                    target.parent,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)


__all__ = [
    "LocalPublicationPort",
    "SimulatorBundleError",
    "canonical_json_bytes",
]
