from __future__ import annotations

import hashlib
import stat
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast

from .bundle import (
    LocalPublicationPort,
    SimulatorBundleError,
    _audit_tree,
    _freeze_tree,
    _identifier,
    _read_relative,
    _relative_path,
    _remove_tree,
    _strict_json,
    _timestamp,
    _validate_document,
    _write_relative,
    canonical_json_bytes,
)
from .models import (
    ActionSnapshot,
    BoundSimulatorAction,
    PreparedPublication,
    PromotionResult,
    PublicationOperationState,
    RecoveryArtifact,
    RecoverySnapshot,
)
from .renderer import OcioRenderer, sha256_bytes


class _Blob(Protocol):
    generation: int | str | None
    metadata: Mapping[str, str] | None
    content_type: str | None
    cache_control: str | None

    def reload(self, *, timeout: float | None = None) -> None: ...

    def download_as_bytes(
        self,
        *,
        if_generation_match: int | None = None,
        timeout: float | None = None,
    ) -> bytes: ...

    def upload_from_string(
        self,
        data: bytes,
        *,
        content_type: str,
        if_generation_match: int,
        checksum: str,
        timeout: float | None = None,
    ) -> None: ...


class _Bucket(Protocol):
    def blob(self, name: str) -> _Blob: ...


class StorageClient(Protocol):
    def bucket(self, bucket_name: str) -> _Bucket: ...


@dataclass(frozen=True, slots=True)
class GcsPublicationPolicy:
    prefix: str = "colortrace/simulator/v1"
    artifact_retention_days: int = 7
    discarded_candidate_retention_days: int = 7
    noncurrent_pointer_retention_days: int = 7
    request_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        normalized = self.prefix.strip("/")
        if (
            not normalized
            or normalized != self.prefix
            or "//" in normalized
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
            or any(
                character not in "abcdefghijklmnopqrstuvwxyz0123456789._-/"
                for character in normalized
            )
        ):
            raise ValueError("gcs publication prefix is invalid")
        if any(
            value < 1
            for value in (
                self.artifact_retention_days,
                self.discarded_candidate_retention_days,
                self.noncurrent_pointer_retention_days,
            )
        ):
            raise ValueError("gcs publication retention is invalid")
        if self.request_timeout_seconds <= 0:
            raise ValueError("gcs publication timeout is invalid")

    def document(self) -> dict[str, Any]:
        return {
            "schema": "colortrace-gcs-publication-policy/v1",
            "object_naming": "objects/sha256/{digest}",
            "immutable_object_mutation": "create-only",
            "discard_behavior": "tombstone-and-retain",
            "artifact_retention_days": self.artifact_retention_days,
            "discarded_candidate_retention_days": self.discarded_candidate_retention_days,
            "noncurrent_pointer_retention_days": self.noncurrent_pointer_retention_days,
        }


_DEFAULT_POLICY = GcsPublicationPolicy()


@dataclass(frozen=True, slots=True)
class _StoredObject:
    value: bytes
    generation: int
    content_type: str
    metadata: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _RemoteActive:
    document: Mapping[str, Any]
    generation: int


_ACTIVE_SCHEMA = "colortrace-gcs-active-publication/v1"
_TREE_SCHEMA = "colortrace-gcs-publication-tree/v1"
_OPERATION_SCHEMA = "colortrace-gcs-prepared-operation/v1"
_DISCARD_SCHEMA = "colortrace-gcs-discarded-operation/v1"
_DIGEST = "sha256:"
_OBJECT_METADATA_KEYS = frozenset(
    {
        "colortrace-sha256",
        "colortrace-content-type",
        "colortrace-object-kind",
        "colortrace-retention-class",
    }
)

GCS_SIMULATOR_REQUIRED_PERMISSIONS = (
    "storage.objects.create",
    "storage.objects.delete",
    "storage.objects.get",
)


def _default_clock() -> datetime:
    return datetime.now(UTC)


def _status_code(error: BaseException) -> int | None:
    value = getattr(error, "code", None)
    if callable(value):
        value = value()
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    response = getattr(error, "response", None)
    value = getattr(response, "status_code", None)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None


def _content_type(path: str) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".json":
        return "application/json"
    if suffix == ".png":
        return "image/png"
    if suffix in {".cube", ".ocio"}:
        return "text/plain; charset=utf-8"
    return "application/octet-stream"


def _plain_mapping(value: object, *, code: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise SimulatorBundleError(code)
    return {str(key): child for key, child in value.items()}


class GcsPublicationPort:
    """Cloud Storage authority with a private local render/seal workspace."""

    def __init__(
        self,
        *,
        root: Path,
        bucket_name: str,
        client: StorageClient,
        fixture_bundle: Path | None = None,
        policy: GcsPublicationPolicy | None = None,
        renderer: OcioRenderer | None = None,
        clock: Callable[[], datetime] = _default_clock,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        if not bucket_name or any(character.isspace() for character in bucket_name):
            raise ValueError("gcs bucket name is invalid")
        self.root = root
        self.bucket_name = bucket_name
        self.policy = policy or _DEFAULT_POLICY
        self.clock = clock
        self.fault_hook = fault_hook or (lambda _point: None)
        self._bucket = client.bucket(bucket_name)
        self._mutex = threading.RLock()

        try:
            root_metadata = root.lstat()
        except FileNotFoundError:
            root.mkdir(parents=True, mode=0o700)
        else:
            if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
                raise SimulatorBundleError("workspace-link-prohibited")
        root.chmod(0o700)
        self._local = LocalPublicationPort(
            root,
            renderer=renderer,
            clock=clock,
            fault_hook=fault_hook,
        )
        remote = self._try_load_active()
        if remote is None:
            if fixture_bundle is None:
                raise SimulatorBundleError("gcs-active-pointer-unavailable")
            self._local = LocalPublicationPort.bootstrap(
                root=root,
                fixture_bundle=fixture_bundle,
                renderer=renderer,
                clock=clock,
                fault_hook=fault_hook,
            )
            remote = self._initialize_remote()
        self._synchronize_active(remote)

    @classmethod
    def bootstrap(
        cls,
        *,
        root: Path,
        fixture_bundle: Path,
        bucket_name: str,
        client: StorageClient,
        policy: GcsPublicationPolicy | None = None,
        renderer: OcioRenderer | None = None,
        clock: Callable[[], datetime] = _default_clock,
        fault_hook: Callable[[str], None] | None = None,
    ) -> GcsPublicationPort:
        return cls(
            root=root,
            bucket_name=bucket_name,
            client=client,
            fixture_bundle=fixture_bundle,
            policy=policy,
            renderer=renderer,
            clock=clock,
            fault_hook=fault_hook,
        )

    @property
    def _active_key(self) -> str:
        return f"{self.policy.prefix}/state/active.json"

    def _object_key(self, digest: str) -> str:
        if not digest.startswith(_DIGEST) or len(digest) != 71:
            raise SimulatorBundleError("gcs-object-digest-invalid")
        suffix = digest.removeprefix(_DIGEST)
        if any(character not in "0123456789abcdef" for character in suffix):
            raise SimulatorBundleError("gcs-object-digest-invalid")
        return f"{self.policy.prefix}/objects/sha256/{suffix}"

    def _operation_root(self, operation_id: str) -> str:
        _identifier(operation_id, code="operation-id-invalid")
        token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        return f"{self.policy.prefix}/operations/sha256/{token}"

    def _object_metadata(
        self,
        *,
        digest: str,
        content_type: str,
        kind: str,
        retention_class: str,
    ) -> dict[str, str]:
        return {
            "colortrace-sha256": digest.removeprefix(_DIGEST),
            "colortrace-content-type": content_type,
            "colortrace-object-kind": kind,
            "colortrace-retention-class": retention_class,
        }

    def _download(self, name: str) -> _StoredObject:
        blob = self._bucket.blob(name)
        try:
            blob.reload(timeout=self.policy.request_timeout_seconds)
            generation = int(cast(int | str, blob.generation))
            value = blob.download_as_bytes(
                if_generation_match=generation,
                timeout=self.policy.request_timeout_seconds,
            )
        except BaseException as error:
            if _status_code(error) == 404:
                raise SimulatorBundleError("gcs-object-unavailable") from error
            if _status_code(error) == 412:
                raise SimulatorBundleError("gcs-object-generation-changed") from error
            raise SimulatorBundleError("gcs-object-read-failed") from error
        content_type = blob.content_type
        metadata = blob.metadata
        if not isinstance(content_type, str) or not isinstance(metadata, Mapping):
            raise SimulatorBundleError("gcs-object-metadata-invalid")
        return _StoredObject(
            value=value,
            generation=generation,
            content_type=content_type,
            metadata=MappingProxyType(dict(metadata)),
        )

    def _upload(
        self,
        name: str,
        value: bytes,
        *,
        content_type: str,
        metadata: Mapping[str, str],
        if_generation_match: int,
        cache_control: str,
    ) -> int:
        blob = self._bucket.blob(name)
        blob.metadata = dict(metadata)
        blob.cache_control = cache_control
        try:
            blob.upload_from_string(
                value,
                content_type=content_type,
                if_generation_match=if_generation_match,
                checksum="auto",
                timeout=self.policy.request_timeout_seconds,
            )
            blob.reload(timeout=self.policy.request_timeout_seconds)
            return int(cast(int | str, blob.generation))
        except BaseException as error:
            if _status_code(error) == 412:
                raise SimulatorBundleError("gcs-precondition-failed") from error
            raise SimulatorBundleError("gcs-object-write-failed") from error

    def _put_immutable(
        self,
        name: str,
        value: bytes,
        *,
        content_type: str,
        kind: str,
        retention_class: str,
    ) -> int:
        digest = sha256_bytes(value)
        metadata = self._object_metadata(
            digest=digest,
            content_type=content_type,
            kind=kind,
            retention_class=retention_class,
        )
        try:
            return self._upload(
                name,
                value,
                content_type=content_type,
                metadata=metadata,
                if_generation_match=0,
                cache_control="private, max-age=31536000, immutable",
            )
        except SimulatorBundleError as error:
            if error.code != "gcs-precondition-failed":
                raise
        existing = self._download(name)
        if (
            existing.value != value
            or existing.content_type != content_type
            or any(existing.metadata.get(key) != metadata[key] for key in _OBJECT_METADATA_KEYS)
        ):
            raise SimulatorBundleError("gcs-immutable-object-conflict")
        return existing.generation

    def _put_digest_object(
        self,
        value: bytes,
    ) -> dict[str, str]:
        digest = sha256_bytes(value)
        name = self._object_key(digest)
        self._put_immutable(
            name,
            value,
            content_type="application/octet-stream",
            kind="digest-object",
            retention_class="publication-artifact",
        )
        return {"object": name, "sha256": digest}

    def _read_json(
        self,
        name: str,
        *,
        expected_digest: str | None = None,
        expected_kind: str | None = None,
        expected_retention_class: str | None = None,
    ) -> tuple[dict[str, Any], int]:
        stored = self._download(name)
        if stored.content_type != "application/json":
            raise SimulatorBundleError("gcs-json-content-type-invalid")
        digest = sha256_bytes(stored.value)
        if expected_digest is not None and digest != expected_digest:
            raise SimulatorBundleError("gcs-json-digest-mismatch")
        if (
            stored.metadata.get("colortrace-sha256") != digest.removeprefix(_DIGEST)
            or stored.metadata.get("colortrace-content-type") != stored.content_type
            or (
                expected_kind is not None
                and stored.metadata.get("colortrace-object-kind") != expected_kind
            )
            or (
                expected_retention_class is not None
                and stored.metadata.get("colortrace-retention-class") != expected_retention_class
            )
        ):
            raise SimulatorBundleError("gcs-json-metadata-mismatch")
        document = _strict_json(stored.value)
        if not isinstance(document, dict) or canonical_json_bytes(document) != stored.value:
            raise SimulatorBundleError("gcs-json-not-canonical")
        return cast(dict[str, Any], document), stored.generation

    def _tree_manifest(self, root: Path, *, kind: str, tree_id: str) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        for relative in _audit_tree(root):
            value = _read_relative(root, relative)
            content_type = _content_type(relative)
            reference = self._put_digest_object(value)
            files.append(
                {
                    "path": relative,
                    "sha256": reference["sha256"],
                    "size": len(value),
                    "content_type": content_type,
                    "object": reference["object"],
                }
            )
        body = {
            "schema": _TREE_SCHEMA,
            "tree_kind": kind,
            "tree_id": tree_id,
            "files": files,
            "storage_policy": self.policy.document(),
        }
        body["tree_sha256"] = sha256_bytes(canonical_json_bytes(files))
        return body

    def _publish_tree(self, root: Path, *, kind: str, tree_id: str) -> dict[str, str]:
        manifest = self._tree_manifest(root, kind=kind, tree_id=tree_id)
        raw = canonical_json_bytes(manifest)
        return self._put_digest_object(raw)

    def _validate_tree_reference(self, value: object) -> dict[str, str]:
        reference = _plain_mapping(value, code="gcs-tree-reference-invalid")
        if set(reference) != {"object", "sha256"}:
            raise SimulatorBundleError("gcs-tree-reference-invalid")
        digest = reference.get("sha256")
        name = reference.get("object")
        if not isinstance(digest, str) or not isinstance(name, str):
            raise SimulatorBundleError("gcs-tree-reference-invalid")
        if name != self._object_key(digest):
            raise SimulatorBundleError("gcs-tree-reference-invalid")
        return {"object": name, "sha256": digest}

    def _load_tree_manifest(
        self,
        reference_value: object,
        *,
        expected_kind: str,
        expected_id: str,
    ) -> dict[str, Any]:
        reference = self._validate_tree_reference(reference_value)
        stored = self._download(reference["object"])
        if (
            stored.content_type != "application/octet-stream"
            or sha256_bytes(stored.value) != reference["sha256"]
            or stored.metadata.get("colortrace-sha256") != reference["sha256"].removeprefix(_DIGEST)
            or stored.metadata.get("colortrace-object-kind") != "digest-object"
        ):
            raise SimulatorBundleError("gcs-tree-manifest-invalid")
        manifest_value = _strict_json(stored.value)
        if (
            not isinstance(manifest_value, dict)
            or canonical_json_bytes(manifest_value) != stored.value
        ):
            raise SimulatorBundleError("gcs-tree-manifest-invalid")
        manifest = cast(dict[str, Any], manifest_value)
        if (
            set(manifest)
            != {"schema", "tree_kind", "tree_id", "tree_sha256", "files", "storage_policy"}
            or manifest.get("schema") != _TREE_SCHEMA
            or manifest.get("tree_kind") != expected_kind
            or manifest.get("tree_id") != expected_id
            or manifest.get("storage_policy") != self.policy.document()
        ):
            raise SimulatorBundleError("gcs-tree-manifest-invalid")
        files = manifest.get("files")
        if not isinstance(files, list) or manifest.get("tree_sha256") != sha256_bytes(
            canonical_json_bytes(files)
        ):
            raise SimulatorBundleError("gcs-tree-manifest-invalid")
        previous = ""
        for item_value in files:
            item = _plain_mapping(item_value, code="gcs-tree-entry-invalid")
            if set(item) != {"path", "sha256", "size", "content_type", "object"}:
                raise SimulatorBundleError("gcs-tree-entry-invalid")
            path = _relative_path(item.get("path"))
            digest = item.get("sha256")
            size = item.get("size")
            content_type = item.get("content_type")
            name = item.get("object")
            if (
                path <= previous
                or not isinstance(digest, str)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(content_type, str)
                or content_type != _content_type(path)
                or not isinstance(name, str)
                or name != self._object_key(digest)
            ):
                raise SimulatorBundleError("gcs-tree-entry-invalid")
            previous = path
        return manifest

    def _materialize_tree(
        self,
        target: Path,
        reference: object,
        *,
        expected_kind: str,
        expected_id: str,
    ) -> None:
        manifest = self._load_tree_manifest(
            reference,
            expected_kind=expected_kind,
            expected_id=expected_id,
        )
        files = cast(list[dict[str, Any]], manifest["files"])
        if target.exists():
            actual = _audit_tree(target)
            if actual != [cast(str, item["path"]) for item in files]:
                raise SimulatorBundleError("gcs-local-tree-drift")
            for item in files:
                value = _read_relative(target, cast(str, item["path"]))
                if len(value) != item["size"] or sha256_bytes(value) != item["sha256"]:
                    raise SimulatorBundleError("gcs-local-tree-drift")
            return
        target.mkdir(parents=True, mode=0o700)
        try:
            for item in files:
                stored = self._download(cast(str, item["object"]))
                if (
                    len(stored.value) != item["size"]
                    or sha256_bytes(stored.value) != item["sha256"]
                    or stored.content_type != "application/octet-stream"
                    or stored.metadata.get("colortrace-sha256")
                    != cast(str, item["sha256"]).removeprefix(_DIGEST)
                    or stored.metadata.get("colortrace-object-kind") != "digest-object"
                ):
                    raise SimulatorBundleError("gcs-artifact-binding-mismatch")
                _write_relative(target, cast(str, item["path"]), stored.value)
            _freeze_tree(target)
        except BaseException:
            _remove_tree(target)
            raise

    def _active_document(
        self,
        pointer: Mapping[str, Any],
        publication_tree: Mapping[str, str],
        source_batch_tree: Mapping[str, str],
        *,
        closure: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        _validate_document(pointer)
        pointer_value = dict(pointer)
        return {
            "schema": _ACTIVE_SCHEMA,
            "pointer": pointer_value,
            "pointer_sha256": sha256_bytes(canonical_json_bytes(pointer_value)),
            "publication_tree": dict(publication_tree),
            "source_batch_tree": dict(source_batch_tree),
            "storage_policy": self.policy.document(),
            "closure": None if closure is None else dict(closure),
        }

    def _validate_active(self, document: Mapping[str, Any], generation: int) -> _RemoteActive:
        if (
            set(document)
            != {
                "schema",
                "pointer",
                "pointer_sha256",
                "publication_tree",
                "source_batch_tree",
                "storage_policy",
                "closure",
            }
            or document.get("schema") != _ACTIVE_SCHEMA
        ):
            raise SimulatorBundleError("gcs-active-pointer-invalid")
        pointer = _plain_mapping(document.get("pointer"), code="gcs-active-pointer-invalid")
        _validate_document(pointer)
        pointer_sha256 = sha256_bytes(canonical_json_bytes(pointer))
        if (
            document.get("pointer_sha256") != pointer_sha256
            or document.get("storage_policy") != self.policy.document()
        ):
            raise SimulatorBundleError("gcs-active-pointer-invalid")
        self._validate_tree_reference(document.get("publication_tree"))
        self._validate_tree_reference(document.get("source_batch_tree"))
        closure = document.get("closure")
        if closure is not None:
            closure_value = _plain_mapping(closure, code="gcs-closure-invalid")
            if (
                set(closure_value) != {"operation_id", "pointer_sha256", "snapshot_sha256"}
                or closure_value.get("pointer_sha256") != pointer_sha256
                or not isinstance(closure_value.get("operation_id"), str)
                or not isinstance(closure_value.get("snapshot_sha256"), str)
            ):
                raise SimulatorBundleError("gcs-closure-invalid")
        return _RemoteActive(document=MappingProxyType(dict(document)), generation=generation)

    def _try_load_active(self) -> _RemoteActive | None:
        try:
            document, generation = self._read_json(
                self._active_key,
                expected_kind="active-publication-pointer",
                expected_retention_class="versioned-active-pointer",
            )
        except SimulatorBundleError as error:
            if error.code == "gcs-object-unavailable":
                return None
            raise
        return self._validate_active(document, generation)

    def _load_active(self) -> _RemoteActive:
        active = self._try_load_active()
        if active is None:
            raise SimulatorBundleError("gcs-active-pointer-unavailable")
        return active

    def _write_active(self, document: Mapping[str, Any], *, generation: int) -> int:
        validated = self._validate_active(document, max(generation, 1))
        raw = canonical_json_bytes(validated.document)
        digest = sha256_bytes(raw)
        metadata = self._object_metadata(
            digest=digest,
            content_type="application/json",
            kind="active-publication-pointer",
            retention_class="versioned-active-pointer",
        )
        return self._upload(
            self._active_key,
            raw,
            content_type="application/json",
            metadata=metadata,
            if_generation_match=generation,
            cache_control="no-store",
        )

    def _initialize_remote(self) -> _RemoteActive:
        context = self._local._load_active_context()
        publication_tree = self._publish_tree(
            context.publication_root,
            kind="publication",
            tree_id=cast(str, context.pointer["publication_id"]),
        )
        source_batch_tree = self._publish_tree(
            context.source_batch_root,
            kind="source-batch",
            tree_id=cast(str, context.pointer["source_batch_id"]),
        )
        document = self._active_document(
            context.pointer,
            publication_tree,
            source_batch_tree,
        )
        try:
            generation = self._write_active(document, generation=0)
            self.fault_hook("gcs-bootstrap-pointer-durable")
            return self._validate_active(document, generation)
        except SimulatorBundleError as error:
            if error.code != "gcs-precondition-failed":
                raise
            return self._load_active()

    def _synchronize_active(self, active: _RemoteActive | None = None) -> _RemoteActive:
        selected = active or self._load_active()
        document = selected.document
        pointer = cast(Mapping[str, Any], document["pointer"])
        source_batch_id = cast(str, pointer["source_batch_id"])
        publication_id = cast(str, pointer["publication_id"])
        self._materialize_tree(
            self._local._batch_root(source_batch_id),
            document["source_batch_tree"],
            expected_kind="source-batch",
            expected_id=source_batch_id,
        )
        self._materialize_tree(
            self._local._publication_root(publication_id),
            document["publication_tree"],
            expected_kind="publication",
            expected_id=publication_id,
        )
        state_path = self.root / "state" / "active.json"
        expected = canonical_json_bytes(pointer)
        current = state_path.read_bytes() if state_path.exists() else None
        if current != expected:
            if self._local._write_active_pointer(pointer) != document["pointer_sha256"]:
                raise SimulatorBundleError("gcs-local-pointer-mismatch")
        context = self._local._load_active_context()
        if context.pointer_sha256 != document["pointer_sha256"]:
            raise SimulatorBundleError("gcs-local-pointer-mismatch")
        return selected

    def _operation_descriptor(
        self,
        prepared: PreparedPublication,
        tree: Mapping[str, str],
    ) -> dict[str, Any]:
        return {
            "schema": _OPERATION_SCHEMA,
            "operation_id": prepared.operation_id,
            "publication_id": prepared.publication_id,
            "predecessor_pointer_sha256": prepared.predecessor_pointer_sha256,
            "candidate_pointer_sha256": prepared.candidate_pointer_sha256,
            "candidate_seal_sha256": prepared.candidate_seal_sha256,
            "candidate_tree_sha256": prepared.candidate_tree_sha256,
            "publication_tree": dict(tree),
            "storage_policy": self.policy.document(),
        }

    def _descriptor_key(self, operation_id: str) -> str:
        return f"{self._operation_root(operation_id)}/prepared.json"

    def _discard_key(self, operation_id: str) -> str:
        return f"{self._operation_root(operation_id)}/discarded.json"

    def _load_discard(self, operation_id: str) -> dict[str, Any] | None:
        try:
            document, _generation = self._read_json(
                self._discard_key(operation_id),
                expected_kind="discarded-operation",
                expected_retention_class="discarded-operation",
            )
        except SimulatorBundleError as error:
            if error.code == "gcs-object-unavailable":
                return None
            raise
        if (
            set(document)
            != {
                "schema",
                "operation_id",
                "publication_id",
                "candidate_pointer_sha256",
                "descriptor_sha256",
                "discarded_at",
                "storage_policy",
            }
            or document.get("schema") != _DISCARD_SCHEMA
            or document.get("operation_id") != operation_id
            or document.get("storage_policy") != self.policy.document()
        ):
            raise SimulatorBundleError("gcs-discard-tombstone-invalid")
        return document

    def _publish_prepared(self, prepared: PreparedPublication) -> None:
        stage = self.root / prepared.candidate_ref
        verified = self._local._prepared_from_root(stage, prepared.candidate_ref)
        if verified != prepared:
            raise SimulatorBundleError("gcs-prepared-candidate-mismatch")
        tree = self._publish_tree(
            stage,
            kind="publication",
            tree_id=prepared.publication_id,
        )
        descriptor = self._operation_descriptor(prepared, tree)
        raw = canonical_json_bytes(descriptor)
        self._put_immutable(
            self._descriptor_key(prepared.operation_id),
            raw,
            content_type="application/json",
            kind="prepared-operation",
            retention_class="prepared-operation",
        )
        self.fault_hook("gcs-candidate-durable")

    def _load_descriptor(self, operation_id: str) -> dict[str, Any] | None:
        if self._load_discard(operation_id) is not None:
            return None
        try:
            document, _generation = self._read_json(
                self._descriptor_key(operation_id),
                expected_kind="prepared-operation",
                expected_retention_class="prepared-operation",
            )
        except SimulatorBundleError as error:
            if error.code == "gcs-object-unavailable":
                return None
            raise
        if (
            set(document)
            != {
                "schema",
                "operation_id",
                "publication_id",
                "predecessor_pointer_sha256",
                "candidate_pointer_sha256",
                "candidate_seal_sha256",
                "candidate_tree_sha256",
                "publication_tree",
                "storage_policy",
            }
            or document.get("schema") != _OPERATION_SCHEMA
            or document.get("operation_id") != operation_id
            or document.get("storage_policy") != self.policy.document()
        ):
            raise SimulatorBundleError("gcs-operation-descriptor-invalid")
        self._validate_tree_reference(document.get("publication_tree"))
        return document

    def _materialize_prepared(self, descriptor: Mapping[str, Any]) -> PreparedPublication:
        operation_id = cast(str, descriptor["operation_id"])
        token = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        candidate_ref = f"staging/prep-{token}"
        target = self.root / candidate_ref
        self._materialize_tree(
            target,
            descriptor["publication_tree"],
            expected_kind="publication",
            expected_id=cast(str, descriptor["publication_id"]),
        )
        prepared = self._local._prepared_from_root(target, candidate_ref)
        if any(
            (
                prepared.predecessor_pointer_sha256 != descriptor["predecessor_pointer_sha256"],
                prepared.candidate_pointer_sha256 != descriptor["candidate_pointer_sha256"],
                prepared.candidate_seal_sha256 != descriptor["candidate_seal_sha256"],
                prepared.candidate_tree_sha256 != descriptor["candidate_tree_sha256"],
            )
        ):
            raise SimulatorBundleError("gcs-operation-descriptor-binding-mismatch")
        return prepared

    def plan_bindings(
        self,
        *,
        commands: Sequence[Mapping[str, Any]],
        targets: Sequence[Mapping[str, Any]],
        exclusions: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        with self._mutex:
            self._synchronize_active()
            return self._local.plan_bindings(
                commands=commands,
                targets=targets,
                exclusions=exclusions,
            )

    def canonical_plan_inputs(self) -> dict[str, Any]:
        with self._mutex:
            self._synchronize_active()
            return self._local.canonical_plan_inputs()

    def snapshot_for_action(self, action: BoundSimulatorAction) -> ActionSnapshot:
        with self._mutex:
            self._synchronize_active()
            return self._local.snapshot_for_action(action)

    def prepare(
        self,
        snapshot: ActionSnapshot,
        trace_ids: Mapping[str, str],
        *,
        heartbeat: Callable[[], None] | None = None,
    ) -> PreparedPublication:
        with self._mutex:
            self._synchronize_active()
            prepared = self._local.prepare(snapshot, trace_ids, heartbeat=heartbeat)
            self._publish_prepared(prepared)
            return prepared

    def _promotion(
        self,
        *,
        state: Literal["promoted", "already-promoted", "conflict"],
        before_pointer: Mapping[str, Any],
        before_sha256: str,
        after_pointer: Mapping[str, Any],
        after_sha256: str,
        changed: bool,
        recovered: bool,
    ) -> PromotionResult:
        observed_at = _timestamp(self.clock())
        promoted_at = observed_at if state != "conflict" else None
        return PromotionResult(
            state=state,
            before_pointer_sha256=before_sha256,
            before_generation=cast(int, before_pointer["generation"]),
            after_pointer_sha256=after_sha256,
            after_generation=cast(int, after_pointer["generation"]),
            pointer_changed=changed,
            recovered=recovered,
            promoted_at=promoted_at,
            observed_at=observed_at,
        )

    def compare_and_swap(self, prepared: PreparedPublication) -> PromotionResult:
        with self._mutex:
            active = self._synchronize_active()
            document = active.document
            pointer = cast(Mapping[str, Any], document["pointer"])
            pointer_sha256 = cast(str, document["pointer_sha256"])
            if (
                pointer_sha256 == prepared.candidate_pointer_sha256
                and pointer.get("operation_id") == prepared.operation_id
            ):
                return self._promotion(
                    state="already-promoted",
                    before_pointer=pointer,
                    before_sha256=pointer_sha256,
                    after_pointer=pointer,
                    after_sha256=pointer_sha256,
                    changed=False,
                    recovered=True,
                )
            if document["closure"] is not None:
                raise SimulatorBundleError("gcs-recovery-closure-active")
            if (
                pointer_sha256 != prepared.predecessor_pointer_sha256
                or pointer != prepared.predecessor_pointer
            ):
                return self._promotion(
                    state="conflict",
                    before_pointer=pointer,
                    before_sha256=pointer_sha256,
                    after_pointer=pointer,
                    after_sha256=pointer_sha256,
                    changed=False,
                    recovered=False,
                )
            descriptor = self._load_descriptor(prepared.operation_id)
            if descriptor is None or self._materialize_prepared(descriptor) != prepared:
                raise SimulatorBundleError("gcs-prepared-candidate-unavailable")
            next_document = self._active_document(
                prepared.candidate_pointer,
                cast(Mapping[str, str], descriptor["publication_tree"]),
                cast(Mapping[str, str], document["source_batch_tree"]),
            )
            try:
                next_generation = self._write_active(next_document, generation=active.generation)
            except SimulatorBundleError as error:
                if error.code != "gcs-precondition-failed":
                    raise
                observed = self._synchronize_active()
                observed_pointer = cast(Mapping[str, Any], observed.document["pointer"])
                observed_sha256 = cast(str, observed.document["pointer_sha256"])
                if (
                    observed_sha256 == prepared.candidate_pointer_sha256
                    and observed_pointer.get("operation_id") == prepared.operation_id
                ):
                    return self._promotion(
                        state="already-promoted",
                        before_pointer=observed_pointer,
                        before_sha256=observed_sha256,
                        after_pointer=observed_pointer,
                        after_sha256=observed_sha256,
                        changed=False,
                        recovered=True,
                    )
                return self._promotion(
                    state="conflict",
                    before_pointer=observed_pointer,
                    before_sha256=observed_sha256,
                    after_pointer=observed_pointer,
                    after_sha256=observed_sha256,
                    changed=False,
                    recovered=False,
                )
            self.fault_hook("gcs-pointer-durable")
            promoted = self._validate_active(next_document, next_generation)
            self._synchronize_active(promoted)
            stage = self.root / prepared.candidate_ref
            if stage.exists():
                _remove_tree(stage)
            return self._promotion(
                state="promoted",
                before_pointer=prepared.predecessor_pointer,
                before_sha256=prepared.predecessor_pointer_sha256,
                after_pointer=prepared.candidate_pointer,
                after_sha256=prepared.candidate_pointer_sha256,
                changed=True,
                recovered=False,
            )

    def inspect_operation(self, operation_id: str) -> PublicationOperationState:
        with self._mutex:
            active = self._synchronize_active()
            pointer = cast(Mapping[str, Any], active.document["pointer"])
            if pointer.get("operation_id") == operation_id:
                return self._local.inspect_operation(operation_id)
            descriptor = self._load_descriptor(operation_id)
            if descriptor is None:
                return PublicationOperationState(
                    state="not-found",
                    prepared=None,
                    promotion=None,
                )
            self._materialize_prepared(descriptor)
            return self._local.inspect_operation(operation_id)

    def discard(self, prepared: PreparedPublication) -> None:
        with self._mutex:
            active = self._synchronize_active()
            pointer = cast(Mapping[str, Any], active.document["pointer"])
            if (
                pointer.get("operation_id") == prepared.operation_id
                or pointer.get("publication_id") == prepared.publication_id
            ):
                raise SimulatorBundleError("active-publication-discard-prohibited")
            discarded = self._load_discard(prepared.operation_id)
            if discarded is not None:
                if (
                    discarded.get("publication_id") != prepared.publication_id
                    or discarded.get("candidate_pointer_sha256")
                    != prepared.candidate_pointer_sha256
                ):
                    raise SimulatorBundleError("discard-candidate-mismatch")
                return
            descriptor = self._load_descriptor(prepared.operation_id)
            if descriptor is None or self._materialize_prepared(descriptor) != prepared:
                raise SimulatorBundleError("discard-candidate-mismatch")
            descriptor_raw = canonical_json_bytes(descriptor)
            tombstone = {
                "schema": _DISCARD_SCHEMA,
                "operation_id": prepared.operation_id,
                "publication_id": prepared.publication_id,
                "candidate_pointer_sha256": prepared.candidate_pointer_sha256,
                "descriptor_sha256": sha256_bytes(descriptor_raw),
                "discarded_at": _timestamp(self.clock()),
                "storage_policy": self.policy.document(),
            }
            self._local.discard(prepared)
            self._put_immutable(
                self._discard_key(prepared.operation_id),
                canonical_json_bytes(tombstone),
                content_type="application/json",
                kind="discarded-operation",
                retention_class="discarded-operation",
            )

    def snapshot_for_recovery(self, outcome: Mapping[str, Any]) -> RecoverySnapshot:
        with self._mutex:
            self._synchronize_active()
            return self._local.snapshot_for_recovery(outcome)

    def read_recovery_artifact(
        self,
        snapshot: RecoverySnapshot,
        artifact: RecoveryArtifact,
    ) -> bytes:
        with self._mutex:
            self._synchronize_active()
            return self._local.read_recovery_artifact(snapshot, artifact)

    def assert_recovery_snapshot_current(self, snapshot: RecoverySnapshot) -> None:
        with self._mutex:
            self._synchronize_active()
            self._local.assert_recovery_snapshot_current(snapshot)

    @contextmanager
    def guard_recovery_closure(
        self,
        snapshot: RecoverySnapshot,
        outcome: Mapping[str, Any],
    ) -> Iterator[None]:
        with self._mutex:
            active = self._synchronize_active()
            pointer_sha256 = cast(str, active.document["pointer_sha256"])
            snapshot_document = snapshot.to_dict()
            snapshot_sha256 = snapshot_document.get("snapshot_sha256")
            operation_id = snapshot_document.get("operation_id")
            if (
                active.document["closure"] is not None
                or pointer_sha256 != snapshot._active_pointer_sha256
                or not isinstance(snapshot_sha256, str)
                or not isinstance(operation_id, str)
            ):
                raise SimulatorBundleError("recovery-snapshot-stale")
            closure = {
                "operation_id": operation_id,
                "pointer_sha256": pointer_sha256,
                "snapshot_sha256": snapshot_sha256,
            }
            locked_document = dict(active.document)
            locked_document["closure"] = closure
            try:
                locked_generation = self._write_active(
                    locked_document,
                    generation=active.generation,
                )
            except SimulatorBundleError as error:
                if error.code == "gcs-precondition-failed":
                    raise SimulatorBundleError("recovery-snapshot-stale") from error
                raise
            try:
                with self._local.guard_recovery_closure(snapshot, outcome):
                    yield
            finally:
                current = self._load_active()
                if (
                    current.generation != locked_generation
                    or current.document["closure"] != closure
                ):
                    raise SimulatorBundleError("gcs-recovery-closure-lost")
                unlocked_document = dict(current.document)
                unlocked_document["closure"] = None
                try:
                    self._write_active(unlocked_document, generation=current.generation)
                except SimulatorBundleError as error:
                    if error.code == "gcs-precondition-failed":
                        raise SimulatorBundleError("gcs-recovery-closure-lost") from error
                    raise


__all__ = [
    "GCS_SIMULATOR_REQUIRED_PERMISSIONS",
    "GcsPublicationPolicy",
    "GcsPublicationPort",
    "StorageClient",
]
