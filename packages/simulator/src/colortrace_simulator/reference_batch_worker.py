from __future__ import annotations

import base64
import binascii
import filecmp
import hashlib
import importlib
import json
import os
import re
import stat
import sys
import tempfile
from argparse import ArgumentParser
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, BinaryIO, Protocol, cast

from jsonschema import Draft202012Validator, ValidationError  # type: ignore[import-untyped]

from .reference_worker import (
    REFERENCE_RECEIPT_SCHEMA,
    ReferenceExecutionIdentity,
    ReferenceRenderJob,
    ReferenceWorkerError,
    execute_reference_render_job_file,
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_EXECUTION_ID = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
_OBJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$")
_MAX_TASK_BYTES = 65_536
_MAX_RECEIPT_BYTES = 65_536
_MAX_OUTPUT_BYTES = 512 * 1024 * 1024
_GCS_DOWNLOAD_CHUNK_BYTES = 8 * 1024 * 1024
_TASK_KEYS = {
    "schema",
    "execution_id",
    "execution_spec_sha256",
    "job",
    "inputs",
    "outputs",
    "execution_identity",
}
_INPUT_KEYS = {"job", "source", "config", "resource"}


class ReferenceBatchWorkerError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReferenceBatchObjectAlreadyExists(RuntimeError):
    pass


class _BoundedFileWriter:
    def __init__(self, destination: BinaryIO, maximum_bytes: int) -> None:
        self._destination = destination
        self._maximum_bytes = maximum_bytes
        self.byte_length = 0

    def write(self, value: bytes) -> int:
        next_length = self.byte_length + len(value)
        if next_length > self._maximum_bytes:
            raise ReferenceBatchWorkerError("reference-batch-object-too-large")
        written = self._destination.write(value)
        if written != len(value):
            raise ReferenceBatchWorkerError("reference-batch-storage-response-invalid")
        self.byte_length = next_length
        return written


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(child) for child in value]
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ReferenceBatchWorkerError("reference-batch-task-invalid")
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise ReferenceBatchWorkerError("reference-batch-task-invalid")


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ReferenceBatchWorkerError("reference-batch-task-invalid")
    return cast(Mapping[str, Any], value)


def _bucket(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _BUCKET.fullmatch(value) is None
        or ".." in value
        or value.startswith("goog")
    ):
        raise ReferenceBatchWorkerError("reference-batch-object-invalid")
    return value


def _object(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _OBJECT.fullmatch(value) is None
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ReferenceBatchWorkerError("reference-batch-object-invalid")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReferenceBatchWorkerError("reference-batch-digest-invalid")
    return value


def _strict_json_bytes(raw: bytes, *, code: str, maximum: int) -> Mapping[str, Any]:
    if not 1 <= len(raw) <= maximum:
        raise ReferenceBatchWorkerError(code)

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate-key")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise ValueError(value)

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ReferenceBatchWorkerError(code) from error
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ReferenceBatchWorkerError(code)
    return cast(Mapping[str, Any], value)


@dataclass(frozen=True, slots=True)
class ReferenceBatchObject:
    bucket: str
    object: str
    generation: int
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        _bucket(self.bucket)
        _object(self.object)
        _digest(self.sha256)
        if (
            not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < 1
            or not isinstance(self.byte_length, int)
            or isinstance(self.byte_length, bool)
            or self.byte_length < 1
        ):
            raise ReferenceBatchWorkerError("reference-batch-object-invalid")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReferenceBatchObject:
        if set(value) != {"bucket", "object", "generation", "sha256", "byte_length"}:
            raise ReferenceBatchWorkerError("reference-batch-object-invalid")
        return cls(
            bucket=cast(str, value.get("bucket")),
            object=cast(str, value.get("object")),
            generation=cast(int, value.get("generation")),
            sha256=cast(str, value.get("sha256")),
            byte_length=cast(int, value.get("byte_length")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket": self.bucket,
            "object": self.object,
            "generation": self.generation,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
        }


@dataclass(frozen=True, slots=True)
class ReferenceBatchOutputs:
    bucket: str
    object: str
    receipt_object: str

    def __post_init__(self) -> None:
        _bucket(self.bucket)
        _object(self.object)
        _object(self.receipt_object)
        if self.object == self.receipt_object:
            raise ReferenceBatchWorkerError("reference-batch-object-collision")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReferenceBatchOutputs:
        if set(value) != {"bucket", "object", "receipt_object"}:
            raise ReferenceBatchWorkerError("reference-batch-task-invalid")
        return cls(
            bucket=cast(str, value.get("bucket")),
            object=cast(str, value.get("object")),
            receipt_object=cast(str, value.get("receipt_object")),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "bucket": self.bucket,
            "object": self.object,
            "receipt_object": self.receipt_object,
        }


@dataclass(frozen=True, slots=True)
class ReferenceBatchTask:
    execution_id: str
    execution_spec_sha256: str
    job: Mapping[str, Any]
    job_object: ReferenceBatchObject
    source_object: ReferenceBatchObject
    config_object: ReferenceBatchObject
    resource_object: ReferenceBatchObject
    outputs: ReferenceBatchOutputs
    execution_identity: ReferenceExecutionIdentity

    def __post_init__(self) -> None:
        if (
            not isinstance(self.execution_id, str)
            or _EXECUTION_ID.fullmatch(self.execution_id) is None
        ):
            raise ReferenceBatchWorkerError("reference-batch-task-invalid")
        _digest(self.execution_spec_sha256)
        if self.execution_identity.mode != "google-cloud-batch":
            raise ReferenceBatchWorkerError("reference-batch-identity-invalid")
        try:
            job = ReferenceRenderJob.from_mapping(_plain_json(self.job))
        except ReferenceWorkerError as error:
            raise ReferenceBatchWorkerError("reference-batch-task-invalid") from error
        frozen_job = _freeze_json(job.to_dict())
        object.__setattr__(self, "job", cast(Mapping[str, Any], frozen_job))
        job_bytes = _canonical_json_bytes(job.to_dict())
        if (
            self.job_object.sha256 != _digest_bytes(job_bytes)
            or self.job_object.byte_length != len(job_bytes)
            or self.source_object.sha256 != job.source_sha256
            or self.source_object.byte_length != job.source_bytes
            or self.config_object.sha256 != job.config_sha256
            or self.resource_object.sha256 != job.resource_sha256
        ):
            raise ReferenceBatchWorkerError("reference-batch-input-binding-invalid")
        inputs = {
            (item.bucket, item.object)
            for item in (
                self.job_object,
                self.source_object,
                self.config_object,
                self.resource_object,
            )
        }
        outputs = {
            (self.outputs.bucket, self.outputs.object),
            (self.outputs.bucket, self.outputs.receipt_object),
        }
        if len(inputs) != 4 or inputs.intersection(outputs):
            raise ReferenceBatchWorkerError("reference-batch-object-collision")
        execution_spec = {
            "schema": "reference-execution-spec/v1",
            "execution_id": self.execution_id,
            "job": job.to_dict(),
            "inputs": {
                "job": self.job_object.to_dict(),
                "source": self.source_object.to_dict(),
                "config": self.config_object.to_dict(),
                "resource": self.resource_object.to_dict(),
            },
            "outputs": self.outputs.to_dict(),
        }
        if _digest_bytes(_canonical_json_bytes(execution_spec)) != self.execution_spec_sha256:
            raise ReferenceBatchWorkerError("reference-batch-spec-binding-invalid")

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReferenceBatchTask:
        if set(value) != _TASK_KEYS or value.get("schema") != "reference-batch-task/v1":
            raise ReferenceBatchWorkerError("reference-batch-task-invalid")
        inputs = _mapping(value.get("inputs"))
        if set(inputs) != _INPUT_KEYS:
            raise ReferenceBatchWorkerError("reference-batch-task-invalid")
        try:
            identity = ReferenceExecutionIdentity.from_mapping(
                _mapping(value.get("execution_identity"))
            )
        except ReferenceWorkerError as error:
            raise ReferenceBatchWorkerError("reference-batch-identity-invalid") from error
        return cls(
            execution_id=cast(str, value.get("execution_id")),
            execution_spec_sha256=cast(str, value.get("execution_spec_sha256")),
            job=_mapping(value.get("job")),
            job_object=ReferenceBatchObject.from_mapping(_mapping(inputs.get("job"))),
            source_object=ReferenceBatchObject.from_mapping(_mapping(inputs.get("source"))),
            config_object=ReferenceBatchObject.from_mapping(_mapping(inputs.get("config"))),
            resource_object=ReferenceBatchObject.from_mapping(_mapping(inputs.get("resource"))),
            outputs=ReferenceBatchOutputs.from_mapping(_mapping(value.get("outputs"))),
            execution_identity=identity,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "reference-batch-task/v1",
            "execution_id": self.execution_id,
            "execution_spec_sha256": self.execution_spec_sha256,
            "job": _plain_json(self.job),
            "inputs": {
                "job": self.job_object.to_dict(),
                "source": self.source_object.to_dict(),
                "config": self.config_object.to_dict(),
                "resource": self.resource_object.to_dict(),
            },
            "outputs": self.outputs.to_dict(),
            "execution_identity": self.execution_identity.to_dict(),
        }

    @property
    def sha256(self) -> str:
        return _digest_bytes(_canonical_json_bytes(self.to_dict()))


def encode_reference_batch_task(task: ReferenceBatchTask) -> tuple[str, str]:
    raw = _canonical_json_bytes(task.to_dict())
    if len(raw) > _MAX_TASK_BYTES:
        raise ReferenceBatchWorkerError("reference-batch-task-too-large")
    return base64.b64encode(raw).decode("ascii"), _digest_bytes(raw)


def decode_reference_batch_task(value: str, expected_sha256: str) -> ReferenceBatchTask:
    _digest(expected_sha256)
    if not isinstance(value, str) or not value or len(value) > ((_MAX_TASK_BYTES + 2) // 3) * 4:
        raise ReferenceBatchWorkerError("reference-batch-task-encoding-invalid")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, binascii.Error) as error:
        raise ReferenceBatchWorkerError("reference-batch-task-encoding-invalid") from error
    if _digest_bytes(raw) != expected_sha256:
        raise ReferenceBatchWorkerError("reference-batch-task-digest-mismatch")
    parsed = _strict_json_bytes(
        raw,
        code="reference-batch-task-invalid",
        maximum=_MAX_TASK_BYTES,
    )
    if _canonical_json_bytes(parsed) != raw:
        raise ReferenceBatchWorkerError("reference-batch-task-not-canonical")
    task = ReferenceBatchTask.from_mapping(parsed)
    if task.sha256 != expected_sha256:
        raise ReferenceBatchWorkerError("reference-batch-task-digest-mismatch")
    return task


@dataclass(frozen=True, slots=True)
class StoredBatchObject:
    bucket: str
    object: str
    generation: int
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        ReferenceBatchObject(
            bucket=self.bucket,
            object=self.object,
            generation=self.generation,
            sha256=self.sha256,
            byte_length=self.byte_length,
        )


class ReferenceBatchObjectStore(Protocol):
    def download_exact(self, reference: ReferenceBatchObject, destination: Path) -> None: ...

    def create_from_path(
        self,
        *,
        bucket: str,
        object: str,
        source: Path,
        content_type: str,
        metadata: Mapping[str, str],
    ) -> StoredBatchObject: ...

    def download_current(
        self,
        *,
        bucket: str,
        object: str,
        destination: Path,
        expected_byte_length: int | None,
        maximum_bytes: int,
        required_metadata: Mapping[str, str],
    ) -> StoredBatchObject | None: ...


class GoogleCloudStorageObjectStore:
    def __init__(
        self,
        client: Any | None = None,
        *,
        precondition_failed_type: type[BaseException] | None = None,
    ) -> None:
        if client is None:
            try:
                storage = importlib.import_module("google.cloud.storage")
                client = storage.Client()
            except (ImportError, AttributeError) as error:
                raise ReferenceBatchWorkerError("reference-batch-storage-unavailable") from error
        if precondition_failed_type is None:
            try:
                exceptions = importlib.import_module("google.api_core.exceptions")
                precondition_failed_type = cast(type[BaseException], exceptions.PreconditionFailed)
            except (ImportError, AttributeError) as error:
                raise ReferenceBatchWorkerError("reference-batch-storage-unavailable") from error
        self._client = client
        self._precondition_failed_type = precondition_failed_type

    def download_exact(self, reference: ReferenceBatchObject, destination: Path) -> None:
        blob = self._client.bucket(reference.bucket).blob(
            reference.object,
            generation=reference.generation,
        )
        blob.download_to_filename(
            str(destination),
            if_generation_match=reference.generation,
        )

    def create_from_path(
        self,
        *,
        bucket: str,
        object: str,
        source: Path,
        content_type: str,
        metadata: Mapping[str, str],
    ) -> StoredBatchObject:
        blob = self._client.bucket(bucket).blob(object)
        blob.metadata = dict(metadata)
        try:
            blob.upload_from_filename(
                str(source),
                content_type=content_type,
                if_generation_match=0,
            )
        except self._precondition_failed_type as error:
            raise ReferenceBatchObjectAlreadyExists(object) from error
        if blob.generation is None:
            blob.reload()
        generation = _positive_int(blob.generation, "reference-batch-storage-response-invalid")
        return StoredBatchObject(
            bucket=bucket,
            object=object,
            generation=generation,
            sha256=_digest_file(source),
            byte_length=source.stat().st_size,
        )

    def download_current(
        self,
        *,
        bucket: str,
        object: str,
        destination: Path,
        expected_byte_length: int | None,
        maximum_bytes: int,
        required_metadata: Mapping[str, str],
    ) -> StoredBatchObject | None:
        if (
            not isinstance(maximum_bytes, int)
            or isinstance(maximum_bytes, bool)
            or maximum_bytes < 1
            or (
                expected_byte_length is not None
                and (
                    not isinstance(expected_byte_length, int)
                    or isinstance(expected_byte_length, bool)
                    or expected_byte_length < 1
                    or expected_byte_length > maximum_bytes
                )
            )
        ):
            raise ReferenceBatchWorkerError("reference-batch-download-bound-invalid")
        live = self._client.bucket(bucket).get_blob(object)
        if live is None:
            return None
        live_metadata = live.metadata
        if (
            not isinstance(live_metadata, Mapping)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in live_metadata.items()
            )
            or set(live_metadata) != {*required_metadata, "colortrace-sha256"}
            or any(live_metadata.get(key) != value for key, value in required_metadata.items())
            or _DIGEST.fullmatch(cast(str, live_metadata.get("colortrace-sha256"))) is None
        ):
            raise ReferenceBatchWorkerError("reference-batch-storage-metadata-invalid")
        remote_byte_length = _positive_int(
            live.size,
            "reference-batch-storage-response-invalid",
        )
        # Receipt timings are intentionally replay-variable, so their canonical byte
        # length can differ. In that case the immutable generation's server-reported
        # size becomes the exact transfer length, still subject to the 64 KiB cap.
        bounded_byte_length = (
            remote_byte_length if expected_byte_length is None else expected_byte_length
        )
        if remote_byte_length != bounded_byte_length or remote_byte_length > maximum_bytes:
            raise ReferenceBatchWorkerError("reference-batch-storage-response-invalid")
        generation = _positive_int(
            live.generation,
            "reference-batch-storage-response-invalid",
        )
        version = self._client.bucket(bucket).blob(object, generation=generation)
        version.chunk_size = _GCS_DOWNLOAD_CHUNK_BYTES
        with destination.open("xb") as output:
            writer = _BoundedFileWriter(output, maximum_bytes)
            version.download_to_file(
                writer,
                if_generation_match=generation,
                checksum=None,
            )
        try:
            downloaded = destination.lstat()
        except OSError as error:
            raise ReferenceBatchWorkerError("reference-batch-storage-response-invalid") from error
        if (
            not stat.S_ISREG(downloaded.st_mode)
            or downloaded.st_nlink != 1
            or writer.byte_length != bounded_byte_length
            or downloaded.st_size != bounded_byte_length
            or _digest_file(destination) != live_metadata["colortrace-sha256"]
        ):
            raise ReferenceBatchWorkerError("reference-batch-storage-response-invalid")
        return StoredBatchObject(
            bucket=bucket,
            object=object,
            generation=generation,
            sha256=_digest_file(destination),
            byte_length=destination.stat().st_size,
        )


def _positive_int(value: Any, code: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ReferenceBatchWorkerError(code) from error
    if parsed < 1:
        raise ReferenceBatchWorkerError(code)
    return parsed


ReferenceBatchWorkerCallable = Callable[..., Mapping[str, Any]]


@dataclass(frozen=True, slots=True)
class ReferenceBatchResult:
    task_sha256: str
    output: StoredBatchObject
    receipt: StoredBatchObject

    def to_dict(self) -> dict[str, Any]:
        def stored(value: StoredBatchObject) -> dict[str, Any]:
            return {
                "bucket": value.bucket,
                "object": value.object,
                "generation": value.generation,
                "sha256": value.sha256,
                "byte_length": value.byte_length,
            }

        return {
            "schema": "reference-batch-result/v1",
            "task_sha256": self.task_sha256,
            "output": stored(self.output),
            "receipt": stored(self.receipt),
        }


def _download_input(
    store: ReferenceBatchObjectStore,
    reference: ReferenceBatchObject,
    destination: Path,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        store.download_exact(reference, destination)
        metadata = destination.lstat()
    except ReferenceBatchWorkerError:
        raise
    except Exception as error:
        raise ReferenceBatchWorkerError("reference-batch-input-download-failed") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != reference.byte_length
        or _digest_file(destination) != reference.sha256
    ):
        raise ReferenceBatchWorkerError("reference-batch-input-integrity-failed")
    os.chmod(destination, 0o400)


def _publish_exact(
    store: ReferenceBatchObjectStore,
    *,
    bucket: str,
    object: str,
    source: Path,
    content_type: str,
    metadata: Mapping[str, str],
    replay_path: Path,
    maximum_bytes: int,
) -> StoredBatchObject:
    expected_sha256 = _digest_file(source)
    expected_bytes = source.stat().st_size
    if expected_bytes > maximum_bytes:
        raise ReferenceBatchWorkerError("reference-batch-render-output-invalid")
    try:
        created = store.create_from_path(
            bucket=bucket,
            object=object,
            source=source,
            content_type=content_type,
            metadata=metadata,
        )
    except ReferenceBatchObjectAlreadyExists:
        try:
            existing = store.download_current(
                bucket=bucket,
                object=object,
                destination=replay_path,
                expected_byte_length=expected_bytes,
                maximum_bytes=maximum_bytes,
                required_metadata={
                    key: value for key, value in metadata.items() if key != "colortrace-sha256"
                },
            )
            identical = existing is not None and filecmp.cmp(
                source,
                replay_path,
                shallow=False,
            )
        except Exception as error:
            raise ReferenceBatchWorkerError("reference-batch-output-conflict") from error
        if (
            existing is None
            or existing.sha256 != expected_sha256
            or existing.byte_length != expected_bytes
            or not identical
        ):
            raise ReferenceBatchWorkerError("reference-batch-output-conflict") from None
        return existing
    except Exception as error:
        raise ReferenceBatchWorkerError("reference-batch-output-upload-failed") from error
    if (
        created.bucket != bucket
        or created.object != object
        or created.sha256 != expected_sha256
        or created.byte_length != expected_bytes
    ):
        raise ReferenceBatchWorkerError("reference-batch-storage-response-invalid")
    return created


def parse_reference_receipt(raw: bytes) -> dict[str, Any]:
    value = dict(
        _strict_json_bytes(
            raw,
            code="reference-batch-receipt-invalid",
            maximum=_MAX_RECEIPT_BYTES,
        )
    )
    try:
        schema = json.loads(REFERENCE_RECEIPT_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(value)
    except (OSError, ValidationError, ValueError) as error:
        raise ReferenceBatchWorkerError("reference-batch-receipt-invalid") from error
    declared = cast(str, value["receipt_sha256"])
    body = dict(value)
    del body["receipt_sha256"]
    if _digest_bytes(_canonical_json_bytes(body)) != declared:
        raise ReferenceBatchWorkerError("reference-batch-receipt-digest-mismatch")
    return value


def validate_reference_receipt(
    receipt: Mapping[str, Any],
    *,
    task: ReferenceBatchTask,
    output_sha256: str,
    output_bytes: int,
) -> None:
    validate_reference_render_receipt(
        receipt,
        job=task.job,
        execution_identity=task.execution_identity,
        output_sha256=output_sha256,
        output_bytes=output_bytes,
    )


def validate_reference_render_receipt(
    receipt: Mapping[str, Any],
    *,
    job: ReferenceRenderJob | Mapping[str, Any],
    execution_identity: ReferenceExecutionIdentity,
    output_sha256: str,
    output_bytes: int,
) -> None:
    render_job = (
        job
        if isinstance(job, ReferenceRenderJob)
        else ReferenceRenderJob.from_mapping(_plain_json(job))
    )
    expected = {
        "job_sha256": _digest_bytes(_canonical_json_bytes(render_job.to_dict())),
        "execution_identity": execution_identity.to_dict(),
        "execution_identity_sha256": execution_identity.sha256,
        "job_id": render_job.job_id,
        "scenario_id": render_job.scenario_id,
        "incident_class": render_job.incident_class,
        "trace_id": render_job.trace_id,
        "worker_id": render_job.worker_id,
        "artifact_id": render_job.artifact_id,
        "source_sha256": render_job.source_sha256,
        "config_sha256": render_job.config_sha256,
        "resource_sha256": render_job.resource_sha256,
        "input_color_space": render_job.input_color_space,
        "output_color_space": render_job.output_color_space,
        "effective_generation": render_job.effective_generation,
        "cache_key": render_job.cache_key,
        "output_relative_path": render_job.output_relative_path,
        "output_sha256": output_sha256,
        "bytes_read": render_job.source_bytes,
        "bytes_written": output_bytes,
    }
    if any(_plain_json(receipt.get(key)) != value for key, value in expected.items()):
        raise ReferenceBatchWorkerError("reference-batch-receipt-binding-invalid")
    width = receipt.get("width")
    height = receipt.get("height")
    pixel_work = receipt.get("pixel_work")
    if (
        not isinstance(width, int)
        or isinstance(width, bool)
        or not isinstance(height, int)
        or isinstance(height, bool)
        or not isinstance(pixel_work, int)
        or isinstance(pixel_work, bool)
        or pixel_work != width * height
    ):
        raise ReferenceBatchWorkerError("reference-batch-receipt-binding-invalid")


def _semantic_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    result = {str(key): _plain_json(child) for key, child in value.items()}
    for key in ("cpu_nanoseconds", "wall_nanoseconds", "receipt_sha256"):
        result.pop(key, None)
    return result


def _publish_receipt(
    store: ReferenceBatchObjectStore,
    *,
    task: ReferenceBatchTask,
    source: Path,
    local_receipt: Mapping[str, Any],
    output: StoredBatchObject,
    task_sha256: str,
    replay_path: Path,
) -> StoredBatchObject:
    metadata = {
        "colortrace-kind": "reference-render-receipt",
        "colortrace-sha256": _digest_file(source),
        "colortrace-task-sha256": task_sha256,
        "colortrace-execution-spec-sha256": task.execution_spec_sha256,
    }
    try:
        created = store.create_from_path(
            bucket=task.outputs.bucket,
            object=task.outputs.receipt_object,
            source=source,
            content_type="application/json",
            metadata=metadata,
        )
    except ReferenceBatchObjectAlreadyExists:
        try:
            existing = store.download_current(
                bucket=task.outputs.bucket,
                object=task.outputs.receipt_object,
                destination=replay_path,
                expected_byte_length=None,
                maximum_bytes=_MAX_RECEIPT_BYTES,
                required_metadata={
                    key: value for key, value in metadata.items() if key != "colortrace-sha256"
                },
            )
            if existing is None:
                raise ReferenceBatchWorkerError("reference-batch-receipt-conflict")
            existing_receipt = parse_reference_receipt(replay_path.read_bytes())
            validate_reference_receipt(
                existing_receipt,
                task=task,
                output_sha256=output.sha256,
                output_bytes=output.byte_length,
            )
        except ReferenceBatchWorkerError:
            raise
        except Exception as error:
            raise ReferenceBatchWorkerError("reference-batch-receipt-conflict") from error
        if _semantic_receipt(existing_receipt) != _semantic_receipt(local_receipt):
            raise ReferenceBatchWorkerError("reference-batch-receipt-conflict") from None
        return existing
    except Exception as error:
        raise ReferenceBatchWorkerError("reference-batch-receipt-upload-failed") from error
    if (
        created.bucket != task.outputs.bucket
        or created.object != task.outputs.receipt_object
        or created.sha256 != _digest_file(source)
        or created.byte_length != source.stat().st_size
    ):
        raise ReferenceBatchWorkerError("reference-batch-storage-response-invalid")
    return created


def execute_reference_batch_task(
    task: ReferenceBatchTask,
    *,
    store: ReferenceBatchObjectStore,
    worker: ReferenceBatchWorkerCallable = execute_reference_render_job_file,
) -> ReferenceBatchResult:
    job = ReferenceRenderJob.from_mapping(_plain_json(task.job))
    with tempfile.TemporaryDirectory(prefix="colortrace-reference-batch-") as temporary_name:
        root = Path(temporary_name)
        job_path = root / "job.json"
        source_root = root / "source"
        config_root = root / "config"
        output_root = root / "output"
        source_path = source_root / PurePosixPath(job.source_relative_path)
        config_path = config_root / PurePosixPath(job.config_relative_path)
        resource_path = config_root / PurePosixPath(job.resource_relative_path)
        for reference, destination in (
            (task.job_object, job_path),
            (task.source_object, source_path),
            (task.config_object, config_path),
            (task.resource_object, resource_path),
        ):
            _download_input(store, reference, destination)
        if job_path.read_bytes() != _canonical_json_bytes(_plain_json(task.job)):
            raise ReferenceBatchWorkerError("reference-batch-job-content-mismatch")
        output_root.mkdir(mode=0o700)
        try:
            receipt = dict(
                worker(
                    job_path,
                    source_root=source_root,
                    config_root=config_root,
                    output_root=output_root,
                    receipt_relative_path="receipt.json",
                    execution_identity=task.execution_identity,
                )
            )
        except ReferenceBatchWorkerError:
            raise
        except ReferenceWorkerError as error:
            raise ReferenceBatchWorkerError(error.code) from error
        except Exception as error:
            raise ReferenceBatchWorkerError("reference-batch-render-failed") from error
        output_path = output_root / PurePosixPath(job.output_relative_path)
        receipt_path = output_root / "receipt.json"
        try:
            output_metadata = output_path.lstat()
            receipt_metadata = receipt_path.lstat()
        except OSError as error:
            raise ReferenceBatchWorkerError("reference-batch-render-output-invalid") from error
        if (
            not stat.S_ISREG(output_metadata.st_mode)
            or not stat.S_ISREG(receipt_metadata.st_mode)
            or output_metadata.st_nlink != 1
            or receipt_metadata.st_nlink != 1
            or output_metadata.st_size > _MAX_OUTPUT_BYTES
            or receipt_metadata.st_size > _MAX_RECEIPT_BYTES
        ):
            raise ReferenceBatchWorkerError("reference-batch-render-output-invalid")
        parsed_receipt = parse_reference_receipt(receipt_path.read_bytes())
        if parsed_receipt != receipt:
            raise ReferenceBatchWorkerError("reference-batch-receipt-invalid")
        output_sha256 = _digest_file(output_path)
        validate_reference_receipt(
            parsed_receipt,
            task=task,
            output_sha256=output_sha256,
            output_bytes=output_metadata.st_size,
        )
        task_sha256 = task.sha256
        output = _publish_exact(
            store,
            bucket=task.outputs.bucket,
            object=task.outputs.object,
            source=output_path,
            content_type="image/x-exr",
            metadata={
                "colortrace-kind": "reference-render-output",
                "colortrace-sha256": output_sha256,
                "colortrace-task-sha256": task_sha256,
                "colortrace-execution-spec-sha256": task.execution_spec_sha256,
            },
            replay_path=root / "existing-output",
            maximum_bytes=_MAX_OUTPUT_BYTES,
        )
        receipt_object = _publish_receipt(
            store,
            task=task,
            source=receipt_path,
            local_receipt=parsed_receipt,
            output=output,
            task_sha256=task_sha256,
            replay_path=root / "existing-receipt",
        )
        return ReferenceBatchResult(
            task_sha256=task_sha256,
            output=output,
            receipt=receipt_object,
        )


def _assert_runtime_source_identity(task: ReferenceBatchTask) -> None:
    if (
        os.environ.get("COLORTRACE_SOURCE_REVISION") != task.execution_identity.source_revision
        or os.environ.get("COLORTRACE_SOURCE_TREE") != task.execution_identity.source_tree
    ):
        raise ReferenceBatchWorkerError("reference-batch-runtime-identity-mismatch")


def main() -> None:
    parser = ArgumentParser(prog="colortrace-reference-batch-worker")
    parser.add_argument("--task-base64", required=True)
    parser.add_argument("--task-sha256", required=True)
    arguments = parser.parse_args()
    try:
        task = decode_reference_batch_task(arguments.task_base64, arguments.task_sha256)
        _assert_runtime_source_identity(task)
        result = execute_reference_batch_task(
            task,
            store=GoogleCloudStorageObjectStore(),
        )
    except (ReferenceBatchWorkerError, ReferenceWorkerError) as error:
        code = getattr(error, "code", "reference-batch-worker-failed")
        print(code, file=sys.stderr)
        raise SystemExit(2) from error
    print(_canonical_json_bytes(result.to_dict()).decode("utf-8"))


__all__ = [
    "GoogleCloudStorageObjectStore",
    "ReferenceBatchObject",
    "ReferenceBatchObjectAlreadyExists",
    "ReferenceBatchObjectStore",
    "ReferenceBatchOutputs",
    "ReferenceBatchResult",
    "ReferenceBatchTask",
    "ReferenceBatchWorkerError",
    "StoredBatchObject",
    "decode_reference_batch_task",
    "encode_reference_batch_task",
    "execute_reference_batch_task",
    "main",
    "parse_reference_receipt",
    "validate_reference_receipt",
    "validate_reference_render_receipt",
]


if __name__ == "__main__":
    main()
