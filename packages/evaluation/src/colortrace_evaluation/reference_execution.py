from __future__ import annotations

import hashlib
import re
import stat
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Protocol, cast

from colortrace_simulator.reference_batch_worker import (
    ReferenceBatchObject,
    ReferenceBatchOutputs,
    ReferenceBatchTask,
    ReferenceBatchWorkerError,
    encode_reference_batch_task,
    parse_reference_receipt,
    validate_reference_receipt,
    validate_reference_render_receipt,
)
from colortrace_simulator.reference_worker import (
    ReferenceExecutionIdentity,
    ReferenceWorkerError,
)

from .contracts import canonical_json_bytes, prefixed_sha256, sha256_file

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_EXECUTION_ID = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_REGION = re.compile(r"^[a-z]+-[a-z]+[0-9]$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$")
_OBJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
_TRACE = re.compile(r"^[0-9a-f]{32}$")
_MAX_REFERENCE_OUTPUT_BYTES = 512 * 1024 * 1024
_MAX_REFERENCE_RECEIPT_BYTES = 65_536
_SCENARIO_CLASSES = {
    "tos-resource-resolution-drift-v1": "resource-resolution-drift/v1",
    "tos-config-rollout-drift-v1": "configuration-rollout-drift/v1",
    "tos-stale-derivative-cache-v1": "stale-derivative-cache/v1",
}
_JOB_KEYS = {
    "schema",
    "job_id",
    "scenario_id",
    "incident_class",
    "trace_id",
    "worker_id",
    "artifact_id",
    "source",
    "color",
    "runtime",
    "output",
}


class ReferenceExecutionError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BatchAlreadyExists(RuntimeError):
    pass


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(child) for child in value]
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ReferenceExecutionError("reference-job-invalid")
        return MappingProxyType({key: _freeze_json(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(child) for child in value)
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise ReferenceExecutionError("reference-job-invalid")


def _mapping(value: Any, *, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ReferenceExecutionError(code)
    return cast(Mapping[str, Any], value)


def _exact_keys(value: Mapping[str, Any], expected: set[str]) -> None:
    if set(value) != expected:
        raise ReferenceExecutionError("reference-job-invalid")


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ReferenceExecutionError("reference-job-invalid")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReferenceExecutionError("reference-job-invalid")
    return value


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReferenceExecutionError("reference-path-invalid")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ReferenceExecutionError("reference-path-invalid")
    return value


def _object_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or _OBJECT.fullmatch(value) is None
        or "//" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ReferenceExecutionError("gcs-object-invalid")
    return value


def _bucket_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or _BUCKET.fullmatch(value) is None
        or ".." in value
        or value.startswith("goog")
    ):
        raise ReferenceExecutionError("gcs-bucket-invalid")
    return value


def _validate_job(job: Mapping[str, Any]) -> None:
    _exact_keys(job, _JOB_KEYS)
    if job.get("schema") != "reference-render-job/v1":
        raise ReferenceExecutionError("reference-job-invalid")
    for key in ("job_id", "scenario_id", "worker_id", "artifact_id"):
        _identifier(job.get(key))
    trace_id = job.get("trace_id")
    scenario_id = cast(str, job["scenario_id"])
    if not isinstance(trace_id, str) or _TRACE.fullmatch(trace_id) is None:
        raise ReferenceExecutionError("reference-job-invalid")
    if _SCENARIO_CLASSES.get(scenario_id) != job.get("incident_class"):
        raise ReferenceExecutionError("reference-job-invalid")

    source = _mapping(job.get("source"), code="reference-job-invalid")
    color = _mapping(job.get("color"), code="reference-job-invalid")
    runtime = _mapping(job.get("runtime"), code="reference-job-invalid")
    output = _mapping(job.get("output"), code="reference-job-invalid")
    _exact_keys(source, {"relative_path", "sha256", "byte_length"})
    _exact_keys(
        color,
        {
            "config_relative_path",
            "config_sha256",
            "resource_relative_path",
            "resource_sha256",
            "input_color_space",
            "output_color_space",
        },
    )
    _exact_keys(runtime, {"effective_generation", "cache_key"})
    _exact_keys(output, {"relative_path"})
    _relative_path(source.get("relative_path"))
    _relative_path(color.get("config_relative_path"))
    _relative_path(color.get("resource_relative_path"))
    _relative_path(output.get("relative_path"))
    _digest(source.get("sha256"))
    _digest(color.get("config_sha256"))
    _digest(color.get("resource_sha256"))
    source_bytes = source.get("byte_length")
    generation = runtime.get("effective_generation")
    if (
        not isinstance(source_bytes, int)
        or isinstance(source_bytes, bool)
        or source_bytes < 1
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
    ):
        raise ReferenceExecutionError("reference-job-invalid")
    _identifier(color.get("input_color_space"))
    _identifier(color.get("output_color_space"))
    cache_key = runtime.get("cache_key")
    if cache_key is not None:
        _identifier(cache_key)


@dataclass(frozen=True, slots=True)
class GcsObjectRef:
    bucket: str
    object: str
    generation: int
    sha256: str
    byte_length: int

    def __post_init__(self) -> None:
        _bucket_name(self.bucket)
        _object_name(self.object)
        if (
            not isinstance(self.generation, int)
            or isinstance(self.generation, bool)
            or self.generation < 1
        ):
            raise ReferenceExecutionError("gcs-generation-invalid")
        if not isinstance(self.sha256, str) or _DIGEST.fullmatch(self.sha256) is None:
            raise ReferenceExecutionError("gcs-digest-invalid")
        if (
            not isinstance(self.byte_length, int)
            or isinstance(self.byte_length, bool)
            or self.byte_length < 1
        ):
            raise ReferenceExecutionError("gcs-byte-length-invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "bucket": self.bucket,
            "object": self.object,
            "generation": self.generation,
            "sha256": self.sha256,
            "byte_length": self.byte_length,
        }


@dataclass(frozen=True, slots=True)
class ReferenceExecutionSpec:
    execution_id: str
    job: Mapping[str, Any]
    job_object: GcsObjectRef
    source_object: GcsObjectRef
    config_object: GcsObjectRef
    resource_object: GcsObjectRef
    output_bucket: str
    output_object: str
    receipt_object: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.execution_id, str)
            or _EXECUTION_ID.fullmatch(self.execution_id) is None
        ):
            raise ReferenceExecutionError("reference-execution-id-invalid")
        frozen = _freeze_json(self.job)
        job = _mapping(frozen, code="reference-job-invalid")
        _validate_job(job)
        object.__setattr__(self, "job", job)
        _bucket_name(self.output_bucket)
        _object_name(self.output_object)
        _object_name(self.receipt_object)
        if self.output_object == self.receipt_object:
            raise ReferenceExecutionError("gcs-output-collision")

        job_body = _plain_json(job)
        encoded_job = canonical_json_bytes(job_body)
        if self.job_object.sha256 != prefixed_sha256(
            job_body
        ) or self.job_object.byte_length != len(encoded_job):
            raise ReferenceExecutionError("reference-job-object-mismatch")
        source = _mapping(job["source"], code="reference-job-invalid")
        color = _mapping(job["color"], code="reference-job-invalid")
        if (
            self.source_object.sha256 != source["sha256"]
            or self.source_object.byte_length != source["byte_length"]
        ):
            raise ReferenceExecutionError("reference-source-object-mismatch")
        if self.config_object.sha256 != color["config_sha256"]:
            raise ReferenceExecutionError("reference-config-object-mismatch")
        if self.resource_object.sha256 != color["resource_sha256"]:
            raise ReferenceExecutionError("reference-resource-object-mismatch")
        input_names = {
            (reference.bucket, reference.object)
            for reference in (
                self.job_object,
                self.source_object,
                self.config_object,
                self.resource_object,
            )
        }
        if len(input_names) != 4 or any(
            (self.output_bucket, name) in input_names
            for name in (self.output_object, self.receipt_object)
        ):
            raise ReferenceExecutionError("gcs-object-collision")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "reference-execution-spec/v1",
            "execution_id": self.execution_id,
            "job": _plain_json(self.job),
            "inputs": {
                "job": self.job_object.to_dict(),
                "source": self.source_object.to_dict(),
                "config": self.config_object.to_dict(),
                "resource": self.resource_object.to_dict(),
            },
            "outputs": {
                "bucket": self.output_bucket,
                "object": self.output_object,
                "receipt_object": self.receipt_object,
            },
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> ReferenceExecutionSpec:
        if (
            set(value) != {"schema", "execution_id", "job", "inputs", "outputs"}
            or value.get("schema") != "reference-execution-spec/v1"
        ):
            raise ReferenceExecutionError("reference-execution-spec-invalid")
        inputs = _mapping(value.get("inputs"), code="reference-execution-spec-invalid")
        outputs = _mapping(value.get("outputs"), code="reference-execution-spec-invalid")
        if set(inputs) != {"job", "source", "config", "resource"} or set(outputs) != {
            "bucket",
            "object",
            "receipt_object",
        }:
            raise ReferenceExecutionError("reference-execution-spec-invalid")

        def object_reference(name: str) -> GcsObjectRef:
            item = _mapping(inputs.get(name), code="reference-execution-spec-invalid")
            if set(item) != {"bucket", "object", "generation", "sha256", "byte_length"}:
                raise ReferenceExecutionError("reference-execution-spec-invalid")
            return GcsObjectRef(
                bucket=cast(str, item.get("bucket")),
                object=cast(str, item.get("object")),
                generation=cast(int, item.get("generation")),
                sha256=cast(str, item.get("sha256")),
                byte_length=cast(int, item.get("byte_length")),
            )

        return cls(
            execution_id=cast(str, value.get("execution_id")),
            job=_mapping(value.get("job"), code="reference-execution-spec-invalid"),
            job_object=object_reference("job"),
            source_object=object_reference("source"),
            config_object=object_reference("config"),
            resource_object=object_reference("resource"),
            output_bucket=cast(str, outputs.get("bucket")),
            output_object=cast(str, outputs.get("object")),
            receipt_object=cast(str, outputs.get("receipt_object")),
        )

    @property
    def sha256(self) -> str:
        return prefixed_sha256(self.to_dict())


class ReferenceWorkerCallable(Protocol):
    def __call__(
        self,
        value: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
        execution_identity: ReferenceExecutionIdentity | Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


class LocalReferenceExecutor:
    def __init__(
        self,
        worker: ReferenceWorkerCallable | None = None,
        *,
        execution_identity: ReferenceExecutionIdentity | Mapping[str, Any],
    ) -> None:
        self._worker = worker
        try:
            self._execution_identity = (
                execution_identity
                if isinstance(execution_identity, ReferenceExecutionIdentity)
                else ReferenceExecutionIdentity.from_mapping(execution_identity)
            )
        except ReferenceWorkerError as error:
            raise ReferenceExecutionError("reference-execution-identity-invalid") from error

    def execute(
        self,
        spec: ReferenceExecutionSpec,
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
    ) -> dict[str, Any]:
        worker = self._worker
        if worker is None:
            from colortrace_simulator.reference_worker import (
                execute_reference_render_job,
            )

            worker = execute_reference_render_job
        result = worker(
            cast(Mapping[str, Any], _plain_json(spec.job)),
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            execution_identity=self._execution_identity,
        )
        if not isinstance(result, Mapping) or any(not isinstance(key, str) for key in result):
            raise ReferenceExecutionError("reference-local-receipt-invalid")
        try:
            parsed = parse_reference_receipt(canonical_json_bytes(_plain_json(result)))
            root = output_root.resolve(strict=True)
            root_metadata = root.lstat()
            relative = _relative_path(
                _mapping(spec.job["output"], code="reference-job-invalid")["relative_path"]
            )
            candidate = output_root / relative
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
            output_metadata = resolved.lstat()
            if (
                root != output_root.absolute()
                or not stat.S_ISDIR(root_metadata.st_mode)
                or candidate != resolved
                or candidate.is_symlink()
                or not stat.S_ISREG(output_metadata.st_mode)
                or output_metadata.st_nlink != 1
            ):
                raise ReferenceExecutionError("reference-local-output-invalid")
            validate_reference_render_receipt(
                parsed,
                job=spec.job,
                execution_identity=self._execution_identity,
                output_sha256=sha256_file(resolved),
                output_bytes=output_metadata.st_size,
            )
        except ReferenceExecutionError:
            raise
        except (OSError, ValueError, ReferenceBatchWorkerError, ReferenceWorkerError) as error:
            raise ReferenceExecutionError("reference-local-receipt-invalid") from error
        return parsed


@dataclass(frozen=True, slots=True)
class GcsBucketSecurity:
    project_id: str
    bucket: str
    uniform_bucket_level_access: bool
    public_access_prevention: str


@dataclass(frozen=True, slots=True)
class GoogleBatchExecutionPlan:
    parent: str
    job_id: str
    job_resource: str
    request_id: str
    spec_sha256: str
    task_sha256: str
    request_sha256: str
    request: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request", _freeze_json(self.request))


@dataclass(frozen=True, slots=True)
class BatchSubmission:
    job_resource: str
    job_id: str
    request_id: str
    spec_sha256: str
    request_sha256: str
    duplicate: bool


@dataclass(frozen=True, slots=True)
class BatchReconciliation:
    job_resource: str
    state: str
    spec_sha256: str
    output: GcsObjectRef | None
    receipt: GcsObjectRef | None


class BatchClient(Protocol):
    @property
    def principal(self) -> str: ...

    def get_job(self, *, name: str) -> Mapping[str, Any] | None: ...

    def create_job(
        self,
        *,
        parent: str,
        job_id: str,
        request_id: str,
        job: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


class GcsControlClient(Protocol):
    """Read-only control-plane access; the Batch worker owns data transfer."""

    @property
    def principal(self) -> str: ...

    def inspect_bucket(self, *, bucket: str) -> GcsBucketSecurity: ...

    def describe_object(self, *, bucket: str, object: str) -> GcsObjectRef | None: ...

    def download_bytes(
        self,
        *,
        reference: GcsObjectRef,
        maximum_bytes: int,
    ) -> bytes: ...

    def digest_object(
        self,
        *,
        reference: GcsObjectRef,
        maximum_bytes: int,
    ) -> tuple[str, int]: ...


def _service_account(value: str, project_id: str) -> str:
    if not isinstance(value, str):
        raise ReferenceExecutionError("batch-service-account-invalid")
    suffix = f"@{project_id}.iam.gserviceaccount.com"
    local = value.removesuffix(suffix)
    if not value.endswith(suffix) or not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", local):
        raise ReferenceExecutionError("batch-service-account-invalid")
    return value


def _worker_image(value: str) -> str:
    if not isinstance(value, str):
        raise ReferenceExecutionError("batch-worker-image-not-pinned")
    prefix, separator, _digest_value = value.rpartition("@sha256:")
    if (
        not separator
        or _IMAGE.fullmatch(value) is None
        or ":" in prefix
        or "//" in prefix
        or any(part in {"", ".", ".."} for part in prefix.split("/"))
    ):
        raise ReferenceExecutionError("batch-worker-image-not-pinned")
    return value


def _network(value: str, project_id: str) -> str:
    pattern = re.compile(
        rf"^projects/{re.escape(project_id)}/global/networks/"
        r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReferenceExecutionError("batch-network-invalid")
    return value


def _subnetwork(value: str, project_id: str, region: str) -> str:
    pattern = re.compile(
        rf"^projects/{re.escape(project_id)}/regions/{re.escape(region)}/subnetworks/"
        r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
    )
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ReferenceExecutionError("batch-subnetwork-invalid")
    return value


def _batch_object(reference: GcsObjectRef) -> ReferenceBatchObject:
    try:
        return ReferenceBatchObject(**reference.to_dict())
    except ReferenceBatchWorkerError as error:
        raise ReferenceExecutionError("reference-batch-task-invalid") from error


def _expected_projection(
    expected: Any,
    remote: Any,
    *,
    path: tuple[str, ...] = (),
) -> Any:
    if isinstance(expected, Mapping):
        if not isinstance(remote, Mapping):
            raise ReferenceExecutionError("batch-job-identity-conflict")
        allowed_extras = (
            {"name", "uid", "status", "createTime", "updateTime"}
            if not path
            else {"name"}
            if path == ("taskGroups", "*")
            else set()
        )
        if not set(remote).difference(expected).issubset(allowed_extras):
            raise ReferenceExecutionError("batch-job-identity-conflict")
        projected: dict[str, Any] = {}
        for key, child in expected.items():
            if key not in remote:
                raise ReferenceExecutionError("batch-job-identity-conflict")
            projected[str(key)] = _expected_projection(
                child,
                remote[key],
                path=(*path, str(key)),
            )
        return projected
    if isinstance(expected, (list, tuple)):
        if (
            not isinstance(remote, Sequence)
            or isinstance(remote, (str, bytes, bytearray))
            or len(remote) != len(expected)
        ):
            raise ReferenceExecutionError("batch-job-identity-conflict")
        return [
            _expected_projection(expected_child, remote_child, path=(*path, "*"))
            for expected_child, remote_child in zip(expected, remote, strict=True)
        ]
    if remote != expected:
        raise ReferenceExecutionError("batch-job-identity-conflict")
    return remote


def _normalized_batch_job_response(
    plan: GoogleBatchExecutionPlan,
    expected_request: Mapping[str, Any],
    value: Mapping[str, Any],
) -> Mapping[str, Any]:
    remote = dict(value)
    allocation_value = value.get("allocationPolicy")
    expected_allocation_value = expected_request.get("allocationPolicy")
    if not isinstance(allocation_value, Mapping) or not isinstance(
        expected_allocation_value, Mapping
    ):
        raise ReferenceExecutionError("batch-job-identity-conflict")
    allocation = dict(allocation_value)

    if "labels" in allocation:
        provider_labels = allocation.pop("labels")
        if not isinstance(provider_labels, Mapping) or dict(provider_labels) != {
            "batch-job-id": plan.job_id
        }:
            raise ReferenceExecutionError("batch-job-identity-conflict")

    location_value = allocation.get("location")
    expected_location_value = expected_allocation_value.get("location")
    if not isinstance(location_value, Mapping) or not isinstance(expected_location_value, Mapping):
        raise ReferenceExecutionError("batch-job-identity-conflict")
    location = dict(location_value)
    observed_locations = location.get("allowedLocations")
    expected_locations = expected_location_value.get("allowedLocations")
    if observed_locations != expected_locations:
        if (
            not isinstance(expected_locations, Sequence)
            or isinstance(expected_locations, (str, bytes, bytearray))
            or len(expected_locations) != 1
            or not isinstance(expected_locations[0], str)
            or not expected_locations[0].startswith("regions/")
            or not isinstance(observed_locations, list)
            or not observed_locations
        ):
            raise ReferenceExecutionError("batch-job-identity-conflict")
        region = expected_locations[0].removeprefix("regions/")
        zone = re.compile(rf"^zones/{re.escape(region)}-[a-z]$")
        if any(
            not isinstance(item, str)
            or (item != expected_locations[0] and zone.fullmatch(item) is None)
            for item in observed_locations
        ) or len(set(observed_locations)) != len(observed_locations):
            raise ReferenceExecutionError("batch-job-identity-conflict")
        location["allowedLocations"] = list(expected_locations)

    allocation["location"] = location
    remote["allocationPolicy"] = allocation
    return remote


@dataclass(frozen=True, slots=True)
class GoogleBatchPlanner:
    project_id: str
    region: str
    worker_image: str
    source_revision: str
    source_tree: str
    submitter_service_account: str
    worker_service_account: str
    network: str
    subnetwork: str

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, str) or _PROJECT_ID.fullmatch(self.project_id) is None:
            raise ReferenceExecutionError("batch-project-invalid")
        if not isinstance(self.region, str) or _REGION.fullmatch(self.region) is None:
            raise ReferenceExecutionError("batch-region-invalid")
        _worker_image(self.worker_image)
        try:
            ReferenceExecutionIdentity.from_mapping(
                {
                    "mode": "google-cloud-batch",
                    "source_revision": self.source_revision,
                    "source_tree": self.source_tree,
                    "container_image_digest": self.worker_image.rpartition("@")[2],
                }
            )
        except ReferenceWorkerError as error:
            raise ReferenceExecutionError("batch-source-identity-invalid") from error
        _service_account(self.submitter_service_account, self.project_id)
        _service_account(self.worker_service_account, self.project_id)
        if self.submitter_service_account == self.worker_service_account:
            raise ReferenceExecutionError("batch-service-accounts-not-separated")
        _network(self.network, self.project_id)
        _subnetwork(self.subnetwork, self.project_id, self.region)

    @property
    def execution_identity(self) -> ReferenceExecutionIdentity:
        return ReferenceExecutionIdentity(
            mode="google-cloud-batch",
            source_revision=self.source_revision,
            source_tree=self.source_tree,
            container_image_digest=self.worker_image.rpartition("@")[2],
        )

    def batch_task(self, spec: ReferenceExecutionSpec) -> ReferenceBatchTask:
        try:
            return ReferenceBatchTask(
                execution_id=spec.execution_id,
                execution_spec_sha256=spec.sha256,
                job=spec.job,
                job_object=_batch_object(spec.job_object),
                source_object=_batch_object(spec.source_object),
                config_object=_batch_object(spec.config_object),
                resource_object=_batch_object(spec.resource_object),
                outputs=ReferenceBatchOutputs(
                    bucket=spec.output_bucket,
                    object=spec.output_object,
                    receipt_object=spec.receipt_object,
                ),
                execution_identity=self.execution_identity,
            )
        except (ReferenceBatchWorkerError, ReferenceWorkerError) as error:
            raise ReferenceExecutionError("reference-batch-task-invalid") from error

    def plan(self, spec: ReferenceExecutionSpec) -> GoogleBatchExecutionPlan:
        spec_hex = spec.sha256.removeprefix("sha256:")
        job_id = f"ct-ref-{spec.execution_id}-{spec_hex[:12]}"
        parent = f"projects/{self.project_id}/locations/{self.region}"
        resource = f"{parent}/jobs/{job_id}"
        request_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"colortrace:{spec.sha256}"))
        task = self.batch_task(spec)
        encoded_task, task_sha256 = encode_reference_batch_task(task)
        request: dict[str, Any] = {
            "taskGroups": [
                {
                    "taskCount": "1",
                    "parallelism": "1",
                    "taskSpec": {
                        "runnables": [
                            {
                                "displayName": "colortrace-reference-worker",
                                "container": {
                                    "imageUri": self.worker_image,
                                    "entrypoint": "colortrace-reference-batch-worker",
                                    "commands": [
                                        "--task-base64",
                                        encoded_task,
                                        "--task-sha256",
                                        task_sha256,
                                    ],
                                },
                            }
                        ],
                        "computeResource": {"cpuMilli": "2000", "memoryMib": "4096"},
                        "maxRunDuration": "3600s",
                    },
                }
            ],
            "allocationPolicy": {
                "location": {"allowedLocations": [f"regions/{self.region}"]},
                "instances": [
                    {
                        "policy": {
                            "machineType": "e2-standard-2",
                            "provisioningModel": "STANDARD",
                        }
                    }
                ],
                "serviceAccount": {"email": self.worker_service_account},
                "network": {
                    "networkInterfaces": [
                        {
                            "network": self.network,
                            "subnetwork": self.subnetwork,
                            "noExternalIpAddress": True,
                        }
                    ]
                },
            },
            "logsPolicy": {"destination": "CLOUD_LOGGING"},
            "labels": {
                "colortrace-execution": spec.execution_id,
                "colortrace-spec-sha256-a": spec_hex[:32],
                "colortrace-spec-sha256-b": spec_hex[32:],
            },
        }
        request_sha256 = prefixed_sha256(request)
        return GoogleBatchExecutionPlan(
            parent=parent,
            job_id=job_id,
            job_resource=resource,
            request_id=request_id,
            spec_sha256=spec.sha256,
            task_sha256=task_sha256,
            request_sha256=request_sha256,
            request=request,
        )


class GoogleBatchSubmitter:
    def __init__(
        self,
        *,
        planner: GoogleBatchPlanner,
        batch: BatchClient,
        objects: GcsControlClient,
    ) -> None:
        if batch.principal != planner.submitter_service_account:
            raise ReferenceExecutionError("batch-submitter-identity-mismatch")
        if objects.principal != planner.submitter_service_account:
            raise ReferenceExecutionError("gcs-control-identity-mismatch")
        self._planner = planner
        self._batch = batch
        self._objects = objects

    def _assert_private_buckets(self, spec: ReferenceExecutionSpec) -> None:
        buckets = {
            spec.job_object.bucket,
            spec.source_object.bucket,
            spec.config_object.bucket,
            spec.resource_object.bucket,
            spec.output_bucket,
        }
        for bucket in sorted(buckets):
            state = self._objects.inspect_bucket(bucket=bucket)
            if (
                state.bucket != bucket
                or state.project_id != self._planner.project_id
                or state.uniform_bucket_level_access is not True
                or state.public_access_prevention != "enforced"
            ):
                raise ReferenceExecutionError("gcs-bucket-not-private")

    @staticmethod
    def _assert_job_identity(
        plan: GoogleBatchExecutionPlan,
        value: Mapping[str, Any],
    ) -> None:
        labels = value.get("labels")
        spec_hex = plan.spec_sha256.removeprefix("sha256:")
        try:
            expected_request = _plain_json(plan.request)
            normalized = _normalized_batch_job_response(plan, expected_request, value)
            remote_request = _expected_projection(expected_request, normalized)
        except (KeyError, TypeError, ValueError) as error:
            raise ReferenceExecutionError("batch-job-identity-conflict") from error
        if (
            value.get("name") != plan.job_resource
            or not isinstance(labels, Mapping)
            or labels.get("colortrace-spec-sha256-a") != spec_hex[:32]
            or labels.get("colortrace-spec-sha256-b") != spec_hex[32:]
            or prefixed_sha256(expected_request) != plan.request_sha256
            or prefixed_sha256(remote_request) != plan.request_sha256
            or remote_request != expected_request
        ):
            raise ReferenceExecutionError("batch-job-identity-conflict")

    def submit(self, spec: ReferenceExecutionSpec) -> BatchSubmission:
        plan = self._planner.plan(spec)
        self._assert_private_buckets(spec)
        existing = self._batch.get_job(name=plan.job_resource)
        duplicate = existing is not None
        if existing is None:
            try:
                existing = self._batch.create_job(
                    parent=plan.parent,
                    job_id=plan.job_id,
                    request_id=plan.request_id,
                    job=cast(Mapping[str, Any], _plain_json(plan.request)),
                )
            except BatchAlreadyExists:
                existing = self._batch.get_job(name=plan.job_resource)
                duplicate = True
                if existing is None:
                    raise ReferenceExecutionError("batch-job-reconciliation-unavailable") from None
        self._assert_job_identity(plan, existing)
        return BatchSubmission(
            job_resource=plan.job_resource,
            job_id=plan.job_id,
            request_id=plan.request_id,
            spec_sha256=plan.spec_sha256,
            request_sha256=plan.request_sha256,
            duplicate=duplicate,
        )

    def reconcile(self, spec: ReferenceExecutionSpec) -> BatchReconciliation:
        plan = self._planner.plan(spec)
        self._assert_private_buckets(spec)
        remote = self._batch.get_job(name=plan.job_resource)
        if remote is None:
            raise ReferenceExecutionError("batch-job-unavailable")
        self._assert_job_identity(plan, remote)
        status = remote.get("status")
        state = status.get("state") if isinstance(status, Mapping) else None
        if state not in {
            "QUEUED",
            "SCHEDULED",
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "CANCELLATION_IN_PROGRESS",
            "CANCELLED",
            "DELETION_IN_PROGRESS",
        }:
            raise ReferenceExecutionError("batch-job-state-invalid")
        if state != "SUCCEEDED":
            return BatchReconciliation(
                job_resource=plan.job_resource,
                state=cast(str, state),
                spec_sha256=plan.spec_sha256,
                output=None,
                receipt=None,
            )
        output = self._objects.describe_object(
            bucket=spec.output_bucket,
            object=spec.output_object,
        )
        receipt = self._objects.describe_object(
            bucket=spec.output_bucket,
            object=spec.receipt_object,
        )
        if output is None or receipt is None:
            raise ReferenceExecutionError("gcs-output-reconciliation-invalid")
        try:
            raw_receipt = self._objects.download_bytes(
                reference=receipt,
                maximum_bytes=_MAX_REFERENCE_RECEIPT_BYTES,
            )
        except Exception as error:
            raise ReferenceExecutionError("gcs-output-reconciliation-invalid") from error
        if (
            len(raw_receipt) != receipt.byte_length
            or f"sha256:{hashlib.sha256(raw_receipt).hexdigest()}" != receipt.sha256
        ):
            raise ReferenceExecutionError("gcs-output-reconciliation-invalid")
        try:
            parsed_receipt = parse_reference_receipt(raw_receipt)
            output_sha256, output_bytes = self._objects.digest_object(
                reference=output,
                maximum_bytes=_MAX_REFERENCE_OUTPUT_BYTES,
            )
            if output_sha256 != output.sha256 or output_bytes != output.byte_length:
                raise ReferenceBatchWorkerError("reference-batch-output-integrity-failed")
            validate_reference_receipt(
                parsed_receipt,
                task=self._planner.batch_task(spec),
                output_sha256=output_sha256,
                output_bytes=output_bytes,
            )
        except (ReferenceBatchWorkerError, ReferenceExecutionError, ReferenceWorkerError) as error:
            raise ReferenceExecutionError("gcs-output-reconciliation-invalid") from error
        return BatchReconciliation(
            job_resource=plan.job_resource,
            state=state,
            spec_sha256=plan.spec_sha256,
            output=output,
            receipt=receipt,
        )


__all__ = [
    "BatchAlreadyExists",
    "BatchClient",
    "BatchReconciliation",
    "BatchSubmission",
    "GcsBucketSecurity",
    "GcsControlClient",
    "GcsObjectRef",
    "GoogleBatchExecutionPlan",
    "GoogleBatchPlanner",
    "GoogleBatchSubmitter",
    "LocalReferenceExecutor",
    "ReferenceExecutionError",
    "ReferenceExecutionSpec",
    "ReferenceWorkerCallable",
]
