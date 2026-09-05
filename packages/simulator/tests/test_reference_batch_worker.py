from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import numpy as np
import OpenImageIO as oiio
import pytest
from colortrace_fixture.fixture import lut_bytes, prepare_worker  # type: ignore[import-untyped]
from colortrace_simulator.reference_batch_worker import (
    GoogleCloudStorageObjectStore,
    ReferenceBatchObject,
    ReferenceBatchObjectAlreadyExists,
    ReferenceBatchOutputs,
    ReferenceBatchTask,
    ReferenceBatchWorkerError,
    StoredBatchObject,
    decode_reference_batch_task,
    encode_reference_batch_task,
    execute_reference_batch_task,
)
from colortrace_simulator.reference_worker import ReferenceExecutionIdentity

SOURCE_REVISION = "4" * 40
SOURCE_TREE = "5" * 40
IMAGE_DIGEST = "sha256:" + "a" * 64


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _task() -> tuple[ReferenceBatchTask, dict[tuple[str, str, int], bytes]]:
    source = b"source-frame"
    config = b"ocio-config"
    resource = b"cube-resource"
    job = {
        "schema": "reference-render-job/v1",
        "job_id": "reference-render-00000",
        "scenario_id": "tos-resource-resolution-drift-v1",
        "incident_class": "resource-resolution-drift/v1",
        "trace_id": "0123456789abcdef0123456789abcdef",
        "worker_id": "worker-A",
        "artifact_id": "frame:03_2a:00000",
        "source": {
            "relative_path": "03_2a/03_2a_00000.exr",
            "sha256": _digest(source),
            "byte_length": len(source),
        },
        "color": {
            "config_relative_path": "config.ocio",
            "config_sha256": _digest(config),
            "resource_relative_path": "luts/show_look.cube",
            "resource_sha256": _digest(resource),
            "input_color_space": "fixture_input",
            "output_color_space": "fixture_output",
        },
        "runtime": {"effective_generation": 7, "cache_key": "cache:03_2a:00000"},
        "output": {"relative_path": "renders/03_2a_00000.exr"},
    }
    job_raw = _canonical(job)
    references = {
        "job": ReferenceBatchObject(
            "ct-reference-input",
            "runs/reference-run-01/job.json",
            11,
            _digest(job_raw),
            len(job_raw),
        ),
        "source": ReferenceBatchObject(
            "ct-reference-input",
            "media/source.exr",
            12,
            _digest(source),
            len(source),
        ),
        "config": ReferenceBatchObject(
            "ct-reference-input",
            "config/config.ocio",
            13,
            _digest(config),
            len(config),
        ),
        "resource": ReferenceBatchObject(
            "ct-reference-input",
            "config/luts/show_look.cube",
            14,
            _digest(resource),
            len(resource),
        ),
    }
    outputs = ReferenceBatchOutputs(
        bucket="ct-reference-output",
        object="runs/reference-run-01/render.exr",
        receipt_object="runs/reference-run-01/receipt.json",
    )
    execution_spec = {
        "schema": "reference-execution-spec/v1",
        "execution_id": "reference-run-01",
        "job": job,
        "inputs": {name: reference.to_dict() for name, reference in references.items()},
        "outputs": outputs.to_dict(),
    }
    task = ReferenceBatchTask(
        execution_id="reference-run-01",
        execution_spec_sha256=_digest(_canonical(execution_spec)),
        job=job,
        job_object=references["job"],
        source_object=references["source"],
        config_object=references["config"],
        resource_object=references["resource"],
        outputs=outputs,
        execution_identity=ReferenceExecutionIdentity(
            mode="google-cloud-batch",
            source_revision=SOURCE_REVISION,
            source_tree=SOURCE_TREE,
            container_image_digest=IMAGE_DIGEST,
        ),
    )
    inputs = {
        (references["job"].bucket, references["job"].object, 11): job_raw,
        (references["source"].bucket, references["source"].object, 12): source,
        (references["config"].bucket, references["config"].object, 13): config,
        (references["resource"].bucket, references["resource"].object, 14): resource,
    }
    return task, inputs


class FakeStore:
    def __init__(self, inputs: Mapping[tuple[str, str, int], bytes]) -> None:
        self.inputs = dict(inputs)
        self.live: dict[tuple[str, str], tuple[int, bytes, dict[str, str]]] = {}
        self.downloads: list[tuple[str, str, int, Path]] = []
        self.events: list[tuple[str, str]] = []
        self.fail_creates: set[tuple[str, str]] = set()
        self._next_generation = 100

    def download_exact(self, reference: ReferenceBatchObject, destination: Path) -> None:
        self.downloads.append(
            (reference.bucket, reference.object, reference.generation, destination)
        )
        destination.write_bytes(
            self.inputs[(reference.bucket, reference.object, reference.generation)]
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
        self.events.append(("create", object))
        key = (bucket, object)
        if key in self.fail_creates:
            raise RuntimeError("injected-upload-failure")
        if key in self.live:
            raise ReferenceBatchObjectAlreadyExists(object)
        raw = source.read_bytes()
        generation = self._next_generation
        self._next_generation += 1
        self.live[key] = (generation, raw, dict(metadata))
        return StoredBatchObject(bucket, object, generation, _digest(raw), len(raw))

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
        self.events.append(("download-current", object))
        item = self.live.get((bucket, object))
        if item is None:
            return None
        generation, raw, metadata = item
        if (
            set(metadata) != {*required_metadata, "colortrace-sha256"}
            or any(metadata.get(key) != value for key, value in required_metadata.items())
            or metadata.get("colortrace-sha256") != _digest(raw)
        ):
            raise ReferenceBatchWorkerError("reference-batch-storage-metadata-invalid")
        if (expected_byte_length is not None and len(raw) != expected_byte_length) or len(
            raw
        ) > maximum_bytes:
            raise ReferenceBatchWorkerError("reference-batch-storage-response-invalid")
        destination.write_bytes(raw)
        return StoredBatchObject(bucket, object, generation, _digest(raw), len(raw))

    def seed(
        self,
        *,
        bucket: str,
        object: str,
        raw: bytes,
        generation: int,
    ) -> None:
        self.live[(bucket, object)] = (generation, raw, {})


def _receipt(task: ReferenceBatchTask, output: bytes, *, cpu: int, wall: int) -> dict[str, Any]:
    job = task.job
    source = job["source"]
    color = job["color"]
    runtime = job["runtime"]
    target = job["output"]
    assert isinstance(source, Mapping)
    assert isinstance(color, Mapping)
    assert isinstance(runtime, Mapping)
    assert isinstance(target, Mapping)
    body: dict[str, Any] = {
        "schema": "reference-render-receipt/v2",
        "job_sha256": task.job_object.sha256,
        "execution_identity": task.execution_identity.to_dict(),
        "execution_identity_sha256": task.execution_identity.sha256,
        "job_id": job["job_id"],
        "scenario_id": job["scenario_id"],
        "incident_class": job["incident_class"],
        "trace_id": job["trace_id"],
        "worker_id": job["worker_id"],
        "artifact_id": job["artifact_id"],
        "source_sha256": source["sha256"],
        "config_sha256": color["config_sha256"],
        "resource_sha256": color["resource_sha256"],
        "input_color_space": color["input_color_space"],
        "output_color_space": color["output_color_space"],
        "effective_generation": runtime["effective_generation"],
        "cache_key": runtime["cache_key"],
        "output_relative_path": target["relative_path"],
        "output_sha256": _digest(output),
        "canonical_pixel_sha256": "sha256:" + "8" * 64,
        "width": 1,
        "height": 1,
        "channels": 3,
        "pixel_work": 1,
        "bytes_read": source["byte_length"],
        "bytes_written": len(output),
        "cpu_nanoseconds": cpu,
        "wall_nanoseconds": wall,
        "dependencies": {"openimageio": "3.1.17.0", "opencolorio": "2.5.2"},
    }
    body["receipt_sha256"] = _digest(_canonical(body))
    return body


def _worker(
    task: ReferenceBatchTask,
    *,
    output: bytes = b"render-output",
    cpu: int = 7,
    wall: int = 12,
    observed_roots: list[tuple[Path, Path, Path]] | None = None,
) -> Any:
    def run(
        job_path: Path,
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
        receipt_relative_path: str,
        execution_identity: ReferenceExecutionIdentity,
    ) -> Mapping[str, Any]:
        assert _digest(job_path.read_bytes()) == task.job_object.sha256
        assert execution_identity == task.execution_identity
        assert receipt_relative_path == "receipt.json"
        if observed_roots is not None:
            observed_roots.append((source_root, config_root, output_root))
        target = output_root / "renders" / "03_2a_00000.exr"
        target.parent.mkdir(parents=True)
        target.write_bytes(output)
        receipt = _receipt(task, output, cpu=cpu, wall=wall)
        (output_root / receipt_relative_path).write_bytes(_canonical(receipt) + b"\n")
        return receipt

    return run


def test_task_encoding_is_canonical_and_digest_bound() -> None:
    task, _inputs = _task()
    encoded, digest = encode_reference_batch_task(task)
    assert decode_reference_batch_task(encoded, digest) == task

    raw = base64.b64decode(encoded)
    noncanonical = b" " + raw
    with pytest.raises(ReferenceBatchWorkerError) as raised:
        decode_reference_batch_task(
            base64.b64encode(noncanonical).decode("ascii"),
            _digest(noncanonical),
        )
    assert raised.value.code == "reference-batch-task-not-canonical"

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        decode_reference_batch_task(encoded, "sha256:" + "0" * 64)
    assert raised.value.code == "reference-batch-task-digest-mismatch"


def test_task_rejects_forged_execution_spec_digest() -> None:
    task, _inputs = _task()
    value = task.to_dict()
    value["execution_spec_sha256"] = "sha256:" + "0" * 64

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        ReferenceBatchTask.from_mapping(value)

    assert raised.value.code == "reference-batch-spec-binding-invalid"


def test_task_decoder_rejects_duplicates_nonfinite_and_bad_base64() -> None:
    for raw in (
        b'{"schema":"reference-batch-task/v1","schema":"reference-batch-task/v1"}',
        b'{"schema":NaN}',
    ):
        with pytest.raises(ReferenceBatchWorkerError) as raised:
            decode_reference_batch_task(base64.b64encode(raw).decode("ascii"), _digest(raw))
        assert raised.value.code == "reference-batch-task-invalid"
    with pytest.raises(ReferenceBatchWorkerError) as raised:
        decode_reference_batch_task("not+valid===", "sha256:" + "0" * 64)
    assert raised.value.code == "reference-batch-task-encoding-invalid"


def test_runner_downloads_exact_generations_then_publishes_receipt_last() -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    roots: list[tuple[Path, Path, Path]] = []

    result = execute_reference_batch_task(
        task,
        store=store,
        worker=_worker(task, observed_roots=roots),
    )

    assert [(item[0], item[1], item[2]) for item in store.downloads] == list(inputs)
    assert store.events == [
        ("create", task.outputs.object),
        ("create", task.outputs.receipt_object),
    ]
    assert result.output.sha256 == _digest(b"render-output")
    assert result.receipt.object == task.outputs.receipt_object
    assert result.task_sha256 == task.sha256
    assert store.live[(task.outputs.bucket, task.outputs.object)][2] == {
        "colortrace-kind": "reference-render-output",
        "colortrace-sha256": _digest(b"render-output"),
        "colortrace-task-sha256": task.sha256,
        "colortrace-execution-spec-sha256": task.execution_spec_sha256,
    }
    assert roots and not roots[0][0].parent.exists()


def test_batch_runner_executes_real_oiio_ocio_worker(tmp_path: Path) -> None:
    source_path = tmp_path / "source.exr"
    pixels = np.array([[[0.0, 0.25, 0.5], [0.75, 1.0, 0.125]]], dtype=np.float32)
    specification = oiio.ImageSpec(2, 1, 3, oiio.FLOAT)
    specification.channelnames = ("R", "G", "B")
    writer = oiio.ImageOutput.create(str(source_path))
    assert writer is not None
    try:
        assert writer.open(str(source_path), specification)
        assert writer.write_image(pixels)
    finally:
        writer.close()

    prepared = prepare_worker(tmp_path / "runtime", "A", lut_bytes("approved"))
    config_root = prepared.config_path.parent
    source = source_path.read_bytes()
    config = prepared.config_path.read_bytes()
    resource = prepared.lut_path.read_bytes()
    job = {
        "schema": "reference-render-job/v1",
        "job_id": "reference-render-real-00000",
        "scenario_id": "tos-resource-resolution-drift-v1",
        "incident_class": "resource-resolution-drift/v1",
        "trace_id": "0123456789abcdef0123456789abcdef",
        "worker_id": "worker-A",
        "artifact_id": "frame:real:00000",
        "source": {
            "relative_path": "source.exr",
            "sha256": _digest(source),
            "byte_length": len(source),
        },
        "color": {
            "config_relative_path": prepared.config_path.relative_to(config_root).as_posix(),
            "config_sha256": _digest(config),
            "resource_relative_path": prepared.lut_path.relative_to(config_root).as_posix(),
            "resource_sha256": _digest(resource),
            "input_color_space": "fixture_input",
            "output_color_space": "fixture_output",
        },
        "runtime": {"effective_generation": 7, "cache_key": "cache:real:00000"},
        "output": {"relative_path": "renders/real.exr"},
    }
    job_raw = _canonical(job)
    references = {
        "job": ReferenceBatchObject(
            "ct-reference-input", "real/job.json", 31, _digest(job_raw), len(job_raw)
        ),
        "source": ReferenceBatchObject(
            "ct-reference-input", "real/source.exr", 32, _digest(source), len(source)
        ),
        "config": ReferenceBatchObject(
            "ct-reference-input", "real/config.ocio", 33, _digest(config), len(config)
        ),
        "resource": ReferenceBatchObject(
            "ct-reference-input", "real/look.cube", 34, _digest(resource), len(resource)
        ),
    }
    outputs = ReferenceBatchOutputs(
        "ct-reference-output",
        "real/render.exr",
        "real/receipt.json",
    )
    execution_spec = {
        "schema": "reference-execution-spec/v1",
        "execution_id": "reference-real-01",
        "job": job,
        "inputs": {name: reference.to_dict() for name, reference in references.items()},
        "outputs": outputs.to_dict(),
    }
    task = ReferenceBatchTask(
        execution_id="reference-real-01",
        execution_spec_sha256=_digest(_canonical(execution_spec)),
        job=job,
        job_object=references["job"],
        source_object=references["source"],
        config_object=references["config"],
        resource_object=references["resource"],
        outputs=outputs,
        execution_identity=ReferenceExecutionIdentity(
            mode="google-cloud-batch",
            source_revision=SOURCE_REVISION,
            source_tree=SOURCE_TREE,
            container_image_digest=IMAGE_DIGEST,
        ),
    )
    inputs = {
        (references["job"].bucket, references["job"].object, 31): job_raw,
        (references["source"].bucket, references["source"].object, 32): source,
        (references["config"].bucket, references["config"].object, 33): config,
        (references["resource"].bucket, references["resource"].object, 34): resource,
    }
    store = FakeStore(inputs)

    result = execute_reference_batch_task(task, store=store)

    _generation, output_raw, _metadata = store.live[(outputs.bucket, outputs.object)]
    decoded_output = tmp_path / "decoded-output.exr"
    decoded_output.write_bytes(output_raw)
    reader = oiio.ImageInput.open(str(decoded_output))
    assert reader is not None
    try:
        assert (reader.spec().width, reader.spec().height, reader.spec().nchannels) == (2, 1, 3)
    finally:
        reader.close()
    receipt_raw = store.live[(outputs.bucket, outputs.receipt_object)][1]
    receipt = json.loads(receipt_raw)
    assert receipt["execution_identity"] == task.execution_identity.to_dict()
    assert receipt["output_sha256"] == result.output.sha256 == _digest(output_raw)
    assert receipt["dependencies"] == {
        "openimageio": "3.1.17.0",
        "opencolorio": "2.5.2",
    }


@pytest.mark.parametrize("mutation", ("generation", "digest", "length", "job-content"))
def test_runner_rejects_unbound_inputs_before_render_or_publish(mutation: str) -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    if mutation == "generation":
        del store.inputs[(task.source_object.bucket, task.source_object.object, 12)]
    elif mutation == "digest":
        store.inputs[(task.source_object.bucket, task.source_object.object, 12)] = b"tampered-data"
    elif mutation == "length":
        store.inputs[(task.config_object.bucket, task.config_object.object, 13)] += b"x"
    else:
        raw = bytearray(store.inputs[(task.job_object.bucket, task.job_object.object, 11)])
        raw[-2] = ord(" ")
        store.inputs[(task.job_object.bucket, task.job_object.object, 11)] = bytes(raw)

    called = False

    def should_not_run(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        nonlocal called
        called = True
        return {}

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        execute_reference_batch_task(task, store=store, worker=should_not_run)

    expected = (
        "reference-batch-input-download-failed"
        if mutation == "generation"
        else "reference-batch-input-integrity-failed"
    )
    assert raised.value.code == expected
    assert called is False
    assert store.events == []


def test_worker_failure_publishes_nothing() -> None:
    task, inputs = _task()
    store = FakeStore(inputs)

    def fail(*args: Any, **kwargs: Any) -> Mapping[str, Any]:
        raise RuntimeError("render failed")

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        execute_reference_batch_task(task, store=store, worker=fail)
    assert raised.value.code == "reference-batch-render-failed"
    assert store.events == []


def test_receipt_upload_failure_leaves_only_an_uncommitted_orphan_output() -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    store.fail_creates.add((task.outputs.bucket, task.outputs.receipt_object))

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        execute_reference_batch_task(task, store=store, worker=_worker(task))

    assert raised.value.code == "reference-batch-receipt-upload-failed"
    assert (task.outputs.bucket, task.outputs.object) in store.live
    assert (task.outputs.bucket, task.outputs.receipt_object) not in store.live
    assert store.events == [
        ("create", task.outputs.object),
        ("create", task.outputs.receipt_object),
    ]


def test_conflicting_existing_output_fails_without_publishing_receipt() -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    store.seed(
        bucket=task.outputs.bucket,
        object=task.outputs.object,
        raw=b"different-output",
        generation=80,
    )

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        execute_reference_batch_task(task, store=store, worker=_worker(task))

    assert raised.value.code == "reference-batch-output-conflict"
    assert store.events == [
        ("create", task.outputs.object),
        ("download-current", task.outputs.object),
    ]
    assert (task.outputs.bucket, task.outputs.receipt_object) not in store.live


def test_exact_replay_reuses_both_immutable_objects() -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    first = execute_reference_batch_task(task, store=store, worker=_worker(task))
    store.events.clear()

    replay = execute_reference_batch_task(task, store=store, worker=_worker(task))

    assert replay == first
    assert store.events == [
        ("create", task.outputs.object),
        ("download-current", task.outputs.object),
        ("create", task.outputs.receipt_object),
        ("download-current", task.outputs.receipt_object),
    ]


def test_semantically_identical_receipt_replay_allows_new_timings() -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    first = execute_reference_batch_task(
        task,
        store=store,
        worker=_worker(task, cpu=5, wall=10),
    )
    replay = execute_reference_batch_task(
        task,
        store=store,
        worker=_worker(task, cpu=50, wall=100),
    )
    assert replay.output == first.output
    assert replay.receipt == first.receipt


def test_conflicting_receipt_is_rejected_after_identical_output_replay() -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    execute_reference_batch_task(task, store=store, worker=_worker(task))
    generation, raw, metadata = store.live[(task.outputs.bucket, task.outputs.receipt_object)]
    receipt = json.loads(raw)
    receipt["artifact_id"] = "different-artifact"
    body = dict(receipt)
    del body["receipt_sha256"]
    receipt["receipt_sha256"] = _digest(_canonical(body))
    mutated_raw = _canonical(receipt) + b"\n"
    metadata = dict(metadata)
    metadata["colortrace-sha256"] = _digest(mutated_raw)
    store.live[(task.outputs.bucket, task.outputs.receipt_object)] = (
        generation,
        mutated_raw,
        metadata,
    )

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        execute_reference_batch_task(task, store=store, worker=_worker(task))
    assert raised.value.code == "reference-batch-receipt-binding-invalid"


def test_receipt_replay_rejects_every_deterministic_or_security_field_mutation() -> None:
    task, _inputs = _task()
    sample = _receipt(task, b"render-output", cpu=7, wall=12)
    variable_fields = {"cpu_nanoseconds", "wall_nanoseconds", "receipt_sha256"}
    deterministic_fields = {
        "schema",
        "job_sha256",
        "execution_identity",
        "execution_identity_sha256",
        "job_id",
        "scenario_id",
        "incident_class",
        "trace_id",
        "worker_id",
        "artifact_id",
        "source_sha256",
        "config_sha256",
        "resource_sha256",
        "input_color_space",
        "output_color_space",
        "effective_generation",
        "cache_key",
        "output_relative_path",
        "output_sha256",
        "canonical_pixel_sha256",
        "width",
        "height",
        "channels",
        "pixel_work",
        "bytes_read",
        "bytes_written",
        "dependencies",
    }
    assert set(sample) == deterministic_fields | variable_fields

    for field in sorted(deterministic_fields):
        current_task, inputs = _task()
        store = FakeStore(inputs)
        execute_reference_batch_task(
            current_task,
            store=store,
            worker=_worker(current_task),
        )
        key = (current_task.outputs.bucket, current_task.outputs.receipt_object)
        generation, raw, metadata = store.live[key]
        receipt = json.loads(raw)
        value = receipt[field]
        if isinstance(value, dict):
            changed = dict(value)
            changed["unexpected"] = "mutation"
            receipt[field] = changed
        elif isinstance(value, int):
            receipt[field] = value + 1
        elif isinstance(value, str) and value.startswith("sha256:"):
            receipt[field] = "sha256:" + "0" * 64
        else:
            receipt[field] = f"{value}-mutation"
        body = dict(receipt)
        del body["receipt_sha256"]
        receipt["receipt_sha256"] = _digest(_canonical(body))
        mutated_raw = _canonical(receipt) + b"\n"
        mutated_metadata = dict(metadata)
        mutated_metadata["colortrace-sha256"] = _digest(mutated_raw)
        store.live[key] = (generation, mutated_raw, mutated_metadata)

        with pytest.raises(ReferenceBatchWorkerError):
            execute_reference_batch_task(
                current_task,
                store=store,
                worker=_worker(current_task),
            )


@pytest.mark.parametrize("kind", ("output", "receipt"))
def test_replay_rejects_missing_or_mutated_required_object_metadata(kind: str) -> None:
    task, inputs = _task()
    store = FakeStore(inputs)
    execute_reference_batch_task(task, store=store, worker=_worker(task))
    object_name = task.outputs.object if kind == "output" else task.outputs.receipt_object
    key = (task.outputs.bucket, object_name)
    generation, raw, metadata = store.live[key]
    changed = dict(metadata)
    changed["colortrace-task-sha256"] = "sha256:" + "0" * 64
    store.live[key] = (generation, raw, changed)

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        execute_reference_batch_task(task, store=store, worker=_worker(task))

    assert raised.value.code == (
        "reference-batch-output-conflict"
        if kind == "output"
        else "reference-batch-storage-metadata-invalid"
    )


class FakePreconditionFailed(Exception):
    pass


class FakeBlob:
    def __init__(
        self,
        bucket: FakeBucket,
        name: str,
        generation: int | None,
    ) -> None:
        self._bucket = bucket
        self.name = name
        self.generation: int | None = generation
        self.metadata: dict[str, str] | None = None
        item = self._bucket.objects.get(name)
        self.size: int | None = None if item is None else len(item[1])
        if item is not None:
            self.metadata = dict(self._bucket.object_metadata.get(name, {}))

    def download_to_filename(self, path: str, *, if_generation_match: int) -> None:
        self._bucket.calls.append(("download", self.name, if_generation_match))
        generation, raw = self._bucket.objects[self.name]
        if generation != self.generation or generation != if_generation_match:
            raise KeyError(self.name)
        Path(path).write_bytes(raw)

    def download_to_file(
        self,
        stream: Any,
        *,
        if_generation_match: int,
        checksum: str | None,
    ) -> None:
        self._bucket.calls.append(("download-file", self.name, if_generation_match, checksum))
        generation, raw = self._bucket.objects[self.name]
        if generation != self.generation or generation != if_generation_match:
            raise KeyError(self.name)
        stream.write(raw)

    def upload_from_filename(
        self,
        path: str,
        *,
        content_type: str,
        if_generation_match: int,
    ) -> None:
        self._bucket.calls.append(("upload", self.name, if_generation_match, content_type))
        if self.name in self._bucket.objects:
            raise FakePreconditionFailed(self.name)
        if self._bucket.populate_generation_on_upload:
            self.generation = 90
        self._bucket.objects[self.name] = (90, Path(path).read_bytes())
        self._bucket.object_metadata[self.name] = dict(self.metadata or {})

    def reload(self) -> None:
        self._bucket.calls.append(("reload", self.name))
        generation, raw = self._bucket.objects[self.name]
        self.generation = generation
        self.size = len(raw)


class FakeBucket:
    def __init__(self) -> None:
        self.objects: dict[str, tuple[int, bytes]] = {}
        self.object_metadata: dict[str, dict[str, str]] = {}
        self.calls: list[tuple[Any, ...]] = []
        self.populate_generation_on_upload = True

    def blob(self, name: str, generation: int | None = None) -> FakeBlob:
        return FakeBlob(self, name, generation)

    def get_blob(self, name: str) -> FakeBlob | None:
        item = self.objects.get(name)
        return None if item is None else FakeBlob(self, name, item[0])


class FakeStorageClient:
    def __init__(self) -> None:
        self.buckets: dict[str, FakeBucket] = {}

    def bucket(self, name: str) -> FakeBucket:
        return self.buckets.setdefault(name, FakeBucket())


def test_google_storage_adapter_enforces_generation_and_create_only(tmp_path: Path) -> None:
    client = FakeStorageClient()
    bucket = client.bucket("ct-reference-input")
    bucket.objects["source.exr"] = (7, b"source")
    adapter = GoogleCloudStorageObjectStore(
        client,
        precondition_failed_type=FakePreconditionFailed,
    )
    reference = ReferenceBatchObject(
        "ct-reference-input",
        "source.exr",
        7,
        _digest(b"source"),
        len(b"source"),
    )
    downloaded = tmp_path / "source.exr"
    adapter.download_exact(reference, downloaded)
    created = adapter.create_from_path(
        bucket="ct-reference-output",
        object="render.exr",
        source=downloaded,
        content_type="image/x-exr",
        metadata={"colortrace-sha256": _digest(b"source")},
    )

    assert downloaded.read_bytes() == b"source"
    assert bucket.calls == [("download", "source.exr", 7)]
    assert client.bucket("ct-reference-output").calls == [
        ("upload", "render.exr", 0, "image/x-exr")
    ]
    assert created.generation == 90
    with pytest.raises(ReferenceBatchObjectAlreadyExists):
        adapter.create_from_path(
            bucket="ct-reference-output",
            object="render.exr",
            source=downloaded,
            content_type="image/x-exr",
            metadata={},
        )


def test_google_storage_adapter_reloads_missing_upload_generation(tmp_path: Path) -> None:
    client = FakeStorageClient()
    bucket = client.bucket("ct-reference-output")
    bucket.populate_generation_on_upload = False
    source = tmp_path / "render.exr"
    source.write_bytes(b"render")
    adapter = GoogleCloudStorageObjectStore(
        client,
        precondition_failed_type=FakePreconditionFailed,
    )

    created = adapter.create_from_path(
        bucket="ct-reference-output",
        object="render.exr",
        source=source,
        content_type="image/x-exr",
        metadata={"colortrace-sha256": _digest(b"render")},
    )

    assert created.generation == 90
    assert bucket.calls == [
        ("upload", "render.exr", 0, "image/x-exr"),
        ("reload", "render.exr"),
    ]


def test_google_storage_adapter_bounds_replay_before_download(tmp_path: Path) -> None:
    client = FakeStorageClient()
    bucket = client.bucket("ct-reference-output")
    raw = b"existing-render"
    bucket.objects["render.exr"] = (80, raw)
    bucket.object_metadata["render.exr"] = {"colortrace-sha256": _digest(raw)}
    adapter = GoogleCloudStorageObjectStore(
        client,
        precondition_failed_type=FakePreconditionFailed,
    )

    for expected_byte_length, maximum_bytes, expected_code in (
        (
            len(b"existing-render") - 1,
            1024,
            "reference-batch-storage-response-invalid",
        ),
        (
            len(b"existing-render"),
            len(b"existing-render") - 1,
            "reference-batch-download-bound-invalid",
        ),
    ):
        destination = tmp_path / f"replay-{expected_byte_length}-{maximum_bytes}.exr"
        with pytest.raises(ReferenceBatchWorkerError) as raised:
            adapter.download_current(
                bucket="ct-reference-output",
                object="render.exr",
                destination=destination,
                expected_byte_length=expected_byte_length,
                maximum_bytes=maximum_bytes,
                required_metadata={},
            )
        assert raised.value.code == expected_code
        assert destination.exists() is False

    assert bucket.calls == []


def test_google_storage_adapter_replay_is_exact_generation_and_size_bounded(
    tmp_path: Path,
) -> None:
    client = FakeStorageClient()
    bucket = client.bucket("ct-reference-output")
    raw = b"existing-render"
    bucket.objects["render.exr"] = (80, raw)
    metadata = {"colortrace-sha256": _digest(raw)}
    bucket.object_metadata["render.exr"] = metadata
    adapter = GoogleCloudStorageObjectStore(
        client,
        precondition_failed_type=FakePreconditionFailed,
    )
    destination = tmp_path / "replay.exr"

    stored = adapter.download_current(
        bucket="ct-reference-output",
        object="render.exr",
        destination=destination,
        expected_byte_length=len(raw),
        maximum_bytes=1024,
        required_metadata={},
    )

    assert stored == StoredBatchObject(
        "ct-reference-output",
        "render.exr",
        80,
        _digest(raw),
        len(raw),
    )
    assert destination.read_bytes() == raw
    assert bucket.calls == [("download-file", "render.exr", 80, None)]


def test_google_storage_adapter_rejects_replay_metadata_before_download(
    tmp_path: Path,
) -> None:
    client = FakeStorageClient()
    bucket = client.bucket("ct-reference-output")
    raw = b"existing-render"
    bucket.objects["render.exr"] = (80, raw)
    bucket.object_metadata["render.exr"] = {
        "colortrace-kind": "wrong-kind",
        "colortrace-sha256": _digest(raw),
    }
    adapter = GoogleCloudStorageObjectStore(
        client,
        precondition_failed_type=FakePreconditionFailed,
    )
    destination = tmp_path / "replay.exr"

    with pytest.raises(ReferenceBatchWorkerError) as raised:
        adapter.download_current(
            bucket="ct-reference-output",
            object="render.exr",
            destination=destination,
            expected_byte_length=len(raw),
            maximum_bytes=1024,
            required_metadata={"colortrace-kind": "reference-render-output"},
        )

    assert raised.value.code == "reference-batch-storage-metadata-invalid"
    assert destination.exists() is False
    assert bucket.calls == []
