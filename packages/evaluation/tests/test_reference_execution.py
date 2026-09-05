from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
from colortrace_evaluation.contracts import canonical_json_bytes, prefixed_sha256
from colortrace_evaluation.reference_execution import (
    BatchAlreadyExists,
    GcsBucketSecurity,
    GcsObjectRef,
    GoogleBatchPlanner,
    GoogleBatchSubmitter,
    LocalReferenceExecutor,
    ReferenceExecutionError,
    ReferenceExecutionSpec,
)
from colortrace_simulator.reference_batch_worker import decode_reference_batch_task
from colortrace_simulator.reference_worker import ReferenceExecutionIdentity

PROJECT_ID = "reference-proj"
REGION = "us-central1"
PROJECT_NUMBER = 123456789
SUBMITTER_IDENTITY = f"ref-submit@{PROJECT_ID}.iam.gserviceaccount.com"
WORKER_IDENTITY = f"ref-worker@{PROJECT_ID}.iam.gserviceaccount.com"
WORKER_IMAGE = f"{REGION}-docker.pkg.dev/{PROJECT_ID}/reference/worker@sha256:" + "a" * 64
NETWORK = f"projects/{PROJECT_ID}/global/networks/reference-private"
SUBNETWORK = f"projects/{PROJECT_ID}/regions/{REGION}/subnetworks/reference-private"
SOURCE_DIGEST = "sha256:" + "1" * 64
CONFIG_DIGEST = "sha256:" + "2" * 64
RESOURCE_DIGEST = "sha256:" + "3" * 64
SOURCE_REVISION = "4" * 40
SOURCE_TREE = "5" * 40
HOST_IDENTITY = ReferenceExecutionIdentity(
    mode="host-python-module",
    source_revision=SOURCE_REVISION,
    source_tree=SOURCE_TREE,
    container_image_digest=None,
)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(child) for child in value]
    return value


def _job() -> dict[str, Any]:
    return {
        "schema": "reference-render-job/v1",
        "job_id": "reference-render-00000",
        "scenario_id": "tos-resource-resolution-drift-v1",
        "incident_class": "resource-resolution-drift/v1",
        "trace_id": "0123456789abcdef0123456789abcdef",
        "worker_id": "worker-A",
        "artifact_id": "frame:03_2a:00000",
        "source": {
            "relative_path": "03_2a/03_2a_00000.exr",
            "sha256": SOURCE_DIGEST,
            "byte_length": 1024,
        },
        "color": {
            "config_relative_path": "config.ocio",
            "config_sha256": CONFIG_DIGEST,
            "resource_relative_path": "luts/show_look.cube",
            "resource_sha256": RESOURCE_DIGEST,
            "input_color_space": "fixture_input",
            "output_color_space": "fixture_output",
        },
        "runtime": {"effective_generation": 7, "cache_key": "cache:03_2a:00000"},
        "output": {"relative_path": "renders/03_2a_00000.exr"},
    }


def _spec(*, job: dict[str, Any] | None = None) -> ReferenceExecutionSpec:
    value = _job() if job is None else job
    job_bytes = canonical_json_bytes(value)
    return ReferenceExecutionSpec(
        execution_id="reference-run-01",
        job=value,
        job_object=GcsObjectRef(
            bucket="ct-reference-input",
            object="runs/reference-run-01/job.json",
            generation=11,
            sha256=prefixed_sha256(value),
            byte_length=len(job_bytes),
        ),
        source_object=GcsObjectRef(
            bucket="ct-reference-input",
            object="media/03_2a/03_2a_00000.exr",
            generation=12,
            sha256=SOURCE_DIGEST,
            byte_length=1024,
        ),
        config_object=GcsObjectRef(
            bucket="ct-reference-input",
            object="configs/approved/config.ocio",
            generation=13,
            sha256=CONFIG_DIGEST,
            byte_length=512,
        ),
        resource_object=GcsObjectRef(
            bucket="ct-reference-input",
            object="configs/approved/luts/show_look.cube",
            generation=14,
            sha256=RESOURCE_DIGEST,
            byte_length=2048,
        ),
        output_bucket="ct-reference-output",
        output_object="runs/reference-run-01/render.exr",
        receipt_object="runs/reference-run-01/receipt.json",
    )


def _planner(**overrides: str) -> GoogleBatchPlanner:
    values = {
        "project_id": PROJECT_ID,
        "region": REGION,
        "worker_image": WORKER_IMAGE,
        "source_revision": SOURCE_REVISION,
        "source_tree": SOURCE_TREE,
        "submitter_service_account": SUBMITTER_IDENTITY,
        "worker_service_account": WORKER_IDENTITY,
        "network": NETWORK,
        "subnetwork": SUBNETWORK,
    }
    values.update(overrides)
    return GoogleBatchPlanner(**values)


class FakeBatch:
    def __init__(self, principal: str = SUBMITTER_IDENTITY) -> None:
        self.principal = principal
        self.jobs: dict[str, dict[str, Any]] = {}
        self.create_calls: list[dict[str, Any]] = []
        self.race = False

    def get_job(self, *, name: str) -> Mapping[str, Any] | None:
        return self.jobs.get(name)

    def create_job(
        self,
        *,
        parent: str,
        job_id: str,
        request_id: str,
        job: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        call = {
            "parent": parent,
            "job_id": job_id,
            "request_id": request_id,
            "job": _plain(job),
        }
        self.create_calls.append(call)
        resource = f"{parent}/jobs/{job_id}"
        remote = {**_plain(job), "name": resource, "status": {"state": "QUEUED"}}
        self.jobs[resource] = remote
        if self.race:
            raise BatchAlreadyExists(job_id)
        return remote


class FakeObjects:
    def __init__(
        self,
        *,
        principal: str = SUBMITTER_IDENTITY,
        public_buckets: frozenset[str] = frozenset(),
    ) -> None:
        self.principal = principal
        self.public_buckets = public_buckets
        self.inspections: list[str] = []
        self.objects: dict[tuple[str, str], tuple[GcsObjectRef, bytes]] = {}
        self.downloads: list[GcsObjectRef] = []

    def inspect_bucket(self, *, bucket: str) -> GcsBucketSecurity:
        self.inspections.append(bucket)
        private = bucket not in self.public_buckets
        return GcsBucketSecurity(
            project_id=PROJECT_ID,
            bucket=bucket,
            uniform_bucket_level_access=private,
            public_access_prevention="enforced" if private else "inherited",
        )

    def describe_object(self, *, bucket: str, object: str) -> GcsObjectRef | None:
        item = self.objects.get((bucket, object))
        return None if item is None else item[0]

    def download_bytes(self, *, reference: GcsObjectRef, maximum_bytes: int) -> bytes:
        self.downloads.append(reference)
        stored_reference, raw = self.objects[(reference.bucket, reference.object)]
        assert stored_reference == reference
        assert len(raw) <= maximum_bytes
        return raw

    def digest_object(
        self,
        *,
        reference: GcsObjectRef,
        maximum_bytes: int,
    ) -> tuple[str, int]:
        self.downloads.append(reference)
        stored_reference, raw = self.objects[(reference.bucket, reference.object)]
        assert stored_reference == reference
        if reference.byte_length > maximum_bytes or len(raw) > maximum_bytes:
            raise ReferenceExecutionError("gcs-object-download-too-large")
        return f"sha256:{hashlib.sha256(raw).hexdigest()}", len(raw)

    def put(self, *, bucket: str, object: str, raw: bytes, generation: int) -> GcsObjectRef:
        reference = GcsObjectRef(
            bucket=bucket,
            object=object,
            generation=generation,
            sha256=f"sha256:{hashlib.sha256(raw).hexdigest()}",
            byte_length=len(raw),
        )
        self.objects[(bucket, object)] = (reference, raw)
        return reference


def _submitter(
    *,
    batch: FakeBatch | None = None,
    objects: FakeObjects | None = None,
    planner: GoogleBatchPlanner | None = None,
) -> tuple[GoogleBatchSubmitter, FakeBatch, FakeObjects]:
    selected_batch = batch or FakeBatch()
    selected_objects = objects or FakeObjects()
    return (
        GoogleBatchSubmitter(
            planner=planner or _planner(),
            batch=selected_batch,
            objects=selected_objects,
        ),
        selected_batch,
        selected_objects,
    )


def _receipt(
    *,
    output: bytes,
    wall: int = 12,
    cpu: int = 7,
    identity: ReferenceExecutionIdentity | None = None,
) -> dict[str, Any]:
    job = _job()
    selected_identity = _planner().execution_identity if identity is None else identity
    body: dict[str, Any] = {
        "schema": "reference-render-receipt/v2",
        "job_sha256": prefixed_sha256(job),
        "execution_identity": selected_identity.to_dict(),
        "execution_identity_sha256": selected_identity.sha256,
        "job_id": job["job_id"],
        "scenario_id": job["scenario_id"],
        "incident_class": job["incident_class"],
        "trace_id": job["trace_id"],
        "worker_id": job["worker_id"],
        "artifact_id": job["artifact_id"],
        "source_sha256": SOURCE_DIGEST,
        "config_sha256": CONFIG_DIGEST,
        "resource_sha256": RESOURCE_DIGEST,
        "input_color_space": "fixture_input",
        "output_color_space": "fixture_output",
        "effective_generation": 7,
        "cache_key": "cache:03_2a:00000",
        "output_relative_path": "renders/03_2a_00000.exr",
        "output_sha256": f"sha256:{hashlib.sha256(output).hexdigest()}",
        "canonical_pixel_sha256": "sha256:" + "8" * 64,
        "width": 1,
        "height": 1,
        "channels": 3,
        "pixel_work": 1,
        "bytes_read": 1024,
        "bytes_written": len(output),
        "cpu_nanoseconds": cpu,
        "wall_nanoseconds": wall,
        "dependencies": {"openimageio": "3.1.17.0", "opencolorio": "2.5.2"},
    }
    body["receipt_sha256"] = prefixed_sha256(body)
    return body


def test_local_executor_uses_the_same_immutable_job_contract(tmp_path: Path) -> None:
    spec = _spec()
    calls: list[dict[str, Any]] = []
    rendered = b"local-render"

    def worker(
        value: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
        execution_identity: ReferenceExecutionIdentity | Mapping[str, Any],
    ) -> Mapping[str, Any]:
        identity = (
            execution_identity.to_dict()
            if isinstance(execution_identity, ReferenceExecutionIdentity)
            else execution_identity
        )
        calls.append({"value": _plain(value), "execution_identity": _plain(identity)})
        target = output_root / "renders/03_2a_00000.exr"
        target.parent.mkdir(parents=True)
        target.write_bytes(rendered)
        return _receipt(output=rendered, identity=HOST_IDENTITY)

    receipt = LocalReferenceExecutor(worker, execution_identity=HOST_IDENTITY).execute(
        spec,
        source_root=tmp_path / "source",
        config_root=tmp_path / "config",
        output_root=tmp_path / "output",
    )

    assert calls == [{"value": _job(), "execution_identity": HOST_IDENTITY.to_dict()}]
    assert receipt == _receipt(output=rendered, identity=HOST_IDENTITY)


@pytest.mark.parametrize("mutation", ("missing-output", "identity", "digest", "schema"))
def test_local_executor_rejects_unproven_worker_receipt(
    tmp_path: Path,
    mutation: str,
) -> None:
    rendered = b"local-render"

    def worker(
        value: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
        execution_identity: ReferenceExecutionIdentity | Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del value, source_root, config_root, execution_identity
        if mutation != "missing-output":
            target = output_root / "renders/03_2a_00000.exr"
            target.parent.mkdir(parents=True)
            target.write_bytes(rendered)
        receipt = _receipt(output=rendered, identity=HOST_IDENTITY)
        if mutation == "identity":
            receipt["execution_identity"] = _planner().execution_identity.to_dict()
        elif mutation == "digest":
            receipt["output_sha256"] = "sha256:" + "0" * 64
        elif mutation == "schema":
            del receipt["canonical_pixel_sha256"]
        if mutation in {"identity", "digest"}:
            body = dict(receipt)
            del body["receipt_sha256"]
            receipt["receipt_sha256"] = prefixed_sha256(body)
        return receipt

    executor = LocalReferenceExecutor(worker, execution_identity=HOST_IDENTITY)
    with pytest.raises(ReferenceExecutionError) as raised:
        executor.execute(
            _spec(),
            source_root=tmp_path / "source",
            config_root=tmp_path / "config",
            output_root=tmp_path / "output",
        )
    assert raised.value.code in {
        "reference-local-output-invalid",
        "reference-local-receipt-invalid",
    }


def test_execution_spec_round_trips_strict_mapping() -> None:
    spec = _spec()
    assert ReferenceExecutionSpec.from_mapping(spec.to_dict()) == spec
    invalid = spec.to_dict()
    invalid["unexpected"] = True
    with pytest.raises(ReferenceExecutionError) as raised:
        ReferenceExecutionSpec.from_mapping(invalid)
    assert raised.value.code == "reference-execution-spec-invalid"


def test_batch_plan_embeds_canonical_task_and_private_network() -> None:
    spec = _spec()
    planner = _planner()
    plan = planner.plan(spec)
    request = _plain(plan.request)
    container = request["taskGroups"][0]["taskSpec"]["runnables"][0]["container"]
    commands = container["commands"]
    task = decode_reference_batch_task(commands[1], commands[3])

    assert plan.parent == "projects/reference-proj/locations/us-central1"
    assert plan.job_resource == f"{plan.parent}/jobs/{plan.job_id}"
    assert plan.request_sha256 == prefixed_sha256(request)
    assert task.to_dict() == planner.batch_task(spec).to_dict()
    assert task.execution_spec_sha256 == spec.sha256
    assert task.execution_identity == planner.execution_identity
    assert task.job_object.generation == 11
    assert task.source_object.generation == 12
    assert task.config_object.generation == 13
    assert task.resource_object.generation == 14
    assert container["imageUri"] == WORKER_IMAGE
    assert container["entrypoint"] == "colortrace-reference-batch-worker"
    assert "volumes" not in container
    assert "blockExternalNetwork" not in container
    interface = request["allocationPolicy"]["network"]["networkInterfaces"][0]
    assert interface == {
        "network": NETWORK,
        "subnetwork": SUBNETWORK,
        "noExternalIpAddress": True,
    }


def test_submission_is_idempotent_and_accepts_output_only_remote_fields() -> None:
    spec = _spec()
    submitter, batch, _objects = _submitter()

    first = submitter.submit(spec)
    remote = batch.jobs[first.job_resource]
    remote["uid"] = "server-generated"
    remote["taskGroups"][0]["name"] = f"{first.job_resource}/taskGroups/group0"
    duplicate = submitter.submit(spec)

    assert first.duplicate is False
    assert duplicate.duplicate is True
    assert duplicate.job_resource == first.job_resource
    assert len(batch.create_calls) == 1


def test_submission_accepts_exact_google_batch_response_normalization() -> None:
    spec = _spec()
    submitter, batch, _objects = _submitter()

    first = submitter.submit(spec)
    remote = batch.jobs[first.job_resource]
    remote["allocationPolicy"]["labels"] = {"batch-job-id": first.job_id}
    remote["allocationPolicy"]["location"]["allowedLocations"] = [
        f"regions/{REGION}",
        f"zones/{REGION}-a",
        f"zones/{REGION}-b",
        f"zones/{REGION}-c",
        f"zones/{REGION}-f",
    ]

    duplicate = submitter.submit(spec)

    assert duplicate.duplicate is True
    assert duplicate.job_resource == first.job_resource
    assert len(batch.create_calls) == 1


@pytest.mark.parametrize(
    ("provider_labels", "allowed_locations"),
    (
        ({"batch-job-id": "different-job"}, [f"zones/{REGION}-a"]),
        (None, [f"zones/{REGION}-a"]),
        (
            {"batch-job-id": "placeholder", "unexpected": "label"},
            [f"zones/{REGION}-a"],
        ),
        ({"batch-job-id": "placeholder"}, ["regions/us-east1"]),
        ({"batch-job-id": "placeholder"}, ["zones/us-east1-b"]),
        (
            {"batch-job-id": "placeholder"},
            [f"zones/{REGION}-a", f"zones/{REGION}-a"],
        ),
    ),
)
def test_submission_rejects_foreign_or_malformed_batch_normalization(
    provider_labels: dict[str, str] | None,
    allowed_locations: list[str],
) -> None:
    spec = _spec()
    submitter, batch, _objects = _submitter()
    first = submitter.submit(spec)
    remote = batch.jobs[first.job_resource]
    remote["allocationPolicy"]["labels"] = (
        None
        if provider_labels is None
        else {
            key: first.job_id if value == "placeholder" else value
            for key, value in provider_labels.items()
        }
    )
    remote["allocationPolicy"]["location"]["allowedLocations"] = allowed_locations

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.submit(spec)

    assert raised.value.code == "batch-job-identity-conflict"
    assert len(batch.create_calls) == 1


def test_already_exists_race_reconciles_the_created_job() -> None:
    batch = FakeBatch()
    batch.race = True
    submitter, _batch, _objects = _submitter(batch=batch)
    result = submitter.submit(_spec())
    assert result.duplicate is True


def test_success_reconciliation_validates_receipt_and_output_binding() -> None:
    spec = _spec()
    submitter, batch, objects = _submitter()
    submitted = submitter.submit(spec)
    batch.jobs[submitted.job_resource]["status"] = {"state": "SUCCEEDED"}
    output = b"render-output"
    output_reference = objects.put(
        bucket=spec.output_bucket,
        object=spec.output_object,
        raw=output,
        generation=21,
    )
    receipt_raw = canonical_json_bytes(_receipt(output=output)) + b"\n"
    receipt_reference = objects.put(
        bucket=spec.output_bucket,
        object=spec.receipt_object,
        raw=receipt_raw,
        generation=22,
    )

    reconciled = submitter.reconcile(spec)

    assert reconciled.output == output_reference
    assert reconciled.receipt == receipt_reference
    assert objects.downloads == [receipt_reference, output_reference]


@pytest.mark.parametrize("tampered", (b"render-outpvt", b"render-output-extra"))
def test_success_reconciliation_hashes_exact_output_bytes(tampered: bytes) -> None:
    spec = _spec()
    submitter, batch, objects = _submitter()
    submitted = submitter.submit(spec)
    batch.jobs[submitted.job_resource]["status"] = {"state": "SUCCEEDED"}
    declared_output = b"render-output"
    output_reference = objects.put(
        bucket=spec.output_bucket,
        object=spec.output_object,
        raw=declared_output,
        generation=21,
    )
    objects.objects[(output_reference.bucket, output_reference.object)] = (
        output_reference,
        tampered,
    )
    receipt_raw = canonical_json_bytes(_receipt(output=declared_output)) + b"\n"
    receipt_reference = objects.put(
        bucket=spec.output_bucket,
        object=spec.receipt_object,
        raw=receipt_raw,
        generation=22,
    )

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.reconcile(spec)

    assert raised.value.code == "gcs-output-reconciliation-invalid"
    assert objects.downloads == [receipt_reference, output_reference]


def test_succeeded_job_with_orphan_output_is_not_a_completed_result() -> None:
    spec = _spec()
    submitter, batch, objects = _submitter()
    submitted = submitter.submit(spec)
    batch.jobs[submitted.job_resource]["status"] = {"state": "SUCCEEDED"}
    objects.put(
        bucket=spec.output_bucket,
        object=spec.output_object,
        raw=b"orphan-render-output",
        generation=21,
    )

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.reconcile(spec)

    assert raised.value.code == "gcs-output-reconciliation-invalid"
    assert objects.downloads == []


def test_pending_reconciliation_does_not_claim_outputs() -> None:
    submitter, _batch, objects = _submitter()
    submitted = submitter.submit(_spec())
    result = submitter.reconcile(_spec())
    assert result.job_resource == submitted.job_resource
    assert result.state == "QUEUED"
    assert result.output is None
    assert result.receipt is None
    assert objects.downloads == []


@pytest.mark.parametrize("state", ("CANCELLATION_IN_PROGRESS", "CANCELLED"))
def test_cancelled_batch_states_are_valid_non_success_results(state: str) -> None:
    submitter, batch, objects = _submitter()
    submitted = submitter.submit(_spec())
    batch.jobs[submitted.job_resource]["status"] = {"state": state}

    result = submitter.reconcile(_spec())

    assert result.state == state
    assert result.output is None
    assert result.receipt is None
    assert objects.downloads == []


@pytest.mark.parametrize(
    "mutation",
    (
        "image",
        "service-account",
        "commands",
        "no-external-ip",
        "subnetwork",
        "task-settings",
        "allocation",
        "labels",
        "extra-runnable",
        "unexpected-environment",
    ),
)
def test_reconciliation_rejects_mutated_immutable_remote_job(mutation: str) -> None:
    spec = _spec()
    submitter, batch, objects = _submitter()
    submitted = submitter.submit(spec)
    remote = batch.jobs[submitted.job_resource]
    task_spec = remote["taskGroups"][0]["taskSpec"]
    container = task_spec["runnables"][0]["container"]
    if mutation == "image":
        container["imageUri"] = WORKER_IMAGE[:-1] + "b"
    elif mutation == "service-account":
        remote["allocationPolicy"]["serviceAccount"]["email"] = (
            f"other-worker@{PROJECT_ID}.iam.gserviceaccount.com"
        )
    elif mutation == "commands":
        container["commands"][-1] = "sha256:" + "b" * 64
    elif mutation == "no-external-ip":
        remote["allocationPolicy"]["network"]["networkInterfaces"][0]["noExternalIpAddress"] = False
    elif mutation == "subnetwork":
        remote["allocationPolicy"]["network"]["networkInterfaces"][0]["subnetwork"] = (
            f"projects/{PROJECT_ID}/regions/{REGION}/subnetworks/other"
        )
    elif mutation == "task-settings":
        task_spec["maxRetryCount"] = 1
    elif mutation == "allocation":
        remote["allocationPolicy"]["instances"][0]["policy"]["machineType"] = "e2-highcpu-2"
    elif mutation == "labels":
        remote["labels"]["colortrace-execution"] = "different-run"
    elif mutation == "unexpected-environment":
        task_spec["environments"] = {"variables": {"COLORTRACE_SOURCE_TREE": "0" * 40}}
    else:
        task_spec["runnables"].append(copy.deepcopy(task_spec["runnables"][0]))

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.reconcile(spec)

    assert raised.value.code == "batch-job-identity-conflict"
    assert objects.downloads == []


@pytest.mark.parametrize(
    "mutation",
    ("missing", "digest", "binding", "identity", "oversize"),
)
def test_success_reconciliation_rejects_invalid_completion(mutation: str) -> None:
    spec = _spec()
    submitter, batch, objects = _submitter()
    submitted = submitter.submit(spec)
    batch.jobs[submitted.job_resource]["status"] = {"state": "SUCCEEDED"}
    output = b"render-output"
    objects.put(
        bucket=spec.output_bucket,
        object=spec.output_object,
        raw=output,
        generation=21,
    )
    if mutation != "missing":
        receipt = _receipt(output=output)
        if mutation == "binding":
            receipt["output_sha256"] = "sha256:" + "9" * 64
        elif mutation == "identity":
            changed_identity = ReferenceExecutionIdentity(
                mode="google-cloud-batch",
                source_revision="6" * 40,
                source_tree=SOURCE_TREE,
                container_image_digest="sha256:" + "b" * 64,
            )
            receipt["execution_identity"] = changed_identity.to_dict()
            receipt["execution_identity_sha256"] = changed_identity.sha256
        if mutation in {"binding", "identity"}:
            body = dict(receipt)
            del body["receipt_sha256"]
            receipt["receipt_sha256"] = prefixed_sha256(body)
        raw = canonical_json_bytes(receipt) + b"\n"
        reference = objects.put(
            bucket=spec.output_bucket,
            object=spec.receipt_object,
            raw=raw,
            generation=22,
        )
        if mutation == "digest":
            objects.objects[(reference.bucket, reference.object)] = (reference, raw + b" ")
        elif mutation == "oversize":
            oversized = GcsObjectRef(
                bucket=reference.bucket,
                object=reference.object,
                generation=reference.generation,
                sha256=reference.sha256,
                byte_length=65_537,
            )
            objects.objects[(reference.bucket, reference.object)] = (oversized, raw)

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.reconcile(spec)

    assert raised.value.code == "gcs-output-reconciliation-invalid"


@pytest.mark.parametrize("bucket", ["ct-reference-input", "ct-reference-output"])
def test_public_input_or_output_bucket_is_rejected_before_submission(bucket: str) -> None:
    objects = FakeObjects(public_buckets=frozenset({bucket}))
    submitter, batch, _ = _submitter(objects=objects)

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.submit(_spec())

    assert raised.value.code == "gcs-bucket-not-private"
    assert batch.create_calls == []


def test_control_and_batch_clients_must_use_submitter_identity() -> None:
    with pytest.raises(ReferenceExecutionError, match="batch-submitter-identity-mismatch"):
        _submitter(batch=FakeBatch(principal=WORKER_IDENTITY))
    with pytest.raises(ReferenceExecutionError, match="gcs-control-identity-mismatch"):
        _submitter(objects=FakeObjects(principal=WORKER_IDENTITY))


def test_mutable_object_reference_is_rejected() -> None:
    with pytest.raises(ReferenceExecutionError) as raised:
        GcsObjectRef(
            bucket="ct-reference-input",
            object="jobs/job.json",
            generation=0,
            sha256="sha256:" + "a" * 64,
            byte_length=10,
        )
    assert raised.value.code == "gcs-generation-invalid"


def test_object_reference_is_immutable() -> None:
    reference = _spec().source_object
    with pytest.raises(FrozenInstanceError):
        reference.generation = 99  # type: ignore[misc]


@pytest.mark.parametrize(
    ("override", "expected_code"),
    [
        (
            {"worker_image": f"{REGION}-docker.pkg.dev/{PROJECT_ID}/reference/worker:latest"},
            "batch-worker-image-not-pinned",
        ),
        (
            {"worker_image": WORKER_IMAGE.replace("/worker@", "/worker:latest@")},
            "batch-worker-image-not-pinned",
        ),
        ({"worker_service_account": SUBMITTER_IDENTITY}, "batch-service-accounts-not-separated"),
        ({"source_revision": "not-a-commit"}, "batch-source-identity-invalid"),
        ({"source_tree": "not-a-tree"}, "batch-source-identity-invalid"),
        (
            {"network": "projects/other/global/networks/reference-private"},
            "batch-network-invalid",
        ),
        (
            {
                "subnetwork": (
                    f"projects/{PROJECT_ID}/regions/europe-west1/subnetworks/reference-private"
                )
            },
            "batch-subnetwork-invalid",
        ),
    ],
)
def test_mutable_images_shared_identities_and_wrong_networks_are_rejected(
    override: dict[str, str],
    expected_code: str,
) -> None:
    with pytest.raises(ReferenceExecutionError) as raised:
        _planner(**override)
    assert raised.value.code == expected_code


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [("job", "reference-path-invalid"), ("gcs", "gcs-object-invalid")],
)
def test_path_injection_is_rejected(mutation: str, expected_code: str) -> None:
    with pytest.raises(ReferenceExecutionError) as raised:
        if mutation == "job":
            job = _job()
            output = job["output"]
            assert isinstance(output, dict)
            output["relative_path"] = "../../escape.exr"
            _spec(job=job)
        else:
            GcsObjectRef(
                bucket="ct-reference-input",
                object="runs/../escape.json",
                generation=1,
                sha256="sha256:" + "a" * 64,
                byte_length=10,
            )
    assert raised.value.code == expected_code


def test_batch_request_has_no_credentials_or_free_form_shell() -> None:
    request = _plain(_planner().plan(_spec()).request)
    keys: list[str] = []

    def visit(value: Any) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                keys.append(str(key).lower())
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(request)
    forbidden = ("password", "credential", "privatekey", "secret", "accesstoken", "keyfile")
    assert not any(any(token in key for token in forbidden) for key in keys)
    container = request["taskGroups"][0]["taskSpec"]["runnables"][0]["container"]
    assert container["entrypoint"] == "colortrace-reference-batch-worker"
    assert container["commands"][0] == "--task-base64"
    assert container["commands"][2] == "--task-sha256"
    assert not {"sh", "bash", "-c"}.intersection(container["commands"])
