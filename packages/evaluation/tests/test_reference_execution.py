from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest
from colortrace_evaluation.contracts import canonical_json_bytes, prefixed_sha256
from colortrace_evaluation.reference_execution import (
    GcsBucketSecurity,
    GcsObjectRef,
    GoogleBatchPlanner,
    GoogleBatchSubmitter,
    LocalReferenceExecutor,
    ReferenceExecutionError,
    ReferenceExecutionSpec,
    StagedTransferPlan,
)

PROJECT_ID = "reference-proj"
REGION = "us-central1"
SUBMITTER_IDENTITY = f"ref-submit@{PROJECT_ID}.iam.gserviceaccount.com"
WORKER_IDENTITY = f"ref-worker@{PROJECT_ID}.iam.gserviceaccount.com"
WORKER_IMAGE = f"{REGION}-docker.pkg.dev/{PROJECT_ID}/reference/worker@sha256:" + "a" * 64
SOURCE_DIGEST = "sha256:" + "1" * 64
CONFIG_DIGEST = "sha256:" + "2" * 64
RESOURCE_DIGEST = "sha256:" + "3" * 64


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
        "submitter_service_account": SUBMITTER_IDENTITY,
        "worker_service_account": WORKER_IDENTITY,
    }
    values.update(overrides)
    return GoogleBatchPlanner(**values)


class FakeBatch:
    def __init__(self, principal: str = SUBMITTER_IDENTITY) -> None:
        self.principal = principal
        self.jobs: dict[str, dict[str, Any]] = {}
        self.create_calls: list[dict[str, Any]] = []

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
        remote = {
            **_plain(job),
            "name": resource,
            "status": {"state": "QUEUED"},
        }
        self.jobs[resource] = remote
        return remote


class FakeTransfers:
    def __init__(
        self,
        *,
        principal: str = WORKER_IDENTITY,
        public_buckets: frozenset[str] = frozenset(),
    ) -> None:
        self.principal = principal
        self.public_buckets = public_buckets
        self.inspections: list[str] = []
        self.prepare_calls: list[tuple[str, StagedTransferPlan]] = []
        self.collect_calls: list[tuple[str, StagedTransferPlan]] = []

    def inspect_bucket(self, *, bucket: str) -> GcsBucketSecurity:
        self.inspections.append(bucket)
        private = bucket not in self.public_buckets
        return GcsBucketSecurity(
            project_id=PROJECT_ID,
            bucket=bucket,
            uniform_bucket_level_access=private,
            public_access_prevention="enforced" if private else "inherited",
        )

    def prepare(self, *, job_resource: str, plan: StagedTransferPlan) -> None:
        self.prepare_calls.append((job_resource, plan))

    def collect(
        self,
        *,
        job_resource: str,
        plan: StagedTransferPlan,
    ) -> Sequence[GcsObjectRef]:
        self.collect_calls.append((job_resource, plan))
        return tuple(
            GcsObjectRef(
                bucket=item.bucket,
                object=item.object,
                generation=index + 21,
                sha256="sha256:" + str(index + 4) * 64,
                byte_length=(index + 1) * 4096,
            )
            for index, item in enumerate(plan.outputs)
        )


def cast_mapping(value: Any) -> Mapping[str, Any]:
    assert isinstance(value, Mapping)
    return value


def _submitter(
    *,
    batch: FakeBatch | None = None,
    transfers: FakeTransfers | None = None,
    planner: GoogleBatchPlanner | None = None,
) -> tuple[GoogleBatchSubmitter, FakeBatch, FakeTransfers]:
    selected_batch = batch or FakeBatch()
    selected_transfers = transfers or FakeTransfers()
    return (
        GoogleBatchSubmitter(
            planner=planner or _planner(),
            batch=selected_batch,
            transfers=selected_transfers,
        ),
        selected_batch,
        selected_transfers,
    )


def test_local_executor_uses_the_same_immutable_job_contract(tmp_path: Path) -> None:
    spec = _spec()
    calls: list[dict[str, Any]] = []

    def worker(
        value: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
    ) -> Mapping[str, Any]:
        calls.append(
            {
                "value": _plain(value),
                "source_root": source_root,
                "config_root": config_root,
                "output_root": output_root,
            }
        )
        return {"schema": "reference-render-receipt/v1", "receipt_sha256": "sha256:" + "f" * 64}

    source_root = tmp_path / "source"
    config_root = tmp_path / "config"
    output_root = tmp_path / "output"
    receipt = LocalReferenceExecutor(worker).execute(
        spec,
        source_root=source_root,
        config_root=config_root,
        output_root=output_root,
    )

    assert calls == [
        {
            "value": _job(),
            "source_root": source_root,
            "config_root": config_root,
            "output_root": output_root,
        }
    ]
    assert receipt["schema"] == "reference-render-receipt/v1"
    plan = _planner().plan(spec)
    assert plan.transfers.inputs[0].reference.sha256 == prefixed_sha256(calls[0]["value"])
    assert plan.transfers.inputs[0].reference == spec.job_object


def test_batch_plan_has_exact_fixed_request_and_staged_transfer_preconditions() -> None:
    spec = _spec()
    plan = _planner().plan(spec)
    spec_hex = spec.sha256.removeprefix("sha256:")
    host_root = f"/mnt/disks/colortrace-reference/{plan.job_id}"
    expected_request = {
        "taskGroups": [
            {
                "taskCount": "1",
                "parallelism": "1",
                "runAsNonRoot": True,
                "taskSpec": {
                    "runnables": [
                        {
                            "displayName": "colortrace-reference-worker",
                            "container": {
                                "imageUri": WORKER_IMAGE,
                                "entrypoint": "colortrace-reference-worker",
                                "commands": [
                                    "--job",
                                    "/mnt/colortrace/input/job.json",
                                    "--source-root",
                                    "/mnt/colortrace/input/source",
                                    "--config-root",
                                    "/mnt/colortrace/input/config",
                                    "--output-root",
                                    "/mnt/colortrace/output",
                                    "--receipt-relative-path",
                                    "receipt.json",
                                ],
                                "volumes": [
                                    f"{host_root}/input:/mnt/colortrace/input:ro",
                                    f"{host_root}/output:/mnt/colortrace/output:rw",
                                ],
                                "blockExternalNetwork": True,
                            },
                        }
                    ],
                    "computeResource": {"cpuMilli": "2000", "memoryMib": "4096"},
                    "maxRetryCount": 0,
                    "maxRunDuration": "3600s",
                },
            }
        ],
        "allocationPolicy": {
            "location": {"allowedLocations": ["regions/us-central1"]},
            "instances": [
                {
                    "policy": {
                        "machineType": "e2-standard-2",
                        "provisioningModel": "STANDARD",
                    }
                }
            ],
            "serviceAccount": {"email": WORKER_IDENTITY},
        },
        "logsPolicy": {"destination": "CLOUD_LOGGING"},
        "labels": {
            "colortrace-execution": "reference-run-01",
            "colortrace-spec-sha256-a": spec_hex[:32],
            "colortrace-spec-sha256-b": spec_hex[32:],
        },
    }

    assert plan.parent == "projects/reference-proj/locations/us-central1"
    assert plan.job_resource == f"{plan.parent}/jobs/{plan.job_id}"
    assert _plain(plan.request) == expected_request
    assert plan.request_sha256 == prefixed_sha256(expected_request)
    assert [item.if_generation_match for item in plan.transfers.inputs] == [11, 12, 13, 14]
    assert [item.if_generation_match for item in plan.transfers.outputs] == [0, 0]
    assert [item.destination for item in plan.transfers.inputs] == [
        f"{host_root}/input/job.json",
        f"{host_root}/input/source/03_2a/03_2a_00000.exr",
        f"{host_root}/input/config/config.ocio",
        f"{host_root}/input/config/luts/show_look.cube",
    ]
    assert [item.source for item in plan.transfers.outputs] == [
        f"{host_root}/output/renders/03_2a_00000.exr",
        f"{host_root}/output/receipt.json",
    ]


def test_submission_and_success_reconciliation_are_idempotent() -> None:
    spec = _spec()
    submitter, batch, transfers = _submitter()

    first = submitter.submit(spec)
    duplicate = submitter.submit(spec)

    assert first.duplicate is False
    assert duplicate == type(duplicate)(
        job_resource=first.job_resource,
        job_id=first.job_id,
        request_id=first.request_id,
        spec_sha256=first.spec_sha256,
        request_sha256=first.request_sha256,
        duplicate=True,
    )
    assert len(batch.create_calls) == 1
    assert len(transfers.prepare_calls) == 2
    assert transfers.prepare_calls[0] == transfers.prepare_calls[1]
    create = batch.create_calls[0]
    assert create["parent"] == "projects/reference-proj/locations/us-central1"
    assert create["job_id"] == first.job_id
    assert create["request_id"] == first.request_id
    assert create["job"] == _plain(_planner().plan(spec).request)

    batch.jobs[first.job_resource]["status"] = {"state": "SUCCEEDED"}
    reconciled = submitter.reconcile(spec)
    repeated = submitter.reconcile(spec)

    assert repeated == reconciled
    assert reconciled.job_resource == first.job_resource
    assert reconciled.state == "SUCCEEDED"
    assert reconciled.output is not None and reconciled.output.generation == 21
    assert reconciled.receipt is not None and reconciled.receipt.generation == 22
    assert len(transfers.collect_calls) == 2
    assert transfers.collect_calls[0] == transfers.collect_calls[1]


@pytest.mark.parametrize(
    "mutation",
    (
        "image",
        "service-account",
        "volume-mode",
        "commands",
        "network",
        "task-settings",
        "allocation",
        "labels",
    ),
)
def test_reconciliation_rejects_mutated_immutable_remote_job(mutation: str) -> None:
    spec = _spec()
    submitter, batch, transfers = _submitter()
    submitted = submitter.submit(spec)
    remote = batch.jobs[submitted.job_resource]
    task_group = remote["taskGroups"][0]
    task_spec = task_group["taskSpec"]
    container = task_spec["runnables"][0]["container"]
    if mutation == "image":
        container["imageUri"] = WORKER_IMAGE[:-1] + "b"
    elif mutation == "service-account":
        remote["allocationPolicy"]["serviceAccount"]["email"] = (
            f"other-worker@{PROJECT_ID}.iam.gserviceaccount.com"
        )
    elif mutation == "volume-mode":
        container["volumes"][0] = container["volumes"][0].removesuffix(":ro") + ":rw"
    elif mutation == "commands":
        container["commands"][-1] = "different-receipt.json"
    elif mutation == "network":
        container["blockExternalNetwork"] = False
    elif mutation == "task-settings":
        task_spec["maxRetryCount"] = 1
    elif mutation == "allocation":
        remote["allocationPolicy"]["instances"][0]["policy"]["machineType"] = "e2-highcpu-2"
    else:
        remote["labels"]["colortrace-execution"] = "different-run"
    remote["status"] = {"state": "SUCCEEDED"}

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.reconcile(spec)

    assert raised.value.code == "batch-job-identity-conflict"
    assert transfers.collect_calls == []


@pytest.mark.parametrize("bucket", ["ct-reference-input", "ct-reference-output"])
def test_public_input_or_output_bucket_is_rejected_before_staging(bucket: str) -> None:
    transfers = FakeTransfers(public_buckets=frozenset({bucket}))
    submitter, batch, _ = _submitter(transfers=transfers)

    with pytest.raises(ReferenceExecutionError) as raised:
        submitter.submit(_spec())

    assert raised.value.code == "gcs-bucket-not-private"
    assert transfers.prepare_calls == []
    assert batch.create_calls == []


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
    ],
)
def test_mutable_images_and_shared_identities_are_rejected(
    override: dict[str, str],
    expected_code: str,
) -> None:
    with pytest.raises(ReferenceExecutionError) as raised:
        _planner(**override)

    assert raised.value.code == expected_code


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("job", "reference-path-invalid"),
        ("gcs", "gcs-object-invalid"),
    ],
)
def test_path_injection_is_rejected(mutation: str, expected_code: str) -> None:
    with pytest.raises(ReferenceExecutionError) as raised:
        if mutation == "job":
            job = _job()
            cast_mapping(job["output"])["relative_path"] = "../../escape.exr"  # type: ignore[index]
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
    assert container["entrypoint"] == "colortrace-reference-worker"
    assert container["commands"] == [
        "--job",
        "/mnt/colortrace/input/job.json",
        "--source-root",
        "/mnt/colortrace/input/source",
        "--config-root",
        "/mnt/colortrace/input/config",
        "--output-root",
        "/mnt/colortrace/output",
        "--receipt-relative-path",
        "receipt.json",
    ]
    assert not {"sh", "bash", "-c"}.intersection(container["commands"])
    assert container["blockExternalNetwork"] is True
