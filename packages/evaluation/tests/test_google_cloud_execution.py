from __future__ import annotations

import hashlib
import importlib
from types import SimpleNamespace
from typing import Any

import pytest
from colortrace_evaluation.google_cloud_execution import (
    GoogleBatchApiClient,
    GoogleCloudStorageControlClient,
)
from colortrace_evaluation.reference_execution import (
    BatchAlreadyExists,
    GcsObjectRef,
    ReferenceExecutionError,
)

PROJECT_ID = "reference-proj"
REGION = "us-central1"
PRINCIPAL = f"ref-submit@{PROJECT_ID}.iam.gserviceaccount.com"


class FakeNotFound(Exception):
    pass


class FakeAlreadyExists(Exception):
    pass


class FakeBatchSdkClient:
    def __init__(self) -> None:
        self.jobs: dict[str, dict[str, Any]] = {}
        self.get_requests: list[Any] = []
        self.create_requests: list[Any] = []
        self.conflict = False

    def get_job(self, *, request: Any) -> dict[str, Any]:
        self.get_requests.append(request)
        try:
            return self.jobs[request["name"]]
        except KeyError as error:
            raise FakeNotFound(request["name"]) from error

    def create_job(self, *, request: Any) -> dict[str, Any]:
        self.create_requests.append(request)
        if self.conflict:
            raise FakeAlreadyExists(request["job_id"])
        name = f"{request['parent']}/jobs/{request['job_id']}"
        result = {**request["job"], "name": name, "status": {"state": "QUEUED"}}
        self.jobs[name] = result
        return result


def test_batch_adapter_uses_official_global_endpoint_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = object()
    calls: list[dict[str, Any]] = []

    def create_client(**kwargs: Any) -> FakeBatchSdkClient:
        calls.append(kwargs)
        return FakeBatchSdkClient()

    batch_module = SimpleNamespace(BatchServiceClient=create_client)
    monkeypatch.setattr(
        importlib,
        "import_module",
        lambda name: batch_module,
    )

    client = GoogleBatchApiClient(
        project_id=PROJECT_ID,
        region=REGION,
        principal=PRINCIPAL,
        credentials=credentials,
        not_found_type=FakeNotFound,
        already_exists_type=FakeAlreadyExists,
    )

    assert client.principal == PRINCIPAL
    assert calls == [{"credentials": credentials}]


def test_batch_adapter_builds_requests_and_translates_sdk_conflicts() -> None:
    sdk = FakeBatchSdkClient()
    client = GoogleBatchApiClient(
        project_id=PROJECT_ID,
        region=REGION,
        principal=PRINCIPAL,
        client=sdk,
        not_found_type=FakeNotFound,
        already_exists_type=FakeAlreadyExists,
    )
    parent = f"projects/{PROJECT_ID}/locations/{REGION}"
    job = {"labels": {"colortrace-execution": "reference-run-01"}}

    assert client.get_job(name=f"{parent}/jobs/missing") is None
    created = client.create_job(
        parent=parent,
        job_id="reference-job",
        request_id="request-id",
        job=job,
    )
    assert created["name"] == f"{parent}/jobs/reference-job"
    assert client.get_job(name=created["name"]) == created
    assert sdk.create_requests == [
        {
            "parent": parent,
            "job_id": "reference-job",
            "request_id": "request-id",
            "job": job,
        }
    ]

    sdk.conflict = True
    with pytest.raises(BatchAlreadyExists):
        client.create_job(
            parent=parent,
            job_id="reference-job",
            request_id="request-id",
            job=job,
        )


def test_batch_adapter_rejects_cross_region_resource() -> None:
    client = GoogleBatchApiClient(
        project_id=PROJECT_ID,
        region=REGION,
        principal=PRINCIPAL,
        client=FakeBatchSdkClient(),
        not_found_type=FakeNotFound,
        already_exists_type=FakeAlreadyExists,
    )
    with pytest.raises(ReferenceExecutionError) as raised:
        client.get_job(name=f"projects/{PROJECT_ID}/locations/europe-west1/jobs/job")
    assert raised.value.code == "batch-job-resource-invalid"


class FakeIamConfiguration:
    uniform_bucket_level_access_enabled = True
    public_access_prevention = "enforced"


class FakeDownloadBlob:
    def __init__(
        self,
        bucket: FakeStorageBucket,
        name: str,
        generation: int,
    ) -> None:
        self._bucket = bucket
        self.name = name
        self.generation = generation

    def download_as_bytes(self, *, if_generation_match: int, checksum: str) -> bytes:
        self._bucket.downloads.append((self.name, self.generation, if_generation_match, checksum))
        generation, raw, _metadata = self._bucket.objects[self.name]
        assert generation == self.generation == if_generation_match
        return raw

    def download_to_file(
        self,
        stream: Any,
        *,
        if_generation_match: int,
        checksum: str | None,
    ) -> None:
        self._bucket.downloads.append((self.name, self.generation, if_generation_match, checksum))
        generation, raw, _metadata = self._bucket.objects[self.name]
        assert generation == self.generation == if_generation_match
        stream.write(raw)


class FakeObjectBlob:
    def __init__(
        self,
        name: str,
        generation: int,
        raw: bytes,
        metadata: dict[str, str],
    ) -> None:
        self.name = name
        self.generation = generation
        self.size = len(raw)
        self.metadata = metadata


class FakeStorageBucket:
    def __init__(self, name: str, project_number: int = 123456789) -> None:
        self.name = name
        self._properties = {"projectNumber": str(project_number)}
        self.iam_configuration = FakeIamConfiguration()
        self.objects: dict[str, tuple[int, bytes, dict[str, str]]] = {}
        self.downloads: list[tuple[str, int, int, str | None]] = []

    def get_blob(self, name: str) -> FakeObjectBlob | None:
        item = self.objects.get(name)
        if item is None:
            return None
        generation, raw, metadata = item
        return FakeObjectBlob(name, generation, raw, metadata)

    def blob(self, name: str, generation: int) -> FakeDownloadBlob:
        return FakeDownloadBlob(self, name, generation)


class FakeStorageSdkClient:
    def __init__(self) -> None:
        self.buckets: dict[str, FakeStorageBucket] = {}

    def get_bucket(self, name: str) -> FakeStorageBucket:
        return self.bucket(name)

    def bucket(self, name: str) -> FakeStorageBucket:
        return self.buckets.setdefault(name, FakeStorageBucket(name))


def test_storage_control_adapter_checks_bucket_and_downloads_exact_generation() -> None:
    sdk = FakeStorageSdkClient()
    bucket = sdk.bucket("ct-reference-output")
    raw = b'{"receipt":true}\n'
    digest = f"sha256:{hashlib.sha256(raw).hexdigest()}"
    bucket.objects["receipt.json"] = (
        22,
        raw,
        {"colortrace-sha256": digest},
    )
    client = GoogleCloudStorageControlClient(
        project_id=PROJECT_ID,
        project_number=123456789,
        principal=PRINCIPAL,
        client=sdk,
    )

    security = client.inspect_bucket(bucket=bucket.name)
    reference = client.describe_object(bucket=bucket.name, object="receipt.json")
    assert reference == GcsObjectRef(bucket.name, "receipt.json", 22, digest, len(raw))
    assert reference is not None
    assert client.download_bytes(reference=reference, maximum_bytes=1024) == raw
    assert client.digest_object(reference=reference, maximum_bytes=1024) == (
        f"sha256:{hashlib.sha256(raw).hexdigest()}",
        len(raw),
    )
    assert security.project_id == PROJECT_ID
    assert security.uniform_bucket_level_access is True
    assert security.public_access_prevention == "enforced"
    assert bucket.downloads == [
        ("receipt.json", 22, 22, "auto"),
        ("receipt.json", 22, 22, None),
    ]


def test_storage_control_adapter_rejects_wrong_project_and_missing_digest() -> None:
    sdk = FakeStorageSdkClient()
    bucket = FakeStorageBucket("ct-reference-output", project_number=999)
    bucket.objects["render.exr"] = (21, b"render", {})
    sdk.buckets[bucket.name] = bucket
    client = GoogleCloudStorageControlClient(
        project_id=PROJECT_ID,
        project_number=123456789,
        principal=PRINCIPAL,
        client=sdk,
    )

    assert client.inspect_bucket(bucket=bucket.name).project_id == "project-number:999"
    with pytest.raises(ReferenceExecutionError) as raised:
        client.describe_object(bucket=bucket.name, object="render.exr")
    assert raised.value.code == "gcs-digest-invalid"


def test_storage_control_adapter_refuses_oversized_download() -> None:
    client = GoogleCloudStorageControlClient(
        project_id=PROJECT_ID,
        project_number=123456789,
        principal=PRINCIPAL,
        client=FakeStorageSdkClient(),
    )
    reference = GcsObjectRef(
        bucket="ct-reference-output",
        object="receipt.json",
        generation=1,
        sha256="sha256:" + "a" * 64,
        byte_length=1025,
    )
    with pytest.raises(ReferenceExecutionError) as raised:
        client.download_bytes(reference=reference, maximum_bytes=1024)
    assert raised.value.code == "gcs-object-download-too-large"


def test_storage_control_adapter_bounds_stream_when_metadata_underreports() -> None:
    sdk = FakeStorageSdkClient()
    bucket = sdk.bucket("ct-reference-output")
    bucket.objects["render.exr"] = (
        21,
        b"render-output",
        {"colortrace-sha256": "sha256:" + "a" * 64},
    )
    client = GoogleCloudStorageControlClient(
        project_id=PROJECT_ID,
        project_number=123456789,
        principal=PRINCIPAL,
        client=sdk,
    )
    reference = GcsObjectRef(
        bucket=bucket.name,
        object="render.exr",
        generation=21,
        sha256="sha256:" + "a" * 64,
        byte_length=1,
    )

    with pytest.raises(ReferenceExecutionError) as raised:
        client.digest_object(reference=reference, maximum_bytes=5)

    assert raised.value.code == "gcs-object-download-too-large"
