from __future__ import annotations

import hashlib
import importlib
import json
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from .contracts import canonical_json_bytes, strict_json_file
from .reference_execution import (
    BatchAlreadyExists,
    BatchReconciliation,
    BatchSubmission,
    GcsBucketSecurity,
    GcsObjectRef,
    GoogleBatchPlanner,
    GoogleBatchSubmitter,
    ReferenceExecutionError,
    ReferenceExecutionSpec,
)

_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_GCS_DOWNLOAD_CHUNK_BYTES = 8 * 1024 * 1024


class _DigestWriter:
    def __init__(self, maximum_bytes: int) -> None:
        self._maximum_bytes = maximum_bytes
        self._digest = hashlib.sha256()
        self.byte_length = 0

    def write(self, value: bytes) -> int:
        next_length = self.byte_length + len(value)
        if next_length > self._maximum_bytes:
            raise ReferenceExecutionError("gcs-object-download-too-large")
        self._digest.update(value)
        self.byte_length = next_length
        return len(value)

    @property
    def sha256(self) -> str:
        return f"sha256:{self._digest.hexdigest()}"


def _mapping(value: Any, *, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ReferenceExecutionError(code)
    return cast(Mapping[str, Any], value)


def _positive_int(value: Any, *, code: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ReferenceExecutionError(code) from error
    if parsed < 1:
        raise ReferenceExecutionError(code)
    return parsed


def _message_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): child for key, child in value.items()}
    encoder = getattr(type(value), "to_json", None)
    if not callable(encoder):
        raise ReferenceExecutionError("batch-response-invalid")
    try:
        encoded = encoder(
            value,
            use_integers_for_enums=False,
            always_print_fields_with_no_presence=False,
        )
        parsed = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ReferenceExecutionError("batch-response-invalid") from error
    return _mapping(parsed, code="batch-response-invalid")


class GoogleBatchApiClient:
    def __init__(
        self,
        *,
        project_id: str,
        region: str,
        principal: str,
        credentials: Any | None = None,
        client: Any | None = None,
        batch_module: Any | None = None,
        not_found_type: type[BaseException] | None = None,
        already_exists_type: type[BaseException] | None = None,
    ) -> None:
        self._project_id = project_id
        self._region = region
        self._principal = principal
        if client is None:
            try:
                batch_module = importlib.import_module("google.cloud.batch_v1")
                client = batch_module.BatchServiceClient(
                    credentials=credentials,
                )
            except (ImportError, AttributeError) as error:
                raise ReferenceExecutionError("batch-sdk-unavailable") from error
        self._client = client
        self._batch_module = batch_module
        if not_found_type is None or already_exists_type is None:
            try:
                exceptions = importlib.import_module("google.api_core.exceptions")
                not_found_type = not_found_type or cast(type[BaseException], exceptions.NotFound)
                already_exists_type = already_exists_type or cast(
                    type[BaseException], exceptions.AlreadyExists
                )
            except (ImportError, AttributeError) as error:
                raise ReferenceExecutionError("batch-sdk-unavailable") from error
        self._not_found_type = not_found_type
        self._already_exists_type = already_exists_type

    @property
    def principal(self) -> str:
        return self._principal

    def get_job(self, *, name: str) -> Mapping[str, Any] | None:
        expected_prefix = f"projects/{self._project_id}/locations/{self._region}/jobs/"
        if not name.startswith(expected_prefix):
            raise ReferenceExecutionError("batch-job-resource-invalid")
        request: Any = {"name": name}
        if self._batch_module is not None:
            request = self._batch_module.GetJobRequest(name=name)
        try:
            response = self._client.get_job(request=request)
        except self._not_found_type:
            return None
        return _message_mapping(response)

    def create_job(
        self,
        *,
        parent: str,
        job_id: str,
        request_id: str,
        job: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        request: Any = {
            "parent": parent,
            "job_id": job_id,
            "request_id": request_id,
            "job": dict(job),
        }
        if self._batch_module is not None:
            try:
                job_message = self._batch_module.Job.from_json(
                    canonical_json_bytes(job).decode("utf-8")
                )
                request = self._batch_module.CreateJobRequest(
                    parent=parent,
                    job_id=job_id,
                    request_id=request_id,
                    job=job_message,
                )
            except (TypeError, ValueError) as error:
                raise ReferenceExecutionError("batch-request-invalid") from error
        try:
            response = self._client.create_job(request=request)
        except self._already_exists_type as error:
            raise BatchAlreadyExists(job_id) from error
        return _message_mapping(response)


class GoogleCloudStorageControlClient:
    def __init__(
        self,
        *,
        project_id: str,
        project_number: int,
        principal: str,
        credentials: Any | None = None,
        client: Any | None = None,
    ) -> None:
        if project_number < 1:
            raise ReferenceExecutionError("gcs-project-number-invalid")
        if client is None:
            try:
                storage = importlib.import_module("google.cloud.storage")
                client = storage.Client(project=project_id, credentials=credentials)
            except (ImportError, AttributeError) as error:
                raise ReferenceExecutionError("gcs-sdk-unavailable") from error
        self._client = client
        self._project_id = project_id
        self._project_number = project_number
        self._principal = principal

    @property
    def principal(self) -> str:
        return self._principal

    def inspect_bucket(self, *, bucket: str) -> GcsBucketSecurity:
        try:
            remote = self._client.get_bucket(bucket)
            properties = _mapping(
                getattr(remote, "_properties", None),
                code="gcs-bucket-response-invalid",
            )
            remote_project_number = _positive_int(
                properties.get("projectNumber"),
                code="gcs-bucket-response-invalid",
            )
            iam = remote.iam_configuration
            uniform = iam.uniform_bucket_level_access_enabled
            prevention = iam.public_access_prevention
        except ReferenceExecutionError:
            raise
        except Exception as error:
            raise ReferenceExecutionError("gcs-bucket-inspection-failed") from error
        return GcsBucketSecurity(
            project_id=(
                self._project_id
                if remote_project_number == self._project_number
                else f"project-number:{remote_project_number}"
            ),
            bucket=cast(str, remote.name),
            uniform_bucket_level_access=uniform is True,
            public_access_prevention=cast(str, prevention),
        )

    def describe_object(self, *, bucket: str, object: str) -> GcsObjectRef | None:
        try:
            blob = self._client.bucket(bucket).get_blob(object)
        except Exception as error:
            raise ReferenceExecutionError("gcs-object-inspection-failed") from error
        if blob is None:
            return None
        metadata = blob.metadata
        if not isinstance(metadata, Mapping):
            raise ReferenceExecutionError("gcs-object-metadata-invalid")
        return GcsObjectRef(
            bucket=bucket,
            object=object,
            generation=_positive_int(
                blob.generation,
                code="gcs-object-metadata-invalid",
            ),
            sha256=cast(str, metadata.get("colortrace-sha256")),
            byte_length=_positive_int(blob.size, code="gcs-object-metadata-invalid"),
        )

    def download_bytes(
        self,
        *,
        reference: GcsObjectRef,
        maximum_bytes: int,
    ) -> bytes:
        if maximum_bytes < 1 or reference.byte_length > maximum_bytes:
            raise ReferenceExecutionError("gcs-object-download-too-large")
        try:
            blob = self._client.bucket(reference.bucket).blob(
                reference.object,
                generation=reference.generation,
            )
            raw = blob.download_as_bytes(
                if_generation_match=reference.generation,
                checksum="auto",
            )
        except Exception as error:
            raise ReferenceExecutionError("gcs-object-download-failed") from error
        if not isinstance(raw, bytes) or len(raw) > maximum_bytes:
            raise ReferenceExecutionError("gcs-object-download-invalid")
        return raw

    def digest_object(
        self,
        *,
        reference: GcsObjectRef,
        maximum_bytes: int,
    ) -> tuple[str, int]:
        if maximum_bytes < 1 or reference.byte_length > maximum_bytes:
            raise ReferenceExecutionError("gcs-object-download-too-large")
        writer = _DigestWriter(maximum_bytes)
        try:
            blob = self._client.bucket(reference.bucket).blob(
                reference.object,
                generation=reference.generation,
            )
            blob.chunk_size = _GCS_DOWNLOAD_CHUNK_BYTES
            blob.download_to_file(
                writer,
                if_generation_match=reference.generation,
                checksum=None,
            )
        except ReferenceExecutionError:
            raise
        except Exception as error:
            raise ReferenceExecutionError("gcs-object-download-failed") from error
        return writer.sha256, writer.byte_length


def _credentials_for(principal: str) -> Any:
    try:
        google_auth = importlib.import_module("google.auth")
        impersonated = importlib.import_module("google.auth.impersonated_credentials")
        source, _project = google_auth.default(scopes=[_CLOUD_PLATFORM_SCOPE])
        if getattr(source, "service_account_email", None) == principal:
            return source
        return impersonated.Credentials(
            source_credentials=source,
            target_principal=principal,
            target_scopes=[_CLOUD_PLATFORM_SCOPE],
            lifetime=900,
        )
    except (ImportError, AttributeError) as error:
        raise ReferenceExecutionError("google-auth-unavailable") from error


def _planner(arguments: Namespace) -> GoogleBatchPlanner:
    return GoogleBatchPlanner(
        project_id=arguments.project_id,
        region=arguments.region,
        worker_image=arguments.worker_image,
        source_revision=arguments.source_revision,
        source_tree=arguments.source_tree,
        submitter_service_account=arguments.submitter_service_account,
        worker_service_account=arguments.worker_service_account,
        network=arguments.network,
        subnetwork=arguments.subnetwork,
    )


def _submission(value: BatchSubmission) -> dict[str, Any]:
    return {
        "schema": "reference-batch-launch/v1",
        "job_resource": value.job_resource,
        "job_id": value.job_id,
        "request_id": value.request_id,
        "spec_sha256": value.spec_sha256,
        "request_sha256": value.request_sha256,
        "duplicate": value.duplicate,
    }


def _reconciliation(value: BatchReconciliation) -> dict[str, Any]:
    def reference(item: GcsObjectRef | None) -> dict[str, Any] | None:
        return None if item is None else item.to_dict()

    return {
        "schema": "reference-batch-reconciliation/v1",
        "job_resource": value.job_resource,
        "state": value.state,
        "spec_sha256": value.spec_sha256,
        "output": reference(value.output),
        "receipt": reference(value.receipt),
    }


def _parser() -> ArgumentParser:
    common = ArgumentParser(add_help=False)
    common.add_argument("--spec", type=Path, required=True)
    common.add_argument("--project-id", required=True)
    common.add_argument("--project-number", type=int, required=True)
    common.add_argument("--region", required=True)
    common.add_argument("--worker-image", required=True)
    common.add_argument("--source-revision", required=True)
    common.add_argument("--source-tree", required=True)
    common.add_argument("--submitter-service-account", required=True)
    common.add_argument("--worker-service-account", required=True)
    common.add_argument("--network", required=True)
    common.add_argument("--subnetwork", required=True)
    parser = ArgumentParser(prog="colortrace-reference-batch")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("submit", parents=[common])
    commands.add_parser("reconcile", parents=[common])
    return parser


def main() -> None:
    arguments = _parser().parse_args()
    try:
        spec = ReferenceExecutionSpec.from_mapping(
            strict_json_file(arguments.spec.resolve(strict=True))
        )
        planner = _planner(arguments)
        credentials = _credentials_for(planner.submitter_service_account)
        submitter = GoogleBatchSubmitter(
            planner=planner,
            batch=GoogleBatchApiClient(
                project_id=planner.project_id,
                region=planner.region,
                principal=planner.submitter_service_account,
                credentials=credentials,
            ),
            objects=GoogleCloudStorageControlClient(
                project_id=planner.project_id,
                project_number=arguments.project_number,
                principal=planner.submitter_service_account,
                credentials=credentials,
            ),
        )
        result = (
            _submission(submitter.submit(spec))
            if arguments.command == "submit"
            else _reconciliation(submitter.reconcile(spec))
        )
    except (OSError, ReferenceExecutionError) as error:
        code = getattr(error, "code", "reference-batch-cli-failed")
        print(code, file=sys.stderr)
        raise SystemExit(2) from error
    print(canonical_json_bytes(result).decode("utf-8"))


__all__ = [
    "GoogleBatchApiClient",
    "GoogleCloudStorageControlClient",
    "main",
]


if __name__ == "__main__":
    main()
