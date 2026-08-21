from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from colortrace_recovery import RecoveryError, canonical_json_bytes
from google.auth.exceptions import GoogleAuthError

from .recovery_tasks import (
    RecoveryVerificationTaskDelivery,
    validate_recovery_verification_task,
)

_QUEUE_PATH = re.compile(
    r"projects/[a-z][a-z0-9-]{4,29}/locations/[a-z0-9-]{1,63}/"
    r"queues/[A-Za-z0-9_-]{1,100}\Z"
)
_SERVICE_ACCOUNT_EMAIL = re.compile(
    r"[a-z0-9][a-z0-9-]{0,62}@[a-z0-9][a-z0-9.-]{0,200}\.iam\.gserviceaccount\.com\Z"
)
_TASK_KEY = re.compile(r"(?:recovery-verification-task|dispatch-task):[0-9a-f]{64}\Z")
_CLOUD_TASK_NAME = re.compile(
    r"projects/[a-z][a-z0-9-]{4,29}/locations/[a-z0-9-]{1,63}/"
    r"queues/[A-Za-z0-9_-]{1,100}/tasks/colortrace-[0-9a-f]{64}\Z"
)
_MAX_URL_LENGTH = 2_048
_CLOUD_TASKS_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class CloudTaskPublishError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class CloudTaskRequestError(CloudTaskPublishError):
    pass


class CloudTaskAlreadyExists(CloudTaskRequestError):
    def __init__(self) -> None:
        super().__init__("cloud-task-already-exists")


class CloudTaskNotFound(CloudTaskRequestError):
    def __init__(self) -> None:
        super().__init__("cloud-task-not-found")


class CloudTasksResponse(Protocol):
    status_code: int

    def json(self) -> object: ...


class CloudTasksHttpSession(Protocol):
    def post(
        self,
        url: str,
        *,
        json: Mapping[str, Any],
        timeout: float,
    ) -> CloudTasksResponse: ...

    def get(
        self,
        url: str,
        *,
        timeout: float,
    ) -> CloudTasksResponse: ...


class CloudTasksClient(Protocol):
    def create_task(
        self,
        *,
        parent: str,
        task: Mapping[str, Any],
    ) -> object: ...

    def get_task(self, *, name: str) -> object: ...


class CloudTaskOutbox(Protocol):
    def reserve_cloud_task_deliveries(
        self,
        *,
        limit: int,
        max_attempts: int,
    ) -> list[RecoveryVerificationTaskDelivery]: ...

    def mark_cloud_task_enqueued(
        self,
        delivery: RecoveryVerificationTaskDelivery,
        *,
        cloud_task_name: str,
    ) -> dict[str, Any]: ...

    def fail_cloud_task_delivery(
        self,
        delivery: RecoveryVerificationTaskDelivery,
        *,
        max_attempts: int,
    ) -> dict[str, Any]: ...


def _https_url(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_URL_LENGTH:
        raise ValueError(f"{name} must be a bounded HTTPS URL")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{name} must be a bounded HTTPS URL") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{name} must be a bounded HTTPS URL")
    return value


@dataclass(frozen=True, slots=True)
class CloudTasksPublisherConfig:
    queue_path: str
    target_base_url: str
    oidc_audience: str
    oidc_service_account_email: str
    max_publish_attempts: int = 5
    dispatch_deadline_seconds: int = 600

    def __post_init__(self) -> None:
        if _QUEUE_PATH.fullmatch(self.queue_path) is None:
            raise ValueError("queue_path must be one exact Cloud Tasks queue resource")
        object.__setattr__(
            self,
            "target_base_url",
            _https_url(self.target_base_url, name="target_base_url").rstrip("/"),
        )
        object.__setattr__(
            self,
            "oidc_audience",
            _https_url(self.oidc_audience, name="oidc_audience"),
        )
        if _SERVICE_ACCOUNT_EMAIL.fullmatch(self.oidc_service_account_email) is None:
            raise ValueError("oidc_service_account_email must identify one service account")
        if (
            not isinstance(self.max_publish_attempts, int)
            or isinstance(self.max_publish_attempts, bool)
            or not 1 <= self.max_publish_attempts <= 20
        ):
            raise ValueError("max_publish_attempts is outside its supported range")
        if (
            not isinstance(self.dispatch_deadline_seconds, int)
            or isinstance(self.dispatch_deadline_seconds, bool)
            or not 15 <= self.dispatch_deadline_seconds <= 1_800
        ):
            raise ValueError("dispatch_deadline_seconds is outside its supported range")

    @property
    def queue_name(self) -> str:
        return self.queue_path.rsplit("/", 1)[-1]


def cloud_task_id(task_key: str) -> str:
    if not isinstance(task_key, str) or _TASK_KEY.fullmatch(task_key) is None:
        raise ValueError("task_key is invalid")
    return f"colortrace-{hashlib.sha256(task_key.encode('ascii')).hexdigest()}"


def cloud_task_name(queue_path: str, task_key: str) -> str:
    if _QUEUE_PATH.fullmatch(queue_path) is None:
        raise ValueError("queue_path is invalid")
    return f"{queue_path}/tasks/{cloud_task_id(task_key)}"


def _task_resource_name(value: object, *, code: str) -> str:
    if not isinstance(value, str) or _CLOUD_TASK_NAME.fullmatch(value) is None:
        raise CloudTaskPublishError(code)
    return value


def _canonical_error_status(response: CloudTasksResponse) -> str | None:
    try:
        document = response.json()
    except (TypeError, ValueError):
        return None
    if not isinstance(document, Mapping):
        return None
    error = document.get("error")
    if not isinstance(error, Mapping):
        return None
    status = error.get("status")
    return status if isinstance(status, str) else None


def _validate_response_name(
    response: CloudTasksResponse,
    *,
    expected_name: str,
    code: str,
) -> None:
    try:
        document = response.json()
    except (TypeError, ValueError):
        raise CloudTaskRequestError(code) from None
    if not isinstance(document, Mapping) or document.get("name") != expected_name:
        raise CloudTaskRequestError(code)


class GoogleCloudTasksRestClient:
    def __init__(
        self,
        *,
        session: CloudTasksHttpSession | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 1 <= float(timeout_seconds) <= 30
        ):
            raise ValueError("timeout_seconds is outside its supported range")
        if session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession

            credentials, _project = google.auth.default(scopes=(_CLOUD_TASKS_SCOPE,))
            session = AuthorizedSession(credentials)  # type: ignore[no-untyped-call]
        self._session = session
        self._timeout_seconds = float(timeout_seconds)

    def create_task(
        self,
        *,
        parent: str,
        task: Mapping[str, Any],
    ) -> object:
        if _QUEUE_PATH.fullmatch(parent) is None:
            raise CloudTaskPublishError("cloud-task-parent-invalid")
        expected_name = _task_resource_name(
            task.get("name"),
            code="cloud-task-name-invalid",
        )
        if not expected_name.startswith(f"{parent}/tasks/"):
            raise CloudTaskPublishError("cloud-task-name-invalid")
        try:
            response = self._session.post(
                f"https://cloudtasks.googleapis.com/v2/{parent}/tasks",
                json={"task": dict(task)},
                timeout=self._timeout_seconds,
            )
        except (GoogleAuthError, OSError):
            raise CloudTaskRequestError("cloud-task-create-request-failed") from None
        if response.status_code == 409 and _canonical_error_status(response) == "ALREADY_EXISTS":
            raise CloudTaskAlreadyExists
        if response.status_code not in {200, 201}:
            raise CloudTaskRequestError("cloud-task-create-failed")
        _validate_response_name(
            response,
            expected_name=expected_name,
            code="cloud-task-create-response-invalid",
        )
        return response

    def get_task(self, *, name: str) -> object:
        expected_name = _task_resource_name(name, code="cloud-task-name-invalid")
        try:
            response = self._session.get(
                f"https://cloudtasks.googleapis.com/v2/{expected_name}",
                timeout=self._timeout_seconds,
            )
        except (GoogleAuthError, OSError):
            raise CloudTaskRequestError("cloud-task-get-request-failed") from None
        if response.status_code == 404 and _canonical_error_status(response) == "NOT_FOUND":
            raise CloudTaskNotFound
        if response.status_code != 200:
            raise CloudTaskRequestError("cloud-task-get-failed")
        _validate_response_name(
            response,
            expected_name=expected_name,
            code="cloud-task-get-response-invalid",
        )
        return response


@dataclass(frozen=True, slots=True)
class CloudTasksPublishReport:
    reserved: int
    enqueued: int
    already_exists: int
    failed: int


class RecoveryCloudTasksPublisher:
    def __init__(
        self,
        *,
        outbox: CloudTaskOutbox,
        client: CloudTasksClient,
        config: CloudTasksPublisherConfig,
    ) -> None:
        self._outbox = outbox
        self._client = client
        self._config = config

    def _task_document(self, delivery: RecoveryVerificationTaskDelivery) -> dict[str, Any]:
        if (
            not isinstance(delivery, RecoveryVerificationTaskDelivery)
            or not isinstance(delivery.attempt, int)
            or isinstance(delivery.attempt, bool)
            or delivery.attempt < 1
        ):
            raise CloudTaskPublishError("cloud-task-delivery-invalid")
        try:
            task = validate_recovery_verification_task(delivery.task)
        except (RecoveryError, TypeError, ValueError):
            raise CloudTaskPublishError("cloud-task-payload-invalid") from None
        task_key = task.get("task_key")
        if not isinstance(task_key, str):
            raise CloudTaskPublishError("cloud-task-payload-invalid")
        task_name = cloud_task_name(self._config.queue_path, task_key)
        target = (
            f"{self._config.target_base_url}/private/v1/recovery-verification-tasks/"
            f"{quote(task_key, safe='')}"
        )
        return {
            "name": task_name,
            "dispatchDeadline": f"{self._config.dispatch_deadline_seconds}s",
            "httpRequest": {
                "httpMethod": "POST",
                "url": target,
                "headers": {"Content-Type": "application/json"},
                "body": base64.b64encode(canonical_json_bytes(task)).decode("ascii"),
                "oidcToken": {
                    "serviceAccountEmail": self._config.oidc_service_account_email,
                    "audience": self._config.oidc_audience,
                },
            },
        }

    def publish_pending(self, *, limit: int = 10) -> CloudTasksPublishReport:
        deliveries = self._outbox.reserve_cloud_task_deliveries(
            limit=limit,
            max_attempts=self._config.max_publish_attempts,
        )
        enqueued = 0
        already_exists = 0
        failed = 0
        for delivery in deliveries:
            task_document = self._task_document(delivery)
            task_name = task_document["name"]
            if not isinstance(task_name, str):
                raise CloudTaskPublishError("cloud-task-name-invalid")
            if delivery.attempt > 1 or delivery.reconciliation_only:
                try:
                    self._client.get_task(name=task_name)
                except CloudTaskNotFound:
                    if delivery.reconciliation_only:
                        self._outbox.fail_cloud_task_delivery(
                            delivery,
                            max_attempts=self._config.max_publish_attempts,
                        )
                        failed += 1
                        continue
                except CloudTaskRequestError:
                    failed += 1
                    continue
                else:
                    self._outbox.mark_cloud_task_enqueued(
                        delivery,
                        cloud_task_name=task_name,
                    )
                    already_exists += 1
                    continue
            try:
                self._client.create_task(
                    parent=self._config.queue_path,
                    task=task_document,
                )
            except CloudTaskRequestError:
                try:
                    self._client.get_task(name=task_name)
                except CloudTaskNotFound:
                    self._outbox.fail_cloud_task_delivery(
                        delivery,
                        max_attempts=self._config.max_publish_attempts,
                    )
                    failed += 1
                except CloudTaskRequestError:
                    failed += 1
                else:
                    self._outbox.mark_cloud_task_enqueued(
                        delivery,
                        cloud_task_name=task_name,
                    )
                    already_exists += 1
            else:
                self._outbox.mark_cloud_task_enqueued(
                    delivery,
                    cloud_task_name=task_name,
                )
                enqueued += 1
        return CloudTasksPublishReport(
            reserved=len(deliveries),
            enqueued=enqueued,
            already_exists=already_exists,
            failed=failed,
        )


@dataclass(frozen=True, slots=True)
class CloudTasksDeliveryMetadata:
    retry_count: int
    execution_count: int


def _header_count(value: str | None) -> int:
    if value is None or re.fullmatch(r"0|[1-9][0-9]{0,2}", value) is None:
        raise CloudTaskPublishError("cloud-task-delivery-metadata-invalid")
    return int(value)


def verify_cloud_tasks_delivery(
    *,
    queue_path: str,
    task_key: str,
    max_delivery_attempts: int,
    queue_name_header: str | None,
    task_name_header: str | None,
    retry_count_header: str | None,
    execution_count_header: str | None,
) -> CloudTasksDeliveryMetadata:
    validate_cloud_tasks_delivery_config(
        queue_path=queue_path,
        max_delivery_attempts=max_delivery_attempts,
    )
    expected_queue = queue_path.rsplit("/", 1)[-1]
    expected_task = cloud_task_id(task_key)
    retry_count = _header_count(retry_count_header)
    execution_count = _header_count(execution_count_header)
    if (
        queue_name_header != expected_queue
        or task_name_header != expected_task
        or retry_count >= max_delivery_attempts
        or execution_count > retry_count
    ):
        raise CloudTaskPublishError("cloud-task-delivery-metadata-invalid")
    return CloudTasksDeliveryMetadata(
        retry_count=retry_count,
        execution_count=execution_count,
    )


def validate_cloud_tasks_delivery_config(
    *,
    queue_path: str,
    max_delivery_attempts: int,
) -> None:
    if (
        _QUEUE_PATH.fullmatch(queue_path) is None
        or not isinstance(max_delivery_attempts, int)
        or isinstance(max_delivery_attempts, bool)
        or not 1 <= max_delivery_attempts <= 100
    ):
        raise ValueError("Cloud Tasks delivery configuration is invalid")


__all__ = [
    "CloudTaskAlreadyExists",
    "CloudTaskNotFound",
    "CloudTaskOutbox",
    "CloudTaskPublishError",
    "CloudTaskRequestError",
    "CloudTasksClient",
    "CloudTasksDeliveryMetadata",
    "CloudTasksPublishReport",
    "CloudTasksPublisherConfig",
    "GoogleCloudTasksRestClient",
    "RecoveryCloudTasksPublisher",
    "cloud_task_id",
    "cloud_task_name",
    "validate_cloud_tasks_delivery_config",
    "verify_cloud_tasks_delivery",
]
