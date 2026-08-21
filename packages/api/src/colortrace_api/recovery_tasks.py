from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast

from colortrace_recovery import (
    RecoveryError,
    canonical_json_bytes,
    document_sha256,
    require_digest,
    require_idempotency_key,
)

TASK_SCHEMA = "recovery-verification-task/v1"
ADMISSION_SCHEMA = "recovery-verification-admission/v1"
RESULT_SCHEMA = "recovery-verification-task-result/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_TASK_KEY = re.compile(r"^recovery-verification-task:[0-9a-f]{64}$")
_CLOUD_TASK_NAME = re.compile(
    r"^projects/[a-z][a-z0-9-]{4,29}/locations/[a-z0-9-]{1,63}/"
    r"queues/[A-Za-z0-9_-]{1,100}/tasks/[A-Za-z0-9_-]{1,500}$"
)
_TASK_FIELDS = frozenset(
    {
        "schema",
        "task_key",
        "incident_id",
        "expected_incident_version",
        "expected_outcome_sha256",
        "payload_sha256",
        "idempotency_key",
    }
)
_ADMISSION_FIELDS = frozenset({*_TASK_FIELDS, "duplicate", "state"})
_RESULT_FIELDS = frozenset(
    {
        "schema",
        "result_id",
        "result_sha256",
        "task_key",
        "payload_sha256",
        "incident_id",
        "expected_incident_version",
        "expected_outcome_sha256",
        "status",
        "packet_id",
        "packet_sha256",
        "reason_code",
    }
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _identifier(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RecoveryError(code)
    return value


def _positive_version(value: Any, *, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RecoveryError(code)
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RecoveryError("verification-task-time-invalid")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RecoveryError("stored-verification-task-invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (OverflowError, ValueError):
        raise RecoveryError("stored-verification-task-invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise RecoveryError("stored-verification-task-invalid")
    selected = parsed.astimezone(UTC)
    if _timestamp(selected) != value:
        raise RecoveryError("stored-verification-task-invalid")
    return selected


def _task_identity_sha256(*, incident_id: str, idempotency_key: str) -> str:
    return document_sha256(
        {
            "schema": "recovery-verification-task-identity/v1",
            "incident_id": incident_id,
            "idempotency_key": idempotency_key,
        }
    )


def _task_payload_sha256(
    *,
    incident_id: str,
    expected_incident_version: int,
    expected_outcome_sha256: str,
    idempotency_key: str,
) -> str:
    return document_sha256(
        {
            "schema": "recovery-verification-task-payload/v1",
            "incident_id": incident_id,
            "expected_incident_version": expected_incident_version,
            "expected_outcome_sha256": expected_outcome_sha256,
            "idempotency_key": idempotency_key,
        }
    )


def build_recovery_verification_task(
    *,
    incident_id: str,
    expected_incident_version: int,
    expected_outcome_sha256: str,
    idempotency_key: str,
) -> dict[str, Any]:
    selected_incident = _identifier(incident_id, code="verification-task-incident-invalid")
    selected_version = _positive_version(
        expected_incident_version,
        code="verification-task-expected-version-invalid",
    )
    selected_outcome = require_digest(
        expected_outcome_sha256,
        code="expected-outcome-digest-invalid",
    )
    selected_key = require_idempotency_key(idempotency_key)
    identity_sha256 = _task_identity_sha256(
        incident_id=selected_incident,
        idempotency_key=selected_key,
    )
    return {
        "schema": TASK_SCHEMA,
        "task_key": f"recovery-verification-task:{identity_sha256.removeprefix('sha256:')}",
        "incident_id": selected_incident,
        "expected_incident_version": selected_version,
        "expected_outcome_sha256": selected_outcome,
        "payload_sha256": _task_payload_sha256(
            incident_id=selected_incident,
            expected_incident_version=selected_version,
            expected_outcome_sha256=selected_outcome,
            idempotency_key=selected_key,
        ),
        "idempotency_key": selected_key,
    }


def validate_recovery_verification_task(value: Mapping[str, Any]) -> dict[str, Any]:
    if set(value) != _TASK_FIELDS or value.get("schema") != TASK_SCHEMA:
        raise RecoveryError("verification-task-invalid")
    expected = build_recovery_verification_task(
        incident_id=cast(str, value.get("incident_id")),
        expected_incident_version=cast(int, value.get("expected_incident_version")),
        expected_outcome_sha256=cast(str, value.get("expected_outcome_sha256")),
        idempotency_key=cast(str, value.get("idempotency_key")),
    )
    task_key = value.get("task_key")
    if not isinstance(task_key, str) or _TASK_KEY.fullmatch(task_key) is None:
        raise RecoveryError("verification-task-key-invalid")
    payload_sha256 = value.get("payload_sha256")
    if not isinstance(payload_sha256, str):
        raise RecoveryError("verification-task-payload-invalid")
    require_digest(payload_sha256, code="verification-task-payload-invalid")
    if task_key != expected["task_key"]:
        raise RecoveryError("verification-task-key-conflict")
    if payload_sha256 != expected["payload_sha256"]:
        raise RecoveryError("verification-task-payload-conflict")
    return expected


def build_recovery_verification_admission(
    task_value: Mapping[str, Any],
    *,
    duplicate: bool,
    state: str,
) -> dict[str, Any]:
    task = validate_recovery_verification_task(task_value)
    if not isinstance(duplicate, bool) or state not in {"queued", "running", "complete"}:
        raise RecoveryError("verification-admission-invalid")
    return {
        **task,
        "schema": ADMISSION_SCHEMA,
        "duplicate": duplicate,
        "state": state,
    }


def validate_recovery_verification_admission(
    value: Mapping[str, Any],
    *,
    task_value: Mapping[str, Any],
) -> dict[str, Any]:
    if set(value) != _ADMISSION_FIELDS or value.get("schema") != ADMISSION_SCHEMA:
        raise RecoveryError("verification-dispatch-response-invalid")
    task = validate_recovery_verification_task(task_value)
    projected = {key: value.get(key) for key in _TASK_FIELDS}
    projected["schema"] = TASK_SCHEMA
    try:
        delivered = validate_recovery_verification_task(projected)
    except RecoveryError as error:
        raise RecoveryError("verification-dispatch-response-invalid") from error
    if canonical_json_bytes(task) != canonical_json_bytes(delivered):
        raise RecoveryError("verification-dispatch-response-invalid")
    duplicate = value.get("duplicate")
    state = value.get("state")
    if not isinstance(duplicate, bool) or state not in {"queued", "running", "complete"}:
        raise RecoveryError("verification-dispatch-response-invalid")
    return build_recovery_verification_admission(task, duplicate=duplicate, state=cast(str, state))


def build_recovery_verification_result(
    task_value: Mapping[str, Any],
    packet: Mapping[str, Any],
) -> dict[str, Any]:
    task = validate_recovery_verification_task(task_value)
    packet_id = packet.get("packet_id")
    packet_sha256 = packet.get("packet_sha256")
    if (
        packet.get("schema") != "recovery-packet/v1"
        or packet.get("incident_id") != task["incident_id"]
        or packet.get("incident_version") != task["expected_incident_version"]
        or packet.get("outcome_sha256") != task["expected_outcome_sha256"]
        or not isinstance(packet_id, str)
        or not isinstance(packet_sha256, str)
    ):
        raise RecoveryError("verification-task-packet-binding-invalid")
    require_digest(packet_sha256, code="verification-task-packet-binding-invalid")
    if packet_id != f"recovery-packet:{packet_sha256.removeprefix('sha256:')}":
        raise RecoveryError("verification-task-packet-binding-invalid")
    body = {
        "schema": RESULT_SCHEMA,
        "task_key": task["task_key"],
        "payload_sha256": task["payload_sha256"],
        "incident_id": task["incident_id"],
        "expected_incident_version": task["expected_incident_version"],
        "expected_outcome_sha256": task["expected_outcome_sha256"],
        "status": "completed",
        "packet_id": packet_id,
        "packet_sha256": packet_sha256,
        "reason_code": None,
    }
    digest = document_sha256(body)
    return {
        **body,
        "result_id": f"recovery-verification-task-result:{digest.removeprefix('sha256:')}",
        "result_sha256": digest,
    }


def build_unresolved_recovery_verification_result(
    task_value: Mapping[str, Any],
    *,
    reason_code: str,
) -> dict[str, Any]:
    task = validate_recovery_verification_task(task_value)
    if (
        not isinstance(reason_code, str)
        or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", reason_code) is None
    ):
        raise RecoveryError("verification-task-result-reason-invalid")
    body = {
        "schema": RESULT_SCHEMA,
        "task_key": task["task_key"],
        "payload_sha256": task["payload_sha256"],
        "incident_id": task["incident_id"],
        "expected_incident_version": task["expected_incident_version"],
        "expected_outcome_sha256": task["expected_outcome_sha256"],
        "status": "unresolved",
        "packet_id": None,
        "packet_sha256": None,
        "reason_code": reason_code,
    }
    digest = document_sha256(body)
    return {
        **body,
        "result_id": f"recovery-verification-task-result:{digest.removeprefix('sha256:')}",
        "result_sha256": digest,
    }


def validate_recovery_verification_result(
    value: Mapping[str, Any],
    *,
    task_value: Mapping[str, Any],
) -> dict[str, Any]:
    if set(value) != _RESULT_FIELDS or value.get("schema") != RESULT_SCHEMA:
        raise RecoveryError("stored-verification-task-result-invalid")
    task = validate_recovery_verification_task(task_value)
    expected_bindings = {
        "task_key": task["task_key"],
        "payload_sha256": task["payload_sha256"],
        "incident_id": task["incident_id"],
        "expected_incident_version": task["expected_incident_version"],
        "expected_outcome_sha256": task["expected_outcome_sha256"],
    }
    if any(value.get(key) != expected for key, expected in expected_bindings.items()):
        raise RecoveryError("stored-verification-task-result-invalid")
    status = value.get("status")
    packet_id = value.get("packet_id")
    packet_sha256 = value.get("packet_sha256")
    reason_code = value.get("reason_code")
    if status == "completed":
        if (
            not isinstance(packet_id, str)
            or not isinstance(packet_sha256, str)
            or reason_code is not None
        ):
            raise RecoveryError("stored-verification-task-result-invalid")
        require_digest(packet_sha256, code="stored-verification-task-result-invalid")
        if packet_id != f"recovery-packet:{packet_sha256.removeprefix('sha256:')}":
            raise RecoveryError("stored-verification-task-result-invalid")
    elif status == "unresolved":
        if (
            packet_id is not None
            or packet_sha256 is not None
            or not isinstance(reason_code, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", reason_code) is None
        ):
            raise RecoveryError("stored-verification-task-result-invalid")
    else:
        raise RecoveryError("stored-verification-task-result-invalid")
    body = {key: value[key] for key in _RESULT_FIELDS - {"result_id", "result_sha256"}}
    digest = document_sha256(body)
    if (
        value.get("result_sha256") != digest
        or value.get("result_id")
        != f"recovery-verification-task-result:{digest.removeprefix('sha256:')}"
    ):
        raise RecoveryError("stored-verification-task-result-invalid")
    return {key: value[key] for key in value}


class RecoveryVerificationTaskDispatcher(Protocol):
    def dispatch(self, task: Mapping[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class RecoveryVerificationTaskClaim:
    task: dict[str, Any]
    owner: str
    generation: int


@dataclass(frozen=True, slots=True)
class RecoveryVerificationTaskDelivery:
    task: dict[str, Any]
    attempt: int
    reconciliation_only: bool = False


class RecoveryVerificationTaskStore(RecoveryVerificationTaskDispatcher, Protocol):
    def claim(
        self,
        task: Mapping[str, Any],
        *,
        owner: str,
    ) -> RecoveryVerificationTaskClaim | dict[str, Any]: ...

    def complete(
        self,
        claim: RecoveryVerificationTaskClaim,
        result: Mapping[str, Any],
    ) -> dict[str, Any]: ...


_SCHEMA_V1 = """
CREATE TABLE recovery_verification_tasks (
    task_key TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    expected_incident_version INTEGER NOT NULL CHECK(expected_incident_version >= 1),
    expected_outcome_sha256 TEXT NOT NULL,
    task_document BLOB NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'complete')),
    claim_owner TEXT,
    claim_generation INTEGER NOT NULL DEFAULT 0 CHECK(claim_generation >= 0),
    claim_expires_at TEXT,
    result_sha256 TEXT,
    result_document BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(
        (status = 'pending' AND claim_owner IS NULL AND claim_generation = 0
            AND claim_expires_at IS NULL
            AND result_sha256 IS NULL AND result_document IS NULL)
        OR (status = 'running' AND claim_owner IS NOT NULL AND claim_generation >= 1
            AND claim_expires_at IS NOT NULL AND result_sha256 IS NULL
            AND result_document IS NULL)
        OR (status = 'complete' AND claim_owner IS NULL AND claim_generation >= 1
            AND claim_expires_at IS NULL AND result_sha256 IS NOT NULL
            AND result_document IS NOT NULL)
    )
) STRICT;
CREATE INDEX recovery_verification_tasks_available
    ON recovery_verification_tasks(status, claim_expires_at, created_at, task_key);
CREATE TRIGGER recovery_verification_tasks_no_delete
BEFORE DELETE ON recovery_verification_tasks BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-tasks-no-delete');
END;
CREATE TRIGGER recovery_verification_tasks_identity_immutable
BEFORE UPDATE ON recovery_verification_tasks
WHEN NEW.task_key != OLD.task_key OR NEW.idempotency_key != OLD.idempotency_key
    OR NEW.payload_sha256 != OLD.payload_sha256 OR NEW.incident_id != OLD.incident_id
    OR NEW.expected_incident_version != OLD.expected_incident_version
    OR NEW.expected_outcome_sha256 != OLD.expected_outcome_sha256
    OR NEW.task_document != OLD.task_document OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-task-identity-immutable');
END;
CREATE TRIGGER recovery_verification_tasks_valid_transition
BEFORE UPDATE ON recovery_verification_tasks
WHEN NOT (
    (OLD.status = 'pending' AND NEW.status = 'running'
        AND NEW.claim_generation = OLD.claim_generation + 1)
    OR (OLD.status = 'running' AND NEW.status = 'running'
        AND NEW.claim_generation = OLD.claim_generation + 1)
    OR (OLD.status = 'running' AND NEW.status = 'complete'
        AND NEW.claim_generation = OLD.claim_generation)
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-task-transition-invalid');
END;
CREATE TRIGGER recovery_verification_tasks_clock_monotonic
BEFORE UPDATE ON recovery_verification_tasks
WHEN NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-task-clock-regression');
END;
"""

_OUTBOX_SCHEMA = """
CREATE TABLE recovery_verification_task_outbox (
    task_key TEXT PRIMARY KEY REFERENCES recovery_verification_tasks(task_key),
    payload_sha256 TEXT NOT NULL,
    task_document BLOB NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'enqueued', 'exhausted', 'suppressed')),
    delivery_attempts INTEGER NOT NULL DEFAULT 0 CHECK(delivery_attempts >= 0),
    cloud_task_name TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(
        (status = 'pending' AND cloud_task_name IS NULL)
        OR (status = 'enqueued' AND delivery_attempts >= 1 AND cloud_task_name IS NOT NULL)
        OR (status IN ('exhausted', 'suppressed') AND cloud_task_name IS NULL)
    )
) STRICT;
CREATE INDEX recovery_verification_task_outbox_pending
    ON recovery_verification_task_outbox(status, created_at, task_key);
CREATE TRIGGER recovery_verification_task_outbox_no_delete
BEFORE DELETE ON recovery_verification_task_outbox BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-task-outbox-no-delete');
END;
CREATE TRIGGER recovery_verification_task_outbox_identity_immutable
BEFORE UPDATE ON recovery_verification_task_outbox
WHEN NEW.task_key != OLD.task_key OR NEW.payload_sha256 != OLD.payload_sha256
    OR NEW.task_document != OLD.task_document OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-task-outbox-identity-immutable');
END;
CREATE TRIGGER recovery_verification_task_outbox_valid_transition
BEFORE UPDATE ON recovery_verification_task_outbox
WHEN NOT (
    (OLD.status = 'pending' AND NEW.status = 'pending'
        AND NEW.delivery_attempts = OLD.delivery_attempts + 1
        AND NEW.cloud_task_name IS NULL)
    OR (OLD.status = 'pending' AND NEW.status = 'enqueued'
        AND NEW.delivery_attempts = OLD.delivery_attempts
        AND NEW.cloud_task_name IS NOT NULL)
    OR (OLD.status = 'pending' AND NEW.status IN ('exhausted', 'suppressed')
        AND NEW.delivery_attempts = OLD.delivery_attempts
        AND NEW.cloud_task_name IS NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-task-outbox-transition-invalid');
END;
CREATE TRIGGER recovery_verification_task_outbox_clock_monotonic
BEFORE UPDATE ON recovery_verification_task_outbox
WHEN NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'recovery-verification-task-outbox-clock-regression');
END;
"""

_SCHEMA = _SCHEMA_V1 + _OUTBOX_SCHEMA

_APPLICATION_ID = 0x43545654
_SCHEMA_VERSION = 2
_SchemaManifest = tuple[tuple[str, str, str, str | None], ...]


def _normalized_sql(value: str | None) -> str | None:
    return None if value is None else value.strip().replace("\r\n", "\n").replace("\r", "\n")


def _schema_manifest(connection: sqlite3.Connection) -> _SchemaManifest:
    rows = connection.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table', 'index', 'trigger') "
        "AND NOT (type = 'table' AND name LIKE 'sqlite_%') "
        "AND NOT (type IN ('index', 'trigger') AND tbl_name LIKE 'sqlite_%') "
        "ORDER BY type, name"
    ).fetchall()
    return tuple(
        (
            cast(str, row[0]),
            cast(str, row[1]),
            cast(str, row[2]),
            _normalized_sql(cast(str | None, row[3])),
        )
        for row in rows
    )


def _schema_sha256(manifest: _SchemaManifest) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()}"


def _expected_schema(schema: str) -> tuple[_SchemaManifest, str]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(schema)
        manifest = _schema_manifest(connection)
        return manifest, _schema_sha256(manifest)
    finally:
        connection.close()


_EXPECTED_SCHEMA_V1, _EXPECTED_SCHEMA_V1_SHA256 = _expected_schema(_SCHEMA_V1)
_EXPECTED_SCHEMA, _EXPECTED_SCHEMA_SHA256 = _expected_schema(_SCHEMA)


class SQLiteRecoveryVerificationTaskStore:
    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], datetime] = _utc_now,
        claim_lease_seconds: int = 120,
    ) -> None:
        if (
            not isinstance(claim_lease_seconds, int)
            or isinstance(claim_lease_seconds, bool)
            or not 1 <= claim_lease_seconds <= 600
        ):
            raise ValueError("verification-task-claim-lease-invalid")
        self._path, created, self._identity = self._prepare_database_path(Path(path))
        self._clock = clock
        self._claim_lease_seconds = claim_lease_seconds
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            self._initialize_or_validate(connection, created=created)
        except RecoveryError:
            raise
        except sqlite3.DatabaseError as error:
            raise RecoveryError("verification-task-store-invalid") from error
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _validate_database_stat(path: Path, value: os.stat_result) -> None:
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or path.is_symlink():
            raise RecoveryError("verification-task-store-path-invalid")
        if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) != 0o600:
            raise RecoveryError("verification-task-store-permissions-invalid")

    @classmethod
    def _prepare_database_path(cls, raw_path: Path) -> tuple[Path, bool, tuple[int, int]]:
        path = raw_path.absolute()
        try:
            parent = path.parent.stat(follow_symlinks=False)
        except OSError as error:
            raise RecoveryError("verification-task-store-path-invalid") from error
        if not stat.S_ISDIR(parent.st_mode):
            raise RecoveryError("verification-task-store-path-invalid")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            try:
                value = path.lstat()
            except OSError as error:
                raise RecoveryError("verification-task-store-path-invalid") from error
            cls._validate_database_stat(path, value)
            return path, False, (value.st_dev, value.st_ino)
        except OSError as error:
            raise RecoveryError("verification-task-store-path-invalid") from error
        try:
            os.fchmod(descriptor, 0o600)
            value = os.fstat(descriptor)
            cls._validate_database_stat(path, value)
            return path, True, (value.st_dev, value.st_ino)
        except OSError as error:
            raise RecoveryError("verification-task-store-path-invalid") from error
        finally:
            os.close(descriptor)

    @classmethod
    def _validate_database_path(
        cls,
        path: Path,
        expected_identity: tuple[int, int],
    ) -> None:
        try:
            value = path.lstat()
        except OSError as error:
            raise RecoveryError("verification-task-store-path-invalid") from error
        cls._validate_database_stat(path, value)
        if (value.st_dev, value.st_ino) != expected_identity:
            raise RecoveryError("verification-task-store-path-changed")

    def _connect(self) -> sqlite3.Connection:
        self._validate_database_path(self._path, self._identity)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{self._path.as_uri()}?mode=rw",
                timeout=5.0,
                isolation_level=None,
                uri=True,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            busy_timeout = connection.execute("PRAGMA busy_timeout").fetchone()
            foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
            trusted_schema = connection.execute("PRAGMA trusted_schema").fetchone()
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            if (
                busy_timeout is None
                or busy_timeout[0] != 5000
                or foreign_keys is None
                or foreign_keys[0] != 1
                or trusted_schema is None
                or trusted_schema[0] != 0
                or synchronous is None
                or synchronous[0] != 2
                or journal_mode is None
                or str(journal_mode[0]).lower() != "delete"
            ):
                raise RecoveryError("verification-task-store-invalid")
            self._validate_database_path(self._path, self._identity)
            return connection
        except RecoveryError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.OperationalError as error:
            if connection is not None:
                connection.close()
            raise RecoveryError("verification-task-store-unavailable") from error
        except sqlite3.DatabaseError as error:
            if connection is not None:
                connection.close()
            raise RecoveryError("verification-task-store-invalid") from error

    @staticmethod
    def _validate_schema_and_integrity(connection: sqlite3.Connection) -> None:
        application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
        version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
        if application_id != _APPLICATION_ID or version != _SCHEMA_VERSION:
            raise RecoveryError("verification-task-store-schema-invalid")
        manifest = _schema_manifest(connection)
        if manifest != _EXPECTED_SCHEMA or _schema_sha256(manifest) != _EXPECTED_SCHEMA_SHA256:
            raise RecoveryError("verification-task-store-schema-invalid")
        check = connection.execute("PRAGMA integrity_check").fetchall()
        if len(check) != 1 or check[0][0] != "ok":
            raise RecoveryError("verification-task-store-integrity-invalid")

    @classmethod
    def _initialize_or_validate(
        cls,
        connection: sqlite3.Connection,
        *,
        created: bool,
    ) -> None:
        if created:
            application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
            version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id != 0 or version != 0 or _schema_manifest(connection):
                raise RecoveryError("verification-task-store-schema-invalid")
            connection.executescript(_SCHEMA)
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        else:
            application_id = cast(int, connection.execute("PRAGMA application_id").fetchone()[0])
            version = cast(int, connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id == _APPLICATION_ID and version == 1:
                manifest = _schema_manifest(connection)
                integrity = connection.execute("PRAGMA integrity_check").fetchall()
                if (
                    manifest != _EXPECTED_SCHEMA_V1
                    or _schema_sha256(manifest) != _EXPECTED_SCHEMA_V1_SHA256
                    or len(integrity) != 1
                    or integrity[0][0] != "ok"
                ):
                    raise RecoveryError("verification-task-store-schema-invalid")
                try:
                    connection.executescript(
                        "BEGIN IMMEDIATE;\n"
                        + _OUTBOX_SCHEMA
                        + "\nINSERT INTO recovery_verification_task_outbox("
                        "task_key, payload_sha256, task_document, status, created_at, updated_at) "
                        "SELECT task_key, payload_sha256, task_document, 'pending', "
                        "created_at, updated_at FROM recovery_verification_tasks "
                        "WHERE status != 'complete';\n"
                        + f"\nPRAGMA user_version = {_SCHEMA_VERSION};\nCOMMIT;"
                    )
                except BaseException:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
        cls._validate_schema_and_integrity(connection)

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            self._validate_database_path(self._path, self._identity)
            self._validate_schema_and_integrity(connection)
            yield connection
            connection.commit()
            self._validate_database_path(self._path, self._identity)
        except RecoveryError:
            if connection.in_transaction:
                connection.rollback()
            raise
        except sqlite3.IntegrityError as error:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryError("verification-task-store-integrity-invalid") from error
        except sqlite3.OperationalError as error:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryError("verification-task-store-unavailable") from error
        except sqlite3.DatabaseError as error:
            if connection.in_transaction:
                connection.rollback()
            raise RecoveryError("verification-task-store-invalid") from error
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _decode(document: Any, *, code: str) -> dict[str, Any]:
        if not isinstance(document, bytes):
            raise RecoveryError(code)
        try:
            value = json.loads(document.decode("utf-8"))
            canonical = canonical_json_bytes(value)
        except (RecursionError, TypeError, UnicodeError, ValueError):
            raise RecoveryError(code) from None
        if not isinstance(value, dict) or canonical != document:
            raise RecoveryError(code)
        return cast(dict[str, Any], value)

    @classmethod
    def _stored_task(cls, row: sqlite3.Row) -> dict[str, Any]:
        task = validate_recovery_verification_task(
            cls._decode(row["task_document"], code="stored-verification-task-invalid")
        )
        if (
            row["task_key"] != task["task_key"]
            or row["idempotency_key"] != task["idempotency_key"]
            or row["payload_sha256"] != task["payload_sha256"]
            or row["incident_id"] != task["incident_id"]
            or row["expected_incident_version"] != task["expected_incident_version"]
            or row["expected_outcome_sha256"] != task["expected_outcome_sha256"]
        ):
            raise RecoveryError("stored-verification-task-invalid")
        created_at = _parse_timestamp(row["created_at"])
        updated_at = _parse_timestamp(row["updated_at"])
        status = row["status"]
        owner = row["claim_owner"]
        generation = row["claim_generation"]
        expires_at = row["claim_expires_at"]
        result_sha256 = row["result_sha256"]
        result_document = row["result_document"]
        if (
            updated_at < created_at
            or not isinstance(generation, int)
            or isinstance(generation, bool)
            or generation < 0
        ):
            raise RecoveryError("stored-verification-task-invalid")
        if status == "pending":
            if (
                generation != 0
                or owner is not None
                or expires_at is not None
                or result_sha256 is not None
                or result_document is not None
            ):
                raise RecoveryError("stored-verification-task-invalid")
        elif status == "running":
            if (
                generation < 1
                or not isinstance(owner, str)
                or _IDENTIFIER.fullmatch(owner) is None
                or result_sha256 is not None
                or result_document is not None
            ):
                raise RecoveryError("stored-verification-task-invalid")
            _parse_timestamp(expires_at)
        elif status == "complete":
            if generation < 1 or owner is not None or expires_at is not None:
                raise RecoveryError("stored-verification-task-invalid")
            cls._stored_result(row, task)
        else:
            raise RecoveryError("stored-verification-task-invalid")
        return task

    @classmethod
    def _stored_result(cls, row: sqlite3.Row, task: Mapping[str, Any]) -> dict[str, Any]:
        result = validate_recovery_verification_result(
            cls._decode(
                row["result_document"],
                code="stored-verification-task-result-invalid",
            ),
            task_value=task,
        )
        if row["result_sha256"] != result["result_sha256"]:
            raise RecoveryError("stored-verification-task-result-invalid")
        return result

    @staticmethod
    def _outbox_row(connection: sqlite3.Connection, task_key: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM recovery_verification_task_outbox WHERE task_key = ?",
                (task_key,),
            ).fetchone(),
        )

    @classmethod
    def _stored_outbox(cls, row: sqlite3.Row, task: Mapping[str, Any]) -> dict[str, Any]:
        document = validate_recovery_verification_task(
            cls._decode(row["task_document"], code="stored-verification-task-outbox-invalid")
        )
        created_at = _parse_timestamp(row["created_at"])
        updated_at = _parse_timestamp(row["updated_at"])
        attempts = row["delivery_attempts"]
        status = row["status"]
        cloud_task_name = row["cloud_task_name"]
        if (
            canonical_json_bytes(document) != canonical_json_bytes(task)
            or row["task_key"] != task["task_key"]
            or row["payload_sha256"] != task["payload_sha256"]
            or updated_at < created_at
            or not isinstance(attempts, int)
            or isinstance(attempts, bool)
            or attempts < 0
        ):
            raise RecoveryError("stored-verification-task-outbox-invalid")
        if status == "pending":
            if cloud_task_name is not None:
                raise RecoveryError("stored-verification-task-outbox-invalid")
        elif status == "enqueued":
            if (
                attempts < 1
                or not isinstance(cloud_task_name, str)
                or _CLOUD_TASK_NAME.fullmatch(cloud_task_name) is None
            ):
                raise RecoveryError("stored-verification-task-outbox-invalid")
        elif status in {"exhausted", "suppressed"}:
            if cloud_task_name is not None:
                raise RecoveryError("stored-verification-task-outbox-invalid")
        else:
            raise RecoveryError("stored-verification-task-outbox-invalid")
        return {
            "task_key": task["task_key"],
            "payload_sha256": task["payload_sha256"],
            "status": status,
            "delivery_attempts": attempts,
            "cloud_task_name": cloud_task_name,
        }

    @staticmethod
    def _row(connection: sqlite3.Connection, task_key: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM recovery_verification_tasks WHERE task_key = ?",
                (task_key,),
            ).fetchone(),
        )

    def dispatch(self, task: Mapping[str, Any]) -> dict[str, Any]:
        selected = validate_recovery_verification_task(task)
        now = _timestamp(self._clock())
        with self._transaction(write=True) as connection:
            row = connection.execute(
                "SELECT * FROM recovery_verification_tasks WHERE idempotency_key = ?",
                (selected["idempotency_key"],),
            ).fetchone()
            if row is not None:
                stored = self._stored_task(row)
                if canonical_json_bytes(stored) != canonical_json_bytes(selected):
                    raise RecoveryError("verification-task-idempotency-conflict")
                state = {"pending": "queued", "running": "running", "complete": "complete"}[
                    row["status"]
                ]
                return build_recovery_verification_admission(
                    stored,
                    duplicate=True,
                    state=state,
                )
            row = self._row(connection, cast(str, selected["task_key"]))
            if row is not None:
                stored = self._stored_task(row)
                if canonical_json_bytes(stored) != canonical_json_bytes(selected):
                    raise RecoveryError("verification-task-payload-conflict")
                return build_recovery_verification_admission(
                    stored,
                    duplicate=True,
                    state={
                        "pending": "queued",
                        "running": "running",
                        "complete": "complete",
                    }[row["status"]],
                )
            connection.execute(
                "INSERT INTO recovery_verification_tasks("
                "task_key, idempotency_key, payload_sha256, incident_id, "
                "expected_incident_version, expected_outcome_sha256, task_document, status, "
                "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    selected["task_key"],
                    selected["idempotency_key"],
                    selected["payload_sha256"],
                    selected["incident_id"],
                    selected["expected_incident_version"],
                    selected["expected_outcome_sha256"],
                    canonical_json_bytes(selected),
                    now,
                    now,
                ),
            )
            connection.execute(
                "INSERT INTO recovery_verification_task_outbox("
                "task_key, payload_sha256, task_document, status, created_at, updated_at) "
                "VALUES(?, ?, ?, 'pending', ?, ?)",
                (
                    selected["task_key"],
                    selected["payload_sha256"],
                    canonical_json_bytes(selected),
                    now,
                    now,
                ),
            )
        return build_recovery_verification_admission(selected, duplicate=False, state="queued")

    @staticmethod
    def _delivery_bounds(*, limit: int, max_attempts: int) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("verification-task-delivery-limit-invalid")
        if (
            not isinstance(max_attempts, int)
            or isinstance(max_attempts, bool)
            or not 1 <= max_attempts <= 100
        ):
            raise ValueError("verification-task-delivery-attempts-invalid")

    def reserve_cloud_task_deliveries(
        self,
        *,
        limit: int = 10,
        max_attempts: int = 5,
    ) -> list[RecoveryVerificationTaskDelivery]:
        self._delivery_bounds(limit=limit, max_attempts=max_attempts)
        now = _timestamp(self._clock())
        deliveries: list[RecoveryVerificationTaskDelivery] = []
        with self._transaction(write=True) as connection:
            rows = connection.execute(
                "SELECT o.task_key FROM recovery_verification_task_outbox AS o "
                "JOIN recovery_verification_tasks AS t ON t.task_key = o.task_key "
                "WHERE o.status = 'pending' AND t.status != 'complete' "
                "ORDER BY o.created_at, o.task_key LIMIT ?",
                (limit,),
            ).fetchall()
            for selected_row in rows:
                task_key = cast(str, selected_row["task_key"])
                task_row = self._row(connection, task_key)
                outbox_row = self._outbox_row(connection, task_key)
                if task_row is None or outbox_row is None:
                    raise RecoveryError("stored-verification-task-outbox-invalid")
                task = self._stored_task(task_row)
                state = self._stored_outbox(outbox_row, task)
                attempts = cast(int, state["delivery_attempts"])
                if attempts >= max_attempts:
                    deliveries.append(
                        RecoveryVerificationTaskDelivery(
                            task=task,
                            attempt=attempts,
                            reconciliation_only=True,
                        )
                    )
                    continue
                attempt = attempts + 1
                updated = connection.execute(
                    "UPDATE recovery_verification_task_outbox "
                    "SET delivery_attempts = ?, updated_at = ? "
                    "WHERE task_key = ? AND status = 'pending' "
                    "AND delivery_attempts = ?",
                    (attempt, now, task_key, attempts),
                )
                if updated.rowcount != 1:
                    raise RecoveryError("verification-task-delivery-claim-conflict")
                deliveries.append(RecoveryVerificationTaskDelivery(task=task, attempt=attempt))
        return deliveries

    @staticmethod
    def _validated_delivery(
        delivery: RecoveryVerificationTaskDelivery,
    ) -> tuple[dict[str, Any], int]:
        if not isinstance(delivery, RecoveryVerificationTaskDelivery):
            raise RecoveryError("verification-task-delivery-invalid")
        task = validate_recovery_verification_task(delivery.task)
        attempt = delivery.attempt
        if (
            not isinstance(attempt, int)
            or isinstance(attempt, bool)
            or attempt < 1
            or not isinstance(delivery.reconciliation_only, bool)
        ):
            raise RecoveryError("verification-task-delivery-invalid")
        return task, attempt

    def mark_cloud_task_enqueued(
        self,
        delivery: RecoveryVerificationTaskDelivery,
        *,
        cloud_task_name: str,
    ) -> dict[str, Any]:
        task, attempt = self._validated_delivery(delivery)
        if (
            not isinstance(cloud_task_name, str)
            or _CLOUD_TASK_NAME.fullmatch(cloud_task_name) is None
        ):
            raise RecoveryError("verification-cloud-task-name-invalid")
        now = _timestamp(self._clock())
        with self._transaction(write=True) as connection:
            task_row = self._row(connection, cast(str, task["task_key"]))
            outbox_row = self._outbox_row(connection, cast(str, task["task_key"]))
            if task_row is None or outbox_row is None:
                raise RecoveryError("verification-task-not-found")
            stored_task = self._stored_task(task_row)
            if canonical_json_bytes(stored_task) != canonical_json_bytes(task):
                raise RecoveryError("verification-task-payload-conflict")
            state = self._stored_outbox(outbox_row, stored_task)
            if state["status"] == "enqueued":
                if state["cloud_task_name"] != cloud_task_name:
                    raise RecoveryError("verification-cloud-task-name-conflict")
                return state
            if state["status"] != "pending" or state["delivery_attempts"] != attempt:
                raise RecoveryError("verification-task-delivery-fenced")
            updated = connection.execute(
                "UPDATE recovery_verification_task_outbox "
                "SET status = 'enqueued', cloud_task_name = ?, updated_at = ? "
                "WHERE task_key = ? AND status = 'pending' AND delivery_attempts = ?",
                (cloud_task_name, now, task["task_key"], attempt),
            )
            if updated.rowcount != 1:
                raise RecoveryError("verification-task-delivery-fenced")
            return {
                **state,
                "status": "enqueued",
                "cloud_task_name": cloud_task_name,
            }

    def fail_cloud_task_delivery(
        self,
        delivery: RecoveryVerificationTaskDelivery,
        *,
        max_attempts: int,
    ) -> dict[str, Any]:
        self._delivery_bounds(limit=1, max_attempts=max_attempts)
        task, attempt = self._validated_delivery(delivery)
        now = _timestamp(self._clock())
        with self._transaction(write=True) as connection:
            task_row = self._row(connection, cast(str, task["task_key"]))
            outbox_row = self._outbox_row(connection, cast(str, task["task_key"]))
            if task_row is None or outbox_row is None:
                raise RecoveryError("verification-task-not-found")
            stored_task = self._stored_task(task_row)
            if canonical_json_bytes(stored_task) != canonical_json_bytes(task):
                raise RecoveryError("verification-task-payload-conflict")
            state = self._stored_outbox(outbox_row, stored_task)
            if state["status"] == "enqueued":
                return state
            if state["status"] != "pending" or state["delivery_attempts"] != attempt:
                raise RecoveryError("verification-task-delivery-fenced")
            if attempt < max_attempts:
                return state
            updated = connection.execute(
                "UPDATE recovery_verification_task_outbox "
                "SET status = 'exhausted', updated_at = ? "
                "WHERE task_key = ? AND status = 'pending' AND delivery_attempts = ?",
                (now, task["task_key"], attempt),
            )
            if updated.rowcount != 1:
                raise RecoveryError("verification-task-delivery-fenced")
            return {**state, "status": "exhausted"}

    def cloud_task_outbox_state(self, task_key: str) -> dict[str, Any]:
        selected_key = _identifier(task_key, code="verification-task-key-invalid")
        if _TASK_KEY.fullmatch(selected_key) is None:
            raise RecoveryError("verification-task-key-invalid")
        with self._transaction(write=False) as connection:
            task_row = self._row(connection, selected_key)
            outbox_row = self._outbox_row(connection, selected_key)
            if task_row is None or outbox_row is None:
                raise RecoveryError("verification-task-not-found")
            task = self._stored_task(task_row)
            return self._stored_outbox(outbox_row, task)

    def pending_tasks(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("verification-task-limit-invalid")
        now = _timestamp(self._clock())
        with self._transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT * FROM recovery_verification_tasks "
                "WHERE status = 'pending' OR (status = 'running' AND claim_expires_at <= ?) "
                "ORDER BY created_at, task_key LIMIT ?",
                (now, limit),
            ).fetchall()
            return [self._stored_task(row) for row in rows]

    def claim(
        self,
        task: Mapping[str, Any],
        *,
        owner: str,
    ) -> RecoveryVerificationTaskClaim | dict[str, Any]:
        selected = validate_recovery_verification_task(task)
        selected_owner = _identifier(owner, code="verification-task-claim-owner-invalid")
        now_value = self._clock()
        now = _timestamp(now_value)
        expires_at = _timestamp(now_value + timedelta(seconds=self._claim_lease_seconds))
        with self._transaction(write=True) as connection:
            row = self._row(connection, cast(str, selected["task_key"]))
            if row is None:
                raise RecoveryError("verification-task-not-found")
            stored = self._stored_task(row)
            if canonical_json_bytes(stored) != canonical_json_bytes(selected):
                raise RecoveryError("verification-task-payload-conflict")
            if row["status"] == "complete":
                return self._stored_result(row, stored)
            if row["status"] == "running":
                if now_value.astimezone(UTC) < _parse_timestamp(row["claim_expires_at"]):
                    raise RecoveryError("verification-task-in-progress")
            generation = cast(int, row["claim_generation"]) + 1
            updated = connection.execute(
                "UPDATE recovery_verification_tasks SET status = 'running', claim_owner = ?, "
                "claim_generation = ?, claim_expires_at = ?, updated_at = ? "
                "WHERE task_key = ? AND claim_generation = ? AND status != 'complete'",
                (
                    selected_owner,
                    generation,
                    expires_at,
                    now,
                    selected["task_key"],
                    row["claim_generation"],
                ),
            )
            if updated.rowcount != 1:
                raise RecoveryError("verification-task-claim-conflict")
            return RecoveryVerificationTaskClaim(
                task=stored,
                owner=selected_owner,
                generation=generation,
            )

    def complete(
        self,
        claim: RecoveryVerificationTaskClaim,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(claim, RecoveryVerificationTaskClaim):
            raise RecoveryError("verification-task-claim-invalid")
        selected = validate_recovery_verification_result(result, task_value=claim.task)
        now = _timestamp(self._clock())
        with self._transaction(write=True) as connection:
            row = self._row(connection, cast(str, claim.task["task_key"]))
            if row is None:
                raise RecoveryError("verification-task-not-found")
            stored_task = self._stored_task(row)
            if canonical_json_bytes(stored_task) != canonical_json_bytes(claim.task):
                raise RecoveryError("verification-task-payload-conflict")
            if row["status"] == "complete":
                stored = self._stored_result(row, stored_task)
                if canonical_json_bytes(stored) != canonical_json_bytes(selected):
                    raise RecoveryError("verification-task-result-conflict")
                return stored
            if (
                row["status"] != "running"
                or row["claim_owner"] != claim.owner
                or row["claim_generation"] != claim.generation
            ):
                raise RecoveryError("verification-task-claim-fenced")
            updated = connection.execute(
                "UPDATE recovery_verification_tasks SET status = 'complete', claim_owner = NULL, "
                "claim_expires_at = NULL, result_sha256 = ?, result_document = ?, updated_at = ? "
                "WHERE task_key = ? AND status = 'running' AND claim_owner = ? "
                "AND claim_generation = ?",
                (
                    selected["result_sha256"],
                    canonical_json_bytes(selected),
                    now,
                    claim.task["task_key"],
                    claim.owner,
                    claim.generation,
                ),
            )
            if updated.rowcount != 1:
                raise RecoveryError("verification-task-claim-fenced")
            connection.execute(
                "UPDATE recovery_verification_task_outbox "
                "SET status = 'suppressed', updated_at = ? "
                "WHERE task_key = ? AND status = 'pending'",
                (now, claim.task["task_key"]),
            )
            return selected


__all__ = [
    "ADMISSION_SCHEMA",
    "RESULT_SCHEMA",
    "TASK_SCHEMA",
    "RecoveryVerificationTaskClaim",
    "RecoveryVerificationTaskDelivery",
    "RecoveryVerificationTaskDispatcher",
    "RecoveryVerificationTaskStore",
    "SQLiteRecoveryVerificationTaskStore",
    "build_recovery_verification_admission",
    "build_recovery_verification_result",
    "build_recovery_verification_task",
    "build_unresolved_recovery_verification_result",
    "validate_recovery_verification_admission",
    "validate_recovery_verification_result",
    "validate_recovery_verification_task",
]
