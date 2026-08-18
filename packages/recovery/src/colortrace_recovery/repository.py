from __future__ import annotations

import os
import sqlite3
import stat
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, cast

from .contracts import (
    RecoveryError,
    assess_post_action_observations,
    build_audit_event,
    canonical_json_bytes,
    document_sha256,
    parse_timestamp,
    prefixed_sha256,
    require_digest,
    require_idempotency_key,
    require_identifier,
    strict_json_bytes,
    timestamp,
    validate_audit_history,
    validate_closure_request,
    validate_closure_result,
    validate_evidence_record,
    validate_evidence_request,
    validate_recovery_packet,
    validate_verification_snapshot,
)

CLAIM_LEASE_SECONDS = 30

_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS recovery_workflows (
    workflow_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    incident_sequence INTEGER NOT NULL CHECK (incident_sequence >= 1),
    incident_version INTEGER NOT NULL CHECK (incident_version >= 1),
    snapshot_id TEXT NOT NULL UNIQUE,
    snapshot_sha256 TEXT NOT NULL UNIQUE,
    snapshot_document BLOB NOT NULL,
    outcome_id TEXT NOT NULL UNIQUE,
    outcome_sha256 TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN (
        'verification_pending', 'verification_running', 'recovery_verified',
        'recovery_failed', 'recovery_unresolved', 'closed'
    )),
    workflow_version INTEGER NOT NULL CHECK (workflow_version >= 1),
    current_attempt_number INTEGER NOT NULL CHECK (current_attempt_number >= 1),
    current_packet_id TEXT,
    current_packet_sha256 TEXT,
    current_packet_document BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (incident_id, incident_sequence),
    CHECK (
        (
            current_packet_id IS NULL
            AND current_packet_sha256 IS NULL
            AND current_packet_document IS NULL
        )
        OR
        (
            current_packet_id IS NOT NULL
            AND current_packet_sha256 IS NOT NULL
            AND current_packet_document IS NOT NULL
        )
    )
) STRICT;
CREATE INDEX IF NOT EXISTS recovery_workflows_incident_current
ON recovery_workflows(incident_id, incident_sequence DESC);
CREATE TABLE IF NOT EXISTS recovery_attempts (
    attempt_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES recovery_workflows(workflow_id),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    workflow_version INTEGER NOT NULL CHECK (workflow_version >= 1),
    request_id TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL UNIQUE,
    request_document BLOB NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_identity_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'complete')),
    claim_owner TEXT,
    claim_generation INTEGER NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claim_expires_at TEXT,
    packet_id TEXT,
    packet_sha256 TEXT,
    packet_document BLOB,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workflow_id, attempt_number),
    CHECK (
        (status = 'pending' AND claim_owner IS NULL AND claim_expires_at IS NULL)
        OR
        (
            status = 'running'
            AND claim_owner IS NOT NULL
            AND claim_generation >= 1
            AND claim_expires_at IS NOT NULL
        )
        OR
        (
            status = 'complete'
            AND packet_id IS NOT NULL
            AND packet_sha256 IS NOT NULL
            AND packet_document IS NOT NULL
        )
    )
) STRICT;
CREATE TABLE IF NOT EXISTS recovery_audit_events (
    workflow_id TEXT NOT NULL REFERENCES recovery_workflows(workflow_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    PRIMARY KEY (workflow_id, sequence)
) STRICT;
CREATE TABLE IF NOT EXISTS recovery_evidence_records (
    evidence_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL REFERENCES recovery_workflows(workflow_id),
    attempt_id TEXT NOT NULL REFERENCES recovery_attempts(attempt_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    evidence_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    UNIQUE (attempt_id, sequence)
) STRICT;
CREATE TABLE IF NOT EXISTS recovery_audit_heads (
    workflow_id TEXT PRIMARY KEY REFERENCES recovery_workflows(workflow_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_sha256 TEXT NOT NULL,
    FOREIGN KEY (workflow_id, sequence) REFERENCES recovery_audit_events(workflow_id, sequence)
) STRICT;
CREATE TABLE IF NOT EXISTS recovery_closures (
    closure_id TEXT PRIMARY KEY,
    workflow_id TEXT NOT NULL UNIQUE REFERENCES recovery_workflows(workflow_id),
    idempotency_key TEXT NOT NULL UNIQUE,
    request_sha256 TEXT NOT NULL,
    result_sha256 TEXT NOT NULL UNIQUE,
    result_document BLOB NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS recovery_audit_no_update
BEFORE UPDATE ON recovery_audit_events
BEGIN
    SELECT RAISE(ABORT, 'recovery-audit-append-only');
END;
CREATE TRIGGER IF NOT EXISTS recovery_audit_no_delete
BEFORE DELETE ON recovery_audit_events
BEGIN
    SELECT RAISE(ABORT, 'recovery-audit-append-only');
END;
CREATE TRIGGER IF NOT EXISTS recovery_evidence_no_update
BEFORE UPDATE ON recovery_evidence_records
BEGIN
    SELECT RAISE(ABORT, 'recovery-evidence-append-only');
END;
CREATE TRIGGER IF NOT EXISTS recovery_evidence_no_delete
BEFORE DELETE ON recovery_evidence_records
BEGIN
    SELECT RAISE(ABORT, 'recovery-evidence-append-only');
END;
"""

_SCHEMA_V3_PRE_BASELINE_SEAL_STATEMENTS = (
    """
CREATE TABLE IF NOT EXISTS recovery_claim_lease_baselines (
    attempt_id TEXT PRIMARY KEY REFERENCES recovery_attempts(attempt_id),
    after_sequence INTEGER NOT NULL CHECK (after_sequence >= 2),
    attempt_status TEXT NOT NULL CHECK (attempt_status IN ('running', 'complete')),
    claim_generation INTEGER NOT NULL CHECK (claim_generation >= 1),
    claim_owner TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_claim_lease_baseline_no_update
BEFORE UPDATE ON recovery_claim_lease_baselines
BEGIN
    SELECT RAISE(ABORT, 'recovery-claim-lease-baseline-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_claim_lease_baseline_no_delete
BEFORE DELETE ON recovery_claim_lease_baselines
BEGIN
    SELECT RAISE(ABORT, 'recovery-claim-lease-baseline-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_claim_lease_baseline_no_replace
BEFORE INSERT ON recovery_claim_lease_baselines
WHEN EXISTS (
    SELECT 1 FROM recovery_claim_lease_baselines WHERE attempt_id = NEW.attempt_id
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-claim-lease-baseline-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_audit_insert_no_replace
BEFORE INSERT ON recovery_audit_events
WHEN EXISTS (
    SELECT 1 FROM recovery_audit_events
    WHERE (workflow_id = NEW.workflow_id AND sequence = NEW.sequence)
       OR event_sha256 = NEW.event_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-audit-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_audit_insert_next
BEFORE INSERT ON recovery_audit_events
BEGIN
    SELECT CASE WHEN NEW.sequence != COALESCE(
        (SELECT sequence + 1 FROM recovery_audit_heads WHERE workflow_id = NEW.workflow_id),
        1
    ) THEN RAISE(ABORT, 'recovery-audit-sequence-invalid') END;
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_audit_head_insert_no_replace
BEFORE INSERT ON recovery_audit_heads
WHEN EXISTS (
    SELECT 1 FROM recovery_audit_heads WHERE workflow_id = NEW.workflow_id
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-audit-head-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_audit_head_insert_exact
BEFORE INSERT ON recovery_audit_heads
BEGIN
    SELECT CASE WHEN NEW.sequence != 1 OR NOT EXISTS (
        SELECT 1 FROM recovery_audit_events
        WHERE workflow_id = NEW.workflow_id
          AND sequence = NEW.sequence
          AND event_sha256 = NEW.event_sha256
    ) THEN RAISE(ABORT, 'recovery-audit-head-invalid') END;
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_audit_head_advance_exact
BEFORE UPDATE ON recovery_audit_heads
BEGIN
    SELECT CASE WHEN NEW.workflow_id != OLD.workflow_id
        OR NEW.sequence != OLD.sequence + 1
        OR NOT EXISTS (
            SELECT 1 FROM recovery_audit_events
            WHERE workflow_id = OLD.workflow_id
              AND sequence = OLD.sequence
              AND event_sha256 = OLD.event_sha256
        )
        OR NOT EXISTS (
            SELECT 1 FROM recovery_audit_events
            WHERE workflow_id = NEW.workflow_id
              AND sequence = NEW.sequence
              AND event_sha256 = NEW.event_sha256
        )
    THEN RAISE(ABORT, 'recovery-audit-head-invalid') END;
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_audit_head_no_delete
BEFORE DELETE ON recovery_audit_heads
BEGIN
    SELECT RAISE(ABORT, 'recovery-audit-head-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_evidence_insert_no_replace
BEFORE INSERT ON recovery_evidence_records
WHEN EXISTS (
    SELECT 1 FROM recovery_evidence_records
    WHERE evidence_id = NEW.evidence_id
       OR evidence_sha256 = NEW.evidence_sha256
       OR (attempt_id = NEW.attempt_id AND sequence = NEW.sequence)
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-evidence-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_workflow_no_delete
BEFORE DELETE ON recovery_workflows
BEGIN
    SELECT RAISE(ABORT, 'recovery-workflow-lifecycle');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_workflow_insert_no_replace
BEFORE INSERT ON recovery_workflows
WHEN EXISTS (
    SELECT 1 FROM recovery_workflows
    WHERE workflow_id = NEW.workflow_id
       OR snapshot_id = NEW.snapshot_id
       OR snapshot_sha256 = NEW.snapshot_sha256
       OR outcome_id = NEW.outcome_id
       OR outcome_sha256 = NEW.outcome_sha256
       OR (incident_id = NEW.incident_id AND incident_sequence = NEW.incident_sequence)
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-workflow-lifecycle');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_attempt_no_delete
BEFORE DELETE ON recovery_attempts
BEGIN
    SELECT RAISE(ABORT, 'recovery-attempt-lifecycle');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_attempt_insert_no_replace
BEFORE INSERT ON recovery_attempts
WHEN EXISTS (
    SELECT 1 FROM recovery_attempts
    WHERE attempt_id = NEW.attempt_id
       OR request_id = NEW.request_id
       OR request_sha256 = NEW.request_sha256
       OR idempotency_key = NEW.idempotency_key
       OR (workflow_id = NEW.workflow_id AND attempt_number = NEW.attempt_number)
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-attempt-lifecycle');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_closure_no_update
BEFORE UPDATE ON recovery_closures
BEGIN
    SELECT RAISE(ABORT, 'recovery-closure-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_closure_insert_no_replace
BEFORE INSERT ON recovery_closures
WHEN EXISTS (
    SELECT 1 FROM recovery_closures
    WHERE closure_id = NEW.closure_id
       OR workflow_id = NEW.workflow_id
       OR idempotency_key = NEW.idempotency_key
       OR result_sha256 = NEW.result_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'recovery-closure-append-only');
END
""",
    """
CREATE TRIGGER IF NOT EXISTS recovery_closure_no_delete
BEFORE DELETE ON recovery_closures
BEGIN
    SELECT RAISE(ABORT, 'recovery-closure-append-only');
END
""",
)

_SCHEMA_V3_BASELINE_SEAL_STATEMENT = """
CREATE TRIGGER IF NOT EXISTS recovery_claim_lease_baseline_no_insert
BEFORE INSERT ON recovery_claim_lease_baselines
BEGIN
    SELECT RAISE(ABORT, 'recovery-claim-lease-baseline-migration-only');
END
"""

_SCHEMA_V3_STATEMENTS = (
    *_SCHEMA_V3_PRE_BASELINE_SEAL_STATEMENTS,
    _SCHEMA_V3_BASELINE_SEAL_STATEMENT,
)

_SCHEMA += ";\n".join(statement.strip() for statement in _SCHEMA_V3_STATEMENTS) + ";\n"

_APPLICATION_ID = 0x43545259
_SCHEMA_VERSION = 3
_PREVIOUS_SCHEMA_VERSION = 2
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
        (cast(str, row[0]), cast(str, row[1]), cast(str, row[2]), _normalized_sql(row[3]))
        for row in rows
    )


def _expected_schema() -> tuple[_SchemaManifest, str]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA)
        manifest = _schema_manifest(connection)
    finally:
        connection.close()
    return manifest, prefixed_sha256(canonical_json_bytes(manifest))


_EXPECTED_SCHEMA, _EXPECTED_SCHEMA_SHA256 = _expected_schema()
_V3_SCHEMA_NAMES = frozenset(
    {
        "recovery_claim_lease_baselines",
        "recovery_claim_lease_baseline_no_update",
        "recovery_claim_lease_baseline_no_delete",
        "recovery_claim_lease_baseline_no_replace",
        "recovery_claim_lease_baseline_no_insert",
        "recovery_audit_insert_no_replace",
        "recovery_audit_insert_next",
        "recovery_audit_head_insert_no_replace",
        "recovery_audit_head_insert_exact",
        "recovery_audit_head_advance_exact",
        "recovery_audit_head_no_delete",
        "recovery_evidence_insert_no_replace",
        "recovery_workflow_no_delete",
        "recovery_workflow_insert_no_replace",
        "recovery_attempt_no_delete",
        "recovery_attempt_insert_no_replace",
        "recovery_closure_no_update",
        "recovery_closure_no_delete",
        "recovery_closure_insert_no_replace",
    }
)
_EXPECTED_SCHEMA_V2 = tuple(
    row
    for row in _EXPECTED_SCHEMA
    if row[1] not in _V3_SCHEMA_NAMES and row[2] not in _V3_SCHEMA_NAMES
)
_EXPECTED_SCHEMA_V2_SHA256 = prefixed_sha256(canonical_json_bytes(_EXPECTED_SCHEMA_V2))


@dataclass(frozen=True, slots=True)
class VerificationAttempt:
    workflow_id: str
    incident_id: str
    incident_version: int
    workflow_version: int
    attempt_id: str
    attempt_number: int
    snapshot: Mapping[str, Any]
    evidence_request: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class VerificationClaim:
    workflow_id: str
    incident_id: str
    incident_version: int
    workflow_version: int
    attempt_id: str
    attempt_number: int
    owner: str
    generation: int
    lease_expires_at: str
    snapshot: Mapping[str, Any]
    evidence_request: Mapping[str, Any]


class SQLiteRecoveryRepository:
    def __init__(self, database: str | Path = ":memory:", *, busy_timeout_ms: int = 30_000) -> None:
        if (
            not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or not 1 <= busy_timeout_ms <= 120_000
        ):
            raise RecoveryError("database-timeout-invalid")
        self._lock = threading.RLock()
        self._closed = False
        self._database = str(database)
        created = False
        self._identity: tuple[int, int] | None = None
        if self._database != ":memory:":
            path = Path(database)
            if not path.is_absolute():
                path = path.resolve()
            parent = path.parent
            if not parent.is_dir() or parent.is_symlink():
                raise RecoveryError("database-path-invalid")
            if path.exists():
                self._validate_database_file(path)
            else:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(descriptor)
                created = True
            self._validate_database_file(path)
            information = path.stat()
            self._identity = (information.st_dev, information.st_ino)
            self._database = str(path)
        try:
            self._connection = sqlite3.connect(
                self._database,
                isolation_level=None,
                check_same_thread=False,
                timeout=busy_timeout_ms / 1000,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA recursive_triggers = ON")
            self._initialize(created=created)
        except Exception:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise

    @staticmethod
    def _validate_database_file(path: Path) -> None:
        try:
            information = path.lstat()
        except OSError as error:
            raise RecoveryError("database-path-invalid") from error
        if (
            path.is_symlink()
            or not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or information.st_mode & 0o077
        ):
            raise RecoveryError("database-path-invalid")

    def _assert_path(self) -> None:
        if self._database == ":memory:":
            return
        path = Path(self._database)
        self._validate_database_file(path)
        information = path.stat()
        if self._identity != (information.st_dev, information.st_ino):
            raise RecoveryError("database-path-changed")

    def _initialize(self, *, created: bool) -> None:
        with self._lock:
            application_id = cast(
                int,
                self._connection.execute("PRAGMA application_id").fetchone()[0],
            )
            user_version = cast(int, self._connection.execute("PRAGMA user_version").fetchone()[0])
            existing_manifest = _schema_manifest(self._connection)
            if created or (application_id == 0 and user_version == 0 and not existing_manifest):
                self._connection.executescript(_SCHEMA)
                self._connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            elif application_id != _APPLICATION_ID:
                raise RecoveryError("database-schema-invalid")
            elif user_version == _PREVIOUS_SCHEMA_VERSION:
                if (
                    existing_manifest != _EXPECTED_SCHEMA_V2
                    or prefixed_sha256(canonical_json_bytes(existing_manifest))
                    != _EXPECTED_SCHEMA_V2_SHA256
                ):
                    raise RecoveryError("database-schema-invalid")
                self._connection.execute("BEGIN IMMEDIATE")
                try:
                    self._validate_all_audit_histories(
                        self._connection,
                        allow_legacy_renewal=True,
                    )
                    for statement in _SCHEMA_V3_PRE_BASELINE_SEAL_STATEMENTS:
                        self._connection.execute(statement)
                    self._capture_v2_claim_lease_baselines(self._connection)
                    self._connection.execute(_SCHEMA_V3_BASELINE_SEAL_STATEMENT)
                    self._validate_all_audit_histories(self._connection)
                    self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                    migrated_manifest = _schema_manifest(self._connection)
                    if (
                        migrated_manifest != _EXPECTED_SCHEMA
                        or prefixed_sha256(canonical_json_bytes(migrated_manifest))
                        != _EXPECTED_SCHEMA_SHA256
                    ):
                        raise RecoveryError("database-schema-invalid")
                    integrity = self._connection.execute("PRAGMA integrity_check").fetchone()
                    if integrity is None or integrity[0] != "ok":
                        raise RecoveryError("database-integrity-invalid")
                    if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                        raise RecoveryError("database-integrity-invalid")
                except BaseException:
                    self._connection.rollback()
                    raise
                else:
                    self._connection.commit()
            elif user_version != _SCHEMA_VERSION:
                raise RecoveryError("database-schema-invalid")
            manifest = _schema_manifest(self._connection)
            if (
                manifest != _EXPECTED_SCHEMA
                or prefixed_sha256(canonical_json_bytes(manifest)) != _EXPECTED_SCHEMA_SHA256
            ):
                raise RecoveryError("database-schema-invalid")
            result = self._connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise RecoveryError("database-integrity-invalid")
            if self._connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise RecoveryError("database-integrity-invalid")

    @contextmanager
    def transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        with self._lock:
            if self._closed:
                raise RecoveryError("repository-closed")
            self._assert_path()
            self._connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield self._connection
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._connection.close()
                self._closed = True

    @staticmethod
    def _decode(value: bytes | memoryview) -> dict[str, Any]:
        selected = strict_json_bytes(bytes(value))
        if not isinstance(selected, dict):
            raise RecoveryError("stored-document-invalid")
        return selected

    @staticmethod
    def _workflow_id(snapshot: Mapping[str, Any]) -> str:
        identity = {
            "schema": "recovery-workflow-identity/v1",
            "incident_id": snapshot["incident_id"],
            "outcome_sha256": cast(Mapping[str, Any], snapshot["action_outcome"])["outcome_sha256"],
        }
        identity_sha256 = prefixed_sha256(canonical_json_bytes(identity))
        return f"recovery-workflow:{identity_sha256.removeprefix('sha256:')}"

    @staticmethod
    def _attempt_id(workflow_id: str, attempt_number: int, request_sha256: str) -> str:
        identity = {
            "schema": "recovery-attempt-identity/v1",
            "workflow_id": workflow_id,
            "attempt_number": attempt_number,
            "request_sha256": request_sha256,
        }
        identity_sha256 = prefixed_sha256(canonical_json_bytes(identity))
        return f"recovery-attempt:{identity_sha256.removeprefix('sha256:')}"

    @classmethod
    def _attempt_from_rows(
        cls,
        workflow: sqlite3.Row,
        attempt: sqlite3.Row,
    ) -> VerificationAttempt:
        return VerificationAttempt(
            workflow_id=cast(str, workflow["workflow_id"]),
            incident_id=cast(str, workflow["incident_id"]),
            incident_version=cast(int, workflow["incident_version"]),
            workflow_version=cast(int, attempt["workflow_version"]),
            attempt_id=cast(str, attempt["attempt_id"]),
            attempt_number=cast(int, attempt["attempt_number"]),
            snapshot=cls._decode(workflow["snapshot_document"]),
            evidence_request=cls._decode(attempt["request_document"]),
        )

    @staticmethod
    def _workflow_row(connection: sqlite3.Connection, workflow_id: str) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM recovery_workflows WHERE workflow_id = ?",
                (workflow_id,),
            ).fetchone(),
        )
        if row is None:
            raise RecoveryError("recovery-workflow-not-found")
        return row

    @staticmethod
    def _current_attempt_row(
        connection: sqlite3.Connection,
        workflow: sqlite3.Row,
    ) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                "SELECT * FROM recovery_attempts WHERE workflow_id = ? AND attempt_number = ?",
                (workflow["workflow_id"], workflow["current_attempt_number"]),
            ).fetchone(),
        )
        if row is None:
            raise RecoveryError("recovery-attempt-not-found")
        return row

    @classmethod
    def _validated_audit_history(
        cls,
        connection: sqlite3.Connection,
        workflow: sqlite3.Row,
        *,
        allow_legacy_renewal: bool = False,
    ) -> list[dict[str, Any]]:
        workflow_id = cast(str, workflow["workflow_id"])
        rows = connection.execute(
            "SELECT workflow_id, sequence, event_sha256, document "
            "FROM recovery_audit_events WHERE workflow_id = ? ORDER BY sequence",
            (workflow_id,),
        ).fetchall()
        events = [cls._decode(row["document"]) for row in rows]
        validate_audit_history(events, workflow_id=workflow_id)
        if not events or len(events) != workflow["workflow_version"]:
            raise RecoveryError("stored-audit-lifecycle-invalid")
        for row, event in zip(rows, events, strict=True):
            if (
                row["workflow_id"] != event["workflow_id"]
                or row["sequence"] != event["sequence"]
                or row["event_sha256"] != event["event_sha256"]
                or event["incident_id"] != workflow["incident_id"]
                or event["snapshot_id"] != workflow["snapshot_id"]
                or event["snapshot_sha256"] != workflow["snapshot_sha256"]
                or event["outcome_id"] != workflow["outcome_id"]
                or event["outcome_sha256"] != workflow["outcome_sha256"]
            ):
                raise RecoveryError("stored-audit-row-invalid")
        heads = connection.execute(
            "SELECT workflow_id, sequence, event_sha256 FROM recovery_audit_heads "
            "WHERE workflow_id = ?",
            (workflow_id,),
        ).fetchall()
        if len(heads) != 1:
            raise RecoveryError("stored-audit-head-invalid")
        head = heads[0]
        tail = events[-1]
        if (
            head["workflow_id"] != workflow_id
            or head["sequence"] != len(events)
            or head["sequence"] != tail["sequence"]
            or head["event_sha256"] != tail["event_sha256"]
        ):
            raise RecoveryError("stored-audit-head-invalid")
        cls._validate_audit_lifecycle(
            connection,
            workflow,
            events,
            allow_legacy_renewal=allow_legacy_renewal,
        )
        return events

    @classmethod
    def _validate_audit_lifecycle(
        cls,
        connection: sqlite3.Connection,
        workflow: sqlite3.Row,
        events: list[dict[str, Any]],
        *,
        allow_legacy_renewal: bool,
    ) -> None:
        workflow_id = cast(str, workflow["workflow_id"])
        snapshot = validate_verification_snapshot(cls._decode(workflow["snapshot_document"]))
        outcome = cast(Mapping[str, Any], snapshot["action_outcome"])
        if (
            cls._workflow_id(snapshot) != workflow_id
            or snapshot["incident_id"] != workflow["incident_id"]
            or snapshot["incident_version"] != workflow["incident_version"]
            or snapshot["snapshot_id"] != workflow["snapshot_id"]
            or snapshot["snapshot_sha256"] != workflow["snapshot_sha256"]
            or outcome["outcome_id"] != workflow["outcome_id"]
            or outcome["outcome_sha256"] != workflow["outcome_sha256"]
        ):
            raise RecoveryError("stored-workflow-binding-invalid")
        attempts = connection.execute(
            "SELECT * FROM recovery_attempts WHERE workflow_id = ? ORDER BY attempt_number",
            (workflow_id,),
        ).fetchall()
        current_number = cast(int, workflow["current_attempt_number"])
        if len(attempts) != current_number or [row["attempt_number"] for row in attempts] != list(
            range(1, current_number + 1)
        ):
            raise RecoveryError("stored-attempt-lifecycle-invalid")
        known_attempts = {cast(str, row["attempt_id"]): row for row in attempts}
        grouped: dict[str, list[dict[str, Any]]] = {attempt_id: [] for attempt_id in known_attempts}
        packet_statuses: dict[str, str] = {}
        closing_events: list[dict[str, Any]] = []
        expected_sequence = 1
        for event in events:
            details = cast(Mapping[str, Any], event["details"])
            if details.get("action_id") != outcome["action_id"]:
                raise RecoveryError("stored-audit-lifecycle-invalid")
            if event["event_type"] == "recovery.closed":
                closing_events.append(event)
                continue
            actor = cast(Mapping[str, Any], event["actor"])
            if (
                actor.get("kind") != "service"
                or actor.get("authorized_role") != "recovery.verifier"
            ):
                raise RecoveryError("stored-audit-authority-invalid")
            attempt_id = details.get("attempt_id")
            if not isinstance(attempt_id, str) or attempt_id not in grouped:
                raise RecoveryError("stored-audit-lifecycle-invalid")
            grouped[attempt_id].append(event)

        for index, attempt in enumerate(attempts, start=1):
            attempt_id = cast(str, attempt["attempt_id"])
            attempt_events = grouped[attempt_id]
            request = validate_evidence_request(
                cls._decode(attempt["request_document"]),
                snapshot=snapshot,
            )
            request_identity_sha256 = document_sha256(
                {
                    "schema": "recovery-verification-registration/v1",
                    "snapshot_sha256": snapshot["snapshot_sha256"],
                    "request_sha256": request["request_sha256"],
                }
            )
            if (
                attempt["workflow_id"] != workflow_id
                or attempt["attempt_number"] != index
                or attempt_id
                != cls._attempt_id(workflow_id, index, cast(str, request["request_sha256"]))
                or attempt["request_id"] != request["request_id"]
                or attempt["request_sha256"] != request["request_sha256"]
                or attempt["request_identity_sha256"] != request_identity_sha256
            ):
                raise RecoveryError("stored-attempt-binding-invalid")
            requested = [
                event for event in attempt_events if event["event_type"] == "verification.requested"
            ]
            transitions = [
                event
                for event in attempt_events
                if event["event_type"]
                in {
                    "verification.claimed",
                    "verification.reclaimed",
                    "verification.renewed",
                }
            ]
            completed = [
                event for event in attempt_events if event["event_type"] == "verification.completed"
            ]
            if len(requested) != 1:
                raise RecoveryError("stored-attempt-lifecycle-invalid")
            request_event = requested[0]
            request_details = cast(Mapping[str, Any], request_event["details"])
            if (
                request_event["sequence"] != expected_sequence
                or request_event["sequence"] != attempt["workflow_version"]
                or request_event["idempotency_key"] != attempt["idempotency_key"]
                or request_event["packet_id"] is not None
                or request_event["packet_sha256"] is not None
                or request_details.get("attempt_number") != index
                or request_event["occurred_at"] != attempt["created_at"]
            ):
                raise RecoveryError("stored-attempt-lifecycle-invalid")
            expected_sequence += 1
            baseline = None
            if not allow_legacy_renewal:
                baseline = connection.execute(
                    "SELECT * FROM recovery_claim_lease_baselines WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if baseline is not None:
                    require_identifier(
                        baseline["claim_owner"],
                        code="stored-claim-lifecycle-invalid",
                    )
                    baseline_expiry = parse_timestamp(baseline["lease_expires_at"])
                    baseline_updated = parse_timestamp(baseline["updated_at"])
                    if (
                        baseline["after_sequence"] <= request_event["sequence"]
                        or baseline["after_sequence"] > len(events)
                        or baseline["claim_generation"] < 1
                        or baseline["claim_generation"] > attempt["claim_generation"]
                        or (
                            baseline["attempt_status"] == "running"
                            and baseline_expiry
                            != baseline_updated + timedelta(seconds=CLAIM_LEASE_SECONDS)
                        )
                        or (
                            baseline["attempt_status"] == "complete"
                            and (
                                attempt["status"] != "complete"
                                or baseline_expiry
                                > baseline_updated + timedelta(seconds=CLAIM_LEASE_SECONDS)
                            )
                        )
                    ):
                        raise RecoveryError("stored-claim-lifecycle-invalid")
            generation = cast(int, attempt["claim_generation"])
            if attempt["status"] == "pending":
                if (
                    generation != 0
                    or attempt["claim_owner"] is not None
                    or attempt["claim_expires_at"] is not None
                    or attempt["updated_at"] != attempt["created_at"]
                    or transitions
                ):
                    raise RecoveryError("stored-claim-lifecycle-invalid")
            else:
                if (
                    generation < 1
                    or not isinstance(attempt["claim_owner"], str)
                    or not isinstance(attempt["claim_expires_at"], str)
                    or not transitions
                ):
                    raise RecoveryError("stored-claim-lifecycle-invalid")
            observed_generation = 0
            observed_owner: str | None = None
            observed_expiry = None
            observed_updated_at = None
            baseline_applied = False
            for event in transitions:
                if (
                    baseline is not None
                    and not baseline_applied
                    and event["sequence"] > baseline["after_sequence"]
                ):
                    observed_generation = cast(int, baseline["claim_generation"])
                    observed_owner = cast(str, baseline["claim_owner"])
                    observed_expiry = parse_timestamp(baseline["lease_expires_at"])
                    observed_updated_at = cast(str, baseline["updated_at"])
                    baseline_applied = True
                details = cast(Mapping[str, Any], event["details"])
                if (
                    event["idempotency_key"] != attempt["idempotency_key"]
                    or event["packet_id"] is not None
                    or event["packet_sha256"] is not None
                    or event["sequence"] != expected_sequence
                ):
                    raise RecoveryError("stored-claim-lifecycle-invalid")
                owner = require_identifier(
                    details.get("claim_owner"),
                    code="stored-claim-lifecycle-invalid",
                )
                occurred_at = parse_timestamp(event["occurred_at"])
                lease_expires_at = parse_timestamp(details.get("lease_expires_at"))
                if lease_expires_at != occurred_at + timedelta(seconds=CLAIM_LEASE_SECONDS):
                    raise RecoveryError("stored-claim-lifecycle-invalid")
                if event["event_type"] == "verification.renewed":
                    if (
                        observed_generation < 1
                        or details.get("claim_generation") != observed_generation
                        or owner != observed_owner
                        or observed_expiry is None
                        or parse_timestamp(details.get("lease_expires_before")) != observed_expiry
                        or occurred_at >= observed_expiry
                        or lease_expires_at <= observed_expiry
                    ):
                        raise RecoveryError("stored-claim-lifecycle-invalid")
                else:
                    observed_generation += 1
                    expected_type = (
                        "verification.claimed"
                        if observed_generation == 1
                        else "verification.reclaimed"
                    )
                    if (
                        event["event_type"] != expected_type
                        or details.get("claim_generation") != observed_generation
                        or (observed_expiry is not None and occurred_at < observed_expiry)
                    ):
                        raise RecoveryError("stored-claim-lifecycle-invalid")
                observed_owner = owner
                observed_expiry = lease_expires_at
                observed_updated_at = cast(str, event["occurred_at"])
                expected_sequence += 1
            if baseline is not None and not baseline_applied:
                observed_generation = cast(int, baseline["claim_generation"])
                observed_owner = cast(str, baseline["claim_owner"])
                observed_expiry = parse_timestamp(baseline["lease_expires_at"])
                observed_updated_at = cast(str, baseline["updated_at"])
                baseline_applied = True
            if attempt["status"] != "pending":
                stored_expiry = parse_timestamp(attempt["claim_expires_at"])
                if observed_generation != generation or observed_owner != attempt["claim_owner"]:
                    raise RecoveryError("stored-claim-lifecycle-invalid")
                if allow_legacy_renewal:
                    bounded_expiry = parse_timestamp(attempt["updated_at"]) + timedelta(
                        seconds=CLAIM_LEASE_SECONDS
                    )
                    if (
                        observed_expiry is None
                        or stored_expiry < observed_expiry
                        or (attempt["status"] == "running" and stored_expiry != bounded_expiry)
                        or (attempt["status"] == "complete" and stored_expiry > bounded_expiry)
                    ):
                        raise RecoveryError("stored-claim-lifecycle-invalid")
                elif observed_expiry != stored_expiry or (
                    attempt["status"] == "running" and attempt["updated_at"] != observed_updated_at
                ):
                    raise RecoveryError("stored-claim-lifecycle-invalid")
            evidence_rows = connection.execute(
                "SELECT evidence_id, workflow_id, attempt_id, sequence, evidence_sha256, "
                "document FROM recovery_evidence_records WHERE attempt_id = ? ORDER BY sequence",
                (attempt_id,),
            ).fetchall()
            records = [
                validate_evidence_record(cls._decode(row["document"])) for row in evidence_rows
            ]
            for sequence, (row, record) in enumerate(
                zip(evidence_rows, records, strict=True),
                start=1,
            ):
                if (
                    row["evidence_id"] != record["evidence_id"]
                    or row["workflow_id"] != workflow_id
                    or row["attempt_id"] != attempt_id
                    or row["sequence"] != sequence
                    or row["evidence_sha256"] != record["evidence_sha256"]
                ):
                    raise RecoveryError("stored-evidence-row-invalid")
            if attempt["status"] != "complete":
                if completed or records:
                    raise RecoveryError("stored-attempt-lifecycle-invalid")
                continue
            if len(completed) != 1:
                raise RecoveryError("stored-attempt-lifecycle-invalid")
            packet = validate_recovery_packet(
                cls._decode(attempt["packet_document"]),
                snapshot=snapshot,
                evidence_request=request,
            )
            packet_statuses[attempt_id] = cast(str, packet["status"])
            completion = completed[0]
            completion_details = cast(Mapping[str, Any], completion["details"])
            if (
                attempt["packet_id"] != packet["packet_id"]
                or attempt["packet_sha256"] != packet["packet_sha256"]
                or packet["workflow_id"] != workflow_id
                or packet["attempt_id"] != attempt_id
                or packet["attempt_number"] != index
                or completion["sequence"] != packet["workflow_version"]
                or completion["sequence"] != expected_sequence
                or completion["idempotency_key"] != attempt["idempotency_key"]
                or completion["packet_id"] != packet["packet_id"]
                or completion["packet_sha256"] != packet["packet_sha256"]
                or completion_details.get("claim_owner") != attempt["claim_owner"]
                or completion_details.get("claim_generation") != generation
                or completion_details.get("status") != packet["status"]
                or completion["occurred_at"] != attempt["updated_at"]
                or set(cast(list[str], packet["evidence_ids"]))
                != {cast(str, record["evidence_id"]) for record in records}
            ):
                raise RecoveryError("stored-completion-lifecycle-invalid")
            expected_sequence += 1

        current = attempts[-1]
        if any(
            row["status"] != "complete"
            or packet_statuses.get(cast(str, row["attempt_id"])) != "recovery_unresolved"
            for row in attempts[:-1]
        ):
            raise RecoveryError("stored-attempt-lifecycle-invalid")
        status = cast(str, workflow["status"])
        expected_attempt_status = {
            "verification_pending": "pending",
            "verification_running": "running",
            "recovery_verified": "complete",
            "recovery_failed": "complete",
            "recovery_unresolved": "complete",
            "closed": "complete",
        }[status]
        if current["status"] != expected_attempt_status:
            raise RecoveryError("stored-attempt-lifecycle-invalid")
        if current["status"] == "complete":
            current_packet_status = packet_statuses[cast(str, current["attempt_id"])]
            if (
                workflow["current_packet_id"] != current["packet_id"]
                or workflow["current_packet_sha256"] != current["packet_sha256"]
                or bytes(workflow["current_packet_document"]) != bytes(current["packet_document"])
                or current_packet_status != ("recovery_verified" if status == "closed" else status)
            ):
                raise RecoveryError("stored-workflow-packet-invalid")
        elif any(
            workflow[key] is not None
            for key in ("current_packet_id", "current_packet_sha256", "current_packet_document")
        ):
            raise RecoveryError("stored-workflow-packet-invalid")

        closures = connection.execute(
            "SELECT * FROM recovery_closures WHERE workflow_id = ?",
            (workflow_id,),
        ).fetchall()
        if status != "closed":
            if closures or closing_events or expected_sequence != len(events) + 1:
                raise RecoveryError("stored-closure-lifecycle-invalid")
            return
        if len(closures) != 1 or len(closing_events) != 1:
            raise RecoveryError("stored-closure-lifecycle-invalid")
        closure = closures[0]
        result = validate_closure_result(cls._decode(closure["result_document"]))
        event = closing_events[0]
        event_details = cast(Mapping[str, Any], event["details"])
        event_actor = cast(Mapping[str, Any], event["actor"])
        if (
            closure["closure_id"] != result["closure_id"]
            or closure["request_sha256"]
            != document_sha256(
                {
                    "schema": "recovery-closure-request/v1",
                    "expected_incident_version": workflow["incident_version"],
                    "expected_workflow_version": result["workflow_version_before"],
                    "expected_packet_id": result["packet_id"],
                    "expected_packet_sha256": result["packet_sha256"],
                    "expected_outcome_id": result["outcome_id"],
                    "expected_outcome_sha256": result["outcome_sha256"],
                    "reason": result["reason"],
                    "idempotency_key": result["idempotency_key"],
                }
            )
            or closure["result_sha256"] != result["closure_sha256"]
            or result["workflow_id"] != workflow_id
            or result["incident_id"] != workflow["incident_id"]
            or result["workflow_version_after"] != workflow["workflow_version"]
            or result["packet_id"] != workflow["current_packet_id"]
            or result["packet_sha256"] != workflow["current_packet_sha256"]
            or result["outcome_id"] != workflow["outcome_id"]
            or result["outcome_sha256"] != workflow["outcome_sha256"]
            or result["idempotency_key"] != closure["idempotency_key"]
            or result["audit_event_id"] != event["event_id"]
            or result["audit_event_sha256"] != event["event_sha256"]
            or result["closed_at"] != event["occurred_at"]
            or result["actor"]
            != {
                key: event_actor[key]
                for key in ("issuer", "subject", "audience", "display_name", "kind")
            }
            or result["authorized_role"] != event_actor.get("authorized_role")
            or event["sequence"] != workflow["workflow_version"]
            or event["sequence"] != expected_sequence
            or event["idempotency_key"] != closure["idempotency_key"]
            or event["packet_id"] != workflow["current_packet_id"]
            or event["packet_sha256"] != workflow["current_packet_sha256"]
            or event_details.get("reason") != result["reason"]
            or event_details.get("workflow_version_before") != result["workflow_version_before"]
            or event_details.get("workflow_version_after") != result["workflow_version_after"]
        ):
            raise RecoveryError("stored-closure-lifecycle-invalid")
        if expected_sequence + 1 != len(events) + 1:
            raise RecoveryError("stored-closure-lifecycle-invalid")

    @classmethod
    def _validate_all_audit_histories(
        cls,
        connection: sqlite3.Connection,
        *,
        allow_legacy_renewal: bool = False,
    ) -> None:
        workflows = connection.execute(
            "SELECT * FROM recovery_workflows ORDER BY workflow_id"
        ).fetchall()
        workflow_ids = {cast(str, workflow["workflow_id"]) for workflow in workflows}
        head_ids = {
            cast(str, row["workflow_id"])
            for row in connection.execute("SELECT workflow_id FROM recovery_audit_heads")
        }
        event_ids = {
            cast(str, row["workflow_id"])
            for row in connection.execute("SELECT DISTINCT workflow_id FROM recovery_audit_events")
        }
        if head_ids != workflow_ids or event_ids != workflow_ids:
            raise RecoveryError("stored-audit-orphan-invalid")
        for workflow in workflows:
            cls._validated_audit_history(
                connection,
                workflow,
                allow_legacy_renewal=allow_legacy_renewal,
            )

    @classmethod
    def _capture_v2_claim_lease_baselines(cls, connection: sqlite3.Connection) -> None:
        attempts = connection.execute(
            "SELECT attempt_id, workflow_id, status FROM recovery_attempts "
            "WHERE status IN ('running', 'complete')"
        ).fetchall()
        for attempt in attempts:
            rows = connection.execute(
                "SELECT document FROM recovery_audit_events WHERE workflow_id = ? "
                "ORDER BY sequence",
                (attempt["workflow_id"],),
            ).fetchall()
            transitions: list[dict[str, Any]] = []
            for row in rows:
                event = cls._decode(row["document"])
                details = cast(Mapping[str, Any], event["details"])
                if (
                    event["event_type"] in {"verification.claimed", "verification.reclaimed"}
                    and details.get("attempt_id") == attempt["attempt_id"]
                ):
                    transitions.append(event)
            if not transitions:
                raise RecoveryError("stored-claim-lifecycle-invalid")
            latest = transitions[-1]
            row = connection.execute(
                "SELECT claim_generation, claim_owner, claim_expires_at, updated_at "
                "FROM recovery_attempts WHERE attempt_id = ?",
                (attempt["attempt_id"],),
            ).fetchone()
            if row is None:
                raise RecoveryError("stored-attempt-lifecycle-invalid")
            after_sequence = (
                cast(int, latest["sequence"])
                if attempt["status"] == "running"
                else cast(
                    int,
                    next(
                        event["sequence"]
                        for event in (cls._decode(value["document"]) for value in rows)
                        if event["event_type"] == "verification.completed"
                        and cast(Mapping[str, Any], event["details"]).get("attempt_id")
                        == attempt["attempt_id"]
                    ),
                )
            )
            connection.execute(
                "INSERT INTO recovery_claim_lease_baselines("
                "attempt_id, after_sequence, attempt_status, claim_generation, claim_owner, "
                "lease_expires_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    attempt["attempt_id"],
                    after_sequence,
                    attempt["status"],
                    row["claim_generation"],
                    row["claim_owner"],
                    row["claim_expires_at"],
                    row["updated_at"],
                ),
            )

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        *,
        workflow: sqlite3.Row,
        event_type: str,
        actor: Mapping[str, Any],
        idempotency_key: str,
        occurred_at: str,
        packet: Mapping[str, Any] | None,
        details: Mapping[str, Any],
    ) -> dict[str, Any]:
        head = connection.execute(
            "SELECT sequence, event_sha256 FROM recovery_audit_heads WHERE workflow_id = ?",
            (workflow["workflow_id"],),
        ).fetchone()
        sequence = 1 if head is None else cast(int, head["sequence"]) + 1
        predecessor = None if head is None else cast(str, head["event_sha256"])
        snapshot = self._decode(workflow["snapshot_document"])
        outcome = cast(Mapping[str, Any], snapshot["action_outcome"])
        event = build_audit_event(
            incident_id=cast(str, workflow["incident_id"]),
            workflow_id=cast(str, workflow["workflow_id"]),
            sequence=sequence,
            event_type=event_type,
            actor=actor,
            snapshot_id=cast(str, workflow["snapshot_id"]),
            snapshot_sha256=cast(str, workflow["snapshot_sha256"]),
            outcome_id=cast(str, workflow["outcome_id"]),
            outcome_sha256=cast(str, workflow["outcome_sha256"]),
            packet_id=None if packet is None else cast(str, packet["packet_id"]),
            packet_sha256=None if packet is None else cast(str, packet["packet_sha256"]),
            idempotency_key=idempotency_key,
            predecessor_event_sha256=predecessor,
            occurred_at=occurred_at,
            details={**dict(details), "action_id": outcome["action_id"]},
        )
        connection.execute(
            "INSERT INTO recovery_audit_events(workflow_id, sequence, event_sha256, document) "
            "VALUES(?, ?, ?, ?)",
            (
                workflow["workflow_id"],
                sequence,
                event["event_sha256"],
                canonical_json_bytes(event),
            ),
        )
        if head is None:
            connection.execute(
                "INSERT INTO recovery_audit_heads(workflow_id, sequence, event_sha256) "
                "VALUES(?, ?, ?)",
                (workflow["workflow_id"], sequence, event["event_sha256"]),
            )
        else:
            connection.execute(
                "UPDATE recovery_audit_heads SET sequence = ?, event_sha256 = ? "
                "WHERE workflow_id = ?",
                (sequence, event["event_sha256"], workflow["workflow_id"]),
            )
        return event

    def register_verification(
        self,
        snapshot_value: Mapping[str, Any],
        request_value: Mapping[str, Any],
        *,
        actor: Mapping[str, Any],
        idempotency_key: str,
        now: str,
    ) -> VerificationAttempt:
        snapshot = validate_verification_snapshot(snapshot_value)
        request = validate_evidence_request(request_value, snapshot=snapshot)
        require_idempotency_key(idempotency_key)
        occurred_at = timestamp(parse_timestamp(now))
        request_identity_sha256 = document_sha256(
            {
                "schema": "recovery-verification-registration/v1",
                "snapshot_sha256": snapshot["snapshot_sha256"],
                "request_sha256": request["request_sha256"],
            }
        )
        workflow_id = self._workflow_id(snapshot)
        outcome = cast(Mapping[str, Any], snapshot["action_outcome"])
        with self.transaction(write=True) as connection:
            replay = connection.execute(
                "SELECT * FROM recovery_attempts WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if replay is not None:
                if replay["request_identity_sha256"] != request_identity_sha256:
                    raise RecoveryError("idempotency-conflict")
                workflow = self._workflow_row(connection, cast(str, replay["workflow_id"]))
                self._validated_audit_history(connection, workflow)
                return self._attempt_from_rows(workflow, replay)

            existing = connection.execute(
                "SELECT * FROM recovery_workflows WHERE workflow_id = ?",
                (workflow_id,),
            ).fetchone()
            if existing is None:
                prior = connection.execute(
                    "SELECT * FROM recovery_workflows WHERE incident_id = ? "
                    "ORDER BY incident_sequence DESC",
                    (snapshot["incident_id"],),
                ).fetchall()
                for prior_workflow in prior:
                    self._validated_audit_history(connection, prior_workflow)
                active = [
                    row for row in prior if row["status"] not in {"recovery_failed", "closed"}
                ]
                if active:
                    raise RecoveryError("active-recovery-workflow-conflict")
                incident_sequence = 1 if not prior else cast(int, prior[0]["incident_sequence"]) + 1
                attempt_number = 1
                workflow_version = 1
                attempt_id = self._attempt_id(
                    workflow_id,
                    attempt_number,
                    cast(str, request["request_sha256"]),
                )
                connection.execute(
                    "INSERT INTO recovery_workflows("
                    "workflow_id, incident_id, incident_sequence, incident_version, "
                    "snapshot_id, snapshot_sha256, snapshot_document, outcome_id, outcome_sha256, "
                    "status, workflow_version, current_attempt_number, created_at, updated_at) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'verification_pending', ?, ?, ?, ?)",
                    (
                        workflow_id,
                        snapshot["incident_id"],
                        incident_sequence,
                        snapshot["incident_version"],
                        snapshot["snapshot_id"],
                        snapshot["snapshot_sha256"],
                        canonical_json_bytes(snapshot),
                        outcome["outcome_id"],
                        outcome["outcome_sha256"],
                        workflow_version,
                        attempt_number,
                        occurred_at,
                        occurred_at,
                    ),
                )
                workflow = self._workflow_row(connection, workflow_id)
            else:
                workflow = existing
                self._validated_audit_history(connection, workflow)
                if (
                    workflow["workflow_id"] != workflow_id
                    or workflow["snapshot_sha256"] != snapshot["snapshot_sha256"]
                    or workflow["outcome_sha256"] != outcome["outcome_sha256"]
                ):
                    raise RecoveryError("recovery-workflow-conflict")
                if workflow["status"] != "recovery_unresolved":
                    raise RecoveryError("verification-retry-not-allowed")
                if parse_timestamp(occurred_at) < parse_timestamp(workflow["updated_at"]):
                    raise RecoveryError("workflow-clock-regression")
                attempt_number = cast(int, workflow["current_attempt_number"]) + 1
                workflow_version = cast(int, workflow["workflow_version"]) + 1
                attempt_id = self._attempt_id(
                    workflow_id,
                    attempt_number,
                    cast(str, request["request_sha256"]),
                )
                connection.execute(
                    "UPDATE recovery_workflows SET status = 'verification_pending', "
                    "workflow_version = ?, current_attempt_number = ?, "
                    "current_packet_id = NULL, current_packet_sha256 = NULL, "
                    "current_packet_document = NULL, updated_at = ? "
                    "WHERE workflow_id = ? AND status = 'recovery_unresolved'",
                    (workflow_version, attempt_number, occurred_at, workflow_id),
                )
                workflow = self._workflow_row(connection, workflow_id)
            connection.execute(
                "INSERT INTO recovery_attempts("
                "attempt_id, workflow_id, attempt_number, workflow_version, "
                "request_id, request_sha256, "
                "request_document, idempotency_key, request_identity_sha256, status, "
                "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    attempt_id,
                    workflow_id,
                    attempt_number,
                    workflow_version,
                    request["request_id"],
                    request["request_sha256"],
                    canonical_json_bytes(request),
                    idempotency_key,
                    request_identity_sha256,
                    occurred_at,
                    occurred_at,
                ),
            )
            self._append_audit(
                connection,
                workflow=workflow,
                event_type="verification.requested",
                actor=actor,
                idempotency_key=idempotency_key,
                occurred_at=occurred_at,
                packet=None,
                details={"attempt_id": attempt_id, "attempt_number": attempt_number},
            )
            attempt = self._current_attempt_row(connection, workflow)
            return self._attempt_from_rows(workflow, attempt)

    def claim_verification(
        self,
        workflow_id: str,
        *,
        owner: str,
        actor: Mapping[str, Any],
        now: str,
    ) -> VerificationClaim:
        require_identifier(workflow_id, code="recovery-workflow-invalid")
        require_identifier(owner, code="claim-owner-invalid")
        now_value = timestamp(parse_timestamp(now))
        expires_at = timestamp(parse_timestamp(now_value) + timedelta(seconds=CLAIM_LEASE_SECONDS))
        with self.transaction(write=True) as connection:
            workflow = self._workflow_row(connection, workflow_id)
            self._validated_audit_history(connection, workflow)
            attempt = self._current_attempt_row(connection, workflow)
            if parse_timestamp(now_value) < parse_timestamp(attempt["updated_at"]):
                raise RecoveryError("claim-clock-regression")
            event_type: str
            if workflow["status"] == "verification_pending" and attempt["status"] == "pending":
                generation = 1
                event_type = "verification.claimed"
            elif workflow["status"] == "verification_running" and attempt["status"] == "running":
                expiry = parse_timestamp(attempt["claim_expires_at"])
                if parse_timestamp(now_value) < expiry:
                    raise RecoveryError("verification-in-progress")
                generation = cast(int, attempt["claim_generation"]) + 1
                event_type = "verification.reclaimed"
            else:
                raise RecoveryError("verification-not-claimable")
            workflow_version = cast(int, workflow["workflow_version"]) + 1
            connection.execute(
                "UPDATE recovery_attempts SET status = 'running', claim_owner = ?, "
                "claim_generation = ?, claim_expires_at = ?, updated_at = ? WHERE attempt_id = ?",
                (owner, generation, expires_at, now_value, attempt["attempt_id"]),
            )
            connection.execute(
                "UPDATE recovery_workflows SET status = 'verification_running', "
                "workflow_version = ?, "
                "updated_at = ? WHERE workflow_id = ?",
                (workflow_version, now_value, workflow_id),
            )
            workflow = self._workflow_row(connection, workflow_id)
            self._append_audit(
                connection,
                workflow=workflow,
                event_type=event_type,
                actor=actor,
                idempotency_key=cast(str, attempt["idempotency_key"]),
                occurred_at=now_value,
                packet=None,
                details={
                    "attempt_id": attempt["attempt_id"],
                    "claim_owner": owner,
                    "claim_generation": generation,
                    "lease_expires_at": expires_at,
                },
            )
            return VerificationClaim(
                workflow_id=workflow_id,
                incident_id=cast(str, workflow["incident_id"]),
                incident_version=cast(int, workflow["incident_version"]),
                workflow_version=workflow_version,
                attempt_id=cast(str, attempt["attempt_id"]),
                attempt_number=cast(int, attempt["attempt_number"]),
                owner=owner,
                generation=generation,
                lease_expires_at=expires_at,
                snapshot=self._decode(workflow["snapshot_document"]),
                evidence_request=self._decode(attempt["request_document"]),
            )

    def renew_claim(
        self,
        claim: VerificationClaim,
        *,
        actor: Mapping[str, Any],
        now: str,
    ) -> VerificationClaim:
        now_value = timestamp(parse_timestamp(now))
        expires_at = timestamp(parse_timestamp(now_value) + timedelta(seconds=CLAIM_LEASE_SECONDS))
        if parse_timestamp(expires_at) <= parse_timestamp(claim.lease_expires_at):
            raise RecoveryError("claim-clock-regression")
        with self.transaction(write=True) as connection:
            workflow = self._workflow_row(connection, claim.workflow_id)
            self._validated_audit_history(connection, workflow)
            attempt = self._current_attempt_row(connection, workflow)
            if (
                workflow["status"] != "verification_running"
                or workflow["workflow_version"] != claim.workflow_version
                or attempt["attempt_id"] != claim.attempt_id
                or attempt["status"] != "running"
                or attempt["claim_owner"] != claim.owner
                or attempt["claim_generation"] != claim.generation
                or attempt["claim_expires_at"] != claim.lease_expires_at
                or parse_timestamp(now_value) >= parse_timestamp(claim.lease_expires_at)
            ):
                raise RecoveryError("claim-fenced")
            next_version = claim.workflow_version + 1
            connection.execute(
                "UPDATE recovery_attempts SET claim_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (expires_at, now_value, claim.attempt_id),
            )
            connection.execute(
                "UPDATE recovery_workflows SET workflow_version = ?, updated_at = ? "
                "WHERE workflow_id = ? AND status = 'verification_running'",
                (next_version, now_value, claim.workflow_id),
            )
            workflow = self._workflow_row(connection, claim.workflow_id)
            self._append_audit(
                connection,
                workflow=workflow,
                event_type="verification.renewed",
                actor=actor,
                idempotency_key=cast(str, attempt["idempotency_key"]),
                occurred_at=now_value,
                packet=None,
                details={
                    "attempt_id": claim.attempt_id,
                    "claim_owner": claim.owner,
                    "claim_generation": claim.generation,
                    "lease_expires_before": claim.lease_expires_at,
                    "lease_expires_at": expires_at,
                },
            )
            return VerificationClaim(
                workflow_id=claim.workflow_id,
                incident_id=claim.incident_id,
                incident_version=claim.incident_version,
                workflow_version=next_version,
                attempt_id=claim.attempt_id,
                attempt_number=claim.attempt_number,
                owner=claim.owner,
                generation=claim.generation,
                lease_expires_at=expires_at,
                snapshot=claim.snapshot,
                evidence_request=claim.evidence_request,
            )

    def complete_verification(
        self,
        claim: VerificationClaim,
        packet_value: Mapping[str, Any],
        *,
        evidence_records: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]],
        actor: Mapping[str, Any],
        now: str,
    ) -> dict[str, Any]:
        packet = validate_recovery_packet(
            packet_value,
            snapshot=claim.snapshot,
            evidence_request=claim.evidence_request,
        )
        records = [validate_evidence_record(value) for value in evidence_records]
        record_ids = [cast(str, value["evidence_id"]) for value in records]
        if len(record_ids) != len(set(record_ids)):
            raise RecoveryError("evidence-citation-duplicate")
        packet_evidence_ids = cast(list[str], packet["evidence_ids"])
        if set(record_ids) != set(packet_evidence_ids):
            raise RecoveryError("evidence-citation-unresolved")
        snapshot = validate_verification_snapshot(claim.snapshot)
        artifact_ids = {
            cast(str, value["artifact_id"])
            for value in cast(list[Mapping[str, Any]], snapshot["verification_artifacts"])
        }
        cited_artifact_ids = {
            artifact_id
            for check in cast(list[Mapping[str, Any]], packet["check_results"])
            for artifact_id in cast(list[str], check["artifact_ids"])
        }
        if not cited_artifact_ids.issubset(artifact_ids):
            raise RecoveryError("artifact-citation-unresolved")
        request_start = parse_timestamp(claim.evidence_request["evaluation_started_at"])
        packet_end = parse_timestamp(packet["evaluation_completed_at"])
        telemetry_state, telemetry_reasons, _ = assess_post_action_observations(
            snapshot,
            records,
            evaluation_started_at=request_start,
            evaluation_completed_at=packet_end,
        )
        telemetry_check = next(
            value
            for value in cast(list[Mapping[str, Any]], packet["check_results"])
            if value["check"] == "post-action-telemetry-correlation"
        )
        if (
            telemetry_check["state"] != telemetry_state
            or tuple(cast(list[str], telemetry_check["reason_codes"])) != telemetry_reasons
        ):
            raise RecoveryError("telemetry-check-binding-invalid")
        now_value = timestamp(parse_timestamp(now))
        with self.transaction(write=True) as connection:
            workflow = self._workflow_row(connection, claim.workflow_id)
            self._validated_audit_history(connection, workflow)
            claimed_attempt = cast(
                sqlite3.Row | None,
                connection.execute(
                    "SELECT * FROM recovery_attempts WHERE workflow_id = ? AND attempt_id = ?",
                    (claim.workflow_id, claim.attempt_id),
                ).fetchone(),
            )
            if claimed_attempt is None:
                raise RecoveryError("claim-fenced")
            if claimed_attempt["status"] == "complete":
                stored = self._decode(claimed_attempt["packet_document"])
                stored_rows = connection.execute(
                    "SELECT document FROM recovery_evidence_records WHERE attempt_id = ? "
                    "ORDER BY sequence",
                    (claim.attempt_id,),
                ).fetchall()
                stored_records = [self._decode(row["document"]) for row in stored_rows]
                if canonical_json_bytes(stored) != canonical_json_bytes(
                    packet
                ) or canonical_json_bytes(stored_records) != canonical_json_bytes(records):
                    raise RecoveryError("verification-completion-conflict")
                return stored
            attempt = self._current_attempt_row(connection, workflow)
            if parse_timestamp(now_value) < parse_timestamp(attempt["updated_at"]):
                raise RecoveryError("claim-clock-regression")
            if (
                workflow["status"] != "verification_running"
                or workflow["workflow_version"] != claim.workflow_version
                or attempt["attempt_id"] != claim.attempt_id
                or attempt["status"] != "running"
                or attempt["claim_owner"] != claim.owner
                or attempt["claim_generation"] != claim.generation
                or attempt["claim_expires_at"] != claim.lease_expires_at
                or (
                    parse_timestamp(now_value) >= parse_timestamp(claim.lease_expires_at)
                    and packet["status"] != "recovery_unresolved"
                )
            ):
                raise RecoveryError("claim-fenced")
            next_version = claim.workflow_version + 1
            if (
                packet["workflow_id"] != claim.workflow_id
                or packet["workflow_version"] != next_version
                or packet["attempt_id"] != claim.attempt_id
                or packet["attempt_number"] != claim.attempt_number
            ):
                raise RecoveryError("packet-workflow-binding-invalid")
            encoded = canonical_json_bytes(packet)
            for sequence, record in enumerate(records, start=1):
                connection.execute(
                    "INSERT INTO recovery_evidence_records(evidence_id, workflow_id, attempt_id, "
                    "sequence, evidence_sha256, document) VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        record["evidence_id"],
                        claim.workflow_id,
                        claim.attempt_id,
                        sequence,
                        record["evidence_sha256"],
                        canonical_json_bytes(record),
                    ),
                )
            connection.execute(
                "UPDATE recovery_attempts SET status = 'complete', packet_id = ?, "
                "packet_sha256 = ?, "
                "packet_document = ?, updated_at = ? WHERE attempt_id = ?",
                (
                    packet["packet_id"],
                    packet["packet_sha256"],
                    encoded,
                    now_value,
                    claim.attempt_id,
                ),
            )
            connection.execute(
                "UPDATE recovery_workflows SET status = ?, workflow_version = ?, "
                "current_packet_id = ?, "
                "current_packet_sha256 = ?, current_packet_document = ?, updated_at = ? "
                "WHERE workflow_id = ?",
                (
                    packet["status"],
                    next_version,
                    packet["packet_id"],
                    packet["packet_sha256"],
                    encoded,
                    now_value,
                    claim.workflow_id,
                ),
            )
            workflow = self._workflow_row(connection, claim.workflow_id)
            self._append_audit(
                connection,
                workflow=workflow,
                event_type="verification.completed",
                actor=actor,
                idempotency_key=cast(str, attempt["idempotency_key"]),
                occurred_at=now_value,
                packet=packet,
                details={
                    "attempt_id": claim.attempt_id,
                    "claim_owner": claim.owner,
                    "claim_generation": claim.generation,
                    "status": packet["status"],
                },
            )
            return packet

    def close_workflow(
        self,
        workflow_id: str,
        request_value: Mapping[str, Any],
        *,
        actor: Mapping[str, Any],
        now: str,
    ) -> dict[str, Any]:
        request = validate_closure_request(request_value)
        now_value = timestamp(parse_timestamp(now))
        request_sha256 = document_sha256(request)
        idempotency_key = cast(str, request["idempotency_key"])
        with self.transaction(write=True) as connection:
            replay = connection.execute(
                "SELECT workflow_id, request_sha256, result_document FROM recovery_closures "
                "WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            if replay is not None:
                if (
                    replay["workflow_id"] != workflow_id
                    or replay["request_sha256"] != request_sha256
                ):
                    raise RecoveryError("idempotency-conflict")
                replay_workflow = self._workflow_row(
                    connection,
                    cast(str, replay["workflow_id"]),
                )
                self._validated_audit_history(connection, replay_workflow)
                return validate_closure_result(self._decode(replay["result_document"]))
            workflow = self._workflow_row(connection, workflow_id)
            self._validated_audit_history(connection, workflow)
            if parse_timestamp(now_value) < parse_timestamp(workflow["updated_at"]):
                raise RecoveryError("workflow-clock-regression")
            if workflow["status"] != "recovery_verified":
                raise RecoveryError("recovery-not-verified")
            packet = self._decode(workflow["current_packet_document"])
            validate_recovery_packet(packet, snapshot=self._decode(workflow["snapshot_document"]))
            if packet["eligible_for_closure"] is not True:
                raise RecoveryError("recovery-not-verified")
            if (
                request["expected_incident_version"] != workflow["incident_version"]
                or request["expected_workflow_version"] != workflow["workflow_version"]
                or request["expected_packet_id"] != workflow["current_packet_id"]
                or request["expected_packet_sha256"] != workflow["current_packet_sha256"]
                or request["expected_outcome_id"] != workflow["outcome_id"]
                or request["expected_outcome_sha256"] != workflow["outcome_sha256"]
            ):
                raise RecoveryError("closure-expected-version-conflict")
            if actor.get("kind") != "human" or actor.get("authorized_role") != "recovery.closer":
                raise RecoveryError("closure-human-required")
            next_version = cast(int, workflow["workflow_version"]) + 1
            event = self._append_audit(
                connection,
                workflow=workflow,
                event_type="recovery.closed",
                actor=actor,
                idempotency_key=idempotency_key,
                occurred_at=now_value,
                packet=packet,
                details={
                    "reason": request["reason"],
                    "workflow_version_before": workflow["workflow_version"],
                    "workflow_version_after": next_version,
                },
            )
            result_actor = {
                key: actor[key] for key in ("issuer", "subject", "audience", "display_name", "kind")
            }
            body = {
                "schema": "recovery-closure-result/v1",
                "incident_id": workflow["incident_id"],
                "workflow_id": workflow_id,
                "workflow_version_before": workflow["workflow_version"],
                "workflow_version_after": next_version,
                "packet_id": packet["packet_id"],
                "packet_sha256": packet["packet_sha256"],
                "outcome_id": workflow["outcome_id"],
                "outcome_sha256": workflow["outcome_sha256"],
                "actor": result_actor,
                "authorized_role": "recovery.closer",
                "reason": request["reason"],
                "closed_at": now_value,
                "idempotency_key": idempotency_key,
                "audit_event_id": event["event_id"],
                "audit_event_sha256": event["event_sha256"],
            }
            digest = document_sha256(body)
            result = validate_closure_result(
                {
                    **body,
                    "closure_id": f"recovery-closure:{digest.removeprefix('sha256:')}",
                    "closure_sha256": digest,
                }
            )
            connection.execute(
                "UPDATE recovery_workflows SET status = 'closed', workflow_version = ?, "
                "updated_at = ? "
                "WHERE workflow_id = ? AND status = 'recovery_verified'",
                (next_version, now_value, workflow_id),
            )
            connection.execute(
                "INSERT INTO recovery_closures(closure_id, workflow_id, idempotency_key, "
                "request_sha256, result_sha256, result_document) VALUES(?, ?, ?, ?, ?, ?)",
                (
                    result["closure_id"],
                    workflow_id,
                    idempotency_key,
                    request_sha256,
                    result["closure_sha256"],
                    canonical_json_bytes(result),
                ),
            )
            return result

    def review(self, workflow_id: str) -> dict[str, Any]:
        require_identifier(workflow_id, code="recovery-workflow-invalid")
        with self.transaction(write=False) as connection:
            workflow = self._workflow_row(connection, workflow_id)
            self._validated_audit_history(connection, workflow)
            attempt = self._current_attempt_row(connection, workflow)
            packet = (
                None
                if workflow["current_packet_document"] is None
                else self._decode(workflow["current_packet_document"])
            )
            return {
                "schema": "recovery-review/v1",
                "incident_id": workflow["incident_id"],
                "incident_version": workflow["incident_version"],
                "workflow_id": workflow["workflow_id"],
                "workflow_version": workflow["workflow_version"],
                "status": workflow["status"],
                "snapshot_id": workflow["snapshot_id"],
                "snapshot_sha256": workflow["snapshot_sha256"],
                "outcome_id": workflow["outcome_id"],
                "outcome_sha256": workflow["outcome_sha256"],
                "current_attempt_id": attempt["attempt_id"],
                "current_attempt_number": workflow["current_attempt_number"],
                "current_packet": packet,
            }

    def durable_aggregate(self, workflow_id: str) -> dict[str, Any]:
        """Return the integrity-checked internal aggregate used by API projection."""

        require_identifier(workflow_id, code="recovery-workflow-invalid")
        with self.transaction(write=False) as connection:
            workflow = self._workflow_row(connection, workflow_id)
            audit = self._validated_audit_history(connection, workflow)
            attempt = self._current_attempt_row(connection, workflow)
            snapshot = validate_verification_snapshot(self._decode(workflow["snapshot_document"]))
            request = validate_evidence_request(
                self._decode(attempt["request_document"]),
                snapshot=snapshot,
            )
            evidence_rows = connection.execute(
                "SELECT document FROM recovery_evidence_records WHERE attempt_id = ? "
                "ORDER BY sequence",
                (attempt["attempt_id"],),
            ).fetchall()
            evidence = [
                validate_evidence_record(self._decode(row["document"])) for row in evidence_rows
            ]
            packet = None
            if workflow["current_packet_document"] is not None:
                packet = validate_recovery_packet(
                    self._decode(workflow["current_packet_document"]),
                    snapshot=snapshot,
                    evidence_request=request,
                )
                packet_evidence = cast(list[str], packet["evidence_ids"])
                record_ids = [cast(str, value["evidence_id"]) for value in evidence]
                duplicate_records = len(record_ids) != len(set(record_ids))
                citation_mismatch = set(record_ids) != set(packet_evidence)
                if duplicate_records or citation_mismatch:
                    raise RecoveryError("stored-evidence-citation-invalid")
                artifact_ids = {
                    cast(str, value["artifact_id"])
                    for value in cast(list[Mapping[str, Any]], snapshot["verification_artifacts"])
                }
                cited = {
                    artifact_id
                    for check in cast(list[Mapping[str, Any]], packet["check_results"])
                    for artifact_id in cast(list[str], check["artifact_ids"])
                }
                if not cited.issubset(artifact_ids):
                    raise RecoveryError("stored-artifact-citation-invalid")
            closure_row = connection.execute(
                "SELECT result_document FROM recovery_closures WHERE workflow_id = ?",
                (workflow_id,),
            ).fetchone()
            closure = (
                None
                if closure_row is None
                else validate_closure_result(self._decode(closure_row["result_document"]))
            )
            return {
                "schema": "recovery-durable-aggregate/v1",
                "review": {
                    "schema": "recovery-review/v1",
                    "incident_id": workflow["incident_id"],
                    "incident_version": workflow["incident_version"],
                    "workflow_id": workflow["workflow_id"],
                    "workflow_version": workflow["workflow_version"],
                    "status": workflow["status"],
                    "snapshot_id": workflow["snapshot_id"],
                    "snapshot_sha256": workflow["snapshot_sha256"],
                    "outcome_id": workflow["outcome_id"],
                    "outcome_sha256": workflow["outcome_sha256"],
                    "current_attempt_id": attempt["attempt_id"],
                    "current_attempt_number": workflow["current_attempt_number"],
                    "current_packet": packet,
                },
                "snapshot": snapshot,
                "evidence_request": request,
                "evidence": evidence,
                "packet": packet,
                "closure": closure,
                "audit_events": audit,
            }

    def durable_aggregate_for_incident(self, incident_id: str) -> dict[str, Any]:
        require_identifier(incident_id, code="incident-invalid")
        with self.transaction(write=False) as connection:
            rows = connection.execute(
                "SELECT workflow_id, status, incident_sequence FROM recovery_workflows "
                "WHERE incident_id = ? ORDER BY incident_sequence DESC",
                (incident_id,),
            ).fetchall()
            if not rows:
                raise RecoveryError("recovery-workflow-not-found")
            active = [row for row in rows if row["status"] not in {"recovery_failed", "closed"}]
            if len(active) > 1:
                raise RecoveryError("recovery-workflow-ambiguous")
            selected = active[0] if active else rows[0]
            workflow_id = cast(str, selected["workflow_id"])
        return self.durable_aggregate(workflow_id)

    def verification_packet_for_idempotency(
        self,
        incident_id: str,
        idempotency_key: str,
        expected_outcome_sha256: str,
    ) -> dict[str, Any] | None:
        """Return the integrity-checked historical packet for one exact trigger key."""

        require_identifier(incident_id, code="incident-invalid")
        require_idempotency_key(idempotency_key)
        require_digest(expected_outcome_sha256, code="expected-outcome-digest-invalid")
        with self.transaction(write=False) as connection:
            attempt = cast(
                sqlite3.Row | None,
                connection.execute(
                    "SELECT * FROM recovery_attempts WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone(),
            )
            if attempt is None:
                return None
            workflow = self._workflow_row(connection, cast(str, attempt["workflow_id"]))
            self._validated_audit_history(connection, workflow)
            if (
                workflow["incident_id"] != incident_id
                or workflow["outcome_sha256"] != expected_outcome_sha256
            ):
                raise RecoveryError("idempotency-conflict")
            if attempt["status"] != "complete":
                return None
            snapshot = validate_verification_snapshot(self._decode(workflow["snapshot_document"]))
            request = validate_evidence_request(
                self._decode(attempt["request_document"]),
                snapshot=snapshot,
            )
            packet = validate_recovery_packet(
                self._decode(attempt["packet_document"]),
                snapshot=snapshot,
                evidence_request=request,
            )
            if (
                packet["workflow_id"] != workflow["workflow_id"]
                or packet["attempt_id"] != attempt["attempt_id"]
                or packet["attempt_number"] != attempt["attempt_number"]
            ):
                raise RecoveryError("stored-recovery-packet-invalid")
            rows = connection.execute(
                "SELECT document FROM recovery_evidence_records WHERE attempt_id = ? "
                "ORDER BY sequence",
                (attempt["attempt_id"],),
            ).fetchall()
            records = [validate_evidence_record(self._decode(row["document"])) for row in rows]
            record_ids = [cast(str, value["evidence_id"]) for value in records]
            if len(record_ids) != len(set(record_ids)) or set(record_ids) != set(
                cast(list[str], packet["evidence_ids"])
            ):
                raise RecoveryError("stored-evidence-citation-invalid")
            artifact_ids = {
                cast(str, value["artifact_id"])
                for value in cast(list[Mapping[str, Any]], snapshot["verification_artifacts"])
            }
            cited = {
                artifact_id
                for check in cast(list[Mapping[str, Any]], packet["check_results"])
                for artifact_id in cast(list[str], check["artifact_ids"])
            }
            if not cited.issubset(artifact_ids):
                raise RecoveryError("stored-artifact-citation-invalid")
            return packet

    def audit_history(self, workflow_id: str) -> list[dict[str, Any]]:
        require_identifier(workflow_id, code="recovery-workflow-invalid")
        with self.transaction(write=False) as connection:
            workflow = self._workflow_row(connection, workflow_id)
            return self._validated_audit_history(connection, workflow)


__all__ = [
    "CLAIM_LEASE_SECONDS",
    "SQLiteRecoveryRepository",
    "VerificationAttempt",
    "VerificationClaim",
]
