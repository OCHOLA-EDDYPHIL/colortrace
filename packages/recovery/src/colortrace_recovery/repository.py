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

_APPLICATION_ID = 0x43545259
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
            elif application_id != _APPLICATION_ID or user_version != _SCHEMA_VERSION:
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
        connection.execute(
            "INSERT INTO recovery_audit_heads(workflow_id, sequence, event_sha256) VALUES(?, ?, ?) "
            "ON CONFLICT(workflow_id) DO UPDATE SET sequence = excluded.sequence, "
            "event_sha256 = excluded.event_sha256",
            (workflow["workflow_id"], sequence, event["event_sha256"]),
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
                if (
                    workflow["workflow_id"] != workflow_id
                    or workflow["snapshot_sha256"] != snapshot["snapshot_sha256"]
                    or workflow["outcome_sha256"] != outcome["outcome_sha256"]
                ):
                    raise RecoveryError("recovery-workflow-conflict")
                if workflow["status"] != "recovery_unresolved":
                    raise RecoveryError("verification-retry-not-allowed")
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
            attempt = self._current_attempt_row(connection, workflow)
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

    def renew_claim(self, claim: VerificationClaim, *, now: str) -> VerificationClaim:
        now_value = timestamp(parse_timestamp(now))
        expires_at = timestamp(parse_timestamp(now_value) + timedelta(seconds=CLAIM_LEASE_SECONDS))
        with self.transaction(write=True) as connection:
            workflow = self._workflow_row(connection, claim.workflow_id)
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
            connection.execute(
                "UPDATE recovery_attempts SET claim_expires_at = ?, updated_at = ? "
                "WHERE attempt_id = ?",
                (expires_at, now_value, claim.attempt_id),
            )
            return VerificationClaim(
                workflow_id=claim.workflow_id,
                incident_id=claim.incident_id,
                incident_version=claim.incident_version,
                workflow_version=claim.workflow_version,
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
                return validate_closure_result(self._decode(replay["result_document"]))
            workflow = self._workflow_row(connection, workflow_id)
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
            audit_rows = connection.execute(
                "SELECT document FROM recovery_audit_events WHERE workflow_id = ? "
                "ORDER BY sequence",
                (workflow_id,),
            ).fetchall()
            audit = [self._decode(row["document"]) for row in audit_rows]
            validate_audit_history(audit, workflow_id=workflow_id)
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
            self._workflow_row(connection, workflow_id)
            rows = connection.execute(
                "SELECT document FROM recovery_audit_events WHERE workflow_id = ? "
                "ORDER BY sequence",
                (workflow_id,),
            ).fetchall()
            events = [self._decode(row["document"]) for row in rows]
            validate_audit_history(events, workflow_id=workflow_id)
            return events


__all__ = [
    "CLAIM_LEASE_SECONDS",
    "SQLiteRecoveryRepository",
    "VerificationAttempt",
    "VerificationClaim",
]
