from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from colortrace_investigation import AlertIntake, validate_response_packet
from colortrace_investigation.contracts import parse_timestamp
from colortrace_validator import validate_result_contract

from .contracts import (
    REPLAY_SCHEMA,
    STORE_SCHEMA_VERSION,
    SliceContractError,
    alert_digest,
    build_claim_event,
    build_task_envelope,
    build_trace_event,
    canonical_json_bytes,
    claim_expiry,
    finalize_replay,
    normalize_timestamp,
    plain_json,
    prefixed_sha256,
    readonly_mapping,
    require_identifier,
    require_trace_id,
    strict_json_bytes,
    validate_claim_events,
    validate_replay,
)

_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS store_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'resolved', 'unresolved')),
    version INTEGER NOT NULL CHECK (version >= 1),
    alert_sha256 TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    packet_id TEXT,
    alert_json BLOB NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(incident_id),
    expected_incident_version INTEGER NOT NULL CHECK (expected_incident_version >= 1),
    alert_sha256 TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'complete')),
    packet_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    content_sha256 TEXT NOT NULL,
    document_json BLOB NOT NULL,
    UNIQUE (incident_id, sequence)
) STRICT;

CREATE TABLE IF NOT EXISTS evidence_batches (
    batch_sha256 TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(incident_id),
    document_json BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS validator_results (
    result_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    content_sha256 TEXT NOT NULL,
    document_json BLOB NOT NULL,
    UNIQUE (incident_id, sequence)
) STRICT;

CREATE TABLE IF NOT EXISTS invocations (
    invocation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    content_sha256 TEXT NOT NULL,
    document_json BLOB NOT NULL,
    UNIQUE (incident_id, sequence)
) STRICT;

CREATE TABLE IF NOT EXISTS packets (
    packet_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE REFERENCES incidents(incident_id),
    content_sha256 TEXT NOT NULL,
    document_json BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS trace_events (
    event_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_sha256 TEXT NOT NULL UNIQUE,
    document_json BLOB NOT NULL,
    UNIQUE (incident_id, sequence)
) STRICT;
"""

_CLAIM_EVENTS_SCHEMA_V2 = """
CREATE TABLE claim_events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    generation INTEGER NOT NULL CHECK (generation >= 1),
    event_sha256 TEXT NOT NULL UNIQUE,
    document_json BLOB NOT NULL,
    UNIQUE (task_id, sequence)
) STRICT
"""

_MIGRATED_CLAIM_OWNER = "migration:v1"


@dataclass(frozen=True, slots=True)
class WorkItem:
    task_id: str
    incident_id: str
    expected_incident_version: int
    alert_sha256: str
    trace_id: str
    claim_owner: str
    claim_generation: int
    claim_expires_at: str
    alert: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class AcceptedIncident:
    incident_id: str
    task_id: str
    status: str
    version: int
    trace_id: str
    duplicate: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "incident-accepted/v1",
            "incident_id": self.incident_id,
            "task_id": self.task_id,
            "status": self.status,
            "version": self.version,
            "trace_id": self.trace_id,
            "duplicate": self.duplicate,
        }


class SqliteIncidentStore:
    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().absolute()
        self._initialize()

    def _validate_database_file(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as error:
            raise SliceContractError("store-unavailable") from error
        if (
            not stat.S_ISREG(info.st_mode)
            or self.path.is_symlink()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise SliceContractError("store-file-invalid")

    def _initialize(self) -> None:
        try:
            parent = self.path.parent.resolve(strict=True)
        except OSError as error:
            raise SliceContractError("store-parent-invalid") from error
        if not parent.is_dir() or self.path.parent.is_symlink() or self.path.parent != parent:
            raise SliceContractError("store-parent-invalid")
        if not self.path.exists():
            try:
                descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            except OSError as error:
                raise SliceContractError("store-unavailable") from error
            else:
                os.close(descriptor)
        self._validate_database_file()
        with self._connection() as connection:
            try:
                connection.executescript(_SCHEMA_V1)
                connection.execute(
                    "INSERT OR IGNORE INTO store_metadata(singleton, schema_version) VALUES(1, 1)"
                )
                self._migrate_schema(connection)
                row = connection.execute(
                    "SELECT schema_version FROM store_metadata WHERE singleton = 1"
                ).fetchone()
            except sqlite3.DatabaseError as error:
                raise SliceContractError("store-schema-invalid") from error
        if row is None or row["schema_version"] != STORE_SCHEMA_VERSION:
            raise SliceContractError("store-schema-drift")
        self._validate_database_file()

    def _migrate_schema(self, connection: sqlite3.Connection) -> None:
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT schema_version FROM store_metadata WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise SliceContractError("store-schema-drift")
            version = cast(int, row["schema_version"])
            if version == 1:
                connection.execute("ALTER TABLE tasks ADD COLUMN claim_owner TEXT")
                connection.execute(
                    "ALTER TABLE tasks ADD COLUMN claim_generation INTEGER NOT NULL "
                    "DEFAULT 0 CHECK (claim_generation >= 0)"
                )
                connection.execute("ALTER TABLE tasks ADD COLUMN claim_expires_at TEXT")
                connection.execute(_CLAIM_EVENTS_SCHEMA_V2)
                running = connection.execute(
                    "SELECT t.task_id, t.incident_id, t.updated_at, "
                    "t.expected_incident_version, i.status AS incident_status, "
                    "i.version AS incident_version "
                    "FROM tasks t JOIN incidents i ON i.incident_id = t.incident_id "
                    "WHERE t.status = 'running'"
                ).fetchall()
                for task in running:
                    if (
                        task["incident_status"] != "running"
                        or task["incident_version"]
                        != cast(int, task["expected_incident_version"]) + 1
                    ):
                        raise SliceContractError("store-schema-drift")
                    occurred_at = normalize_timestamp(
                        task["updated_at"], code="stored-claim-time-invalid"
                    )
                    expires_at = claim_expiry(occurred_at)
                    connection.execute(
                        "UPDATE tasks SET claim_owner = ?, claim_generation = 1, "
                        "claim_expires_at = ? WHERE task_id = ?",
                        (_MIGRATED_CLAIM_OWNER, expires_at, task["task_id"]),
                    )
                    self._append_claim_event(
                        connection,
                        task_id=cast(str, task["task_id"]),
                        incident_id=cast(str, task["incident_id"]),
                        event_type="claim.migrated",
                        owner=_MIGRATED_CLAIM_OWNER,
                        generation=1,
                        lease_expires_at=expires_at,
                        occurred_at=occurred_at,
                    )
                connection.execute(
                    "UPDATE store_metadata SET schema_version = ? WHERE singleton = 1",
                    (STORE_SCHEMA_VERSION,),
                )
            elif version != STORE_SCHEMA_VERSION:
                raise SliceContractError("store-schema-drift")
            self._validate_schema_v2(connection)
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise

    @classmethod
    def _validate_schema_v2(cls, connection: sqlite3.Connection) -> None:
        columns = {
            cast(str, row["name"])
            for row in connection.execute("PRAGMA table_info(tasks)").fetchall()
        }
        if not {"claim_owner", "claim_generation", "claim_expires_at"}.issubset(columns):
            raise SliceContractError("store-schema-drift")
        claim_table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'claim_events'"
        ).fetchone()
        invalid = connection.execute(
            "SELECT count(*) FROM tasks WHERE "
            "(status = 'queued' AND (claim_owner IS NOT NULL OR claim_generation != 0 "
            "OR claim_expires_at IS NOT NULL)) OR "
            "(status = 'running' AND (claim_owner IS NULL OR claim_generation < 1 "
            "OR claim_expires_at IS NULL)) OR "
            "(status = 'complete' AND claim_expires_at IS NOT NULL)"
        ).fetchone()
        if claim_table is None or invalid is None or cast(int, invalid[0]) != 0:
            raise SliceContractError("store-schema-drift")
        tasks = connection.execute("SELECT * FROM tasks ORDER BY task_id").fetchall()
        for task in tasks:
            cls._claim_events_for_task(connection, task)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        self._validate_database_file()
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=5,
                isolation_level=None,
                detect_types=0,
            )
        except sqlite3.Error as error:
            raise SliceContractError("store-unavailable") from error
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.execute("COMMIT")
            except BaseException:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    @staticmethod
    def _decode(document: bytes | memoryview) -> dict[str, Any]:
        raw = bytes(document)
        try:
            value = strict_json_bytes(raw)
        except Exception as error:
            raise SliceContractError("stored-document-invalid") from error
        if not isinstance(value, dict):
            raise SliceContractError("stored-document-invalid")
        return value

    @classmethod
    def _claim_events_for_task(
        cls, connection: sqlite3.Connection, task: sqlite3.Row
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT event_id, task_id, incident_id, sequence, generation, event_sha256, "
            "document_json FROM claim_events WHERE task_id = ? ORDER BY sequence",
            (task["task_id"],),
        ).fetchall()
        events: list[dict[str, Any]] = []
        for sequence, row in enumerate(rows, start=1):
            event = cls._decode(row["document_json"])
            if (
                row["event_id"] != event.get("event_id")
                or row["task_id"] != event.get("task_id")
                or row["incident_id"] != event.get("incident_id")
                or row["sequence"] != sequence
                or row["sequence"] != event.get("sequence")
                or row["generation"] != event.get("generation")
                or row["event_sha256"] != event.get("event_sha256")
            ):
                raise SliceContractError("stored-claim-event-binding")
            events.append(event)
        try:
            validate_claim_events(
                events,
                task_id=cast(str, task["task_id"]),
                incident_id=cast(str, task["incident_id"]),
            )
        except SliceContractError as error:
            raise SliceContractError("stored-claim-event-binding") from error

        generation = cast(int, task["claim_generation"])
        status = cast(str, task["status"])
        owner = task["claim_owner"]
        expires_at = task["claim_expires_at"]
        if generation == 0:
            if events or owner is not None or status == "running":
                raise SliceContractError("stored-claim-state-binding")
            return events
        if not events:
            raise SliceContractError("stored-claim-state-binding")
        last = events[-1]
        if last["generation"] != generation or last["owner"] != owner:
            raise SliceContractError("stored-claim-state-binding")
        if status == "running":
            if last["event_type"] == "claim.completed" or last["lease_expires_at"] != expires_at:
                raise SliceContractError("stored-claim-state-binding")
        elif status == "complete":
            if last["event_type"] != "claim.completed" or expires_at is not None:
                raise SliceContractError("stored-claim-state-binding")
        else:
            raise SliceContractError("stored-claim-state-binding")
        return events

    @staticmethod
    def _incident_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schema": "incident-record/v1",
            "incident_id": row["incident_id"],
            "alert_id": row["alert_id"],
            "status": row["status"],
            "version": row["version"],
            "alert_sha256": row["alert_sha256"],
            "trace_id": row["trace_id"],
            "packet_id": row["packet_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _task_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schema": "incident-task/v1",
            "task_id": row["task_id"],
            "incident_id": row["incident_id"],
            "expected_incident_version": row["expected_incident_version"],
            "alert_sha256": row["alert_sha256"],
            "trace_id": row["trace_id"],
            "status": row["status"],
            "packet_id": row["packet_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _append_event(
        self,
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        event_type: str,
        trace_id: str,
        payload: Mapping[str, Any],
        occurred_at: str,
    ) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence, event_sha256, document_json FROM trace_events "
            "WHERE incident_id = ? ORDER BY sequence DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
        sequence = 1 if previous is None else cast(int, previous["sequence"]) + 1
        predecessor = None if previous is None else cast(str, previous["event_sha256"])
        parent_span = None
        if previous is not None:
            parent_span = cast(str, self._decode(previous["document_json"])["span_id"])
        event = build_trace_event(
            incident_id=incident_id,
            sequence=sequence,
            event_type=event_type,
            trace_id=trace_id,
            parent_span_id=parent_span,
            predecessor_event_sha256=predecessor,
            payload=payload,
            occurred_at=occurred_at,
        )
        connection.execute(
            "INSERT INTO trace_events("
            "event_id, incident_id, sequence, event_sha256, document_json"
            ") "
            "VALUES(?, ?, ?, ?, ?)",
            (
                event["event_id"],
                incident_id,
                sequence,
                event["event_sha256"],
                canonical_json_bytes(event),
            ),
        )
        return event

    def _append_claim_event(
        self,
        connection: sqlite3.Connection,
        *,
        task_id: str,
        incident_id: str,
        event_type: str,
        owner: str,
        generation: int,
        lease_expires_at: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence, event_sha256 FROM claim_events "
            "WHERE task_id = ? ORDER BY sequence DESC LIMIT 1",
            (task_id,),
        ).fetchone()
        sequence = 1 if previous is None else cast(int, previous["sequence"]) + 1
        predecessor = None if previous is None else cast(str, previous["event_sha256"])
        event = build_claim_event(
            task_id=task_id,
            incident_id=incident_id,
            sequence=sequence,
            event_type=event_type,
            owner=owner,
            generation=generation,
            lease_expires_at=lease_expires_at,
            predecessor_event_sha256=predecessor,
            occurred_at=occurred_at,
        )
        connection.execute(
            "INSERT INTO claim_events(event_id, task_id, incident_id, sequence, generation, "
            "event_sha256, document_json) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (
                event["event_id"],
                task_id,
                incident_id,
                sequence,
                generation,
                event["event_sha256"],
                canonical_json_bytes(event),
            ),
        )
        return event

    @staticmethod
    def _work_item(row: sqlite3.Row, alert: Mapping[str, Any]) -> WorkItem:
        owner = row["claim_owner"]
        expires_at = row["claim_expires_at"]
        generation = row["claim_generation"]
        if owner is None or expires_at is None or not isinstance(generation, int) or generation < 1:
            raise SliceContractError("stored-claim-invalid")
        return WorkItem(
            cast(str, row["task_id"]),
            cast(str, row["incident_id"]),
            cast(int, row["expected_incident_version"]),
            cast(str, row["alert_sha256"]),
            cast(str, row["trace_id"]),
            cast(str, owner),
            generation,
            cast(str, expires_at),
            readonly_mapping(alert),
        )

    def accept_alert(self, alert: Mapping[str, Any], *, now: str) -> AcceptedIncident:
        now_value = normalize_timestamp(now)
        try:
            intake = AlertIntake.from_mapping(alert)
            digest = alert_digest(alert)
            task = build_task_envelope(alert, created_at=now_value)
        except Exception as error:
            if isinstance(error, SliceContractError):
                raise
            raise SliceContractError("alert-invalid") from error
        incident_id = intake.incident_id
        trace_id = require_trace_id(intake.correlation_keys["trace_id"])
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            if existing is not None:
                if existing["alert_sha256"] != digest:
                    raise SliceContractError("idempotency-conflict")
                existing_task = connection.execute(
                    "SELECT task_id FROM tasks WHERE incident_id = ?", (incident_id,)
                ).fetchone()
                if existing_task is None:
                    raise SliceContractError("store-integrity")
                return AcceptedIncident(
                    incident_id,
                    cast(str, existing_task["task_id"]),
                    cast(str, existing["status"]),
                    cast(int, existing["version"]),
                    trace_id,
                    True,
                )
            connection.execute(
                "INSERT INTO incidents(incident_id, alert_id, status, version, alert_sha256, "
                "trace_id, packet_id, alert_json, created_at, updated_at) "
                "VALUES(?, ?, 'queued', 1, ?, ?, NULL, ?, ?, ?)",
                (
                    incident_id,
                    intake.alert_id,
                    digest,
                    trace_id,
                    canonical_json_bytes(alert),
                    now_value,
                    now_value,
                ),
            )
            connection.execute(
                "INSERT INTO tasks(task_id, incident_id, expected_incident_version, alert_sha256, "
                "trace_id, status, packet_id, created_at, updated_at) "
                "VALUES(?, ?, ?, ?, ?, 'queued', NULL, ?, ?)",
                (
                    task["task_id"],
                    incident_id,
                    task["expected_incident_version"],
                    digest,
                    trace_id,
                    now_value,
                    now_value,
                ),
            )
            self._append_event(
                connection,
                incident_id=incident_id,
                event_type="api.intake.accepted",
                trace_id=trace_id,
                payload={
                    "alert_id": intake.alert_id,
                    "alert_sha256": digest,
                    "source_predecessor_event_sha256": intake.predecessor_event_sha256,
                },
                occurred_at=now_value,
            )
            self._append_event(
                connection,
                incident_id=incident_id,
                event_type="task.queued",
                trace_id=trace_id,
                payload={
                    "task_id": task["task_id"],
                    "expected_incident_version": task["expected_incident_version"],
                    "payload_sha256": digest,
                },
                occurred_at=now_value,
            )
        return AcceptedIncident(
            incident_id,
            cast(str, task["task_id"]),
            "queued",
            1,
            trace_id,
            False,
        )

    def completed_packet(self, task_id: str) -> dict[str, Any] | None:
        require_identifier(task_id)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT p.document_json, p.content_sha256, "
                "p.packet_id AS stored_packet_id, p.incident_id AS packet_incident_id, "
                "t.packet_id AS task_packet_id, t.incident_id AS task_incident_id "
                "FROM tasks t "
                "LEFT JOIN packets p ON p.packet_id = t.packet_id "
                "WHERE t.task_id = ? AND t.status = 'complete'",
                (task_id,),
            ).fetchone()
        if row is None or row["document_json"] is None:
            return None
        packet = self._decode(row["document_json"])
        if prefixed_sha256(canonical_json_bytes(packet)) != row["content_sha256"]:
            raise SliceContractError("stored-packet-digest")
        validate_response_packet(packet)
        if (
            row["stored_packet_id"] != row["task_packet_id"]
            or row["packet_incident_id"] != row["task_incident_id"]
            or packet.get("packet_id") != row["stored_packet_id"]
            or packet.get("incident_id") != row["packet_incident_id"]
        ):
            raise SliceContractError("stored-packet-binding")
        return packet

    def claim_task(self, task_id: str, *, owner: str, now: str) -> WorkItem:
        require_identifier(task_id)
        owner_value = require_identifier(owner, code="claim-owner-invalid")
        now_value = normalize_timestamp(now, code="claim-time-invalid")
        expires_at = claim_expiry(now_value)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT t.*, i.version AS incident_version, i.status AS incident_status, "
                "i.alert_json FROM tasks t JOIN incidents i ON i.incident_id = t.incident_id "
                "WHERE t.task_id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise SliceContractError("task-not-found")
            if row["status"] == "complete":
                raise SliceContractError("task-complete")
            alert = self._decode(row["alert_json"])
            if alert_digest(alert) != row["alert_sha256"]:
                raise SliceContractError("stored-alert-digest")
            updated_at = normalize_timestamp(row["updated_at"], code="stored-claim-time-invalid")
            if parse_timestamp(now_value) < parse_timestamp(updated_at):
                raise SliceContractError("claim-clock-regression")
            if row["status"] == "queued":
                if (
                    row["incident_status"] != "queued"
                    or row["incident_version"] != row["expected_incident_version"]
                    or row["claim_owner"] is not None
                    or row["claim_generation"] != 0
                    or row["claim_expires_at"] is not None
                ):
                    raise SliceContractError("incident-version-conflict")
                generation = 1
                changed = connection.execute(
                    "UPDATE tasks SET status = 'running', claim_owner = ?, "
                    "claim_generation = ?, claim_expires_at = ?, updated_at = ? "
                    "WHERE task_id = ? AND status = 'queued' AND claim_owner IS NULL "
                    "AND claim_generation = 0 AND claim_expires_at IS NULL",
                    (owner_value, generation, expires_at, now_value, task_id),
                )
                incident_changed = connection.execute(
                    "UPDATE incidents SET status = 'running', version = version + 1, "
                    "updated_at = ? WHERE incident_id = ? AND status = 'queued' AND version = ?",
                    (now_value, row["incident_id"], row["expected_incident_version"]),
                )
                if changed.rowcount != 1 or incident_changed.rowcount != 1:
                    raise SliceContractError("incident-version-conflict")
                self._append_claim_event(
                    connection,
                    task_id=task_id,
                    incident_id=cast(str, row["incident_id"]),
                    event_type="claim.acquired",
                    owner=owner_value,
                    generation=generation,
                    lease_expires_at=expires_at,
                    occurred_at=now_value,
                )
                self._append_event(
                    connection,
                    incident_id=cast(str, row["incident_id"]),
                    event_type="worker.started",
                    trace_id=cast(str, row["trace_id"]),
                    payload={
                        "task_id": task_id,
                        "expected_incident_version": row["expected_incident_version"],
                        "payload_sha256": row["alert_sha256"],
                    },
                    occurred_at=now_value,
                )
            elif row["status"] == "running":
                if (
                    row["incident_status"] != "running"
                    or row["incident_version"] != row["expected_incident_version"] + 1
                    or row["claim_owner"] is None
                    or row["claim_generation"] < 1
                    or row["claim_expires_at"] is None
                ):
                    raise SliceContractError("stored-claim-invalid")
                current_expiry = normalize_timestamp(
                    row["claim_expires_at"], code="stored-claim-time-invalid"
                )
                if parse_timestamp(now_value) < parse_timestamp(current_expiry):
                    raise SliceContractError("task-in-progress")
                generation = cast(int, row["claim_generation"]) + 1
                changed = connection.execute(
                    "UPDATE tasks SET claim_owner = ?, claim_generation = ?, "
                    "claim_expires_at = ?, updated_at = ? WHERE task_id = ? "
                    "AND status = 'running' AND claim_owner = ? AND claim_generation = ? "
                    "AND claim_expires_at = ?",
                    (
                        owner_value,
                        generation,
                        expires_at,
                        now_value,
                        task_id,
                        row["claim_owner"],
                        row["claim_generation"],
                        current_expiry,
                    ),
                )
                if changed.rowcount != 1:
                    raise SliceContractError("claim-fenced")
                self._append_claim_event(
                    connection,
                    task_id=task_id,
                    incident_id=cast(str, row["incident_id"]),
                    event_type="claim.reclaimed",
                    owner=owner_value,
                    generation=generation,
                    lease_expires_at=expires_at,
                    occurred_at=now_value,
                )
            else:
                raise SliceContractError("incident-version-conflict")
            claimed = connection.execute(
                "SELECT t.*, i.version AS incident_version, i.status AS incident_status, "
                "i.alert_json FROM tasks t JOIN incidents i ON i.incident_id = t.incident_id "
                "WHERE t.task_id = ?",
                (task_id,),
            ).fetchone()
            if claimed is None:
                raise SliceContractError("task-not-found")
        return self._work_item(claimed, alert)

    def renew_claim(self, work: WorkItem, *, now: str) -> None:
        now_value = normalize_timestamp(now, code="claim-time-invalid")
        next_expiry = claim_expiry(now_value)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT t.*, i.status AS incident_status, i.version AS incident_version "
                "FROM tasks t JOIN incidents i ON i.incident_id = t.incident_id "
                "WHERE t.task_id = ? AND t.incident_id = ?",
                (work.task_id, work.incident_id),
            ).fetchone()
            if row is None:
                raise SliceContractError("task-not-found")
            if (
                row["status"] != "running"
                or row["incident_status"] != "running"
                or row["incident_version"] != work.expected_incident_version + 1
                or row["claim_owner"] != work.claim_owner
                or row["claim_generation"] != work.claim_generation
            ):
                raise SliceContractError("claim-fenced")
            current_expiry = normalize_timestamp(
                row["claim_expires_at"], code="stored-claim-time-invalid"
            )
            updated_at = normalize_timestamp(row["updated_at"], code="stored-claim-time-invalid")
            current_time = parse_timestamp(now_value)
            if current_time < parse_timestamp(updated_at):
                raise SliceContractError("claim-clock-regression")
            if current_time >= parse_timestamp(current_expiry):
                raise SliceContractError("claim-expired")
            if parse_timestamp(next_expiry) <= parse_timestamp(current_expiry):
                return
            changed = connection.execute(
                "UPDATE tasks SET claim_expires_at = ?, updated_at = ? WHERE task_id = ? "
                "AND status = 'running' AND claim_owner = ? AND claim_generation = ? "
                "AND claim_expires_at = ?",
                (
                    next_expiry,
                    now_value,
                    work.task_id,
                    work.claim_owner,
                    work.claim_generation,
                    current_expiry,
                ),
            )
            if changed.rowcount != 1:
                raise SliceContractError("claim-fenced")
            self._append_claim_event(
                connection,
                task_id=work.task_id,
                incident_id=work.incident_id,
                event_type="claim.renewed",
                owner=work.claim_owner,
                generation=work.claim_generation,
                lease_expires_at=next_expiry,
                occurred_at=now_value,
            )

    def expire_claim(self, work: WorkItem, *, now: str) -> None:
        now_value = normalize_timestamp(now, code="claim-time-invalid")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ? AND incident_id = ?",
                (work.task_id, work.incident_id),
            ).fetchone()
            if row is None:
                raise SliceContractError("task-not-found")
            if (
                row["status"] != "running"
                or row["claim_owner"] != work.claim_owner
                or row["claim_generation"] != work.claim_generation
            ):
                raise SliceContractError("claim-fenced")
            current_expiry = normalize_timestamp(
                row["claim_expires_at"], code="stored-claim-time-invalid"
            )
            updated_at = normalize_timestamp(row["updated_at"], code="stored-claim-time-invalid")
            if parse_timestamp(now_value) < parse_timestamp(updated_at):
                raise SliceContractError("claim-clock-regression")
            effective_expiry = min(
                (current_expiry, now_value), key=lambda value: parse_timestamp(value)
            )
            changed = connection.execute(
                "UPDATE tasks SET claim_expires_at = ?, updated_at = ? WHERE task_id = ? "
                "AND status = 'running' AND claim_owner = ? AND claim_generation = ? "
                "AND claim_expires_at = ?",
                (
                    effective_expiry,
                    now_value,
                    work.task_id,
                    work.claim_owner,
                    work.claim_generation,
                    current_expiry,
                ),
            )
            if changed.rowcount != 1:
                raise SliceContractError("claim-fenced")
            self._append_claim_event(
                connection,
                task_id=work.task_id,
                incident_id=work.incident_id,
                event_type="claim.cancelled",
                owner=work.claim_owner,
                generation=work.claim_generation,
                lease_expires_at=effective_expiry,
                occurred_at=now_value,
            )

    def claim_history(self, task_id: str) -> list[dict[str, Any]]:
        require_identifier(task_id)
        with self._connection() as connection:
            task = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
            ).fetchone()
            if task is None:
                raise SliceContractError("task-not-found")
            return self._claim_events_for_task(connection, task)

    @staticmethod
    def _insert_documents(
        connection: sqlite3.Connection,
        *,
        table: str,
        id_column: str,
        incident_id: str,
        documents: Sequence[Mapping[str, Any]],
        identity: str,
    ) -> None:
        allowed = {
            ("evidence", "evidence_id"),
            ("validator_results", "result_id"),
            ("invocations", "invocation_id"),
        }
        if (table, id_column) not in allowed:
            raise SliceContractError("store-query-invalid")
        for sequence, document in enumerate(documents, start=1):
            value = cast(dict[str, Any], plain_json(document))
            identifier = require_identifier(value.get(identity))
            encoded = canonical_json_bytes(value)
            connection.execute(
                f"INSERT INTO {table}({id_column}, incident_id, sequence, content_sha256, "
                "document_json) VALUES(?, ?, ?, ?, ?)",
                (identifier, incident_id, sequence, prefixed_sha256(encoded), encoded),
            )

    def complete_task(
        self,
        work: WorkItem,
        *,
        packet: Mapping[str, Any],
        evidence: Sequence[Mapping[str, Any]],
        evidence_batches: Sequence[Mapping[str, Any]],
        validator_results: Sequence[Mapping[str, Any]],
        now: str,
    ) -> dict[str, Any]:
        now_value = normalize_timestamp(now, code="claim-time-invalid")
        packet_value = cast(dict[str, Any], plain_json(packet))
        validate_response_packet(packet_value)
        if packet_value.get("incident_id") != work.incident_id:
            raise SliceContractError("packet-incident-binding")
        if packet_value.get("status") not in {"resolved", "unresolved"}:
            raise SliceContractError("packet-status-invalid")
        evidence_values = [cast(dict[str, Any], plain_json(item)) for item in evidence]
        batch_values = [cast(dict[str, Any], plain_json(item)) for item in evidence_batches]
        if len(batch_values) > 1:
            raise SliceContractError("evidence-batch-duplicate")
        if batch_values and batch_values[0].get("envelopes") != evidence_values:
            raise SliceContractError("evidence-batch-binding")
        if evidence_values and not batch_values:
            raise SliceContractError("evidence-batch-missing")
        validator_values = [cast(dict[str, Any], plain_json(item)) for item in validator_results]
        for result in validator_values:
            validate_result_contract(result)
            if result.get("incident_id") != work.incident_id:
                raise SliceContractError("validator-result-binding")
        invocations = [
            cast(dict[str, Any], plain_json(item))
            for item in cast(Sequence[Mapping[str, Any]], packet_value["invocation_records"])
        ]
        packet_id = require_identifier(packet_value["packet_id"])
        packet_encoded = canonical_json_bytes(packet_value)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT t.status AS task_status, t.alert_sha256, t.trace_id, "
                "t.claim_owner, t.claim_generation, t.claim_expires_at, t.updated_at, "
                "i.status AS incident_status, i.version AS incident_version "
                "FROM tasks t JOIN incidents i ON i.incident_id = t.incident_id "
                "WHERE t.task_id = ? AND t.incident_id = ?",
                (work.task_id, work.incident_id),
            ).fetchone()
            if row is None:
                raise SliceContractError("task-not-found")
            if (
                row["claim_owner"] != work.claim_owner
                or row["claim_generation"] != work.claim_generation
            ):
                raise SliceContractError("claim-fenced")
            if (
                row["task_status"] != "running"
                or row["incident_status"] != "running"
                or row["incident_version"] != work.expected_incident_version + 1
                or row["alert_sha256"] != work.alert_sha256
                or row["trace_id"] != work.trace_id
            ):
                raise SliceContractError("incident-version-conflict")
            current_expiry = normalize_timestamp(
                row["claim_expires_at"], code="stored-claim-time-invalid"
            )
            updated_at = normalize_timestamp(row["updated_at"], code="stored-claim-time-invalid")
            if parse_timestamp(now_value) < parse_timestamp(updated_at):
                raise SliceContractError("claim-clock-regression")
            if parse_timestamp(now_value) >= parse_timestamp(current_expiry):
                raise SliceContractError("claim-expired")
            self._insert_documents(
                connection,
                table="evidence",
                id_column="evidence_id",
                incident_id=work.incident_id,
                documents=evidence_values,
                identity="evidence_id",
            )
            for batch in batch_values:
                batch_encoded = canonical_json_bytes(batch)
                connection.execute(
                    "INSERT INTO evidence_batches(batch_sha256, incident_id, document_json) "
                    "VALUES(?, ?, ?)",
                    (prefixed_sha256(batch_encoded), work.incident_id, batch_encoded),
                )
            self._insert_documents(
                connection,
                table="validator_results",
                id_column="result_id",
                incident_id=work.incident_id,
                documents=validator_values,
                identity="result_id",
            )
            self._insert_documents(
                connection,
                table="invocations",
                id_column="invocation_id",
                incident_id=work.incident_id,
                documents=invocations,
                identity="invocation_id",
            )
            connection.execute(
                "INSERT INTO packets(packet_id, incident_id, content_sha256, document_json) "
                "VALUES(?, ?, ?, ?)",
                (
                    packet_id,
                    work.incident_id,
                    prefixed_sha256(packet_encoded),
                    packet_encoded,
                ),
            )
            self._append_event(
                connection,
                incident_id=work.incident_id,
                event_type="packet.persisted",
                trace_id=work.trace_id,
                payload={
                    "packet_id": packet_id,
                    "packet_sha256": prefixed_sha256(packet_encoded),
                    "status": packet_value["status"],
                    "evidence_records": len(evidence_values),
                    "evidence_batches": len(batch_values),
                    "validator_results": len(validator_values),
                    "invocation_records": len(invocations),
                },
                occurred_at=now_value,
            )
            self._append_claim_event(
                connection,
                task_id=work.task_id,
                incident_id=work.incident_id,
                event_type="claim.completed",
                owner=work.claim_owner,
                generation=work.claim_generation,
                lease_expires_at=current_expiry,
                occurred_at=now_value,
            )
            task_changed = connection.execute(
                "UPDATE tasks SET status = 'complete', packet_id = ?, claim_expires_at = NULL, "
                "updated_at = ? WHERE task_id = ? AND status = 'running' "
                "AND claim_owner = ? AND claim_generation = ? AND claim_expires_at = ?",
                (
                    packet_id,
                    now_value,
                    work.task_id,
                    work.claim_owner,
                    work.claim_generation,
                    current_expiry,
                ),
            )
            incident_changed = connection.execute(
                "UPDATE incidents SET status = ?, version = version + 1, packet_id = ?, "
                "updated_at = ? WHERE incident_id = ? AND status = 'running' AND version = ?",
                (
                    packet_value["status"],
                    packet_id,
                    now_value,
                    work.incident_id,
                    work.expected_incident_version + 1,
                ),
            )
            if task_changed.rowcount != 1 or incident_changed.rowcount != 1:
                raise SliceContractError("claim-fenced")
            self._append_event(
                connection,
                incident_id=work.incident_id,
                event_type="incident.completed",
                trace_id=work.trace_id,
                payload={
                    "task_id": work.task_id,
                    "packet_id": packet_id,
                    "status": packet_value["status"],
                    "incident_version": work.expected_incident_version + 2,
                },
                occurred_at=now_value,
            )
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (work.incident_id,)
            ).fetchone()
            task = connection.execute(
                "SELECT * FROM tasks WHERE task_id = ?", (work.task_id,)
            ).fetchone()
            trace_rows = connection.execute(
                "SELECT document_json FROM trace_events WHERE incident_id = ? ORDER BY sequence",
                (work.incident_id,),
            ).fetchall()
            if incident is None or task is None:
                raise SliceContractError("incident-not-found")
            transaction_replay = finalize_replay(
                {
                    "schema": REPLAY_SCHEMA,
                    "incident": self._incident_record(incident),
                    "task": self._task_record(task),
                    "alert": work.alert,
                    "evidence_batches": batch_values,
                    "evidence": evidence_values,
                    "validator_results": validator_values,
                    "invocations": invocations,
                    "packet": packet_value,
                    "trace_events": [
                        self._decode(trace_row["document_json"]) for trace_row in trace_rows
                    ],
                }
            )
            if transaction_replay["packet"] != packet_value:
                raise SliceContractError("packet-replay-mismatch")
        replay = self.replay(work.incident_id)
        if replay["packet"] != packet_value:
            raise SliceContractError("packet-replay-mismatch")
        return packet_value

    def incident_view(self, incident_id: str) -> dict[str, Any]:
        require_identifier(incident_id)
        with self._connection() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            task = connection.execute(
                "SELECT * FROM tasks WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            packet_row = connection.execute(
                "SELECT packet_id, incident_id, content_sha256, document_json "
                "FROM packets WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if incident is None or task is None:
            raise SliceContractError("incident-not-found")
        if packet_row is None and (
            incident["packet_id"] is not None or task["packet_id"] is not None
        ):
            raise SliceContractError("stored-packet-missing")
        packet = None if packet_row is None else self._decode(packet_row["document_json"])
        if packet is not None:
            if prefixed_sha256(canonical_json_bytes(packet)) != packet_row["content_sha256"]:
                raise SliceContractError("stored-packet-digest")
            validate_response_packet(packet)
            if (
                packet_row["packet_id"] != incident["packet_id"]
                or packet_row["packet_id"] != task["packet_id"]
                or packet_row["incident_id"] != incident_id
                or packet.get("packet_id") != packet_row["packet_id"]
                or packet.get("incident_id") != incident_id
            ):
                raise SliceContractError("stored-packet-binding")
        return {
            "schema": "incident-view/v1",
            "incident": self._incident_record(incident),
            "task": self._task_record(task),
            "packet": packet,
        }

    def replay(self, incident_id: str) -> dict[str, Any]:
        require_identifier(incident_id)
        with self._connection() as connection:
            incident = connection.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            task = connection.execute(
                "SELECT * FROM tasks WHERE incident_id = ?", (incident_id,)
            ).fetchone()
            packet = connection.execute(
                "SELECT document_json, content_sha256 FROM packets WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            evidence = connection.execute(
                "SELECT document_json, content_sha256 FROM evidence WHERE incident_id = ? "
                "ORDER BY sequence",
                (incident_id,),
            ).fetchall()
            evidence_batches = connection.execute(
                "SELECT document_json, batch_sha256 FROM evidence_batches WHERE incident_id = ?",
                (incident_id,),
            ).fetchall()
            validator_results = connection.execute(
                "SELECT document_json, content_sha256 FROM validator_results "
                "WHERE incident_id = ? ORDER BY sequence",
                (incident_id,),
            ).fetchall()
            invocations = connection.execute(
                "SELECT document_json, content_sha256 FROM invocations WHERE incident_id = ? "
                "ORDER BY sequence",
                (incident_id,),
            ).fetchall()
            trace_events = connection.execute(
                "SELECT document_json, event_sha256 FROM trace_events WHERE incident_id = ? "
                "ORDER BY sequence",
                (incident_id,),
            ).fetchall()
        if incident is None or task is None:
            raise SliceContractError("incident-not-found")
        if packet is None or incident["packet_id"] is None or task["status"] != "complete":
            raise SliceContractError("incident-incomplete")

        def verified_documents(
            rows: Sequence[sqlite3.Row], digest_column: str
        ) -> list[dict[str, Any]]:
            result: list[dict[str, Any]] = []
            for row in rows:
                document = self._decode(row["document_json"])
                encoded = canonical_json_bytes(document)
                expected = (
                    document.get("event_sha256")
                    if digest_column == "event_sha256"
                    else prefixed_sha256(encoded)
                )
                if row[digest_column] != expected:
                    raise SliceContractError("stored-document-digest")
                result.append(document)
            return result

        alert = self._decode(incident["alert_json"])
        if alert_digest(alert) != incident["alert_sha256"]:
            raise SliceContractError("stored-alert-digest")
        packet_value = self._decode(packet["document_json"])
        if prefixed_sha256(canonical_json_bytes(packet_value)) != packet["content_sha256"]:
            raise SliceContractError("stored-packet-digest")
        body = {
            "schema": REPLAY_SCHEMA,
            "incident": self._incident_record(incident),
            "task": self._task_record(task),
            "alert": alert,
            "evidence_batches": verified_documents(evidence_batches, "batch_sha256"),
            "evidence": verified_documents(evidence, "content_sha256"),
            "validator_results": verified_documents(validator_results, "content_sha256"),
            "invocations": verified_documents(invocations, "content_sha256"),
            "packet": packet_value,
            "trace_events": verified_documents(trace_events, "event_sha256"),
        }
        replay = finalize_replay(body)
        validate_replay(replay)
        return replay

    def reset(self) -> dict[str, int | str]:
        with self._transaction() as connection:
            counts = {
                name: cast(int, connection.execute(f"SELECT count(*) FROM {name}").fetchone()[0])
                for name in (
                    "incidents",
                    "tasks",
                    "evidence",
                    "evidence_batches",
                    "validator_results",
                    "invocations",
                    "packets",
                    "trace_events",
                )
            }
            for table in (
                "claim_events",
                "trace_events",
                "invocations",
                "validator_results",
                "evidence_batches",
                "evidence",
                "packets",
                "tasks",
                "incidents",
            ):
                connection.execute(f"DELETE FROM {table}")
        return {"schema": "incident-store-reset/v1", **counts}

    def assert_empty(self) -> None:
        with self._connection() as connection:
            counts = [
                connection.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
                for name in ("incidents", "tasks", "claim_events", "packets", "trace_events")
            ]
        if any(counts):
            raise SliceContractError("store-not-empty")


__all__ = ["AcceptedIncident", "SqliteIncidentStore", "WorkItem"]
