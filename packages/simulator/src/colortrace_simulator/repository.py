from __future__ import annotations

import os
import re
import sqlite3
import stat
import threading
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from .authority import (
    SimulatorAuthorityError,
    ValidatedDispatchBundle,
    action_from_bundle,
    canonical_json_bytes,
    plain_json,
    prefixed_sha256,
    require_digest,
    stable_action_id,
    strict_json_bytes,
    validate_schema,
)
from .models import (
    ActionClaim,
    BoundSimulatorAction,
    DispatchIdentity,
    PreparedPublication,
    PromotionResult,
)

CLAIM_LEASE_SECONDS = 30
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_REASON = re.compile(r"[a-z][a-z0-9-]{1,63}")


class SimulatorRepositoryError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE simulator_actions (
    action_id TEXT PRIMARY KEY,
    task_key TEXT NOT NULL UNIQUE,
    operation_id TEXT NOT NULL UNIQUE,
    payload_sha256 TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    incident_version INTEGER NOT NULL CHECK (incident_version >= 1),
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL CHECK (plan_version >= 1),
    plan_sha256 TEXT NOT NULL,
    approval_sha256 TEXT NOT NULL,
    authorization_sha256 TEXT NOT NULL UNIQUE,
    consumption_sha256 TEXT NOT NULL UNIQUE,
    bundle_sha256 TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN (
        'queued', 'running', 'publication_pending', 'succeeded', 'failed'
    )),
    claim_owner TEXT,
    claim_generation INTEGER NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
    claim_expires_at TEXT,
    started_at TEXT,
    admitted_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    outcome_sha256 TEXT UNIQUE,
    bundle_document BLOB NOT NULL,
    UNIQUE (task_key, operation_id, payload_sha256),
    CHECK (
        (status = 'queued' AND claim_owner IS NULL AND claim_generation = 0
            AND claim_expires_at IS NULL AND started_at IS NULL AND outcome_sha256 IS NULL)
        OR
        (status IN ('running', 'publication_pending') AND claim_owner IS NOT NULL
            AND claim_generation >= 1 AND claim_expires_at IS NOT NULL
            AND started_at IS NOT NULL AND outcome_sha256 IS NULL)
        OR
        (status IN ('succeeded', 'failed') AND claim_owner IS NOT NULL
            AND claim_generation >= 1 AND claim_expires_at IS NULL
            AND started_at IS NOT NULL AND outcome_sha256 IS NOT NULL)
    )
);
CREATE INDEX simulator_actions_claim_expiry
    ON simulator_actions(status, claim_expires_at);
CREATE TABLE simulator_admissions (
    admission_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE,
    admission_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    FOREIGN KEY (action_id) REFERENCES simulator_actions(action_id)
);
CREATE TABLE simulator_claim_events (
    action_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 1),
    event_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    PRIMARY KEY (action_id, sequence),
    FOREIGN KEY (action_id) REFERENCES simulator_actions(action_id)
);
CREATE TABLE simulator_publication_intents (
    intent_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE,
    claim_generation INTEGER NOT NULL CHECK (claim_generation >= 1),
    intent_sha256 TEXT NOT NULL UNIQUE,
    expected_pointer_sha256 TEXT NOT NULL,
    expected_generation INTEGER NOT NULL CHECK (expected_generation >= 1),
    candidate_pointer_sha256 TEXT NOT NULL,
    candidate_generation INTEGER NOT NULL CHECK (candidate_generation = expected_generation + 1),
    document BLOB NOT NULL,
    FOREIGN KEY (action_id) REFERENCES simulator_actions(action_id)
);
CREATE TABLE simulator_publication_receipts (
    receipt_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE,
    intent_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('promoted', 'conflict')),
    receipt_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    FOREIGN KEY (action_id) REFERENCES simulator_actions(action_id),
    FOREIGN KEY (intent_id) REFERENCES simulator_publication_intents(intent_id)
);
CREATE TABLE simulator_action_outcomes (
    outcome_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('succeeded', 'failed')),
    outcome_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    FOREIGN KEY (action_id) REFERENCES simulator_actions(action_id)
);
CREATE TABLE simulator_action_audit_events (
    action_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    record_sha256 TEXT NOT NULL UNIQUE,
    event_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    PRIMARY KEY (action_id, sequence),
    FOREIGN KEY (action_id) REFERENCES simulator_actions(action_id)
);
CREATE TABLE simulator_action_audit_heads (
    action_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_sha256 TEXT NOT NULL,
    FOREIGN KEY (action_id, sequence)
        REFERENCES simulator_action_audit_events(action_id, sequence)
);
CREATE TABLE simulator_idempotency (
    idempotency_key TEXT PRIMARY KEY,
    operation TEXT NOT NULL CHECK (operation = 'dispatch.admit'),
    request_sha256 TEXT NOT NULL,
    action_id TEXT NOT NULL UNIQUE,
    admission_sha256 TEXT NOT NULL UNIQUE,
    result BLOB NOT NULL,
    FOREIGN KEY (action_id) REFERENCES simulator_actions(action_id)
);
CREATE TRIGGER simulator_actions_no_delete
BEFORE DELETE ON simulator_actions BEGIN
    SELECT RAISE(ABORT, 'simulator-actions-no-delete');
END;
CREATE TRIGGER simulator_actions_identity_immutable
BEFORE UPDATE ON simulator_actions
WHEN NEW.action_id != OLD.action_id OR NEW.task_key != OLD.task_key
    OR NEW.operation_id != OLD.operation_id OR NEW.payload_sha256 != OLD.payload_sha256
    OR NEW.incident_id != OLD.incident_id OR NEW.incident_version != OLD.incident_version
    OR NEW.plan_id != OLD.plan_id
    OR NEW.plan_version != OLD.plan_version OR NEW.plan_sha256 != OLD.plan_sha256
    OR NEW.approval_sha256 != OLD.approval_sha256
    OR NEW.authorization_sha256 != OLD.authorization_sha256
    OR NEW.consumption_sha256 != OLD.consumption_sha256
    OR NEW.bundle_sha256 != OLD.bundle_sha256 OR NEW.bundle_document != OLD.bundle_document
    OR NEW.admitted_at != OLD.admitted_at
BEGIN
    SELECT RAISE(ABORT, 'simulator-action-identity-immutable');
END;
CREATE TRIGGER simulator_actions_valid_transition
BEFORE UPDATE ON simulator_actions
WHEN NOT (
    (OLD.status = 'queued' AND NEW.status = 'running')
    OR (OLD.status = 'running' AND NEW.status IN ('running', 'publication_pending', 'failed'))
    OR (OLD.status = 'publication_pending'
        AND NEW.status IN ('publication_pending', 'succeeded', 'failed'))
)
BEGIN
    SELECT RAISE(ABORT, 'simulator-action-transition-invalid');
END;
CREATE TRIGGER simulator_actions_clock_monotonic
BEFORE UPDATE ON simulator_actions
WHEN NEW.updated_at < OLD.updated_at
BEGIN
    SELECT RAISE(ABORT, 'simulator-action-clock-regression');
END;
CREATE TRIGGER simulator_audit_head_valid_advance
BEFORE UPDATE ON simulator_action_audit_heads
WHEN NEW.action_id != OLD.action_id OR NEW.sequence != OLD.sequence + 1
    OR NOT EXISTS (
        SELECT 1 FROM simulator_action_audit_events AS event
        WHERE event.action_id = NEW.action_id AND event.sequence = NEW.sequence
            AND event.event_sha256 = NEW.event_sha256
    )
BEGIN
    SELECT RAISE(ABORT, 'simulator-audit-head-advance-invalid');
END;
CREATE TRIGGER simulator_audit_head_no_delete
BEFORE DELETE ON simulator_action_audit_heads BEGIN
    SELECT RAISE(ABORT, 'simulator-audit-head-no-delete');
END;
"""

for _table in (
    "simulator_admissions",
    "simulator_claim_events",
    "simulator_publication_intents",
    "simulator_publication_receipts",
    "simulator_action_outcomes",
    "simulator_action_audit_events",
    "simulator_idempotency",
):
    _suffix = _table.removeprefix("simulator_")
    _SCHEMA += f"""
CREATE TRIGGER {_suffix}_no_update BEFORE UPDATE ON {_table} BEGIN
    SELECT RAISE(ABORT, '{_suffix}-append-only');
END;
CREATE TRIGGER {_suffix}_no_delete BEFORE DELETE ON {_table} BEGIN
    SELECT RAISE(ABORT, '{_suffix}-append-only');
END;
"""

_APPLICATION_ID = 0x43545349
_SCHEMA_VERSION = 1
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


def _require_identifier(value: Any, *, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SimulatorRepositoryError(code)
    return value


def _parse_time(value: Any, *, code: str) -> datetime:
    if not isinstance(value, str) or len(value) != 24 or not value.endswith("Z"):
        raise SimulatorRepositoryError(code)
    try:
        selected = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise SimulatorRepositoryError(code) from error
    if selected.tzinfo is None:
        raise SimulatorRepositoryError(code)
    normalized = selected.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if normalized != value:
        raise SimulatorRepositoryError(code)
    return selected.astimezone(UTC)


def normalize_time(value: datetime | str, *, code: str = "time-invalid") -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise SimulatorRepositoryError(code)
        selected = value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        _parse_time(selected, code=code)
        return selected
    _parse_time(value, code=code)
    return value


def _claim_expiry(now: str) -> str:
    return normalize_time(
        _parse_time(now, code="claim-time-invalid") + timedelta(seconds=CLAIM_LEASE_SECONDS)
    )


class SQLiteSimulatorRepository:
    def __init__(self, database: str | Path = ":memory:", *, busy_timeout_ms: int = 30_000) -> None:
        if (
            not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or not 1 <= busy_timeout_ms <= 30_000
        ):
            raise SimulatorRepositoryError("repository-timeout-invalid")
        self._database = str(database)
        self._lock = threading.RLock()
        created = False
        expected_identity: tuple[int, int] | None = None
        connect_target = self._database
        use_uri = False
        if self._database != ":memory:":
            path, created, expected_identity = self._prepare_database_path(Path(database))
            self._database = str(path)
            connect_target = f"{path.as_uri()}?mode=rw"
            use_uri = True
        try:
            self._connection = sqlite3.connect(
                connect_target,
                isolation_level=None,
                check_same_thread=False,
                timeout=busy_timeout_ms / 1000,
                uri=use_uri,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            self._connection.execute("PRAGMA synchronous = FULL")
            if self._database != ":memory:":
                self._connection.execute("PRAGMA journal_mode = DELETE")
                self._validate_database_path(Path(self._database), expected_identity)
            self._initialize_or_validate(created=created or self._database == ":memory:")
        except SimulatorRepositoryError:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise
        except sqlite3.DatabaseError as error:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise SimulatorRepositoryError("repository-invalid") from error

    @staticmethod
    def _validate_stat(path: Path, value: os.stat_result) -> None:
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or path.is_symlink():
            raise SimulatorRepositoryError("repository-path-invalid")
        if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) & 0o077:
            raise SimulatorRepositoryError("repository-permissions-invalid")

    @classmethod
    def _prepare_database_path(cls, raw_path: Path) -> tuple[Path, bool, tuple[int, int]]:
        path = raw_path.absolute()
        try:
            parent = path.parent.stat(follow_symlinks=False)
        except OSError as error:
            raise SimulatorRepositoryError("repository-path-invalid") from error
        if not stat.S_ISDIR(parent.st_mode):
            raise SimulatorRepositoryError("repository-path-invalid")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            value = path.lstat()
            cls._validate_stat(path, value)
            return path, False, (value.st_dev, value.st_ino)
        except OSError as error:
            raise SimulatorRepositoryError("repository-path-invalid") from error
        try:
            value = os.fstat(descriptor)
            cls._validate_stat(path, value)
            return path, True, (value.st_dev, value.st_ino)
        finally:
            os.close(descriptor)

    @classmethod
    def _validate_database_path(cls, path: Path, expected: tuple[int, int] | None) -> None:
        value = path.lstat()
        cls._validate_stat(path, value)
        if expected is None or (value.st_dev, value.st_ino) != expected:
            raise SimulatorRepositoryError("repository-path-changed")

    def _initialize_or_validate(self, *, created: bool) -> None:
        application_id = cast(int, self._connection.execute("PRAGMA application_id").fetchone()[0])
        version = cast(int, self._connection.execute("PRAGMA user_version").fetchone()[0])
        if created:
            if application_id != 0 or version != 0:
                raise SimulatorRepositoryError("repository-schema-invalid")
            self._connection.executescript(_SCHEMA)
            self._connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        elif application_id != _APPLICATION_ID or version != _SCHEMA_VERSION:
            raise SimulatorRepositoryError("repository-schema-invalid")
        manifest = _schema_manifest(self._connection)
        if (
            manifest != _EXPECTED_SCHEMA
            or prefixed_sha256(canonical_json_bytes(manifest)) != _EXPECTED_SCHEMA_SHA256
        ):
            raise SimulatorRepositoryError("repository-schema-invalid")
        check = self._connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise SimulatorRepositoryError("repository-integrity-error")

    @contextmanager
    def transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield self._connection
                self._connection.commit()
            except (SimulatorRepositoryError, SimulatorAuthorityError):
                self._connection.rollback()
                raise
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise SimulatorRepositoryError("repository-integrity-error") from error
            except sqlite3.OperationalError as error:
                self._connection.rollback()
                raise SimulatorRepositoryError("repository-unavailable") from error
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise SimulatorRepositoryError("repository-invalid") from error
            except BaseException:
                self._connection.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @staticmethod
    def decode(document: bytes | memoryview) -> dict[str, Any]:
        value = strict_json_bytes(bytes(document))
        if not isinstance(value, dict):
            raise SimulatorRepositoryError("stored-document-invalid")
        return cast(dict[str, Any], value)

    @staticmethod
    def _request_sha256(identity: DispatchIdentity) -> str:
        return prefixed_sha256(
            canonical_json_bytes(
                {
                    "operation": "dispatch.admit",
                    "task_key": identity.task_key,
                    "operation_id": identity.operation_id,
                    "payload_sha256": identity.payload_sha256,
                }
            )
        )

    @classmethod
    def _build_admission(
        cls,
        action: BoundSimulatorAction,
        *,
        executor_actor: Mapping[str, str],
        admitted_at: str,
    ) -> dict[str, Any]:
        body = {
            "schema": "simulator-action-admission/v1",
            "action_id": action.action_id,
            "task_key": action.identity.task_key,
            "operation_id": action.identity.operation_id,
            "payload_sha256": action.identity.payload_sha256,
            "dispatch_bundle_sha256": action.dispatch_bundle_sha256,
            "incident_id": action.incident_id,
            "incident_version": action.incident_version,
            "plan_id": action.plan_id,
            "plan_version": action.plan_version,
            "plan_sha256": action.plan_sha256,
            "approval_id": action.approval_id,
            "approval_sha256": action.approval_sha256,
            "authorization_id": action.authorization_id,
            "authorization_sha256": action.authorization_sha256,
            "consumption_id": action.consumption_id,
            "consumption_sha256": action.consumption_sha256,
            "executor_actor": dict(executor_actor),
            "admitted_at": admitted_at,
        }
        digest = prefixed_sha256(canonical_json_bytes(body))
        admission = {
            **body,
            "admission_id": f"simulator-admission:{digest.removeprefix('sha256:')}",
            "admission_sha256": digest,
        }
        validate_schema("simulator-action-admission-v1.schema.json", admission)
        return admission

    @classmethod
    def _build_audit_event(
        cls,
        connection: sqlite3.Connection,
        *,
        action_id: str,
        event_type: str,
        record_sha256: str,
        actor_id: str,
        claim_generation: int | None,
        occurred_at: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT sequence, event_sha256 FROM simulator_action_audit_events "
            "WHERE action_id = ? ORDER BY sequence DESC LIMIT 1",
            (action_id,),
        ).fetchone()
        sequence = 1 if row is None else cast(int, row["sequence"]) + 1
        predecessor = None if row is None else cast(str, row["event_sha256"])
        body = {
            "schema": "simulator-action-audit-event/v1",
            "action_id": action_id,
            "sequence": sequence,
            "event_type": event_type,
            "record_sha256": require_digest(record_sha256),
            "actor_id": _require_identifier(actor_id, code="audit-actor-invalid"),
            "claim_generation": claim_generation,
            "predecessor_event_sha256": predecessor,
            "occurred_at": normalize_time(occurred_at),
        }
        digest = prefixed_sha256(canonical_json_bytes(body))
        event = {
            **body,
            "event_id": f"simulator-audit-event:{digest.removeprefix('sha256:')}",
            "event_sha256": digest,
        }
        validate_schema("simulator-action-audit-event-v1.schema.json", event)
        return event

    @classmethod
    def _append_audit(
        cls,
        connection: sqlite3.Connection,
        *,
        action_id: str,
        event_type: str,
        record_sha256: str,
        actor_id: str,
        claim_generation: int | None,
        occurred_at: str,
    ) -> dict[str, Any]:
        event = cls._build_audit_event(
            connection,
            action_id=action_id,
            event_type=event_type,
            record_sha256=record_sha256,
            actor_id=actor_id,
            claim_generation=claim_generation,
            occurred_at=occurred_at,
        )
        connection.execute(
            "INSERT INTO simulator_action_audit_events("
            "action_id, sequence, event_id, event_type, record_sha256, event_sha256, document) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                action_id,
                event["sequence"],
                event["event_id"],
                event_type,
                record_sha256,
                event["event_sha256"],
                canonical_json_bytes(event),
            ),
        )
        if event["sequence"] == 1:
            connection.execute(
                "INSERT INTO simulator_action_audit_heads(action_id, sequence, event_sha256) "
                "VALUES (?, 1, ?)",
                (action_id, event["event_sha256"]),
            )
        else:
            changed = connection.execute(
                "UPDATE simulator_action_audit_heads SET sequence = ?, event_sha256 = ? "
                "WHERE action_id = ? AND sequence = ? AND event_sha256 = ?",
                (
                    event["sequence"],
                    event["event_sha256"],
                    action_id,
                    cast(int, event["sequence"]) - 1,
                    event["predecessor_event_sha256"],
                ),
            )
            if changed.rowcount != 1:
                raise SimulatorRepositoryError("audit-head-conflict")
        return event

    @classmethod
    def _build_claim_event(
        cls,
        connection: sqlite3.Connection,
        *,
        action_id: str,
        event_type: str,
        owner: str,
        generation: int,
        lease_expires_at: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT sequence, event_sha256 FROM simulator_claim_events "
            "WHERE action_id = ? ORDER BY sequence DESC LIMIT 1",
            (action_id,),
        ).fetchone()
        sequence = 1 if row is None else cast(int, row["sequence"]) + 1
        predecessor = None if row is None else cast(str, row["event_sha256"])
        body = {
            "schema": "simulator-action-claim-event/v1",
            "action_id": action_id,
            "sequence": sequence,
            "event_type": event_type,
            "owner": _require_identifier(owner, code="claim-owner-invalid"),
            "generation": generation,
            "lease_expires_at": normalize_time(lease_expires_at, code="claim-expiry-invalid"),
            "predecessor_event_sha256": predecessor,
            "occurred_at": normalize_time(occurred_at, code="claim-time-invalid"),
        }
        digest = prefixed_sha256(canonical_json_bytes(body))
        event = {
            **body,
            "event_id": f"simulator-claim-event:{digest.removeprefix('sha256:')}",
            "event_sha256": digest,
        }
        validate_schema("simulator-action-claim-event-v1.schema.json", event)
        return event

    @classmethod
    def _append_claim_event(
        cls,
        connection: sqlite3.Connection,
        *,
        action_id: str,
        event_type: str,
        owner: str,
        generation: int,
        lease_expires_at: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        event = cls._build_claim_event(
            connection,
            action_id=action_id,
            event_type=event_type,
            owner=owner,
            generation=generation,
            lease_expires_at=lease_expires_at,
            occurred_at=occurred_at,
        )
        connection.execute(
            "INSERT INTO simulator_claim_events("
            "action_id, sequence, event_id, event_type, generation, event_sha256, document) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                action_id,
                event["sequence"],
                event["event_id"],
                event_type,
                generation,
                event["event_sha256"],
                canonical_json_bytes(event),
            ),
        )
        cls._append_audit(
            connection,
            action_id=action_id,
            event_type=event_type,
            record_sha256=cast(str, event["event_sha256"]),
            actor_id=owner,
            claim_generation=generation,
            occurred_at=occurred_at,
        )
        return event

    @classmethod
    def _record_map(
        cls, connection: sqlite3.Connection, action_id: str
    ) -> dict[str, tuple[str, dict[str, Any]]]:
        records: dict[str, tuple[str, dict[str, Any]]] = {}
        queries = (
            ("simulator_admissions", "admission_sha256", "document", "admission"),
            ("simulator_claim_events", "event_sha256", "document", "claim"),
            ("simulator_publication_intents", "intent_sha256", "document", "intent"),
            ("simulator_publication_receipts", "receipt_sha256", "document", "receipt"),
            ("simulator_action_outcomes", "outcome_sha256", "document", "outcome"),
        )
        for table, digest_column, document_column, kind in queries:
            rows = connection.execute(
                f"SELECT {digest_column} AS digest, {document_column} AS document "
                f"FROM {table} WHERE action_id = ?",
                (action_id,),
            ).fetchall()
            for row in rows:
                digest = cast(str, row["digest"])
                if digest in records:
                    raise SimulatorRepositoryError("audit-record-duplicate")
                records[digest] = (kind, cls.decode(row["document"]))
        return records

    @classmethod
    def _validate_history(cls, connection: sqlite3.Connection, action_id: str) -> None:
        row = connection.execute(
            "SELECT * FROM simulator_actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            raise SimulatorRepositoryError("action-not-found")
        bundle = cls.decode(row["bundle_document"])
        action = action_from_bundle(bundle)
        if (
            action.action_id != action_id
            or action.identity.task_key != row["task_key"]
            or action.identity.operation_id != row["operation_id"]
            or action.identity.payload_sha256 != row["payload_sha256"]
            or action.dispatch_bundle_sha256 != row["bundle_sha256"]
            or action.incident_version != row["incident_version"]
            or action.plan_sha256 != row["plan_sha256"]
            or action.approval_sha256 != row["approval_sha256"]
            or action.authorization_sha256 != row["authorization_sha256"]
            or action.consumption_sha256 != row["consumption_sha256"]
        ):
            raise SimulatorRepositoryError("stored-action-binding")

        records = cls._record_map(connection, action_id)
        for digest, (kind, document) in records.items():
            schema_name = {
                "admission": "simulator-action-admission-v1.schema.json",
                "claim": "simulator-action-claim-event-v1.schema.json",
                "intent": "simulator-publication-intent-v1.schema.json",
                "receipt": "simulator-publication-receipt-v1.schema.json",
                "outcome": "simulator-action-outcome-v1.schema.json",
            }[kind]
            digest_field = {
                "admission": "admission_sha256",
                "claim": "event_sha256",
                "intent": "intent_sha256",
                "receipt": "receipt_sha256",
                "outcome": "outcome_sha256",
            }[kind]
            validate_schema(schema_name, document)
            excluded = {
                "admission": {"admission_id", "admission_sha256"},
                "claim": {"event_id", "event_sha256"},
                "intent": {"intent_id", "intent_sha256"},
                "receipt": {"receipt_id", "receipt_sha256"},
                "outcome": {"outcome_id", "outcome_sha256"},
            }[kind]
            body = {key: child for key, child in document.items() if key not in excluded}
            expected = prefixed_sha256(canonical_json_bytes(body))
            if document.get(digest_field) != digest or digest != expected:
                raise SimulatorRepositoryError(f"stored-{kind}-digest")

        admissions = [document for kind, document in records.values() if kind == "admission"]
        if len(admissions) != 1:
            raise SimulatorRepositoryError("stored-admission-binding")
        admission = admissions[0]
        admission_bindings = {
            "action_id": action.action_id,
            "task_key": action.identity.task_key,
            "operation_id": action.identity.operation_id,
            "payload_sha256": action.identity.payload_sha256,
            "dispatch_bundle_sha256": action.dispatch_bundle_sha256,
            "incident_id": action.incident_id,
            "incident_version": action.incident_version,
            "plan_id": action.plan_id,
            "plan_version": action.plan_version,
            "plan_sha256": action.plan_sha256,
            "approval_id": action.approval_id,
            "approval_sha256": action.approval_sha256,
            "authorization_id": action.authorization_id,
            "authorization_sha256": action.authorization_sha256,
            "consumption_id": action.consumption_id,
            "consumption_sha256": action.consumption_sha256,
        }
        if any(admission.get(key) != value for key, value in admission_bindings.items()):
            raise SimulatorRepositoryError("stored-admission-binding")

        audit_rows = connection.execute(
            "SELECT * FROM simulator_action_audit_events WHERE action_id = ? ORDER BY sequence",
            (action_id,),
        ).fetchall()
        head = connection.execute(
            "SELECT sequence, event_sha256 FROM simulator_action_audit_heads WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if not audit_rows or head is None or head["sequence"] != len(audit_rows):
            raise SimulatorRepositoryError("audit-head-mismatch")
        predecessor: str | None = None
        seen: set[str] = set()
        audit_events: list[dict[str, Any]] = []
        previous_occurred_at: datetime | None = None
        for sequence, audit_row in enumerate(audit_rows, start=1):
            event = cls.decode(audit_row["document"])
            validate_schema("simulator-action-audit-event-v1.schema.json", event)
            body = {
                key: child
                for key, child in event.items()
                if key not in {"event_id", "event_sha256"}
            }
            expected = prefixed_sha256(canonical_json_bytes(body))
            record_digest = cast(str, event["record_sha256"])
            if (
                event["action_id"] != action_id
                or event["sequence"] != sequence
                or event["predecessor_event_sha256"] != predecessor
                or event["event_sha256"] != expected
                or audit_row["event_sha256"] != expected
                or record_digest not in records
                or record_digest in seen
            ):
                raise SimulatorRepositoryError("audit-chain-binding")
            occurred_at = _parse_time(event["occurred_at"], code="stored-audit-time-invalid")
            if previous_occurred_at is not None and occurred_at < previous_occurred_at:
                raise SimulatorRepositoryError("audit-clock-regression")
            seen.add(record_digest)
            predecessor = expected
            previous_occurred_at = occurred_at
            audit_events.append(event)
        if predecessor != head["event_sha256"] or seen != set(records):
            raise SimulatorRepositoryError("audit-record-binding")
        audit_by_record = {cast(str, event["record_sha256"]): event for event in audit_events}
        if (
            audit_events[0]["event_type"] != "dispatch.admitted"
            or audit_events[0]["record_sha256"] != admission["admission_sha256"]
            or audit_events[0]["occurred_at"] != admission["admitted_at"]
            or admission["admitted_at"] != row["admitted_at"]
            or audit_events[-1]["occurred_at"] != row["updated_at"]
        ):
            raise SimulatorRepositoryError("stored-action-time-binding")

        claims = [document for kind, document in records.values() if kind == "claim"]
        claims.sort(key=lambda value: cast(int, value["sequence"]))
        claim_predecessor: str | None = None
        last_generation = 0
        for index, event in enumerate(claims, start=1):
            if event["sequence"] != index or event["predecessor_event_sha256"] != claim_predecessor:
                raise SimulatorRepositoryError("claim-history-binding")
            event_type = cast(str, event["event_type"])
            generation = cast(int, event["generation"])
            occurred_at = _parse_time(event["occurred_at"], code="stored-claim-time-invalid")
            expiry = _parse_time(event["lease_expires_at"], code="stored-claim-time-invalid")
            claim_audit = audit_by_record.get(cast(str, event["event_sha256"]))
            if claim_audit is None or (
                claim_audit["event_type"] != event_type
                or claim_audit["actor_id"] != event["owner"]
                or claim_audit["claim_generation"] != generation
                or claim_audit["occurred_at"] != event["occurred_at"]
            ):
                raise SimulatorRepositoryError("claim-audit-binding")
            if index == 1 and (event_type != "claim.acquired" or generation != 1):
                raise SimulatorRepositoryError("claim-history-binding")
            if (
                event_type in {"claim.acquired", "claim.reclaimed", "claim.renewed"}
                and expiry <= occurred_at
            ):
                raise SimulatorRepositoryError("claim-history-binding")
            if event_type == "claim.reclaimed" and generation != last_generation + 1:
                raise SimulatorRepositoryError("claim-history-binding")
            if (
                event_type not in {"claim.reclaimed", "claim.acquired"}
                and generation != last_generation
            ):
                raise SimulatorRepositoryError("claim-history-binding")
            last_generation = generation
            claim_predecessor = cast(str, event["event_sha256"])

        status = cast(str, row["status"])
        if claims:
            if claims[0]["occurred_at"] != row["started_at"]:
                raise SimulatorRepositoryError("stored-action-time-binding")
        elif row["started_at"] is not None:
            raise SimulatorRepositoryError("stored-action-time-binding")
        outcomes = [document for kind, document in records.values() if kind == "outcome"]
        if status == "queued":
            if claims or outcomes:
                raise SimulatorRepositoryError("stored-action-state")
        elif status in {"running", "publication_pending"}:
            if not claims or claims[-1]["event_type"] == "claim.completed" or outcomes:
                raise SimulatorRepositoryError("stored-action-state")
            if (
                claims[-1]["owner"] != row["claim_owner"]
                or claims[-1]["generation"] != row["claim_generation"]
                or claims[-1]["lease_expires_at"] != row["claim_expires_at"]
            ):
                raise SimulatorRepositoryError("stored-claim-state")
        else:
            if len(outcomes) != 1 or not claims or claims[-1]["event_type"] != "claim.completed":
                raise SimulatorRepositoryError("stored-action-state")
            if outcomes[0]["outcome_sha256"] != row["outcome_sha256"]:
                raise SimulatorRepositoryError("stored-action-state")
            outcome = outcomes[0]
            if (
                outcome["status"] != status
                or outcome["action_started_at"] != row["started_at"]
                or outcome["completed_at"] != row["updated_at"]
                or claims[-1]["occurred_at"] != outcome["completed_at"]
            ):
                raise SimulatorRepositoryError("stored-outcome-time-binding")
            terminal_audit = audit_by_record.get(cast(str, outcome["outcome_sha256"]))
            if terminal_audit is None or (
                terminal_audit["event_type"] != f"action.{status}"
                or terminal_audit["occurred_at"] != outcome["completed_at"]
                or terminal_audit["claim_generation"] != row["claim_generation"]
                or terminal_audit["actor_id"] != row["claim_owner"]
            ):
                raise SimulatorRepositoryError("stored-outcome-time-binding")

        if outcomes:
            outcome = outcomes[0]
            outcome_bindings = {
                "action_id": action.action_id,
                "task_key": action.identity.task_key,
                "operation_id": action.identity.operation_id,
                "payload_sha256": action.identity.payload_sha256,
                "incident_id": action.incident_id,
                "incident_version": action.incident_version,
                "plan_id": action.plan_id,
                "plan_version": action.plan_version,
                "plan_sha256": action.plan_sha256,
                "approval_id": action.approval_id,
                "approval_sha256": action.approval_sha256,
                "authorization_id": action.authorization_id,
                "authorization_sha256": action.authorization_sha256,
                "consumption_id": action.consumption_id,
                "consumption_sha256": action.consumption_sha256,
                "admission_id": admission["admission_id"],
                "admission_sha256": admission["admission_sha256"],
                "dispatch_bundle_sha256": action.dispatch_bundle_sha256,
                "action_envelope_sha256": action.action_envelope_sha256,
                "targets": plain_json(action.targets),
                "exclusions": plain_json(action.exclusions),
            }
            if any(outcome.get(key) != value for key, value in outcome_bindings.items()):
                raise SimulatorRepositoryError("stored-outcome-binding")

            intents = [document for kind, document in records.values() if kind == "intent"]
            receipts = [document for kind, document in records.values() if kind == "receipt"]
            intent = None if not intents else intents[0]
            receipt = None if not receipts else receipts[0]
            if len(intents) > 1 or len(receipts) > 1:
                raise SimulatorRepositoryError("stored-outcome-binding")
            if (
                outcome["publication_intent_id"]
                != (None if intent is None else intent["intent_id"])
                or outcome["publication_intent_sha256"]
                != (None if intent is None else intent["intent_sha256"])
                or outcome["publication_receipt_id"]
                != (None if receipt is None else receipt["receipt_id"])
                or outcome["publication_receipt_sha256"]
                != (None if receipt is None else receipt["receipt_sha256"])
            ):
                raise SimulatorRepositoryError("stored-outcome-binding")
            if status == "succeeded":
                if intent is None or receipt is None or receipt["state"] != "promoted":
                    raise SimulatorRepositoryError("stored-outcome-binding")
                projection = {
                    "fixture_id": intent["fixture_id"],
                    "predecessor_publication_pointer_sha256": intent["predecessor_pointer_sha256"],
                    "predecessor_publication_generation": intent["predecessor_generation"],
                    "candidate_publication_pointer_sha256": intent["candidate_pointer_sha256"],
                    "candidate_publication_generation": intent["candidate_generation"],
                    "source_generation": intent["predecessor_generation"],
                    "candidate_generation": intent["candidate_generation"],
                    "source_batch_id": intent["source_batch_id"],
                    "source_batch_sha256": intent["source_batch_sha256"],
                    "active_publication_pointer_sha256": receipt["after_pointer_sha256"],
                    "active_runtime_manifest_sha256": intent["candidate_runtime_manifest_sha256"],
                    "candidate_fixture_manifest_sha256": intent[
                        "candidate_fixture_manifest_sha256"
                    ],
                    "candidate_runtime_manifest_sha256": intent[
                        "candidate_runtime_manifest_sha256"
                    ],
                    "candidate_lineage_manifest_sha256": intent[
                        "candidate_lineage_manifest_sha256"
                    ],
                    "declared_resource_manifest_sha256": intent[
                        "declared_resource_manifest_sha256"
                    ],
                    "preservation_manifest_sha256": intent["preservation_manifest_sha256"],
                    "safe_complement_before_sha256": intent["safe_complement_before_sha256"],
                    "safe_complement_after_sha256": intent["safe_complement_after_sha256"],
                    "safe_complement_proof_sha256": intent["safe_complement_proof_sha256"],
                    "candidate_seal_sha256": intent["candidate_seal_sha256"],
                    "candidate_tree_sha256": intent["candidate_tree_sha256"],
                    "command_outcomes": intent["command_results"],
                    "new_trace_ids": sorted(
                        cast(str, result["trace_id"])
                        for result in cast(Sequence[Mapping[str, Any]], intent["command_results"])
                    ),
                    "publication_promoted_at": receipt["promoted_at"],
                }
                if any(outcome.get(key) != value for key, value in projection.items()):
                    raise SimulatorRepositoryError("stored-outcome-projection")
                command_results = cast(Sequence[Mapping[str, Any]], outcome["command_outcomes"])
                result_kinds = [result["result_kind"] for result in command_results]
                if (
                    result_kinds.count("quarantine") != 1
                    or result_kinds.count("frame") != 3
                    or result_kinds.count("derivative") != 1
                    or {canonical_json_bytes(result["target"]) for result in command_results}
                    != {canonical_json_bytes(target) for target in action.targets}
                ):
                    raise SimulatorRepositoryError("stored-outcome-projection")

    @classmethod
    def _admission_for_action(
        cls, connection: sqlite3.Connection, action_id: str
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT document FROM simulator_admissions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            raise SimulatorRepositoryError("admission-not-found")
        return cls.decode(row["document"])

    @classmethod
    def _replay_admission(
        cls,
        connection: sqlite3.Connection,
        identity: DispatchIdentity,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256, action_id, admission_sha256, result "
            "FROM simulator_idempotency WHERE idempotency_key = ?",
            (identity.task_key,),
        ).fetchone()
        if row is None:
            conflict = connection.execute(
                "SELECT 1 FROM simulator_actions WHERE task_key = ?", (identity.task_key,)
            ).fetchone()
            if conflict is not None:
                raise SimulatorRepositoryError("idempotency-record-missing")
            return None
        if row["request_sha256"] != cls._request_sha256(identity):
            raise SimulatorRepositoryError("idempotency-conflict")
        cls._validate_history(connection, cast(str, row["action_id"]))
        admission = cls._admission_for_action(connection, cast(str, row["action_id"]))
        encoded = canonical_json_bytes(admission)
        if (
            admission["admission_sha256"] != row["admission_sha256"]
            or not isinstance(row["result"], bytes)
            or row["result"] != encoded
        ):
            raise SimulatorRepositoryError("idempotency-result-invalid")
        return admission

    def replay_admission(self, identity: DispatchIdentity) -> dict[str, Any] | None:
        if stable_action_id(identity) == "":  # validates the exact identity shape
            raise AssertionError("unreachable")
        with self.transaction(write=False) as connection:
            return self._replay_admission(connection, identity)

    def admit(
        self,
        bundle: ValidatedDispatchBundle,
        *,
        executor_actor: Mapping[str, Any],
        admitted_at: datetime | str,
    ) -> dict[str, Any]:
        action = bundle.action
        stored_action = action_from_bundle(bundle.document)
        if stored_action != action:
            raise SimulatorRepositoryError("dispatch-bundle-binding")
        now = normalize_time(admitted_at)
        if set(executor_actor) != {"issuer", "subject", "audience", "kind"}:
            raise SimulatorRepositoryError("executor-actor-invalid")
        normalized_actor: dict[str, str] = {}
        for key, maximum in (("issuer", 512), ("subject", 255), ("audience", 255)):
            value = executor_actor.get(key)
            if (
                not isinstance(value, str)
                or not value
                or len(value) > maximum
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise SimulatorRepositoryError("executor-actor-invalid")
            normalized_actor[key] = value
        if executor_actor.get("kind") != "service":
            raise SimulatorRepositoryError("executor-actor-invalid")
        normalized_actor["kind"] = "service"
        request_sha256 = self._request_sha256(action.identity)
        admission = self._build_admission(
            action,
            executor_actor=normalized_actor,
            admitted_at=now,
        )
        encoded_admission = canonical_json_bytes(admission)
        with self.transaction(write=True) as connection:
            replay = self._replay_admission(connection, action.identity)
            if replay is not None:
                return replay
            connection.execute(
                "INSERT INTO simulator_actions("
                "action_id, task_key, operation_id, payload_sha256, incident_id, "
                "incident_version, plan_id, "
                "plan_version, plan_sha256, approval_sha256, authorization_sha256, "
                "consumption_sha256, bundle_sha256, status, admitted_at, updated_at, "
                "bundle_document) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "'queued', ?, ?, ?)",
                (
                    action.action_id,
                    action.identity.task_key,
                    action.identity.operation_id,
                    action.identity.payload_sha256,
                    action.incident_id,
                    action.incident_version,
                    action.plan_id,
                    action.plan_version,
                    action.plan_sha256,
                    action.approval_sha256,
                    action.authorization_sha256,
                    action.consumption_sha256,
                    action.dispatch_bundle_sha256,
                    now,
                    now,
                    canonical_json_bytes(bundle.document),
                ),
            )
            connection.execute(
                "INSERT INTO simulator_admissions("
                "admission_id, action_id, admission_sha256, document) VALUES (?, ?, ?, ?)",
                (
                    admission["admission_id"],
                    action.action_id,
                    admission["admission_sha256"],
                    encoded_admission,
                ),
            )
            self._append_audit(
                connection,
                action_id=action.action_id,
                event_type="dispatch.admitted",
                record_sha256=cast(str, admission["admission_sha256"]),
                actor_id=normalized_actor["subject"],
                claim_generation=None,
                occurred_at=now,
            )
            connection.execute(
                "INSERT INTO simulator_idempotency("
                "idempotency_key, operation, request_sha256, action_id, admission_sha256, result) "
                "VALUES (?, 'dispatch.admit', ?, ?, ?, ?)",
                (
                    action.identity.task_key,
                    request_sha256,
                    action.action_id,
                    admission["admission_sha256"],
                    encoded_admission,
                ),
            )
            self._validate_history(connection, action.action_id)
            return admission

    @classmethod
    def _action_row(
        cls,
        connection: sqlite3.Connection,
        action_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM simulator_actions WHERE action_id = ?", (action_id,)
        ).fetchone()
        if row is None:
            raise SimulatorRepositoryError("action-not-found")
        return cast(sqlite3.Row, row)

    @classmethod
    def _assert_identity(cls, row: sqlite3.Row, identity: DispatchIdentity) -> None:
        if (
            stable_action_id(identity) != row["action_id"]
            or identity.task_key != row["task_key"]
            or identity.operation_id != row["operation_id"]
            or identity.payload_sha256 != row["payload_sha256"]
        ):
            raise SimulatorRepositoryError("action-identity-conflict")

    @classmethod
    def _assert_claim(
        cls,
        connection: sqlite3.Connection,
        claim: ActionClaim,
        *,
        now: str,
    ) -> sqlite3.Row:
        row = cls._action_row(connection, claim.action_id)
        cls._assert_identity(row, claim.identity)
        if (
            row["status"] not in {"running", "publication_pending"}
            or row["claim_owner"] != claim.owner
            or row["claim_generation"] != claim.generation
            or row["claim_expires_at"] != claim.lease_expires_at
            or row["bundle_sha256"] != claim.dispatch_bundle_sha256
        ):
            raise SimulatorRepositoryError("claim-fenced")
        current = _parse_time(now, code="claim-time-invalid")
        updated = _parse_time(row["updated_at"], code="stored-claim-time-invalid")
        expiry = _parse_time(row["claim_expires_at"], code="stored-claim-time-invalid")
        if current < updated:
            raise SimulatorRepositoryError("claim-clock-regression")
        if current >= expiry:
            raise SimulatorRepositoryError("claim-expired")
        return row

    def load_action(self, identity: DispatchIdentity) -> BoundSimulatorAction:
        action_id = stable_action_id(identity)
        with self.transaction(write=False) as connection:
            self._validate_history(connection, action_id)
            row = self._action_row(connection, action_id)
            self._assert_identity(row, identity)
            return action_from_bundle(self.decode(row["bundle_document"]))

    def claim_action(
        self,
        action: BoundSimulatorAction,
        *,
        owner: str,
        now: datetime | str,
    ) -> ActionClaim:
        owner_value = _require_identifier(owner, code="claim-owner-invalid")
        now_value = normalize_time(now, code="claim-time-invalid")
        expires_at = _claim_expiry(now_value)
        with self.transaction(write=True) as connection:
            self._validate_history(connection, action.action_id)
            row = self._action_row(connection, action.action_id)
            self._assert_identity(row, action.identity)
            if row["bundle_sha256"] != action.dispatch_bundle_sha256:
                raise SimulatorRepositoryError("action-bundle-conflict")
            if row["status"] in {"succeeded", "failed"}:
                raise SimulatorRepositoryError("action-complete")
            updated = _parse_time(row["updated_at"], code="stored-claim-time-invalid")
            current = _parse_time(now_value, code="claim-time-invalid")
            if current < updated:
                raise SimulatorRepositoryError("claim-clock-regression")
            if row["status"] == "queued":
                generation = 1
                changed = connection.execute(
                    "UPDATE simulator_actions SET status = 'running', claim_owner = ?, "
                    "claim_generation = 1, claim_expires_at = ?, started_at = ?, updated_at = ? "
                    "WHERE action_id = ? AND status = 'queued' AND claim_owner IS NULL "
                    "AND claim_generation = 0 AND claim_expires_at IS NULL",
                    (owner_value, expires_at, now_value, now_value, action.action_id),
                )
                event_type = "claim.acquired"
            else:
                current_expiry = _parse_time(
                    row["claim_expires_at"], code="stored-claim-time-invalid"
                )
                if current < current_expiry:
                    raise SimulatorRepositoryError("action-in-progress")
                generation = cast(int, row["claim_generation"]) + 1
                changed = connection.execute(
                    "UPDATE simulator_actions SET claim_owner = ?, claim_generation = ?, "
                    "claim_expires_at = ?, updated_at = ? WHERE action_id = ? "
                    "AND status = ? AND claim_owner = ? AND claim_generation = ? "
                    "AND claim_expires_at = ?",
                    (
                        owner_value,
                        generation,
                        expires_at,
                        now_value,
                        action.action_id,
                        row["status"],
                        row["claim_owner"],
                        row["claim_generation"],
                        row["claim_expires_at"],
                    ),
                )
                event_type = "claim.reclaimed"
            if changed.rowcount != 1:
                raise SimulatorRepositoryError("claim-fenced")
            self._append_claim_event(
                connection,
                action_id=action.action_id,
                event_type=event_type,
                owner=owner_value,
                generation=generation,
                lease_expires_at=expires_at,
                occurred_at=now_value,
            )
            has_intent = connection.execute(
                "SELECT 1 FROM simulator_publication_intents WHERE action_id = ?",
                (action.action_id,),
            ).fetchone()
            self._validate_history(connection, action.action_id)
            return ActionClaim(
                action_id=action.action_id,
                identity=action.identity,
                owner=owner_value,
                generation=generation,
                lease_expires_at=expires_at,
                phase="reconcile" if has_intent is not None else "execute",
                dispatch_bundle_sha256=action.dispatch_bundle_sha256,
            )

    def renew_claim(
        self,
        claim: ActionClaim,
        *,
        now: datetime | str,
    ) -> ActionClaim:
        now_value = normalize_time(now, code="claim-time-invalid")
        next_expiry = _claim_expiry(now_value)
        with self.transaction(write=True) as connection:
            self._validate_history(connection, claim.action_id)
            row = self._assert_claim(connection, claim, now=now_value)
            current_expiry = cast(str, row["claim_expires_at"])
            if _parse_time(next_expiry, code="claim-time-invalid") <= _parse_time(
                current_expiry, code="stored-claim-time-invalid"
            ):
                return claim
            changed = connection.execute(
                "UPDATE simulator_actions SET claim_expires_at = ?, updated_at = ? "
                "WHERE action_id = ? AND status = ? AND claim_owner = ? "
                "AND claim_generation = ? AND claim_expires_at = ?",
                (
                    next_expiry,
                    now_value,
                    claim.action_id,
                    row["status"],
                    claim.owner,
                    claim.generation,
                    current_expiry,
                ),
            )
            if changed.rowcount != 1:
                raise SimulatorRepositoryError("claim-fenced")
            self._append_claim_event(
                connection,
                action_id=claim.action_id,
                event_type="claim.renewed",
                owner=claim.owner,
                generation=claim.generation,
                lease_expires_at=next_expiry,
                occurred_at=now_value,
            )
            self._validate_history(connection, claim.action_id)
            return ActionClaim(
                action_id=claim.action_id,
                identity=claim.identity,
                owner=claim.owner,
                generation=claim.generation,
                lease_expires_at=next_expiry,
                phase=claim.phase,
                dispatch_bundle_sha256=claim.dispatch_bundle_sha256,
            )

    def cancel_claim(self, claim: ActionClaim, *, now: datetime | str) -> None:
        now_value = normalize_time(now, code="claim-time-invalid")
        with self.transaction(write=True) as connection:
            self._validate_history(connection, claim.action_id)
            row = self._assert_claim(connection, claim, now=now_value)
            effective_expiry = min(
                (cast(str, row["claim_expires_at"]), now_value),
                key=lambda value: _parse_time(value, code="claim-time-invalid"),
            )
            changed = connection.execute(
                "UPDATE simulator_actions SET claim_expires_at = ?, updated_at = ? "
                "WHERE action_id = ? AND status = ? AND claim_owner = ? "
                "AND claim_generation = ? AND claim_expires_at = ?",
                (
                    effective_expiry,
                    now_value,
                    claim.action_id,
                    row["status"],
                    claim.owner,
                    claim.generation,
                    row["claim_expires_at"],
                ),
            )
            if changed.rowcount != 1:
                raise SimulatorRepositoryError("claim-fenced")
            self._append_claim_event(
                connection,
                action_id=claim.action_id,
                event_type="claim.cancelled",
                owner=claim.owner,
                generation=claim.generation,
                lease_expires_at=effective_expiry,
                occurred_at=now_value,
            )
            self._validate_history(connection, claim.action_id)

    @staticmethod
    def _action_envelope(bundle: Mapping[str, Any]) -> Mapping[str, Any]:
        authorization = cast(Mapping[str, Any], bundle["authorization"])
        commands = cast(Sequence[Mapping[str, Any]], authorization["commands"])
        if not commands:
            raise SimulatorRepositoryError("action-commands-empty")
        envelope = cast(Mapping[str, Any], commands[0]["action_envelope"])
        if any(command.get("action_envelope") != envelope for command in commands):
            raise SimulatorRepositoryError("action-envelope-conflict")
        return envelope

    @staticmethod
    def _validate_result_digests(value: Mapping[str, Any], *, keys: frozenset[str]) -> None:
        if set(value) != keys:
            raise SimulatorRepositoryError("command-result-shape-invalid")
        for child in value.values():
            try:
                require_digest(child)
            except SimulatorAuthorityError as error:
                raise SimulatorRepositoryError("command-result-digest-invalid") from error

    @classmethod
    def _validate_command_results(
        cls,
        action: BoundSimulatorAction,
        prepared: PreparedPublication,
    ) -> list[dict[str, Any]]:
        results = cast(list[dict[str, Any]], plain_json(prepared.command_results))
        if [result.get("command_id") for result in results] != sorted(
            cast(str, command["command_id"]) for command in action.commands
        ):
            raise SimulatorRepositoryError("command-result-binding")
        commands = {cast(str, command["command_id"]): command for command in action.commands}
        traces: set[str] = set()
        for result in results:
            if (
                set(result)
                != {
                    "schema",
                    "command_id",
                    "result_kind",
                    "target",
                    "trace_id",
                    "before",
                    "after",
                }
                or result.get("schema") != "simulator-command-result/v1"
            ):
                raise SimulatorRepositoryError("command-result-shape-invalid")
            command_id = result.get("command_id")
            if (
                command_id not in commands
                or result.get("target") != commands[cast(str, command_id)]["target"]
            ):
                raise SimulatorRepositoryError("command-result-binding")
            trace_id = result.get("trace_id")
            if (
                not isinstance(trace_id, str)
                or re.fullmatch(r"[0-9a-f]{32}", trace_id) is None
                or trace_id in traces
            ):
                raise SimulatorRepositoryError("command-result-trace-invalid")
            traces.add(trace_id)
            target = cast(Mapping[str, Any], result["target"])
            kind = target.get("kind")
            before = cast(Mapping[str, Any], result["before"])
            after = cast(Mapping[str, Any], result["after"])
            if kind == "color-resource":
                if result.get("result_kind") != "quarantine":
                    raise SimulatorRepositoryError("command-result-kind-invalid")
                cls._validate_result_digests(before, keys=frozenset({"resource_sha256"}))
                cls._validate_result_digests(after, keys=frozenset({"resource_sha256"}))
            elif kind == "frame":
                if result.get("result_kind") != "frame":
                    raise SimulatorRepositoryError("command-result-kind-invalid")
                keys = frozenset({"output_sha256", "display_sha256"})
                cls._validate_result_digests(before, keys=keys)
                cls._validate_result_digests(after, keys=keys)
            elif kind == "derivative":
                if result.get("result_kind") != "derivative":
                    raise SimulatorRepositoryError("command-result-kind-invalid")
                keys = frozenset({"derivative_sha256", "derivative_display_sha256"})
                cls._validate_result_digests(before, keys=keys)
                cls._validate_result_digests(after, keys=keys)
            else:
                raise SimulatorRepositoryError("command-result-kind-invalid")
        return results

    @classmethod
    def _build_intent(
        cls,
        *,
        claim: ActionClaim,
        action: BoundSimulatorAction,
        envelope: Mapping[str, Any],
        prepared: PreparedPublication,
    ) -> dict[str, Any]:
        if prepared.operation_id != action.identity.operation_id:
            raise SimulatorRepositoryError("publication-operation-conflict")
        try:
            expected = {
                "predecessor_pointer_sha256": envelope["expected_publication_pointer_sha256"],
                "predecessor_generation": envelope["expected_publication_generation"],
                "source_batch_id": envelope["source_batch_id"],
                "source_batch_sha256": envelope["source_batch_sha256"],
                "declared_resource_manifest_sha256": envelope["declared_resource_manifest_sha256"],
                "preservation_manifest_sha256": envelope["preservation_manifest_sha256"],
                "safe_complement_before_sha256": envelope["safe_complement_sha256"],
            }
            fixture_id = _require_identifier(envelope["fixture_id"], code="action-envelope-invalid")
            predecessor_fixture_manifest_sha256 = require_digest(
                envelope["fixture_manifest_sha256"]
            )
        except KeyError as error:
            raise SimulatorRepositoryError("action-envelope-invalid") from error
        if any(getattr(prepared, key) != value for key, value in expected.items()):
            raise SimulatorRepositoryError("publication-precondition-conflict")
        if (
            prepared.candidate_generation != prepared.predecessor_generation + 1
            or prepared.safe_complement_after_sha256 != prepared.safe_complement_before_sha256
        ):
            raise SimulatorRepositoryError("publication-preservation-conflict")
        for digest in (
            prepared.predecessor_pointer_sha256,
            prepared.source_batch_sha256,
            prepared.candidate_fixture_manifest_sha256,
            prepared.candidate_runtime_manifest_sha256,
            prepared.candidate_lineage_manifest_sha256,
            prepared.declared_resource_manifest_sha256,
            prepared.preservation_manifest_sha256,
            prepared.safe_complement_before_sha256,
            prepared.safe_complement_after_sha256,
            prepared.safe_complement_proof_sha256,
            prepared.candidate_seal_sha256,
            prepared.candidate_tree_sha256,
            prepared.candidate_pointer_sha256,
        ):
            require_digest(digest)
        if (
            prefixed_sha256(canonical_json_bytes(prepared.predecessor_pointer))
            != prepared.predecessor_pointer_sha256
        ):
            raise SimulatorRepositoryError("publication-predecessor-digest")
        if (
            prefixed_sha256(canonical_json_bytes(prepared.candidate_pointer))
            != prepared.candidate_pointer_sha256
        ):
            raise SimulatorRepositoryError("publication-candidate-digest")
        _require_identifier(prepared.publication_id, code="publication-id-invalid")
        _require_identifier(prepared.candidate_ref, code="publication-candidate-ref-invalid")
        prepared_at = normalize_time(prepared.prepared_at, code="publication-time-invalid")
        quarantine = cast(dict[str, Any], plain_json(prepared.quarantine))
        if set(quarantine) != {
            "schema",
            "logical_path",
            "source_generation",
            "resource_sha256",
            "replacement_sha256",
            "quarantine_path",
            "size",
        } or (
            quarantine.get("schema") != "simulator-quarantine-result/v1"
            or quarantine.get("logical_path") != "luts/show_look.cube"
            or quarantine.get("source_generation") != prepared.predecessor_generation
            or quarantine.get("resource_sha256") != envelope["expected_resource_sha256"]
            or quarantine.get("replacement_sha256") != envelope["replacement_resource_sha256"]
            or not isinstance(quarantine.get("size"), int)
            or isinstance(quarantine.get("size"), bool)
            or cast(int, quarantine["size"]) < 1
        ):
            raise SimulatorRepositoryError("quarantine-result-invalid")
        old_suffix = cast(str, quarantine["resource_sha256"]).removeprefix("sha256:")
        if quarantine.get("quarantine_path") != f"runtime/quarantine/sha256/{old_suffix}.cube":
            raise SimulatorRepositoryError("quarantine-path-invalid")
        results = cls._validate_command_results(action, prepared)
        quarantine_results = [result for result in results if result["result_kind"] == "quarantine"]
        if len(quarantine_results) != 1 or (
            quarantine_results[0]["before"] != {"resource_sha256": quarantine["resource_sha256"]}
            or quarantine_results[0]["after"]
            != {"resource_sha256": quarantine["replacement_sha256"]}
        ):
            raise SimulatorRepositoryError("quarantine-command-binding")

        body = {
            "schema": "simulator-publication-intent/v1",
            "action_id": action.action_id,
            "operation_id": action.identity.operation_id,
            "claim_generation": claim.generation,
            "dispatch_bundle_sha256": action.dispatch_bundle_sha256,
            "action_envelope_sha256": action.action_envelope_sha256,
            "publication_id": prepared.publication_id,
            "predecessor_pointer": plain_json(prepared.predecessor_pointer),
            "predecessor_pointer_sha256": prepared.predecessor_pointer_sha256,
            "predecessor_generation": prepared.predecessor_generation,
            "candidate_generation": prepared.candidate_generation,
            "fixture_id": fixture_id,
            "source_batch_id": prepared.source_batch_id,
            "source_batch_sha256": prepared.source_batch_sha256,
            "predecessor_fixture_manifest_sha256": predecessor_fixture_manifest_sha256,
            "candidate_fixture_manifest_sha256": prepared.candidate_fixture_manifest_sha256,
            "candidate_runtime_manifest_sha256": prepared.candidate_runtime_manifest_sha256,
            "candidate_lineage_manifest_sha256": prepared.candidate_lineage_manifest_sha256,
            "declared_resource_manifest_sha256": prepared.declared_resource_manifest_sha256,
            "preservation_manifest_sha256": prepared.preservation_manifest_sha256,
            "safe_complement_before_sha256": prepared.safe_complement_before_sha256,
            "safe_complement_after_sha256": prepared.safe_complement_after_sha256,
            "safe_complement_proof_sha256": prepared.safe_complement_proof_sha256,
            "candidate_seal_sha256": prepared.candidate_seal_sha256,
            "candidate_tree_sha256": prepared.candidate_tree_sha256,
            "candidate_ref": prepared.candidate_ref,
            "quarantine": quarantine,
            "command_results": results,
            "candidate_pointer": plain_json(prepared.candidate_pointer),
            "candidate_pointer_sha256": prepared.candidate_pointer_sha256,
            "prepared_at": prepared_at,
        }
        digest = prefixed_sha256(canonical_json_bytes(body))
        intent = {
            **body,
            "intent_id": f"simulator-publication-intent:{digest.removeprefix('sha256:')}",
            "intent_sha256": digest,
        }
        validate_schema("simulator-publication-intent-v1.schema.json", intent)
        return intent

    @staticmethod
    def prepared_from_intent(intent: Mapping[str, Any]) -> PreparedPublication:
        return PreparedPublication(
            operation_id=cast(str, intent["operation_id"]),
            publication_id=cast(str, intent["publication_id"]),
            predecessor_pointer=cast(Mapping[str, Any], plain_json(intent["predecessor_pointer"])),
            predecessor_pointer_sha256=cast(str, intent["predecessor_pointer_sha256"]),
            predecessor_generation=cast(int, intent["predecessor_generation"]),
            candidate_generation=cast(int, intent["candidate_generation"]),
            source_batch_id=cast(str, intent["source_batch_id"]),
            source_batch_sha256=cast(str, intent["source_batch_sha256"]),
            candidate_fixture_manifest_sha256=cast(
                str, intent["candidate_fixture_manifest_sha256"]
            ),
            candidate_runtime_manifest_sha256=cast(
                str, intent["candidate_runtime_manifest_sha256"]
            ),
            candidate_lineage_manifest_sha256=cast(
                str, intent["candidate_lineage_manifest_sha256"]
            ),
            declared_resource_manifest_sha256=cast(
                str, intent["declared_resource_manifest_sha256"]
            ),
            preservation_manifest_sha256=cast(str, intent["preservation_manifest_sha256"]),
            safe_complement_before_sha256=cast(str, intent["safe_complement_before_sha256"]),
            safe_complement_after_sha256=cast(str, intent["safe_complement_after_sha256"]),
            safe_complement_proof_sha256=cast(str, intent["safe_complement_proof_sha256"]),
            candidate_seal_sha256=cast(str, intent["candidate_seal_sha256"]),
            candidate_tree_sha256=cast(str, intent["candidate_tree_sha256"]),
            candidate_ref=cast(str, intent["candidate_ref"]),
            quarantine=cast(Mapping[str, Any], plain_json(intent["quarantine"])),
            command_results=tuple(
                cast(Sequence[Mapping[str, Any]], plain_json(intent["command_results"]))
            ),
            candidate_pointer=cast(Mapping[str, Any], plain_json(intent["candidate_pointer"])),
            candidate_pointer_sha256=cast(str, intent["candidate_pointer_sha256"]),
            prepared_at=cast(str, intent["prepared_at"]),
        )

    def record_publication_intent(
        self,
        claim: ActionClaim,
        prepared: PreparedPublication,
        *,
        now: datetime | str,
    ) -> dict[str, Any]:
        now_value = normalize_time(now, code="publication-time-invalid")
        with self.transaction(write=True) as connection:
            self._validate_history(connection, claim.action_id)
            row = self._assert_claim(connection, claim, now=now_value)
            action = action_from_bundle(self.decode(row["bundle_document"]))
            envelope = self._action_envelope(self.decode(row["bundle_document"]))
            intent = self._build_intent(
                claim=claim,
                action=action,
                envelope=envelope,
                prepared=prepared,
            )
            existing = connection.execute(
                "SELECT document FROM simulator_publication_intents WHERE action_id = ?",
                (claim.action_id,),
            ).fetchone()
            if existing is not None:
                stored = self.decode(existing["document"])
                if stored != intent:
                    raise SimulatorRepositoryError("publication-intent-conflict")
                return stored
            if row["status"] != "running":
                raise SimulatorRepositoryError("publication-state-conflict")
            connection.execute(
                "INSERT INTO simulator_publication_intents("
                "intent_id, action_id, claim_generation, intent_sha256, "
                "expected_pointer_sha256, expected_generation, candidate_pointer_sha256, "
                "candidate_generation, document) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    intent["intent_id"],
                    claim.action_id,
                    claim.generation,
                    intent["intent_sha256"],
                    intent["predecessor_pointer_sha256"],
                    intent["predecessor_generation"],
                    intent["candidate_pointer_sha256"],
                    intent["candidate_generation"],
                    canonical_json_bytes(intent),
                ),
            )
            changed = connection.execute(
                "UPDATE simulator_actions SET status = 'publication_pending', updated_at = ? "
                "WHERE action_id = ? AND status = 'running' AND claim_owner = ? "
                "AND claim_generation = ? AND claim_expires_at = ?",
                (
                    now_value,
                    claim.action_id,
                    claim.owner,
                    claim.generation,
                    claim.lease_expires_at,
                ),
            )
            if changed.rowcount != 1:
                raise SimulatorRepositoryError("claim-fenced")
            self._append_audit(
                connection,
                action_id=claim.action_id,
                event_type="publication.prepared",
                record_sha256=cast(str, intent["intent_sha256"]),
                actor_id=claim.owner,
                claim_generation=claim.generation,
                occurred_at=now_value,
            )
            self._validate_history(connection, claim.action_id)
            return intent

    @classmethod
    def _build_receipt(
        cls,
        *,
        action_id: str,
        intent: Mapping[str, Any],
        result: PromotionResult,
    ) -> dict[str, Any]:
        observed_at = normalize_time(result.observed_at, code="publication-time-invalid")
        promoted_at = (
            None
            if result.promoted_at is None
            else normalize_time(result.promoted_at, code="publication-time-invalid")
        )
        predecessor_sha = cast(str, intent["predecessor_pointer_sha256"])
        predecessor_generation = cast(int, intent["predecessor_generation"])
        candidate_sha = cast(str, intent["candidate_pointer_sha256"])
        candidate_generation = cast(int, intent["candidate_generation"])
        if result.state == "promoted":
            valid = (
                result.before_pointer_sha256 == predecessor_sha
                and result.before_generation == predecessor_generation
                and result.after_pointer_sha256 == candidate_sha
                and result.after_generation == candidate_generation
                and result.pointer_changed
                and not result.recovered
                and promoted_at is not None
            )
            receipt_state = "promoted"
        elif result.state == "already-promoted":
            valid = (
                result.before_pointer_sha256 == candidate_sha
                and result.before_generation == candidate_generation
                and result.after_pointer_sha256 == candidate_sha
                and result.after_generation == candidate_generation
                and not result.pointer_changed
                and result.recovered
                and promoted_at is not None
            )
            receipt_state = "promoted"
        elif result.state == "conflict":
            valid = (
                result.before_pointer_sha256 == result.after_pointer_sha256
                and result.before_generation == result.after_generation
                and result.after_pointer_sha256 not in {predecessor_sha, candidate_sha}
                and not result.pointer_changed
                and not result.recovered
                and promoted_at is None
            )
            receipt_state = "conflict"
        else:  # pragma: no cover - the dataclass type is closed
            valid = False
            receipt_state = "conflict"
        if not valid:
            raise SimulatorRepositoryError("publication-result-invalid")
        require_digest(result.before_pointer_sha256)
        require_digest(result.after_pointer_sha256)
        body = {
            "schema": "simulator-publication-receipt/v1",
            "action_id": action_id,
            "intent_id": intent["intent_id"],
            "intent_sha256": intent["intent_sha256"],
            "state": receipt_state,
            "before_pointer_sha256": result.before_pointer_sha256,
            "before_generation": result.before_generation,
            "after_pointer_sha256": result.after_pointer_sha256,
            "after_generation": result.after_generation,
            "pointer_changed": result.pointer_changed,
            "recovered": result.recovered,
            "promoted_at": promoted_at,
            "observed_at": observed_at,
        }
        digest = prefixed_sha256(canonical_json_bytes(body))
        receipt = {
            **body,
            "receipt_id": f"simulator-publication-receipt:{digest.removeprefix('sha256:')}",
            "receipt_sha256": digest,
        }
        validate_schema("simulator-publication-receipt-v1.schema.json", receipt)
        return receipt

    @classmethod
    def _build_outcome(
        cls,
        *,
        action: BoundSimulatorAction,
        admission: Mapping[str, Any],
        started_at: str,
        completed_at: str,
        status: str,
        reason_codes: Sequence[str],
        intent: Mapping[str, Any] | None,
        receipt: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        reasons = sorted(
            {_require_identifier(value, code="outcome-reason-invalid") for value in reason_codes}
        )
        if (
            len(reasons) != len(reason_codes)
            or len(reasons) > 32
            or any(_REASON.fullmatch(value) is None for value in reasons)
        ):
            raise SimulatorRepositoryError("outcome-reason-invalid")
        if status not in {"succeeded", "failed"} or (status == "succeeded") == bool(reasons):
            raise SimulatorRepositoryError("outcome-status-invalid")
        if status == "succeeded" and (
            intent is None or receipt is None or receipt.get("state") != "promoted"
        ):
            raise SimulatorRepositoryError("outcome-promotion-required")
        started_value = normalize_time(started_at, code="outcome-time-invalid")
        completed_value = normalize_time(completed_at, code="outcome-time-invalid")
        if _parse_time(completed_value, code="outcome-time-invalid") < _parse_time(
            started_value, code="outcome-time-invalid"
        ):
            raise SimulatorRepositoryError("outcome-time-invalid")
        succeeded = status == "succeeded"
        projection = intent if succeeded else None
        command_results = (
            cast(list[dict[str, Any]], projection["command_results"])
            if projection is not None
            else []
        )
        trace_ids = sorted(cast(str, result["trace_id"]) for result in command_results)
        if len(trace_ids) != len(set(trace_ids)):
            raise SimulatorRepositoryError("outcome-trace-duplicate")
        promoted_at = receipt["promoted_at"] if succeeded and receipt is not None else None
        if promoted_at is not None and not (
            _parse_time(started_value, code="outcome-time-invalid")
            <= _parse_time(promoted_at, code="outcome-time-invalid")
            <= _parse_time(completed_value, code="outcome-time-invalid")
        ):
            raise SimulatorRepositoryError("outcome-time-invalid")
        body = {
            "schema": "simulator-action-outcome/v1",
            "action_id": action.action_id,
            "task_key": action.identity.task_key,
            "operation_id": action.identity.operation_id,
            "payload_sha256": action.identity.payload_sha256,
            "status": status,
            "reason_codes": reasons,
            "incident_id": action.incident_id,
            "incident_version": action.incident_version,
            "plan_id": action.plan_id,
            "plan_version": action.plan_version,
            "plan_sha256": action.plan_sha256,
            "approval_id": action.approval_id,
            "approval_sha256": action.approval_sha256,
            "authorization_id": action.authorization_id,
            "authorization_sha256": action.authorization_sha256,
            "consumption_id": action.consumption_id,
            "consumption_sha256": action.consumption_sha256,
            "admission_id": admission["admission_id"],
            "admission_sha256": admission["admission_sha256"],
            "dispatch_bundle_sha256": action.dispatch_bundle_sha256,
            "action_envelope_sha256": action.action_envelope_sha256,
            "action_started_at": started_value,
            "publication_intent_id": None if intent is None else intent["intent_id"],
            "publication_intent_sha256": None if intent is None else intent["intent_sha256"],
            "publication_receipt_id": None if receipt is None else receipt["receipt_id"],
            "publication_receipt_sha256": None if receipt is None else receipt["receipt_sha256"],
            "publication_promoted_at": promoted_at,
            "completed_at": completed_value,
            "fixture_id": None if projection is None else projection["fixture_id"],
            "predecessor_publication_pointer_sha256": (
                None if projection is None else projection["predecessor_pointer_sha256"]
            ),
            "predecessor_publication_generation": (
                None if projection is None else projection["predecessor_generation"]
            ),
            "candidate_publication_pointer_sha256": (
                None if projection is None else projection["candidate_pointer_sha256"]
            ),
            "candidate_publication_generation": (
                None if projection is None else projection["candidate_generation"]
            ),
            "source_generation": (
                None if projection is None else projection["predecessor_generation"]
            ),
            "candidate_generation": (
                None if projection is None else projection["candidate_generation"]
            ),
            "source_batch_id": None if projection is None else projection["source_batch_id"],
            "source_batch_sha256": (
                None if projection is None else projection["source_batch_sha256"]
            ),
            "active_publication_pointer_sha256": (
                receipt["after_pointer_sha256"] if succeeded and receipt is not None else None
            ),
            "active_runtime_manifest_sha256": (
                None if projection is None else projection["candidate_runtime_manifest_sha256"]
            ),
            "candidate_fixture_manifest_sha256": (
                None if projection is None else projection["candidate_fixture_manifest_sha256"]
            ),
            "candidate_runtime_manifest_sha256": (
                None if projection is None else projection["candidate_runtime_manifest_sha256"]
            ),
            "candidate_lineage_manifest_sha256": (
                None if projection is None else projection["candidate_lineage_manifest_sha256"]
            ),
            "declared_resource_manifest_sha256": (
                None if projection is None else projection["declared_resource_manifest_sha256"]
            ),
            "preservation_manifest_sha256": (
                None if projection is None else projection["preservation_manifest_sha256"]
            ),
            "safe_complement_before_sha256": (
                None if projection is None else projection["safe_complement_before_sha256"]
            ),
            "safe_complement_after_sha256": (
                None if projection is None else projection["safe_complement_after_sha256"]
            ),
            "safe_complement_proof_sha256": (
                None if projection is None else projection["safe_complement_proof_sha256"]
            ),
            "candidate_seal_sha256": (
                None if projection is None else projection["candidate_seal_sha256"]
            ),
            "candidate_tree_sha256": (
                None if projection is None else projection["candidate_tree_sha256"]
            ),
            "targets": plain_json(action.targets),
            "exclusions": plain_json(action.exclusions),
            "command_outcomes": plain_json(command_results),
            "new_trace_ids": trace_ids,
        }
        digest = prefixed_sha256(canonical_json_bytes(body))
        outcome = {
            **body,
            "outcome_id": f"simulator-action-outcome:{digest.removeprefix('sha256:')}",
            "outcome_sha256": digest,
        }
        validate_schema("simulator-action-outcome-v1.schema.json", outcome)
        return outcome

    @classmethod
    def _persist_terminal(
        cls,
        connection: sqlite3.Connection,
        *,
        claim: ActionClaim,
        row: sqlite3.Row,
        outcome: Mapping[str, Any],
        completed_at: str,
    ) -> None:
        connection.execute(
            "INSERT INTO simulator_action_outcomes("
            "outcome_id, action_id, status, outcome_sha256, document) VALUES (?, ?, ?, ?, ?)",
            (
                outcome["outcome_id"],
                claim.action_id,
                outcome["status"],
                outcome["outcome_sha256"],
                canonical_json_bytes(outcome),
            ),
        )
        cls._append_audit(
            connection,
            action_id=claim.action_id,
            event_type=f"action.{outcome['status']}",
            record_sha256=cast(str, outcome["outcome_sha256"]),
            actor_id=claim.owner,
            claim_generation=claim.generation,
            occurred_at=completed_at,
        )
        cls._append_claim_event(
            connection,
            action_id=claim.action_id,
            event_type="claim.completed",
            owner=claim.owner,
            generation=claim.generation,
            lease_expires_at=cast(str, row["claim_expires_at"]),
            occurred_at=completed_at,
        )
        changed = connection.execute(
            "UPDATE simulator_actions SET status = ?, claim_expires_at = NULL, "
            "updated_at = ?, outcome_sha256 = ? WHERE action_id = ? AND status = ? "
            "AND claim_owner = ? AND claim_generation = ? AND claim_expires_at = ?",
            (
                outcome["status"],
                completed_at,
                outcome["outcome_sha256"],
                claim.action_id,
                row["status"],
                claim.owner,
                claim.generation,
                row["claim_expires_at"],
            ),
        )
        if changed.rowcount != 1:
            raise SimulatorRepositoryError("claim-fenced")

    def reconcile_publication(
        self,
        claim: ActionClaim,
        *,
        now: datetime | str,
        promote: Callable[[PreparedPublication], PromotionResult],
    ) -> dict[str, Any]:
        now_value = normalize_time(now, code="publication-time-invalid")
        with self.transaction(write=True) as connection:
            existing = connection.execute(
                "SELECT document FROM simulator_action_outcomes WHERE action_id = ?",
                (claim.action_id,),
            ).fetchone()
            if existing is not None:
                self._validate_history(connection, claim.action_id)
                return self.decode(existing["document"])
            self._validate_history(connection, claim.action_id)
            row = self._assert_claim(connection, claim, now=now_value)
            if row["status"] != "publication_pending":
                raise SimulatorRepositoryError("publication-state-conflict")
            intent_row = connection.execute(
                "SELECT document FROM simulator_publication_intents WHERE action_id = ?",
                (claim.action_id,),
            ).fetchone()
            if intent_row is None:
                raise SimulatorRepositoryError("publication-intent-missing")
            intent = self.decode(intent_row["document"])
            prepared = self.prepared_from_intent(intent)
            result = promote(prepared)
            receipt = self._build_receipt(
                action_id=claim.action_id,
                intent=intent,
                result=result,
            )
            connection.execute(
                "INSERT INTO simulator_publication_receipts("
                "receipt_id, action_id, intent_id, state, receipt_sha256, document) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    receipt["receipt_id"],
                    claim.action_id,
                    receipt["intent_id"],
                    receipt["state"],
                    receipt["receipt_sha256"],
                    canonical_json_bytes(receipt),
                ),
            )
            self._append_audit(
                connection,
                action_id=claim.action_id,
                event_type=(
                    "publication.promoted"
                    if receipt["state"] == "promoted"
                    else "publication.conflicted"
                ),
                record_sha256=cast(str, receipt["receipt_sha256"]),
                actor_id=claim.owner,
                claim_generation=claim.generation,
                occurred_at=cast(str, receipt["observed_at"]),
            )
            action = action_from_bundle(self.decode(row["bundle_document"]))
            admission = self._admission_for_action(connection, claim.action_id)
            status = "succeeded" if receipt["state"] == "promoted" else "failed"
            reasons: tuple[str, ...] = (
                () if status == "succeeded" else ("publication-pointer-conflict",)
            )
            completed_at = cast(str, receipt["observed_at"])
            outcome = self._build_outcome(
                action=action,
                admission=admission,
                started_at=cast(str, row["started_at"]),
                completed_at=completed_at,
                status=status,
                reason_codes=reasons,
                intent=intent,
                receipt=receipt,
            )
            self._persist_terminal(
                connection,
                claim=claim,
                row=row,
                outcome=outcome,
                completed_at=completed_at,
            )
            self._validate_history(connection, claim.action_id)
            return outcome

    def fail_action(
        self,
        claim: ActionClaim,
        *,
        reason_codes: Sequence[str],
        now: datetime | str,
    ) -> dict[str, Any]:
        now_value = normalize_time(now, code="outcome-time-invalid")
        with self.transaction(write=True) as connection:
            existing = connection.execute(
                "SELECT document FROM simulator_action_outcomes WHERE action_id = ?",
                (claim.action_id,),
            ).fetchone()
            if existing is not None:
                self._validate_history(connection, claim.action_id)
                return self.decode(existing["document"])
            self._validate_history(connection, claim.action_id)
            row = self._assert_claim(connection, claim, now=now_value)
            if (
                connection.execute(
                    "SELECT 1 FROM simulator_publication_intents WHERE action_id = ?",
                    (claim.action_id,),
                ).fetchone()
                is not None
            ):
                raise SimulatorRepositoryError("publication-intent-present")
            action = action_from_bundle(self.decode(row["bundle_document"]))
            admission = self._admission_for_action(connection, claim.action_id)
            outcome = self._build_outcome(
                action=action,
                admission=admission,
                started_at=cast(str, row["started_at"]),
                completed_at=now_value,
                status="failed",
                reason_codes=reason_codes,
                intent=None,
                receipt=None,
            )
            self._persist_terminal(
                connection,
                claim=claim,
                row=row,
                outcome=outcome,
                completed_at=now_value,
            )
            self._validate_history(connection, claim.action_id)
            return outcome

    def outcome(self, identity: DispatchIdentity) -> dict[str, Any] | None:
        action_id = stable_action_id(identity)
        with self.transaction(write=False) as connection:
            self._validate_history(connection, action_id)
            row = self._action_row(connection, action_id)
            self._assert_identity(row, identity)
            outcome = connection.execute(
                "SELECT document FROM simulator_action_outcomes WHERE action_id = ?",
                (action_id,),
            ).fetchone()
            return None if outcome is None else self.decode(outcome["document"])

    def audit_history(self, identity: DispatchIdentity) -> list[dict[str, Any]]:
        action_id = stable_action_id(identity)
        with self.transaction(write=False) as connection:
            self._validate_history(connection, action_id)
            row = self._action_row(connection, action_id)
            self._assert_identity(row, identity)
            events = connection.execute(
                "SELECT document FROM simulator_action_audit_events "
                "WHERE action_id = ? ORDER BY sequence",
                (action_id,),
            ).fetchall()
            return [self.decode(event["document"]) for event in events]


__all__ = [
    "CLAIM_LEASE_SECONDS",
    "SQLiteSimulatorRepository",
    "SimulatorRepositoryError",
    "normalize_time",
]
