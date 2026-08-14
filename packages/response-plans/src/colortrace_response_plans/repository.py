from __future__ import annotations

import os
import sqlite3
import stat
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from .contracts import (
    ResponsePlanError,
    canonical_json_bytes,
    normalize_target,
    plain_json,
    prefixed_sha256,
    require_digest,
    require_identifier,
    strict_json_bytes,
    target_identity,
)


@dataclass(frozen=True, slots=True)
class CanonicalIncidentAuthority:
    incident_id: str
    incident_version: int
    _trust_token: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ResponsePacketAuthority:
    packet_id: str
    incident_id: str
    incident_version: int
    packet_sha256: str
    deterministic_scope_sha256: str
    targets: tuple[Mapping[str, Any], ...]
    exclusions: tuple[Mapping[str, Any], ...]
    unresolved_item_ids: tuple[str, ...] = ()
    blocking_unresolved_item_ids: tuple[str, ...] = ()
    unknown_target_ids: tuple[str, ...] = ()
    _trust_token: object = field(default_factory=object, repr=False, compare=False)


class CanonicalAuthorityBoundary:
    def __init__(self) -> None:
        self._trust_token = object()

    def bind_incident_snapshot(
        self,
        *,
        incident_id: str,
        incident_version: int,
        canonical_state_verified: bool,
    ) -> CanonicalIncidentAuthority:
        if canonical_state_verified is not True:
            raise ResponsePlanError("canonical-state-not-verified")
        incident = require_identifier(incident_id)
        if (
            not isinstance(incident_version, int)
            or isinstance(incident_version, bool)
            or incident_version < 1
        ):
            raise ResponsePlanError("incident-version-invalid")
        return CanonicalIncidentAuthority(
            incident_id=incident,
            incident_version=incident_version,
            _trust_token=self._trust_token,
        )

    def bind_response_packet(
        self,
        *,
        incident: CanonicalIncidentAuthority,
        packet_id: str,
        packet_sha256: str,
        deterministic_scope_sha256: str,
        targets: Sequence[Mapping[str, Any]],
        exclusions: Sequence[Mapping[str, Any]],
        unresolved_item_ids: Sequence[str] = (),
        blocking_unresolved_item_ids: Sequence[str] = (),
        unknown_target_ids: Sequence[str] = (),
        canonical_state_verified: bool,
    ) -> ResponsePacketAuthority:
        if canonical_state_verified is not True:
            raise ResponsePlanError("canonical-state-not-verified")
        self.assert_incident(incident)
        return ResponsePacketAuthority(
            packet_id=packet_id,
            incident_id=incident.incident_id,
            incident_version=incident.incident_version,
            packet_sha256=packet_sha256,
            deterministic_scope_sha256=deterministic_scope_sha256,
            targets=tuple(targets),
            exclusions=tuple(exclusions),
            unresolved_item_ids=tuple(unresolved_item_ids),
            blocking_unresolved_item_ids=tuple(blocking_unresolved_item_ids),
            unknown_target_ids=tuple(unknown_target_ids),
            _trust_token=self._trust_token,
        )

    def assert_incident(self, incident: CanonicalIncidentAuthority) -> None:
        if (
            not isinstance(incident, CanonicalIncidentAuthority)
            or incident._trust_token is not self._trust_token
        ):
            raise ResponsePlanError("canonical-authority-boundary-mismatch")

    def assert_response_packet(self, authority: ResponsePacketAuthority) -> None:
        if (
            not isinstance(authority, ResponsePacketAuthority)
            or authority._trust_token is not self._trust_token
        ):
            raise ResponsePlanError("canonical-authority-boundary-mismatch")


_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS authority_incidents (
    incident_id TEXT PRIMARY KEY,
    incident_version INTEGER NOT NULL CHECK (incident_version >= 1)
);
CREATE TABLE IF NOT EXISTS response_packet_authority (
    packet_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    incident_version INTEGER NOT NULL CHECK (incident_version >= 1),
    packet_sha256 TEXT NOT NULL UNIQUE,
    deterministic_scope_sha256 TEXT NOT NULL,
    document BLOB NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES authority_incidents(incident_id)
);
CREATE TABLE IF NOT EXISTS response_plans (
    incident_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL CHECK (plan_version >= 1),
    incident_version INTEGER NOT NULL CHECK (incident_version >= 1),
    plan_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    PRIMARY KEY (incident_id, plan_version),
    FOREIGN KEY (incident_id) REFERENCES authority_incidents(incident_id)
);
CREATE TABLE IF NOT EXISTS response_plan_decisions (
    incident_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    decision_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    PRIMARY KEY (incident_id, plan_version),
    FOREIGN KEY (incident_id, plan_version)
        REFERENCES response_plans(incident_id, plan_version)
);
CREATE TABLE IF NOT EXISTS dispatch_authorizations (
    authorization_id TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    incident_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('authorized', 'consumed', 'invalidated')),
    document BLOB NOT NULL,
    consumption_document BLOB,
    UNIQUE (incident_id, plan_version),
    FOREIGN KEY (incident_id, plan_version)
        REFERENCES response_plans(incident_id, plan_version)
);
CREATE TABLE IF NOT EXISTS response_plan_audit_events (
    incident_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_sha256 TEXT NOT NULL UNIQUE,
    document BLOB NOT NULL,
    PRIMARY KEY (incident_id, sequence),
    FOREIGN KEY (incident_id) REFERENCES authority_incidents(incident_id)
);
CREATE TABLE IF NOT EXISTS response_plan_audit_heads (
    incident_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    event_sha256 TEXT NOT NULL,
    FOREIGN KEY (incident_id, sequence)
        REFERENCES response_plan_audit_events(incident_id, sequence)
);
CREATE TABLE IF NOT EXISTS response_plan_idempotency (
    idempotency_key TEXT PRIMARY KEY,
    request_sha256 TEXT NOT NULL,
    result BLOB NOT NULL
);
CREATE TRIGGER IF NOT EXISTS response_plan_audit_no_update
BEFORE UPDATE ON response_plan_audit_events
BEGIN
    SELECT RAISE(ABORT, 'response-plan-audit-append-only');
END;
CREATE TRIGGER IF NOT EXISTS response_plan_audit_no_delete
BEFORE DELETE ON response_plan_audit_events
BEGIN
    SELECT RAISE(ABORT, 'response-plan-audit-append-only');
END;
"""

_APPLICATION_ID = 0x43545250
_SCHEMA_VERSION = 1
_SchemaManifest = tuple[tuple[str, str, str, str | None], ...]


def _normalize_schema_sql(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().replace("\r\n", "\n").replace("\r", "\n")


def _schema_manifest(
    connection: sqlite3.Connection,
) -> _SchemaManifest:
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
            _normalize_schema_sql(cast(str | None, row[3])),
        )
        for row in rows
    )


def _build_expected_schema_manifest() -> tuple[_SchemaManifest, str]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(_SCHEMA)
        manifest = _schema_manifest(connection)
    finally:
        connection.close()
    return manifest, prefixed_sha256(canonical_json_bytes(manifest))


_EXPECTED_SCHEMA_MANIFEST, _EXPECTED_SCHEMA_SHA256 = _build_expected_schema_manifest()


class SQLiteResponsePlanRepository:
    def __init__(
        self,
        database: str | Path = ":memory:",
        *,
        authority_boundary: CanonicalAuthorityBoundary,
        busy_timeout_ms: int = 30_000,
    ) -> None:
        if (
            not isinstance(busy_timeout_ms, int)
            or isinstance(busy_timeout_ms, bool)
            or not 1 <= busy_timeout_ms <= 30_000
        ):
            raise ResponsePlanError("repository-timeout-invalid")
        self._authority_boundary = authority_boundary
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
            self._connection.execute("PRAGMA synchronous = FULL")
            if self._database != ":memory:":
                self._connection.execute("PRAGMA journal_mode = DELETE")
                self._validate_database_path(Path(self._database), expected_identity)
            self._initialize_or_validate_schema(created=created or self._database == ":memory:")
        except ResponsePlanError:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise
        except sqlite3.DatabaseError as error:
            if hasattr(self, "_connection"):
                self._connection.close()
            raise ResponsePlanError("repository-invalid") from error

    @staticmethod
    def _validate_database_stat(path: Path, value: os.stat_result) -> None:
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ResponsePlanError("repository-path-invalid")
        if value.st_uid != os.getuid() or stat.S_IMODE(value.st_mode) & 0o077:
            raise ResponsePlanError("repository-permissions-invalid")
        if path.is_symlink():
            raise ResponsePlanError("repository-path-invalid")

    @classmethod
    def _prepare_database_path(cls, raw_path: Path) -> tuple[Path, bool, tuple[int, int]]:
        path = raw_path.absolute()
        try:
            parent = path.parent.stat(follow_symlinks=False)
        except OSError as error:
            raise ResponsePlanError("repository-path-invalid") from error
        if not stat.S_ISDIR(parent.st_mode):
            raise ResponsePlanError("repository-path-invalid")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        created = False
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            try:
                value = path.lstat()
            except OSError as error:
                raise ResponsePlanError("repository-path-invalid") from error
            cls._validate_database_stat(path, value)
            return path, created, (value.st_dev, value.st_ino)
        except OSError as error:
            raise ResponsePlanError("repository-path-invalid") from error
        try:
            value = os.fstat(descriptor)
            cls._validate_database_stat(path, value)
            created = True
            return path, created, (value.st_dev, value.st_ino)
        finally:
            os.close(descriptor)

    @classmethod
    def _validate_database_path(cls, path: Path, expected_identity: tuple[int, int] | None) -> None:
        try:
            value = path.lstat()
        except OSError as error:
            raise ResponsePlanError("repository-path-invalid") from error
        cls._validate_database_stat(path, value)
        if expected_identity is None or (value.st_dev, value.st_ino) != expected_identity:
            raise ResponsePlanError("repository-path-changed")

    def _initialize_or_validate_schema(self, *, created: bool) -> None:
        application_id = cast(int, self._connection.execute("PRAGMA application_id").fetchone()[0])
        version = cast(int, self._connection.execute("PRAGMA user_version").fetchone()[0])
        if created:
            if application_id != 0 or version != 0:
                raise ResponsePlanError("repository-schema-invalid")
            self._connection.executescript(_SCHEMA)
            self._connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
            self._connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        elif application_id != _APPLICATION_ID or version != _SCHEMA_VERSION:
            raise ResponsePlanError("repository-schema-invalid")
        manifest = _schema_manifest(self._connection)
        if (
            manifest != _EXPECTED_SCHEMA_MANIFEST
            or prefixed_sha256(canonical_json_bytes(manifest)) != _EXPECTED_SCHEMA_SHA256
        ):
            raise ResponsePlanError("repository-schema-invalid")
        check = self._connection.execute("PRAGMA quick_check").fetchone()
        if check is None or check[0] != "ok":
            raise ResponsePlanError("repository-integrity-error")

    @contextmanager
    def transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                yield self._connection
                self._connection.commit()
            except ResponsePlanError:
                self._connection.rollback()
                raise
            except sqlite3.IntegrityError as error:
                self._connection.rollback()
                raise ResponsePlanError("repository-integrity-error") from error
            except sqlite3.OperationalError as error:
                self._connection.rollback()
                raise ResponsePlanError("repository-unavailable") from error
            except sqlite3.DatabaseError as error:
                self._connection.rollback()
                raise ResponsePlanError("repository-invalid") from error
            except BaseException:
                self._connection.rollback()
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def register_incident(self, authority: CanonicalIncidentAuthority) -> None:
        self._authority_boundary.assert_incident(authority)
        incident = authority.incident_id
        incident_version = authority.incident_version
        with self.transaction(write=True) as connection:
            row = connection.execute(
                "SELECT incident_version FROM authority_incidents WHERE incident_id = ?",
                (incident,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO authority_incidents(incident_id, incident_version) VALUES (?, ?)",
                    (incident, incident_version),
                )
            elif cast(int, row["incident_version"]) != incident_version:
                raise ResponsePlanError("incident-registration-conflict")

    def advance_incident(
        self,
        authority: CanonicalIncidentAuthority,
        *,
        expected_incident_version: int,
    ) -> None:
        self._authority_boundary.assert_incident(authority)
        incident = authority.incident_id
        incident_version = authority.incident_version
        if incident_version <= expected_incident_version:
            raise ResponsePlanError("incident-version-invalid")
        with self.transaction(write=True) as connection:
            cursor = connection.execute(
                "UPDATE authority_incidents SET incident_version = ? "
                "WHERE incident_id = ? AND incident_version = ?",
                (incident_version, incident, expected_incident_version),
            )
            if cursor.rowcount != 1:
                raise ResponsePlanError("expected-version-conflict")

    @staticmethod
    def _sorted_targets(values: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
        targets = [normalize_target(value) for value in values]
        targets.sort(key=target_identity)
        identities = [target_identity(value) for value in targets]
        if len(identities) != len(set(identities)):
            raise ResponsePlanError("target-duplicate")
        return targets

    @staticmethod
    def normalize_packet_authority(authority: ResponsePacketAuthority) -> dict[str, Any]:
        packet_id = require_identifier(authority.packet_id, code="response-packet-id-invalid")
        packet_digest = require_digest(
            authority.packet_sha256, code="response-packet-digest-invalid"
        )
        if packet_id != f"response-packet:{packet_digest.removeprefix('sha256:')}":
            raise ResponsePlanError("response-packet-binding-conflict")
        incident_id = require_identifier(authority.incident_id)
        if (
            not isinstance(authority.incident_version, int)
            or isinstance(authority.incident_version, bool)
            or authority.incident_version < 1
        ):
            raise ResponsePlanError("incident-version-invalid")
        targets = SQLiteResponsePlanRepository._sorted_targets(authority.targets)
        exclusions = SQLiteResponsePlanRepository._sorted_targets(authority.exclusions)
        if not targets:
            raise ResponsePlanError("plan-targets-empty")
        if {target_identity(value) for value in targets} & {
            target_identity(value) for value in exclusions
        }:
            raise ResponsePlanError("target-exclusion-overlap")

        def identifiers(values: Sequence[str], *, code: str) -> list[str]:
            normalized = sorted({require_identifier(value, code=code) for value in values})
            if len(normalized) != len(values):
                raise ResponsePlanError(f"{code}-duplicate")
            return normalized

        return {
            "schema": "response-packet-plan-authority/v1",
            "response_packet_id": packet_id,
            "incident_id": incident_id,
            "incident_version": authority.incident_version,
            "response_packet_sha256": packet_digest,
            "deterministic_scope_sha256": require_digest(
                authority.deterministic_scope_sha256,
                code="deterministic-scope-digest-invalid",
            ),
            "targets": targets,
            "exclusions": exclusions,
            "unresolved_item_ids": identifiers(
                authority.unresolved_item_ids, code="unresolved-item-invalid"
            ),
            "blocking_unresolved_item_ids": identifiers(
                authority.blocking_unresolved_item_ids,
                code="blocking-unresolved-item-invalid",
            ),
            "unknown_target_ids": identifiers(
                authority.unknown_target_ids, code="unknown-target-invalid"
            ),
        }

    def register_response_packet(self, authority: ResponsePacketAuthority) -> None:
        self._authority_boundary.assert_response_packet(authority)
        packet = self.normalize_packet_authority(authority)
        encoded = canonical_json_bytes(packet)
        with self.transaction(write=True) as connection:
            incident = connection.execute(
                "SELECT incident_version FROM authority_incidents WHERE incident_id = ?",
                (packet["incident_id"],),
            ).fetchone()
            if incident is None:
                raise ResponsePlanError("incident-not-found")
            if incident["incident_version"] != packet["incident_version"]:
                raise ResponsePlanError("expected-version-conflict")
            row = connection.execute(
                "SELECT document FROM response_packet_authority WHERE packet_id = ?",
                (packet["response_packet_id"],),
            ).fetchone()
            if row is not None:
                if bytes(row["document"]) != encoded:
                    raise ResponsePlanError("response-packet-registration-conflict")
                return
            connection.execute(
                "INSERT INTO response_packet_authority("
                "packet_id, incident_id, incident_version, packet_sha256, "
                "deterministic_scope_sha256, document) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    packet["response_packet_id"],
                    packet["incident_id"],
                    packet["incident_version"],
                    packet["response_packet_sha256"],
                    packet["deterministic_scope_sha256"],
                    encoded,
                ),
            )

    @staticmethod
    def decode(document: bytes) -> dict[str, Any]:
        value = strict_json_bytes(document)
        if not isinstance(value, dict):
            raise ResponsePlanError("stored-document-invalid")
        return cast(dict[str, Any], plain_json(value))


__all__ = [
    "CanonicalAuthorityBoundary",
    "CanonicalIncidentAuthority",
    "ResponsePacketAuthority",
    "SQLiteResponsePlanRepository",
]
