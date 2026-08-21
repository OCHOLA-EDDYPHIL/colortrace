from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from .canonical import _snapshot_from_record_rows
from .ports import ConnectionFactory, DbConnection, DbCursor, MetadataSnapshot, PersistenceError
from .schema_validation import validate_reader_privileges

_ROLE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}$")
_DATABASE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")
HOSTED_FIXTURE_RECORD_ID = "incident-hosted-synthetic-001"
HOSTED_READINESS_RECORD_ID = "hosted-readiness:synthetic-hosted-read-v1"
_HOSTED_RECORD_IDS = frozenset({HOSTED_FIXTURE_RECORD_ID, HOSTED_READINESS_RECORD_ID})


def _column_names(cursor: DbCursor) -> tuple[str, ...]:
    description = cursor.description
    if not isinstance(description, (list, tuple)):
        raise PersistenceError("postgres-result-invalid")
    names: list[str] = []
    for value in description:
        if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
            names.append(value[0])
            continue
        name = getattr(value, "name", None)
        if not isinstance(name, str):
            raise PersistenceError("postgres-result-invalid")
        names.append(name)
    return tuple(names)


def _rows(cursor: DbCursor) -> list[dict[str, Any]]:
    names = _column_names(cursor)
    rows: list[dict[str, Any]] = []
    for value in cursor.fetchall():
        if not isinstance(value, (list, tuple)) or len(value) != len(names):
            raise PersistenceError("postgres-result-invalid")
        rows.append(dict(zip(names, value, strict=True)))
    return rows


@contextmanager
def _connection(factory: ConnectionFactory) -> Iterator[tuple[DbConnection, DbCursor]]:
    connection: DbConnection | None = None
    cursor: DbCursor | None = None
    try:
        connection = factory.connect()
        cursor = connection.cursor()
    except Exception:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        raise PersistenceError("postgres-unavailable") from None
    try:
        yield connection, cursor
        connection.commit()
    except PersistenceError:
        try:
            connection.rollback()
        except Exception:
            raise PersistenceError("postgres-rollback-failed") from None
        raise
    except Exception:
        try:
            connection.rollback()
        except Exception:
            raise PersistenceError("postgres-rollback-failed") from None
        raise PersistenceError("postgres-operation-failed") from None
    finally:
        failed = False
        try:
            cursor.close()
        except Exception:
            failed = True
        try:
            connection.close()
        except Exception:
            failed = True
        if failed:
            raise PersistenceError("postgres-close-failed")


@dataclass(frozen=True, slots=True)
class PostgresReaderVerifier:
    connection_factory: ConnectionFactory
    database: str
    reader_role: str

    def __post_init__(self) -> None:
        if _DATABASE_NAME.fullmatch(self.database) is None:
            raise PersistenceError("postgres-reader-database-invalid")
        if _ROLE_NAME.fullmatch(self.reader_role) is None:
            raise PersistenceError("postgres-reader-role-invalid")

    def validate(self) -> None:
        with _connection(self.connection_factory) as (_connection_value, cursor):
            cursor.execute("SELECT session_user, current_user, current_database()")
            identity = _rows(cursor)
            if len(identity) != 1:
                raise PersistenceError("postgres-result-invalid")
            if (
                identity[0].get("session_user") != self.reader_role
                or identity[0].get("current_user") != self.reader_role
            ):
                raise PersistenceError("postgres-reader-role-mismatch")
            if identity[0].get("current_database") != self.database:
                raise PersistenceError("postgres-reader-database-mismatch")
            cursor.execute(
                "SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, "
                "rolreplication, rolbypassrls FROM pg_roles WHERE rolname = %s",
                (self.reader_role,),
            )
            roles = _rows(cursor)
            if len(roles) != 1:
                raise PersistenceError("postgres-role-missing")
            role = roles[0]
            if role != {
                "rolsuper": False,
                "rolinherit": True,
                "rolcreaterole": False,
                "rolcreatedb": False,
                "rolcanlogin": True,
                "rolreplication": False,
                "rolbypassrls": False,
            }:
                raise PersistenceError("postgres-role-privileges-invalid")
            validate_reader_privileges(cursor, self.reader_role)


@dataclass(frozen=True, slots=True)
class HostedProjectionPostgresStore:
    connection_factory: ConnectionFactory

    @property
    def namespace(self) -> str:
        return "incident"

    def read(self, record_id: str) -> MetadataSnapshot:
        if record_id not in _HOSTED_RECORD_IDS:
            raise PersistenceError("metadata-record-not-found")
        with _connection(self.connection_factory) as (_connection_value, cursor):
            cursor.execute(
                "SELECT current_version, current_document, current_document_sha256, "
                "current_chain_sha256, history_version, history_document, "
                "history_document_sha256, history_previous_chain_sha256, "
                "history_chain_sha256 FROM colortrace.hosted_read_projection_v1 "
                "WHERE namespace = 'incident' AND record_id = %s ORDER BY history_version",
                (record_id,),
            )
            rows = _rows(cursor)
        return _snapshot_from_record_rows("incident", record_id, rows)
