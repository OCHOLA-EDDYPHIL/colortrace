from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, cast

from .ports import ConnectionFactory, DbConnection, DbCursor, PersistenceError

_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_(?P<name>[a-z][a-z0-9_]*)\.up\.sql$")
_STATEMENT_MARKER = "\n-- colortrace-statement\n"
_MIGRATION_LOCK = 4851319803954839635
_BOOTSTRAP = (
    "CREATE SCHEMA IF NOT EXISTS colortrace",
    """
    CREATE TABLE IF NOT EXISTS colortrace.schema_migrations (
        version INTEGER PRIMARY KEY CHECK (version >= 1),
        name TEXT NOT NULL,
        migration_sha256 TEXT NOT NULL CHECK (
            migration_sha256 ~ '^sha256:[0-9a-f]{64}$'
        ),
        applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
    )
    """,
    "REVOKE ALL ON SCHEMA colortrace FROM PUBLIC",
    "REVOKE ALL ON colortrace.schema_migrations FROM PUBLIC",
)


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    up_sql: str
    down_sql: str
    sha256: str

    @property
    def up_statements(self) -> tuple[str, ...]:
        return _statements(self.up_sql)

    @property
    def down_statements(self) -> tuple[str, ...]:
        return _statements(self.down_sql)


def _statements(script: str) -> tuple[str, ...]:
    statements = tuple(value.strip() for value in script.split(_STATEMENT_MARKER))
    if not statements or any(not value for value in statements):
        raise PersistenceError("migration-script-invalid")
    return statements


def load_migrations() -> tuple[Migration, ...]:
    root = files("colortrace_persistence").joinpath("migration_sql")
    migrations: list[Migration] = []
    for entry in sorted(root.iterdir(), key=lambda value: value.name):
        match = _MIGRATION_NAME.fullmatch(entry.name)
        if match is None:
            continue
        version = int(match.group("version"))
        name = match.group("name")
        down = root.joinpath(f"{version:04d}_{name}.down.sql")
        if not down.is_file():
            raise PersistenceError("migration-rollback-missing")
        up_sql = entry.read_text(encoding="utf-8")
        down_sql = down.read_text(encoding="utf-8")
        digest = _sha256(up_sql.encode("utf-8") + b"\x00" + down_sql.encode("utf-8"))
        migration = Migration(version, name, up_sql, down_sql, digest)
        if not migration.up_statements or not migration.down_statements:
            raise PersistenceError("migration-script-invalid")
        migrations.append(migration)
    versions = [value.version for value in migrations]
    if not migrations or versions != list(range(1, len(migrations) + 1)):
        raise PersistenceError("migration-sequence-invalid")
    return tuple(migrations)


def _column_names(cursor: DbCursor) -> tuple[str, ...]:
    description = cursor.description
    if description is None or not isinstance(description, (list, tuple)):
        return ()
    names: list[str] = []
    for value in description:
        if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
            names.append(value[0])
        else:
            name = getattr(value, "name", None)
            if not isinstance(name, str):
                raise PersistenceError("postgres-result-invalid")
            names.append(name)
    return tuple(names)


def _rows(cursor: DbCursor) -> list[dict[str, Any]]:
    names = _column_names(cursor)
    values = cursor.fetchall()
    rows: list[dict[str, Any]] = []
    for value in values:
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
        finally:
            try:
                connection.close()
            except Exception:
                failed = True
        if failed:
            raise PersistenceError("postgres-close-failed")


class PostgresMigrationRunner:
    def __init__(
        self,
        connection_factory: ConnectionFactory,
        *,
        migrations: tuple[Migration, ...] | None = None,
    ) -> None:
        self._factory = connection_factory
        self._migrations = load_migrations() if migrations is None else migrations
        if tuple(value.version for value in self._migrations) != tuple(
            range(1, len(self._migrations) + 1)
        ):
            raise PersistenceError("migration-sequence-invalid")

    @staticmethod
    def _bootstrap(cursor: DbCursor) -> None:
        for statement in _BOOTSTRAP:
            cursor.execute(statement)

    @staticmethod
    def _lock(cursor: DbCursor) -> None:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK,))

    def applied(self) -> tuple[tuple[int, str, str], ...]:
        with _connection(self._factory) as (_connection_value, cursor):
            self._bootstrap(cursor)
            cursor.execute(
                "SELECT version, name, migration_sha256 "
                "FROM colortrace.schema_migrations ORDER BY version"
            )
            rows = _rows(cursor)
        return tuple(
            (cast(int, row["version"]), cast(str, row["name"]), cast(str, row["migration_sha256"]))
            for row in rows
        )

    def apply_all(self) -> tuple[int, ...]:
        applied_now: list[int] = []
        with _connection(self._factory) as (_connection_value, cursor):
            self._bootstrap(cursor)
            self._lock(cursor)
            cursor.execute(
                "SELECT version, name, migration_sha256 "
                "FROM colortrace.schema_migrations ORDER BY version"
            )
            existing = _rows(cursor)
            if len(existing) > len(self._migrations):
                raise PersistenceError("migration-unknown")
            for index, row in enumerate(existing):
                expected = self._migrations[index]
                if (
                    row.get("version") != expected.version
                    or row.get("name") != expected.name
                    or row.get("migration_sha256") != expected.sha256
                ):
                    raise PersistenceError("migration-drift")
            for migration in self._migrations[len(existing) :]:
                for statement in migration.up_statements:
                    cursor.execute(statement)
                cursor.execute(
                    "INSERT INTO colortrace.schema_migrations "
                    "(version, name, migration_sha256) VALUES (%s, %s, %s)",
                    (migration.version, migration.name, migration.sha256),
                )
                applied_now.append(migration.version)
        return tuple(applied_now)

    def rollback_latest(self) -> int | None:
        with _connection(self._factory) as (_connection_value, cursor):
            self._bootstrap(cursor)
            self._lock(cursor)
            cursor.execute(
                "SELECT version, name, migration_sha256 "
                "FROM colortrace.schema_migrations ORDER BY version DESC LIMIT 1"
            )
            rows = _rows(cursor)
            if not rows:
                return None
            row = rows[0]
            version = row.get("version")
            if not isinstance(version, int) or not 1 <= version <= len(self._migrations):
                raise PersistenceError("migration-unknown")
            migration = self._migrations[version - 1]
            if row.get("name") != migration.name or row.get("migration_sha256") != migration.sha256:
                raise PersistenceError("migration-drift")
            for statement in migration.down_statements:
                cursor.execute(statement)
            cursor.execute(
                "DELETE FROM colortrace.schema_migrations WHERE version = %s",
                (migration.version,),
            )
        return migration.version
