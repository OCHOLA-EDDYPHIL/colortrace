from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, cast

from .ports import ConnectionFactory, DbConnection, DbCursor, PersistenceError
from .schema_validation import validate_revoked_reader_privileges, validate_schema

_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_(?P<name>[a-z][a-z0-9_]*)\.up\.sql$")
_ROLE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}$")
_STATEMENT_MARKER = "\n-- colortrace-statement\n"
_MIGRATION_LOCK = 4851319803954839635
_HOSTED_PROJECTION_VERSION = 2
_HOSTED_READER_BINDING = "hosted-read-v1"
_BOOTSTRAP = (
    "CREATE SCHEMA IF NOT EXISTS colortrace",
    """
    CREATE TABLE IF NOT EXISTS colortrace.schema_migrations (
        version INTEGER PRIMARY KEY CHECK (version >= 1),
        name TEXT NOT NULL,
        migration_sha256 TEXT NOT NULL CHECK (
            migration_sha256 ~ '^sha256:[0-9a-f]{64}$'
        ),
        migration_role TEXT NOT NULL,
        runtime_role TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
    )
    """,
    "REVOKE ALL ON SCHEMA colortrace FROM PUBLIC",
    "REVOKE ALL ON colortrace.schema_migrations FROM PUBLIC",
)

_RUNTIME_TABLE_PRIVILEGES: dict[str, tuple[str, ...]] = {
    "metadata_claim_events": ("INSERT", "SELECT"),
    "metadata_claims": ("DELETE", "INSERT", "SELECT", "UPDATE"),
    "metadata_idempotency": ("INSERT", "SELECT"),
    "metadata_record_versions": ("INSERT", "SELECT"),
    "metadata_records": ("INSERT", "SELECT", "UPDATE"),
}


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _role_name(value: str, *, code: str) -> str:
    if not isinstance(value, str) or _ROLE_NAME.fullmatch(value) is None:
        raise PersistenceError(code)
    return value


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


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
        migration_role: str,
        runtime_role: str,
        reader_role: str,
        migrations: tuple[Migration, ...] | None = None,
    ) -> None:
        self._factory = connection_factory
        self._migration_role = _role_name(
            migration_role,
            code="postgres-migration-role-invalid",
        )
        self._runtime_role = _role_name(runtime_role, code="postgres-runtime-role-invalid")
        self._reader_role = _role_name(reader_role, code="postgres-reader-role-invalid")
        if len({self._migration_role, self._runtime_role, self._reader_role}) != 3:
            raise PersistenceError("postgres-role-separation-invalid")
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

    def _validate_roles(self, cursor: DbCursor) -> str:
        cursor.execute("SELECT current_user, current_database()")
        current_rows = _rows(cursor)
        if len(current_rows) != 1:
            raise PersistenceError("postgres-result-invalid")
        current = current_rows[0]
        if current.get("current_user") != self._migration_role:
            raise PersistenceError("postgres-migration-role-mismatch")
        database = current.get("current_database")
        if not isinstance(database, str) or not database:
            raise PersistenceError("postgres-result-invalid")

        cursor.execute(
            "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, "
            "rolreplication, rolbypassrls FROM pg_roles WHERE rolname IN (%s, %s, %s)",
            (self._migration_role, self._runtime_role, self._reader_role),
        )
        roles = {cast(str, row["rolname"]): row for row in _rows(cursor)}
        if set(roles) != {self._migration_role, self._runtime_role, self._reader_role}:
            raise PersistenceError("postgres-role-missing")
        for role in roles.values():
            if (
                role.get("rolsuper") is not False
                or role.get("rolinherit") is not True
                or role.get("rolcreaterole") is not False
                or role.get("rolcreatedb") is not False
                or role.get("rolcanlogin") is not True
                or role.get("rolreplication") is not False
                or role.get("rolbypassrls") is not False
            ):
                raise PersistenceError("postgres-role-privileges-invalid")
        cursor.execute(
            "SELECT pg_has_role(%s, %s, 'MEMBER') AS runtime_is_migrator, "
            "pg_has_role(%s, %s, 'MEMBER') AS reader_is_migrator, "
            "pg_has_role(%s, %s, 'MEMBER') AS reader_is_runtime",
            (
                self._runtime_role,
                self._migration_role,
                self._reader_role,
                self._migration_role,
                self._reader_role,
                self._runtime_role,
            ),
        )
        membership = _rows(cursor)
        if len(membership) != 1 or membership[0] != {
            "runtime_is_migrator": False,
            "reader_is_migrator": False,
            "reader_is_runtime": False,
        }:
            raise PersistenceError("postgres-role-separation-invalid")
        return database

    def _grant_runtime_access(
        self,
        cursor: DbCursor,
        database: str,
        *,
        hosted_projection: bool,
    ) -> None:
        runtime = _quote_identifier(self._runtime_role)
        database_name = _quote_identifier(database)
        cursor.execute(f"REVOKE CREATE ON DATABASE {database_name} FROM {runtime}")
        cursor.execute(f"GRANT CONNECT ON DATABASE {database_name} TO {runtime}")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON SCHEMA colortrace FROM {runtime}")
        cursor.execute(f"GRANT USAGE ON SCHEMA colortrace TO {runtime}")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON colortrace.schema_migrations FROM {runtime}")
        for table, privileges in _RUNTIME_TABLE_PRIVILEGES.items():
            cursor.execute(f"REVOKE ALL PRIVILEGES ON TABLE colortrace.{table} FROM {runtime}")
            cursor.execute(
                f"GRANT {', '.join(privileges)} ON TABLE colortrace.{table} TO {runtime}"
            )
        cursor.execute(
            f"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA colortrace FROM {runtime}"
        )
        if hosted_projection:
            cursor.execute(
                f"REVOKE ALL PRIVILEGES ON TABLE colortrace.hosted_read_bindings FROM {runtime}"
            )
            cursor.execute(
                f"REVOKE ALL PRIVILEGES ON TABLE colortrace.hosted_read_projection_v1 "
                f"FROM {runtime}"
            )

    @staticmethod
    def _revoke_reader_role(cursor: DbCursor, database: str, reader_role: str) -> None:
        reader = _quote_identifier(_role_name(reader_role, code="postgres-reader-role-invalid"))
        database_name = _quote_identifier(database)
        cursor.execute(f"REVOKE ALL PRIVILEGES ON DATABASE {database_name} FROM {reader} CASCADE")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON SCHEMA colortrace FROM {reader} CASCADE")
        cursor.execute(
            f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA colortrace FROM {reader} CASCADE"
        )
        cursor.execute(
            f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA colortrace FROM {reader} CASCADE"
        )
        cursor.execute(
            f"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA colortrace FROM {reader} CASCADE"
        )
        cursor.execute(
            "SELECT n.nspname, c.relname, a.attname, acl.privilege_type "
            "FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace "
            "JOIN pg_attribute AS a ON a.attrelid = c.oid "
            "CROSS JOIN LATERAL aclexplode(a.attacl) AS acl "
            "JOIN pg_roles AS grantee ON grantee.oid = acl.grantee "
            "WHERE n.nspname = 'colortrace' AND a.attnum > 0 "
            "AND NOT a.attisdropped AND grantee.rolname = %s "
            "ORDER BY n.nspname, c.relname, a.attnum, acl.privilege_type",
            (reader_role,),
        )
        column_grants = _rows(cursor)
        column_privileges = {"INSERT", "REFERENCES", "SELECT", "UPDATE"}
        for row in column_grants:
            schema_name = row.get("nspname")
            relation_name = row.get("relname")
            column_name = row.get("attname")
            privilege = row.get("privilege_type")
            if (
                not isinstance(schema_name, str)
                or not isinstance(relation_name, str)
                or not isinstance(column_name, str)
                or privilege not in column_privileges
            ):
                raise PersistenceError("postgres-result-invalid")
            cursor.execute(
                f"REVOKE {privilege} ({_quote_identifier(column_name)}) ON TABLE "
                f"{_quote_identifier(schema_name)}.{_quote_identifier(relation_name)} "
                f"FROM {reader} CASCADE"
            )

    @staticmethod
    def _bound_reader_role(cursor: DbCursor) -> str:
        cursor.execute(
            "SELECT reader_role FROM colortrace.hosted_read_bindings "
            "WHERE binding_key = %s FOR UPDATE",
            (_HOSTED_READER_BINDING,),
        )
        rows = _rows(cursor)
        if len(rows) != 1:
            raise PersistenceError("postgres-reader-binding-invalid")
        observed = rows[0].get("reader_role")
        if not isinstance(observed, str):
            raise PersistenceError("postgres-reader-binding-invalid")
        return _role_name(observed, code="postgres-reader-binding-invalid")

    def _grant_reader_access(
        self,
        cursor: DbCursor,
        database: str,
        *,
        initialize_binding: bool,
    ) -> None:
        previous_role: str | None
        if initialize_binding:
            cursor.execute("SELECT 1 FROM colortrace.hosted_read_bindings")
            if _rows(cursor):
                raise PersistenceError("postgres-reader-binding-invalid")
            previous_role = None
        else:
            previous_role = self._bound_reader_role(cursor)
            self._revoke_reader_role(cursor, database, previous_role)
        if previous_role is None or previous_role != self._reader_role:
            self._revoke_reader_role(cursor, database, self._reader_role)
        if previous_role is not None:
            cursor.execute(
                "UPDATE colortrace.hosted_read_bindings SET reader_role = %s "
                "WHERE binding_key = %s",
                (self._reader_role, _HOSTED_READER_BINDING),
            )
        else:
            cursor.execute(
                "INSERT INTO colortrace.hosted_read_bindings (binding_key, reader_role) "
                "VALUES (%s, %s)",
                (_HOSTED_READER_BINDING, self._reader_role),
            )
        reader = _quote_identifier(self._reader_role)
        database_name = _quote_identifier(database)
        cursor.execute(f"GRANT CONNECT ON DATABASE {database_name} TO {reader}")
        cursor.execute(f"GRANT USAGE ON SCHEMA colortrace TO {reader}")
        cursor.execute(f"GRANT SELECT ON colortrace.hosted_read_projection_v1 TO {reader}")
        if previous_role is not None and previous_role != self._reader_role:
            validate_revoked_reader_privileges(cursor, previous_role)

    def _revoke_runtime_access(self, cursor: DbCursor, database: str) -> None:
        runtime = _quote_identifier(self._runtime_role)
        database_name = _quote_identifier(database)
        cursor.execute(f"REVOKE ALL PRIVILEGES ON SCHEMA colortrace FROM {runtime}")
        cursor.execute(f"REVOKE CONNECT ON DATABASE {database_name} FROM {runtime}")

    def _revoke_reader_access(self, cursor: DbCursor, database: str) -> None:
        self._revoke_reader_role(cursor, database, self._reader_role)

    def _existing(self, cursor: DbCursor) -> list[dict[str, Any]]:
        cursor.execute(
            "SELECT version, name, migration_sha256, migration_role, runtime_role "
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
            if (
                row.get("migration_role") != self._migration_role
                or row.get("runtime_role") != self._runtime_role
            ):
                raise PersistenceError("migration-role-drift")
        return existing

    @staticmethod
    def _canonical_state_is_empty(cursor: DbCursor) -> bool:
        cursor.execute(
            "SELECT NOT ("
            "EXISTS (SELECT 1 FROM colortrace.metadata_records) OR "
            "EXISTS (SELECT 1 FROM colortrace.metadata_record_versions) OR "
            "EXISTS (SELECT 1 FROM colortrace.metadata_idempotency) OR "
            "EXISTS (SELECT 1 FROM colortrace.metadata_claims) OR "
            "EXISTS (SELECT 1 FROM colortrace.metadata_claim_events)"
            ") AS empty"
        )
        rows = _rows(cursor)
        return len(rows) == 1 and rows[0].get("empty") is True

    def applied(self) -> tuple[tuple[int, str, str], ...]:
        with _connection(self._factory) as (_connection_value, cursor):
            self._validate_roles(cursor)
            self._lock(cursor)
            self._bootstrap(cursor)
            rows = self._existing(cursor)
        return tuple(
            (cast(int, row["version"]), cast(str, row["name"]), cast(str, row["migration_sha256"]))
            for row in rows
        )

    def apply_all(self) -> tuple[int, ...]:
        applied_now: list[int] = []
        with _connection(self._factory) as (_connection_value, cursor):
            database = self._validate_roles(cursor)
            self._lock(cursor)
            self._bootstrap(cursor)
            existing = self._existing(cursor)
            for migration in self._migrations[len(existing) :]:
                for statement in migration.up_statements:
                    cursor.execute(statement)
                cursor.execute(
                    "INSERT INTO colortrace.schema_migrations "
                    "(version, name, migration_sha256, migration_role, runtime_role) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (
                        migration.version,
                        migration.name,
                        migration.sha256,
                        self._migration_role,
                        self._runtime_role,
                    ),
                )
                applied_now.append(migration.version)
            hosted_projection = len(self._migrations) >= _HOSTED_PROJECTION_VERSION
            self._grant_runtime_access(
                cursor,
                database,
                hosted_projection=hosted_projection,
            )
            if hosted_projection:
                self._grant_reader_access(
                    cursor,
                    database,
                    initialize_binding=_HOSTED_PROJECTION_VERSION in applied_now,
                )
            else:
                self._revoke_reader_access(cursor, database)
            validate_schema(
                cursor,
                migration_role=self._migration_role,
                runtime_role=self._runtime_role,
                reader_role=self._reader_role if hosted_projection else None,
                hosted_projection=hosted_projection,
            )
        return tuple(applied_now)

    def rollback_latest(self) -> int | None:
        with _connection(self._factory) as (_connection_value, cursor):
            database = self._validate_roles(cursor)
            self._lock(cursor)
            self._bootstrap(cursor)
            existing = self._existing(cursor)
            if not existing:
                return None
            row = existing[-1]
            version = row.get("version")
            if not isinstance(version, int) or not 1 <= version <= len(self._migrations):
                raise PersistenceError("migration-unknown")
            migration = self._migrations[version - 1]
            hosted_projection = migration.version >= _HOSTED_PROJECTION_VERSION
            removes_projection = migration.version == _HOSTED_PROJECTION_VERSION
            bound_reader = self._bound_reader_role(cursor) if hosted_projection else None
            validate_schema(
                cursor,
                migration_role=self._migration_role,
                runtime_role=self._runtime_role,
                reader_role=bound_reader,
                hosted_projection=hosted_projection,
            )
            if migration.version == 1 and not self._canonical_state_is_empty(cursor):
                raise PersistenceError("migration-rollback-nonempty")
            if bound_reader is not None and removes_projection:
                self._revoke_reader_role(cursor, database, bound_reader)
                validate_revoked_reader_privileges(cursor, bound_reader)
            for statement in migration.down_statements:
                cursor.execute(statement)
            cursor.execute(
                "DELETE FROM colortrace.schema_migrations WHERE version = %s",
                (migration.version,),
            )
            if migration.version == 1:
                self._revoke_runtime_access(cursor, database)
                self._revoke_reader_access(cursor, database)
            elif migration.version == _HOSTED_PROJECTION_VERSION:
                validate_schema(
                    cursor,
                    migration_role=self._migration_role,
                    runtime_role=self._runtime_role,
                    reader_role=None,
                    hosted_projection=False,
                )
        return migration.version
