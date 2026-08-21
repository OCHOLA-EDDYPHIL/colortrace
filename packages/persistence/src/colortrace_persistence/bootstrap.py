from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, cast

from .ports import ConnectionFactory, DbConnection, DbCursor, PersistenceError

_ROLE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,62}$")
_DATABASE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")


def _safe_name(value: str, *, pattern: re.Pattern[str], code: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise PersistenceError(code)
    return value


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


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
class PostgresRoleBootstrapper:
    connection_factory: ConnectionFactory
    database: str
    admin_role: str
    migration_role: str
    runtime_role: str
    reader_role: str

    def __post_init__(self) -> None:
        _safe_name(
            self.database,
            pattern=_DATABASE_NAME,
            code="postgres-bootstrap-database-invalid",
        )
        for value, code in (
            (self.admin_role, "postgres-admin-role-invalid"),
            (self.migration_role, "postgres-migration-role-invalid"),
            (self.runtime_role, "postgres-runtime-role-invalid"),
            (self.reader_role, "postgres-reader-role-invalid"),
        ):
            _safe_name(value, pattern=_ROLE_NAME, code=code)
        if len({self.admin_role, self.migration_role, self.runtime_role, self.reader_role}) != 4:
            raise PersistenceError("postgres-role-separation-invalid")

    def _validate_identity(self, cursor: DbCursor) -> None:
        cursor.execute("SELECT current_user, current_database()")
        rows = _rows(cursor)
        if len(rows) != 1:
            raise PersistenceError("postgres-result-invalid")
        if rows[0].get("current_user") != self.admin_role:
            raise PersistenceError("postgres-admin-role-mismatch")
        if rows[0].get("current_database") != self.database:
            raise PersistenceError("postgres-bootstrap-database-mismatch")

    def _validate_roles(self, cursor: DbCursor) -> None:
        cursor.execute(
            "SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, "
            "rolreplication, rolbypassrls FROM pg_roles WHERE rolname IN (%s, %s, %s)",
            (self.migration_role, self.runtime_role, self.reader_role),
        )
        roles = {cast(str, row["rolname"]): row for row in _rows(cursor)}
        expected = {self.migration_role, self.runtime_role, self.reader_role}
        if set(roles) != expected:
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
                self.runtime_role,
                self.migration_role,
                self.reader_role,
                self.migration_role,
                self.reader_role,
                self.runtime_role,
            ),
        )
        memberships = _rows(cursor)
        if len(memberships) != 1 or memberships[0] != {
            "runtime_is_migrator": False,
            "reader_is_migrator": False,
            "reader_is_runtime": False,
        }:
            raise PersistenceError("postgres-role-separation-invalid")
        cursor.execute(
            "SELECT EXISTS ("
            "SELECT 1 FROM pg_auth_members AS memberships "
            "JOIN pg_roles AS granted_role ON granted_role.oid = memberships.roleid "
            "JOIN pg_roles AS member_role ON member_role.oid = memberships.member "
            "WHERE granted_role.rolname = %s OR member_role.rolname = %s"
            ") AS has_reader_membership",
            (self.reader_role, self.reader_role),
        )
        reader_memberships = _rows(cursor)
        if (
            len(reader_memberships) != 1
            or reader_memberships[0].get("has_reader_membership") is not False
        ):
            raise PersistenceError("postgres-role-separation-invalid")

    def _apply_privileges(self, cursor: DbCursor) -> None:
        database = _quote_identifier(self.database)
        migration = _quote_identifier(self.migration_role)
        runtime = _quote_identifier(self.runtime_role)
        reader = _quote_identifier(self.reader_role)
        cursor.execute(f"REVOKE ALL PRIVILEGES ON DATABASE {database} FROM PUBLIC")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON DATABASE {database} FROM {migration}")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON DATABASE {database} FROM {runtime}")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON DATABASE {database} FROM {reader}")
        cursor.execute(f"GRANT CONNECT ON DATABASE {database} TO {migration} WITH GRANT OPTION")
        cursor.execute(f"GRANT CREATE ON DATABASE {database} TO {migration}")
        cursor.execute("REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {runtime}")
        cursor.execute(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {reader}")

    def _validate_existing_schema(self, cursor: DbCursor) -> None:
        cursor.execute(
            "SELECT pg_get_userbyid(n.nspowner) AS owner FROM pg_namespace AS n "
            "WHERE n.nspname = 'colortrace'"
        )
        rows = _rows(cursor)
        if len(rows) > 1:
            raise PersistenceError("postgres-result-invalid")
        if rows and rows[0].get("owner") != self.migration_role:
            raise PersistenceError("postgres-bootstrap-schema-owner-invalid")

    def apply(self) -> None:
        with _connection(self.connection_factory) as (_connection_value, cursor):
            self._validate_identity(cursor)
            self._validate_roles(cursor)
            self._apply_privileges(cursor)
            self._validate_existing_schema(cursor)
