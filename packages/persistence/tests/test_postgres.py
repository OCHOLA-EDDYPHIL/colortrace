from __future__ import annotations

import hashlib
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pg8000.dbapi
import pytest
from colortrace_api.hosted_read import (
    _load_seeded_fixture,
    bundled_fixture_digest,
    load_fixture,
    seed_fixture,
)
from colortrace_persistence import (
    HOSTED_FIXTURE_RECORD_ID,
    HOSTED_READINESS_RECORD_ID,
    CanonicalPostgresStore,
    HostedMetadataStores,
    HostedProjectionPostgresStore,
    Migration,
    PersistenceError,
    PostgresMigrationRunner,
    PostgresReaderVerifier,
    PostgresRoleBootstrapper,
    load_migrations,
)
from colortrace_persistence.ports import DbConnection

_NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
_MIGRATION_ROLE = "colortrace_migrator_test"
_RUNTIME_ROLE = "colortrace_runtime_test"
_READER_ROLE = "colortrace_reader_test"
_ROTATED_READER_ROLE = "colortrace_reader_rotated_test"
_READER_GROUP_ROLE = "colortrace_reader_group_test"
_CLOUD_SQL_IAM_SERVICE_ACCOUNT_ROLE = "cloudsqliamserviceaccount"


class LocalPostgresFactory:
    def __init__(
        self,
        *,
        host: str | None = None,
        port: int | None = None,
        database: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> None:
        self.host = os.environ.get("COLORTRACE_POSTGRES_TEST_HOST", "") if host is None else host
        try:
            self.port = (
                int(os.environ.get("COLORTRACE_POSTGRES_TEST_PORT", "0")) if port is None else port
            )
        except ValueError:
            self.port = 0
        self.database = (
            os.environ.get("COLORTRACE_POSTGRES_TEST_DATABASE", "")
            if database is None
            else database
        )
        self.user = os.environ.get("COLORTRACE_POSTGRES_TEST_USER", "") if user is None else user
        self.password = (
            os.environ.get("COLORTRACE_POSTGRES_TEST_PASSWORD", "")
            if password is None
            else password
        )
        if (
            self.host not in {"127.0.0.1", "::1"}
            or self.database != "colortrace_test"
            or not self.user
            or not 1 <= self.port <= 65535
            or not self.password
        ):
            if os.environ.get("COLORTRACE_POSTGRES_TEST_REQUIRED") == "1":
                raise RuntimeError("required isolated loopback PostgreSQL test database is invalid")
            pytest.skip("isolated loopback PostgreSQL test database is not configured")

    def as_user(self, user: str, password: str) -> LocalPostgresFactory:
        return LocalPostgresFactory(
            host=self.host,
            port=self.port,
            database=self.database,
            user=user,
            password=password,
        )

    def connect(self) -> DbConnection:
        return cast(
            DbConnection,
            pg8000.dbapi.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                timeout=5,
            ),
        )


@contextmanager
def _cursor(factory: LocalPostgresFactory) -> Iterator[Any]:
    connection = factory.connect()
    cursor = connection.cursor()
    try:
        yield cursor
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _assert_database_error(factory: LocalPostgresFactory, statement: str) -> None:
    connection = factory.connect()
    cursor = connection.cursor()
    try:
        with pytest.raises(pg8000.dbapi.DatabaseError):
            cursor.execute(statement)
            connection.commit()
        connection.rollback()
    finally:
        cursor.close()
        connection.close()


def _assert_connection_error(factory: LocalPostgresFactory) -> None:
    with pytest.raises(pg8000.dbapi.DatabaseError):
        factory.connect()


def _quoted_literal(cursor: Any, value: str) -> str:
    cursor.execute("SELECT quote_literal(%s)", (value,))
    quoted = cursor.fetchone()[0]
    assert isinstance(quoted, str)
    return quoted


def _clean_database(factory: LocalPostgresFactory) -> None:
    with _cursor(factory) as cursor:
        cursor.execute("DROP SCHEMA IF EXISTS colortrace CASCADE")
        for role in (
            _MIGRATION_ROLE,
            _RUNTIME_ROLE,
            _READER_ROLE,
            _ROTATED_READER_ROLE,
            _READER_GROUP_ROLE,
        ):
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,))
            if cursor.fetchone() is not None:
                cursor.execute(
                    f'REVOKE ALL PRIVILEGES ON DATABASE colortrace_test FROM "{role}" CASCADE'
                )
                cursor.execute(f'DROP OWNED BY "{role}"')
                cursor.execute(f'DROP ROLE "{role}"')


@dataclass(frozen=True, slots=True)
class PostgresEnvironment:
    admin: LocalPostgresFactory
    migration: LocalPostgresFactory
    runtime: LocalPostgresFactory
    reader: LocalPostgresFactory
    rotated_reader: LocalPostgresFactory

    def runner(self, *, reader_role: str = _READER_ROLE) -> PostgresMigrationRunner:
        return PostgresMigrationRunner(
            self.migration,
            migration_role=_MIGRATION_ROLE,
            runtime_role=_RUNTIME_ROLE,
            reader_role=reader_role,
        )


@pytest.fixture
def postgres() -> Iterator[PostgresEnvironment]:
    admin = LocalPostgresFactory()
    _clean_database(admin)
    migration_password = f"{admin.password}-migration"
    runtime_password = f"{admin.password}-runtime"
    reader_password = f"{admin.password}-reader"
    rotated_reader_password = f"{admin.password}-reader-rotated"
    with _cursor(admin) as cursor:
        migration_literal = _quoted_literal(cursor, migration_password)
        runtime_literal = _quoted_literal(cursor, runtime_password)
        reader_literal = _quoted_literal(cursor, reader_password)
        rotated_reader_literal = _quoted_literal(cursor, rotated_reader_password)
        cursor.execute(
            f'CREATE ROLE "{_MIGRATION_ROLE}" LOGIN PASSWORD {migration_literal} '
            "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
        cursor.execute(
            f'CREATE ROLE "{_RUNTIME_ROLE}" LOGIN PASSWORD {runtime_literal} '
            "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
        cursor.execute(
            f'CREATE ROLE "{_READER_ROLE}" LOGIN PASSWORD {reader_literal} '
            "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
        cursor.execute(
            f'CREATE ROLE "{_ROTATED_READER_ROLE}" LOGIN PASSWORD {rotated_reader_literal} '
            "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
    bootstrapper = PostgresRoleBootstrapper(
        admin,
        database="colortrace_test",
        admin_role=admin.user,
        migration_role=_MIGRATION_ROLE,
        runtime_role=_RUNTIME_ROLE,
        reader_role=_READER_ROLE,
    )
    bootstrapper.apply()
    bootstrapper.apply()
    environment = PostgresEnvironment(
        admin=admin,
        migration=admin.as_user(_MIGRATION_ROLE, migration_password),
        runtime=admin.as_user(_RUNTIME_ROLE, runtime_password),
        reader=admin.as_user(_READER_ROLE, reader_password),
        rotated_reader=admin.as_user(_ROTATED_READER_ROLE, rotated_reader_password),
    )
    try:
        yield environment
    finally:
        _clean_database(admin)


@pytest.fixture
def migrated(postgres: PostgresEnvironment) -> PostgresEnvironment:
    assert postgres.runner().apply_all() == (1, 2)
    return postgres


def test_migration_is_repeatable_detects_drift_and_rolls_back(
    postgres: PostgresEnvironment,
) -> None:
    runner = postgres.runner()
    assert runner.apply_all() == (1, 2)
    assert runner.apply_all() == ()
    applied = runner.applied()
    assert [(version, name) for version, name, _digest in applied] == [
        (1, "canonical_metadata"),
        (2, "hosted_read_projection"),
    ]
    assert runner.rollback_latest() == 2
    assert runner.rollback_latest() == 1
    assert runner.rollback_latest() is None
    assert runner.apply_all() == (1, 2)

    with _cursor(postgres.migration) as cursor:
        cursor.execute(
            "UPDATE colortrace.schema_migrations SET migration_sha256 = %s WHERE version = 1",
            ("sha256:" + "0" * 64,),
        )
    with pytest.raises(PersistenceError, match="^migration-drift$"):
        runner.apply_all()


def test_concurrent_initial_migrations_serialize(postgres: PostgresEnvironment) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _value: postgres.runner().apply_all(), range(2)))

    assert sorted(results, key=len) == [(), (1, 2)]


def test_future_migration_rollback_preserves_v2_reader_access(
    postgres: PostgresEnvironment,
) -> None:
    up_sql = "SELECT 1"
    down_sql = "SELECT 1"
    digest = (
        "sha256:"
        + hashlib.sha256(up_sql.encode("utf-8") + b"\x00" + down_sql.encode("utf-8")).hexdigest()
    )
    migration_v3 = Migration(
        version=3,
        name="future_noop",
        up_sql=up_sql,
        down_sql=down_sql,
        sha256=digest,
    )
    runner = PostgresMigrationRunner(
        postgres.migration,
        migration_role=_MIGRATION_ROLE,
        runtime_role=_RUNTIME_ROLE,
        reader_role=_READER_ROLE,
        migrations=(*load_migrations(), migration_v3),
    )
    assert runner.apply_all() == (1, 2, 3)
    fixture_digest = bundled_fixture_digest()
    seed_fixture(
        CanonicalPostgresStore(postgres.migration, namespace="incident"),
        fixture_digest,
    )
    expected = HostedProjectionPostgresStore(postgres.reader).read(HOSTED_FIXTURE_RECORD_ID)

    assert runner.rollback_latest() == 3
    PostgresReaderVerifier(
        postgres.reader,
        database="colortrace_test",
        reader_role=_READER_ROLE,
    ).validate()
    assert HostedProjectionPostgresStore(postgres.reader).read(HOSTED_FIXTURE_RECORD_ID) == expected
    assert [version for version, _name, _digest in runner.applied()] == [1, 2]


def test_v1_upgrade_requires_binding_the_legacy_reader_before_rotation(
    postgres: PostgresEnvironment,
) -> None:
    migration_v1 = (load_migrations()[0],)
    v1_runner = PostgresMigrationRunner(
        postgres.migration,
        migration_role=_MIGRATION_ROLE,
        runtime_role=_RUNTIME_ROLE,
        reader_role=_READER_ROLE,
        migrations=migration_v1,
    )
    assert v1_runner.apply_all() == (1,)
    with _cursor(postgres.migration) as cursor:
        cursor.execute(f'GRANT CONNECT ON DATABASE colortrace_test TO "{_READER_ROLE}"')
        cursor.execute(f'GRANT USAGE ON SCHEMA colortrace TO "{_READER_ROLE}"')
        cursor.execute(
            f"GRANT SELECT ON colortrace.metadata_records, "
            f'colortrace.metadata_record_versions TO "{_READER_ROLE}"'
        )
    digest = bundled_fixture_digest()
    seed_fixture(CanonicalPostgresStore(postgres.migration, namespace="incident"), digest)
    assert (
        CanonicalPostgresStore(postgres.reader, namespace="incident")
        .read(HOSTED_FIXTURE_RECORD_ID)
        .document
        == load_fixture(digest).document
    )

    with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
        postgres.runner(reader_role=_ROTATED_READER_ROLE).apply_all()
    assert [version for version, _name, _digest in postgres.runner().applied()] == [1]
    assert CanonicalPostgresStore(postgres.reader, namespace="incident").read(
        HOSTED_FIXTURE_RECORD_ID
    )

    assert postgres.runner().apply_all() == (2,)
    _assert_database_error(postgres.reader, "SELECT * FROM colortrace.metadata_records")
    assert (
        HostedProjectionPostgresStore(postgres.reader).read(HOSTED_FIXTURE_RECORD_ID).document
        == load_fixture(digest).document
    )


def test_runtime_role_can_use_store_but_cannot_modify_schema(
    migrated: PostgresEnvironment,
) -> None:
    store = CanonicalPostgresStore(migrated.runtime, namespace="incident")
    assert store.create("role-check", {"state": "created"}, idempotency_key="role-create")
    _assert_database_error(
        migrated.runtime,
        "DROP TRIGGER metadata_record_identity_immutable ON colortrace.metadata_records",
    )
    _assert_database_error(
        migrated.runtime,
        "CREATE TABLE colortrace.runtime_ddl_forbidden (id INTEGER)",
    )
    _assert_database_error(
        migrated.runtime,
        "ALTER TABLE colortrace.metadata_records ADD COLUMN runtime_ddl_forbidden TEXT",
    )
    _assert_database_error(migrated.runtime, "DROP TABLE colortrace.metadata_records")
    _assert_database_error(
        migrated.runtime,
        "UPDATE colortrace.metadata_record_versions SET document = '{}'::bytea",
    )


def test_reader_role_can_read_only_the_hosted_projection_and_denies_base_tables(
    migrated: PostgresEnvironment,
) -> None:
    migration_store = CanonicalPostgresStore(migrated.migration, namespace="incident")
    digest = bundled_fixture_digest()
    seeded = seed_fixture(migration_store, digest)
    PostgresReaderVerifier(
        migrated.reader,
        database="colortrace_test",
        reader_role=_READER_ROLE,
    ).validate()
    projection = HostedProjectionPostgresStore(migrated.reader)
    assert (
        projection.read(HOSTED_FIXTURE_RECORD_ID).document
        == load_fixture(seeded.fixture_sha256).document
    )
    assert projection.read(HOSTED_READINESS_RECORD_ID).version == seeded.readiness_record_version
    with pytest.raises(PersistenceError, match="^metadata-record-not-found$"):
        projection.read("reader-check")
    for statement in (
        "SELECT * FROM colortrace.metadata_records",
        "SELECT * FROM colortrace.metadata_record_versions",
        "SELECT * FROM colortrace.hosted_read_bindings",
        "INSERT INTO colortrace.metadata_records "
        "(namespace, record_id, record_version, document, document_sha256, chain_sha256) "
        "VALUES ('incident', 'forbidden', 1, '{}'::bytea, 'sha256:' || repeat('0', 64), "
        "'sha256:' || repeat('0', 64))",
        "UPDATE colortrace.metadata_records SET updated_at = clock_timestamp()",
        "DELETE FROM colortrace.metadata_records",
        "SELECT * FROM colortrace.metadata_idempotency",
        "CREATE TABLE colortrace.reader_ddl_forbidden (id INTEGER)",
        "CREATE TEMPORARY TABLE reader_temp_forbidden (id INTEGER)",
    ):
        _assert_database_error(migrated.reader, statement)


def test_hosted_fixture_seed_replays_and_reader_verifies_readiness(
    migrated: PostgresEnvironment,
) -> None:
    migration_store = CanonicalPostgresStore(migrated.migration, namespace="incident")
    digest = bundled_fixture_digest()

    first = seed_fixture(migration_store, digest)
    second = seed_fixture(migration_store, digest)

    assert first == second
    fixture, readiness = _load_seeded_fixture(
        HostedProjectionPostgresStore(migrated.reader),
        load_fixture(digest),
    )
    assert fixture.version == 1
    assert readiness.version == 1


def test_hosted_projection_excludes_unrelated_incidents_and_other_namespaces(
    migrated: PostgresEnvironment,
) -> None:
    digest = bundled_fixture_digest()
    seed_fixture(CanonicalPostgresStore(migrated.migration, namespace="incident"), digest)
    CanonicalPostgresStore(migrated.runtime, namespace="incident").create(
        "private-incident",
        {"classification": "private"},
        idempotency_key="private-incident-create",
    )
    CanonicalPostgresStore(migrated.runtime, namespace="recovery-task").create(
        HOSTED_FIXTURE_RECORD_ID,
        {"classification": "other-namespace"},
        idempotency_key="other-namespace-create",
    )

    with _cursor(migrated.reader) as cursor:
        cursor.execute(
            "SELECT DISTINCT namespace, record_id "
            "FROM colortrace.hosted_read_projection_v1 ORDER BY namespace, record_id"
        )
        assert cursor.fetchall() == (
            ["incident", HOSTED_READINESS_RECORD_ID],
            ["incident", HOSTED_FIXTURE_RECORD_ID],
        )
    _assert_database_error(migrated.reader, "SELECT * FROM colortrace.metadata_records")
    with pytest.raises(PersistenceError, match="^metadata-record-not-found$"):
        HostedProjectionPostgresStore(migrated.reader).read("private-incident")


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE colortrace.metadata_records ADD COLUMN drift TEXT",
        "ALTER TABLE colortrace.metadata_records DROP CONSTRAINT "
        "metadata_records_record_version_check",
        "DROP TRIGGER metadata_record_versions_immutable ON colortrace.metadata_record_versions",
        "CREATE OR REPLACE FUNCTION colortrace.reject_immutable_metadata() "
        "RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN OLD; END;'",
        "ALTER VIEW colortrace.hosted_read_projection_v1 SET (security_barrier = false)",
    ],
)
def test_migration_rejects_schema_constraint_trigger_and_function_drift(
    migrated: PostgresEnvironment,
    statement: str,
) -> None:
    with _cursor(migrated.migration) as cursor:
        cursor.execute(statement)

    with pytest.raises(PersistenceError, match="^migration-schema-drift$"):
        migrated.runner().apply_all()


def test_migration_repairs_runtime_privilege_drift(migrated: PostgresEnvironment) -> None:
    with _cursor(migrated.migration) as cursor:
        cursor.execute(f'GRANT TRUNCATE ON colortrace.metadata_records TO "{_RUNTIME_ROLE}"')

    assert migrated.runner().apply_all() == ()
    _assert_database_error(migrated.runtime, "TRUNCATE colortrace.metadata_records")


def test_migration_repairs_reader_privilege_drift(migrated: PostgresEnvironment) -> None:
    with _cursor(migrated.migration) as cursor:
        cursor.execute(f'GRANT INSERT ON colortrace.metadata_records TO "{_READER_ROLE}"')

    assert migrated.runner().apply_all() == ()
    PostgresReaderVerifier(
        migrated.reader,
        database="colortrace_test",
        reader_role=_READER_ROLE,
    ).validate()
    _assert_database_error(
        migrated.reader,
        "INSERT INTO colortrace.metadata_records "
        "(namespace, record_id, record_version, document, document_sha256, chain_sha256) "
        "VALUES ('incident', 'forbidden', 1, '{}'::bytea, 'sha256:' || repeat('0', 64), "
        "'sha256:' || repeat('0', 64))",
    )


def test_migration_repairs_reader_column_privilege_drift(
    migrated: PostgresEnvironment,
) -> None:
    with _cursor(migrated.migration) as cursor:
        cursor.execute(
            f'GRANT SELECT (document) ON colortrace.metadata_records TO "{_READER_ROLE}"'
        )

    assert migrated.runner().apply_all() == ()
    _assert_database_error(
        migrated.reader,
        "SELECT document FROM colortrace.metadata_records",
    )


def test_reader_profile_rejects_and_repairs_delegated_grant_option(
    migrated: PostgresEnvironment,
) -> None:
    with _cursor(migrated.migration) as cursor:
        cursor.execute(
            f'GRANT SELECT ON colortrace.hosted_read_projection_v1 TO "{_READER_ROLE}" '
            "WITH GRANT OPTION"
        )
    with _cursor(migrated.reader) as cursor:
        cursor.execute(
            f'GRANT SELECT ON colortrace.hosted_read_projection_v1 TO "{_ROTATED_READER_ROLE}"'
        )

    with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
        PostgresReaderVerifier(
            migrated.reader,
            database="colortrace_test",
            reader_role=_READER_ROLE,
        ).validate()
    assert migrated.runner().apply_all() == ()
    PostgresReaderVerifier(
        migrated.reader,
        database="colortrace_test",
        reader_role=_READER_ROLE,
    ).validate()


def test_migration_rejects_unbound_relation_grantee(
    migrated: PostgresEnvironment,
) -> None:
    with _cursor(migrated.admin) as cursor:
        cursor.execute(f'GRANT SELECT ON colortrace.metadata_records TO "{_ROTATED_READER_ROLE}"')

    with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
        migrated.runner().apply_all()


def test_migration_rejects_missing_persisted_reader_binding(
    migrated: PostgresEnvironment,
) -> None:
    digest = bundled_fixture_digest()
    seed_fixture(CanonicalPostgresStore(migrated.migration, namespace="incident"), digest)
    with _cursor(migrated.reader) as cursor:
        cursor.execute("SELECT count(*) FROM colortrace.hosted_read_projection_v1")
        assert cursor.fetchone() == [2]
    with _cursor(migrated.migration) as cursor:
        cursor.execute("DELETE FROM colortrace.hosted_read_bindings")

    with pytest.raises(PersistenceError, match="^postgres-reader-binding-invalid$"):
        migrated.runner().apply_all()
    with _cursor(migrated.reader) as cursor:
        cursor.execute("SELECT count(*) FROM colortrace.hosted_read_projection_v1")
        assert cursor.fetchone() == [0]
    with pytest.raises(PersistenceError, match="^metadata-record-not-found$"):
        HostedProjectionPostgresStore(migrated.reader).read(HOSTED_FIXTURE_RECORD_ID)


@pytest.mark.parametrize(
    "grant_statement",
    [
        f'GRANT "{_READER_GROUP_ROLE}" TO "{_READER_ROLE}"',
        f'GRANT "{_READER_ROLE}" TO "{_READER_GROUP_ROLE}"',
    ],
)
def test_reader_profile_rejects_role_membership_edges(
    migrated: PostgresEnvironment,
    grant_statement: str,
) -> None:
    with _cursor(migrated.admin) as cursor:
        cursor.execute(
            f'CREATE ROLE "{_READER_GROUP_ROLE}" NOLOGIN NOSUPERUSER NOCREATEDB '
            "NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
        cursor.execute(grant_statement)

    with pytest.raises(PersistenceError, match="^postgres-role-separation-invalid$"):
        PostgresRoleBootstrapper(
            migrated.admin,
            database="colortrace_test",
            admin_role=migrated.admin.user,
            migration_role=_MIGRATION_ROLE,
            runtime_role=_RUNTIME_ROLE,
            reader_role=_READER_ROLE,
        ).apply()
    with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
        migrated.runner().apply_all()
    with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
        PostgresReaderVerifier(
            migrated.reader,
            database="colortrace_test",
            reader_role=_READER_ROLE,
        ).validate()


def test_cloud_sql_iam_membership_profile_preserves_exact_reader_isolation(
    postgres: PostgresEnvironment,
) -> None:
    roles = (_MIGRATION_ROLE, _RUNTIME_ROLE, _READER_ROLE, _ROTATED_READER_ROLE)
    with _cursor(postgres.admin) as cursor:
        cursor.execute(
            f'CREATE ROLE "{_CLOUD_SQL_IAM_SERVICE_ACCOUNT_ROLE}" NOLOGIN NOSUPERUSER '
            "NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
        for role in roles:
            cursor.execute(f'GRANT "{_CLOUD_SQL_IAM_SERVICE_ACCOUNT_ROLE}" TO "{role}"')

    try:
        bootstrapper = PostgresRoleBootstrapper(
            postgres.admin,
            database="colortrace_test",
            admin_role=postgres.admin.user,
            migration_role=_MIGRATION_ROLE,
            runtime_role=_RUNTIME_ROLE,
            reader_role=_READER_ROLE,
            cloud_sql_iam_service_account=True,
        )
        bootstrapper.apply()
        bootstrapper.apply()

        runner = PostgresMigrationRunner(
            postgres.migration,
            migration_role=_MIGRATION_ROLE,
            runtime_role=_RUNTIME_ROLE,
            reader_role=_READER_ROLE,
            cloud_sql_iam_service_account=True,
        )
        assert runner.apply_all() == (1, 2)
        assert runner.apply_all() == ()
        PostgresReaderVerifier(
            postgres.reader,
            database="colortrace_test",
            reader_role=_READER_ROLE,
            cloud_sql_iam_service_account=True,
        ).validate()

        with _cursor(postgres.admin) as cursor:
            cursor.execute("SELECT current_setting('server_version_num')::integer")
            server_version = cursor.fetchone()[0]
        if server_version >= 160000:
            for option in ("INHERIT", "SET"):
                with _cursor(postgres.admin) as cursor:
                    cursor.execute(
                        f'GRANT "{_CLOUD_SQL_IAM_SERVICE_ACCOUNT_ROLE}" '
                        f'TO "{_READER_ROLE}" WITH {option} FALSE'
                    )
                with pytest.raises(
                    PersistenceError,
                    match="^postgres-reader-privilege-invalid$",
                ):
                    PostgresReaderVerifier(
                        postgres.reader,
                        database="colortrace_test",
                        reader_role=_READER_ROLE,
                        cloud_sql_iam_service_account=True,
                    ).validate()
                with _cursor(postgres.admin) as cursor:
                    cursor.execute(
                        f'GRANT "{_CLOUD_SQL_IAM_SERVICE_ACCOUNT_ROLE}" '
                        f'TO "{_READER_ROLE}" WITH {option} TRUE'
                    )
                PostgresReaderVerifier(
                    postgres.reader,
                    database="colortrace_test",
                    reader_role=_READER_ROLE,
                    cloud_sql_iam_service_account=True,
                ).validate()

        rotated_runner = PostgresMigrationRunner(
            postgres.migration,
            migration_role=_MIGRATION_ROLE,
            runtime_role=_RUNTIME_ROLE,
            reader_role=_ROTATED_READER_ROLE,
            cloud_sql_iam_service_account=True,
        )
        assert rotated_runner.apply_all() == ()
        PostgresReaderVerifier(
            postgres.rotated_reader,
            database="colortrace_test",
            reader_role=_ROTATED_READER_ROLE,
            cloud_sql_iam_service_account=True,
        ).validate()
        with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
            PostgresReaderVerifier(
                postgres.rotated_reader,
                database="colortrace_test",
                reader_role=_ROTATED_READER_ROLE,
            ).validate()
    finally:
        with _cursor(postgres.admin) as cursor:
            for role in roles:
                cursor.execute(f'REVOKE "{_CLOUD_SQL_IAM_SERVICE_ACCOUNT_ROLE}" FROM "{role}"')
            cursor.execute(f'DROP ROLE "{_CLOUD_SQL_IAM_SERVICE_ACCOUNT_ROLE}"')


def test_reader_rotation_is_atomic_and_revokes_existing_sessions(
    migrated: PostgresEnvironment,
) -> None:
    digest = bundled_fixture_digest()
    seed_fixture(CanonicalPostgresStore(migrated.migration, namespace="incident"), digest)
    rotated_runner = migrated.runner(reader_role=_ROTATED_READER_ROLE)
    old_connection = migrated.reader.connect()
    old_cursor = old_connection.cursor()
    try:
        old_cursor.execute(
            "PREPARE hosted_read_probe AS SELECT count(*) FROM colortrace.hosted_read_projection_v1"
        )
        old_cursor.execute("EXECUTE hosted_read_probe")
        assert old_cursor.fetchone() == [2]
        old_connection.commit()

        with _cursor(migrated.admin) as cursor:
            cursor.execute(f'GRANT CREATE ON SCHEMA public TO "{_ROTATED_READER_ROLE}"')
        with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
            rotated_runner.apply_all()

        old_cursor.execute("EXECUTE hosted_read_probe")
        assert old_cursor.fetchone() == [2]
        old_connection.commit()
        _assert_connection_error(migrated.rotated_reader)
        with _cursor(migrated.migration) as cursor:
            cursor.execute(
                "SELECT reader_role FROM colortrace.hosted_read_bindings "
                "WHERE binding_key = 'hosted-read-v1'"
            )
            assert cursor.fetchone() == [_READER_ROLE]

        with _cursor(migrated.admin) as cursor:
            cursor.execute(f'REVOKE CREATE ON SCHEMA public FROM "{_ROTATED_READER_ROLE}"')
        assert rotated_runner.apply_all() == ()
        with pytest.raises(pg8000.dbapi.DatabaseError):
            old_cursor.execute("EXECUTE hosted_read_probe")
        old_connection.rollback()
    finally:
        old_cursor.close()
        old_connection.close()

    _assert_connection_error(migrated.reader)
    PostgresReaderVerifier(
        migrated.rotated_reader,
        database="colortrace_test",
        reader_role=_ROTATED_READER_ROLE,
    ).validate()
    fixture = HostedProjectionPostgresStore(migrated.rotated_reader).read(HOSTED_FIXTURE_RECORD_ID)
    assert fixture.document == load_fixture(digest).document
    assert rotated_runner.apply_all() == ()


def test_reader_profile_fails_closed_on_out_of_band_schema_create_grant(
    migrated: PostgresEnvironment,
) -> None:
    with _cursor(migrated.admin) as cursor:
        cursor.execute(f'GRANT CREATE ON SCHEMA public TO "{_READER_ROLE}"')

    with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
        migrated.runner().apply_all()
    with pytest.raises(PersistenceError, match="^postgres-reader-privilege-invalid$"):
        PostgresReaderVerifier(
            migrated.reader,
            database="colortrace_test",
            reader_role=_READER_ROLE,
        ).validate()


def test_public_database_connect_is_denied_and_drift_fails_closed(
    migrated: PostgresEnvironment,
) -> None:
    with _cursor(migrated.migration) as cursor:
        cursor.execute("SELECT has_database_privilege('public', current_database(), 'CONNECT')")
        assert cursor.fetchone() == [False]
    PostgresReaderVerifier(
        migrated.reader,
        database="colortrace_test",
        reader_role=_READER_ROLE,
    ).validate()

    with _cursor(migrated.admin) as cursor:
        cursor.execute("GRANT CONNECT ON DATABASE colortrace_test TO PUBLIC")

    with pytest.raises(PersistenceError, match="^postgres-public-privilege-invalid$"):
        migrated.runner().apply_all()
    with pytest.raises(PersistenceError, match="^postgres-public-privilege-invalid$"):
        PostgresReaderVerifier(
            migrated.reader,
            database="colortrace_test",
            reader_role=_READER_ROLE,
        ).validate()


def test_projection_rollback_preserves_seed_and_idempotent_replay(
    migrated: PostgresEnvironment,
) -> None:
    digest = bundled_fixture_digest()
    store = CanonicalPostgresStore(migrated.migration, namespace="incident")
    first = seed_fixture(store, digest)

    def counts() -> list[int]:
        with _cursor(migrated.migration) as cursor:
            cursor.execute(
                "SELECT (SELECT count(*) FROM colortrace.metadata_records), "
                "(SELECT count(*) FROM colortrace.metadata_record_versions), "
                "(SELECT count(*) FROM colortrace.metadata_idempotency)"
            )
            values = cursor.fetchone()
        assert values is not None
        return cast(list[int], values)

    expected_counts = counts()

    assert migrated.runner().rollback_latest() == 2
    assert counts() == expected_counts
    assert store.read(HOSTED_FIXTURE_RECORD_ID).document == load_fixture(digest).document

    assert migrated.runner().apply_all() == (2,)
    assert seed_fixture(store, digest) == first
    assert counts() == expected_counts
    fixture, readiness = _load_seeded_fixture(
        HostedProjectionPostgresStore(migrated.reader),
        load_fixture(digest),
    )
    assert fixture.version == first.fixture_record_version
    assert readiness.version == first.readiness_record_version

    assert migrated.runner().rollback_latest() == 2
    with pytest.raises(PersistenceError, match="^migration-rollback-nonempty$"):
        migrated.runner().rollback_latest()
    assert counts() == expected_counts


def test_hosted_namespaces_share_canonical_semantics_and_preserve_replay(
    migrated: PostgresEnvironment,
) -> None:
    stores = HostedMetadataStores.from_connection_factory(migrated.runtime)
    expected = {
        "incident": stores.incidents,
        "response-plan": stores.response_plans,
        "recovery": stores.recovery,
        "recovery-task": stores.recovery_tasks,
        "simulator-action": stores.simulator_actions,
    }

    for namespace, store in expected.items():
        created = store.create("record-1", {"state": "created"}, idempotency_key="create-1")
        assert created.namespace == namespace
        assert created.version == 1
        assert store.create("record-1", {"state": "created"}, idempotency_key="create-1") == created
        with pytest.raises(PersistenceError, match="^metadata-record-conflict$"):
            store.create("record-1", {"state": "created"}, idempotency_key="create-duplicate")
        updated = store.update(
            "record-1",
            {"state": "updated", "ordinal": 2},
            expected_version=1,
            idempotency_key="update-1",
        )
        assert updated.version == 2
        assert (
            store.update(
                "record-1",
                {"ordinal": 2, "state": "updated"},
                expected_version=1,
                idempotency_key="update-1",
            )
            == updated
        )
        assert store.read("record-1") == updated


def test_concurrent_updates_are_fenced_and_failed_write_rolls_back(
    migrated: PostgresEnvironment,
) -> None:
    store = CanonicalPostgresStore(migrated.runtime, namespace="incident")
    store.create("incident-1", {"state": "created"}, idempotency_key="create")

    def update(ordinal: int) -> int | str:
        try:
            return store.update(
                "incident-1",
                {"state": "updated", "ordinal": ordinal},
                expected_version=1,
                idempotency_key=f"update-{ordinal}",
            ).version
        except PersistenceError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(update, (1, 2)))

    assert sorted(results, key=str) == sorted([2, "metadata-version-conflict"], key=str)
    assert store.read("incident-1").version == 2
    with pytest.raises(PersistenceError, match="^metadata-idempotency-conflict$"):
        store.update(
            "incident-1",
            {"state": "different"},
            expected_version=1,
            idempotency_key="update-1" if results[0] == 2 else "update-2",
        )
    assert store.read("incident-1").version == 2


def test_claim_recovery_fences_stale_owner_and_completion_replays_without_action(
    migrated: PostgresEnvironment,
) -> None:
    store = CanonicalPostgresStore(migrated.runtime, namespace="recovery-task")
    store.create("task-1", {"state": "pending"}, idempotency_key="create")
    first = store.claim("task-1", owner="worker-a", expected_version=1, now=_NOW, lease_seconds=10)
    assert (
        store.claim(
            "task-1",
            owner="worker-a",
            expected_version=1,
            now=_NOW + timedelta(seconds=1),
            lease_seconds=10,
        )
        == first
    )
    with pytest.raises(PersistenceError, match="^claim-in-progress$"):
        store.claim(
            "task-1",
            owner="worker-b",
            expected_version=1,
            now=_NOW + timedelta(seconds=2),
            lease_seconds=10,
        )

    recovered = store.claim(
        "task-1",
        owner="worker-b",
        expected_version=1,
        now=_NOW + timedelta(seconds=11),
        lease_seconds=10,
    )
    assert recovered.generation == 2
    with pytest.raises(PersistenceError, match="^claim-fenced$"):
        store.renew_claim(first, now=_NOW + timedelta(seconds=12), lease_seconds=20)
    renewed = store.renew_claim(
        recovered,
        now=_NOW + timedelta(seconds=12),
        lease_seconds=20,
    )
    completed = store.complete_claim(
        renewed,
        {"state": "completed"},
        idempotency_key="complete",
        now=_NOW + timedelta(seconds=13),
    )
    assert completed.version == 2
    assert (
        store.complete_claim(
            renewed,
            {"state": "completed"},
            idempotency_key="complete",
            now=_NOW + timedelta(seconds=13),
        )
        == completed
    )
    assert [event["event_type"] for event in store.claim_history("task-1")] == [
        "acquired",
        "reclaimed",
        "renewed",
        "completed",
    ]


def test_claim_events_reject_clock_regression(migrated: PostgresEnvironment) -> None:
    store = CanonicalPostgresStore(migrated.runtime, namespace="recovery-task")
    store.create("clock-task", {"state": "pending"}, idempotency_key="clock-create")
    claim = store.claim(
        "clock-task",
        owner="worker",
        expected_version=1,
        now=_NOW,
        lease_seconds=10,
    )

    with pytest.raises(PersistenceError, match="^claim-clock-regression$"):
        store.claim(
            "clock-task",
            owner="worker",
            expected_version=1,
            now=_NOW - timedelta(seconds=5),
            lease_seconds=10,
        )
    with pytest.raises(PersistenceError, match="^claim-clock-regression$"):
        store.renew_claim(
            claim,
            now=_NOW - timedelta(seconds=5),
            lease_seconds=20,
        )
    renewed = store.renew_claim(
        claim,
        now=_NOW + timedelta(seconds=1),
        lease_seconds=20,
    )
    with pytest.raises(PersistenceError, match="^claim-clock-regression$"):
        store.complete_claim(
            renewed,
            {"state": "complete"},
            idempotency_key="clock-complete",
            now=_NOW,
        )
    store.complete_claim(
        renewed,
        {"state": "complete"},
        idempotency_key="clock-complete",
        now=_NOW + timedelta(seconds=2),
    )
    times = [event["occurred_at"] for event in store.claim_history("clock-task")]
    assert times == sorted(times)


def test_corruption_and_public_privileges_fail_closed(migrated: PostgresEnvironment) -> None:
    store = CanonicalPostgresStore(migrated.runtime, namespace="simulator-action")
    store.create("action-1", {"state": "accepted"}, idempotency_key="create")
    with _cursor(migrated.migration) as cursor:
        cursor.execute(
            "SELECT has_schema_privilege('public', 'colortrace', 'USAGE'), "
            "has_table_privilege('public', 'colortrace.metadata_records', 'SELECT')"
        )
        assert tuple(cursor.fetchone()) == (False, False)

    connection = migrated.runtime.connect()
    cursor = connection.cursor()
    try:
        with pytest.raises(pg8000.dbapi.DatabaseError):
            cursor.execute(
                "UPDATE colortrace.metadata_record_versions SET document = %s",
                (b"{}",),
            )
            connection.commit()
        connection.rollback()
    finally:
        cursor.close()
        connection.close()

    with _cursor(migrated.runtime) as cursor:
        cursor.execute(
            "UPDATE colortrace.metadata_records SET document = %s "
            "WHERE namespace = %s AND record_id = %s",
            (b"{}", "simulator-action", "action-1"),
        )
    with pytest.raises(PersistenceError, match="^stored-metadata-record-invalid$"):
        store.read("action-1")
