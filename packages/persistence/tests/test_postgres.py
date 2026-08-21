from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pg8000.dbapi
import pytest
from colortrace_persistence import (
    CanonicalPostgresStore,
    HostedMetadataStores,
    PersistenceError,
    PostgresMigrationRunner,
)
from colortrace_persistence.ports import DbConnection

_NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
_MIGRATION_ROLE = "colortrace_migrator_test"
_RUNTIME_ROLE = "colortrace_runtime_test"


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


def _quoted_literal(cursor: Any, value: str) -> str:
    cursor.execute("SELECT quote_literal(%s)", (value,))
    quoted = cursor.fetchone()[0]
    assert isinstance(quoted, str)
    return quoted


def _clean_database(factory: LocalPostgresFactory) -> None:
    with _cursor(factory) as cursor:
        cursor.execute("DROP SCHEMA IF EXISTS colortrace CASCADE")
        for role in (_MIGRATION_ROLE, _RUNTIME_ROLE):
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

    def runner(self) -> PostgresMigrationRunner:
        return PostgresMigrationRunner(
            self.migration,
            migration_role=_MIGRATION_ROLE,
            runtime_role=_RUNTIME_ROLE,
        )


@pytest.fixture
def postgres() -> Iterator[PostgresEnvironment]:
    admin = LocalPostgresFactory()
    _clean_database(admin)
    migration_password = f"{admin.password}-migration"
    runtime_password = f"{admin.password}-runtime"
    with _cursor(admin) as cursor:
        migration_literal = _quoted_literal(cursor, migration_password)
        runtime_literal = _quoted_literal(cursor, runtime_password)
        cursor.execute(
            f'CREATE ROLE "{_MIGRATION_ROLE}" LOGIN PASSWORD {migration_literal} '
            "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
        cursor.execute(
            f'CREATE ROLE "{_RUNTIME_ROLE}" LOGIN PASSWORD {runtime_literal} '
            "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS"
        )
        cursor.execute(
            f'GRANT CONNECT, CREATE ON DATABASE colortrace_test TO "{_MIGRATION_ROLE}" '
            "WITH GRANT OPTION"
        )
    environment = PostgresEnvironment(
        admin=admin,
        migration=admin.as_user(_MIGRATION_ROLE, migration_password),
        runtime=admin.as_user(_RUNTIME_ROLE, runtime_password),
    )
    try:
        yield environment
    finally:
        _clean_database(admin)


@pytest.fixture
def migrated(postgres: PostgresEnvironment) -> PostgresEnvironment:
    assert postgres.runner().apply_all() == (1,)
    return postgres


def test_migration_is_repeatable_detects_drift_and_rolls_back(
    postgres: PostgresEnvironment,
) -> None:
    runner = postgres.runner()
    assert runner.apply_all() == (1,)
    assert runner.apply_all() == ()
    assert runner.applied() == ((1, "canonical_metadata", runner.applied()[0][2]),)
    assert runner.rollback_latest() == 1
    assert runner.rollback_latest() is None
    assert runner.apply_all() == (1,)

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

    assert sorted(results, key=len) == [(), (1,)]


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


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER TABLE colortrace.metadata_records ADD COLUMN drift TEXT",
        "ALTER TABLE colortrace.metadata_records DROP CONSTRAINT "
        "metadata_records_record_version_check",
        "DROP TRIGGER metadata_record_versions_immutable ON colortrace.metadata_record_versions",
        "CREATE OR REPLACE FUNCTION colortrace.reject_immutable_metadata() "
        "RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN OLD; END;'",
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


def test_rollback_refuses_nonempty_canonical_state(migrated: PostgresEnvironment) -> None:
    store = CanonicalPostgresStore(migrated.runtime, namespace="incident")
    created = store.create("retained", {"state": "created"}, idempotency_key="retain-create")

    with pytest.raises(PersistenceError, match="^migration-rollback-nonempty$"):
        migrated.runner().rollback_latest()

    assert store.read("retained") == created


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
