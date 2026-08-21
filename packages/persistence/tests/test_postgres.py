from __future__ import annotations

import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
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


class LocalPostgresFactory:
    def __init__(self) -> None:
        self.host = os.environ.get("COLORTRACE_POSTGRES_TEST_HOST", "")
        self.port = int(os.environ.get("COLORTRACE_POSTGRES_TEST_PORT", "0"))
        self.database = os.environ.get("COLORTRACE_POSTGRES_TEST_DATABASE", "")
        self.user = os.environ.get("COLORTRACE_POSTGRES_TEST_USER", "")
        self.password = os.environ.get("COLORTRACE_POSTGRES_TEST_PASSWORD", "")
        if (
            self.host not in {"127.0.0.1", "::1"}
            or self.database != "colortrace_test"
            or self.user != "colortrace_test"
            or not 1 <= self.port <= 65535
            or not self.password
        ):
            pytest.skip("isolated loopback PostgreSQL test database is not configured")

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


def _drop_schema(factory: LocalPostgresFactory) -> None:
    with _cursor(factory) as cursor:
        cursor.execute("DROP SCHEMA IF EXISTS colortrace CASCADE")


@pytest.fixture
def postgres() -> Iterator[LocalPostgresFactory]:
    factory = LocalPostgresFactory()
    _drop_schema(factory)
    try:
        yield factory
    finally:
        _drop_schema(factory)


@pytest.fixture
def migrated(postgres: LocalPostgresFactory) -> LocalPostgresFactory:
    assert PostgresMigrationRunner(postgres).apply_all() == (1,)
    return postgres


def test_migration_is_repeatable_detects_drift_and_rolls_back(
    postgres: LocalPostgresFactory,
) -> None:
    runner = PostgresMigrationRunner(postgres)
    assert runner.apply_all() == (1,)
    assert runner.apply_all() == ()
    assert runner.applied() == ((1, "canonical_metadata", runner.applied()[0][2]),)
    assert runner.rollback_latest() == 1
    assert runner.rollback_latest() is None
    assert runner.apply_all() == (1,)

    with _cursor(postgres) as cursor:
        cursor.execute(
            "UPDATE colortrace.schema_migrations SET migration_sha256 = %s WHERE version = 1",
            ("sha256:" + "0" * 64,),
        )
    with pytest.raises(PersistenceError, match="^migration-drift$"):
        runner.apply_all()


def test_hosted_namespaces_share_canonical_semantics_and_preserve_replay(
    migrated: LocalPostgresFactory,
) -> None:
    stores = HostedMetadataStores.from_connection_factory(migrated)
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
    migrated: LocalPostgresFactory,
) -> None:
    store = CanonicalPostgresStore(migrated, namespace="incident")
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
    migrated: LocalPostgresFactory,
) -> None:
    store = CanonicalPostgresStore(migrated, namespace="recovery-task")
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


def test_corruption_and_public_privileges_fail_closed(migrated: LocalPostgresFactory) -> None:
    store = CanonicalPostgresStore(migrated, namespace="simulator-action")
    store.create("action-1", {"state": "accepted"}, idempotency_key="create")
    with _cursor(migrated) as cursor:
        cursor.execute(
            "SELECT has_schema_privilege('public', 'colortrace', 'USAGE'), "
            "has_table_privilege('public', 'colortrace.metadata_records', 'SELECT')"
        )
        assert tuple(cursor.fetchone()) == (False, False)

    connection = migrated.connect()
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

    with _cursor(migrated) as cursor:
        cursor.execute(
            "UPDATE colortrace.metadata_records SET document = %s "
            "WHERE namespace = %s AND record_id = %s",
            (b"{}", "simulator-action", "action-1"),
        )
    with pytest.raises(PersistenceError, match="^stored-metadata-record-invalid$"):
        store.read("action-1")
