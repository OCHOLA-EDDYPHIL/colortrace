from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from colortrace_api import (
    SQLiteRecoveryVerificationTaskStore,
    build_recovery_verification_task,
)
from colortrace_api import recovery_tasks as recovery_task_module
from colortrace_recovery import canonical_json_bytes

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
INCIDENT_ID = "incident-recovery-task"
OUTCOME_SHA256 = f"sha256:{'a' * 64}"


def recovery_task(*, key: str) -> dict[str, Any]:
    return build_recovery_verification_task(
        incident_id=INCIDENT_ID,
        expected_incident_version=4,
        expected_outcome_sha256=OUTCOME_SHA256,
        idempotency_key=key,
    )


def test_v1_task_store_migration_preserves_pending_authorized_tasks(tmp_path: Path) -> None:
    database = tmp_path / "v1-tasks.sqlite3"
    database.touch(mode=0o600)
    task = recovery_task(key="v1-pending")
    timestamp = "2026-08-21T12:00:00.000Z"
    with sqlite3.connect(database) as connection:
        connection.executescript(recovery_task_module._SCHEMA_V1)
        connection.execute(f"PRAGMA application_id = {recovery_task_module._APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 1")
        connection.execute(
            "INSERT INTO recovery_verification_tasks("
            "task_key, idempotency_key, payload_sha256, incident_id, "
            "expected_incident_version, expected_outcome_sha256, task_document, status, "
            "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
            (
                task["task_key"],
                task["idempotency_key"],
                task["payload_sha256"],
                task["incident_id"],
                task["expected_incident_version"],
                task["expected_outcome_sha256"],
                canonical_json_bytes(task),
                timestamp,
                timestamp,
            ),
        )

    store = SQLiteRecoveryVerificationTaskStore(database, clock=lambda: NOW)

    assert store.pending_tasks() == [task]
    assert store.cloud_task_outbox_state(task["task_key"])["status"] == "pending"
    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2


def test_local_completion_suppresses_a_pending_cloud_delivery(tmp_path: Path) -> None:
    store = SQLiteRecoveryVerificationTaskStore(tmp_path / "local.sqlite3", clock=lambda: NOW)
    task = recovery_task(key="completed-before-publish")
    store.dispatch(task)
    claim = store.claim(task, owner="local-worker")
    assert not isinstance(claim, dict)
    result = recovery_task_module.build_unresolved_recovery_verification_result(
        task,
        reason_code="verification-unresolved",
    )

    store.complete(claim, result)

    assert store.cloud_task_outbox_state(task["task_key"])["status"] == "suppressed"
    assert store.reserve_cloud_task_deliveries(limit=1, max_attempts=3) == []
