from __future__ import annotations

import hashlib

import pytest
from colortrace_persistence import Migration, PersistenceError, PostgresMigrationRunner
from colortrace_persistence.migrations import load_migrations


class NeverConnect:
    def connect(self) -> None:
        raise AssertionError("validation must fail before a database connection")


def test_migration_bundle_is_contiguous_digest_bound_and_reversible() -> None:
    migrations = load_migrations()

    assert [migration.version for migration in migrations] == [1]
    assert [migration.name for migration in migrations] == ["canonical_metadata"]
    assert all(migration.sha256.startswith("sha256:") for migration in migrations)
    assert all(len(migration.sha256) == 71 for migration in migrations)
    assert all(migration.up_statements for migration in migrations)
    assert all(migration.down_statements for migration in migrations)
    assert "metadata_records" in migrations[0].up_sql
    assert "DROP TABLE IF EXISTS colortrace.metadata_records" in migrations[0].down_sql


def test_migration_digest_changes_if_either_direction_changes() -> None:
    migration = load_migrations()[0]
    expected = (
        "sha256:"
        + hashlib.sha256(
            migration.up_sql.encode("utf-8") + b"\x00" + migration.down_sql.encode("utf-8")
        ).hexdigest()
    )
    changed = (
        "sha256:"
        + hashlib.sha256(
            migration.up_sql.encode("utf-8")
            + b"\x00"
            + (migration.down_sql + "\n-- changed\n").encode("utf-8")
        ).hexdigest()
    )

    assert migration.sha256 == expected
    assert migration.sha256 != changed


def test_migration_runner_fails_closed_on_noncontiguous_input() -> None:
    original = load_migrations()[0]
    invalid = Migration(
        version=2,
        name=original.name,
        up_sql=original.up_sql,
        down_sql=original.down_sql,
        sha256=original.sha256,
    )

    with pytest.raises(PersistenceError, match="^migration-sequence-invalid$"):
        PostgresMigrationRunner(
            NeverConnect(),  # type: ignore[arg-type]
            migration_role="colortrace_migrator",
            runtime_role="colortrace_runtime",
            migrations=(invalid,),
        )


@pytest.mark.parametrize(
    ("migration_role", "runtime_role", "code"),
    [
        ("bad role", "colortrace_runtime", "postgres-migration-role-invalid"),
        ("colortrace_migrator", "bad role", "postgres-runtime-role-invalid"),
        ("colortrace_runtime", "colortrace_runtime", "postgres-role-separation-invalid"),
    ],
)
def test_migration_runner_requires_distinct_safe_role_names(
    migration_role: str,
    runtime_role: str,
    code: str,
) -> None:
    with pytest.raises(PersistenceError, match=f"^{code}$"):
        PostgresMigrationRunner(
            NeverConnect(),  # type: ignore[arg-type]
            migration_role=migration_role,
            runtime_role=runtime_role,
        )
