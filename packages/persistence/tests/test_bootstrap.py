from __future__ import annotations

import pytest
from colortrace_persistence import PersistenceError, PostgresRoleBootstrapper


class NeverConnect:
    def connect(self) -> None:
        raise AssertionError("validation must fail before a database connection")


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"database": "bad/database"}, "postgres-bootstrap-database-invalid"),
        ({"admin_role": "bad role"}, "postgres-admin-role-invalid"),
        ({"migration_role": "bad role"}, "postgres-migration-role-invalid"),
        ({"runtime_role": "bad role"}, "postgres-runtime-role-invalid"),
        ({"reader_role": "bad role"}, "postgres-reader-role-invalid"),
        ({"reader_role": "colortrace_runtime"}, "postgres-role-separation-invalid"),
    ],
)
def test_bootstrap_requires_exact_distinct_database_roles(
    change: dict[str, str],
    code: str,
) -> None:
    values = {
        "database": "colortrace",
        "admin_role": "postgres",
        "migration_role": "colortrace_migration",
        "runtime_role": "colortrace_runtime",
        "reader_role": "colortrace_api",
        **change,
    }

    with pytest.raises(PersistenceError, match=f"^{code}$"):
        PostgresRoleBootstrapper(NeverConnect(), **values)  # type: ignore[arg-type]
