from __future__ import annotations

import pytest
from colortrace_persistence import PersistenceError, PostgresRoleBootstrapper
from colortrace_persistence.schema_validation import validate_reader_memberships


class NeverConnect:
    def connect(self) -> None:
        raise AssertionError("validation must fail before a database connection")


class MembershipCursor:
    description = (
        ("granted_role",),
        ("member_role",),
        ("admin_option",),
        ("inherit_option",),
        ("set_option",),
    )

    def __init__(self, rows: list[tuple[str, str, bool, bool, bool]]) -> None:
        self.rows = rows
        self.parameters: tuple[str, str] | None = None
        self.statement: str | None = None

    def execute(self, statement: str, parameters: tuple[str, str]) -> None:
        self.statement = statement
        self.parameters = parameters

    def fetchall(self) -> list[tuple[str, str, bool, bool, bool]]:
        return self.rows


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


@pytest.mark.parametrize(
    ("cloud_sql_iam_service_account", "rows"),
    [
        (False, []),
        (
            True,
            [("cloudsqliamserviceaccount", "colortrace_reader", False, True, True)],
        ),
    ],
)
def test_reader_membership_profile_accepts_only_its_exact_mode(
    cloud_sql_iam_service_account: bool,
    rows: list[tuple[str, str, bool, bool, bool]],
) -> None:
    cursor = MembershipCursor(rows)

    validate_reader_memberships(
        cursor,  # type: ignore[arg-type]
        "colortrace_reader",
        cloud_sql_iam_service_account=cloud_sql_iam_service_account,
        code="reader-membership-invalid",
    )

    assert cursor.parameters == ("colortrace_reader", "colortrace_reader")
    assert cursor.statement is not None
    assert "to_jsonb(memberships)" in cursor.statement
    assert "'inherit_option'" in cursor.statement
    assert "'set_option'" in cursor.statement


@pytest.mark.parametrize(
    ("cloud_sql_iam_service_account", "rows"),
    [
        (
            False,
            [("cloudsqliamserviceaccount", "colortrace_reader", False, True, True)],
        ),
        (True, []),
        (
            True,
            [("cloudsqliamserviceaccount", "colortrace_reader", True, True, True)],
        ),
        (
            True,
            [("cloudsqliamserviceaccount", "colortrace_reader", False, False, True)],
        ),
        (
            True,
            [("cloudsqliamserviceaccount", "colortrace_reader", False, True, False)],
        ),
        (
            True,
            [("colortrace_reader", "cloudsqliamserviceaccount", False, True, True)],
        ),
        (
            True,
            [
                ("cloudsqliamserviceaccount", "colortrace_reader", False, True, True),
                ("unexpected_group", "colortrace_reader", False, True, True),
            ],
        ),
    ],
)
def test_reader_membership_profile_rejects_missing_or_additional_edges(
    cloud_sql_iam_service_account: bool,
    rows: list[tuple[str, str, bool, bool, bool]],
) -> None:
    with pytest.raises(PersistenceError, match="^reader-membership-invalid$"):
        validate_reader_memberships(
            MembershipCursor(rows),  # type: ignore[arg-type]
            "colortrace_reader",
            cloud_sql_iam_service_account=cloud_sql_iam_service_account,
            code="reader-membership-invalid",
        )
