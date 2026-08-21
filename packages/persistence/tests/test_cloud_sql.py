from __future__ import annotations

from typing import Any

import pytest
from colortrace_persistence import CloudSqlConnectionFactory, PersistenceError
from google.cloud.sql.connector import IPTypes


class FakeConnector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, object]]] = []
        self.connection = object()
        self.closed = False
        self.failure: Exception | None = None

    def connect(self, instance: str, driver: str, **kwargs: object) -> Any:
        self.calls.append((instance, driver, kwargs))
        if self.failure is not None:
            raise self.failure
        return self.connection

    def close(self) -> None:
        self.closed = True


def test_cloud_sql_factory_uses_private_iam_auth_without_password() -> None:
    connector = FakeConnector()
    factory = CloudSqlConnectionFactory(
        instance_connection_name="example-project:us-central1:colortrace-staging",
        database="colortrace",
        user="colortrace-runtime@example-project.iam",
        connector=connector,
    )

    assert factory.connect() is connector.connection
    assert connector.calls == [
        (
            "example-project:us-central1:colortrace-staging",
            "pg8000",
            {
                "user": "colortrace-runtime@example-project.iam",
                "db": "colortrace",
                "enable_iam_auth": True,
                "ip_type": IPTypes.PRIVATE,
            },
        )
    ]
    assert "password" not in connector.calls[0][2]
    assert "example-project" not in repr(factory)
    assert "connector" not in repr(factory)

    factory.close()
    assert connector.closed


def test_cloud_sql_factory_uses_private_password_auth_without_exposing_secret() -> None:
    connector = FakeConnector()
    factory = CloudSqlConnectionFactory(
        instance_connection_name="example-project:us-central1:colortrace-staging",
        database="colortrace",
        user="postgres",
        connector=connector,
        password="synthetic-admin-password",
    )

    assert factory.connect() is connector.connection
    assert connector.calls == [
        (
            "example-project:us-central1:colortrace-staging",
            "pg8000",
            {
                "user": "postgres",
                "db": "colortrace",
                "enable_iam_auth": False,
                "ip_type": IPTypes.PRIVATE,
                "password": "synthetic-admin-password",
            },
        )
    ]
    assert "synthetic-admin-password" not in repr(factory)


@pytest.mark.parametrize(
    ("instance", "database", "user", "code"),
    [
        ("missing-regions", "colortrace", "runtime", "cloud-sql-instance-invalid"),
        (
            "project:region:instance",
            "bad/database",
            "runtime",
            "cloud-sql-database-invalid",
        ),
        ("project:region:instance", "colortrace", " runtime", "cloud-sql-user-invalid"),
    ],
)
def test_cloud_sql_factory_rejects_ambiguous_identity(
    instance: str,
    database: str,
    user: str,
    code: str,
) -> None:
    with pytest.raises(PersistenceError, match=code):
        CloudSqlConnectionFactory(
            instance_connection_name=instance,
            database=database,
            user=user,
            connector=FakeConnector(),
        )


def test_cloud_sql_factory_sanitizes_connector_failure() -> None:
    connector = FakeConnector()
    connector.failure = RuntimeError("credential-value-that-must-not-escape")
    factory = CloudSqlConnectionFactory(
        instance_connection_name="project:region:instance",
        database="colortrace",
        user="runtime",
        connector=connector,
    )

    with pytest.raises(PersistenceError, match="^cloud-sql-unavailable$") as captured:
        factory.connect()

    assert "credential-value" not in str(captured.value)
