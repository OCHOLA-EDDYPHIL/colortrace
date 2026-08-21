from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from google.cloud.sql.connector import Connector, IPTypes

from .ports import DbConnection, PersistenceError

_INSTANCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*:[A-Za-z0-9-]+:[A-Za-z0-9-]+$")
_DATABASE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,62}$")


class CloudSqlConnector(Protocol):
    def connect(self, instance_connection_string: str, driver: str, **kwargs: object) -> Any: ...

    def close(self) -> None: ...


def _identity(value: str, *, code: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PersistenceError(code)
    return value


@dataclass(slots=True, repr=False)
class CloudSqlConnectionFactory:
    instance_connection_name: str
    database: str
    user: str
    connector: CloudSqlConnector = field(repr=False)
    password: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        instance = _identity(
            self.instance_connection_name,
            code="cloud-sql-instance-invalid",
            maximum=256,
        )
        database = _identity(self.database, code="cloud-sql-database-invalid", maximum=63)
        _identity(self.user, code="cloud-sql-user-invalid", maximum=256)
        if self.password is not None:
            _identity(self.password, code="cloud-sql-password-invalid", maximum=16_384)
        if _INSTANCE_NAME.fullmatch(instance) is None:
            raise PersistenceError("cloud-sql-instance-invalid")
        if _DATABASE_NAME.fullmatch(database) is None:
            raise PersistenceError("cloud-sql-database-invalid")
        if not callable(getattr(self.connector, "connect", None)) or not callable(
            getattr(self.connector, "close", None)
        ):
            raise PersistenceError("cloud-sql-connector-invalid")

    @classmethod
    def private_iam(
        cls,
        *,
        instance_connection_name: str,
        database: str,
        user: str,
    ) -> CloudSqlConnectionFactory:
        return cls(
            instance_connection_name=instance_connection_name,
            database=database,
            user=user,
            connector=Connector(refresh_strategy="LAZY"),
        )

    @classmethod
    def private_password(
        cls,
        *,
        instance_connection_name: str,
        database: str,
        user: str,
        password: str,
    ) -> CloudSqlConnectionFactory:
        return cls(
            instance_connection_name=instance_connection_name,
            database=database,
            user=user,
            connector=Connector(refresh_strategy="LAZY"),
            password=password,
        )

    def connect(self) -> DbConnection:
        try:
            options: dict[str, object] = {
                "user": self.user,
                "db": self.database,
                "enable_iam_auth": self.password is None,
                "ip_type": IPTypes.PRIVATE,
            }
            if self.password is not None:
                options["password"] = self.password
            connection = self.connector.connect(
                self.instance_connection_name,
                "pg8000",
                **options,
            )
        except Exception:
            raise PersistenceError("cloud-sql-unavailable") from None
        return cast(DbConnection, connection)

    def close(self) -> None:
        try:
            self.connector.close()
        except Exception:
            raise PersistenceError("cloud-sql-close-failed") from None
