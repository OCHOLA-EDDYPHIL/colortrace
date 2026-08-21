from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


class PersistenceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DbCursor(Protocol):
    description: object
    rowcount: int

    def execute(self, operation: str, args: tuple[object, ...] | None = None) -> object: ...

    def fetchone(self) -> object: ...

    def fetchall(self) -> list[object]: ...

    def close(self) -> None: ...


class DbConnection(Protocol):
    def cursor(self) -> DbCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


class ConnectionFactory(Protocol):
    def connect(self) -> DbConnection: ...


@dataclass(frozen=True, slots=True)
class MetadataSnapshot:
    namespace: str
    record_id: str
    version: int
    document: Mapping[str, Any]
    document_sha256: str
    chain_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "canonical-metadata-record/v1",
            "namespace": self.namespace,
            "record_id": self.record_id,
            "version": self.version,
            "document": dict(self.document),
            "document_sha256": self.document_sha256,
            "chain_sha256": self.chain_sha256,
        }


@dataclass(frozen=True, slots=True)
class ClaimSnapshot:
    namespace: str
    record_id: str
    owner: str
    generation: int
    record_version: int
    expires_at: datetime
    event_sequence: int
    event_sha256: str


class CanonicalMetadataPort(Protocol):
    @property
    def namespace(self) -> str: ...

    def create(
        self,
        record_id: str,
        document: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> MetadataSnapshot: ...

    def read(self, record_id: str) -> MetadataSnapshot: ...

    def update(
        self,
        record_id: str,
        document: Mapping[str, Any],
        *,
        expected_version: int,
        idempotency_key: str,
    ) -> MetadataSnapshot: ...

    def claim(
        self,
        record_id: str,
        *,
        owner: str,
        expected_version: int,
        now: datetime,
        lease_seconds: int,
    ) -> ClaimSnapshot: ...

    def renew_claim(
        self,
        claim: ClaimSnapshot,
        *,
        now: datetime,
        lease_seconds: int,
    ) -> ClaimSnapshot: ...

    def complete_claim(
        self,
        claim: ClaimSnapshot,
        document: Mapping[str, Any],
        *,
        idempotency_key: str,
        now: datetime,
    ) -> MetadataSnapshot: ...

    def claim_history(self, record_id: str) -> list[dict[str, Any]]: ...
