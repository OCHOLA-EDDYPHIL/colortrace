from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from .ports import (
    ClaimSnapshot,
    ConnectionFactory,
    DbConnection,
    DbCursor,
    MetadataSnapshot,
    PersistenceError,
)

_NAMESPACES = frozenset(
    {"incident", "response-plan", "recovery", "recovery-task", "simulator-action"}
)
_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _plain_json(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key or len(key) > 256 or key in result:
                raise PersistenceError("metadata-document-invalid")
            result[key] = _plain_json(child)
        return result
    if isinstance(value, (list, tuple)):
        return [_plain_json(child) for child in value]
    raise PersistenceError("metadata-document-invalid")


def _canonical_json(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            _plain_json(value),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (RecursionError, TypeError, UnicodeError, ValueError):
        raise PersistenceError("metadata-document-invalid") from None
    if not encoded or len(encoded) > _MAX_DOCUMENT_BYTES:
        raise PersistenceError("metadata-document-invalid")
    return encoded


def _duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_float(_value: str) -> None:
    raise ValueError("floating-point value")


def _decode_document(value: object, *, code: str) -> dict[str, Any]:
    if isinstance(value, memoryview):
        raw = value.tobytes()
    elif isinstance(value, bytearray):
        raw = bytes(value)
    elif isinstance(value, bytes):
        raw = value
    else:
        raise PersistenceError(code)
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (RecursionError, UnicodeError, ValueError, json.JSONDecodeError):
        raise PersistenceError(code) from None
    if not isinstance(document, dict) or _canonical_json(document) != raw:
        raise PersistenceError(code)
    return document


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _safe_text(value: str, *, code: str, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PersistenceError(code)
    return value


def _time(value: datetime, *, code: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PersistenceError(code)
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _column_names(cursor: DbCursor) -> tuple[str, ...]:
    description = cursor.description
    if not isinstance(description, (list, tuple)):
        raise PersistenceError("postgres-result-invalid")
    names: list[str] = []
    for value in description:
        if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
            names.append(value[0])
            continue
        name = getattr(value, "name", None)
        if not isinstance(name, str):
            raise PersistenceError("postgres-result-invalid")
        names.append(name)
    return tuple(names)


def _rows(cursor: DbCursor) -> list[dict[str, Any]]:
    names = _column_names(cursor)
    values = cursor.fetchall()
    rows: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, (list, tuple)) or len(value) != len(names):
            raise PersistenceError("postgres-result-invalid")
        rows.append(dict(zip(names, value, strict=True)))
    return rows


def _one(cursor: DbCursor) -> dict[str, Any] | None:
    names = _column_names(cursor)
    value = cursor.fetchone()
    if value is None:
        return None
    if not isinstance(value, (list, tuple)) or len(value) != len(names):
        raise PersistenceError("postgres-result-invalid")
    return dict(zip(names, value, strict=True))


@contextmanager
def _transaction(factory: ConnectionFactory) -> Iterator[DbCursor]:
    connection: DbConnection | None = None
    cursor: DbCursor | None = None
    try:
        connection = factory.connect()
        cursor = connection.cursor()
    except PersistenceError:
        if connection is not None:
            connection.close()
        raise
    except Exception:
        if connection is not None:
            connection.close()
        raise PersistenceError("postgres-unavailable") from None
    try:
        yield cursor
        connection.commit()
    except PersistenceError:
        try:
            connection.rollback()
        except Exception:
            raise PersistenceError("postgres-rollback-failed") from None
        raise
    except Exception:
        try:
            connection.rollback()
        except Exception:
            raise PersistenceError("postgres-rollback-failed") from None
        raise PersistenceError("postgres-operation-failed") from None
    finally:
        failed = False
        try:
            cursor.close()
        except Exception:
            failed = True
        finally:
            try:
                connection.close()
            except Exception:
                failed = True
        if failed:
            raise PersistenceError("postgres-close-failed")


def _advisory_key(*values: str) -> int:
    token = "\x00".join(values).encode("utf-8")
    return int.from_bytes(hashlib.sha256(token).digest()[:8], "big", signed=True)


def _lock(cursor: DbCursor, *values: str) -> None:
    cursor.execute("SELECT pg_advisory_xact_lock(%s)", (_advisory_key(*values),))


def _chain_sha256(
    *,
    namespace: str,
    record_id: str,
    version: int,
    document_sha256: str,
    previous_chain_sha256: str | None,
) -> str:
    return _sha256(
        _canonical_json(
            {
                "schema": "canonical-metadata-chain/v1",
                "namespace": namespace,
                "record_id": record_id,
                "version": version,
                "document_sha256": document_sha256,
                "previous_chain_sha256": previous_chain_sha256,
            }
        )
    )


def _claim_event_sha256(
    *,
    namespace: str,
    record_id: str,
    sequence: int,
    generation: int,
    event_type: str,
    owner: str,
    record_version: int,
    expires_at: datetime | None,
    previous_event_sha256: str | None,
    occurred_at: datetime,
) -> str:
    return _sha256(
        _canonical_json(
            {
                "schema": "canonical-metadata-claim-event/v1",
                "namespace": namespace,
                "record_id": record_id,
                "sequence": sequence,
                "generation": generation,
                "event_type": event_type,
                "owner": owner,
                "record_version": record_version,
                "expires_at": None if expires_at is None else _timestamp(expires_at),
                "previous_event_sha256": previous_event_sha256,
                "occurred_at": _timestamp(occurred_at),
            }
        )
    )


_RECORD_QUERY = """
SELECT
    records.record_version AS current_version,
    records.document AS current_document,
    records.document_sha256 AS current_document_sha256,
    records.chain_sha256 AS current_chain_sha256,
    versions.record_version AS history_version,
    versions.document AS history_document,
    versions.document_sha256 AS history_document_sha256,
    versions.previous_chain_sha256 AS history_previous_chain_sha256,
    versions.chain_sha256 AS history_chain_sha256
FROM colortrace.metadata_records AS records
JOIN colortrace.metadata_record_versions AS versions
  ON versions.namespace = records.namespace
 AND versions.record_id = records.record_id
WHERE records.namespace = %s AND records.record_id = %s
ORDER BY versions.record_version
"""


class CanonicalPostgresStore:
    def __init__(self, connection_factory: ConnectionFactory, *, namespace: str) -> None:
        if namespace not in _NAMESPACES:
            raise PersistenceError("metadata-namespace-invalid")
        self._factory = connection_factory
        self._namespace = namespace

    @property
    def namespace(self) -> str:
        return self._namespace

    def _load(
        self,
        cursor: DbCursor,
        record_id: str,
        *,
        for_update: bool,
        required: bool,
    ) -> MetadataSnapshot | None:
        query = _RECORD_QUERY + (" FOR UPDATE OF records" if for_update else "")
        cursor.execute(query, (self._namespace, record_id))
        rows = _rows(cursor)
        if not rows:
            if required:
                raise PersistenceError("metadata-record-not-found")
            return None
        expected_version = 1
        previous_chain: str | None = None
        final_document: dict[str, Any] | None = None
        final_document_bytes: bytes | None = None
        final_document_sha256: str | None = None
        final_chain_sha256: str | None = None
        for row in rows:
            if row.get("history_version") != expected_version:
                raise PersistenceError("stored-metadata-history-invalid")
            document = _decode_document(
                row.get("history_document"), code="stored-metadata-document-invalid"
            )
            document_bytes = _canonical_json(document)
            document_sha256 = _sha256(document_bytes)
            if (
                row.get("history_document_sha256") != document_sha256
                or row.get("history_previous_chain_sha256") != previous_chain
            ):
                raise PersistenceError("stored-metadata-history-invalid")
            chain_sha256 = _chain_sha256(
                namespace=self._namespace,
                record_id=record_id,
                version=expected_version,
                document_sha256=document_sha256,
                previous_chain_sha256=previous_chain,
            )
            if row.get("history_chain_sha256") != chain_sha256:
                raise PersistenceError("stored-metadata-history-invalid")
            final_document = document
            final_document_bytes = document_bytes
            final_document_sha256 = document_sha256
            final_chain_sha256 = chain_sha256
            previous_chain = chain_sha256
            expected_version += 1
        last = rows[-1]
        if (
            final_document is None
            or final_document_bytes is None
            or final_document_sha256 is None
            or final_chain_sha256 is None
            or last.get("current_version") != expected_version - 1
        ):
            raise PersistenceError("stored-metadata-record-invalid")
        current_document = _decode_document(
            last.get("current_document"), code="stored-metadata-document-invalid"
        )
        if (
            _canonical_json(current_document) != final_document_bytes
            or last.get("current_document_sha256") != final_document_sha256
            or last.get("current_chain_sha256") != final_chain_sha256
        ):
            raise PersistenceError("stored-metadata-record-invalid")
        return MetadataSnapshot(
            namespace=self._namespace,
            record_id=record_id,
            version=expected_version - 1,
            document=final_document,
            document_sha256=final_document_sha256,
            chain_sha256=final_chain_sha256,
        )

    @staticmethod
    def _request_sha256(value: Mapping[str, Any]) -> str:
        return _sha256(_canonical_json(value))

    def _idempotent_replay(
        self,
        cursor: DbCursor,
        *,
        operation: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> MetadataSnapshot | None:
        cursor.execute(
            "SELECT operation, request_sha256, response_document, response_sha256 "
            "FROM colortrace.metadata_idempotency "
            "WHERE namespace = %s AND idempotency_key = %s",
            (self._namespace, idempotency_key),
        )
        row = _one(cursor)
        if row is None:
            return None
        if row.get("operation") != operation or row.get("request_sha256") != request_sha256:
            raise PersistenceError("metadata-idempotency-conflict")
        response = _decode_document(
            row.get("response_document"), code="stored-idempotency-response-invalid"
        )
        response_bytes = _canonical_json(response)
        if row.get("response_sha256") != _sha256(response_bytes):
            raise PersistenceError("stored-idempotency-response-invalid")
        snapshot = self._snapshot_from_response(response)
        cursor.execute(
            "SELECT document, document_sha256, chain_sha256 "
            "FROM colortrace.metadata_record_versions "
            "WHERE namespace = %s AND record_id = %s AND record_version = %s",
            (self._namespace, snapshot.record_id, snapshot.version),
        )
        version = _one(cursor)
        if version is None:
            raise PersistenceError("stored-idempotency-response-invalid")
        stored_document = _decode_document(
            version.get("document"), code="stored-idempotency-response-invalid"
        )
        if (
            _canonical_json(stored_document) != _canonical_json(snapshot.document)
            or version.get("document_sha256") != snapshot.document_sha256
            or version.get("chain_sha256") != snapshot.chain_sha256
        ):
            raise PersistenceError("stored-idempotency-response-invalid")
        return snapshot

    def _snapshot_from_response(self, value: Mapping[str, Any]) -> MetadataSnapshot:
        if (
            set(value)
            != {
                "schema",
                "namespace",
                "record_id",
                "version",
                "document",
                "document_sha256",
                "chain_sha256",
            }
            or value.get("schema") != "canonical-metadata-record/v1"
        ):
            raise PersistenceError("stored-idempotency-response-invalid")
        record_id = value.get("record_id")
        version = value.get("version")
        document = value.get("document")
        if (
            value.get("namespace") != self._namespace
            or not isinstance(record_id, str)
            or _safe_text(record_id, code="stored-idempotency-response-invalid") != record_id
            or not isinstance(version, int)
            or isinstance(version, bool)
            or version < 1
            or not isinstance(document, Mapping)
        ):
            raise PersistenceError("stored-idempotency-response-invalid")
        document_bytes = _canonical_json(document)
        document_sha256 = _sha256(document_bytes)
        chain_sha256 = value.get("chain_sha256")
        if (
            value.get("document_sha256") != document_sha256
            or not isinstance(chain_sha256, str)
            or _DIGEST.fullmatch(chain_sha256) is None
        ):
            raise PersistenceError("stored-idempotency-response-invalid")
        return MetadataSnapshot(
            namespace=self._namespace,
            record_id=record_id,
            version=version,
            document=cast(Mapping[str, Any], _plain_json(document)),
            document_sha256=document_sha256,
            chain_sha256=chain_sha256,
        )

    def _record_idempotency(
        self,
        cursor: DbCursor,
        *,
        operation: str,
        idempotency_key: str,
        request_sha256: str,
        response: MetadataSnapshot,
    ) -> None:
        response_document = _canonical_json(response.to_dict())
        cursor.execute(
            "INSERT INTO colortrace.metadata_idempotency "
            "(namespace, idempotency_key, operation, request_sha256, "
            "response_document, response_sha256) VALUES (%s, %s, %s, %s, %s, %s)",
            (
                self._namespace,
                idempotency_key,
                operation,
                request_sha256,
                response_document,
                _sha256(response_document),
            ),
        )

    def create(
        self,
        record_id: str,
        document: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> MetadataSnapshot:
        record = _safe_text(record_id, code="metadata-record-id-invalid")
        key = _safe_text(idempotency_key, code="metadata-idempotency-key-invalid")
        document_bytes = _canonical_json(document)
        document_sha256 = _sha256(document_bytes)
        request_sha256 = self._request_sha256(
            {
                "operation": "create",
                "namespace": self._namespace,
                "record_id": record,
                "document_sha256": document_sha256,
            }
        )
        with _transaction(self._factory) as cursor:
            _lock(cursor, "idempotency", self._namespace, key)
            replay = self._idempotent_replay(
                cursor,
                operation="create",
                idempotency_key=key,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            _lock(cursor, "record", self._namespace, record)
            existing = self._load(cursor, record, for_update=True, required=False)
            if existing is not None:
                raise PersistenceError("metadata-record-conflict")
            else:
                chain_sha256 = _chain_sha256(
                    namespace=self._namespace,
                    record_id=record,
                    version=1,
                    document_sha256=document_sha256,
                    previous_chain_sha256=None,
                )
                cursor.execute(
                    "INSERT INTO colortrace.metadata_records "
                    "(namespace, record_id, record_version, document, document_sha256, "
                    "chain_sha256) "
                    "VALUES (%s, %s, 1, %s, %s, %s)",
                    (self._namespace, record, document_bytes, document_sha256, chain_sha256),
                )
                cursor.execute(
                    "INSERT INTO colortrace.metadata_record_versions "
                    "(namespace, record_id, record_version, document, document_sha256, "
                    "previous_chain_sha256, chain_sha256) VALUES (%s, %s, 1, %s, %s, NULL, %s)",
                    (self._namespace, record, document_bytes, document_sha256, chain_sha256),
                )
                response = MetadataSnapshot(
                    self._namespace,
                    record,
                    1,
                    cast(Mapping[str, Any], _plain_json(document)),
                    document_sha256,
                    chain_sha256,
                )
            self._record_idempotency(
                cursor,
                operation="create",
                idempotency_key=key,
                request_sha256=request_sha256,
                response=response,
            )
            return response

    def read(self, record_id: str) -> MetadataSnapshot:
        record = _safe_text(record_id, code="metadata-record-id-invalid")
        with _transaction(self._factory) as cursor:
            snapshot = self._load(cursor, record, for_update=False, required=True)
            if snapshot is None:  # pragma: no cover - required load fails first
                raise PersistenceError("metadata-record-not-found")
            return snapshot

    def _write_locked(
        self,
        cursor: DbCursor,
        current: MetadataSnapshot,
        document: Mapping[str, Any],
    ) -> MetadataSnapshot:
        document_bytes = _canonical_json(document)
        document_sha256 = _sha256(document_bytes)
        version = current.version + 1
        chain_sha256 = _chain_sha256(
            namespace=self._namespace,
            record_id=current.record_id,
            version=version,
            document_sha256=document_sha256,
            previous_chain_sha256=current.chain_sha256,
        )
        cursor.execute(
            "INSERT INTO colortrace.metadata_record_versions "
            "(namespace, record_id, record_version, document, document_sha256, "
            "previous_chain_sha256, chain_sha256) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (
                self._namespace,
                current.record_id,
                version,
                document_bytes,
                document_sha256,
                current.chain_sha256,
                chain_sha256,
            ),
        )
        cursor.execute(
            "UPDATE colortrace.metadata_records "
            "SET record_version = %s, document = %s, document_sha256 = %s, "
            "chain_sha256 = %s, updated_at = clock_timestamp() "
            "WHERE namespace = %s AND record_id = %s AND record_version = %s "
            "RETURNING record_version",
            (
                version,
                document_bytes,
                document_sha256,
                chain_sha256,
                self._namespace,
                current.record_id,
                current.version,
            ),
        )
        updated = _one(cursor)
        if updated is None or updated.get("record_version") != version:
            raise PersistenceError("metadata-version-conflict")
        return MetadataSnapshot(
            self._namespace,
            current.record_id,
            version,
            cast(Mapping[str, Any], _plain_json(document)),
            document_sha256,
            chain_sha256,
        )

    def update(
        self,
        record_id: str,
        document: Mapping[str, Any],
        *,
        expected_version: int,
        idempotency_key: str,
    ) -> MetadataSnapshot:
        record = _safe_text(record_id, code="metadata-record-id-invalid")
        key = _safe_text(idempotency_key, code="metadata-idempotency-key-invalid")
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
        ):
            raise PersistenceError("metadata-version-invalid")
        document_sha256 = _sha256(_canonical_json(document))
        request_sha256 = self._request_sha256(
            {
                "operation": "update",
                "namespace": self._namespace,
                "record_id": record,
                "expected_version": expected_version,
                "document_sha256": document_sha256,
            }
        )
        with _transaction(self._factory) as cursor:
            _lock(cursor, "idempotency", self._namespace, key)
            replay = self._idempotent_replay(
                cursor,
                operation="update",
                idempotency_key=key,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            _lock(cursor, "record", self._namespace, record)
            current = self._load(cursor, record, for_update=True, required=True)
            if current is None:  # pragma: no cover - required load fails first
                raise PersistenceError("metadata-record-not-found")
            if current.version != expected_version:
                raise PersistenceError("metadata-version-conflict")
            response = self._write_locked(cursor, current, document)
            self._record_idempotency(
                cursor,
                operation="update",
                idempotency_key=key,
                request_sha256=request_sha256,
                response=response,
            )
            return response

    @staticmethod
    def _claim_from_row(namespace: str, record_id: str, row: Mapping[str, Any]) -> ClaimSnapshot:
        expires_at = row.get("expires_at")
        if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
            raise PersistenceError("stored-claim-invalid")
        values = (
            row.get("owner"),
            row.get("generation"),
            row.get("record_version"),
            row.get("event_sequence"),
            row.get("event_sha256"),
        )
        if (
            not isinstance(values[0], str)
            or not isinstance(values[1], int)
            or not isinstance(values[2], int)
            or not isinstance(values[3], int)
            or not isinstance(values[4], str)
        ):
            raise PersistenceError("stored-claim-invalid")
        return ClaimSnapshot(
            namespace,
            record_id,
            values[0],
            values[1],
            values[2],
            expires_at.astimezone(UTC),
            values[3],
            values[4],
        )

    def _active_claim(self, cursor: DbCursor, record_id: str) -> ClaimSnapshot | None:
        cursor.execute(
            "SELECT owner, generation, record_version, expires_at, event_sequence, event_sha256 "
            "FROM colortrace.metadata_claims "
            "WHERE namespace = %s AND record_id = %s FOR UPDATE",
            (self._namespace, record_id),
        )
        row = _one(cursor)
        return None if row is None else self._claim_from_row(self._namespace, record_id, row)

    def _last_claim_event(self, cursor: DbCursor, record_id: str) -> dict[str, Any] | None:
        cursor.execute(
            "SELECT event_sequence, generation, event_sha256 "
            "FROM colortrace.metadata_claim_events "
            "WHERE namespace = %s AND record_id = %s "
            "ORDER BY event_sequence DESC LIMIT 1",
            (self._namespace, record_id),
        )
        return _one(cursor)

    def _append_claim_event(
        self,
        cursor: DbCursor,
        *,
        record_id: str,
        sequence: int,
        generation: int,
        event_type: str,
        owner: str,
        record_version: int,
        expires_at: datetime | None,
        previous_event_sha256: str | None,
        occurred_at: datetime,
    ) -> str:
        event_sha256 = _claim_event_sha256(
            namespace=self._namespace,
            record_id=record_id,
            sequence=sequence,
            generation=generation,
            event_type=event_type,
            owner=owner,
            record_version=record_version,
            expires_at=expires_at,
            previous_event_sha256=previous_event_sha256,
            occurred_at=occurred_at,
        )
        cursor.execute(
            "INSERT INTO colortrace.metadata_claim_events "
            "(namespace, record_id, event_sequence, generation, event_type, owner, "
            "record_version, expires_at, previous_event_sha256, event_sha256, occurred_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                self._namespace,
                record_id,
                sequence,
                generation,
                event_type,
                owner,
                record_version,
                expires_at,
                previous_event_sha256,
                event_sha256,
                occurred_at,
            ),
        )
        return event_sha256

    @staticmethod
    def _lease_seconds(value: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 600:
            raise PersistenceError("claim-lease-invalid")
        return value

    def claim(
        self,
        record_id: str,
        *,
        owner: str,
        expected_version: int,
        now: datetime,
        lease_seconds: int,
    ) -> ClaimSnapshot:
        record = _safe_text(record_id, code="metadata-record-id-invalid")
        claim_owner = _safe_text(owner, code="claim-owner-invalid")
        instant = _time(now, code="claim-time-invalid")
        lease = self._lease_seconds(lease_seconds)
        if (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 1
        ):
            raise PersistenceError("metadata-version-invalid")
        with _transaction(self._factory) as cursor:
            _lock(cursor, "record", self._namespace, record)
            current = self._load(cursor, record, for_update=True, required=True)
            if current is None or current.version != expected_version:
                raise PersistenceError("metadata-version-conflict")
            active = self._active_claim(cursor, record)
            if active is not None and active.expires_at > instant:
                if active.owner == claim_owner and active.record_version == expected_version:
                    return active
                raise PersistenceError("claim-in-progress")
            expires_at = instant + timedelta(seconds=lease)
            last = self._last_claim_event(cursor, record)
            sequence = 1 if last is None else cast(int, last["event_sequence"]) + 1
            generation = 1 if last is None else cast(int, last["generation"]) + 1
            previous = None if last is None else cast(str, last["event_sha256"])
            event_type = "acquired" if active is None else "reclaimed"
            event_sha256 = self._append_claim_event(
                cursor,
                record_id=record,
                sequence=sequence,
                generation=generation,
                event_type=event_type,
                owner=claim_owner,
                record_version=expected_version,
                expires_at=expires_at,
                previous_event_sha256=previous,
                occurred_at=instant,
            )
            if active is None:
                cursor.execute(
                    "INSERT INTO colortrace.metadata_claims "
                    "(namespace, record_id, owner, generation, record_version, expires_at, "
                    "event_sequence, event_sha256) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        self._namespace,
                        record,
                        claim_owner,
                        generation,
                        expected_version,
                        expires_at,
                        sequence,
                        event_sha256,
                    ),
                )
            else:
                cursor.execute(
                    "UPDATE colortrace.metadata_claims SET owner = %s, generation = %s, "
                    "record_version = %s, expires_at = %s, event_sequence = %s, event_sha256 = %s "
                    "WHERE namespace = %s AND record_id = %s",
                    (
                        claim_owner,
                        generation,
                        expected_version,
                        expires_at,
                        sequence,
                        event_sha256,
                        self._namespace,
                        record,
                    ),
                )
            return ClaimSnapshot(
                self._namespace,
                record,
                claim_owner,
                generation,
                expected_version,
                expires_at,
                sequence,
                event_sha256,
            )

    def _assert_claim(
        self,
        cursor: DbCursor,
        claim: ClaimSnapshot,
    ) -> ClaimSnapshot:
        if claim.namespace != self._namespace:
            raise PersistenceError("claim-fenced")
        active = self._active_claim(cursor, claim.record_id)
        if active != claim:
            raise PersistenceError("claim-fenced")
        return active

    def renew_claim(
        self,
        claim: ClaimSnapshot,
        *,
        now: datetime,
        lease_seconds: int,
    ) -> ClaimSnapshot:
        instant = _time(now, code="claim-time-invalid")
        lease = self._lease_seconds(lease_seconds)
        record = _safe_text(claim.record_id, code="metadata-record-id-invalid")
        with _transaction(self._factory) as cursor:
            _lock(cursor, "record", self._namespace, record)
            current = self._load(cursor, record, for_update=True, required=True)
            active = self._assert_claim(cursor, claim)
            if current is None or current.version != active.record_version:
                raise PersistenceError("claim-fenced")
            if instant >= active.expires_at:
                raise PersistenceError("claim-expired")
            expires_at = instant + timedelta(seconds=lease)
            if expires_at <= active.expires_at:
                raise PersistenceError("claim-renewal-invalid")
            sequence = active.event_sequence + 1
            event_sha256 = self._append_claim_event(
                cursor,
                record_id=record,
                sequence=sequence,
                generation=active.generation,
                event_type="renewed",
                owner=active.owner,
                record_version=active.record_version,
                expires_at=expires_at,
                previous_event_sha256=active.event_sha256,
                occurred_at=instant,
            )
            cursor.execute(
                "UPDATE colortrace.metadata_claims SET expires_at = %s, event_sequence = %s, "
                "event_sha256 = %s WHERE namespace = %s AND record_id = %s",
                (expires_at, sequence, event_sha256, self._namespace, record),
            )
            return ClaimSnapshot(
                self._namespace,
                record,
                active.owner,
                active.generation,
                active.record_version,
                expires_at,
                sequence,
                event_sha256,
            )

    def complete_claim(
        self,
        claim: ClaimSnapshot,
        document: Mapping[str, Any],
        *,
        idempotency_key: str,
        now: datetime,
    ) -> MetadataSnapshot:
        instant = _time(now, code="claim-time-invalid")
        record = _safe_text(claim.record_id, code="metadata-record-id-invalid")
        key = _safe_text(idempotency_key, code="metadata-idempotency-key-invalid")
        document_sha256 = _sha256(_canonical_json(document))
        request_sha256 = self._request_sha256(
            {
                "operation": "complete-claim",
                "namespace": self._namespace,
                "record_id": record,
                "claim_owner": claim.owner,
                "claim_generation": claim.generation,
                "claim_record_version": claim.record_version,
                "document_sha256": document_sha256,
            }
        )
        with _transaction(self._factory) as cursor:
            _lock(cursor, "idempotency", self._namespace, key)
            replay = self._idempotent_replay(
                cursor,
                operation="complete-claim",
                idempotency_key=key,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            _lock(cursor, "record", self._namespace, record)
            current = self._load(cursor, record, for_update=True, required=True)
            active = self._assert_claim(cursor, claim)
            if current is None or current.version != active.record_version:
                raise PersistenceError("claim-fenced")
            if instant >= active.expires_at:
                raise PersistenceError("claim-expired")
            response = self._write_locked(cursor, current, document)
            event_sha256 = self._append_claim_event(
                cursor,
                record_id=record,
                sequence=active.event_sequence + 1,
                generation=active.generation,
                event_type="completed",
                owner=active.owner,
                record_version=active.record_version,
                expires_at=None,
                previous_event_sha256=active.event_sha256,
                occurred_at=instant,
            )
            if not event_sha256:
                raise PersistenceError("stored-claim-invalid")  # pragma: no cover
            cursor.execute(
                "DELETE FROM colortrace.metadata_claims WHERE namespace = %s AND record_id = %s",
                (self._namespace, record),
            )
            self._record_idempotency(
                cursor,
                operation="complete-claim",
                idempotency_key=key,
                request_sha256=request_sha256,
                response=response,
            )
            return response

    def claim_history(self, record_id: str) -> list[dict[str, Any]]:
        record = _safe_text(record_id, code="metadata-record-id-invalid")
        with _transaction(self._factory) as cursor:
            self._load(cursor, record, for_update=False, required=True)
            cursor.execute(
                "SELECT event_sequence, generation, event_type, owner, record_version, "
                "expires_at, previous_event_sha256, event_sha256, occurred_at "
                "FROM colortrace.metadata_claim_events "
                "WHERE namespace = %s AND record_id = %s ORDER BY event_sequence",
                (self._namespace, record),
            )
            rows = _rows(cursor)
        events: list[dict[str, Any]] = []
        previous: str | None = None
        for expected_sequence, row in enumerate(rows, start=1):
            occurred_at = row.get("occurred_at")
            expires_at = row.get("expires_at")
            if (
                row.get("event_sequence") != expected_sequence
                or not isinstance(row.get("generation"), int)
                or not isinstance(row.get("event_type"), str)
                or not isinstance(row.get("owner"), str)
                or not isinstance(row.get("record_version"), int)
                or not isinstance(occurred_at, datetime)
                or occurred_at.tzinfo is None
                or (expires_at is not None and not isinstance(expires_at, datetime))
                or row.get("previous_event_sha256") != previous
            ):
                raise PersistenceError("stored-claim-history-invalid")
            normalized_expiry = None if expires_at is None else expires_at.astimezone(UTC)
            normalized_time = occurred_at.astimezone(UTC)
            event_sha256 = _claim_event_sha256(
                namespace=self._namespace,
                record_id=record,
                sequence=expected_sequence,
                generation=cast(int, row["generation"]),
                event_type=cast(str, row["event_type"]),
                owner=cast(str, row["owner"]),
                record_version=cast(int, row["record_version"]),
                expires_at=normalized_expiry,
                previous_event_sha256=previous,
                occurred_at=normalized_time,
            )
            if row.get("event_sha256") != event_sha256:
                raise PersistenceError("stored-claim-history-invalid")
            events.append(
                {
                    "schema": "canonical-metadata-claim-event/v1",
                    "namespace": self._namespace,
                    "record_id": record,
                    "sequence": expected_sequence,
                    "generation": row["generation"],
                    "event_type": row["event_type"],
                    "owner": row["owner"],
                    "record_version": row["record_version"],
                    "expires_at": (
                        None if normalized_expiry is None else _timestamp(normalized_expiry)
                    ),
                    "previous_event_sha256": previous,
                    "event_sha256": event_sha256,
                    "occurred_at": _timestamp(normalized_time),
                }
            )
            previous = event_sha256
        return events


@dataclass(frozen=True, slots=True)
class HostedMetadataStores:
    incidents: CanonicalPostgresStore
    response_plans: CanonicalPostgresStore
    recovery: CanonicalPostgresStore
    recovery_tasks: CanonicalPostgresStore
    simulator_actions: CanonicalPostgresStore

    @classmethod
    def from_connection_factory(cls, factory: ConnectionFactory) -> HostedMetadataStores:
        return cls(
            incidents=CanonicalPostgresStore(factory, namespace="incident"),
            response_plans=CanonicalPostgresStore(factory, namespace="response-plan"),
            recovery=CanonicalPostgresStore(factory, namespace="recovery"),
            recovery_tasks=CanonicalPostgresStore(factory, namespace="recovery-task"),
            simulator_actions=CanonicalPostgresStore(factory, namespace="simulator-action"),
        )
