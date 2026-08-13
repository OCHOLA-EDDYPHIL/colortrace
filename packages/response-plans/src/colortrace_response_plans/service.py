from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, cast

from .contracts import (
    APPROVER_ROLE,
    DISPATCHER_ROLE,
    EDITOR_ROLE,
    ResponsePlanError,
    build_audit_event,
    build_decision,
    build_dispatch_authorization,
    build_dispatch_consumption,
    build_plan,
    canonical_json_bytes,
    plain_json,
    prefixed_sha256,
    require_digest,
    require_idempotency_key,
    require_identifier,
    timestamp,
    validate_audit_chain,
    validate_decision,
    validate_dispatch_authorization,
    validate_dispatch_consumption,
    validate_plan,
)
from .identity import OIDCTrustBoundary, VerifiedPrincipal
from .repository import SQLiteResponsePlanRepository


class ResponsePlanService:
    def __init__(
        self,
        *,
        repository: SQLiteResponsePlanRepository,
        identity_boundary: OIDCTrustBoundary,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._repository = repository
        self._identity_boundary = identity_boundary
        self._clock = clock or (lambda: datetime.now(UTC))

    def _now_datetime(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ResponsePlanError("invalid-time")
        return value.astimezone(UTC)

    def _now(self) -> str:
        return timestamp(self._now_datetime())

    def _authorize(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        role: str,
        kinds: frozenset[str],
    ) -> dict[str, str]:
        incident = require_identifier(incident_id)
        if principal is None:
            raise ResponsePlanError("authentication-required")
        self._identity_boundary.assert_trusted(principal, now=self._now_datetime())
        if principal.kind == "model":
            raise ResponsePlanError("model-authority-forbidden")
        if incident not in principal.incident_ids:
            raise ResponsePlanError("incident-access-denied")
        if role not in principal.roles:
            raise ResponsePlanError("role-required")
        if principal.kind not in kinds:
            if kinds == frozenset({"human"}):
                raise ResponsePlanError("human-approval-required")
            raise ResponsePlanError("service-identity-required")
        return principal.actor()

    @staticmethod
    def _request_digest(value: Mapping[str, Any]) -> str:
        try:
            return prefixed_sha256(canonical_json_bytes(plain_json(value)))
        except (TypeError, ValueError) as error:
            raise ResponsePlanError("request-invalid") from error

    @classmethod
    def _replay(
        cls,
        connection: sqlite3.Connection,
        key: str,
        request_sha256: str,
        *,
        incident_id: str,
        event_type: str,
        expected_plan_version: int,
        authorization_id: str | None = None,
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT request_sha256, result FROM response_plan_idempotency "
            "WHERE idempotency_key = ?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_sha256:
            raise ResponsePlanError("idempotency-conflict")
        cls._validate_history(connection, incident_id)
        record, record_sha256 = cls._authoritative_replay_record(
            connection,
            incident_id=incident_id,
            event_type=event_type,
            expected_plan_version=expected_plan_version,
            authorization_id=authorization_id,
        )
        matching_events = [
            event
            for event in cls._events(connection, incident_id)
            if event["event_type"] == event_type and event["record_sha256"] == record_sha256
        ]
        if len(matching_events) != 1 or (
            event_type != "dispatch.consumed" and matching_events[0]["idempotency_key"] != key
        ):
            raise ResponsePlanError("idempotency-result-invalid")
        result = row["result"]
        if not isinstance(result, bytes) or result != canonical_json_bytes(record):
            raise ResponsePlanError("idempotency-result-invalid")
        return cast(dict[str, Any], plain_json(record))

    @classmethod
    def _authoritative_replay_record(
        cls,
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        event_type: str,
        expected_plan_version: int,
        authorization_id: str | None,
    ) -> tuple[dict[str, Any], str]:
        if event_type == "plan.created":
            if cls._require_version(expected_plan_version, minimum=0) != 0:
                raise ResponsePlanError("idempotency-result-invalid")
            plan = cls._plan_version(connection, incident_id, 1)
            return plan, cast(str, plan["plan_sha256"])
        if event_type == "plan.edited":
            previous_version = cls._require_version(expected_plan_version, minimum=1)
            plan = cls._plan_version(connection, incident_id, previous_version + 1)
            return plan, cast(str, plan["plan_sha256"])

        version = cls._require_version(expected_plan_version, minimum=1)
        plan = cls._plan_version(connection, incident_id, version)
        approval = cls._decision(connection, incident_id, version)
        if event_type in {"plan.approved", "plan.rejected"}:
            if approval is None:
                raise ResponsePlanError("idempotency-result-invalid")
            validate_decision(approval, plan=plan)
            if approval["outcome"] != event_type.removeprefix("plan."):
                raise ResponsePlanError("idempotency-result-invalid")
            return approval, cast(str, approval["decision_sha256"])
        if approval is None or approval["outcome"] != "approved":
            raise ResponsePlanError("idempotency-result-invalid")
        validate_decision(approval, plan=plan)
        authorization_row = connection.execute(
            "SELECT authorization_id, status, document, consumption_document "
            "FROM dispatch_authorizations WHERE incident_id = ? AND plan_version = ?",
            (incident_id, version),
        ).fetchone()
        if authorization_row is None:
            raise ResponsePlanError("idempotency-result-invalid")
        authorization = SQLiteResponsePlanRepository.decode(bytes(authorization_row["document"]))
        validate_dispatch_authorization(authorization, plan=plan, approval=approval)
        if event_type == "dispatch.authorized":
            return authorization, cast(str, authorization["authorization_sha256"])
        if event_type != "dispatch.consumed" or authorization_id is None:
            raise ResponsePlanError("idempotency-result-invalid")
        if (
            authorization_row["authorization_id"] != authorization_id
            or authorization_row["status"] != "consumed"
            or authorization_row["consumption_document"] is None
        ):
            raise ResponsePlanError("idempotency-result-invalid")
        consumption = SQLiteResponsePlanRepository.decode(
            bytes(authorization_row["consumption_document"])
        )
        validate_dispatch_consumption(
            consumption,
            authorization=authorization,
            plan=plan,
            approval=approval,
        )
        return consumption, cast(str, consumption["consumption_sha256"])

    @staticmethod
    def _remember(
        connection: sqlite3.Connection,
        key: str,
        request_sha256: str,
        result: Mapping[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO response_plan_idempotency("
            "idempotency_key, request_sha256, result) VALUES (?, ?, ?)",
            (key, request_sha256, canonical_json_bytes(result)),
        )

    @staticmethod
    def _require_version(value: int, *, minimum: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
            raise ResponsePlanError("expected-version-invalid")
        return value

    @classmethod
    def _check_current_incident(
        cls,
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        expected_incident_version: int,
    ) -> int:
        expected = cls._require_version(expected_incident_version, minimum=1)
        row = connection.execute(
            "SELECT incident_version FROM authority_incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise ResponsePlanError("incident-not-found")
        if row["incident_version"] != expected:
            raise ResponsePlanError("expected-version-conflict")
        return expected

    @staticmethod
    def _current_plan(connection: sqlite3.Connection, incident_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT document FROM response_plans WHERE incident_id = ? "
            "ORDER BY plan_version DESC LIMIT 1",
            (incident_id,),
        ).fetchone()
        if row is None:
            raise ResponsePlanError("plan-not-found")
        plan = SQLiteResponsePlanRepository.decode(bytes(row["document"]))
        validate_plan(plan)
        return plan

    @staticmethod
    def _plan_version(
        connection: sqlite3.Connection, incident_id: str, version: int
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT document FROM response_plans WHERE incident_id = ? AND plan_version = ?",
            (incident_id, version),
        ).fetchone()
        if row is None:
            raise ResponsePlanError("plan-not-found")
        plan = SQLiteResponsePlanRepository.decode(bytes(row["document"]))
        validate_plan(plan)
        return plan

    @classmethod
    def _check_expected_plan(
        cls,
        plan: Mapping[str, Any],
        *,
        expected_plan_version: int,
        expected_plan_sha256: str,
    ) -> None:
        expected_plan = cls._require_version(expected_plan_version, minimum=1)
        if expected_plan != plan["version"]:
            raise ResponsePlanError("expected-version-conflict")
        if require_digest(expected_plan_sha256) != plan["plan_sha256"]:
            raise ResponsePlanError("plan-hash-conflict")

    @staticmethod
    def _packet_authority(
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        expected_incident_version: int,
        response_packet_id: str,
        response_packet_sha256: str,
        deterministic_scope_sha256: str,
    ) -> dict[str, Any]:
        packet_id = require_identifier(response_packet_id, code="response-packet-id-invalid")
        row = connection.execute(
            "SELECT document FROM response_packet_authority WHERE packet_id = ?",
            (packet_id,),
        ).fetchone()
        if row is None:
            raise ResponsePlanError("response-packet-not-found")
        packet = SQLiteResponsePlanRepository.decode(bytes(row["document"]))
        expected = {
            "incident_id": incident_id,
            "incident_version": expected_incident_version,
            "response_packet_id": packet_id,
            "response_packet_sha256": require_digest(
                response_packet_sha256, code="response-packet-digest-invalid"
            ),
            "deterministic_scope_sha256": require_digest(
                deterministic_scope_sha256, code="deterministic-scope-digest-invalid"
            ),
        }
        if any(packet[key] != value for key, value in expected.items()):
            raise ResponsePlanError("response-packet-binding-conflict")
        if packet["blocking_unresolved_item_ids"]:
            raise ResponsePlanError("blocking-unresolved-evidence")
        if packet["unknown_target_ids"]:
            raise ResponsePlanError("unknown-targets-prohibited")
        return packet

    @staticmethod
    def _decision(
        connection: sqlite3.Connection, incident_id: str, version: int
    ) -> dict[str, Any] | None:
        row = connection.execute(
            "SELECT document FROM response_plan_decisions "
            "WHERE incident_id = ? AND plan_version = ?",
            (incident_id, version),
        ).fetchone()
        if row is None:
            return None
        return SQLiteResponsePlanRepository.decode(bytes(row["document"]))

    @staticmethod
    def _events(connection: sqlite3.Connection, incident_id: str) -> list[dict[str, Any]]:
        rows = connection.execute(
            "SELECT document FROM response_plan_audit_events WHERE incident_id = ? "
            "ORDER BY sequence",
            (incident_id,),
        ).fetchall()
        return [SQLiteResponsePlanRepository.decode(bytes(row["document"])) for row in rows]

    @staticmethod
    def _records(connection: sqlite3.Connection, incident_id: str) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}

        def add_record(digest: Any, record: dict[str, Any]) -> None:
            selected_digest = require_digest(digest)
            if selected_digest in records:
                raise ResponsePlanError("audit-record-duplicate")
            records[selected_digest] = record

        queries = (
            ("SELECT plan_sha256 AS digest, document FROM response_plans WHERE incident_id = ?",),
            (
                "SELECT decision_sha256 AS digest, document FROM response_plan_decisions "
                "WHERE incident_id = ?",
            ),
            (
                "SELECT json_extract(CAST(document AS TEXT), '$.authorization_sha256') AS digest, "
                "document FROM dispatch_authorizations WHERE incident_id = ?",
            ),
        )
        for (query,) in queries:
            for row in connection.execute(query, (incident_id,)).fetchall():
                record = SQLiteResponsePlanRepository.decode(bytes(row["document"]))
                add_record(row["digest"], record)
        consumption_rows = connection.execute(
            "SELECT consumption_document FROM dispatch_authorizations "
            "WHERE incident_id = ? AND consumption_document IS NOT NULL",
            (incident_id,),
        ).fetchall()
        for row in consumption_rows:
            record = SQLiteResponsePlanRepository.decode(bytes(row["consumption_document"]))
            add_record(record.get("consumption_sha256"), record)
        return records

    @staticmethod
    def _head(connection: sqlite3.Connection, incident_id: str) -> tuple[int, str] | None:
        row = connection.execute(
            "SELECT sequence, event_sha256 FROM response_plan_audit_heads WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if row is None:
            return None
        return cast(int, row["sequence"]), cast(str, row["event_sha256"])

    @classmethod
    def _validate_history(cls, connection: sqlite3.Connection, incident_id: str) -> None:
        events = cls._events(connection, incident_id)
        head = cls._head(connection, incident_id)
        if not events or head is None or head[0] != len(events):
            raise ResponsePlanError("audit-head-mismatch")
        validate_audit_chain(
            events,
            trusted_head_sha256=head[1],
            records=cls._records(connection, incident_id),
        )

    @classmethod
    def _build_audit(
        cls,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        plan: Mapping[str, Any],
        record: Mapping[str, Any],
        record_sha256: str,
        actor: Mapping[str, Any],
        idempotency_key: str,
        occurred_at: str,
    ) -> dict[str, Any]:
        incident_id = cast(str, plan["incident_id"])
        events = cls._events(connection, incident_id)
        previous = None if not events else events[-1]
        event = build_audit_event(
            previous=previous,
            event_type=event_type,
            incident_id=incident_id,
            plan_id=cast(str, plan["plan_id"]),
            plan_version=cast(int, plan["version"]),
            plan_sha256=cast(str, plan["plan_sha256"]),
            record_sha256=record_sha256,
            actor=actor,
            idempotency_key=idempotency_key,
            occurred_at=occurred_at,
        )
        candidate_records = cls._records(connection, incident_id)
        candidate_records[record_sha256] = cast(dict[str, Any], plain_json(record))
        validate_audit_chain(
            [*events, event],
            trusted_head_sha256=cast(str, event["event_sha256"]),
            records=candidate_records,
        )
        return event

    @classmethod
    def _append_audit(
        cls,
        connection: sqlite3.Connection,
        *,
        incident_id: str,
        event: Mapping[str, Any],
    ) -> None:
        connection.execute(
            "INSERT INTO response_plan_audit_events("
            "incident_id, sequence, event_sha256, document) VALUES (?, ?, ?, ?)",
            (
                incident_id,
                event["sequence"],
                event["event_sha256"],
                canonical_json_bytes(event),
            ),
        )
        previous_sequence = cast(int, event["sequence"]) - 1
        if previous_sequence == 0:
            connection.execute(
                "INSERT INTO response_plan_audit_heads(incident_id, sequence, event_sha256) "
                "VALUES (?, ?, ?)",
                (incident_id, event["sequence"], event["event_sha256"]),
            )
        else:
            cursor = connection.execute(
                "UPDATE response_plan_audit_heads SET sequence = ?, event_sha256 = ? "
                "WHERE incident_id = ? AND sequence = ? "
                "AND event_sha256 = ?",
                (
                    event["sequence"],
                    event["event_sha256"],
                    incident_id,
                    previous_sequence,
                    event["predecessor_event_sha256"],
                ),
            )
            if cursor.rowcount != 1:
                raise ResponsePlanError("audit-head-conflict")

    @staticmethod
    def _assert_scope_binding(plan: Mapping[str, Any], packet: Mapping[str, Any]) -> None:
        expected = {
            "response_packet_id": packet["response_packet_id"],
            "response_packet_sha256": packet["response_packet_sha256"],
            "deterministic_scope_sha256": packet["deterministic_scope_sha256"],
            "targets": packet["targets"],
            "exclusions": packet["exclusions"],
            "unresolved_item_ids": packet["unresolved_item_ids"],
            "blocking_unresolved_item_ids": packet["blocking_unresolved_item_ids"],
            "unknown_target_ids": packet["unknown_target_ids"],
        }
        if any(plan[key] != value for key, value in expected.items()):
            raise ResponsePlanError("deterministic-scope-binding-conflict")

    def create_plan(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        expected_incident_version: int,
        expected_plan_version: int,
        response_packet_id: str,
        response_packet_sha256: str,
        deterministic_scope_sha256: str,
        targets: Sequence[Mapping[str, Any]],
        exclusions: Sequence[Mapping[str, Any]],
        commands: Sequence[Mapping[str, Any]],
        unresolved_acknowledged: bool = False,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor = self._authorize(
            principal,
            incident_id=incident_id,
            role=EDITOR_ROLE,
            kinds=frozenset({"human"}),
        )
        key = require_idempotency_key(idempotency_key)
        request = {
            "operation": "plan.create",
            "actor": actor,
            "incident_id": incident_id,
            "expected_incident_version": expected_incident_version,
            "expected_plan_version": expected_plan_version,
            "response_packet_id": response_packet_id,
            "response_packet_sha256": response_packet_sha256,
            "deterministic_scope_sha256": deterministic_scope_sha256,
            "targets": targets,
            "exclusions": exclusions,
            "commands": commands,
            "unresolved_acknowledged": unresolved_acknowledged,
            "idempotency_key": key,
        }
        request_sha256 = self._request_digest(request)
        with self._repository.transaction(write=True) as connection:
            replay = self._replay(
                connection,
                key,
                request_sha256,
                incident_id=incident_id,
                event_type="plan.created",
                expected_plan_version=expected_plan_version,
            )
            if replay is not None:
                return replay
            incident_version = self._check_current_incident(
                connection,
                incident_id=incident_id,
                expected_incident_version=expected_incident_version,
            )
            if self._require_version(expected_plan_version, minimum=0) != 0:
                raise ResponsePlanError("expected-version-conflict")
            existing = connection.execute(
                "SELECT 1 FROM response_plans WHERE incident_id = ? LIMIT 1",
                (incident_id,),
            ).fetchone()
            if existing is not None:
                raise ResponsePlanError("plan-already-exists")
            packet = self._packet_authority(
                connection,
                incident_id=incident_id,
                expected_incident_version=incident_version,
                response_packet_id=response_packet_id,
                response_packet_sha256=response_packet_sha256,
                deterministic_scope_sha256=deterministic_scope_sha256,
            )
            occurred_at = self._now()
            plan = build_plan(
                incident_id=incident_id,
                incident_version=incident_version,
                version=1,
                previous_plan_sha256=None,
                response_packet_id=response_packet_id,
                response_packet_sha256=response_packet_sha256,
                deterministic_scope_sha256=deterministic_scope_sha256,
                targets=targets,
                exclusions=exclusions,
                commands=commands,
                unresolved_item_ids=cast(Sequence[str], packet["unresolved_item_ids"]),
                blocking_unresolved_item_ids=cast(
                    Sequence[str], packet["blocking_unresolved_item_ids"]
                ),
                unknown_target_ids=cast(Sequence[str], packet["unknown_target_ids"]),
                unresolved_acknowledged=unresolved_acknowledged,
                created_by=actor,
                created_at=occurred_at,
            )
            self._assert_scope_binding(plan, packet)
            audit = self._build_audit(
                connection,
                event_type="plan.created",
                plan=plan,
                record=plan,
                record_sha256=cast(str, plan["plan_sha256"]),
                actor=actor,
                idempotency_key=key,
                occurred_at=occurred_at,
            )
            connection.execute(
                "INSERT INTO response_plans(incident_id, plan_version, incident_version, "
                "plan_sha256, document) VALUES (?, ?, ?, ?, ?)",
                (
                    incident_id,
                    plan["version"],
                    plan["incident_version"],
                    plan["plan_sha256"],
                    canonical_json_bytes(plan),
                ),
            )
            self._append_audit(connection, incident_id=incident_id, event=audit)
            self._remember(connection, key, request_sha256, plan)
            return cast(dict[str, Any], plain_json(plan))

    def edit_plan(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        expected_incident_version: int,
        expected_plan_version: int,
        expected_plan_sha256: str,
        response_packet_id: str,
        response_packet_sha256: str,
        deterministic_scope_sha256: str,
        targets: Sequence[Mapping[str, Any]],
        exclusions: Sequence[Mapping[str, Any]],
        commands: Sequence[Mapping[str, Any]],
        unresolved_acknowledged: bool = False,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor = self._authorize(
            principal,
            incident_id=incident_id,
            role=EDITOR_ROLE,
            kinds=frozenset({"human"}),
        )
        key = require_idempotency_key(idempotency_key)
        request = {
            "operation": "plan.edit",
            "actor": actor,
            "incident_id": incident_id,
            "expected_incident_version": expected_incident_version,
            "expected_plan_version": expected_plan_version,
            "expected_plan_sha256": expected_plan_sha256,
            "response_packet_id": response_packet_id,
            "response_packet_sha256": response_packet_sha256,
            "deterministic_scope_sha256": deterministic_scope_sha256,
            "targets": targets,
            "exclusions": exclusions,
            "commands": commands,
            "unresolved_acknowledged": unresolved_acknowledged,
            "idempotency_key": key,
        }
        request_sha256 = self._request_digest(request)
        with self._repository.transaction(write=True) as connection:
            replay = self._replay(
                connection,
                key,
                request_sha256,
                incident_id=incident_id,
                event_type="plan.edited",
                expected_plan_version=expected_plan_version,
            )
            if replay is not None:
                return replay
            incident_version = self._check_current_incident(
                connection,
                incident_id=incident_id,
                expected_incident_version=expected_incident_version,
            )
            current = self._current_plan(connection, incident_id)
            self._check_expected_plan(
                current,
                expected_plan_version=expected_plan_version,
                expected_plan_sha256=expected_plan_sha256,
            )
            packet = self._packet_authority(
                connection,
                incident_id=incident_id,
                expected_incident_version=incident_version,
                response_packet_id=response_packet_id,
                response_packet_sha256=response_packet_sha256,
                deterministic_scope_sha256=deterministic_scope_sha256,
            )
            occurred_at = self._now()
            plan = build_plan(
                incident_id=incident_id,
                incident_version=incident_version,
                version=cast(int, current["version"]) + 1,
                previous_plan_sha256=cast(str, current["plan_sha256"]),
                response_packet_id=response_packet_id,
                response_packet_sha256=response_packet_sha256,
                deterministic_scope_sha256=deterministic_scope_sha256,
                targets=targets,
                exclusions=exclusions,
                commands=commands,
                unresolved_item_ids=cast(Sequence[str], packet["unresolved_item_ids"]),
                blocking_unresolved_item_ids=cast(
                    Sequence[str], packet["blocking_unresolved_item_ids"]
                ),
                unknown_target_ids=cast(Sequence[str], packet["unknown_target_ids"]),
                unresolved_acknowledged=unresolved_acknowledged,
                created_by=actor,
                created_at=occurred_at,
            )
            self._assert_scope_binding(plan, packet)
            audit = self._build_audit(
                connection,
                event_type="plan.edited",
                plan=plan,
                record=plan,
                record_sha256=cast(str, plan["plan_sha256"]),
                actor=actor,
                idempotency_key=key,
                occurred_at=occurred_at,
            )
            connection.execute(
                "INSERT INTO response_plans(incident_id, plan_version, incident_version, "
                "plan_sha256, document) VALUES (?, ?, ?, ?, ?)",
                (
                    incident_id,
                    plan["version"],
                    plan["incident_version"],
                    plan["plan_sha256"],
                    canonical_json_bytes(plan),
                ),
            )
            connection.execute(
                "UPDATE dispatch_authorizations SET status = 'invalidated' "
                "WHERE incident_id = ? AND status = 'authorized'",
                (incident_id,),
            )
            self._append_audit(connection, incident_id=incident_id, event=audit)
            self._remember(connection, key, request_sha256, plan)
            return cast(dict[str, Any], plain_json(plan))

    def approve_plan(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        expected_incident_version: int,
        expected_plan_version: int,
        expected_plan_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._decide(
            principal,
            incident_id=incident_id,
            expected_incident_version=expected_incident_version,
            expected_plan_version=expected_plan_version,
            expected_plan_sha256=expected_plan_sha256,
            outcome="approved",
            reason_code=None,
            idempotency_key=idempotency_key,
        )

    def reject_plan(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        expected_incident_version: int,
        expected_plan_version: int,
        expected_plan_sha256: str,
        reason_code: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._decide(
            principal,
            incident_id=incident_id,
            expected_incident_version=expected_incident_version,
            expected_plan_version=expected_plan_version,
            expected_plan_sha256=expected_plan_sha256,
            outcome="rejected",
            reason_code=reason_code,
            idempotency_key=idempotency_key,
        )

    def _decide(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        expected_incident_version: int,
        expected_plan_version: int,
        expected_plan_sha256: str,
        outcome: str,
        reason_code: str | None,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor = self._authorize(
            principal,
            incident_id=incident_id,
            role=APPROVER_ROLE,
            kinds=frozenset({"human"}),
        )
        key = require_idempotency_key(idempotency_key)
        request = {
            "operation": f"plan.{outcome}",
            "actor": actor,
            "incident_id": incident_id,
            "expected_incident_version": expected_incident_version,
            "expected_plan_version": expected_plan_version,
            "expected_plan_sha256": expected_plan_sha256,
            "reason_code": reason_code,
            "idempotency_key": key,
        }
        request_sha256 = self._request_digest(request)
        with self._repository.transaction(write=True) as connection:
            replay = self._replay(
                connection,
                key,
                request_sha256,
                incident_id=incident_id,
                event_type=f"plan.{outcome}",
                expected_plan_version=expected_plan_version,
            )
            if replay is not None:
                return replay
            incident_version = self._check_current_incident(
                connection,
                incident_id=incident_id,
                expected_incident_version=expected_incident_version,
            )
            plan = self._current_plan(connection, incident_id)
            self._check_expected_plan(
                plan,
                expected_plan_version=expected_plan_version,
                expected_plan_sha256=expected_plan_sha256,
            )
            if plan["incident_version"] != incident_version:
                raise ResponsePlanError("expected-version-conflict")
            if self._decision(connection, incident_id, expected_plan_version) is not None:
                raise ResponsePlanError("plan-decision-conflict")
            occurred_at = self._now()
            decision = build_decision(
                plan=plan,
                outcome=outcome,
                actor=actor,
                idempotency_key=key,
                decided_at=occurred_at,
                reason_code=reason_code,
            )
            audit = self._build_audit(
                connection,
                event_type=f"plan.{outcome}",
                plan=plan,
                record=decision,
                record_sha256=cast(str, decision["decision_sha256"]),
                actor=actor,
                idempotency_key=key,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    "INSERT INTO response_plan_decisions("
                    "incident_id, plan_version, decision_sha256, document) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        incident_id,
                        expected_plan_version,
                        decision["decision_sha256"],
                        canonical_json_bytes(decision),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ResponsePlanError("plan-decision-conflict") from error
            self._append_audit(connection, incident_id=incident_id, event=audit)
            self._remember(connection, key, request_sha256, decision)
            return cast(dict[str, Any], plain_json(decision))

    def authorize_dispatch(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        expected_incident_version: int,
        expected_plan_version: int,
        expected_plan_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor = self._authorize(
            principal,
            incident_id=incident_id,
            role=DISPATCHER_ROLE,
            kinds=frozenset({"service"}),
        )
        key = require_idempotency_key(idempotency_key)
        request = {
            "operation": "dispatch.authorize",
            "actor": actor,
            "incident_id": incident_id,
            "expected_incident_version": expected_incident_version,
            "expected_plan_version": expected_plan_version,
            "expected_plan_sha256": expected_plan_sha256,
            "idempotency_key": key,
        }
        request_sha256 = self._request_digest(request)
        with self._repository.transaction(write=True) as connection:
            incident_version = self._check_current_incident(
                connection,
                incident_id=incident_id,
                expected_incident_version=expected_incident_version,
            )
            plan = self._current_plan(connection, incident_id)
            self._check_expected_plan(
                plan,
                expected_plan_version=expected_plan_version,
                expected_plan_sha256=expected_plan_sha256,
            )
            if plan["incident_version"] != incident_version:
                raise ResponsePlanError("expected-version-conflict")
            replay = self._replay(
                connection,
                key,
                request_sha256,
                incident_id=incident_id,
                event_type="dispatch.authorized",
                expected_plan_version=expected_plan_version,
            )
            if replay is not None:
                return replay
            existing = connection.execute(
                "SELECT 1 FROM dispatch_authorizations WHERE incident_id = ? AND plan_version = ?",
                (incident_id, expected_plan_version),
            ).fetchone()
            if existing is not None:
                raise ResponsePlanError("dispatch-authorization-conflict")
            approval = self._decision(connection, incident_id, expected_plan_version)
            if approval is None:
                raise ResponsePlanError("plan-not-approved")
            validate_decision(approval, plan=plan)
            if approval["outcome"] != "approved":
                raise ResponsePlanError("plan-rejected")
            occurred_at = self._now()
            authorization = build_dispatch_authorization(
                plan=plan,
                approval=approval,
                actor=actor,
                idempotency_key=key,
                authorized_at=occurred_at,
            )
            audit = self._build_audit(
                connection,
                event_type="dispatch.authorized",
                plan=plan,
                record=authorization,
                record_sha256=cast(str, authorization["authorization_sha256"]),
                actor=actor,
                idempotency_key=key,
                occurred_at=occurred_at,
            )
            try:
                connection.execute(
                    "INSERT INTO dispatch_authorizations("
                    "authorization_id, operation_id, incident_id, plan_version, status, document) "
                    "VALUES (?, ?, ?, ?, 'authorized', ?)",
                    (
                        authorization["authorization_id"],
                        authorization["operation_id"],
                        incident_id,
                        expected_plan_version,
                        canonical_json_bytes(authorization),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ResponsePlanError("dispatch-authorization-conflict") from error
            self._append_audit(connection, incident_id=incident_id, event=audit)
            self._remember(connection, key, request_sha256, authorization)
            return cast(dict[str, Any], plain_json(authorization))

    def consume_dispatch_authorization(
        self,
        principal: VerifiedPrincipal | None,
        *,
        incident_id: str,
        authorization_id: str,
        expected_incident_version: int,
        expected_plan_version: int,
        expected_plan_sha256: str,
        expected_task_key: str,
        expected_payload_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        actor = self._authorize(
            principal,
            incident_id=incident_id,
            role=DISPATCHER_ROLE,
            kinds=frozenset({"service"}),
        )
        authorization_identifier = require_identifier(
            authorization_id, code="dispatch-authorization-id-invalid"
        )
        task_key = require_idempotency_key(expected_task_key)
        payload_sha256 = require_digest(expected_payload_sha256)
        key = require_idempotency_key(idempotency_key)
        request = {
            "operation": "dispatch.consume",
            "actor": actor,
            "incident_id": incident_id,
            "authorization_id": authorization_identifier,
            "expected_incident_version": expected_incident_version,
            "expected_plan_version": expected_plan_version,
            "expected_plan_sha256": expected_plan_sha256,
            "expected_task_key": task_key,
            "expected_payload_sha256": payload_sha256,
            "idempotency_key": key,
        }
        request_sha256 = self._request_digest(request)
        with self._repository.transaction(write=True) as connection:
            incident_version = self._check_current_incident(
                connection,
                incident_id=incident_id,
                expected_incident_version=expected_incident_version,
            )
            plan = self._current_plan(connection, incident_id)
            self._check_expected_plan(
                plan,
                expected_plan_version=expected_plan_version,
                expected_plan_sha256=expected_plan_sha256,
            )
            if plan["incident_version"] != incident_version:
                raise ResponsePlanError("expected-version-conflict")
            row = connection.execute(
                "SELECT status, document, consumption_document FROM dispatch_authorizations "
                "WHERE authorization_id = ? AND incident_id = ? AND plan_version = ?",
                (authorization_identifier, incident_id, expected_plan_version),
            ).fetchone()
            if row is None:
                raise ResponsePlanError("dispatch-authorization-not-found")
            authorization = SQLiteResponsePlanRepository.decode(bytes(row["document"]))
            if authorization["task_key"] != task_key:
                raise ResponsePlanError("dispatch-task-key-conflict")
            if authorization["payload_sha256"] != payload_sha256:
                raise ResponsePlanError("dispatch-payload-conflict")
            approval = self._decision(connection, incident_id, expected_plan_version)
            if approval is None or approval["outcome"] != "approved":
                raise ResponsePlanError("plan-not-approved")
            validate_dispatch_authorization(authorization, plan=plan, approval=approval)
            if row["status"] == "invalidated":
                raise ResponsePlanError("dispatch-authorization-stale")
            replay = self._replay(
                connection,
                key,
                request_sha256,
                incident_id=incident_id,
                event_type="dispatch.consumed",
                expected_plan_version=expected_plan_version,
                authorization_id=authorization_identifier,
            )
            if replay is not None:
                return replay
            if row["status"] == "consumed":
                self._validate_history(connection, incident_id)
                if row["consumption_document"] is None:
                    raise ResponsePlanError("stored-document-invalid")
                consumption = SQLiteResponsePlanRepository.decode(
                    bytes(row["consumption_document"])
                )
                validate_dispatch_consumption(
                    consumption,
                    authorization=authorization,
                    plan=plan,
                    approval=approval,
                )
                self._remember(connection, key, request_sha256, consumption)
                return consumption
            occurred_at = self._now()
            consumption = build_dispatch_consumption(
                authorization=authorization,
                plan=plan,
                approval=approval,
                actor=actor,
                idempotency_key=key,
                consumed_at=occurred_at,
            )
            audit = self._build_audit(
                connection,
                event_type="dispatch.consumed",
                plan=plan,
                record=consumption,
                record_sha256=cast(str, consumption["consumption_sha256"]),
                actor=actor,
                idempotency_key=key,
                occurred_at=occurred_at,
            )
            cursor = connection.execute(
                "UPDATE dispatch_authorizations SET status = 'consumed', "
                "consumption_document = ? WHERE authorization_id = ? AND status = 'authorized'",
                (canonical_json_bytes(consumption), authorization_identifier),
            )
            if cursor.rowcount != 1:
                raise ResponsePlanError("dispatch-consumption-conflict")
            self._append_audit(connection, incident_id=incident_id, event=audit)
            self._remember(connection, key, request_sha256, consumption)
            return cast(dict[str, Any], plain_json(consumption))

    def current_plan(self, incident_id: str) -> dict[str, Any]:
        incident = require_identifier(incident_id)
        with self._repository.transaction(write=False) as connection:
            self._validate_history(connection, incident)
            return cast(dict[str, Any], plain_json(self._current_plan(connection, incident)))

    def plan_version(self, incident_id: str, version: int) -> dict[str, Any]:
        incident = require_identifier(incident_id)
        selected_version = self._require_version(version, minimum=1)
        with self._repository.transaction(write=False) as connection:
            self._validate_history(connection, incident)
            return cast(
                dict[str, Any],
                plain_json(self._plan_version(connection, incident, selected_version)),
            )

    def decision(self, incident_id: str, version: int) -> dict[str, Any] | None:
        incident = require_identifier(incident_id)
        selected_version = self._require_version(version, minimum=1)
        with self._repository.transaction(write=False) as connection:
            self._validate_history(connection, incident)
            plan = self._plan_version(connection, incident, selected_version)
            decision = self._decision(connection, incident, selected_version)
            if decision is None:
                return None
            validate_decision(decision, plan=plan)
            return cast(dict[str, Any], plain_json(decision))

    def audit_history(self, incident_id: str) -> list[dict[str, Any]]:
        incident = require_identifier(incident_id)
        with self._repository.transaction(write=False) as connection:
            self._validate_history(connection, incident)
            return cast(list[dict[str, Any]], plain_json(self._events(connection, incident)))


__all__ = ["ResponsePlanService"]
