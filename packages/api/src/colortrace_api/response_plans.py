from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from colortrace_response_plans import (
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    ResponsePlanError,
    ResponsePlanService,
    SQLiteResponsePlanRepository,
    VerifiedPrincipal,
)
from colortrace_response_plans.contracts import canonical_json_bytes, prefixed_sha256
from colortrace_simulator import DispatchIdentity, StoredDispatchProof

from .auth import Principal


class CanonicalIncidentReader(Protocol):
    def replay(self, incident_id: str) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class PlanAuthoritySnapshot:
    incident_id: str
    incident_version: int
    response_packet_id: str
    response_packet_sha256: str
    deterministic_scope_sha256: str
    targets: tuple[dict[str, str], ...]
    exclusions: tuple[dict[str, str], ...]
    unresolved_item_ids: tuple[str, ...]
    blocking_unresolved_item_ids: tuple[str, ...]
    unknown_target_ids: tuple[str, ...]

    def to_draft(self) -> dict[str, Any]:
        return {
            "schema": "response-plan-draft/v1",
            "incident_id": self.incident_id,
            "incident_version": self.incident_version,
            "response_packet_id": self.response_packet_id,
            "response_packet_sha256": self.response_packet_sha256,
            "deterministic_scope_sha256": self.deterministic_scope_sha256,
            "targets": [dict(value) for value in self.targets],
            "exclusions": [dict(value) for value in self.exclusions],
            "unresolved_item_ids": list(self.unresolved_item_ids),
            "blocking_unresolved_item_ids": list(self.blocking_unresolved_item_ids),
            "unknown_target_ids": list(self.unknown_target_ids),
        }


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _exact_body(body: Mapping[str, Any], fields: frozenset[str]) -> None:
    if set(body) != fields:
        raise ResponsePlanError("request-invalid")


def _target(kind: str, identifier: str) -> dict[str, str]:
    return {
        "schema": "simulator-target/v1",
        "namespace": "colortrace-simulator",
        "kind": kind,
        "id": identifier,
    }


class ResponsePlanCoordinator:
    def __init__(
        self,
        *,
        incident_reader: CanonicalIncidentReader,
        repository: SQLiteResponsePlanRepository,
        authority_boundary: CanonicalAuthorityBoundary,
        identity_boundary: OIDCTrustBoundary,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._incident_reader = incident_reader
        self._repository = repository
        self._authority_boundary = authority_boundary
        self._identity_boundary = identity_boundary
        self._clock = clock
        self._service = ResponsePlanService(
            repository=repository,
            identity_boundary=identity_boundary,
            clock=clock,
        )

    def _principal(self, principal: Principal) -> VerifiedPrincipal:
        return self._identity_boundary.bind_verified_claims(
            issuer=principal.issuer,
            subject=principal.subject,
            audience=principal.audience,
            kind=principal.principal_kind,
            roles=principal.roles,
            incident_ids=principal.incident_ids,
            credential_sha256=principal.credential_sha256,
            expires_at=principal.expires_at,
            credential_verified=True,
            now=self._clock(),
        )

    def _snapshot(self, incident_id: str) -> PlanAuthoritySnapshot:
        replay = self._incident_reader.replay(incident_id)
        incident = cast(Mapping[str, Any], replay.get("incident"))
        packet = cast(Mapping[str, Any], replay.get("packet"))
        if (
            replay.get("schema") != "incident-replay/v1"
            or incident.get("incident_id") != incident_id
            or packet.get("incident_id") != incident_id
            or incident.get("status") not in {"resolved", "unresolved"}
        ):
            raise ResponsePlanError("canonical-state-invalid")
        incident_version = incident.get("version")
        if not isinstance(incident_version, int) or isinstance(incident_version, bool):
            raise ResponsePlanError("canonical-state-invalid")
        scope = cast(Mapping[str, Any], packet.get("scope"))
        candidate = packet.get("candidate_plan")
        if not isinstance(candidate, Mapping):
            raise ResponsePlanError("response-plan-unavailable")
        affected = cast(Sequence[Mapping[str, Any]], scope.get("affected"))
        safe = cast(Sequence[Mapping[str, Any]], scope.get("safe"))
        unknown = cast(Sequence[Mapping[str, Any]], scope.get("unknown"))
        if list(candidate.get("targets", ())) != list(affected):
            raise ResponsePlanError("canonical-scope-invalid")
        causal_values = {
            nested_scope.get("causal_resource_sha256")
            for result in cast(Sequence[Mapping[str, Any]], replay.get("validator_results", ()))
            if isinstance((nested_scope := result.get("scope")), Mapping)
            and nested_scope.get("causal_resource_sha256") is not None
        }
        if len(causal_values) != 1:
            raise ResponsePlanError("canonical-scope-invalid")
        causal_resource = next(iter(causal_values))
        if (
            not isinstance(causal_resource, str)
            or re.fullmatch(r"[0-9a-f]{64}", causal_resource) is None
        ):
            raise ResponsePlanError("canonical-scope-invalid")
        causal_resource_target = f"sha256:{causal_resource}"

        def scoped_target(value: Mapping[str, Any]) -> dict[str, str]:
            kind = value.get("kind")
            identifier = value.get("id")
            if kind not in {"frame", "derivative"} or not isinstance(identifier, str):
                raise ResponsePlanError("canonical-scope-invalid")
            return _target(cast(str, kind), identifier)

        targets = (
            _target("color-resource", causal_resource_target),
            *(scoped_target(item) for item in affected),
        )
        exclusions = tuple(scoped_target(item) for item in safe)
        unknown_ids = tuple(sorted(cast(str, item.get("id")) for item in unknown))
        unresolved_items = cast(Sequence[Mapping[str, Any]], packet.get("unresolved_items", ()))
        unresolved = tuple(sorted({cast(str, item.get("code")) for item in unresolved_items}))
        blocking = (
            unresolved
            if packet.get("status") != "resolved" or scope.get("state") != "resolved"
            else ()
        )
        packet_sha256 = packet.get("derivation_sha256")
        packet_id = packet.get("packet_id")
        if not isinstance(packet_sha256, str) or not isinstance(packet_id, str):
            raise ResponsePlanError("canonical-state-invalid")
        deterministic_scope_sha256 = prefixed_sha256(
            canonical_json_bytes(
                {
                    "schema": "deterministic-plan-scope/v1",
                    "scope": scope,
                    "causal_resource_sha256": causal_resource,
                }
            )
        )
        return PlanAuthoritySnapshot(
            incident_id=incident_id,
            incident_version=incident_version,
            response_packet_id=packet_id,
            response_packet_sha256=packet_sha256,
            deterministic_scope_sha256=deterministic_scope_sha256,
            targets=tuple(targets),
            exclusions=exclusions,
            unresolved_item_ids=unresolved,
            blocking_unresolved_item_ids=blocking,
            unknown_target_ids=unknown_ids,
        )

    def _register_authority(self, incident_id: str) -> PlanAuthoritySnapshot:
        snapshot = self._snapshot(incident_id)
        incident = self._authority_boundary.bind_incident_snapshot(
            incident_id=snapshot.incident_id,
            incident_version=snapshot.incident_version,
            canonical_state_verified=True,
        )
        self._repository.register_incident(incident)
        self._repository.register_response_packet(
            self._authority_boundary.bind_response_packet(
                incident=incident,
                packet_id=snapshot.response_packet_id,
                packet_sha256=snapshot.response_packet_sha256,
                deterministic_scope_sha256=snapshot.deterministic_scope_sha256,
                targets=snapshot.targets,
                exclusions=snapshot.exclusions,
                unresolved_item_ids=snapshot.unresolved_item_ids,
                blocking_unresolved_item_ids=snapshot.blocking_unresolved_item_ids,
                unknown_target_ids=snapshot.unknown_target_ids,
                canonical_state_verified=True,
            )
        )
        return snapshot

    def _assert_current(self, incident_id: str, expected_incident_version: int) -> None:
        if self._snapshot(incident_id).incident_version != expected_incident_version:
            raise ResponsePlanError("expected-version-conflict")

    def load_current_consumed(self, identity: DispatchIdentity) -> StoredDispatchProof:
        """Bridge #22 authority into #23 without accepting commands from the caller."""

        initial = self._service.current_consumed_dispatch(
            task_key=identity.task_key,
            operation_id=identity.operation_id,
            payload_sha256=identity.payload_sha256,
        )
        incident_id = cast(str, cast(Mapping[str, Any], initial["plan"])["incident_id"])
        before = self._snapshot(incident_id)
        proof = self._service.current_consumed_dispatch(
            task_key=identity.task_key,
            operation_id=identity.operation_id,
            payload_sha256=identity.payload_sha256,
        )
        after = self._snapshot(incident_id)
        return self._validated_dispatch_proof(proof, before=before, after=after)

    @contextmanager
    def guard_current_consumed(
        self,
        identity: DispatchIdentity,
    ) -> Iterator[StoredDispatchProof]:
        """Keep one exact consumed dispatch stable through publication and terminal commit."""

        with self._service.guard_current_consumed_dispatch(
            task_key=identity.task_key,
            operation_id=identity.operation_id,
            payload_sha256=identity.payload_sha256,
        ) as proof:
            plan = cast(Mapping[str, Any], proof["plan"])
            incident_id = cast(str, plan["incident_id"])
            before = self._snapshot(incident_id)
            after = self._snapshot(incident_id)
            yield self._validated_dispatch_proof(proof, before=before, after=after)

    @staticmethod
    def _validated_dispatch_proof(
        proof: Mapping[str, Any],
        *,
        before: PlanAuthoritySnapshot,
        after: PlanAuthoritySnapshot,
    ) -> StoredDispatchProof:
        plan = cast(Mapping[str, Any], proof["plan"])

        def ordered_targets(values: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
            return sorted(
                values,
                key=lambda value: (
                    str(value.get("namespace")),
                    str(value.get("kind")),
                    str(value.get("id")),
                ),
            )

        expected_authority = {
            "incident_id": before.incident_id,
            "incident_version": before.incident_version,
            "response_packet_id": before.response_packet_id,
            "response_packet_sha256": before.response_packet_sha256,
            "deterministic_scope_sha256": before.deterministic_scope_sha256,
            "targets": ordered_targets(before.targets),
            "exclusions": ordered_targets(before.exclusions),
        }
        plan_authority = {key: plan.get(key) for key in expected_authority}
        plan_authority["targets"] = ordered_targets(
            cast(Sequence[Mapping[str, Any]], plan.get("targets"))
        )
        plan_authority["exclusions"] = ordered_targets(
            cast(Sequence[Mapping[str, Any]], plan.get("exclusions"))
        )
        if before != after or canonical_json_bytes(expected_authority) != canonical_json_bytes(
            plan_authority
        ):
            raise ResponsePlanError("canonical-state-changed")
        return StoredDispatchProof(
            plan=plan,
            approval=cast(Mapping[str, Any], proof["approval"]),
            authorization=cast(Mapping[str, Any], proof["authorization"]),
            consumption=cast(Mapping[str, Any], proof["consumption"]),
            audit_events=tuple(cast(list[Mapping[str, Any]], proof["audit_events"])),
            records=cast(Mapping[str, Mapping[str, Any]], proof["records"]),
            trusted_audit_head_sha256=cast(str, proof["trusted_audit_head_sha256"]),
        )

    def draft(self, incident_id: str) -> dict[str, Any]:
        return self._snapshot(incident_id).to_draft()

    def review(self, incident_id: str) -> dict[str, Any]:
        plan = self._service.current_plan(incident_id)
        decision = self._service.decision(incident_id, cast(int, plan["version"]))
        snapshot = self._snapshot(incident_id)
        if snapshot.incident_version != plan["incident_version"]:
            state = "stale"
        elif decision is None:
            state = "pending"
        else:
            state = cast(str, decision["outcome"])
        return {
            "schema": "response-plan-review/v1",
            "state": state,
            "current_incident_version": snapshot.incident_version,
            "plan": plan,
            "decision": decision,
            "audit_events": self._service.audit_history(incident_id),
        }

    def create(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        _exact_body(
            body,
            frozenset(
                {
                    "expected_incident_version",
                    "expected_plan_version",
                    "response_packet_id",
                    "response_packet_sha256",
                    "deterministic_scope_sha256",
                    "targets",
                    "exclusions",
                    "commands",
                    "unresolved_acknowledged",
                    "idempotency_key",
                }
            ),
        )
        verified_principal = self._principal(principal)
        self._service.preauthorize_plan_editor(
            verified_principal,
            incident_id=incident_id,
        )
        self._register_authority(incident_id)
        return self._service.create_plan(
            verified_principal,
            incident_id=incident_id,
            expected_incident_version=cast(int, body["expected_incident_version"]),
            expected_plan_version=cast(int, body["expected_plan_version"]),
            response_packet_id=cast(str, body["response_packet_id"]),
            response_packet_sha256=cast(str, body["response_packet_sha256"]),
            deterministic_scope_sha256=cast(str, body["deterministic_scope_sha256"]),
            targets=cast(Sequence[Mapping[str, Any]], body["targets"]),
            exclusions=cast(Sequence[Mapping[str, Any]], body["exclusions"]),
            commands=cast(Sequence[Mapping[str, Any]], body["commands"]),
            unresolved_acknowledged=cast(bool, body["unresolved_acknowledged"]),
            idempotency_key=cast(str, body["idempotency_key"]),
        )

    def edit(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        _exact_body(
            body,
            frozenset(
                {
                    "expected_incident_version",
                    "expected_plan_version",
                    "expected_plan_sha256",
                    "response_packet_id",
                    "response_packet_sha256",
                    "deterministic_scope_sha256",
                    "targets",
                    "exclusions",
                    "commands",
                    "unresolved_acknowledged",
                    "idempotency_key",
                }
            ),
        )
        verified_principal = self._principal(principal)
        self._service.preauthorize_plan_editor(
            verified_principal,
            incident_id=incident_id,
        )
        self._register_authority(incident_id)
        return self._service.edit_plan(
            verified_principal,
            incident_id=incident_id,
            expected_incident_version=cast(int, body["expected_incident_version"]),
            expected_plan_version=cast(int, body["expected_plan_version"]),
            expected_plan_sha256=cast(str, body["expected_plan_sha256"]),
            response_packet_id=cast(str, body["response_packet_id"]),
            response_packet_sha256=cast(str, body["response_packet_sha256"]),
            deterministic_scope_sha256=cast(str, body["deterministic_scope_sha256"]),
            targets=cast(Sequence[Mapping[str, Any]], body["targets"]),
            exclusions=cast(Sequence[Mapping[str, Any]], body["exclusions"]),
            commands=cast(Sequence[Mapping[str, Any]], body["commands"]),
            unresolved_acknowledged=cast(bool, body["unresolved_acknowledged"]),
            idempotency_key=cast(str, body["idempotency_key"]),
        )

    def approve(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        _exact_body(
            body,
            frozenset(
                {
                    "expected_incident_version",
                    "expected_plan_version",
                    "expected_plan_sha256",
                    "idempotency_key",
                }
            ),
        )
        expected_incident_version = cast(int, body["expected_incident_version"])
        self._assert_current(incident_id, expected_incident_version)
        return self._service.approve_plan(
            self._principal(principal),
            incident_id=incident_id,
            expected_incident_version=expected_incident_version,
            expected_plan_version=cast(int, body["expected_plan_version"]),
            expected_plan_sha256=cast(str, body["expected_plan_sha256"]),
            idempotency_key=cast(str, body["idempotency_key"]),
        )

    def reject(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        _exact_body(
            body,
            frozenset(
                {
                    "expected_incident_version",
                    "expected_plan_version",
                    "expected_plan_sha256",
                    "reason_code",
                    "idempotency_key",
                }
            ),
        )
        expected_incident_version = cast(int, body["expected_incident_version"])
        self._assert_current(incident_id, expected_incident_version)
        return self._service.reject_plan(
            self._principal(principal),
            incident_id=incident_id,
            expected_incident_version=expected_incident_version,
            expected_plan_version=cast(int, body["expected_plan_version"]),
            expected_plan_sha256=cast(str, body["expected_plan_sha256"]),
            reason_code=cast(str, body["reason_code"]),
            idempotency_key=cast(str, body["idempotency_key"]),
        )

    def authorize_dispatch(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        _exact_body(
            body,
            frozenset(
                {
                    "expected_incident_version",
                    "expected_plan_version",
                    "expected_plan_sha256",
                    "idempotency_key",
                }
            ),
        )
        expected_incident_version = cast(int, body["expected_incident_version"])
        self._assert_current(incident_id, expected_incident_version)
        return self._service.authorize_dispatch(
            self._principal(principal),
            incident_id=incident_id,
            expected_incident_version=expected_incident_version,
            expected_plan_version=cast(int, body["expected_plan_version"]),
            expected_plan_sha256=cast(str, body["expected_plan_sha256"]),
            idempotency_key=cast(str, body["idempotency_key"]),
        )

    def consume_dispatch(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        _exact_body(
            body,
            frozenset(
                {
                    "authorization_id",
                    "expected_incident_version",
                    "expected_plan_version",
                    "expected_plan_sha256",
                    "expected_task_key",
                    "expected_payload_sha256",
                    "idempotency_key",
                }
            ),
        )
        expected_incident_version = cast(int, body["expected_incident_version"])
        self._assert_current(incident_id, expected_incident_version)
        return self._service.consume_dispatch_authorization(
            self._principal(principal),
            incident_id=incident_id,
            authorization_id=cast(str, body["authorization_id"]),
            expected_incident_version=expected_incident_version,
            expected_plan_version=cast(int, body["expected_plan_version"]),
            expected_plan_sha256=cast(str, body["expected_plan_sha256"]),
            expected_task_key=cast(str, body["expected_task_key"]),
            expected_payload_sha256=cast(str, body["expected_payload_sha256"]),
            idempotency_key=cast(str, body["idempotency_key"]),
        )


class ResponsePlanApi(Protocol):
    def draft(self, incident_id: str) -> dict[str, Any]: ...
    def review(self, incident_id: str) -> dict[str, Any]: ...
    def create(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...
    def edit(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...
    def approve(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...
    def reject(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...
    def authorize_dispatch(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...
    def consume_dispatch(
        self, principal: Principal, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]: ...


__all__ = ["ResponsePlanApi", "ResponsePlanCoordinator"]
