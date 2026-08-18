from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from .authority import RecoveryIdentityBoundary, RecoveryPrincipal
from .contracts import (
    RecoveryError,
    timestamp,
    validate_closure_request,
    validate_evidence_record,
    validate_evidence_request,
    validate_recovery_packet,
    validate_verification_snapshot,
)
from .repository import SQLiteRecoveryRepository, VerificationAttempt, VerificationClaim


def _utc_now() -> datetime:
    return datetime.now(UTC)


class RecoveryVerificationService:
    """Service-only authority for immutable, fenced recovery verification."""

    def __init__(
        self,
        *,
        repository: SQLiteRecoveryRepository,
        identity_boundary: RecoveryIdentityBoundary,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._repository = repository
        self._identity_boundary = identity_boundary
        self._clock = clock

    def request_verification(
        self,
        principal: RecoveryPrincipal,
        snapshot_value: Mapping[str, Any],
        request_value: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> VerificationAttempt:
        now = self._clock()
        snapshot = validate_verification_snapshot(snapshot_value)
        request = validate_evidence_request(request_value, snapshot=snapshot)
        actor = self._identity_boundary.assert_verifier(
            principal,
            incident_id=str(snapshot["incident_id"]),
            now=now,
        )
        return self._repository.register_verification(
            snapshot,
            request,
            actor=actor,
            idempotency_key=idempotency_key,
            now=timestamp(now),
        )

    def claim_verification(
        self,
        principal: RecoveryPrincipal,
        workflow_id: str,
        *,
        owner: str,
    ) -> VerificationClaim:
        now = self._clock()
        review = self._repository.review(workflow_id)
        actor = self._identity_boundary.assert_verifier(
            principal,
            incident_id=str(review["incident_id"]),
            now=now,
        )
        return self._repository.claim_verification(
            workflow_id,
            owner=owner,
            actor=actor,
            now=timestamp(now),
        )

    def renew_claim(
        self,
        principal: RecoveryPrincipal,
        claim: VerificationClaim,
    ) -> VerificationClaim:
        now = self._clock()
        actor = self._identity_boundary.assert_verifier(
            principal,
            incident_id=claim.incident_id,
            now=now,
        )
        return self._repository.renew_claim(
            claim,
            actor=actor,
            now=timestamp(now),
        )

    def complete_verification(
        self,
        principal: RecoveryPrincipal,
        claim: VerificationClaim,
        packet_value: Mapping[str, Any],
        *,
        evidence_records: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        now = self._clock()
        actor = self._identity_boundary.assert_verifier(
            principal,
            incident_id=claim.incident_id,
            now=now,
        )
        packet = validate_recovery_packet(
            packet_value,
            snapshot=claim.snapshot,
            evidence_request=claim.evidence_request,
        )
        records = tuple(validate_evidence_record(value) for value in evidence_records)
        return self._repository.complete_verification(
            claim,
            packet,
            evidence_records=records,
            actor=actor,
            now=timestamp(now),
        )


class RecoveryClosureService:
    """Authenticated human-only incident recovery closure."""

    def __init__(
        self,
        *,
        repository: SQLiteRecoveryRepository,
        identity_boundary: RecoveryIdentityBoundary,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._repository = repository
        self._identity_boundary = identity_boundary
        self._clock = clock

    def close(
        self,
        principal: RecoveryPrincipal,
        workflow_id: str,
        request_value: Mapping[str, Any],
    ) -> dict[str, Any]:
        now = self._clock()
        request = validate_closure_request(request_value)
        review = self._repository.review(workflow_id)
        actor = self._identity_boundary.assert_closer(
            principal,
            incident_id=str(review["incident_id"]),
            now=now,
        )
        return self._repository.close_workflow(
            workflow_id,
            request,
            actor=actor,
            now=timestamp(now),
        )


class RecoveryReadService:
    def __init__(self, repository: SQLiteRecoveryRepository) -> None:
        self._repository = repository

    def durable_aggregate(self, workflow_id: str) -> dict[str, Any]:
        return self._repository.durable_aggregate(workflow_id)

    def durable_aggregate_for_incident(self, incident_id: str) -> dict[str, Any]:
        return self._repository.durable_aggregate_for_incident(incident_id)

    def verification_packet_for_idempotency(
        self,
        incident_id: str,
        idempotency_key: str,
        expected_outcome_sha256: str,
    ) -> dict[str, Any] | None:
        return self._repository.verification_packet_for_idempotency(
            incident_id,
            idempotency_key,
            expected_outcome_sha256,
        )


__all__ = [
    "RecoveryClosureService",
    "RecoveryReadService",
    "RecoveryVerificationService",
    "RecoveryError",
]
