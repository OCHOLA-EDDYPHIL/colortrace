from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from colortrace_recovery import (
    RecoveryClosureService,
    RecoveryError,
    RecoveryIdentityBoundary,
    RecoveryPrincipal,
    require_digest,
    require_idempotency_key,
    validate_closure_request,
)

from .auth import Principal
from .recovery_closure import RecoveryClosureFence
from .recovery_tasks import (
    RecoveryVerificationTaskDispatcher,
    build_recovery_verification_task,
    validate_recovery_verification_admission,
)

SCHEDULER_ROLE = "recovery.scheduler"


def _utc_now() -> datetime:
    return datetime.now(UTC)


class CanonicalIncidentReader(Protocol):
    def replay(self, incident_id: str) -> dict[str, Any]: ...


class RecoveryAggregateReader(Protocol):
    def durable_aggregate_for_incident(self, incident_id: str) -> dict[str, Any]: ...


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RecoveryError("stored-recovery-time-invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise RecoveryError("stored-recovery-time-invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise RecoveryError("stored-recovery-time-invalid")
    return parsed.astimezone(UTC)


class RecoveryCoordinator:
    """Projects durable recovery authority without moving verification into the browser."""

    def __init__(
        self,
        *,
        incident_reader: CanonicalIncidentReader,
        aggregate_reader: RecoveryAggregateReader,
        closure_service: RecoveryClosureService,
        identity_boundary: RecoveryIdentityBoundary,
        task_dispatcher: RecoveryVerificationTaskDispatcher | None = None,
        closure_fence: RecoveryClosureFence | None = None,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        self._incident_reader = incident_reader
        self._aggregate_reader = aggregate_reader
        self._closure_service = closure_service
        self._identity_boundary = identity_boundary
        self._task_dispatcher = task_dispatcher
        self._closure_fence = closure_fence
        self._clock = clock

    def _principal(self, principal: Principal) -> RecoveryPrincipal:
        return self._identity_boundary.bind_verified_claims(
            issuer=principal.issuer,
            subject=principal.subject,
            display_name=principal.display_name,
            audience=principal.audience,
            kind=principal.principal_kind,
            roles=principal.roles,
            incident_ids=principal.incident_ids,
            credential_sha256=principal.credential_sha256,
            expires_at=principal.expires_at,
            credential_verified=True,
            now=self._clock(),
        )

    def _incident_version(self, incident_id: str) -> int:
        replay = self._incident_reader.replay(incident_id)
        incident = replay.get("incident")
        if (
            replay.get("schema") != "incident-replay/v1"
            or not isinstance(incident, Mapping)
            or incident.get("incident_id") != incident_id
            or incident.get("status") not in {"resolved", "unresolved"}
        ):
            raise RecoveryError("canonical-incident-invalid")
        version = incident.get("version")
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise RecoveryError("canonical-incident-invalid")
        return version

    @staticmethod
    def _target_for_evidence(
        outcome: Mapping[str, Any],
        record: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        subject_id = record.get("subject_id")
        if record.get("subject_kind") == "command":
            matches = [
                item.get("target")
                for item in cast(Sequence[Mapping[str, Any]], outcome.get("command_outcomes", ()))
                if item.get("command_id") == subject_id and isinstance(item.get("target"), Mapping)
            ]
        else:
            matches = [
                item
                for item in cast(Sequence[Mapping[str, Any]], outcome.get("exclusions", ()))
                if item.get("id") == subject_id
            ]
        if len(matches) != 1:
            raise RecoveryError("stored-evidence-target-invalid")
        return cast(Mapping[str, Any], matches[0])

    @staticmethod
    def _freshness(
        record: Mapping[str, Any],
        *,
        action_started_at: datetime,
        evaluation_started_at: datetime,
        evaluation_completed_at: datetime,
    ) -> str:
        provenance = record.get("clock_provenance")
        skew = record.get("clock_skew_milliseconds")
        if (
            provenance == "unknown"
            or not isinstance(skew, int)
            or isinstance(skew, bool)
            or abs(skew) > 5_000
        ):
            return "ambiguous"
        observed = _parse_time(record.get("observed_at"))
        emitted = _parse_time(record.get("emitted_at"))
        retrieved = _parse_time(record.get("retrieved_at"))
        if observed <= action_started_at or emitted <= action_started_at:
            return "pre-action"
        if (
            not evaluation_started_at <= retrieved <= evaluation_completed_at
            or evaluation_completed_at - retrieved > timedelta(seconds=60)
        ):
            return "late"
        return "post-action"

    @classmethod
    def _public_evidence(
        cls,
        aggregate: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        snapshot = cast(Mapping[str, Any], aggregate["snapshot"])
        outcome = cast(Mapping[str, Any], snapshot["action_outcome"])
        packet = aggregate.get("packet")
        if packet is None:
            return []
        if not isinstance(packet, Mapping):
            raise RecoveryError("stored-recovery-packet-invalid")
        started = _parse_time(outcome["action_started_at"])
        evaluation_start = _parse_time(packet["evaluation_started_at"])
        evaluation_end = _parse_time(packet["evaluation_completed_at"])
        records: list[dict[str, Any]] = []
        for raw in cast(Sequence[Mapping[str, Any]], aggregate.get("evidence", ())):
            target = cls._target_for_evidence(outcome, raw)
            signal = raw.get("signal")
            subject_kind = raw.get("subject_kind")
            subject_id = raw.get("subject_id")
            excerpt = f"{signal} evidence for {subject_kind} {subject_id}"
            records.append(
                {
                    "schema": "recovery-evidence-record/v1",
                    "evidence_id": raw.get("evidence_id"),
                    "evidence_sha256": raw.get("evidence_sha256"),
                    "signal": signal,
                    "event_id": raw.get("event_id"),
                    "subject_kind": subject_kind,
                    "subject_id": subject_id,
                    "trace_id": raw.get("trace_id"),
                    "observed_at": raw.get("observed_at"),
                    "emitted_at": raw.get("emitted_at"),
                    "retrieved_at": raw.get("retrieved_at"),
                    "freshness": cls._freshness(
                        raw,
                        action_started_at=started,
                        evaluation_started_at=evaluation_start,
                        evaluation_completed_at=evaluation_end,
                    ),
                    "correlation": {
                        "incident_id": snapshot["incident_id"],
                        "action_id": outcome["action_id"],
                        "outcome_id": outcome["outcome_id"],
                        "outcome_sha256": outcome["outcome_sha256"],
                        "target": dict(target),
                    },
                    "source_label": raw.get("source_label"),
                    "display_excerpt": excerpt[:4_096],
                }
            )
        return sorted(records, key=lambda item: cast(str, item["evidence_id"]))

    def review(self, incident_id: str) -> dict[str, Any]:
        current_version = self._incident_version(incident_id)
        aggregate = self._aggregate_reader.durable_aggregate_for_incident(incident_id)
        internal = aggregate.get("review")
        snapshot = aggregate.get("snapshot")
        if (
            aggregate.get("schema") != "recovery-durable-aggregate/v1"
            or not isinstance(internal, Mapping)
            or not isinstance(snapshot, Mapping)
            or internal.get("incident_id") != incident_id
            or snapshot.get("incident_id") != incident_id
        ):
            raise RecoveryError("stored-recovery-aggregate-invalid")
        return {
            "schema": "recovery-review/v1",
            "state": internal.get("status"),
            "current_incident_version": current_version,
            "workflow_version": internal.get("workflow_version"),
            "snapshot": snapshot,
            "evidence_records": self._public_evidence(aggregate),
            "packet": aggregate.get("packet"),
            "closure": aggregate.get("closure"),
            "audit_events": aggregate.get("audit_events"),
        }

    def _assert_scheduler(
        self,
        principal: RecoveryPrincipal,
        *,
        incident_id: str,
    ) -> None:
        self._identity_boundary.assert_trusted(principal, now=self._clock())
        if principal.kind == "model":
            raise RecoveryError("model-authority-forbidden")
        if principal.kind != "service":
            raise RecoveryError("scheduler-service-required")
        if SCHEDULER_ROLE not in principal.roles:
            raise RecoveryError("scheduler-role-required")
        if incident_id not in principal.incident_ids:
            raise RecoveryError("incident-access-denied")

    def admit_verification(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        if (
            set(body)
            != {
                "schema",
                "expected_incident_version",
                "expected_outcome_sha256",
                "idempotency_key",
            }
            or body.get("schema") != "recovery-verification-admission-request/v1"
        ):
            raise RecoveryError("verification-admission-request-invalid")
        recovery_principal = self._principal(principal)
        self._assert_scheduler(recovery_principal, incident_id=incident_id)
        if self._task_dispatcher is None:
            raise RecoveryError("recovery-verification-dispatcher-unavailable")
        expected_incident_version = body.get("expected_incident_version")
        idempotency_key = body.get("idempotency_key")
        expected_outcome_sha256 = body.get("expected_outcome_sha256")
        if (
            not isinstance(expected_incident_version, int)
            or isinstance(expected_incident_version, bool)
            or expected_incident_version < 1
            or not isinstance(idempotency_key, str)
            or not isinstance(expected_outcome_sha256, str)
        ):
            raise RecoveryError("verification-admission-request-invalid")
        require_idempotency_key(idempotency_key)
        require_digest(expected_outcome_sha256, code="expected-outcome-digest-invalid")
        current_version = self._incident_version(incident_id)
        if current_version != expected_incident_version:
            raise RecoveryError("verification-expected-version-conflict")
        task = build_recovery_verification_task(
            incident_id=incident_id,
            expected_incident_version=current_version,
            expected_outcome_sha256=expected_outcome_sha256,
            idempotency_key=idempotency_key,
        )
        admission = self._task_dispatcher.dispatch(task)
        return validate_recovery_verification_admission(
            admission,
            task_value=task,
        )

    def close(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        request = validate_closure_request(body)
        recovery_principal = self._principal(principal)
        self._identity_boundary.assert_closer(
            recovery_principal,
            incident_id=incident_id,
            now=self._clock(),
        )
        current_version = self._incident_version(incident_id)
        if request["expected_incident_version"] != current_version:
            raise RecoveryError("closure-expected-version-conflict")
        aggregate = self._aggregate_reader.durable_aggregate_for_incident(incident_id)
        review = aggregate.get("review")
        snapshot = aggregate.get("snapshot")
        if (
            not isinstance(review, Mapping)
            or not isinstance(review.get("workflow_id"), str)
            or not isinstance(snapshot, Mapping)
        ):
            raise RecoveryError("stored-recovery-aggregate-invalid")
        workflow_id = cast(str, review["workflow_id"])
        if review.get("status") == "closed":
            return self._closure_service.close(recovery_principal, workflow_id, request)
        if self._closure_fence is None:
            raise RecoveryError("recovery-closure-fence-unavailable")
        with self._closure_fence.guard(
            incident_id=incident_id,
            expected_outcome_sha256=cast(str, request["expected_outcome_sha256"]),
            verified_snapshot=snapshot,
        ):
            if self._incident_version(incident_id) != current_version:
                raise RecoveryError("closure-expected-version-conflict")
            return self._closure_service.close(recovery_principal, workflow_id, request)


class RecoveryApi(Protocol):
    def review(self, incident_id: str) -> dict[str, Any]: ...

    def close(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]: ...


class RecoveryVerificationAdmissionApi(Protocol):
    def admit_verification(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]: ...


__all__ = [
    "SCHEDULER_ROLE",
    "RecoveryApi",
    "RecoveryCoordinator",
    "RecoveryVerificationAdmissionApi",
]
