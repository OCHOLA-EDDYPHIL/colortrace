from __future__ import annotations

import hmac
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any, Literal, cast

from colortrace_validator import ActionIntent, IncidentClass

from .authority import (
    SimulatorAuthorityError,
    canonical_json_bytes,
    plain_json,
    prefixed_sha256,
    validate_schema,
)

REFERENCE_RECOVERY_STATE_VERSION = "reference-recovery-state/v3"
REFERENCE_HUMAN_APPROVAL_VERSION = "reference-human-approval/v3"
REFERENCE_RECOVERY_RECEIPT_VERSION = "reference-recovery-receipt/v3"
REFERENCE_RECOVERY_VERIFICATION_VERSION = "reference-recovery-verification/v1"
REFERENCE_PUBLIC_APPROVAL_PHRASE = "APPROVE_COLORTRACE_SIMULATOR_ACTION"
REFERENCE_PUBLIC_DENIAL_PHRASE = "DENY_COLORTRACE_SIMULATOR_ACTION"

ApprovalDecision = Literal["approved", "denied"]
IdentityAssurance = Literal["verified-identity", "unverified-public-demo-gesture"]
RecoveryCommand = Literal["reconcile-resource", "pin-rollout", "invalidate-cache"]

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_ACTION_ID = re.compile(r"^action-intent:[0-9a-f]{64}$")
_RECONCILIATION_ID = re.compile(r"^diagnosis-reconciliation:[0-9a-f]{64}$")
_APPROVAL_ID = re.compile(r"^reference-approval:[0-9a-f]{64}$")
_SCENARIO_CLASS: Mapping[str, IncidentClass] = MappingProxyType(
    {
        "tos-resource-resolution-drift-v1": IncidentClass.RESOURCE_RESOLUTION_DRIFT,
        "tos-config-rollout-drift-v1": IncidentClass.CONFIGURATION_ROLLOUT_DRIFT,
        "tos-stale-derivative-cache-v1": IncidentClass.STALE_DERIVATIVE_CACHE,
    }
)
_CLASS_COMMAND: Mapping[IncidentClass, RecoveryCommand] = MappingProxyType(
    {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: "reconcile-resource",
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: "pin-rollout",
        IncidentClass.STALE_DERIVATIVE_CACHE: "invalidate-cache",
    }
)
_CLASS_EXPECTED_FIELDS: Mapping[IncidentClass, tuple[str, ...]] = MappingProxyType(
    {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: ("effective_resource_sha256",),
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: (
            "config_generation",
            "effective_config_sha256",
        ),
        IncidentClass.STALE_DERIVATIVE_CACHE: (
            "derivative_generation",
            "derivative_parent_sha256",
        ),
    }
)
_ACTION_KEYS = frozenset(
    {
        "schema",
        "reconciliation_id",
        "incident_class",
        "command",
        "target",
        "requires_human_approval",
        "authorizes_execution",
        "affected_job_ids",
        "evidence_fact_ids",
        "parameters",
        "action_intent_id",
        "derivation_sha256",
    }
)
_MAX_APPROVAL_TTL = timedelta(minutes=10)


class ReferenceRecoveryError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _digest(value: Any) -> str:
    return prefixed_sha256(canonical_json_bytes(value))


def _plain(value: Any) -> Any:
    return plain_json(value)


def _require_digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ReferenceRecoveryError(code)
    return value


def _require_identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ReferenceRecoveryError(code)
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ReferenceRecoveryError("reference-approval-time-invalid")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReferenceRecoveryError("reference-approval-time-invalid") from error
    if parsed.tzinfo is None:
        raise ReferenceRecoveryError("reference-approval-time-invalid")
    return parsed.astimezone(UTC)


def validate_reference_action_intent(
    value: ActionIntent | Mapping[str, Any],
) -> ActionIntent:
    if isinstance(value, ActionIntent):
        return value
    try:
        raw_document = _plain(value)
        if not isinstance(raw_document, dict):
            raise ReferenceRecoveryError("reference-action-intent-invalid")
        document = cast(dict[str, Any], raw_document)
        if set(document) != _ACTION_KEYS or document["schema"] != "simulator-action-intent/v1":
            raise ReferenceRecoveryError("reference-action-intent-invalid")
        affected = document["affected_job_ids"]
        evidence = document["evidence_fact_ids"]
        parameters = document["parameters"]
        if (
            not isinstance(affected, list)
            or not isinstance(evidence, list)
            or not isinstance(parameters, Mapping)
        ):
            raise ReferenceRecoveryError("reference-action-intent-invalid")
        parsed = ActionIntent(
            reconciliation_id=cast(str, document["reconciliation_id"]),
            incident_class=IncidentClass(cast(str, document["incident_class"])),
            command=cast(RecoveryCommand, document["command"]),
            affected_job_ids=tuple(cast(list[str], affected)),
            evidence_fact_ids=tuple(cast(list[str], evidence)),
            parameters=cast(Mapping[str, Any], parameters),
            target=cast(Literal["simulator"], document["target"]),
            requires_human_approval=cast(bool, document["requires_human_approval"]),
            authorizes_execution=cast(bool, document["authorizes_execution"]),
        )
    except (KeyError, SimulatorAuthorityError, TypeError, ValueError) as error:
        raise ReferenceRecoveryError("reference-action-intent-invalid") from error
    if parsed.to_dict() != document:
        raise ReferenceRecoveryError("reference-action-intent-invalid")
    return parsed


def validate_reference_recovery_verification(value: Mapping[str, Any]) -> dict[str, Any]:
    code = "reference-recovery-verification-invalid"
    fields = {
        "schema",
        "verifier",
        "result",
        "scenario_id",
        "incident_class",
        "action_intent_id",
        "action_intent_sha256",
        "reconciliation_id",
        "before",
        "after",
        "affected_job_ids",
        "affected_expected_field_checks",
        "checks",
        "establishes_pixel_output",
        "establishes_full_population_scope",
        "production_evidence",
        "verification_sha256",
    }
    expected_checks = {
        "generation_advanced_exactly_once": True,
        "all_affected_expected_fields_match": True,
        "protected_state_unchanged": True,
        "receipt_state_bindings_match": True,
    }
    try:
        raw = _plain(value)
        if not isinstance(raw, dict):
            raise ReferenceRecoveryError(code)
        document = cast(dict[str, Any], raw)
        before = document.get("before")
        after = document.get("after")
        affected = document.get("affected_job_ids")
        field_checks = document.get("affected_expected_field_checks")
        checks = document.get("checks")
        scenario_id = document.get("scenario_id")
        incident_value = document.get("incident_class")
        if not isinstance(scenario_id, str) or not isinstance(incident_value, str):
            raise ReferenceRecoveryError(code)
        incident_class = IncidentClass(incident_value)
        before_generation = before.get("generation") if isinstance(before, dict) else None
        after_generation = after.get("generation") if isinstance(after, dict) else None
        if (
            set(document) != fields
            or document.get("schema") != REFERENCE_RECOVERY_VERIFICATION_VERSION
            or document.get("verifier") != "deterministic-simulator-state"
            or document.get("result") != "verified"
            or _SCENARIO_CLASS.get(scenario_id) is not incident_class
            or not isinstance(before, dict)
            or not isinstance(after, dict)
            or not isinstance(affected, list)
            or not affected
            or tuple(affected) != tuple(sorted(set(affected)))
            or not isinstance(field_checks, list)
            or [item.get("field") for item in field_checks if isinstance(item, dict)]
            != list(_CLASS_EXPECTED_FIELDS[incident_class])
            or len(field_checks) != len(_CLASS_EXPECTED_FIELDS[incident_class])
            or any(
                not isinstance(item, dict)
                or set(item) != {"field", "expected_value", "matched_job_ids"}
                or item.get("matched_job_ids") != affected
                for item in field_checks
            )
            or checks != expected_checks
            or isinstance(before_generation, bool)
            or not isinstance(before_generation, int)
            or isinstance(after_generation, bool)
            or not isinstance(after_generation, int)
            or after_generation != before_generation + 1
            or before.get("protected_state_sha256") != after.get("protected_state_sha256")
            or document.get("establishes_pixel_output") is not False
            or document.get("establishes_full_population_scope") is not False
            or document.get("production_evidence") is not False
        ):
            raise ReferenceRecoveryError(code)
        body = {key: item for key, item in document.items() if key != "verification_sha256"}
        if document.get("verification_sha256") != _digest(body):
            raise ReferenceRecoveryError(code)
        validate_schema("reference-recovery-verification-v1.schema.json", document)
        return document
    except ReferenceRecoveryError:
        raise
    except (KeyError, SimulatorAuthorityError, TypeError, ValueError) as error:
        raise ReferenceRecoveryError(code) from error


@dataclass(frozen=True, slots=True)
class ReferenceJobState:
    job_id: str
    effective_resource_sha256: str
    effective_config_sha256: str
    config_generation: int
    frame_sha256: str
    derivative_parent_sha256: str
    derivative_generation: int
    cache_key: str
    derivative_sha256: str
    job_state_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            _IDENTIFIER.fullmatch(self.job_id) is None
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.effective_resource_sha256,
                    self.effective_config_sha256,
                    self.frame_sha256,
                    self.derivative_parent_sha256,
                    self.derivative_sha256,
                )
            )
            or isinstance(self.config_generation, bool)
            or self.config_generation < 1
            or isinstance(self.derivative_generation, bool)
            or self.derivative_generation < 1
            or _IDENTIFIER.fullmatch(self.cache_key) is None
        ):
            raise ReferenceRecoveryError("reference-job-state-invalid")
        object.__setattr__(self, "job_state_sha256", _digest(self._body()))

    def _body(self) -> dict[str, Any]:
        return {
            "schema": "reference-job-state/v3",
            "job_id": self.job_id,
            "effective_resource_sha256": self.effective_resource_sha256,
            "effective_config_sha256": self.effective_config_sha256,
            "config_generation": self.config_generation,
            "frame_sha256": self.frame_sha256,
            "derivative_parent_sha256": self.derivative_parent_sha256,
            "derivative_generation": self.derivative_generation,
            "cache_key": self.cache_key,
            "derivative_sha256": self.derivative_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "job_state_sha256": self.job_state_sha256}


@dataclass(frozen=True, slots=True)
class ReferenceRecoveryState:
    scenario_id: str
    incident_class: IncidentClass
    generation: int
    affected_job_ids: tuple[str, ...]
    protected_job_ids: tuple[str, ...]
    jobs: tuple[ReferenceJobState, ...]
    protected_state_sha256: str = field(init=False)
    state_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        affected = tuple(sorted(set(self.affected_job_ids)))
        protected = tuple(sorted(set(self.protected_job_ids)))
        jobs = tuple(sorted(self.jobs, key=lambda item: item.job_id))
        job_ids = tuple(item.job_id for item in jobs)
        if (
            _SCENARIO_CLASS.get(self.scenario_id) is not self.incident_class
            or isinstance(self.generation, bool)
            or self.generation < 1
            or not affected
            or not protected
            or set(affected) & set(protected)
            or len(job_ids) != len(set(job_ids))
            or set(job_ids) != set(affected) | set(protected)
        ):
            raise ReferenceRecoveryError("reference-recovery-state-invalid")
        object.__setattr__(self, "affected_job_ids", affected)
        object.__setattr__(self, "protected_job_ids", protected)
        object.__setattr__(self, "jobs", jobs)
        protected_body = {
            "schema": "reference-protected-state/v3",
            "scenario_id": self.scenario_id,
            "jobs": [item.to_dict() for item in jobs if item.job_id in set(protected)],
        }
        object.__setattr__(self, "protected_state_sha256", _digest(protected_body))
        object.__setattr__(self, "state_sha256", _digest(self._body()))
        validate_schema("reference-recovery-state-v3.schema.json", self.to_dict())

    def _body(self) -> dict[str, Any]:
        return {
            "schema": REFERENCE_RECOVERY_STATE_VERSION,
            "scenario_id": self.scenario_id,
            "incident_class": self.incident_class.value,
            "generation": self.generation,
            "scope": {
                "affected_job_ids": list(self.affected_job_ids),
                "protected_job_ids": list(self.protected_job_ids),
            },
            "jobs": [item.to_dict() for item in self.jobs],
            "protected_state_sha256": self.protected_state_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "state_sha256": self.state_sha256}

    def job(self, job_id: str) -> ReferenceJobState:
        try:
            return next(item for item in self.jobs if item.job_id == job_id)
        except StopIteration:
            raise ReferenceRecoveryError("reference-job-state-missing") from None


@dataclass(frozen=True, slots=True)
class ReferenceHumanApproval:
    decision: ApprovalDecision
    approver_issuer: str | None
    approver_subject: str | None
    approver_audience: str
    identity_verified: bool
    identity_assurance: IdentityAssurance
    approval_gesture: Literal["explicit-phrase-and-nonce"] | None
    approval_nonce: str
    issued_at: str
    expires_at: str
    action_intent_id: str
    action_intent_sha256: str
    reconciliation_id: str
    scenario_id: str
    incident_class: IncidentClass
    command: RecoveryCommand
    affected_job_ids: tuple[str, ...]
    state_generation: int
    state_sha256: str
    protected_state_sha256: str
    _trust_token: object = field(repr=False, compare=False)
    approval_id: str = field(init=False)
    approval_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        affected = tuple(sorted(set(self.affected_job_ids)))
        if (
            self.decision not in {"approved", "denied"}
            or not isinstance(self.identity_verified, bool)
            or any(
                _IDENTIFIER.fullmatch(value) is None
                for value in (
                    self.approver_audience,
                    self.approval_nonce,
                    self.scenario_id,
                    *affected,
                )
            )
            or (
                self.identity_verified is True
                and (
                    self.identity_assurance != "verified-identity"
                    or self.approval_gesture is not None
                    or not isinstance(self.approver_issuer, str)
                    or not self.approver_issuer
                    or len(self.approver_issuer) > 512
                    or any(
                        ord(character) < 32 or ord(character) == 127
                        for character in self.approver_issuer
                    )
                    or not isinstance(self.approver_subject, str)
                    or _IDENTIFIER.fullmatch(self.approver_subject) is None
                )
            )
            or (
                self.identity_verified is False
                and (
                    self.identity_assurance != "unverified-public-demo-gesture"
                    or self.approval_gesture != "explicit-phrase-and-nonce"
                    or self.approver_issuer is not None
                    or self.approver_subject is not None
                )
            )
            or _ACTION_ID.fullmatch(self.action_intent_id) is None
            or _RECONCILIATION_ID.fullmatch(self.reconciliation_id) is None
            or _DIGEST.fullmatch(self.action_intent_sha256) is None
            or _DIGEST.fullmatch(self.state_sha256) is None
            or _DIGEST.fullmatch(self.protected_state_sha256) is None
            or not affected
            or isinstance(self.state_generation, bool)
            or self.state_generation < 1
            or _SCENARIO_CLASS.get(self.scenario_id) is not self.incident_class
            or _CLASS_COMMAND[self.incident_class] != self.command
            or _parse_timestamp(self.expires_at) <= _parse_timestamp(self.issued_at)
            or _parse_timestamp(self.expires_at) - _parse_timestamp(self.issued_at)
            > _MAX_APPROVAL_TTL
        ):
            raise ReferenceRecoveryError("reference-approval-invalid")
        object.__setattr__(self, "affected_job_ids", affected)
        digest = _digest(self._body())
        object.__setattr__(self, "approval_sha256", digest)
        object.__setattr__(
            self,
            "approval_id",
            f"reference-approval:{digest.removeprefix('sha256:')}",
        )
        validate_schema("reference-human-approval-v3.schema.json", self.to_dict())

    def _body(self) -> dict[str, Any]:
        approver: dict[str, Any] = {
            "audience": self.approver_audience,
            "kind": "human",
            "identity_verified": self.identity_verified,
            "identity_assurance": self.identity_assurance,
        }
        if self.identity_verified:
            approver["identity"] = {
                "issuer": self.approver_issuer,
                "subject": self.approver_subject,
            }
        else:
            approver["gesture"] = self.approval_gesture
        return {
            "schema": REFERENCE_HUMAN_APPROVAL_VERSION,
            "decision": self.decision,
            "approver": approver,
            "approval_nonce": self.approval_nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "action_intent_id": self.action_intent_id,
            "action_intent_sha256": self.action_intent_sha256,
            "reconciliation_id": self.reconciliation_id,
            "scenario_id": self.scenario_id,
            "incident_class": self.incident_class.value,
            "command": self.command,
            "affected_job_ids": list(self.affected_job_ids),
            "state_generation": self.state_generation,
            "state_sha256": self.state_sha256,
            "protected_state_sha256": self.protected_state_sha256,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "approval_id": self.approval_id,
            "approval_sha256": self.approval_sha256,
        }


class ReferenceHumanApprovalBoundary:
    def __init__(
        self,
        *,
        audience: str,
        clock: Callable[[], datetime],
    ) -> None:
        self._audience = _require_identifier(audience, "reference-approval-audience-invalid")
        self._clock = clock
        self._trust_token = object()
        self._lock = threading.RLock()
        self._issued: dict[str, bytes] = {}

    def issue(
        self,
        action_intent: ActionIntent | Mapping[str, Any],
        state: ReferenceRecoveryState,
        *,
        actor: Mapping[str, Any],
        identity_verified: bool,
        decision: ApprovalDecision,
        approval_nonce: str,
        ttl: timedelta = timedelta(minutes=5),
    ) -> ReferenceHumanApproval:
        intent = validate_reference_action_intent(action_intent)
        if (
            identity_verified is not True
            or set(actor) != {"issuer", "subject", "audience", "kind"}
            or actor.get("kind") != "human"
            or actor.get("audience") != self._audience
            or not isinstance(ttl, timedelta)
            or ttl <= timedelta(0)
            or ttl > _MAX_APPROVAL_TTL
            or state.incident_class is not intent.incident_class
            or tuple(intent.affected_job_ids) != state.affected_job_ids
        ):
            raise ReferenceRecoveryError("reference-approval-authority-invalid")
        issuer = actor.get("issuer")
        subject = actor.get("subject")
        if not isinstance(issuer, str) or not isinstance(subject, str):
            raise ReferenceRecoveryError("reference-approval-authority-invalid")
        issued_raw = self._clock()
        if issued_raw.tzinfo is None:
            raise ReferenceRecoveryError("reference-approval-time-invalid")
        issued = issued_raw.astimezone(UTC)
        approval = ReferenceHumanApproval(
            decision=decision,
            approver_issuer=issuer,
            approver_subject=subject,
            approver_audience=self._audience,
            identity_verified=True,
            identity_assurance="verified-identity",
            approval_gesture=None,
            approval_nonce=approval_nonce,
            issued_at=_timestamp(issued),
            expires_at=_timestamp(issued + ttl),
            action_intent_id=intent.action_intent_id,
            action_intent_sha256=intent.derivation_sha256,
            reconciliation_id=intent.reconciliation_id,
            scenario_id=state.scenario_id,
            incident_class=intent.incident_class,
            command=intent.command,
            affected_job_ids=intent.affected_job_ids,
            state_generation=state.generation,
            state_sha256=state.state_sha256,
            protected_state_sha256=state.protected_state_sha256,
            _trust_token=self._trust_token,
        )
        document = canonical_json_bytes(approval.to_dict())
        with self._lock:
            previous = self._issued.get(approval.approval_id)
            if previous is not None and previous != document:
                raise ReferenceRecoveryError("reference-approval-id-conflict")
            self._issued[approval.approval_id] = document
        return approval

    def issue_public_demo_gesture(
        self,
        action_intent: ActionIntent | Mapping[str, Any],
        state: ReferenceRecoveryState,
        *,
        decision: ApprovalDecision,
        approval_nonce: str,
        approval_phrase: str,
        ttl: timedelta = timedelta(minutes=5),
    ) -> ReferenceHumanApproval:
        expected_phrase = (
            REFERENCE_PUBLIC_APPROVAL_PHRASE
            if decision == "approved"
            else REFERENCE_PUBLIC_DENIAL_PHRASE
        )
        intent = validate_reference_action_intent(action_intent)
        if (
            decision not in {"approved", "denied"}
            or not isinstance(approval_phrase, str)
            or not hmac.compare_digest(approval_phrase, expected_phrase)
            or not isinstance(ttl, timedelta)
            or ttl <= timedelta(0)
            or ttl > _MAX_APPROVAL_TTL
            or state.incident_class is not intent.incident_class
            or tuple(intent.affected_job_ids) != state.affected_job_ids
        ):
            raise ReferenceRecoveryError("reference-approval-gesture-invalid")
        issued_raw = self._clock()
        if issued_raw.tzinfo is None:
            raise ReferenceRecoveryError("reference-approval-time-invalid")
        issued = issued_raw.astimezone(UTC)
        approval = ReferenceHumanApproval(
            decision=decision,
            approver_issuer=None,
            approver_subject=None,
            approver_audience=self._audience,
            identity_verified=False,
            identity_assurance="unverified-public-demo-gesture",
            approval_gesture="explicit-phrase-and-nonce",
            approval_nonce=approval_nonce,
            issued_at=_timestamp(issued),
            expires_at=_timestamp(issued + ttl),
            action_intent_id=intent.action_intent_id,
            action_intent_sha256=intent.derivation_sha256,
            reconciliation_id=intent.reconciliation_id,
            scenario_id=state.scenario_id,
            incident_class=intent.incident_class,
            command=intent.command,
            affected_job_ids=intent.affected_job_ids,
            state_generation=state.generation,
            state_sha256=state.state_sha256,
            protected_state_sha256=state.protected_state_sha256,
            _trust_token=self._trust_token,
        )
        document = canonical_json_bytes(approval.to_dict())
        with self._lock:
            previous = self._issued.get(approval.approval_id)
            if previous is not None and previous != document:
                raise ReferenceRecoveryError("reference-approval-id-conflict")
            self._issued[approval.approval_id] = document
        return approval

    def assert_issued(
        self,
        approval: ReferenceHumanApproval,
        action_intent: ActionIntent,
    ) -> None:
        if (
            not isinstance(approval, ReferenceHumanApproval)
            or approval._trust_token is not self._trust_token
            or _APPROVAL_ID.fullmatch(approval.approval_id) is None
        ):
            raise ReferenceRecoveryError("reference-approval-untrusted")
        document = canonical_json_bytes(approval.to_dict())
        with self._lock:
            if self._issued.get(approval.approval_id) != document:
                raise ReferenceRecoveryError("reference-approval-untrusted")
        if (
            approval.action_intent_id != action_intent.action_intent_id
            or approval.action_intent_sha256 != action_intent.derivation_sha256
            or approval.reconciliation_id != action_intent.reconciliation_id
            or approval.incident_class is not action_intent.incident_class
            or approval.command != action_intent.command
            or approval.affected_job_ids != action_intent.affected_job_ids
        ):
            raise ReferenceRecoveryError("reference-approval-intent-mismatch")

    def assert_current(
        self,
        approval: ReferenceHumanApproval,
        action_intent: ActionIntent,
        state: ReferenceRecoveryState,
    ) -> None:
        self.assert_issued(approval, action_intent)
        now_raw = self._clock()
        if now_raw.tzinfo is None:
            raise ReferenceRecoveryError("reference-approval-time-invalid")
        now = now_raw.astimezone(UTC)
        if approval.decision != "approved":
            raise ReferenceRecoveryError("reference-approval-denied")
        if now < _parse_timestamp(approval.issued_at) or now >= _parse_timestamp(
            approval.expires_at
        ):
            raise ReferenceRecoveryError("reference-approval-stale")
        if (
            approval.scenario_id != state.scenario_id
            or approval.state_generation != state.generation
            or approval.state_sha256 != state.state_sha256
            or approval.protected_state_sha256 != state.protected_state_sha256
            or approval.affected_job_ids != state.affected_job_ids
        ):
            raise ReferenceRecoveryError("reference-approval-state-mismatch")


def _frame_sha256(job: ReferenceJobState) -> str:
    return _digest(
        {
            "schema": "reference-frame-state-derivation/v3",
            "job_id": job.job_id,
            "effective_resource_sha256": job.effective_resource_sha256,
            "effective_config_sha256": job.effective_config_sha256,
            "config_generation": job.config_generation,
        }
    )


def _derivative_sha256(job: ReferenceJobState) -> str:
    return _digest(
        {
            "schema": "reference-derivative-state-derivation/v3",
            "job_id": job.job_id,
            "frame_sha256": job.frame_sha256,
            "derivative_parent_sha256": job.derivative_parent_sha256,
            "derivative_generation": job.derivative_generation,
            "cache_key": job.cache_key,
        }
    )


def _repair_job(job: ReferenceJobState, intent: ActionIntent) -> ReferenceJobState:
    parameters = intent.parameters
    expected = cast(Mapping[str, Any], parameters["expected"])
    observed = cast(Mapping[str, Any], parameters["observed"])
    if intent.incident_class is IncidentClass.RESOURCE_RESOLUTION_DRIFT:
        if job.effective_resource_sha256 != observed["effective_resource_sha256"]:
            raise ReferenceRecoveryError("reference-action-precondition-mismatch")
        updated = replace(
            job,
            effective_resource_sha256=cast(str, expected["effective_resource_sha256"]),
        )
        frame_sha256 = _frame_sha256(updated)
        updated = replace(
            updated,
            frame_sha256=frame_sha256,
            derivative_parent_sha256=frame_sha256,
        )
        return replace(updated, derivative_sha256=_derivative_sha256(updated))
    if intent.incident_class is IncidentClass.CONFIGURATION_ROLLOUT_DRIFT:
        if (
            job.effective_config_sha256 != observed["effective_config_sha256"]
            or job.config_generation != observed["config_generation"]
        ):
            raise ReferenceRecoveryError("reference-action-precondition-mismatch")
        updated = replace(
            job,
            effective_config_sha256=cast(str, expected["effective_config_sha256"]),
            config_generation=cast(int, expected["config_generation"]),
        )
        frame_sha256 = _frame_sha256(updated)
        updated = replace(
            updated,
            frame_sha256=frame_sha256,
            derivative_parent_sha256=frame_sha256,
        )
        return replace(updated, derivative_sha256=_derivative_sha256(updated))
    if intent.incident_class is IncidentClass.STALE_DERIVATIVE_CACHE:
        if (
            job.derivative_parent_sha256 != observed["derivative_parent_sha256"]
            or job.derivative_generation != observed["derivative_generation"]
            or job.cache_key != parameters["cache_key"]
        ):
            raise ReferenceRecoveryError("reference-action-precondition-mismatch")
        updated = replace(
            job,
            derivative_parent_sha256=cast(str, expected["derivative_parent_sha256"]),
            derivative_generation=cast(int, expected["derivative_generation"]),
        )
        return replace(updated, derivative_sha256=_derivative_sha256(updated))
    raise ReferenceRecoveryError("reference-action-command-denied")


def _apply_recovery(
    state: ReferenceRecoveryState,
    intent: ActionIntent,
) -> ReferenceRecoveryState:
    if (
        state.incident_class is not intent.incident_class
        or _CLASS_COMMAND[state.incident_class] != intent.command
        or tuple(intent.affected_job_ids) != state.affected_job_ids
        or intent.target != "simulator"
        or intent.requires_human_approval is not True
        or intent.authorizes_execution is not False
    ):
        raise ReferenceRecoveryError("reference-action-scope-mismatch")
    affected = set(state.affected_job_ids)
    repaired = tuple(
        _repair_job(job, intent) if job.job_id in affected else job for job in state.jobs
    )
    return ReferenceRecoveryState(
        scenario_id=state.scenario_id,
        incident_class=state.incident_class,
        generation=state.generation + 1,
        affected_job_ids=state.affected_job_ids,
        protected_job_ids=state.protected_job_ids,
        jobs=repaired,
    )


def _receipt_state_reference(state: ReferenceRecoveryState) -> dict[str, Any]:
    return {
        "generation": state.generation,
        "state_sha256": state.state_sha256,
        "protected_state_sha256": state.protected_state_sha256,
    }


def _recovery_verification(
    *,
    intent: ActionIntent,
    before: ReferenceRecoveryState,
    after: ReferenceRecoveryState,
    receipt_before: Mapping[str, Any],
    receipt_after: Mapping[str, Any],
) -> dict[str, Any]:
    expected_fields = _CLASS_EXPECTED_FIELDS[intent.incident_class]
    expected = cast(Mapping[str, str | int], intent.parameters["expected"])
    expected_before = {
        "generation": before.generation,
        "state_sha256": before.state_sha256,
        "protected_state_sha256": before.protected_state_sha256,
    }
    expected_after = {
        "generation": after.generation,
        "state_sha256": after.state_sha256,
        "protected_state_sha256": after.protected_state_sha256,
    }
    generation_advanced = after.generation == before.generation + 1
    affected_match = all(
        getattr(after.job(job_id), field) == expected[field]
        for job_id in after.affected_job_ids
        for field in expected_fields
    )
    protected_unchanged = after.protected_state_sha256 == before.protected_state_sha256
    receipt_bindings_match = (
        dict(receipt_before) == expected_before and dict(receipt_after) == expected_after
    )
    if (
        before.scenario_id != after.scenario_id
        or before.incident_class is not after.incident_class
        or after.incident_class is not intent.incident_class
        or before.affected_job_ids != after.affected_job_ids
        or after.affected_job_ids != tuple(intent.affected_job_ids)
        or not generation_advanced
        or not affected_match
        or not protected_unchanged
        or not receipt_bindings_match
    ):
        raise ReferenceRecoveryError("reference-recovery-verification-failed")
    body = {
        "schema": REFERENCE_RECOVERY_VERIFICATION_VERSION,
        "verifier": "deterministic-simulator-state",
        "result": "verified",
        "scenario_id": after.scenario_id,
        "incident_class": after.incident_class.value,
        "action_intent_id": intent.action_intent_id,
        "action_intent_sha256": intent.derivation_sha256,
        "reconciliation_id": intent.reconciliation_id,
        "before": dict(receipt_before),
        "after": dict(receipt_after),
        "affected_job_ids": list(after.affected_job_ids),
        "affected_expected_field_checks": [
            {
                "field": field,
                "expected_value": expected[field],
                "matched_job_ids": list(after.affected_job_ids),
            }
            for field in expected_fields
        ],
        "checks": {
            "generation_advanced_exactly_once": True,
            "all_affected_expected_fields_match": True,
            "protected_state_unchanged": True,
            "receipt_state_bindings_match": True,
        },
        "establishes_pixel_output": False,
        "establishes_full_population_scope": False,
        "production_evidence": False,
    }
    verification = {**body, "verification_sha256": _digest(body)}
    return validate_reference_recovery_verification(verification)


def _recovery_receipt(
    *,
    approval: ReferenceHumanApproval,
    intent: ActionIntent,
    before: ReferenceRecoveryState,
    after: ReferenceRecoveryState,
) -> dict[str, Any]:
    before_reference = _receipt_state_reference(before)
    after_reference = _receipt_state_reference(after)
    verification = _recovery_verification(
        intent=intent,
        before=before,
        after=after,
        receipt_before=before_reference,
        receipt_after=after_reference,
    )
    changed_components = (
        ["derivative"]
        if intent.incident_class is IncidentClass.STALE_DERIVATIVE_CACHE
        else ["frame", "derivative"]
    )
    mutations = [
        {
            "job_id": job_id,
            "before_job_state_sha256": before.job(job_id).job_state_sha256,
            "after_job_state_sha256": after.job(job_id).job_state_sha256,
            "changed_components": changed_components,
        }
        for job_id in before.affected_job_ids
    ]
    body = {
        "schema": REFERENCE_RECOVERY_RECEIPT_VERSION,
        "approval_id": approval.approval_id,
        "approval_sha256": approval.approval_sha256,
        "action_intent_id": intent.action_intent_id,
        "action_intent_sha256": intent.derivation_sha256,
        "reconciliation_id": intent.reconciliation_id,
        "scenario_id": before.scenario_id,
        "incident_class": intent.incident_class.value,
        "command": intent.command,
        "before": before_reference,
        "after": after_reference,
        "affected_job_ids": list(before.affected_job_ids),
        "protected_job_ids": list(before.protected_job_ids),
        "mutations": mutations,
        "protected_state_unchanged": (
            before.protected_state_sha256 == after.protected_state_sha256
        ),
        "action_intent_requires_human_approval": True,
        "action_intent_authorizes_execution": False,
        "verification": verification,
        "result": "applied",
    }
    digest = _digest(body)
    receipt = {
        **body,
        "receipt_id": f"reference-recovery:{digest.removeprefix('sha256:')}",
        "receipt_sha256": digest,
    }
    validate_schema("reference-recovery-receipt-v3.schema.json", receipt)
    return receipt


class ReferenceRecoveryService:
    def __init__(
        self,
        *,
        states: Sequence[ReferenceRecoveryState],
        approval_boundary: ReferenceHumanApprovalBoundary,
    ) -> None:
        state_by_scenario = {state.scenario_id: state for state in states}
        if not states or len(state_by_scenario) != len(states):
            raise ReferenceRecoveryError("reference-recovery-state-set-invalid")
        self._states = state_by_scenario
        self._approval_boundary = approval_boundary
        self._receipts: dict[str, tuple[str, str, Mapping[str, Any]]] = {}
        self._lock = threading.RLock()

    def snapshot(self, scenario_id: str) -> ReferenceRecoveryState:
        with self._lock:
            try:
                return self._states[scenario_id]
            except KeyError:
                raise ReferenceRecoveryError("reference-recovery-scenario-unknown") from None

    def execute(
        self,
        action_intent: ActionIntent | Mapping[str, Any],
        approval: ReferenceHumanApproval,
    ) -> dict[str, Any]:
        intent = validate_reference_action_intent(action_intent)
        self._approval_boundary.assert_issued(approval, intent)
        if approval.decision != "approved":
            raise ReferenceRecoveryError("reference-approval-denied")
        with self._lock:
            replay = self._receipts.get(approval.approval_id)
            if replay is not None:
                approval_sha256, intent_sha256, receipt = replay
                if (
                    approval_sha256 != approval.approval_sha256
                    or intent_sha256 != intent.derivation_sha256
                ):
                    raise ReferenceRecoveryError("reference-recovery-replay-conflict")
                return cast(dict[str, Any], _plain(receipt))
            try:
                state = self._states[approval.scenario_id]
            except KeyError:
                raise ReferenceRecoveryError("reference-recovery-scenario-unknown") from None
            self._approval_boundary.assert_current(approval, intent, state)
            after = _apply_recovery(state, intent)
            if after.protected_state_sha256 != state.protected_state_sha256:
                raise ReferenceRecoveryError("reference-protected-state-changed")
            receipt = _recovery_receipt(
                approval=approval,
                intent=intent,
                before=state,
                after=after,
            )
            stored = cast(Mapping[str, Any], MappingProxyType(receipt))
            self._states[state.scenario_id] = after
            self._receipts[approval.approval_id] = (
                approval.approval_sha256,
                intent.derivation_sha256,
                stored,
            )
            return cast(dict[str, Any], _plain(stored))


__all__ = [
    "ApprovalDecision",
    "REFERENCE_HUMAN_APPROVAL_VERSION",
    "REFERENCE_PUBLIC_APPROVAL_PHRASE",
    "REFERENCE_PUBLIC_DENIAL_PHRASE",
    "REFERENCE_RECOVERY_RECEIPT_VERSION",
    "REFERENCE_RECOVERY_STATE_VERSION",
    "REFERENCE_RECOVERY_VERIFICATION_VERSION",
    "RecoveryCommand",
    "ReferenceHumanApproval",
    "ReferenceHumanApprovalBoundary",
    "ReferenceJobState",
    "ReferenceRecoveryError",
    "ReferenceRecoveryService",
    "ReferenceRecoveryState",
    "validate_reference_action_intent",
    "validate_reference_recovery_verification",
]
