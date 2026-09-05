from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, cast

from colortrace_response_plans import (
    ResponsePlanError,
    validate_audit_chain,
    validate_decision,
    validate_dispatch_authorization,
    validate_dispatch_consumption,
    validate_plan,
)
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)

from .models import BoundSimulatorAction, DispatchIdentity, StoredDispatchProof

SCHEMA_ROOT = Path(__file__).parent / "schemas"
SIMULATOR_NAMESPACE = "colortrace-simulator"
SIMULATOR_EXECUTOR_ROLE = "simulator.executor"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}")
_TASK_KEY = re.compile(r"dispatch-task:[0-9a-f]{64}")
_OPERATION_ID = re.compile(r"dispatch-operation:[0-9a-f]{64}")
_SCHEMA_FILES = (
    "simulator-dispatch-bundle-v1.schema.json",
    "simulator-action-admission-v1.schema.json",
    "simulator-action-claim-event-v1.schema.json",
    "simulator-publication-intent-v1.schema.json",
    "simulator-publication-receipt-v1.schema.json",
    "simulator-action-outcome-v1.schema.json",
    "simulator-action-audit-event-v1.schema.json",
    "reference-recovery-state-v3.schema.json",
    "reference-human-approval-v3.schema.json",
    "reference-recovery-receipt-v3.schema.json",
    "reference-recovery-verification-v1.schema.json",
)


class SimulatorAuthorityError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ExecutorAuthorization:
    incident_id: str
    issuer: str
    subject: str
    audience: str
    _trust_token: object = field(repr=False, compare=False)

    def actor(self) -> dict[str, str]:
        return {
            "issuer": self.issuer,
            "subject": self.subject,
            "audience": self.audience,
            "kind": "service",
        }


class SimulatorExecutorBoundary:
    def __init__(self) -> None:
        self._trust_token = object()

    @staticmethod
    def _actor_text(value: Any, *, maximum: int) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > maximum
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise SimulatorAuthorityError("executor-actor-invalid")
        return value

    def bind_verified_service(
        self,
        *,
        incident_id: str,
        actor: Mapping[str, Any],
        roles: Sequence[str],
        incident_ids: Sequence[str],
        identity_verified: bool,
    ) -> ExecutorAuthorization:
        if identity_verified is not True:
            raise SimulatorAuthorityError("executor-identity-unverified")
        if (
            set(actor) != {"issuer", "subject", "audience", "kind"}
            or actor.get("kind") != "service"
        ):
            raise SimulatorAuthorityError("executor-service-required")
        if SIMULATOR_EXECUTOR_ROLE not in roles:
            raise SimulatorAuthorityError("executor-role-required")
        if not isinstance(incident_id, str) or _IDENTIFIER.fullmatch(incident_id) is None:
            raise SimulatorAuthorityError("executor-incident-invalid")
        if incident_id not in incident_ids:
            raise SimulatorAuthorityError("executor-incident-denied")
        return ExecutorAuthorization(
            incident_id=incident_id,
            issuer=self._actor_text(actor.get("issuer"), maximum=512),
            subject=self._actor_text(actor.get("subject"), maximum=255),
            audience=self._actor_text(actor.get("audience"), maximum=255),
            _trust_token=self._trust_token,
        )

    def assert_authorized(
        self,
        authorization: ExecutorAuthorization,
        *,
        incident_id: str,
    ) -> dict[str, str]:
        if (
            not isinstance(authorization, ExecutorAuthorization)
            or authorization._trust_token is not self._trust_token
            or authorization.incident_id != incident_id
        ):
            raise SimulatorAuthorityError("executor-authority-boundary-mismatch")
        return authorization.actor()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonfinite(token: str) -> None:
    raise ValueError(f"non-finite JSON value: {token}")


def strict_json_bytes(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=lambda _: (_ for _ in ()).throw(ValueError("floating-point value")),
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SimulatorAuthorityError("malformed-json") from error


def canonical_json_bytes(value: Any) -> bytes:
    def normalize(item: Any) -> Any:
        if isinstance(item, float):
            raise TypeError("floating-point values are not canonical")
        if isinstance(item, Mapping):
            result: dict[str, Any] = {}
            for key, child in item.items():
                if not isinstance(key, str):
                    raise TypeError("canonical object keys must be strings")
                result[key] = normalize(child)
            return result
        if isinstance(item, (list, tuple)):
            return [normalize(child) for child in item]
        if item is None or isinstance(item, (str, int, bool)):
            return item
        raise TypeError("value is not canonical JSON")

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def plain_json(value: Any) -> Any:
    return strict_json_bytes(canonical_json_bytes(value))


def prefixed_sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def require_digest(value: Any, *, code: str = "digest-invalid") -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise SimulatorAuthorityError(code)
    return value


def require_identity(value: DispatchIdentity) -> DispatchIdentity:
    if not isinstance(value, DispatchIdentity):
        raise SimulatorAuthorityError("dispatch-identity-invalid")
    if _TASK_KEY.fullmatch(value.task_key) is None:
        raise SimulatorAuthorityError("dispatch-task-key-invalid")
    if _OPERATION_ID.fullmatch(value.operation_id) is None:
        raise SimulatorAuthorityError("dispatch-operation-id-invalid")
    require_digest(value.payload_sha256, code="dispatch-payload-invalid")
    return value


def stable_action_id(identity: DispatchIdentity) -> str:
    selected = require_identity(identity)
    body = {
        "schema": "simulator-action-identity/v1",
        "task_key": selected.task_key,
        "operation_id": selected.operation_id,
        "payload_sha256": selected.payload_sha256,
    }
    digest = prefixed_sha256(canonical_json_bytes(body)).removeprefix("sha256:")
    return f"simulator-action:{digest}"


@cache
def _schema_document(name: str) -> Mapping[str, Any]:
    if name not in _SCHEMA_FILES:
        raise SimulatorAuthorityError("schema-unknown")
    try:
        value = strict_json_bytes((SCHEMA_ROOT / name).read_bytes())
    except OSError as error:
        raise SimulatorAuthorityError("schema-unavailable") from error
    if not isinstance(value, dict):
        raise SimulatorAuthorityError("schema-invalid")
    Draft202012Validator.check_schema(value)
    return cast(Mapping[str, Any], value)


@cache
def _schema_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(_schema_document(name), format_checker=FormatChecker())


def validate_schema(name: str, value: Mapping[str, Any]) -> None:
    try:
        _schema_validator(name).validate(dict(value))
    except ValidationError as error:
        raise SimulatorAuthorityError("schema-validation") from error


@dataclass(frozen=True, slots=True)
class ValidatedDispatchBundle:
    action: BoundSimulatorAction
    document: Mapping[str, Any]


def _source_event(
    events: Sequence[Mapping[str, Any]], *, event_type: str, record_sha256: str
) -> Mapping[str, Any]:
    selected = [
        event
        for event in events
        if event.get("event_type") == event_type and event.get("record_sha256") == record_sha256
    ]
    if len(selected) != 1:
        raise SimulatorAuthorityError("dispatch-source-event-invalid")
    return selected[0]


class SimulatorAuthorityBoundary:
    """Binds only a current, consumed #22 dispatch to the simulator namespace."""

    def bind(
        self,
        identity: DispatchIdentity,
        proof: StoredDispatchProof,
    ) -> ValidatedDispatchBundle:
        selected = require_identity(identity)
        try:
            plan = cast(dict[str, Any], plain_json(proof.plan))
            approval = cast(dict[str, Any], plain_json(proof.approval))
            authorization = cast(dict[str, Any], plain_json(proof.authorization))
            consumption = cast(dict[str, Any], plain_json(proof.consumption))
            events = cast(list[dict[str, Any]], plain_json(proof.audit_events))
            records = cast(dict[str, dict[str, Any]], plain_json(proof.records))
            trusted_head = require_digest(
                proof.trusted_audit_head_sha256,
                code="dispatch-source-head-invalid",
            )
            validate_plan(plan)
            validate_decision(approval, plan=plan)
            validate_dispatch_authorization(authorization, plan=plan, approval=approval)
            validate_dispatch_consumption(
                consumption,
                authorization=authorization,
                plan=plan,
                approval=approval,
            )
            validate_audit_chain(events, trusted_head_sha256=trusted_head, records=records)
        except (ResponsePlanError, TypeError, ValueError) as error:
            raise SimulatorAuthorityError("dispatch-proof-invalid") from error

        expected_identity = (
            authorization.get("task_key"),
            authorization.get("operation_id"),
            authorization.get("payload_sha256"),
        )
        if expected_identity != (
            selected.task_key,
            selected.operation_id,
            selected.payload_sha256,
        ) or any(
            consumption.get(key) != authorization.get(key)
            for key in ("task_key", "operation_id", "payload_sha256")
        ):
            raise SimulatorAuthorityError("dispatch-identity-conflict")
        if approval.get("outcome") != "approved":
            raise SimulatorAuthorityError("dispatch-not-approved")
        if authorization.get("authorized_role") != "response-plan.dispatcher":
            raise SimulatorAuthorityError("dispatch-role-invalid")
        commands = cast(list[dict[str, Any]], authorization.get("commands"))
        if not commands or any(
            command.get("namespace") != SIMULATOR_NAMESPACE for command in commands
        ):
            raise SimulatorAuthorityError("dispatch-namespace-invalid")
        targets = cast(list[dict[str, Any]], authorization["targets"])
        exclusions = cast(list[dict[str, Any]], authorization["exclusions"])
        target_profile = Counter(str(target.get("kind")) for target in targets)
        if (
            len(commands) != 5
            or len(targets) != 5
            or target_profile != {"color-resource": 1, "frame": 3, "derivative": 1}
            or not exclusions
            or any(target.get("kind") != "frame" for target in exclusions)
        ):
            raise SimulatorAuthorityError("dispatch-profile-invalid")

        plan_events = [
            event for event in events if event.get("event_type") in {"plan.created", "plan.edited"}
        ]
        if not plan_events:
            raise SimulatorAuthorityError("dispatch-current-plan-invalid")
        latest_plan = plan_events[-1]
        if (
            latest_plan.get("plan_version") != plan.get("version")
            or latest_plan.get("plan_sha256") != plan.get("plan_sha256")
            or latest_plan.get("record_sha256") != plan.get("plan_sha256")
        ):
            raise SimulatorAuthorityError("dispatch-current-plan-invalid")

        approval_event = _source_event(
            events,
            event_type="plan.approved",
            record_sha256=cast(str, approval["decision_sha256"]),
        )
        authorization_event = _source_event(
            events,
            event_type="dispatch.authorized",
            record_sha256=cast(str, authorization["authorization_sha256"]),
        )
        consumption_event = _source_event(
            events,
            event_type="dispatch.consumed",
            record_sha256=cast(str, consumption["consumption_sha256"]),
        )
        if not (
            cast(int, approval_event["sequence"])
            < cast(int, authorization_event["sequence"])
            < cast(int, consumption_event["sequence"])
        ):
            raise SimulatorAuthorityError("dispatch-source-order-invalid")

        command_envelopes = {
            canonical_json_bytes(cast(Mapping[str, Any], command["action_envelope"]))
            for command in commands
        }
        if len(command_envelopes) != 1:
            raise SimulatorAuthorityError("dispatch-envelope-invalid")
        envelope_sha256 = prefixed_sha256(next(iter(command_envelopes)))
        commands_sha256 = prefixed_sha256(canonical_json_bytes(commands))
        targets_sha256 = prefixed_sha256(canonical_json_bytes(targets))
        exclusions_sha256 = prefixed_sha256(canonical_json_bytes(exclusions))
        action_id = stable_action_id(selected)
        bundle_body = {
            "schema": "simulator-dispatch-bundle/v1",
            "action_id": action_id,
            "identity": {
                "task_key": selected.task_key,
                "operation_id": selected.operation_id,
                "payload_sha256": selected.payload_sha256,
            },
            "plan": plan,
            "approval": approval,
            "authorization": authorization,
            "consumption": consumption,
            "source_dispatch_consumed_event": consumption_event,
            "source_audit_head_sha256": trusted_head,
            "action_envelope_sha256": envelope_sha256,
            "commands_sha256": commands_sha256,
            "targets_sha256": targets_sha256,
            "exclusions_sha256": exclusions_sha256,
        }
        bundle_sha256 = prefixed_sha256(canonical_json_bytes(bundle_body))
        document = {**bundle_body, "bundle_sha256": bundle_sha256}
        validate_schema("simulator-dispatch-bundle-v1.schema.json", document)
        action = BoundSimulatorAction(
            action_id=action_id,
            identity=selected,
            incident_id=cast(str, plan["incident_id"]),
            incident_version=cast(int, plan["incident_version"]),
            plan_id=cast(str, plan["plan_id"]),
            plan_version=cast(int, plan["version"]),
            plan_sha256=cast(str, plan["plan_sha256"]),
            approval_id=cast(str, approval["decision_id"]),
            approval_sha256=cast(str, approval["decision_sha256"]),
            authorization_id=cast(str, authorization["authorization_id"]),
            authorization_sha256=cast(str, authorization["authorization_sha256"]),
            consumption_id=cast(str, consumption["consumption_id"]),
            consumption_sha256=cast(str, consumption["consumption_sha256"]),
            action_envelope_sha256=envelope_sha256,
            commands_sha256=commands_sha256,
            targets_sha256=targets_sha256,
            exclusions_sha256=exclusions_sha256,
            commands=tuple(commands),
            targets=tuple(targets),
            exclusions=tuple(exclusions),
            dispatch_bundle_sha256=bundle_sha256,
        )
        return ValidatedDispatchBundle(action=action, document=document)


def action_from_bundle(document: Mapping[str, Any]) -> BoundSimulatorAction:
    bundle = cast(dict[str, Any], plain_json(document))
    validate_schema("simulator-dispatch-bundle-v1.schema.json", bundle)
    body = {key: child for key, child in bundle.items() if key != "bundle_sha256"}
    if bundle["bundle_sha256"] != prefixed_sha256(canonical_json_bytes(body)):
        raise SimulatorAuthorityError("dispatch-bundle-digest")
    identity_value = cast(Mapping[str, Any], bundle["identity"])
    identity = DispatchIdentity(
        task_key=cast(str, identity_value["task_key"]),
        operation_id=cast(str, identity_value["operation_id"]),
        payload_sha256=cast(str, identity_value["payload_sha256"]),
    )
    authorization = cast(Mapping[str, Any], bundle["authorization"])
    approval = cast(Mapping[str, Any], bundle["approval"])
    consumption = cast(Mapping[str, Any], bundle["consumption"])
    plan = cast(Mapping[str, Any], bundle["plan"])
    if stable_action_id(identity) != bundle["action_id"]:
        raise SimulatorAuthorityError("dispatch-action-binding")
    return BoundSimulatorAction(
        action_id=cast(str, bundle["action_id"]),
        identity=identity,
        incident_id=cast(str, plan["incident_id"]),
        incident_version=cast(int, plan["incident_version"]),
        plan_id=cast(str, plan["plan_id"]),
        plan_version=cast(int, plan["version"]),
        plan_sha256=cast(str, plan["plan_sha256"]),
        approval_id=cast(str, approval["decision_id"]),
        approval_sha256=cast(str, approval["decision_sha256"]),
        authorization_id=cast(str, authorization["authorization_id"]),
        authorization_sha256=cast(str, authorization["authorization_sha256"]),
        consumption_id=cast(str, consumption["consumption_id"]),
        consumption_sha256=cast(str, consumption["consumption_sha256"]),
        action_envelope_sha256=cast(str, bundle["action_envelope_sha256"]),
        commands_sha256=cast(str, bundle["commands_sha256"]),
        targets_sha256=cast(str, bundle["targets_sha256"]),
        exclusions_sha256=cast(str, bundle["exclusions_sha256"]),
        commands=tuple(cast(Sequence[Mapping[str, Any]], authorization["commands"])),
        targets=tuple(cast(Sequence[Mapping[str, Any]], authorization["targets"])),
        exclusions=tuple(cast(Sequence[Mapping[str, Any]], authorization["exclusions"])),
        dispatch_bundle_sha256=cast(str, bundle["bundle_sha256"]),
    )


__all__ = [
    "ExecutorAuthorization",
    "SIMULATOR_EXECUTOR_ROLE",
    "SimulatorAuthorityBoundary",
    "SimulatorAuthorityError",
    "SimulatorExecutorBoundary",
    "ValidatedDispatchBundle",
    "action_from_bundle",
    "canonical_json_bytes",
    "plain_json",
    "prefixed_sha256",
    "require_digest",
    "stable_action_id",
    "strict_json_bytes",
    "validate_schema",
]
