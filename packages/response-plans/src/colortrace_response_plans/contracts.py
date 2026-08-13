from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, cast

from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)
from referencing import Registry, Resource

SCHEMA_ROOT = Path(__file__).parent / "schemas"
EDITOR_ROLE = "response-plan.editor"
APPROVER_ROLE = "response-plan.approver"
DISPATCHER_ROLE = "response-plan.dispatcher"
DISPATCH_POLICY = "response-plan-dispatch-policy/v1"
SIMULATOR_NAMESPACE = "colortrace-simulator"
TARGET_KINDS = frozenset({"color-resource", "frame", "derivative"})
REJECTION_CODES = frozenset(
    {"unsafe-scope", "insufficient-evidence", "incorrect-command", "unresolved-risk"}
)
AUDIT_EVENT_TYPES = (
    "plan.created",
    "plan.edited",
    "plan.approved",
    "plan.rejected",
    "dispatch.authorized",
    "dispatch.consumed",
)
_SCHEMA_FILES = (
    "simulator-command-v1.schema.json",
    "response-plan-v1.schema.json",
    "response-plan-decision-v1.schema.json",
    "response-plan-dispatch-authorization-v1.schema.json",
    "response-plan-dispatch-consumption-v1.schema.json",
    "response-plan-audit-event-v1.schema.json",
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class ResponsePlanError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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
        raise ResponsePlanError("malformed-json") from error


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


def timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ResponsePlanError("invalid-time")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _safe_text(value: Any, *, code: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ResponsePlanError(code)
    return value


def require_identifier(value: Any, *, code: str = "identifier-invalid") -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ResponsePlanError(code)
    return value


def require_digest(value: Any, *, code: str = "digest-invalid") -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ResponsePlanError(code)
    return value


def require_idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or _IDEMPOTENCY_KEY.fullmatch(value) is None:
        raise ResponsePlanError("idempotency-key-invalid")
    return value


@cache
def _schema_documents() -> Mapping[str, Mapping[str, Any]]:
    documents: dict[str, Mapping[str, Any]] = {}
    for name in _SCHEMA_FILES:
        try:
            value = strict_json_bytes((SCHEMA_ROOT / name).read_bytes())
        except OSError as error:
            raise ResponsePlanError("schema-unavailable") from error
        if not isinstance(value, dict):
            raise ResponsePlanError("schema-invalid")
        Draft202012Validator.check_schema(value)
        documents[name] = value
    return documents


@cache
def _schema_registry() -> Registry[Any]:
    resources = [
        (cast(str, document["$id"]), Resource.from_contents(document))
        for document in _schema_documents().values()
    ]
    return Registry().with_resources(resources)


@cache
def _schema_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        _schema_documents()[name],
        registry=_schema_registry(),
        format_checker=FormatChecker(),
    )


def validate_schema(name: str, value: Mapping[str, Any]) -> None:
    try:
        _schema_validator(name).validate(dict(value))
    except ValidationError as error:
        raise ResponsePlanError("schema-validation") from error


def _normalize_actor(value: Mapping[str, Any], *, kinds: frozenset[str]) -> dict[str, str]:
    actor = cast(dict[str, Any], plain_json(value))
    if set(actor) != {"issuer", "subject", "audience", "kind"}:
        raise ResponsePlanError("actor-invalid")
    kind = actor.get("kind")
    if kind not in kinds:
        raise ResponsePlanError("actor-kind-invalid")
    return {
        "issuer": _safe_text(actor.get("issuer"), code="actor-invalid", maximum=512),
        "subject": _safe_text(actor.get("subject"), code="actor-invalid", maximum=255),
        "audience": _safe_text(actor.get("audience"), code="actor-invalid", maximum=255),
        "kind": cast(str, kind),
    }


def normalize_target(value: Mapping[str, Any]) -> dict[str, str]:
    target = cast(dict[str, Any], plain_json(value))
    if set(target) != {"schema", "namespace", "kind", "id"}:
        raise ResponsePlanError("target-invalid")
    if target.get("schema") != "simulator-target/v1":
        raise ResponsePlanError("target-invalid")
    if target.get("namespace") != SIMULATOR_NAMESPACE:
        raise ResponsePlanError("production-target-forbidden")
    if target.get("kind") not in TARGET_KINDS:
        raise ResponsePlanError("target-kind-invalid")
    identifier = require_identifier(target.get("id"), code="target-id-invalid")
    return {
        "schema": "simulator-target/v1",
        "namespace": SIMULATOR_NAMESPACE,
        "kind": cast(str, target["kind"]),
        "id": identifier,
    }


def target_identity(value: Mapping[str, Any]) -> tuple[str, str, str]:
    target = normalize_target(value)
    return target["namespace"], target["kind"], target["id"]


def normalize_command(value: Mapping[str, Any]) -> dict[str, Any]:
    command = cast(dict[str, Any], plain_json(value))
    validate_schema("simulator-command-v1.schema.json", command)
    target = normalize_target(cast(Mapping[str, Any], command["target"]))
    schema = command.get("schema")
    if schema == "simulator-quarantine-command/v1":
        if target["kind"] != "color-resource":
            raise ResponsePlanError("quarantine-target-invalid")
        if target["id"] != command["expected_resource_sha256"]:
            raise ResponsePlanError("quarantine-resource-binding")
        envelope_resource = command["action_envelope"]["expected_resource_sha256"]
        if command["expected_resource_sha256"] != envelope_resource:
            raise ResponsePlanError("quarantine-resource-binding")
        if (
            command["expected_resource_sha256"]
            == command["action_envelope"]["replacement_resource_sha256"]
        ):
            raise ResponsePlanError("replacement-resource-unchanged")
    elif schema == "simulator-targeted-rerender-command/v1":
        if target["kind"] not in {"frame", "derivative"}:
            raise ResponsePlanError("rerender-target-invalid")
    else:  # pragma: no cover - schema validation rejects it
        raise ResponsePlanError("command-schema-invalid")
    command["command_id"] = require_identifier(command.get("command_id"), code="command-id-invalid")
    command["target"] = target
    return command


def _sorted_targets(values: Sequence[Mapping[str, Any]]) -> list[dict[str, str]]:
    targets = [normalize_target(value) for value in values]
    targets.sort(key=target_identity)
    identities = [target_identity(target) for target in targets]
    if len(identities) != len(set(identities)):
        raise ResponsePlanError("target-duplicate")
    return targets


def _sorted_commands(values: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    commands = [normalize_command(value) for value in values]
    commands.sort(key=lambda command: cast(str, command["command_id"]))
    identifiers = [cast(str, command["command_id"]) for command in commands]
    command_targets = [
        target_identity(cast(Mapping[str, Any], item["target"])) for item in commands
    ]
    if len(identifiers) != len(set(identifiers)):
        raise ResponsePlanError("command-id-duplicate")
    if len(command_targets) != len(set(command_targets)):
        raise ResponsePlanError("command-target-duplicate")
    if commands:
        envelopes = {canonical_json_bytes(command["action_envelope"]) for command in commands}
        if len(envelopes) != 1:
            raise ResponsePlanError("action-envelope-conflict")
        envelope = commands[0]["action_envelope"]
        generations = {
            envelope["fixture_generation"],
            envelope["runtime_generation"],
            envelope["expected_publication_generation"],
            envelope["lineage_generation"],
        }
        if len(generations) != 1:
            raise ResponsePlanError("action-generation-conflict")
    return commands


def stable_plan_id(incident_id: str) -> str:
    identity = {
        "schema": "response-plan-identity/v1",
        "incident_id": require_identifier(incident_id),
    }
    return (
        f"response-plan:{prefixed_sha256(canonical_json_bytes(identity)).removeprefix('sha256:')}"
    )


def build_plan(
    *,
    incident_id: str,
    incident_version: int,
    version: int,
    previous_plan_sha256: str | None,
    response_packet_id: str,
    response_packet_sha256: str,
    deterministic_scope_sha256: str,
    targets: Sequence[Mapping[str, Any]],
    exclusions: Sequence[Mapping[str, Any]],
    commands: Sequence[Mapping[str, Any]],
    unresolved_item_ids: Sequence[str],
    blocking_unresolved_item_ids: Sequence[str],
    unknown_target_ids: Sequence[str],
    unresolved_acknowledged: bool,
    created_by: Mapping[str, Any],
    created_at: str,
) -> dict[str, Any]:
    incident = require_identifier(incident_id)
    if (
        not isinstance(incident_version, int)
        or isinstance(incident_version, bool)
        or incident_version < 1
    ):
        raise ResponsePlanError("incident-version-invalid")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ResponsePlanError("plan-version-invalid")
    if (version == 1) != (previous_plan_sha256 is None):
        raise ResponsePlanError("plan-predecessor-invalid")
    predecessor = None if previous_plan_sha256 is None else require_digest(previous_plan_sha256)
    packet_id = require_identifier(response_packet_id, code="response-packet-id-invalid")
    packet_digest = require_digest(response_packet_sha256, code="response-packet-digest-invalid")
    if packet_id != f"response-packet:{packet_digest.removeprefix('sha256:')}":
        raise ResponsePlanError("response-packet-binding-conflict")
    scope_digest = require_digest(
        deterministic_scope_sha256, code="deterministic-scope-digest-invalid"
    )
    target_values = _sorted_targets(targets)
    exclusion_values = _sorted_targets(exclusions)
    if not target_values:
        raise ResponsePlanError("plan-targets-empty")
    target_ids = {target_identity(value) for value in target_values}
    exclusion_ids = {target_identity(value) for value in exclusion_values}
    if target_ids & exclusion_ids:
        raise ResponsePlanError("target-exclusion-overlap")
    command_values = _sorted_commands(commands)
    if {
        target_identity(cast(Mapping[str, Any], value["target"])) for value in command_values
    } != target_ids:
        raise ResponsePlanError("command-target-binding")
    unresolved = sorted(
        {require_identifier(item, code="unresolved-item-invalid") for item in unresolved_item_ids}
    )
    if len(unresolved) != len(unresolved_item_ids):
        raise ResponsePlanError("unresolved-item-duplicate")
    blocking_unresolved = sorted(
        {
            require_identifier(item, code="blocking-unresolved-item-invalid")
            for item in blocking_unresolved_item_ids
        }
    )
    if len(blocking_unresolved) != len(blocking_unresolved_item_ids):
        raise ResponsePlanError("blocking-unresolved-item-duplicate")
    unknown_targets = sorted(
        {require_identifier(item, code="unknown-target-invalid") for item in unknown_target_ids}
    )
    if len(unknown_targets) != len(unknown_target_ids):
        raise ResponsePlanError("unknown-target-duplicate")
    if not isinstance(unresolved_acknowledged, bool):
        raise ResponsePlanError("unresolved-acknowledgement-invalid")
    actor = _normalize_actor(created_by, kinds=frozenset({"human", "service"}))
    body = {
        "schema": "response-plan/v1",
        "plan_id": stable_plan_id(incident),
        "incident_id": incident,
        "incident_version": incident_version,
        "version": version,
        "previous_plan_sha256": predecessor,
        "response_packet_id": packet_id,
        "response_packet_sha256": packet_digest,
        "deterministic_scope_sha256": scope_digest,
        "targets": target_values,
        "exclusions": exclusion_values,
        "commands": command_values,
        "unresolved_item_ids": unresolved,
        "blocking_unresolved_item_ids": blocking_unresolved,
        "unknown_target_ids": unknown_targets,
        "unresolved_acknowledged": unresolved_acknowledged,
        "created_by": actor,
        "created_at": created_at,
    }
    plan = {**body, "plan_sha256": prefixed_sha256(canonical_json_bytes(body))}
    validate_schema("response-plan-v1.schema.json", plan)
    return cast(dict[str, Any], plain_json(plan))


def validate_plan(value: Mapping[str, Any]) -> None:
    plan = cast(dict[str, Any], plain_json(value))
    validate_schema("response-plan-v1.schema.json", plan)
    body = {key: child for key, child in plan.items() if key != "plan_sha256"}
    if plan["plan_sha256"] != prefixed_sha256(canonical_json_bytes(body)):
        raise ResponsePlanError("plan-digest")
    rebuilt = build_plan(
        incident_id=cast(str, plan["incident_id"]),
        incident_version=cast(int, plan["incident_version"]),
        version=cast(int, plan["version"]),
        previous_plan_sha256=cast(str | None, plan["previous_plan_sha256"]),
        response_packet_id=cast(str, plan["response_packet_id"]),
        response_packet_sha256=cast(str, plan["response_packet_sha256"]),
        deterministic_scope_sha256=cast(str, plan["deterministic_scope_sha256"]),
        targets=cast(Sequence[Mapping[str, Any]], plan["targets"]),
        exclusions=cast(Sequence[Mapping[str, Any]], plan["exclusions"]),
        commands=cast(Sequence[Mapping[str, Any]], plan["commands"]),
        unresolved_item_ids=cast(Sequence[str], plan["unresolved_item_ids"]),
        blocking_unresolved_item_ids=cast(Sequence[str], plan["blocking_unresolved_item_ids"]),
        unknown_target_ids=cast(Sequence[str], plan["unknown_target_ids"]),
        unresolved_acknowledged=cast(bool, plan["unresolved_acknowledged"]),
        created_by=cast(Mapping[str, Any], plan["created_by"]),
        created_at=cast(str, plan["created_at"]),
    )
    if rebuilt != plan:
        raise ResponsePlanError("plan-binding")


def component_digest(plan: Mapping[str, Any], key: str) -> str:
    if key not in {"targets", "exclusions", "commands"}:
        raise ResponsePlanError("component-invalid")
    return prefixed_sha256(canonical_json_bytes(plan[key]))


def _validate_decision_semantics(
    *, outcome: object, reason_code: object, plan: Mapping[str, Any]
) -> None:
    if outcome not in {"approved", "rejected"}:
        raise ResponsePlanError("decision-outcome-invalid")
    if outcome == "approved":
        if reason_code is not None:
            raise ResponsePlanError("approval-reason-invalid")
        if plan["blocking_unresolved_item_ids"]:
            raise ResponsePlanError("blocking-unresolved-evidence")
        if plan["unknown_target_ids"]:
            raise ResponsePlanError("unknown-targets-prohibited")
        if plan["unresolved_item_ids"] and not plan["unresolved_acknowledged"]:
            raise ResponsePlanError("unresolved-acknowledgement-required")
    elif reason_code not in REJECTION_CODES:
        raise ResponsePlanError("rejection-reason-invalid")


def build_decision(
    *,
    plan: Mapping[str, Any],
    outcome: str,
    actor: Mapping[str, Any],
    idempotency_key: str,
    decided_at: str,
    reason_code: str | None,
) -> dict[str, Any]:
    validate_plan(plan)
    _validate_decision_semantics(outcome=outcome, reason_code=reason_code, plan=plan)
    actor_value = _normalize_actor(actor, kinds=frozenset({"human"}))
    body = {
        "schema": "response-plan-decision/v1",
        "outcome": outcome,
        "incident_id": plan["incident_id"],
        "incident_version": plan["incident_version"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "response_packet_id": plan["response_packet_id"],
        "response_packet_sha256": plan["response_packet_sha256"],
        "deterministic_scope_sha256": plan["deterministic_scope_sha256"],
        "targets": plan["targets"],
        "exclusions": plan["exclusions"],
        "commands": plan["commands"],
        "targets_sha256": component_digest(plan, "targets"),
        "exclusions_sha256": component_digest(plan, "exclusions"),
        "commands_sha256": component_digest(plan, "commands"),
        "unresolved_item_ids": plan["unresolved_item_ids"],
        "blocking_unresolved_item_ids": plan["blocking_unresolved_item_ids"],
        "unknown_target_ids": plan["unknown_target_ids"],
        "unresolved_acknowledged": plan["unresolved_acknowledged"],
        "reason_code": reason_code,
        "actor": actor_value,
        "idempotency_key": require_idempotency_key(idempotency_key),
        "decided_at": decided_at,
    }
    digest = prefixed_sha256(canonical_json_bytes(body))
    decision = {
        **body,
        "decision_id": f"plan-decision:{digest.removeprefix('sha256:')}",
        "decision_sha256": digest,
    }
    validate_schema("response-plan-decision-v1.schema.json", decision)
    return cast(dict[str, Any], plain_json(decision))


def validate_decision(value: Mapping[str, Any], *, plan: Mapping[str, Any] | None = None) -> None:
    decision = cast(dict[str, Any], plain_json(value))
    validate_schema("response-plan-decision-v1.schema.json", decision)
    _normalize_actor(cast(Mapping[str, Any], decision["actor"]), kinds=frozenset({"human"}))
    if plan is not None:
        validate_plan(plan)
    if plan is None:
        semantic_plan: Mapping[str, Any] = {
            "blocking_unresolved_item_ids": decision["blocking_unresolved_item_ids"],
            "unknown_target_ids": decision["unknown_target_ids"],
            "unresolved_item_ids": decision["unresolved_item_ids"],
            "unresolved_acknowledged": decision["unresolved_acknowledged"],
        }
    else:
        semantic_plan = plan
    _validate_decision_semantics(
        outcome=decision["outcome"],
        reason_code=decision["reason_code"],
        plan=semantic_plan,
    )
    body = {
        key: child
        for key, child in decision.items()
        if key not in {"decision_id", "decision_sha256"}
    }
    digest = prefixed_sha256(canonical_json_bytes(body))
    if (
        decision["decision_sha256"] != digest
        or decision["decision_id"] != f"plan-decision:{digest.removeprefix('sha256:')}"
    ):
        raise ResponsePlanError("decision-digest")
    if plan is not None:
        expected = {
            "incident_id": plan["incident_id"],
            "incident_version": plan["incident_version"],
            "plan_id": plan["plan_id"],
            "plan_version": plan["version"],
            "plan_sha256": plan["plan_sha256"],
            "response_packet_id": plan["response_packet_id"],
            "response_packet_sha256": plan["response_packet_sha256"],
            "deterministic_scope_sha256": plan["deterministic_scope_sha256"],
            "targets": plan["targets"],
            "exclusions": plan["exclusions"],
            "commands": plan["commands"],
            "targets_sha256": component_digest(plan, "targets"),
            "exclusions_sha256": component_digest(plan, "exclusions"),
            "commands_sha256": component_digest(plan, "commands"),
            "unresolved_item_ids": plan["unresolved_item_ids"],
            "blocking_unresolved_item_ids": plan["blocking_unresolved_item_ids"],
            "unknown_target_ids": plan["unknown_target_ids"],
            "unresolved_acknowledged": plan["unresolved_acknowledged"],
        }
        if any(decision[key] != child for key, child in expected.items()):
            raise ResponsePlanError("decision-plan-binding")


def stable_dispatch_operation_id(*, plan: Mapping[str, Any], approval: Mapping[str, Any]) -> str:
    validate_plan(plan)
    validate_decision(approval, plan=plan)
    if approval["outcome"] != "approved":
        raise ResponsePlanError("plan-not-approved")
    identity = {
        "schema": "response-plan-dispatch-operation-identity/v1",
        "authorization_policy": DISPATCH_POLICY,
        "authorized_role": DISPATCHER_ROLE,
        "incident_id": plan["incident_id"],
        "incident_version": plan["incident_version"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "approval_id": approval["decision_id"],
        "approval_sha256": approval["decision_sha256"],
    }
    digest = prefixed_sha256(canonical_json_bytes(identity)).removeprefix("sha256:")
    return f"dispatch-operation:{digest}"


def dispatch_payload_sha256(*, plan: Mapping[str, Any], approval: Mapping[str, Any]) -> str:
    operation_id = stable_dispatch_operation_id(plan=plan, approval=approval)
    payload = {
        "schema": "response-plan-dispatch-payload/v1",
        "authorization_policy": DISPATCH_POLICY,
        "authorized_role": DISPATCHER_ROLE,
        "operation_id": operation_id,
        "incident_id": plan["incident_id"],
        "incident_version": plan["incident_version"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "response_packet_id": plan["response_packet_id"],
        "response_packet_sha256": plan["response_packet_sha256"],
        "deterministic_scope_sha256": plan["deterministic_scope_sha256"],
        "approval_id": approval["decision_id"],
        "approval_sha256": approval["decision_sha256"],
        "targets": plan["targets"],
        "exclusions": plan["exclusions"],
        "commands": plan["commands"],
        "unresolved_item_ids": plan["unresolved_item_ids"],
        "blocking_unresolved_item_ids": plan["blocking_unresolved_item_ids"],
        "unknown_target_ids": plan["unknown_target_ids"],
        "unresolved_acknowledged": plan["unresolved_acknowledged"],
    }
    return prefixed_sha256(canonical_json_bytes(payload))


def stable_dispatch_task_key(*, plan: Mapping[str, Any], approval: Mapping[str, Any]) -> str:
    suffix = stable_dispatch_operation_id(plan=plan, approval=approval).removeprefix(
        "dispatch-operation:"
    )
    return f"dispatch-task:{suffix}"


def build_dispatch_authorization(
    *,
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    actor: Mapping[str, Any],
    idempotency_key: str,
    authorized_at: str,
) -> dict[str, Any]:
    validate_plan(plan)
    validate_decision(approval, plan=plan)
    if approval.get("outcome") != "approved":
        raise ResponsePlanError("plan-not-approved")
    operation_id = stable_dispatch_operation_id(plan=plan, approval=approval)
    body = {
        "schema": "response-plan-dispatch-authorization/v1",
        "authorization_policy": DISPATCH_POLICY,
        "authorized_role": DISPATCHER_ROLE,
        "operation_id": operation_id,
        "task_key": stable_dispatch_task_key(plan=plan, approval=approval),
        "payload_sha256": dispatch_payload_sha256(plan=plan, approval=approval),
        "incident_id": plan["incident_id"],
        "incident_version": plan["incident_version"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "response_packet_id": plan["response_packet_id"],
        "response_packet_sha256": plan["response_packet_sha256"],
        "deterministic_scope_sha256": plan["deterministic_scope_sha256"],
        "approval_id": approval["decision_id"],
        "approval_sha256": approval["decision_sha256"],
        "targets": plan["targets"],
        "exclusions": plan["exclusions"],
        "commands": plan["commands"],
        "unresolved_item_ids": plan["unresolved_item_ids"],
        "blocking_unresolved_item_ids": plan["blocking_unresolved_item_ids"],
        "unknown_target_ids": plan["unknown_target_ids"],
        "unresolved_acknowledged": plan["unresolved_acknowledged"],
        "actor": _normalize_actor(actor, kinds=frozenset({"service"})),
        "idempotency_key": require_idempotency_key(idempotency_key),
        "authorized_at": authorized_at,
    }
    digest = prefixed_sha256(canonical_json_bytes(body))
    authorization = {
        **body,
        "authorization_id": f"dispatch-authorization:{digest.removeprefix('sha256:')}",
        "authorization_sha256": digest,
    }
    validate_schema("response-plan-dispatch-authorization-v1.schema.json", authorization)
    return cast(dict[str, Any], plain_json(authorization))


def validate_dispatch_authorization(
    value: Mapping[str, Any], *, plan: Mapping[str, Any], approval: Mapping[str, Any]
) -> None:
    authorization = cast(dict[str, Any], plain_json(value))
    validate_schema("response-plan-dispatch-authorization-v1.schema.json", authorization)
    _normalize_actor(
        cast(Mapping[str, Any], authorization["actor"]),
        kinds=frozenset({"service"}),
    )
    validate_plan(plan)
    validate_decision(approval, plan=plan)
    if approval.get("outcome") != "approved":
        raise ResponsePlanError("plan-not-approved")
    body = {
        key: child
        for key, child in authorization.items()
        if key not in {"authorization_id", "authorization_sha256"}
    }
    digest = prefixed_sha256(canonical_json_bytes(body))
    if (
        authorization["authorization_sha256"] != digest
        or authorization["authorization_id"]
        != f"dispatch-authorization:{digest.removeprefix('sha256:')}"
    ):
        raise ResponsePlanError("dispatch-authorization-digest")
    expected = {
        "authorization_policy": DISPATCH_POLICY,
        "authorized_role": DISPATCHER_ROLE,
        "operation_id": stable_dispatch_operation_id(plan=plan, approval=approval),
        "task_key": stable_dispatch_task_key(plan=plan, approval=approval),
        "payload_sha256": dispatch_payload_sha256(plan=plan, approval=approval),
        "incident_id": plan["incident_id"],
        "incident_version": plan["incident_version"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "response_packet_id": plan["response_packet_id"],
        "response_packet_sha256": plan["response_packet_sha256"],
        "deterministic_scope_sha256": plan["deterministic_scope_sha256"],
        "approval_id": approval["decision_id"],
        "approval_sha256": approval["decision_sha256"],
        "targets": plan["targets"],
        "exclusions": plan["exclusions"],
        "commands": plan["commands"],
        "unresolved_item_ids": plan["unresolved_item_ids"],
        "blocking_unresolved_item_ids": plan["blocking_unresolved_item_ids"],
        "unknown_target_ids": plan["unknown_target_ids"],
        "unresolved_acknowledged": plan["unresolved_acknowledged"],
    }
    if any(authorization[key] != child for key, child in expected.items()):
        raise ResponsePlanError("dispatch-authorization-binding")


def build_dispatch_consumption(
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
    actor: Mapping[str, Any],
    idempotency_key: str,
    consumed_at: str,
) -> dict[str, Any]:
    validate_dispatch_authorization(authorization, plan=plan, approval=approval)
    body = {
        "schema": "response-plan-dispatch-consumption/v1",
        "authorization_policy": authorization["authorization_policy"],
        "authorized_role": authorization["authorized_role"],
        "authorization_id": authorization["authorization_id"],
        "authorization_sha256": authorization["authorization_sha256"],
        "operation_id": authorization["operation_id"],
        "task_key": authorization["task_key"],
        "payload_sha256": authorization["payload_sha256"],
        "incident_id": authorization["incident_id"],
        "incident_version": authorization["incident_version"],
        "plan_id": authorization["plan_id"],
        "plan_version": authorization["plan_version"],
        "plan_sha256": authorization["plan_sha256"],
        "approval_id": authorization["approval_id"],
        "approval_sha256": authorization["approval_sha256"],
        "actor": _normalize_actor(actor, kinds=frozenset({"service"})),
        "idempotency_key": require_idempotency_key(idempotency_key),
        "consumed_at": consumed_at,
    }
    digest = prefixed_sha256(canonical_json_bytes(body))
    consumption = {
        **body,
        "consumption_id": f"dispatch-consumption:{digest.removeprefix('sha256:')}",
        "consumption_sha256": digest,
    }
    validate_schema("response-plan-dispatch-consumption-v1.schema.json", consumption)
    return cast(dict[str, Any], plain_json(consumption))


def validate_dispatch_consumption(
    value: Mapping[str, Any],
    *,
    authorization: Mapping[str, Any],
    plan: Mapping[str, Any],
    approval: Mapping[str, Any],
) -> None:
    consumption = cast(dict[str, Any], plain_json(value))
    validate_schema("response-plan-dispatch-consumption-v1.schema.json", consumption)
    _normalize_actor(cast(Mapping[str, Any], consumption["actor"]), kinds=frozenset({"service"}))
    validate_dispatch_authorization(authorization, plan=plan, approval=approval)
    body = {
        key: child
        for key, child in consumption.items()
        if key not in {"consumption_id", "consumption_sha256"}
    }
    digest = prefixed_sha256(canonical_json_bytes(body))
    if (
        consumption["consumption_sha256"] != digest
        or consumption["consumption_id"] != f"dispatch-consumption:{digest.removeprefix('sha256:')}"
    ):
        raise ResponsePlanError("dispatch-consumption-digest")
    expected = {
        "authorization_policy": DISPATCH_POLICY,
        "authorized_role": DISPATCHER_ROLE,
        "authorization_id": authorization["authorization_id"],
        "authorization_sha256": authorization["authorization_sha256"],
        "operation_id": authorization["operation_id"],
        "task_key": authorization["task_key"],
        "payload_sha256": authorization["payload_sha256"],
        "incident_id": authorization["incident_id"],
        "incident_version": authorization["incident_version"],
        "plan_id": authorization["plan_id"],
        "plan_version": authorization["plan_version"],
        "plan_sha256": authorization["plan_sha256"],
        "approval_id": authorization["approval_id"],
        "approval_sha256": authorization["approval_sha256"],
    }
    if any(consumption[key] != child for key, child in expected.items()):
        raise ResponsePlanError("dispatch-consumption-binding")


def build_audit_event(
    *,
    previous: Mapping[str, Any] | None,
    event_type: str,
    incident_id: str,
    plan_id: str,
    plan_version: int,
    plan_sha256: str,
    record_sha256: str,
    actor: Mapping[str, Any],
    idempotency_key: str,
    occurred_at: str,
) -> dict[str, Any]:
    if event_type not in AUDIT_EVENT_TYPES:
        raise ResponsePlanError("audit-event-type-invalid")
    sequence = 1 if previous is None else cast(int, previous["sequence"]) + 1
    predecessor = None if previous is None else require_digest(previous.get("event_sha256"))
    body = {
        "schema": "response-plan-audit-event/v1",
        "sequence": sequence,
        "event_type": event_type,
        "incident_id": require_identifier(incident_id),
        "plan_id": plan_id,
        "plan_version": plan_version,
        "plan_sha256": require_digest(plan_sha256),
        "record_sha256": require_digest(record_sha256),
        "actor": _normalize_actor(actor, kinds=frozenset({"human", "service"})),
        "idempotency_key": require_idempotency_key(idempotency_key),
        "predecessor_event_sha256": predecessor,
        "occurred_at": occurred_at,
    }
    digest = prefixed_sha256(canonical_json_bytes(body))
    event = {
        **body,
        "event_id": f"plan-audit-event:{digest.removeprefix('sha256:')}",
        "event_sha256": digest,
    }
    validate_schema("response-plan-audit-event-v1.schema.json", event)
    return cast(dict[str, Any], plain_json(event))


def validate_audit_chain(
    events: Sequence[Mapping[str, Any]],
    *,
    trusted_head_sha256: str | None = None,
    records: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    if not events:
        raise ResponsePlanError("audit-chain-empty")
    predecessor: str | None = None
    plan_id: str | None = None
    incident_id: str | None = None
    current_version = 0
    current_plan_sha256: str | None = None
    decision: str | None = None
    current_plan_record: Mapping[str, Any] | None = None
    current_decision_record: Mapping[str, Any] | None = None
    current_authorization_record: Mapping[str, Any] | None = None
    dispatch_authorized = False
    dispatch_consumed = False
    seen_record_sha256: set[str] = set()
    for sequence, raw in enumerate(events, start=1):
        event = cast(dict[str, Any], plain_json(raw))
        validate_schema("response-plan-audit-event-v1.schema.json", event)
        _normalize_actor(
            cast(Mapping[str, Any], event["actor"]),
            kinds=frozenset({"human", "service"}),
        )
        body = {
            key: child for key, child in event.items() if key not in {"event_id", "event_sha256"}
        }
        digest = prefixed_sha256(canonical_json_bytes(body))
        if (
            event["sequence"] != sequence
            or event["predecessor_event_sha256"] != predecessor
            or event["event_sha256"] != digest
            or event["event_id"] != f"plan-audit-event:{digest.removeprefix('sha256:')}"
        ):
            raise ResponsePlanError("audit-chain-binding")
        if plan_id is None:
            plan_id = cast(str, event["plan_id"])
            incident_id = cast(str, event["incident_id"])
        elif event["plan_id"] != plan_id or event["incident_id"] != incident_id:
            raise ResponsePlanError("audit-chain-binding")
        event_type = cast(str, event["event_type"])
        version = cast(int, event["plan_version"])
        plan_digest = cast(str, event["plan_sha256"])
        record_digest = cast(str, event["record_sha256"])
        if record_digest in seen_record_sha256:
            raise ResponsePlanError("audit-record-duplicate")
        seen_record_sha256.add(record_digest)
        record: Mapping[str, Any] | None = None
        if records is not None:
            record = records.get(record_digest)
            if record is None:
                raise ResponsePlanError("audit-record-missing")
        if event_type == "plan.created":
            if sequence != 1 or version != 1 or event["record_sha256"] != plan_digest:
                raise ResponsePlanError("audit-transition-invalid")
            current_version = version
            current_plan_sha256 = plan_digest
            if record is not None:
                validate_plan(record)
                if (
                    record["plan_sha256"] != event["record_sha256"]
                    or record["plan_id"] != event["plan_id"]
                    or record["incident_id"] != event["incident_id"]
                    or record["version"] != version
                    or record["created_by"] != event["actor"]
                ):
                    raise ResponsePlanError("audit-record-binding")
                current_plan_record = record
        elif event_type == "plan.edited":
            if version != current_version + 1 or event["record_sha256"] != plan_digest:
                raise ResponsePlanError("audit-transition-invalid")
            current_version = version
            current_plan_sha256 = plan_digest
            decision = None
            current_decision_record = None
            current_authorization_record = None
            dispatch_authorized = False
            dispatch_consumed = False
            if record is not None:
                validate_plan(record)
                if (
                    record["plan_sha256"] != event["record_sha256"]
                    or record["plan_id"] != event["plan_id"]
                    or record["incident_id"] != event["incident_id"]
                    or record["version"] != version
                    or record["created_by"] != event["actor"]
                    or current_plan_record is None
                    or record["previous_plan_sha256"] != current_plan_record["plan_sha256"]
                ):
                    raise ResponsePlanError("audit-record-binding")
                current_plan_record = record
        elif event_type in {"plan.approved", "plan.rejected"}:
            if (
                version != current_version
                or plan_digest != current_plan_sha256
                or decision is not None
            ):
                raise ResponsePlanError("audit-transition-invalid")
            decision = event_type.removeprefix("plan.")
            if cast(Mapping[str, Any], event["actor"]).get("kind") != "human":
                raise ResponsePlanError("audit-transition-invalid")
            if record is not None:
                if current_plan_record is None:
                    raise ResponsePlanError("audit-record-binding")
                validate_decision(record, plan=current_plan_record)
                if (
                    record["decision_sha256"] != event["record_sha256"]
                    or record["outcome"] != decision
                    or record["actor"] != event["actor"]
                    or record["idempotency_key"] != event["idempotency_key"]
                ):
                    raise ResponsePlanError("audit-record-binding")
                current_decision_record = record
        elif event_type == "dispatch.authorized":
            if (
                version != current_version
                or plan_digest != current_plan_sha256
                or decision != "approved"
                or dispatch_authorized
            ):
                raise ResponsePlanError("audit-transition-invalid")
            if cast(Mapping[str, Any], event["actor"]).get("kind") != "service":
                raise ResponsePlanError("audit-transition-invalid")
            if record is not None:
                if current_plan_record is None or current_decision_record is None:
                    raise ResponsePlanError("audit-record-binding")
                validate_dispatch_authorization(
                    record,
                    plan=current_plan_record,
                    approval=current_decision_record,
                )
                if (
                    record["authorization_sha256"] != event["record_sha256"]
                    or record["actor"] != event["actor"]
                    or record["idempotency_key"] != event["idempotency_key"]
                ):
                    raise ResponsePlanError("audit-record-binding")
                current_authorization_record = record
            dispatch_authorized = True
        elif event_type == "dispatch.consumed":
            if (
                version != current_version
                or plan_digest != current_plan_sha256
                or decision != "approved"
                or not dispatch_authorized
                or dispatch_consumed
            ):
                raise ResponsePlanError("audit-transition-invalid")
            if cast(Mapping[str, Any], event["actor"]).get("kind") != "service":
                raise ResponsePlanError("audit-transition-invalid")
            if records is not None and current_authorization_record is None:
                raise ResponsePlanError("audit-record-binding")
            if record is not None:
                if (
                    current_plan_record is None
                    or current_decision_record is None
                    or current_authorization_record is None
                ):
                    raise ResponsePlanError("audit-record-binding")
                validate_dispatch_consumption(
                    record,
                    authorization=current_authorization_record,
                    plan=current_plan_record,
                    approval=current_decision_record,
                )
                if (
                    record["consumption_sha256"] != event["record_sha256"]
                    or record["actor"] != event["actor"]
                    or record["idempotency_key"] != event["idempotency_key"]
                ):
                    raise ResponsePlanError("audit-record-binding")
            dispatch_consumed = True
        predecessor = digest
    if trusted_head_sha256 is not None:
        if require_digest(trusted_head_sha256) != predecessor:
            raise ResponsePlanError("audit-head-mismatch")
    if records is not None and set(records) != seen_record_sha256:
        raise ResponsePlanError("audit-record-orphan")


__all__ = [
    "APPROVER_ROLE",
    "AUDIT_EVENT_TYPES",
    "DISPATCHER_ROLE",
    "DISPATCH_POLICY",
    "EDITOR_ROLE",
    "REJECTION_CODES",
    "ResponsePlanError",
    "SIMULATOR_NAMESPACE",
    "build_audit_event",
    "build_decision",
    "build_dispatch_authorization",
    "build_dispatch_consumption",
    "build_plan",
    "canonical_json_bytes",
    "component_digest",
    "dispatch_payload_sha256",
    "normalize_command",
    "normalize_target",
    "plain_json",
    "prefixed_sha256",
    "require_digest",
    "require_idempotency_key",
    "require_identifier",
    "stable_plan_id",
    "stable_dispatch_operation_id",
    "stable_dispatch_task_key",
    "strict_json_bytes",
    "target_identity",
    "timestamp",
    "validate_audit_chain",
    "validate_decision",
    "validate_dispatch_authorization",
    "validate_dispatch_consumption",
    "validate_plan",
    "validate_schema",
]
