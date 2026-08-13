from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from colortrace_grafana_mcp import EvidenceBatch
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)
from referencing import Registry, Resource

POLICY_VERSION = "bounded-investigation/v1"
MODEL_PROFILE_VERSION = "bounded-gemini-investigator/v1"
MODEL_ID = "gemini-3.5-flash"
MODEL_LOCATION = "global"
ADK_VERSION = "2.6.3"
GENAI_VERSION = "2.17.0"
RESPONSE_PACKET_VERSION = "response-packet/v1"
INVOCATION_VERSION = "model-tool-invocation/v1"
QUERY_KEYS = (
    "alert.rule",
    "log.correlated-events",
    "metric.correlated-observations",
    "trace.by-id",
)
HYPOTHESIS_KEYS = (
    "color-resource-drift",
    "nominal-config-drift",
    "unrelated-event",
    "worker-only-failure",
)
TOOL_BY_QUERY = MappingProxyType(
    {
        "alert.rule": "alerting_manage_rules",
        "log.correlated-events": "query_loki_logs",
        "metric.correlated-observations": "query_prometheus",
        "trace.by-id": "tempo_get-trace",
    }
)
POLICY_CANONICAL_SHA256 = "215622df9dc7b3628a4256d10ef4dc672b7f70324d17347fbdfaa35d7892d080"
MODEL_PROFILE_CANONICAL_SHA256 = "ca4ba33609f79a814321ed6ab1625186cf1f6f2bfa0f64a11b0ffaa009f7b851"
SCHEMA_ROOT = Path(__file__).parent / "schemas"


class ContractError(RuntimeError):
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
        raise ContractError("malformed-json") from error


def strict_json_file(path: Path) -> dict[str, Any]:
    try:
        value = strict_json_bytes(path.resolve(strict=True).read_bytes())
    except OSError as error:
        raise ContractError("configuration-unavailable") from error
    if not isinstance(value, dict):
        raise ContractError("malformed-json")
    return value


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(child) for child in value]
    return value


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
        return item

    return json.dumps(
        normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def prefixed_sha256(value: bytes) -> str:
    return f"sha256:{sha256(value)}"


def timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ContractError("invalid-time")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ContractError("invalid-time") from error
    if parsed.tzinfo is None:
        raise ContractError("invalid-time")
    return parsed.astimezone(UTC)


@cache
def _schema_documents() -> Mapping[str, Mapping[str, Any]]:
    names = (
        "alert-intake-v1.schema.json",
        "model-advisory-v1.schema.json",
        "model-selection-v1.schema.json",
        "model-tool-invocation-v1.schema.json",
        "response-packet-v1.schema.json",
    )
    documents: dict[str, Mapping[str, Any]] = {}
    for name in names:
        document = strict_json_file(SCHEMA_ROOT / name)
        Draft202012Validator.check_schema(document)
        documents[name] = document
    return MappingProxyType(documents)


@cache
def _schema_registry() -> Registry[Any]:
    resources = []
    for document in _schema_documents().values():
        resources.append((cast(str, document["$id"]), Resource.from_contents(document)))
    return Registry().with_resources(resources)


@cache
def _schema_validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(
        _schema_documents()[name],
        registry=_schema_registry(),
        format_checker=FormatChecker(),
    )


def validate_contract(name: str, value: Mapping[str, Any]) -> None:
    try:
        _schema_validator(name).validate(dict(value))
    except ValidationError as error:
        raise ContractError("schema-validation") from error


@dataclass(frozen=True, slots=True)
class Budgets:
    end_to_end_seconds: int = 120
    maximum_model_turns: int = 6
    maximum_input_tokens: int = 32_000
    maximum_output_tokens: int = 4_096
    maximum_mcp_attempts: int = 8
    maximum_validator_calls: int = 6
    maximum_calls_in_flight: int = 2
    model_timeout_seconds: int = 45
    evidence_timeout_seconds: int = 20
    maximum_trusted_transient_retries: int = 1
    maximum_model_visible_bytes: int = 1_048_576
    maximum_hypotheses: int = 4


@dataclass(frozen=True, slots=True)
class InvestigationPolicy:
    version: str
    digest: str
    model_profile_digest: str
    budgets: Budgets
    required_query_keys: tuple[str, ...]
    hypothesis_keys: tuple[str, ...]
    trusted_transient_errors: frozenset[str]
    no_action_reasons: frozenset[str]

    @classmethod
    def load(cls, policy_path: Path, model_profile_path: Path) -> InvestigationPolicy:
        policy = strict_json_file(policy_path)
        profile = strict_json_file(model_profile_path)
        policy_digest = sha256(canonical_json_bytes(policy))
        profile_digest = sha256(canonical_json_bytes(profile))
        if policy_digest != POLICY_CANONICAL_SHA256 or profile_digest != (
            MODEL_PROFILE_CANONICAL_SHA256
        ):
            raise ContractError("policy-drift")
        raw_budgets = policy.get("budgets")
        if not isinstance(raw_budgets, dict):
            raise ContractError("policy-drift")
        try:
            budgets = Budgets(**raw_budgets)
        except TypeError as error:
            raise ContractError("policy-drift") from error
        if budgets != Budgets():
            raise ContractError("policy-drift")
        if (
            policy.get("schema") != "investigation-policy/v1"
            or policy.get("policy_version") != POLICY_VERSION
            or policy.get("claim_policy") != "deterministic-claim/v1"
            or policy.get("scope_policy") != "single-causal-resource-scope/v1"
            or tuple(policy.get("required_query_keys", ())) != QUERY_KEYS
            or tuple(policy.get("hypothesis_keys", ())) != HYPOTHESIS_KEYS
            or profile.get("schema") != "vertex-model-profile/v1"
            or profile.get("profile_version") != MODEL_PROFILE_VERSION
            or profile.get("provider") != "vertex-ai"
            or profile.get("framework") != "google-adk"
            or profile.get("model") != MODEL_ID
            or profile.get("location") != MODEL_LOCATION
            or profile.get("google_adk_version") != ADK_VERSION
            or profile.get("google_genai_version") != GENAI_VERSION
            or profile.get("response_mime_type") != "application/json"
            or profile.get("thinking_level") != "MINIMAL"
        ):
            raise ContractError("policy-drift")
        transient = policy.get("trusted_transient_errors")
        no_action = policy.get("terminal_no_action_reasons")
        if not isinstance(transient, list) or not isinstance(no_action, list):
            raise ContractError("policy-drift")
        return cls(
            POLICY_VERSION,
            prefixed_sha256(canonical_json_bytes(policy)),
            prefixed_sha256(canonical_json_bytes(profile)),
            budgets,
            QUERY_KEYS,
            HYPOTHESIS_KEYS,
            frozenset(cast(list[str], transient)),
            frozenset(cast(list[str], no_action)),
        )


@dataclass(frozen=True, slots=True)
class FrozenWindow:
    start: datetime
    end: datetime
    frozen_at: datetime

    def to_dict(self) -> dict[str, str]:
        return {
            "start": timestamp(self.start),
            "end": timestamp(self.end),
            "frozen_at": timestamp(self.frozen_at),
        }


@dataclass(frozen=True, slots=True)
class AlertIntake:
    incident_id: str
    alert_id: str
    alert_started_at: datetime
    retrieved_at: datetime
    measured_clock_skew_seconds: int
    binding: Mapping[str, str]
    correlation_keys: Mapping[str, str]
    predecessor_event_sha256: str | None
    window: FrozenWindow

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> AlertIntake:
        validate_contract("alert-intake-v1.schema.json", value)
        started = parse_timestamp(cast(str, value["alert_started_at"]))
        retrieved = parse_timestamp(cast(str, value["retrieved_at"]))
        if retrieved < started or retrieved - started > timedelta(hours=24):
            raise ContractError("invalid-time")
        start = started - timedelta(seconds=300)
        end = min(retrieved, started + timedelta(seconds=300))
        if end < start or end - start > timedelta(seconds=600):
            raise ContractError("invalid-time")
        return cls(
            cast(str, value["incident_id"]),
            cast(str, value["alert_id"]),
            started,
            retrieved,
            cast(int, value["measured_clock_skew_seconds"]),
            MappingProxyType(dict(cast(Mapping[str, str], value["binding"]))),
            MappingProxyType(dict(cast(Mapping[str, str], value["correlation_keys"]))),
            cast(str | None, value["predecessor_event_sha256"]),
            FrozenWindow(start, end, retrieved),
        )

    def evidence_batch(self, query_keys: Sequence[str]) -> EvidenceBatch:
        request = {
            "schema": "grafana-evidence-request/v1",
            "request_id": f"evidence-{sha256(self.incident_id.encode('utf-8'))[:24]}",
            "incident_id": self.incident_id,
            "query_keys": list(query_keys),
            "window": {
                "start": timestamp(self.window.start),
                "end": timestamp(self.window.end),
            },
            "binding": dict(self.binding),
            "correlation_keys": dict(self.correlation_keys),
            "predecessor_event_sha256": self.predecessor_event_sha256,
        }
        return EvidenceBatch.from_mapping(request)

    def model_view(self) -> dict[str, Any]:
        return {
            "schema": "quoted-alert-view/v1",
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "alert_started_at": timestamp(self.alert_started_at),
            "fixed_window": self.window.to_dict(),
            "correlation_keys": dict(self.correlation_keys),
            "available_query_keys": list(QUERY_KEYS),
            "available_hypothesis_keys": list(HYPOTHESIS_KEYS),
            "trust": "untrusted-alert-data",
        }


@dataclass(frozen=True, slots=True)
class ModelSelection:
    hypothesis_keys: tuple[str, ...]
    query_keys: tuple[str, ...]

    @classmethod
    def from_bytes(cls, raw: bytes) -> ModelSelection:
        value = strict_json_bytes(raw)
        if not isinstance(value, dict):
            raise ContractError("model-output-invalid")
        try:
            validate_contract("model-selection-v1.schema.json", value)
        except ContractError as error:
            raise ContractError("model-output-invalid") from error
        return cls(
            tuple(cast(list[str], value["hypothesis_keys"])),
            tuple(cast(list[str], value["query_keys"])),
        )


@dataclass(frozen=True, slots=True)
class ModelAdvisory:
    summary: str
    evidence_ids: tuple[str, ...]
    output_sha256: str

    @classmethod
    def from_bytes(cls, raw: bytes, allowed_evidence_ids: frozenset[str]) -> ModelAdvisory:
        value = strict_json_bytes(raw)
        if not isinstance(value, dict):
            raise ContractError("model-output-invalid")
        try:
            validate_contract("model-advisory-v1.schema.json", value)
        except ContractError as error:
            raise ContractError("model-output-invalid") from error
        evidence_ids = tuple(cast(list[str], value["evidence_ids"]))
        if not set(evidence_ids).issubset(allowed_evidence_ids):
            raise ContractError("model-citation-invalid")
        return cls(cast(str, value["summary"]), evidence_ids, prefixed_sha256(raw))

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust": "untrusted-model-output",
            "summary": self.summary,
            "evidence_ids": list(self.evidence_ids),
            "output_sha256": self.output_sha256,
        }


def finalize_derived_record(
    body: Mapping[str, Any], *, id_field: str, id_prefix: str
) -> dict[str, Any]:
    plain = cast(dict[str, Any], _plain_json(body))
    derivation = prefixed_sha256(canonical_json_bytes(plain))
    record = {**plain, id_field: f"{id_prefix}:{derivation.removeprefix('sha256:')}"}
    record["derivation_sha256"] = derivation
    return {key: record[key] for key in sorted(record)}


def finalize_response_packet(body: Mapping[str, Any]) -> dict[str, Any]:
    packet = finalize_derived_record(body, id_field="packet_id", id_prefix="response-packet")
    validate_contract("response-packet-v1.schema.json", packet)
    validate_response_packet(packet)
    return packet


def validate_response_packet(value: Mapping[str, Any]) -> None:
    validate_contract("response-packet-v1.schema.json", value)
    derivation_input = {
        key: child for key, child in value.items() if key not in {"packet_id", "derivation_sha256"}
    }
    expected = prefixed_sha256(canonical_json_bytes(derivation_input))
    if value.get("derivation_sha256") != expected or value.get("packet_id") != (
        f"response-packet:{expected.removeprefix('sha256:')}"
    ):
        raise ContractError("packet-digest")
    status = value.get("status")
    claims = cast(Sequence[Mapping[str, Any]], value.get("claims", ()))
    unresolved = cast(Sequence[Mapping[str, Any]], value.get("unresolved_items", ()))
    candidate = value.get("candidate_plan")
    no_action = value.get("no_action_reason")
    scope = cast(Mapping[str, Any], value.get("scope", {}))
    advisory = value.get("model_advisory")
    budget_use = cast(Mapping[str, int], value.get("budget_use", {}))
    evidence_ids = set(cast(Sequence[str], value.get("evidence_ids", ())))
    results = cast(Sequence[Mapping[str, Any]], value.get("deterministic_results", ()))
    result_ids: set[str] = set()
    for result in results:
        result_id = cast(str, result["result_id"])
        derivation = cast(str, result["derivation_sha256"])
        if result_id != f"validation-result:{derivation}" or not set(
            cast(Sequence[str], result["evidence_ids"])
        ).issubset(evidence_ids):
            raise ContractError("deterministic-result-binding")
        result_ids.add(result_id)
    for claim in claims:
        if not set(cast(Sequence[str], claim["evidence_ids"])).issubset(evidence_ids):
            raise ContractError("claim-citation")
        if claim["state"] in {"confirmed", "rejected"} and (
            not claim["evidence_ids"]
            or claim["deterministic_result_evidence_id"] is None
            or claim["source_validator_result_id"] not in result_ids
        ):
            raise ContractError("claim-citation")
        if claim.get("policy") == "deterministic-claim/v1":
            identity = {
                "claim_type": claim.get("claim_type"),
                "subject": claim.get("subject"),
            }
            derivation_input = {
                **identity,
                "state": claim.get("state"),
                "policy": claim.get("policy"),
                "normalized_inputs_sha256": claim.get("normalized_inputs_sha256"),
                "evidence_ids": claim.get("evidence_ids"),
                "reason_codes": claim.get("reason_codes"),
            }
            derivation = sha256(canonical_json_bytes(derivation_input))
            contradictory = "contradictory-authoritative-evidence" in cast(
                Sequence[str], claim.get("reason_codes", ())
            )
            expected_contradictions = claim.get("evidence_ids") if contradictory else []
            if (
                claim.get("claim_id") != f"claim:{sha256(canonical_json_bytes(identity))}"
                or claim.get("derivation_sha256") != derivation
                or claim.get("deterministic_result_evidence_id")
                != f"deterministic-result:{derivation}"
                or claim.get("normalized_inputs_sha256")
                != sha256(canonical_json_bytes(claim.get("subject")))
                or claim.get("contradiction_links") != expected_contradictions
            ):
                raise ContractError("claim-derivation")
        deterministic_evidence_id = claim.get("deterministic_result_evidence_id")
        if deterministic_evidence_id is not None and deterministic_evidence_id not in evidence_ids:
            raise ContractError("claim-citation")
    if isinstance(advisory, Mapping):
        advisory_evidence_ids = cast(Sequence[str], advisory.get("evidence_ids", ()))
        if not advisory_evidence_ids or not set(advisory_evidence_ids).issubset(evidence_ids):
            raise ContractError("model-citation")
    if status == "resolved":
        affected = cast(Sequence[Mapping[str, Any]], scope.get("affected", ()))
        confirmed_ids = {
            cast(str, claim["claim_id"]) for claim in claims if claim["state"] == "confirmed"
        }
        if (
            unresolved
            or scope.get("state") != "resolved"
            or scope.get("unknown")
            or advisory is None
            or not results
            or budget_use.get("elapsed_ms", 120_001) > 120_000
            or budget_use.get("input_tokens", 32_001)
            + budget_use.get("unavailable_input_tokens_reserved", 0)
            > 32_000
            or budget_use.get("output_tokens", 4_097)
            + budget_use.get("unavailable_output_tokens_reserved", 0)
            > 4_096
            or any(claim.get("policy") != "deterministic-claim/v1" for claim in claims)
            or any(claim["state"] not in {"confirmed", "rejected"} for claim in claims)
            or any(
                result.get("status") != "resolved"
                for result in cast(
                    Sequence[Mapping[str, Any]], value.get("deterministic_results", ())
                )
            )
        ):
            raise ContractError("packet-state")
        if affected:
            if not isinstance(candidate, Mapping) or no_action is not None:
                raise ContractError("packet-state")
            if candidate.get("targets") != list(affected) or not set(
                cast(Sequence[str], candidate.get("claim_ids", ()))
            ).issubset(confirmed_ids):
                raise ContractError("candidate-plan-binding")
            candidate_body = {
                key: candidate.get(key)
                for key in ("schema", "non_executable", "targets", "claim_ids")
            }
            if candidate.get("plan_id") != (
                f"candidate-plan:{sha256(canonical_json_bytes(candidate_body))}"
            ):
                raise ContractError("candidate-plan-binding")
        elif candidate is not None or no_action != "no-affected-targets":
            raise ContractError("packet-state")
    else:
        if (
            not unresolved
            or candidate is not None
            or no_action is None
            or scope.get("state") != "unresolved"
            or advisory is not None
        ):
            raise ContractError("packet-state")
