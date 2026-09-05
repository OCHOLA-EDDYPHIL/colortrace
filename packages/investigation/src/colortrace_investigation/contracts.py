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

from colortrace_grafana_mcp import ADAPTIVE_QUERY_KEYS, EvidenceBatch
from colortrace_validator import (
    AssessmentStatus,
    assess_expected_state,
    assess_incident_classes,
    assess_operational_evidence,
    reconcile_diagnosis,
)
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
    FormatChecker,
    ValidationError,
)
from referencing import Registry, Resource

POLICY_VERSION = "bounded-investigation/v1"
ADAPTIVE_POLICY_VERSION = "bounded-adaptive-investigation/v1"
MODEL_PROFILE_VERSION = "bounded-gemini-investigator/v1"
ADAPTIVE_MODEL_PROFILE_VERSION = "bounded-adaptive-gemini-investigator/v1"
MODEL_ID = "gemini-3.5-flash"
MODEL_LOCATION = "global"
ADK_VERSION = "2.6.3"
GENAI_VERSION = "2.17.0"
RESPONSE_PACKET_VERSION = "response-packet/v1"
INVOCATION_VERSION = "model-tool-invocation/v1"
ADAPTIVE_RESPONSE_PACKET_VERSION = "response-packet/v2"
ADAPTIVE_INVOCATION_VERSION = "model-tool-invocation/v2"
REFERENCE_RESPONSE_PACKET_VERSION = "response-packet/v3"
REFERENCE_POLICY_VERSION = "reference-investigation/v1"
QUERY_KEYS = (
    "alert.rule",
    "log.correlated-events",
    "metric.correlated-observations",
    "trace.by-id",
)
EXACT_QUERY_KEYS = QUERY_KEYS[1:]
COHORT_QUERY_KEYS = (
    "metric.worker-cohort",
    "log.config-cohort",
)
if tuple(ADAPTIVE_QUERY_KEYS) != QUERY_KEYS + COHORT_QUERY_KEYS:
    raise RuntimeError("adaptive query catalogue drift")
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
        "metric.worker-cohort": "query_prometheus",
        "log.config-cohort": "query_loki_logs",
    }
)
POLICY_CANONICAL_SHA256 = "215622df9dc7b3628a4256d10ef4dc672b7f70324d17347fbdfaa35d7892d080"
MODEL_PROFILE_CANONICAL_SHA256 = "0381b53d866478ade184abdceafed2af160c93c5d5eaa33b5168286e5aa2ed49"
ADAPTIVE_POLICY_CANONICAL_SHA256 = (
    "8126979fe5a9b054a67747debf3401bfd0d8f3deb82f4ffcb759ef0f046ef131"
)
ADAPTIVE_MODEL_PROFILE_CANONICAL_SHA256 = (
    "37f1d97404bcf38ce1da3b3b83485cf7f202c6fcc5645b5084d325e4c149fed8"
)
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
        "model-selection-v2.schema.json",
        "model-selection-v3.schema.json",
        "model-tool-invocation-v1.schema.json",
        "model-tool-invocation-v2.schema.json",
        "reference-evidence-v3.schema.json",
        "response-packet-v1.schema.json",
        "response-packet-v2.schema.json",
        "response-packet-v3.schema.json",
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
    baseline_query_key: str = "alert.rule"
    exact_query_keys: tuple[str, ...] = EXACT_QUERY_KEYS
    cohort_query_keys: tuple[str, ...] = ()
    maximum_post_baseline_calls: int = 3

    @property
    def adaptive(self) -> bool:
        return self.version == ADAPTIVE_POLICY_VERSION

    @classmethod
    def fixed_v1(cls) -> InvestigationPolicy:
        return cls(
            version=POLICY_VERSION,
            digest=f"sha256:{POLICY_CANONICAL_SHA256}",
            model_profile_digest=f"sha256:{MODEL_PROFILE_CANONICAL_SHA256}",
            budgets=Budgets(),
            required_query_keys=QUERY_KEYS,
            hypothesis_keys=HYPOTHESIS_KEYS,
            trusted_transient_errors=frozenset({"rate_limit", "service", "timeout", "transport"}),
            no_action_reasons=frozenset(
                {
                    "budget-exhausted",
                    "contradictory-evidence",
                    "evidence-unavailable",
                    "incomplete-evidence",
                    "invalid-intake",
                    "model-unavailable",
                    "no-affected-targets",
                    "policy-drift",
                    "stale-evidence",
                    "validator-unresolved",
                }
            ),
        )

    @classmethod
    def load(cls, policy_path: Path, model_profile_path: Path) -> InvestigationPolicy:
        policy = strict_json_file(policy_path)
        profile = strict_json_file(model_profile_path)
        policy_digest = sha256(canonical_json_bytes(policy))
        profile_digest = sha256(canonical_json_bytes(profile))
        legacy = (
            policy_digest == POLICY_CANONICAL_SHA256
            and profile_digest == MODEL_PROFILE_CANONICAL_SHA256
        )
        adaptive = (
            policy_digest == ADAPTIVE_POLICY_CANONICAL_SHA256
            and profile_digest == ADAPTIVE_MODEL_PROFILE_CANONICAL_SHA256
        )
        if not (legacy or adaptive):
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
        expected_policy_version = ADAPTIVE_POLICY_VERSION if adaptive else POLICY_VERSION
        expected_profile_version = (
            ADAPTIVE_MODEL_PROFILE_VERSION if adaptive else MODEL_PROFILE_VERSION
        )
        policy_shape_valid = (
            policy.get("schema") == "investigation-policy/v2"
            and policy.get("baseline_query_key") == "alert.rule"
            and tuple(policy.get("exact_query_keys", ())) == EXACT_QUERY_KEYS
            and tuple(policy.get("cohort_query_keys", ())) == COHORT_QUERY_KEYS
            and policy.get("maximum_post_baseline_calls") == 3
            if adaptive
            else policy.get("schema") == "investigation-policy/v1"
            and tuple(policy.get("required_query_keys", ())) == QUERY_KEYS
        )
        if (
            not policy_shape_valid
            or policy.get("policy_version") != expected_policy_version
            or policy.get("claim_policy") != "deterministic-claim/v1"
            or policy.get("scope_policy") != "single-causal-resource-scope/v1"
            or tuple(policy.get("hypothesis_keys", ())) != HYPOTHESIS_KEYS
            or profile.get("schema") != "vertex-model-profile/v1"
            or profile.get("profile_version") != expected_profile_version
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
            expected_policy_version,
            prefixed_sha256(canonical_json_bytes(policy)),
            prefixed_sha256(canonical_json_bytes(profile)),
            budgets,
            tuple(ADAPTIVE_QUERY_KEYS) if adaptive else QUERY_KEYS,
            HYPOTHESIS_KEYS,
            frozenset(cast(list[str], transient)),
            frozenset(cast(list[str], no_action)),
            "alert.rule",
            EXACT_QUERY_KEYS,
            COHORT_QUERY_KEYS if adaptive else (),
            3,
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

    def adaptive_evidence_batch(self, query_keys: Sequence[str]) -> EvidenceBatch:
        request = {
            "schema": "grafana-evidence-request/v2",
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

    def adaptive_model_view(self) -> dict[str, Any]:
        view = self.model_view()
        view["schema"] = "quoted-alert-view/v2"
        view["available_query_keys"] = list(ADAPTIVE_QUERY_KEYS)
        view["exact_query_keys"] = list(EXACT_QUERY_KEYS)
        view["cohort_query_keys"] = list(COHORT_QUERY_KEYS)
        view["maximum_post_baseline_calls"] = 3
        return view


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
class AdaptiveModelSelection:
    hypotheses: tuple[Mapping[str, Any], ...]
    query_keys: tuple[str, ...]
    stop_reason: str

    @classmethod
    def from_bytes(
        cls, raw: bytes, *, allowed_evidence_ids: frozenset[str]
    ) -> AdaptiveModelSelection:
        value = strict_json_bytes(raw)
        if not isinstance(value, dict):
            raise ContractError("model-output-invalid")
        try:
            validate_contract("model-selection-v2.schema.json", value)
        except ContractError as error:
            raise ContractError("model-output-invalid") from error
        raw_hypotheses = cast(Sequence[Mapping[str, Any]], value["hypotheses"])
        if [item["ordinal"] for item in raw_hypotheses] != list(range(1, len(raw_hypotheses) + 1)):
            raise ContractError("model-output-invalid")
        if len({item["hypothesis_key"] for item in raw_hypotheses}) != len(raw_hypotheses):
            raise ContractError("model-output-invalid")
        for item in raw_hypotheses:
            if not set(cast(Sequence[str], item["evidence_ids"])).issubset(allowed_evidence_ids):
                raise ContractError("model-citation-invalid")
        hypotheses = tuple(
            MappingProxyType(
                {
                    "ordinal": cast(int, item["ordinal"]),
                    "hypothesis_key": cast(str, item["hypothesis_key"]),
                    "evidence_ids": tuple(cast(Sequence[str], item["evidence_ids"])),
                }
            )
            for item in raw_hypotheses
        )
        return cls(
            hypotheses,
            tuple(cast(Sequence[str], value["query_keys"])),
            cast(str, value["stop_reason"]),
        )

    def hypotheses_to_dict(self) -> list[dict[str, Any]]:
        return [
            {
                "ordinal": item["ordinal"],
                "hypothesis_key": item["hypothesis_key"],
                "evidence_ids": list(cast(Sequence[str], item["evidence_ids"])),
            }
            for item in self.hypotheses
        ]


REFERENCE_INCIDENT_CLASSES = (
    "resource-resolution-drift/v1",
    "configuration-rollout-drift/v1",
    "stale-derivative-cache/v1",
)
REFERENCE_POLICY_DOCUMENT: Mapping[str, Any] = MappingProxyType(
    {
        "schema": REFERENCE_POLICY_VERSION,
        "baseline_query_key": "alert.rule",
        "maximum_post_baseline_calls": 3,
        "maximum_model_calls": 4,
        "maximum_output_tokens": 768,
        "evidence_timeout_seconds": 20,
        "model_timeout_seconds": 75,
        "required_signal_classes": 2,
        "query_keys": ADAPTIVE_QUERY_KEYS,
        "incident_classes": REFERENCE_INCIDENT_CLASSES,
        "authority": {
            "model": "query-selection-only",
            "grafana": "structured-runtime-evidence",
            "validators": "facts-classification-and-scope",
            "human": "sole-action-approval",
            "action_target": "simulator-only",
        },
    }
)
REFERENCE_POLICY_SHA256 = prefixed_sha256(canonical_json_bytes(REFERENCE_POLICY_DOCUMENT))


@dataclass(frozen=True, slots=True)
class ReferenceModelSelection:
    hypotheses: tuple[Mapping[str, Any], ...]
    query_keys: tuple[str, ...]
    stop_reason: str
    output_sha256: str

    @classmethod
    def from_bytes(
        cls,
        raw: bytes,
        *,
        allowed_evidence_ids: frozenset[str],
    ) -> ReferenceModelSelection:
        value = strict_json_bytes(raw)
        if not isinstance(value, dict):
            raise ContractError("model-output-invalid")
        try:
            validate_contract("model-selection-v3.schema.json", value)
        except ContractError as error:
            raise ContractError("model-output-invalid") from error
        raw_hypotheses = cast(Sequence[Mapping[str, Any]], value["hypotheses"])
        ordinals = [item["ordinal"] for item in raw_hypotheses]
        if ordinals != list(range(1, len(raw_hypotheses) + 1)):
            raise ContractError("model-output-invalid")
        if len({item["incident_class"] for item in raw_hypotheses}) != len(raw_hypotheses):
            raise ContractError("model-output-invalid")
        for item in raw_hypotheses:
            citations = set(cast(Sequence[str], item["evidence_ids"]))
            if not citations.issubset(allowed_evidence_ids):
                raise ContractError("model-citation-invalid")
        return cls(
            hypotheses=tuple(
                MappingProxyType(
                    {
                        "ordinal": cast(int, item["ordinal"]),
                        "incident_class": cast(str, item["incident_class"]),
                        "evidence_ids": tuple(cast(Sequence[str], item["evidence_ids"])),
                    }
                )
                for item in raw_hypotheses
            ),
            query_keys=tuple(cast(Sequence[str], value["query_keys"])),
            stop_reason=cast(str, value["stop_reason"]),
            output_sha256=prefixed_sha256(raw),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "model-selection/v3",
            "trust": "untrusted-model-output",
            "hypotheses": [
                {
                    "ordinal": item["ordinal"],
                    "incident_class": item["incident_class"],
                    "evidence_ids": list(cast(Sequence[str], item["evidence_ids"])),
                }
                for item in self.hypotheses
            ],
            "query_keys": list(self.query_keys),
            "stop_reason": self.stop_reason,
            "output_sha256": self.output_sha256,
        }


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


def finalize_adaptive_response_packet(body: Mapping[str, Any]) -> dict[str, Any]:
    packet = finalize_derived_record(body, id_field="packet_id", id_prefix="response-packet")
    validate_adaptive_response_packet(packet)
    return packet


def finalize_reference_evidence(body: Mapping[str, Any]) -> dict[str, Any]:
    evidence = finalize_derived_record(
        body,
        id_field="evidence_bundle_id",
        id_prefix="reference-evidence",
    )
    validate_reference_evidence(evidence)
    return evidence


def finalize_reference_response_packet(body: Mapping[str, Any]) -> dict[str, Any]:
    packet = finalize_derived_record(body, id_field="packet_id", id_prefix="response-packet")
    validate_reference_response_packet(packet)
    return packet


def _validate_packet_digest(value: Mapping[str, Any]) -> None:
    derivation_input = {
        key: child for key, child in value.items() if key not in {"packet_id", "derivation_sha256"}
    }
    expected = prefixed_sha256(canonical_json_bytes(derivation_input))
    if value.get("derivation_sha256") != expected or value.get("packet_id") != (
        f"response-packet:{expected.removeprefix('sha256:')}"
    ):
        raise ContractError("packet-digest")


_REFERENCE_PROJECTION_KEYS = frozenset(
    {
        "schema",
        "request_id",
        "incident_id",
        "query_keys",
        "evidence_ids",
        "observations",
        "projection_sha256",
    }
)
_REFERENCE_OBSERVATION_KEYS = frozenset(
    {
        "schema",
        "request_id",
        "incident_id",
        "event_id",
        "signal",
        "fixture_id",
        "run_id",
        "job_id",
        "worker_id",
        "trace_id",
        "artifact_id",
        "config_sha256",
        "resource_sha256",
        "transform_id",
        "observed_at",
        "emitted_at",
        "retrieved_at",
        "attributes",
        "provenance",
        "fact_id",
        "fact_sha256",
    }
)


def _validate_reference_projection(
    value: Any,
    *,
    request_id: Any,
    incident_id: Any,
) -> tuple[Mapping[str, Any], ...]:
    code = "runtime-projection-binding"
    if not isinstance(value, Mapping) or set(value) != _REFERENCE_PROJECTION_KEYS:
        raise ContractError(code)
    observations = value.get("observations")
    query_keys = value.get("query_keys")
    evidence_ids = value.get("evidence_ids")
    if (
        value.get("schema") != "runtime-evidence-projection/v1"
        or value.get("request_id") != request_id
        or value.get("incident_id") != incident_id
        or not isinstance(observations, list)
        or not isinstance(query_keys, list)
        or not isinstance(evidence_ids, list)
    ):
        raise ContractError(code)
    parsed: list[Mapping[str, Any]] = []
    observed_queries: list[str] = []
    observed_evidence_ids: list[str] = []
    for item in observations:
        if not isinstance(item, Mapping) or set(item) != _REFERENCE_OBSERVATION_KEYS:
            raise ContractError(code)
        fact_body = {
            key: child for key, child in item.items() if key not in {"fact_id", "fact_sha256"}
        }
        fact_sha256 = prefixed_sha256(canonical_json_bytes(fact_body))
        provenance = item.get("provenance")
        if (
            item.get("request_id") != request_id
            or item.get("incident_id") != incident_id
            or item.get("fact_sha256") != fact_sha256
            or item.get("fact_id") != f"runtime-fact:{fact_sha256.removeprefix('sha256:')}"
            or not isinstance(provenance, Mapping)
            or not isinstance(provenance.get("query_key"), str)
            or not isinstance(provenance.get("evidence_id"), str)
        ):
            raise ContractError(code)
        selected_query = cast(str, provenance["query_key"])
        selected_evidence = cast(str, provenance["evidence_id"])
        if selected_query not in observed_queries:
            observed_queries.append(selected_query)
        if selected_evidence not in observed_evidence_ids:
            observed_evidence_ids.append(selected_evidence)
        parsed.append(cast(Mapping[str, Any], item))
    projection_body = {key: child for key, child in value.items() if key != "projection_sha256"}
    if (
        value.get("projection_sha256") != prefixed_sha256(canonical_json_bytes(projection_body))
        or query_keys != observed_queries
        or evidence_ids != observed_evidence_ids
    ):
        raise ContractError(code)
    return tuple(parsed)


def _validate_reference_assessment_chain(
    *,
    expected: Mapping[str, Any],
    operational: Mapping[str, Any],
    class_assessments: Sequence[Mapping[str, Any]],
    reconciliation: Mapping[str, Any],
    projection: Any,
    request_id: Any,
    incident_id: Any,
) -> None:
    code = "assessment-chain-binding"
    try:
        expected_input = {
            "schema": "reference-expected-state/v1",
            "expected_state_id": expected["expected_state_id"],
            "expected_state_sha256": expected["expected_state_sha256"],
            "scenario_id": expected["scenario_id"],
            "fixture_id": expected["fixture_id"],
            "run_id": expected["run_id"],
            "evidence_window": expected["evidence_window"],
            "approved": expected["approved"],
            "scope": expected["scope"],
        }
        derived_expected = assess_expected_state(expected_input)
        if (
            derived_expected.status is not AssessmentStatus.SUPPORTED
            or derived_expected.to_dict() != _plain_json(expected)
        ):
            raise ContractError(code)
        observations = _validate_reference_projection(
            projection,
            request_id=request_id,
            incident_id=incident_id,
        )
        derived_operational = assess_operational_evidence(derived_expected, observations)
        derived_classes = assess_incident_classes(derived_expected, derived_operational)
        derived_reconciliation = reconcile_diagnosis(
            derived_expected,
            derived_operational,
            derived_classes,
        )
        if (
            derived_operational.to_dict() != _plain_json(operational)
            or [item.to_dict() for item in derived_classes] != _plain_json(class_assessments)
            or derived_reconciliation.to_dict() != _plain_json(reconciliation)
        ):
            raise ContractError(code)
    except ContractError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ContractError(code) from error


def validate_reference_evidence(value: Mapping[str, Any]) -> None:
    validate_contract("reference-evidence-v3.schema.json", value)
    body = {
        key: child
        for key, child in value.items()
        if key not in {"evidence_bundle_id", "derivation_sha256"}
    }
    derivation = prefixed_sha256(canonical_json_bytes(body))
    if (
        value["derivation_sha256"] != derivation
        or value["evidence_bundle_id"] != f"reference-evidence:{derivation.removeprefix('sha256:')}"
    ):
        raise ContractError("reference-evidence-digest")
    projection = cast(Mapping[str, Any], value["runtime_projection"])
    if (
        projection.get("schema") != "runtime-evidence-projection/v1"
        or projection.get("request_id") != value["request_id"]
        or projection.get("incident_id") != value["incident_id"]
        or not set(cast(Sequence[str], projection.get("query_keys", ()))).issubset(
            set(cast(Sequence[str], value["query_keys"]))
        )
        or not set(cast(Sequence[str], projection.get("evidence_ids", ()))).issubset(
            set(cast(Sequence[str], value["evidence_ids"]))
        )
    ):
        raise ContractError("reference-evidence-binding")


def _validate_adaptive_invocations(
    invocations: Sequence[Mapping[str, Any]],
    *,
    incident_id: str,
    evidence_ids: set[str],
    policy_sha256: str,
) -> dict[str, Mapping[str, Any]]:
    invocation_by_id: dict[str, Mapping[str, Any]] = {}
    attempts: dict[str, int] = {}
    drafting_started = False
    for invocation in invocations:
        body = {
            key: child
            for key, child in invocation.items()
            if key not in {"invocation_id", "derivation_sha256"}
        }
        derivation = prefixed_sha256(canonical_json_bytes(body))
        invocation_id = cast(str, invocation["invocation_id"])
        turn_kind = cast(str, invocation["turn_kind"])
        attempt = cast(int, invocation["attempt"])
        usage = cast(Mapping[str, Any], invocation["usage"])
        result_class = invocation["result_class"]
        error_code = invocation["error_code"]
        output_sha256 = invocation["output_sha256"]
        observed_usage = usage["input_tokens"] is not None and usage["output_tokens"] is not None
        if (
            invocation.get("derivation_sha256") != derivation
            or invocation_id != f"model-invocation:{derivation.removeprefix('sha256:')}"
            or invocation_id in invocation_by_id
            or invocation.get("incident_id") != incident_id
            or invocation.get("policy_version") != ADAPTIVE_POLICY_VERSION
            or invocation.get("policy_sha256") != policy_sha256
            or invocation.get("prompt_version") != f"{turn_kind}/v2"
            or attempt != attempts.get(turn_kind, 0) + 1
            or list(cast(Sequence[str], invocation["input_evidence_ids"]))
            != sorted(cast(Sequence[str], invocation["input_evidence_ids"]))
            or not set(cast(Sequence[str], invocation["input_evidence_ids"])).issubset(evidence_ids)
            or usage["unobserved_model_calls"] > usage["model_calls"]
            or (drafting_started and turn_kind == "evidence-selection")
        ):
            raise ContractError("invocation-binding")
        if turn_kind == "response-drafting":
            drafting_started = True
        if result_class == "accepted":
            valid_result = (
                error_code is None
                and output_sha256 is not None
                and observed_usage
                and usage["unobserved_model_calls"] == 0
            )
        elif result_class in {"budget-rejected", "invalid"}:
            valid_result = (
                error_code is not None
                and output_sha256 is not None
                and observed_usage
                and usage["unobserved_model_calls"] == 0
            )
        else:
            valid_result = error_code is not None and output_sha256 is None
        if not valid_result:
            raise ContractError("invocation-result-binding")
        invocation_by_id[invocation_id] = invocation
        attempts[turn_kind] = attempt
    return invocation_by_id


def validate_response_packet(value: Mapping[str, Any]) -> None:
    if value.get("schema") == REFERENCE_RESPONSE_PACKET_VERSION:
        validate_reference_response_packet(value)
        return
    if value.get("schema") == ADAPTIVE_RESPONSE_PACKET_VERSION:
        validate_adaptive_response_packet(value)
        return
    validate_contract("response-packet-v1.schema.json", value)
    _validate_packet_digest(value)
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


def validate_adaptive_response_packet(value: Mapping[str, Any]) -> None:
    validate_contract("response-packet-v2.schema.json", value)
    _validate_packet_digest(value)
    policy = cast(Mapping[str, Any], value["policy_binding"])
    if policy != {
        "version": ADAPTIVE_POLICY_VERSION,
        "sha256": f"sha256:{ADAPTIVE_POLICY_CANONICAL_SHA256}",
    }:
        raise ContractError("packet-policy-binding")

    evidence_ids = set(cast(Sequence[str], value["evidence_ids"]))
    invocations = cast(Sequence[Mapping[str, Any]], value["invocation_records"])
    invocation_by_id = _validate_adaptive_invocations(
        invocations,
        incident_id=cast(str, value["incident_id"]),
        evidence_ids=evidence_ids,
        policy_sha256=cast(str, policy["sha256"]),
    )
    deterministic_result_ids = {
        item["result_id"]
        for item in cast(Sequence[Mapping[str, Any]], value["deterministic_results"])
    }

    trace = cast(Sequence[Mapping[str, Any]], value["adaptive_trace"])
    if [item["sequence"] for item in trace] != list(range(len(trace))):
        raise ContractError("adaptive-trace-sequence")
    baseline = trace[0]
    if (
        baseline.get("selected_by") != "policy"
        or baseline.get("query_key") != "alert.rule"
        or baseline.get("selection_request_sha256")
        != prefixed_sha256(canonical_json_bytes({"query_key": "alert.rule"}))
        or baseline.get("selection_invocation_id") is not None
        or baseline.get("selection_output_sha256") is not None
    ):
        raise ContractError("adaptive-trace-baseline")
    evidence_queries: set[str] = set()
    for entry in trace:
        evidence_id = entry.get("evidence_id")
        query_key = entry.get("query_key")
        if evidence_id is not None and evidence_id not in evidence_ids:
            raise ContractError("adaptive-trace-evidence")
        if query_key is not None and entry.get("selection_request_sha256") != prefixed_sha256(
            canonical_json_bytes({"query_key": query_key})
        ):
            raise ContractError("adaptive-trace-request")
        if evidence_id is not None:
            if not isinstance(query_key, str) or query_key in evidence_queries:
                raise ContractError("adaptive-trace-evidence")
            evidence_queries.add(query_key)
        if entry.get("selected_by") == "model":
            invocation = invocation_by_id.get(cast(str, entry.get("selection_invocation_id")))
            if (
                invocation is None
                or invocation.get("turn_kind") != "evidence-selection"
                or invocation.get("output_sha256") != entry.get("selection_output_sha256")
            ):
                raise ContractError("adaptive-trace-invocation")
        if (entry.get("disposition") == "resolved") != (
            entry.get("validator_result_id") is not None
        ):
            raise ContractError("adaptive-trace-disposition")
        if (
            entry.get("validator_result_id") is not None
            and entry.get("validator_result_id") not in deterministic_result_ids
        ):
            raise ContractError("adaptive-trace-disposition")
    if trace[-1].get("disposition") == "continue" or value["stop_reason"] != trace[-1].get(
        "reason_code"
    ):
        raise ContractError("adaptive-trace-terminal")

    hypotheses = cast(Sequence[Mapping[str, Any]], value["hypotheses"])
    if [item["ordinal"] for item in hypotheses] != list(range(1, len(hypotheses) + 1)):
        raise ContractError("hypothesis-order")
    if len({item["hypothesis_key"] for item in hypotheses}) != len(hypotheses) or any(
        not set(cast(Sequence[str], item["evidence_ids"])).issubset(evidence_ids)
        for item in hypotheses
    ):
        raise ContractError("hypothesis-binding")

    selected = [
        cast(str, item["query_key"])
        for item in trace[1:]
        if item.get("query_key") is not None and item.get("evidence_id") is not None
    ]
    if value["status"] == "resolved":
        result_ids = {
            item["result_id"]
            for item in cast(Sequence[Mapping[str, Any]], value["deterministic_results"])
            if item.get("status") == "resolved"
        }
        if (
            value["stop_reason"] != "sufficient-evidence"
            or not hypotheses
            or not set(selected).intersection(EXACT_QUERY_KEYS)
            or not set(selected).intersection(COHORT_QUERY_KEYS)
            or trace[-1].get("disposition") != "resolved"
            or trace[-1].get("reason_code") != "sufficient-evidence"
            or trace[-1].get("validator_result_id") not in result_ids
            or any(
                item.get("result_class") != "accepted"
                for item in invocations
                if item.get("turn_kind") == "evidence-selection"
            )
        ):
            raise ContractError("adaptive-sufficiency")

    advisory = value.get("model_advisory")
    if isinstance(advisory, Mapping) and not any(
        item.get("turn_kind") == "response-drafting"
        and item.get("result_class") == "accepted"
        and item.get("output_sha256") == advisory.get("output_sha256")
        for item in invocations
    ):
        raise ContractError("model-advisory-binding")

    legacy_body = {
        "schema": RESPONSE_PACKET_VERSION,
        "incident_id": value["incident_id"],
        "version": 1,
        "status": value["status"],
        "fixed_window": value["fixed_window"],
        "evidence_ids": value["evidence_ids"],
        "deterministic_results": value["deterministic_results"],
        "claims": value["claims"],
        "scope": value["scope"],
        "invocation_records": [],
        "budget_use": value["budget_use"],
        "unresolved_items": value["unresolved_items"],
        "candidate_plan": value["candidate_plan"],
        "no_action_reason": value["no_action_reason"],
        "model_advisory": value["model_advisory"],
        "state_history": value["state_history"],
        "finalized_at": value["finalized_at"],
    }
    finalize_response_packet(legacy_body)


def validate_reference_response_packet(value: Mapping[str, Any]) -> None:
    validate_contract("response-packet-v3.schema.json", value)
    _validate_packet_digest(value)
    if value["policy_binding"] != {
        "version": REFERENCE_POLICY_VERSION,
        "sha256": REFERENCE_POLICY_SHA256,
    }:
        raise ContractError("packet-policy-binding")
    if value["authority_policy"] != [
        "gemini-query-selection-only",
        "grafana-read-only-evidence",
        "deterministic-validators-authoritative",
        "human-approval-required-for-action",
    ]:
        raise ContractError("packet-authority-policy")

    expected = cast(Mapping[str, Any], value["expected_state_assessment"])
    operational = cast(Mapping[str, Any], value["operational_evidence_assessment"])
    class_assessments = cast(Sequence[Mapping[str, Any]], value["incident_class_assessments"])
    reconciliation = cast(Mapping[str, Any], value["diagnosis_reconciliation"])
    action_intent = value["action_intent"]
    evidence_ids = set(cast(Sequence[str], value["evidence_ids"]))
    reference_evidence = cast(Mapping[str, Any], value["reference_evidence"])
    validate_reference_evidence(reference_evidence)
    if (
        reference_evidence.get("incident_id") != value["incident_id"]
        or reference_evidence.get("scenario_id") != value["scenario_id"]
        or reference_evidence.get("fixture_id") != value["fixture_id"]
        or reference_evidence.get("run_id") != value["run_id"]
        or reference_evidence.get("expected_state_sha256") != expected.get("expected_state_sha256")
        or reference_evidence.get("evidence_ids") != value["evidence_ids"]
        or reference_evidence.get("runtime_projection") != value["runtime_evidence_projection"]
    ):
        raise ContractError("reference-evidence-binding")
    _validate_reference_assessment_chain(
        expected=expected,
        operational=operational,
        class_assessments=class_assessments,
        reconciliation=reconciliation,
        projection=value["runtime_evidence_projection"],
        request_id=reference_evidence.get("request_id"),
        incident_id=value["incident_id"],
    )
    if (
        expected.get("schema") != "expected-state-assessment/v1"
        or expected.get("scenario_id") != value["scenario_id"]
        or expected.get("fixture_id") != value["fixture_id"]
        or expected.get("run_id") != value["run_id"]
        or operational.get("schema") != "operational-evidence-assessment/v1"
        or operational.get("expected_state_assessment_id") != expected.get("assessment_id")
        or reconciliation.get("schema") != "diagnosis-reconciliation/v1"
        or reconciliation.get("expected_state_assessment_id") != expected.get("assessment_id")
        or reconciliation.get("operational_evidence_assessment_id")
        != operational.get("assessment_id")
        or [item.get("incident_class") for item in class_assessments]
        != list(REFERENCE_INCIDENT_CLASSES)
        or reconciliation.get("class_assessment_ids")
        != [item.get("assessment_id") for item in class_assessments]
    ):
        raise ContractError("assessment-binding")

    projection = value["runtime_evidence_projection"]
    if projection is not None:
        projection_mapping = cast(Mapping[str, Any], projection)
        if (
            projection_mapping.get("schema") != "runtime-evidence-projection/v1"
            or projection_mapping.get("incident_id") != value["incident_id"]
            or not set(cast(Sequence[str], projection_mapping.get("evidence_ids", ()))).issubset(
                evidence_ids
            )
        ):
            raise ContractError("evidence-binding")

    trace = cast(Sequence[Mapping[str, Any]], value["selection_trace"])
    if [entry["sequence"] for entry in trace] != list(range(len(trace))):
        raise ContractError("selection-trace-sequence")
    if trace[0]["selected_by"] != "policy" or trace[0]["query_key"] != "alert.rule":
        raise ContractError("selection-trace-baseline")
    if any(entry["selected_by"] != "model" for entry in trace[1:]):
        raise ContractError("selection-trace-authority")
    traced_queries = [cast(str, entry["query_key"]) for entry in trace]
    if (
        len(set(traced_queries)) != len(traced_queries)
        or reference_evidence.get("query_keys") != traced_queries
        or trace[-1].get("operational_assessment_id") != operational.get("assessment_id")
        or trace[-1].get("reconciliation_id") != reconciliation.get("reconciliation_id")
    ):
        raise ContractError("selection-trace-query")
    for entry in trace:
        evidence_id = entry.get("evidence_id")
        if evidence_id is not None and evidence_id not in evidence_ids:
            raise ContractError("selection-trace-evidence")

    selection = value["model_selection"]
    invocation = value["model_invocation"]
    if isinstance(invocation, Mapping):
        invocation_status = invocation.get("status")
        invocation_input_tokens = invocation.get("input_tokens")
        invocation_output_tokens = invocation.get("output_tokens")
        invocation_output_sha256 = invocation.get("output_sha256")
        invocation_model_calls = cast(int, invocation.get("model_calls"))
        invocation_unobserved_model_calls = cast(
            int,
            invocation.get("unobserved_model_calls"),
        )
        usage_is_unknown = invocation_input_tokens is None and invocation_output_tokens is None
        usage_is_observed = isinstance(invocation_input_tokens, int) and isinstance(
            invocation_output_tokens, int
        )
        if (
            not (usage_is_unknown or usage_is_observed)
            or invocation_unobserved_model_calls > invocation_model_calls
            or (invocation_unobserved_model_calls > 0 and not usage_is_unknown)
            or (invocation_status == "failed" and invocation_output_sha256 is not None)
            or (
                invocation_status in {"accepted", "invalid"}
                and (
                    invocation_output_sha256 is None
                    or not usage_is_observed
                    or invocation_unobserved_model_calls != 0
                )
            )
        ):
            raise ContractError("model-invocation-binding")
    if (
        selection is None
        and isinstance(invocation, Mapping)
        and invocation.get("status") == ("accepted")
    ):
        raise ContractError("model-selection-binding")
    if selection is not None:
        selection_mapping = cast(Mapping[str, Any], selection)
        hypotheses = cast(Sequence[Mapping[str, Any]], selection_mapping.get("hypotheses", ()))
        selection_contract = {
            key: child
            for key, child in selection_mapping.items()
            if key not in {"trust", "output_sha256"}
        }
        validate_contract("model-selection-v3.schema.json", selection_contract)
        if (
            invocation is None
            or cast(Mapping[str, Any], invocation).get("status") != "accepted"
            or selection_mapping.get("schema") != "model-selection/v3"
            or selection_mapping.get("trust") != "untrusted-model-output"
            or selection_mapping.get("query_keys") != traced_queries
            or selection_mapping.get("output_sha256")
            != cast(Mapping[str, Any], invocation).get("output_sha256")
            or [item.get("ordinal") for item in hypotheses] != list(range(1, len(hypotheses) + 1))
            or any(
                not set(cast(Sequence[str], item.get("evidence_ids", ()))).issubset(evidence_ids)
                for item in hypotheses
            )
        ):
            raise ContractError("model-selection-binding")

    spans = cast(Mapping[str, Any], value["agent_trace"])["spans"]
    if [span["sequence"] for span in spans] != list(range(len(spans))):
        raise ContractError("agent-trace-sequence")
    for span in spans:
        unobserved_model_calls = cast(int, span.get("unobserved_model_calls"))
        if (
            (span.get("stage") != "gemini" and unobserved_model_calls != 0)
            or unobserved_model_calls > cast(int, span.get("attempts"))
            or (
                unobserved_model_calls > 0
                and (span.get("input_tokens") is not None or span.get("output_tokens") is not None)
            )
        ):
            raise ContractError("agent-trace-usage")
    if isinstance(invocation, Mapping):
        model_spans = [span for span in spans if span.get("stage") == "gemini"]
        if len(model_spans) != 1:
            raise ContractError("agent-trace-model-binding")
        model_span = model_spans[0]
        if (
            model_span.get("input_tokens") != invocation.get("input_tokens")
            or model_span.get("output_tokens") != invocation.get("output_tokens")
            or model_span.get("attempts") != invocation.get("model_calls")
            or model_span.get("unobserved_model_calls") != invocation.get("unobserved_model_calls")
        ):
            raise ContractError("agent-trace-model-binding")

    resolved = value["status"] == "resolved"
    if resolved:
        if (
            reconciliation.get("status") != "supported"
            or not isinstance(action_intent, Mapping)
            or action_intent != reconciliation.get("action_intent")
            or action_intent.get("target") != "simulator"
            or action_intent.get("requires_human_approval") is not True
            or action_intent.get("authorizes_execution") is not False
            or value["no_action_reason"] is not None
            or selection is None
            or not isinstance(invocation, Mapping)
            or invocation.get("status") != "accepted"
            or trace[-1]["disposition"] != "resolved"
            or cast(Mapping[str, Any], selection).get("stop_reason") != "sufficient-evidence"
        ):
            raise ContractError("packet-state")
    elif action_intent is not None or value["no_action_reason"] is None:
        raise ContractError("packet-state")
