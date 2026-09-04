from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal, cast

EXPECTED_STATE_VERSION = "reference-expected-state/v1"
EXPECTED_STATE_ASSESSMENT_VERSION = "expected-state-assessment/v1"
OPERATIONAL_EVIDENCE_ASSESSMENT_VERSION = "operational-evidence-assessment/v1"
INCIDENT_CLASS_ASSESSMENT_VERSION = "incident-class-assessment/v1"
DIAGNOSIS_RECONCILIATION_VERSION = "diagnosis-reconciliation/v1"
ACTION_INTENT_VERSION = "simulator-action-intent/v1"
NORMALIZED_RUNTIME_OBSERVATION_VERSION = "normalized-runtime-observation/v1"

_SCENARIOS = frozenset(
    {
        "tos-resource-resolution-drift-v1",
        "tos-config-rollout-drift-v1",
        "tos-stale-derivative-cache-v1",
    }
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_PREFIXED_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")

_EXPECTED_KEYS = frozenset(
    {
        "schema",
        "expected_state_id",
        "expected_state_sha256",
        "scenario_id",
        "fixture_id",
        "run_id",
        "evidence_window",
        "approved",
        "scope",
    }
)
_APPROVED_KEYS = frozenset(
    {
        "resource_sha256",
        "config_sha256",
        "config_generation",
        "frame_pipeline_sha256",
        "derivative_parent_sha256",
        "derivative_generation",
        "cache_key",
    }
)
_SCOPE_KEYS = frozenset({"affected_job_ids", "safe_job_ids"})
_WINDOW_KEYS = frozenset({"start", "end"})
_FACT_BODY_KEYS = (
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
)
_SEMANTIC_FIELDS = (
    "effective_resource_sha256",
    "effective_config_sha256",
    "config_generation",
    "frame_pipeline_sha256",
    "derivative_parent_sha256",
    "derivative_generation",
    "cache_key",
)
_CAUSAL_FIELDS = tuple(name for name in _SEMANTIC_FIELDS if name != "frame_pipeline_sha256")
_EXPECTED_SEMANTIC_FIELDS = MappingProxyType(
    {
        "effective_resource_sha256": "resource_sha256",
        "effective_config_sha256": "config_sha256",
        "config_generation": "config_generation",
        "frame_pipeline_sha256": "frame_pipeline_sha256",
        "derivative_parent_sha256": "derivative_parent_sha256",
        "derivative_generation": "derivative_generation",
        "cache_key": "cache_key",
    }
)
_ATTRIBUTE_FIELDS = MappingProxyType(
    {
        "effective_resource_sha256": ("runtime.effective_resource_sha256",),
        "effective_config_sha256": ("runtime.effective_config_sha256",),
        "config_generation": ("runtime.config_generation",),
        "frame_pipeline_sha256": ("runtime.frame_pipeline_sha256",),
        "derivative_parent_sha256": ("derivative.parent_sha256",),
        "derivative_generation": ("cache.generation", "derivative.generation"),
        "cache_key": ("cache.key",),
        "reference_state": ("declared_reference.state",),
    }
)
_MATCH_ATTRIBUTE_FIELDS = MappingProxyType(
    {
        "effective_resource_sha256": ("declared_reference.effective_resource_matches_approved"),
        "effective_config_sha256": ("declared_reference.effective_config_matches_approved"),
        "config_generation": "declared_reference.config_generation_matches_approved",
        "frame_pipeline_sha256": ("declared_reference.frame_pipeline_matches_approved"),
        "derivative_parent_sha256": ("declared_reference.derivative_parent_matches_approved"),
        "derivative_generation": ("declared_reference.derivative_generation_matches_approved"),
        "cache_key": "declared_reference.cache_key_matches_approved",
    }
)
_APPROVED_STATE_ATTRIBUTE = "declared_reference.approved_state_sha256"
_METRIC_SCOPE_ATTRIBUTES = frozenset(
    {
        "reference.evidence_scope",
        "reference.affected_representative_count",
        "reference.protected_representative_count",
        "reference.population_affected_artifact_count",
        "reference.population_protected_artifact_count",
    }
)
_SIGNAL_REQUIRED_ATTRIBUTES = MappingProxyType(
    {
        "metric": frozenset(
            {
                "declared_reference.state",
                _APPROVED_STATE_ATTRIBUTE,
                *_MATCH_ATTRIBUTE_FIELDS.values(),
                *_METRIC_SCOPE_ATTRIBUTES,
            }
        ),
        "log": frozenset(
            {
                "runtime.effective_resource_sha256",
                "runtime.effective_config_sha256",
                "runtime.config_generation",
                "runtime.frame_pipeline_sha256",
                "cache.key",
            }
        ),
        "trace": frozenset(
            {
                "runtime.frame_pipeline_sha256",
                "derivative.parent_sha256",
                "cache.generation",
                "cache.key",
            }
        ),
    }
)
_ROLE_BOUND_ATTRIBUTES = frozenset(
    {attribute for attributes in _ATTRIBUTE_FIELDS.values() for attribute in attributes}
    | set(_MATCH_ATTRIBUTE_FIELDS.values())
    | {_APPROVED_STATE_ATTRIBUTE}
    | set(_METRIC_SCOPE_ATTRIBUTES)
)
_QUERY_SIGNALS = MappingProxyType(
    {
        "metric.correlated-observations": "metric",
        "metric.worker-cohort": "metric",
        "log.correlated-events": "log",
        "log.config-cohort": "log",
        "trace.by-id": "trace",
    }
)
_QUERY_TOOLS = MappingProxyType(
    {
        "metric.correlated-observations": "query_prometheus",
        "metric.worker-cohort": "query_prometheus",
        "log.correlated-events": "query_loki_logs",
        "log.config-cohort": "query_loki_logs",
        "trace.by-id": "tempo_get-trace",
    }
)


class IncidentClass(StrEnum):
    RESOURCE_RESOLUTION_DRIFT = "resource-resolution-drift/v1"
    CONFIGURATION_ROLLOUT_DRIFT = "configuration-rollout-drift/v1"
    STALE_DERIVATIVE_CACHE = "stale-derivative-cache/v1"


class AssessmentStatus(StrEnum):
    SUPPORTED = "supported"
    REJECTED = "rejected"
    INSUFFICIENT = "insufficient"
    CONFLICTING = "conflicting"


_ACTION_COMMANDS: Mapping[
    IncidentClass, Literal["reconcile-resource", "pin-rollout", "invalidate-cache"]
] = MappingProxyType(
    {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: "reconcile-resource",
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: "pin-rollout",
        IncidentClass.STALE_DERIVATIVE_CACHE: "invalidate-cache",
    }
)
_CLASS_CHANGED_FIELDS: Mapping[IncidentClass, tuple[str, ...]] = MappingProxyType(
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


class _AssessmentFailure(ValueError):
    def __init__(self, code: str, status: AssessmentStatus = AssessmentStatus.INSUFFICIENT) -> None:
        self.code = code
        self.status = status
        super().__init__(code)


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(child) for child in value]
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(child) for child in value)
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    def validate(child: Any) -> None:
        if isinstance(child, float):
            raise TypeError("floating-point values are not canonical")
        if isinstance(child, Mapping):
            for key, nested in child.items():
                if not isinstance(key, str):
                    raise TypeError("canonical object keys must be strings")
                validate(nested)
        elif isinstance(child, (tuple, list)):
            for nested in child:
                validate(nested)

    plain = _plain(value)
    validate(plain)
    return json.dumps(
        plain,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json_bytes(value)).hexdigest()}"


def _derived_identity(prefix: str, body: Mapping[str, Any]) -> tuple[str, str]:
    digest = _sha256(body)
    return f"{prefix}:{digest.removeprefix('sha256:')}", digest


def _reasons(*values: str) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _mapping(value: Any, code: str) -> dict[str, Any]:
    plain = _plain(value)
    if not isinstance(plain, dict):
        raise _AssessmentFailure(code)
    return plain


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], code: str) -> None:
    if set(value) != expected:
        raise _AssessmentFailure(code)


def _identifier(value: Any, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise _AssessmentFailure(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise _AssessmentFailure(code)
    return value if value.startswith("sha256:") else f"sha256:{value}"


def _positive_integer(value: Any, code: str) -> int:
    if isinstance(value, bool):
        raise _AssessmentFailure(code)
    if isinstance(value, int) and value >= 1:
        return value
    if isinstance(value, str) and _POSITIVE_INTEGER.fullmatch(value) is not None:
        return int(value)
    raise _AssessmentFailure(code)


def _timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str):
        raise _AssessmentFailure(code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise _AssessmentFailure(code) from error
    if parsed.tzinfo is None:
        raise _AssessmentFailure(code)
    return parsed.astimezone(UTC)


def _timestamp_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ExpectedStateAssessment:
    status: AssessmentStatus
    expected_state_id: str | None
    expected_state_sha256: str | None
    scenario_id: str | None
    fixture_id: str | None
    run_id: str | None
    window_start: str | None
    window_end: str | None
    approved: Mapping[str, str | int]
    affected_job_ids: tuple[str, ...]
    safe_job_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    assessment_id: str = field(init=False)
    derivation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "approved", _freeze(_plain(self.approved)))
        object.__setattr__(self, "affected_job_ids", tuple(self.affected_job_ids))
        object.__setattr__(self, "safe_job_ids", tuple(self.safe_job_ids))
        object.__setattr__(self, "reason_codes", _reasons(*self.reason_codes))
        identity, digest = _derived_identity("expected-assessment", self._body())
        object.__setattr__(self, "assessment_id", identity)
        object.__setattr__(self, "derivation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "schema": EXPECTED_STATE_ASSESSMENT_VERSION,
            "status": self.status.value,
            "expected_state_id": self.expected_state_id,
            "expected_state_sha256": self.expected_state_sha256,
            "scenario_id": self.scenario_id,
            "fixture_id": self.fixture_id,
            "run_id": self.run_id,
            "evidence_window": {
                "start": self.window_start,
                "end": self.window_end,
            },
            "approved": _plain(self.approved),
            "scope": {
                "affected_job_ids": list(self.affected_job_ids),
                "safe_job_ids": list(self.safe_job_ids),
            },
            "reason_codes": list(self.reason_codes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "assessment_id": self.assessment_id,
            "derivation_sha256": self.derivation_sha256,
        }


@dataclass(frozen=True, slots=True)
class OperationalEvidenceAssessment:
    status: AssessmentStatus
    expected_state_assessment_id: str
    request_id: str | None
    incident_id: str | None
    fixture_id: str | None
    run_id: str | None
    job_facts: Mapping[str, Mapping[str, Any]]
    fact_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    assessment_id: str = field(init=False)
    derivation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "job_facts", _freeze(_plain(self.job_facts)))
        object.__setattr__(self, "fact_ids", tuple(sorted(set(self.fact_ids))))
        object.__setattr__(self, "evidence_ids", tuple(sorted(set(self.evidence_ids))))
        object.__setattr__(self, "reason_codes", _reasons(*self.reason_codes))
        identity, digest = _derived_identity("operational-assessment", self._body())
        object.__setattr__(self, "assessment_id", identity)
        object.__setattr__(self, "derivation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "schema": OPERATIONAL_EVIDENCE_ASSESSMENT_VERSION,
            "status": self.status.value,
            "expected_state_assessment_id": self.expected_state_assessment_id,
            "request_id": self.request_id,
            "incident_id": self.incident_id,
            "fixture_id": self.fixture_id,
            "run_id": self.run_id,
            "job_facts": _plain(self.job_facts),
            "fact_ids": list(self.fact_ids),
            "evidence_ids": list(self.evidence_ids),
            "reason_codes": list(self.reason_codes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "assessment_id": self.assessment_id,
            "derivation_sha256": self.derivation_sha256,
        }


@dataclass(frozen=True, slots=True)
class IncidentClassAssessment:
    status: AssessmentStatus
    incident_class: IncidentClass
    expected_state_assessment_id: str
    operational_evidence_assessment_id: str
    affected_job_ids: tuple[str, ...]
    safe_job_ids: tuple[str, ...]
    evidence_fact_ids: tuple[str, ...]
    cause: Mapping[str, Any]
    reason_codes: tuple[str, ...]
    assessment_id: str = field(init=False)
    derivation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "affected_job_ids", tuple(sorted(set(self.affected_job_ids))))
        object.__setattr__(self, "safe_job_ids", tuple(sorted(set(self.safe_job_ids))))
        object.__setattr__(self, "evidence_fact_ids", tuple(sorted(set(self.evidence_fact_ids))))
        object.__setattr__(self, "cause", _freeze(_plain(self.cause)))
        object.__setattr__(self, "reason_codes", _reasons(*self.reason_codes))
        if (
            bool(set(self.affected_job_ids) & set(self.safe_job_ids))
            or any(_IDENTIFIER.fullmatch(value) is None for value in self.affected_job_ids)
            or any(_IDENTIFIER.fullmatch(value) is None for value in self.safe_job_ids)
            or any(
                not value.startswith("runtime-fact:")
                or _DIGEST.fullmatch(value.removeprefix("runtime-fact:")) is None
                for value in self.evidence_fact_ids
            )
            or (self.status is AssessmentStatus.SUPPORTED) != bool(self.cause)
        ):
            raise ValueError("incident class assessment invalid")
        identity, digest = _derived_identity("class-assessment", self._body())
        object.__setattr__(self, "assessment_id", identity)
        object.__setattr__(self, "derivation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "schema": INCIDENT_CLASS_ASSESSMENT_VERSION,
            "status": self.status.value,
            "incident_class": self.incident_class.value,
            "expected_state_assessment_id": self.expected_state_assessment_id,
            "operational_evidence_assessment_id": self.operational_evidence_assessment_id,
            "scope": {
                "affected_job_ids": list(self.affected_job_ids),
                "safe_job_ids": list(self.safe_job_ids),
            },
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "cause": _plain(self.cause),
            "reason_codes": list(self.reason_codes),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "assessment_id": self.assessment_id,
            "derivation_sha256": self.derivation_sha256,
        }


@dataclass(frozen=True, slots=True)
class ActionIntent:
    reconciliation_id: str
    incident_class: IncidentClass
    command: Literal["reconcile-resource", "pin-rollout", "invalidate-cache"]
    affected_job_ids: tuple[str, ...]
    evidence_fact_ids: tuple[str, ...]
    parameters: Mapping[str, Any]
    target: Literal["simulator"] = "simulator"
    requires_human_approval: bool = True
    authorizes_execution: bool = False
    action_intent_id: str = field(init=False)
    derivation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        parameters = _plain(self.parameters)
        required_parameter_keys = {"changed_fields", "expected", "observed"}
        if self.incident_class is IncidentClass.STALE_DERIVATIVE_CACHE:
            required_parameter_keys.add("cache_key")
        if (
            not isinstance(parameters, dict)
            or set(parameters) != required_parameter_keys
            or parameters.get("changed_fields") != list(_CLASS_CHANGED_FIELDS[self.incident_class])
            or not isinstance(parameters.get("expected"), dict)
            or set(parameters["expected"]) != set(_CLASS_CHANGED_FIELDS[self.incident_class])
            or not isinstance(parameters.get("observed"), dict)
            or set(parameters["observed"]) != set(_CLASS_CHANGED_FIELDS[self.incident_class])
            or any(
                parameters["expected"][name] == parameters["observed"][name]
                for name in _CLASS_CHANGED_FIELDS[self.incident_class]
            )
            or (
                self.incident_class is IncidentClass.STALE_DERIVATIVE_CACHE
                and (
                    not isinstance(parameters.get("cache_key"), str)
                    or _IDENTIFIER.fullmatch(parameters["cache_key"]) is None
                )
            )
            or self.target != "simulator"
            or self.requires_human_approval is not True
            or self.authorizes_execution is not False
            or self.command != _ACTION_COMMANDS[self.incident_class]
            or not self.reconciliation_id.startswith("diagnosis-reconciliation:")
            or _DIGEST.fullmatch(self.reconciliation_id.removeprefix("diagnosis-reconciliation:"))
            is None
            or not self.affected_job_ids
            or not self.evidence_fact_ids
            or any(_IDENTIFIER.fullmatch(value) is None for value in self.affected_job_ids)
            or any(
                not value.startswith("runtime-fact:")
                or _DIGEST.fullmatch(value.removeprefix("runtime-fact:")) is None
                for value in self.evidence_fact_ids
            )
        ):
            raise ValueError("action intent authority invalid")
        object.__setattr__(self, "affected_job_ids", tuple(sorted(set(self.affected_job_ids))))
        object.__setattr__(self, "evidence_fact_ids", tuple(sorted(set(self.evidence_fact_ids))))
        object.__setattr__(self, "parameters", _freeze(parameters))
        identity, digest = _derived_identity("action-intent", self._body())
        object.__setattr__(self, "action_intent_id", identity)
        object.__setattr__(self, "derivation_sha256", digest)

    def _body(self) -> dict[str, Any]:
        return {
            "schema": ACTION_INTENT_VERSION,
            "reconciliation_id": self.reconciliation_id,
            "incident_class": self.incident_class.value,
            "command": self.command,
            "target": self.target,
            "requires_human_approval": self.requires_human_approval,
            "authorizes_execution": self.authorizes_execution,
            "affected_job_ids": list(self.affected_job_ids),
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "parameters": _plain(self.parameters),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._body(),
            "action_intent_id": self.action_intent_id,
            "derivation_sha256": self.derivation_sha256,
        }


@dataclass(frozen=True, slots=True)
class DiagnosisReconciliation:
    reconciliation_id: str
    status: AssessmentStatus
    incident_class: IncidentClass | None
    expected_state_assessment_id: str
    operational_evidence_assessment_id: str
    class_assessment_ids: tuple[str, ...]
    affected_job_ids: tuple[str, ...]
    safe_job_ids: tuple[str, ...]
    evidence_fact_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    action_intent: ActionIntent | None
    derivation_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "class_assessment_ids", tuple(self.class_assessment_ids))
        object.__setattr__(self, "affected_job_ids", tuple(sorted(set(self.affected_job_ids))))
        object.__setattr__(self, "safe_job_ids", tuple(sorted(set(self.safe_job_ids))))
        object.__setattr__(self, "evidence_fact_ids", tuple(sorted(set(self.evidence_fact_ids))))
        object.__setattr__(self, "reason_codes", _reasons(*self.reason_codes))
        if (
            bool(set(self.affected_job_ids) & set(self.safe_job_ids))
            or any(_IDENTIFIER.fullmatch(value) is None for value in self.affected_job_ids)
            or any(_IDENTIFIER.fullmatch(value) is None for value in self.safe_job_ids)
            or any(
                not value.startswith("runtime-fact:")
                or _DIGEST.fullmatch(value.removeprefix("runtime-fact:")) is None
                for value in self.evidence_fact_ids
            )
            or (self.status is AssessmentStatus.SUPPORTED)
            != (self.incident_class is not None and self.action_intent is not None)
            or self.action_intent is not None
            and (
                self.action_intent.reconciliation_id != self.reconciliation_id
                or self.action_intent.incident_class is not self.incident_class
                or self.action_intent.affected_job_ids != self.affected_job_ids
                or self.action_intent.evidence_fact_ids != self.evidence_fact_ids
            )
        ):
            raise ValueError("reconciliation contract invalid")
        expected_id = _reconciliation_id(
            status=self.status,
            incident_class=self.incident_class,
            expected_state_assessment_id=self.expected_state_assessment_id,
            operational_evidence_assessment_id=self.operational_evidence_assessment_id,
            class_assessment_ids=self.class_assessment_ids,
            affected_job_ids=self.affected_job_ids,
            safe_job_ids=self.safe_job_ids,
            evidence_fact_ids=self.evidence_fact_ids,
            reason_codes=self.reason_codes,
        )
        if self.reconciliation_id != expected_id:
            raise ValueError("reconciliation identity invalid")
        object.__setattr__(self, "derivation_sha256", _sha256(self._body()))

    def _body(self) -> dict[str, Any]:
        return {
            "schema": DIAGNOSIS_RECONCILIATION_VERSION,
            "reconciliation_id": self.reconciliation_id,
            "status": self.status.value,
            "incident_class": self.incident_class.value if self.incident_class else None,
            "expected_state_assessment_id": self.expected_state_assessment_id,
            "operational_evidence_assessment_id": self.operational_evidence_assessment_id,
            "class_assessment_ids": list(self.class_assessment_ids),
            "scope": {
                "affected_job_ids": list(self.affected_job_ids),
                "safe_job_ids": list(self.safe_job_ids),
            },
            "evidence_fact_ids": list(self.evidence_fact_ids),
            "reason_codes": list(self.reason_codes),
            "action_intent": self.action_intent.to_dict() if self.action_intent else None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "derivation_sha256": self.derivation_sha256}


@dataclass(frozen=True, slots=True)
class _RuntimeFact:
    request_id: str
    incident_id: str
    event_id: str
    signal: str
    fixture_id: str
    run_id: str
    job_id: str
    worker_id: str
    trace_id: str
    artifact_id: str | None
    config_sha256: str | None
    resource_sha256: str | None
    transform_id: str | None
    observed_at: str
    emitted_at: str
    retrieved_at: str
    attributes: Mapping[str, str]
    fact_id: str
    evidence_id: str


def _invalid_expected(*reason_codes: str) -> ExpectedStateAssessment:
    return ExpectedStateAssessment(
        status=AssessmentStatus.INSUFFICIENT,
        expected_state_id=None,
        expected_state_sha256=None,
        scenario_id=None,
        fixture_id=None,
        run_id=None,
        window_start=None,
        window_end=None,
        approved={},
        affected_job_ids=(),
        safe_job_ids=(),
        reason_codes=_reasons(*reason_codes),
    )


def assess_expected_state(value: Mapping[str, Any]) -> ExpectedStateAssessment:
    try:
        document = _mapping(value, "expected-state-schema-invalid")
        _exact_keys(document, _EXPECTED_KEYS, "expected-state-schema-invalid")
        if document["schema"] != EXPECTED_STATE_VERSION:
            raise _AssessmentFailure("expected-state-schema-invalid")
        scenario_id = _identifier(document["scenario_id"], "expected-state-scenario-invalid")
        if scenario_id not in _SCENARIOS:
            raise _AssessmentFailure("expected-state-scenario-invalid")
        fixture_id = _identifier(document["fixture_id"], "expected-state-binding-invalid")
        run_id = _identifier(document["run_id"], "expected-state-binding-invalid")

        window = _mapping(document["evidence_window"], "expected-state-window-invalid")
        _exact_keys(window, _WINDOW_KEYS, "expected-state-window-invalid")
        window_start = _timestamp(window["start"], "expected-state-window-invalid")
        window_end = _timestamp(window["end"], "expected-state-window-invalid")
        if window_end <= window_start or window_end - window_start > timedelta(minutes=10):
            raise _AssessmentFailure("expected-state-window-invalid")

        approved_input = _mapping(document["approved"], "expected-state-approved-invalid")
        _exact_keys(approved_input, _APPROVED_KEYS, "expected-state-approved-invalid")
        approved: dict[str, str | int] = {
            "resource_sha256": _digest(
                approved_input["resource_sha256"], "expected-state-approved-invalid"
            ),
            "config_sha256": _digest(
                approved_input["config_sha256"], "expected-state-approved-invalid"
            ),
            "config_generation": _positive_integer(
                approved_input["config_generation"], "expected-state-approved-invalid"
            ),
            "frame_pipeline_sha256": _digest(
                approved_input["frame_pipeline_sha256"], "expected-state-approved-invalid"
            ),
            "derivative_parent_sha256": _digest(
                approved_input["derivative_parent_sha256"],
                "expected-state-approved-invalid",
            ),
            "derivative_generation": _positive_integer(
                approved_input["derivative_generation"], "expected-state-approved-invalid"
            ),
            "cache_key": _identifier(
                approved_input["cache_key"], "expected-state-approved-invalid"
            ),
        }

        scope = _mapping(document["scope"], "expected-state-scope-invalid")
        _exact_keys(scope, _SCOPE_KEYS, "expected-state-scope-invalid")
        affected_raw = scope["affected_job_ids"]
        safe_raw = scope["safe_job_ids"]
        if not isinstance(affected_raw, list) or not isinstance(safe_raw, list):
            raise _AssessmentFailure("expected-state-scope-invalid")
        affected = tuple(
            _identifier(child, "expected-state-scope-invalid") for child in affected_raw
        )
        safe = tuple(_identifier(child, "expected-state-scope-invalid") for child in safe_raw)
        if (
            not affected
            or not safe
            or affected != tuple(sorted(set(affected)))
            or safe != tuple(sorted(set(safe)))
            or set(affected) & set(safe)
        ):
            raise _AssessmentFailure("expected-state-scope-invalid")

        body = {
            key: document[key]
            for key in _EXPECTED_KEYS - {"expected_state_id", "expected_state_sha256"}
        }
        expected_sha256 = _sha256(body)
        expected_id = f"expected-state:{expected_sha256.removeprefix('sha256:')}"
        if (
            document["expected_state_sha256"] != expected_sha256
            or document["expected_state_id"] != expected_id
        ):
            raise _AssessmentFailure("expected-state-identity-invalid")
        return ExpectedStateAssessment(
            status=AssessmentStatus.SUPPORTED,
            expected_state_id=expected_id,
            expected_state_sha256=expected_sha256,
            scenario_id=scenario_id,
            fixture_id=fixture_id,
            run_id=run_id,
            window_start=_timestamp_text(window_start),
            window_end=_timestamp_text(window_end),
            approved=approved,
            affected_job_ids=affected,
            safe_job_ids=safe,
            reason_codes=("expected-state-supported",),
        )
    except (KeyError, TypeError, _AssessmentFailure) as error:
        code = (
            error.code if isinstance(error, _AssessmentFailure) else "expected-state-schema-invalid"
        )
        return _invalid_expected(code)


def _parse_runtime_fact(value: Mapping[str, Any]) -> _RuntimeFact:
    document = _mapping(value, "runtime-observation-malformed")
    if any(key not in document for key in (*_FACT_BODY_KEYS, "fact_id", "fact_sha256")):
        raise _AssessmentFailure("runtime-observation-malformed")
    body = {key: document[key] for key in _FACT_BODY_KEYS}
    expected_sha256 = _sha256(body)
    expected_id = f"runtime-fact:{expected_sha256.removeprefix('sha256:')}"
    if (
        document["schema"] != NORMALIZED_RUNTIME_OBSERVATION_VERSION
        or document["fact_sha256"] != expected_sha256
        or document["fact_id"] != expected_id
    ):
        raise _AssessmentFailure("runtime-observation-digest-mismatch")

    signal = document["signal"]
    if signal not in {"metric", "log", "trace"}:
        raise _AssessmentFailure("runtime-observation-malformed")
    request_id = _identifier(document["request_id"], "runtime-observation-malformed")
    incident_id = _identifier(document["incident_id"], "runtime-observation-malformed")
    event_id = _identifier(document["event_id"], "runtime-observation-malformed")
    fixture_id = _identifier(document["fixture_id"], "runtime-observation-malformed")
    run_id = _identifier(document["run_id"], "runtime-observation-malformed")
    job_id = _identifier(document["job_id"], "runtime-observation-malformed")
    worker_id = _identifier(document["worker_id"], "runtime-observation-malformed")
    trace_id = document["trace_id"]
    if not isinstance(trace_id, str) or _TRACE_ID.fullmatch(trace_id) is None:
        raise _AssessmentFailure("runtime-observation-malformed")
    artifact_id = document["artifact_id"]
    if artifact_id is not None:
        artifact_id = _identifier(artifact_id, "runtime-observation-malformed")
    resource_value = document["resource_sha256"]
    resource_sha256 = (
        None
        if resource_value == "none"
        else _digest(resource_value, "runtime-observation-malformed")
    )
    config_sha256 = document["config_sha256"]
    if config_sha256 is not None:
        config_sha256 = _digest(config_sha256, "runtime-observation-malformed")
    transform_id = document["transform_id"]
    if transform_id is not None:
        _identifier(transform_id, "runtime-observation-malformed")

    observed = _timestamp(document["observed_at"], "runtime-observation-malformed")
    emitted = _timestamp(document["emitted_at"], "runtime-observation-malformed")
    retrieved = _timestamp(document["retrieved_at"], "runtime-observation-malformed")
    if emitted < observed or retrieved < emitted:
        raise _AssessmentFailure("runtime-observation-time-invalid")

    attributes = _mapping(document["attributes"], "runtime-observation-malformed")
    if any(
        not isinstance(key, str) or not isinstance(child, str) for key, child in attributes.items()
    ):
        raise _AssessmentFailure("runtime-observation-malformed")
    required_attributes = _SIGNAL_REQUIRED_ATTRIBUTES[signal]
    present_role_attributes = set(attributes) & _ROLE_BOUND_ATTRIBUTES
    if (
        not required_attributes <= set(attributes)
        or not present_role_attributes <= required_attributes
    ):
        raise _AssessmentFailure("runtime-signal-semantics-invalid")
    if signal == "metric":
        if (
            resource_sha256 is not None
            or attributes["reference.evidence_scope"] != "representative"
            or attributes["reference.affected_representative_count"] != "1"
            or attributes["reference.protected_representative_count"] != "1"
            or any(
                _positive_integer(attributes[name], "runtime-facts-malformed") < 1
                for name in (
                    "reference.population_affected_artifact_count",
                    "reference.population_protected_artifact_count",
                )
            )
            or _PREFIXED_DIGEST.fullmatch(attributes[_APPROVED_STATE_ATTRIBUTE]) is None
            or any(
                attributes[name] not in {"true", "false"}
                for name in _MATCH_ATTRIBUTE_FIELDS.values()
            )
        ):
            raise _AssessmentFailure("runtime-signal-semantics-invalid")
    elif signal == "log":
        if resource_sha256 is None or resource_sha256 != _digest(
            attributes["runtime.effective_resource_sha256"],
            "runtime-facts-malformed",
        ):
            raise _AssessmentFailure("runtime-signal-semantics-invalid")
    elif resource_sha256 is not None:
        raise _AssessmentFailure("runtime-signal-semantics-invalid")
    provenance = _mapping(document["provenance"], "runtime-observation-malformed")
    required_provenance = {
        "query_key",
        "evidence_id",
        "event_sha256",
        "content_sha256",
        "catalog_version",
        "catalog_sha256",
        "tool",
        "normalized_arguments",
    }
    if any(key not in provenance for key in required_provenance):
        raise _AssessmentFailure("runtime-observation-malformed")
    query_key = provenance["query_key"]
    if (
        not isinstance(query_key, str)
        or _QUERY_SIGNALS.get(query_key) != signal
        or provenance["tool"] != _QUERY_TOOLS.get(query_key)
        or provenance["catalog_version"] != "grafana-evidence-query-catalog/v2"
        or provenance["evidence_id"] != provenance["event_sha256"]
        or not isinstance(provenance["normalized_arguments"], Mapping)
    ):
        raise _AssessmentFailure("runtime-observation-provenance-invalid")
    for name in ("evidence_id", "event_sha256", "content_sha256", "catalog_sha256"):
        if (
            not isinstance(provenance[name], str)
            or _PREFIXED_DIGEST.fullmatch(provenance[name]) is None
        ):
            raise _AssessmentFailure("runtime-observation-provenance-invalid")
    return _RuntimeFact(
        request_id=request_id,
        incident_id=incident_id,
        event_id=event_id,
        signal=signal,
        fixture_id=fixture_id,
        run_id=run_id,
        job_id=job_id,
        worker_id=worker_id,
        trace_id=trace_id,
        artifact_id=cast(str | None, artifact_id),
        config_sha256=cast(str | None, config_sha256),
        resource_sha256=resource_sha256,
        transform_id=cast(str | None, transform_id),
        observed_at=_timestamp_text(observed),
        emitted_at=_timestamp_text(emitted),
        retrieved_at=_timestamp_text(retrieved),
        attributes=cast(Mapping[str, str], _freeze(attributes)),
        fact_id=cast(str, document["fact_id"]),
        evidence_id=cast(str, provenance["evidence_id"]),
    )


def _invalid_operational(
    expected: ExpectedStateAssessment,
    status: AssessmentStatus,
    reason_codes: Sequence[str],
    *,
    request_id: str | None = None,
    incident_id: str | None = None,
) -> OperationalEvidenceAssessment:
    return OperationalEvidenceAssessment(
        status=status,
        expected_state_assessment_id=expected.assessment_id,
        request_id=request_id,
        incident_id=incident_id,
        fixture_id=expected.fixture_id,
        run_id=expected.run_id,
        job_facts={},
        fact_ids=(),
        evidence_ids=(),
        reason_codes=tuple(reason_codes),
    )


def _fact_semantic_identity(fact: _RuntimeFact) -> bytes:
    semantic_attributes = {
        attribute: value
        for attribute, value in fact.attributes.items()
        if attribute in _ROLE_BOUND_ATTRIBUTES
    }
    return _canonical_json_bytes(
        {
            "event_id": fact.event_id,
            "signal": fact.signal,
            "fixture_id": fact.fixture_id,
            "run_id": fact.run_id,
            "job_id": fact.job_id,
            "worker_id": fact.worker_id,
            "trace_id": fact.trace_id,
            "artifact_id": fact.artifact_id,
            "config_sha256": fact.config_sha256,
            "resource_sha256": fact.resource_sha256,
            "transform_id": fact.transform_id,
            "observed_at": fact.observed_at,
            "emitted_at": fact.emitted_at,
            "attributes": semantic_attributes,
        }
    )


def _job_semantic_value(facts: Sequence[_RuntimeFact], field_name: str) -> str | int:
    values: set[str] = set()
    if field_name == "effective_resource_sha256":
        values.update(fact.resource_sha256 for fact in facts if fact.resource_sha256 is not None)
    for fact in facts:
        for attribute in _ATTRIBUTE_FIELDS[field_name]:
            if attribute in fact.attributes:
                raw = fact.attributes[attribute]
                if field_name.endswith("sha256"):
                    values.add(_digest(raw, "runtime-facts-malformed"))
                elif field_name.endswith("generation"):
                    values.add(str(_positive_integer(raw, "runtime-facts-malformed")))
                elif field_name == "cache_key":
                    values.add(_identifier(raw, "runtime-facts-malformed"))
                else:
                    values.add(raw)
    if not values:
        raise _AssessmentFailure("runtime-facts-incomplete")
    if len(values) != 1:
        raise _AssessmentFailure("runtime-observation-conflict", AssessmentStatus.CONFLICTING)
    selected = next(iter(values))
    return int(selected) if field_name.endswith("generation") else selected


def _optional_job_semantic_value(
    facts: Sequence[_RuntimeFact], field_name: str
) -> str | int | None:
    try:
        return _job_semantic_value(facts, field_name)
    except _AssessmentFailure as error:
        if error.code == "runtime-facts-incomplete":
            return None
        raise


def _job_match_flags(
    facts: Sequence[_RuntimeFact], expected: ExpectedStateAssessment
) -> Mapping[str, bool]:
    metrics = [fact for fact in facts if fact.signal == "metric"]
    if not metrics:
        raise _AssessmentFailure("complementary-signals-missing")
    approved_state_sha256 = _sha256(expected.approved)
    approved_bindings = {fact.attributes[_APPROVED_STATE_ATTRIBUTE] for fact in metrics}
    if approved_bindings != {approved_state_sha256}:
        raise _AssessmentFailure(
            "runtime-approved-state-binding-mismatch",
            AssessmentStatus.CONFLICTING,
        )
    result: dict[str, bool] = {}
    for field_name, attribute_name in _MATCH_ATTRIBUTE_FIELDS.items():
        values = {fact.attributes[attribute_name] for fact in metrics}
        if len(values) != 1:
            raise _AssessmentFailure(
                "runtime-observation-conflict",
                AssessmentStatus.CONFLICTING,
            )
        result[field_name] = next(iter(values)) == "true"
    return MappingProxyType(result)


def _job_values(facts: Sequence[_RuntimeFact], expected: ExpectedStateAssessment) -> dict[str, Any]:
    flags = _job_match_flags(facts, expected)
    values: dict[str, Any] = {}
    for field_name in _SEMANTIC_FIELDS:
        approved = expected.approved[_EXPECTED_SEMANTIC_FIELDS[field_name]]
        observed = _optional_job_semantic_value(facts, field_name)
        if flags[field_name]:
            if observed is not None and observed != approved:
                raise _AssessmentFailure(
                    "runtime-observation-conflict",
                    AssessmentStatus.CONFLICTING,
                )
            values[field_name] = approved
            continue
        if observed is None:
            raise _AssessmentFailure("runtime-facts-incomplete")
        if observed == approved:
            raise _AssessmentFailure(
                "runtime-observation-conflict",
                AssessmentStatus.CONFLICTING,
            )
        values[field_name] = observed
    state = _job_semantic_value(facts, "reference_state")
    if state not in {"reference_match", "reference_mismatch"}:
        raise _AssessmentFailure("runtime-facts-malformed")
    if (state == "reference_mismatch") != any(not matches for matches in flags.values()):
        raise _AssessmentFailure(
            "runtime-observation-conflict",
            AssessmentStatus.CONFLICTING,
        )
    values["reference_state"] = state
    values["matches_approved"] = dict(flags)
    return values


def assess_operational_evidence(
    expected: ExpectedStateAssessment,
    observations: Sequence[Mapping[str, Any]],
) -> OperationalEvidenceAssessment:
    if expected.status is not AssessmentStatus.SUPPORTED:
        return _invalid_operational(
            expected,
            AssessmentStatus.INSUFFICIENT,
            ("expected-state-unresolved",),
        )
    if not observations:
        return _invalid_operational(
            expected,
            AssessmentStatus.INSUFFICIENT,
            ("no-runtime-observations",),
        )

    facts: list[_RuntimeFact] = []
    failures: list[_AssessmentFailure] = []
    for observation in observations:
        try:
            facts.append(_parse_runtime_fact(observation))
        except (TypeError, _AssessmentFailure) as error:
            failures.append(
                error
                if isinstance(error, _AssessmentFailure)
                else _AssessmentFailure("runtime-observation-malformed")
            )
    request_ids = {fact.request_id for fact in facts}
    incident_ids = {fact.incident_id for fact in facts}
    request_id = next(iter(request_ids)) if len(request_ids) == 1 else None
    incident_id = next(iter(incident_ids)) if len(incident_ids) == 1 else None
    if failures:
        status = (
            AssessmentStatus.CONFLICTING
            if any(failure.status is AssessmentStatus.CONFLICTING for failure in failures)
            else AssessmentStatus.INSUFFICIENT
        )
        return _invalid_operational(
            expected,
            status,
            tuple(failure.code for failure in failures),
            request_id=request_id,
            incident_id=incident_id,
        )
    if len(request_ids) != 1 or len(incident_ids) != 1:
        return _invalid_operational(
            expected,
            AssessmentStatus.CONFLICTING,
            ("runtime-observation-binding-mismatch",),
        )
    if any(
        fact.fixture_id != expected.fixture_id or fact.run_id != expected.run_id for fact in facts
    ):
        return _invalid_operational(
            expected,
            AssessmentStatus.CONFLICTING,
            ("runtime-observation-cross-run",),
            request_id=request_id,
            incident_id=incident_id,
        )

    window_start = _timestamp(expected.window_start, "expected-state-window-invalid")
    window_end = _timestamp(expected.window_end, "expected-state-window-invalid")
    if any(
        _timestamp(fact.observed_at, "runtime-observation-time-invalid") < window_start
        or _timestamp(fact.observed_at, "runtime-observation-time-invalid") > window_end
        for fact in facts
    ):
        return _invalid_operational(
            expected,
            AssessmentStatus.INSUFFICIENT,
            ("runtime-observation-stale",),
            request_id=request_id,
            incident_id=incident_id,
        )

    event_identities: dict[str, bytes] = {}
    unique_facts: dict[str, _RuntimeFact] = {}
    for fact in facts:
        semantic = _fact_semantic_identity(fact)
        previous = event_identities.get(fact.event_id)
        if previous is not None and previous != semantic:
            return _invalid_operational(
                expected,
                AssessmentStatus.CONFLICTING,
                ("runtime-observation-conflict",),
                request_id=request_id,
                incident_id=incident_id,
            )
        event_identities[fact.event_id] = semantic
        unique_facts[fact.fact_id] = fact
    facts = list(unique_facts.values())

    expected_jobs = set(expected.affected_job_ids) | set(expected.safe_job_ids)
    observed_jobs = {fact.job_id for fact in facts}
    if observed_jobs != expected_jobs:
        return _invalid_operational(
            expected,
            AssessmentStatus.CONFLICTING,
            ("scope-mismatch",),
            request_id=request_id,
            incident_id=incident_id,
        )

    job_facts: dict[str, dict[str, Any]] = {}
    try:
        for job_id in sorted(expected_jobs):
            selected = [fact for fact in facts if fact.job_id == job_id]
            signals = tuple(sorted({fact.signal for fact in selected}))
            if len(signals) < 2:
                raise _AssessmentFailure("complementary-signals-missing")
            workers = {fact.worker_id for fact in selected}
            traces = {fact.trace_id for fact in selected}
            artifacts = {fact.artifact_id for fact in selected if fact.artifact_id is not None}
            if len(workers) != 1 or len(traces) != 1 or len(artifacts) > 1:
                raise _AssessmentFailure(
                    "runtime-observation-conflict", AssessmentStatus.CONFLICTING
                )
            approved_config = cast(str, expected.approved["config_sha256"])
            if any(fact.config_sha256 != approved_config for fact in selected):
                raise _AssessmentFailure(
                    "runtime-observation-conflict",
                    AssessmentStatus.CONFLICTING,
                )
            values = _job_values(selected, expected)
            values.update(
                {
                    "worker_id": next(iter(workers)),
                    "trace_id": next(iter(traces)),
                    "artifact_id": next(iter(artifacts)) if artifacts else None,
                    "signals": list(signals),
                    "fact_ids": sorted(fact.fact_id for fact in selected),
                }
            )
            job_facts[job_id] = values
    except _AssessmentFailure as error:
        return _invalid_operational(
            expected,
            error.status,
            (error.code,),
            request_id=request_id,
            incident_id=incident_id,
        )

    affected = {
        job_id
        for job_id, value in job_facts.items()
        if value["reference_state"] == "reference_mismatch"
    }
    safe = {
        job_id
        for job_id, value in job_facts.items()
        if value["reference_state"] == "reference_match"
    }
    if affected != set(expected.affected_job_ids) or safe != set(expected.safe_job_ids):
        return _invalid_operational(
            expected,
            AssessmentStatus.CONFLICTING,
            ("scope-mismatch",),
            request_id=request_id,
            incident_id=incident_id,
        )
    return OperationalEvidenceAssessment(
        status=AssessmentStatus.SUPPORTED,
        expected_state_assessment_id=expected.assessment_id,
        request_id=request_id,
        incident_id=incident_id,
        fixture_id=expected.fixture_id,
        run_id=expected.run_id,
        job_facts=job_facts,
        fact_ids=tuple(fact.fact_id for fact in facts),
        evidence_ids=tuple(fact.evidence_id for fact in facts),
        reason_codes=("operational-evidence-supported",),
    )


@dataclass(frozen=True, slots=True)
class _IncidentAssessor:
    incident_class: IncidentClass
    changed_fields: frozenset[str]
    action_command: Literal["reconcile-resource", "pin-rollout", "invalidate-cache"]

    def assess(
        self,
        expected: ExpectedStateAssessment,
        operational: OperationalEvidenceAssessment,
    ) -> IncidentClassAssessment:
        if (
            expected.status is not AssessmentStatus.SUPPORTED
            or operational.status is not AssessmentStatus.SUPPORTED
            or operational.expected_state_assessment_id != expected.assessment_id
        ):
            return IncidentClassAssessment(
                status=AssessmentStatus.INSUFFICIENT,
                incident_class=self.incident_class,
                expected_state_assessment_id=expected.assessment_id,
                operational_evidence_assessment_id=operational.assessment_id,
                affected_job_ids=expected.affected_job_ids,
                safe_job_ids=expected.safe_job_ids,
                evidence_fact_ids=operational.fact_ids,
                cause={},
                reason_codes=("assessment-prerequisite-unresolved",),
            )

        approved = expected.approved
        supported = True
        observed: dict[str, set[str | int]] = {name: set() for name in self.changed_fields}
        for job_id in expected.safe_job_ids:
            facts = operational.job_facts[job_id]
            if any(
                facts[name] != approved[_EXPECTED_SEMANTIC_FIELDS[name]]
                for name in _SEMANTIC_FIELDS
            ):
                supported = False
        for job_id in expected.affected_job_ids:
            facts = operational.job_facts[job_id]
            differences = {
                name
                for name in _CAUSAL_FIELDS
                if facts[name] != approved[_EXPECTED_SEMANTIC_FIELDS[name]]
            }
            frame_pipeline_differs = (
                facts["frame_pipeline_sha256"] != approved["frame_pipeline_sha256"]
            )
            expected_frame_difference = (
                self.incident_class is not IncidentClass.STALE_DERIVATIVE_CACHE
            )
            if (
                differences != self.changed_fields
                or frame_pipeline_differs is not expected_frame_difference
            ):
                supported = False
            for name in self.changed_fields:
                observed[name].add(cast(str | int, facts[name]))
        if any(len(values) != 1 for values in observed.values()):
            supported = False

        cause: dict[str, Any] = {}
        if supported:
            cause = {
                "changed_fields": sorted(self.changed_fields),
                "expected": {
                    name: approved[_EXPECTED_SEMANTIC_FIELDS[name]]
                    for name in sorted(self.changed_fields)
                },
                "observed": {
                    name: next(iter(observed[name])) for name in sorted(self.changed_fields)
                },
            }
            if self.incident_class is IncidentClass.STALE_DERIVATIVE_CACHE:
                cause["cache_key"] = approved["cache_key"]
        return IncidentClassAssessment(
            status=AssessmentStatus.SUPPORTED if supported else AssessmentStatus.REJECTED,
            incident_class=self.incident_class,
            expected_state_assessment_id=expected.assessment_id,
            operational_evidence_assessment_id=operational.assessment_id,
            affected_job_ids=expected.affected_job_ids,
            safe_job_ids=expected.safe_job_ids,
            evidence_fact_ids=operational.fact_ids,
            cause=cause,
            reason_codes=(
                f"{self.incident_class.value.removesuffix('/v1')}-supported"
                if supported
                else f"{self.incident_class.value.removesuffix('/v1')}-rejected",
            ),
        )


SEALED_INCIDENT_ASSESSORS = (
    _IncidentAssessor(
        IncidentClass.RESOURCE_RESOLUTION_DRIFT,
        frozenset({"effective_resource_sha256"}),
        "reconcile-resource",
    ),
    _IncidentAssessor(
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT,
        frozenset({"effective_config_sha256", "config_generation"}),
        "pin-rollout",
    ),
    _IncidentAssessor(
        IncidentClass.STALE_DERIVATIVE_CACHE,
        frozenset({"derivative_parent_sha256", "derivative_generation"}),
        "invalidate-cache",
    ),
)


def assess_incident_classes(
    expected: ExpectedStateAssessment,
    operational: OperationalEvidenceAssessment,
) -> tuple[IncidentClassAssessment, ...]:
    return tuple(assessor.assess(expected, operational) for assessor in SEALED_INCIDENT_ASSESSORS)


def _reconciliation_identity_body(
    *,
    status: AssessmentStatus,
    incident_class: IncidentClass | None,
    expected_state_assessment_id: str,
    operational_evidence_assessment_id: str,
    class_assessment_ids: Sequence[str],
    affected_job_ids: Sequence[str],
    safe_job_ids: Sequence[str],
    evidence_fact_ids: Sequence[str],
    reason_codes: Sequence[str],
) -> dict[str, Any]:
    return {
        "schema": "diagnosis-reconciliation-identity/v1",
        "status": status.value,
        "incident_class": incident_class.value if incident_class else None,
        "expected_state_assessment_id": expected_state_assessment_id,
        "operational_evidence_assessment_id": operational_evidence_assessment_id,
        "class_assessment_ids": list(class_assessment_ids),
        "scope": {
            "affected_job_ids": list(affected_job_ids),
            "safe_job_ids": list(safe_job_ids),
        },
        "evidence_fact_ids": list(evidence_fact_ids),
        "reason_codes": list(reason_codes),
    }


def _reconciliation_id(**values: Any) -> str:
    identity, _digest_value = _derived_identity(
        "diagnosis-reconciliation", _reconciliation_identity_body(**values)
    )
    return identity


def reconcile_diagnosis(
    expected: ExpectedStateAssessment,
    operational: OperationalEvidenceAssessment,
    assessments: Sequence[IncidentClassAssessment],
) -> DiagnosisReconciliation:
    supplied = tuple(assessments)
    by_class = {assessment.incident_class: assessment for assessment in supplied}
    ordered = tuple(
        by_class[assessor.incident_class]
        for assessor in SEALED_INCIDENT_ASSESSORS
        if assessor.incident_class in by_class
    )
    reason_codes: tuple[str, ...]
    status = AssessmentStatus.INSUFFICIENT
    incident_class: IncidentClass | None = None
    valid_bindings = (
        len(supplied) == len(SEALED_INCIDENT_ASSESSORS)
        and len(ordered) == len(SEALED_INCIDENT_ASSESSORS)
        and {assessment.incident_class for assessment in supplied}
        == {assessor.incident_class for assessor in SEALED_INCIDENT_ASSESSORS}
        and all(
            assessment.expected_state_assessment_id == expected.assessment_id
            and assessment.operational_evidence_assessment_id == operational.assessment_id
            and assessment.affected_job_ids == expected.affected_job_ids
            and assessment.safe_job_ids == expected.safe_job_ids
            and assessment.evidence_fact_ids == operational.fact_ids
            for assessment in ordered
        )
    )
    if not valid_bindings:
        status = AssessmentStatus.CONFLICTING
        reason_codes = ("class-assessment-binding-invalid",)
    elif (
        expected.status is not AssessmentStatus.SUPPORTED
        or operational.status is not AssessmentStatus.SUPPORTED
    ):
        reason_codes = ("diagnosis-prerequisite-unresolved",)
    else:
        supported = [
            assessment for assessment in ordered if assessment.status is AssessmentStatus.SUPPORTED
        ]
        if not supported:
            reason_codes = ("no-incident-class-supported",)
        elif len(supported) > 1:
            status = AssessmentStatus.CONFLICTING
            reason_codes = ("multiple-incident-classes-supported",)
        elif any(
            assessment.status is not AssessmentStatus.REJECTED
            for assessment in ordered
            if assessment is not supported[0]
        ):
            reason_codes = ("class-assessment-incomplete",)
        else:
            status = AssessmentStatus.SUPPORTED
            incident_class = supported[0].incident_class
            reason_codes = ("diagnosis-supported",)

    class_ids = tuple(assessment.assessment_id for assessment in ordered)
    evidence_fact_ids = tuple(sorted(set(operational.fact_ids)))
    reconciliation_id = _reconciliation_id(
        status=status,
        incident_class=incident_class,
        expected_state_assessment_id=expected.assessment_id,
        operational_evidence_assessment_id=operational.assessment_id,
        class_assessment_ids=class_ids,
        affected_job_ids=expected.affected_job_ids,
        safe_job_ids=expected.safe_job_ids,
        evidence_fact_ids=evidence_fact_ids,
        reason_codes=reason_codes,
    )
    action: ActionIntent | None = None
    if status is AssessmentStatus.SUPPORTED and incident_class is not None:
        selected = next(
            assessment for assessment in ordered if assessment.incident_class is incident_class
        )
        command = next(
            assessor.action_command
            for assessor in SEALED_INCIDENT_ASSESSORS
            if assessor.incident_class is incident_class
        )
        action = ActionIntent(
            reconciliation_id=reconciliation_id,
            incident_class=incident_class,
            command=command,
            affected_job_ids=expected.affected_job_ids,
            evidence_fact_ids=evidence_fact_ids,
            parameters=selected.cause,
        )
    return DiagnosisReconciliation(
        reconciliation_id=reconciliation_id,
        status=status,
        incident_class=incident_class,
        expected_state_assessment_id=expected.assessment_id,
        operational_evidence_assessment_id=operational.assessment_id,
        class_assessment_ids=class_ids,
        affected_job_ids=expected.affected_job_ids,
        safe_job_ids=expected.safe_job_ids,
        evidence_fact_ids=evidence_fact_ids,
        reason_codes=reason_codes,
        action_intent=action,
    )
