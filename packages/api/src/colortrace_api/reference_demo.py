from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
import struct
import threading
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from colortrace_fixture import (
    ReferenceMediaManifest,
    ReferenceScenario,
    load_reference_media_manifest,
    reference_manifest_identity,
    reference_scenarios,
)
from colortrace_investigation import (
    AlertIntake,
    ContractError,
    ReferenceInvestigationError,
    validate_reference_response_packet,
)
from colortrace_simulator import (
    REFERENCE_PUBLIC_APPROVAL_PHRASE,
    REFERENCE_PUBLIC_DENIAL_PHRASE,
    ApprovalDecision,
    ReferenceHumanApprovalBoundary,
    ReferenceJobState,
    ReferenceRecoveryError,
    ReferenceRecoveryService,
    ReferenceRecoveryState,
    validate_reference_action_intent,
    validate_reference_recovery_verification,
)
from colortrace_telemetry import (
    REFERENCE_FIXTURE_ID,
    ReferenceTelemetryPlan,
    ReferenceTelemetrySink,
    build_generated_reference_telemetry_plan,
    emit_reference_telemetry,
)
from colortrace_validator import ActionIntent, IncidentClass

from .reference_live_render import (
    ReferenceLiveRenderer,
    ReferenceLiveRenderError,
    ReferenceLiveRenderResult,
)
from .reference_results import (
    REFERENCE_RESULT_PATH,
    ReferenceResultError,
    load_reference_impact_result,
)
from .reference_visuals import (
    ReferencePreviewCatalog,
    ReferencePreviewError,
    load_reference_preview_catalog,
)

REFERENCE_SCENARIO_LIST_SCHEMA = "reference-scenario-list/v2"
REFERENCE_SCENARIO_DETAIL_SCHEMA = "reference-scenario-detail/v2"
REFERENCE_BENCHMARK_SUITE_SCHEMA = "reference-benchmark-suite/v1"
REFERENCE_AUTHORITY_SCHEMA = "reference-authority-boundary/v1"
REFERENCE_PROVENANCE_SCHEMA = "reference-scenario-provenance/v1"
REFERENCE_SCENARIO_RUN_REQUEST_SCHEMA = "reference-scenario-run-request/v1"
REFERENCE_RECOVERY_DECISION_REQUEST_SCHEMA = "reference-recovery-decision-request/v1"
REFERENCE_RECOVERY_DECISION_SCHEMA = "reference-recovery-decision/v2"
REFERENCE_APPROVAL_PHRASE = REFERENCE_PUBLIC_APPROVAL_PHRASE
REFERENCE_DENIAL_PHRASE = REFERENCE_PUBLIC_DENIAL_PHRASE
REFERENCE_RUN_MAX_IN_FLIGHT = 4
REFERENCE_RUN_DEADLINE_SECONDS = 150.0
_RUN_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PACKET_ID = re.compile(r"^response-packet:[0-9a-f]{64}$")
_ACTION_INTENT_ID = re.compile(r"^action-intent:[0-9a-f]{64}$")
_RECONCILIATION_ID = re.compile(r"^diagnosis-reconciliation:[0-9a-f]{64}$")

_VISUAL_KINDS = ("expected", "observed", "diff")
_REFERENCE_RUN_REPLAY_CACHE_SIZE = 256
_REFERENCE_LIVE_RENDER_TIMEOUT_SECONDS = 15.0
_LIVE_RENDER_KEYS = frozenset(
    {
        "schema",
        "scenario_id",
        "request_id",
        "action_intent_id",
        "action_intent_sha256",
        "approval_id",
        "approval_sha256",
        "execution_target",
        "source_artifact_id",
        "source_sha256",
        "job_sha256",
        "worker_receipt_sha256",
        "output_sha256",
        "canonical_pixel_sha256",
        "expected_canonical_pixel_sha256",
        "output_equivalent",
        "visual_content_sha256",
        "visual_width",
        "visual_height",
        "dependencies",
        "wall_nanoseconds",
        "live_render_sha256",
    }
)


class ReferenceDemoError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ReferenceVisual:
    content: bytes
    media_type: str
    sha256: str
    scenario_sha256: str
    representation: str
    pixel_evidence: bool


@dataclass(frozen=True, slots=True)
class ReferenceLiveVisual:
    content: bytes
    sha256: str
    scenario_id: str
    request_id: str
    decision_sha256: str
    worker_receipt_sha256: str


class ReferenceDemoApi(Protocol):
    def list_scenarios(self) -> dict[str, Any]: ...

    def get_scenario(self, scenario_id: str) -> dict[str, Any]: ...

    def scenario_visual(self, scenario_id: str, kind: str) -> ReferenceVisual: ...

    def benchmark_suite(self) -> dict[str, Any]: ...


class ReferenceInvestigationWorkflowPort(Protocol):
    async def run(
        self,
        *,
        alert: Mapping[str, Any],
        expected_state: Mapping[str, Any],
    ) -> dict[str, Any]: ...


class ReferenceScenarioRunApi(Protocol):
    async def run_scenario(
        self,
        scenario_id: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]: ...

    async def decide_scenario(
        self,
        scenario_id: str,
        request_id: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]: ...

    def live_visual(self, scenario_id: str, request_id: str) -> ReferenceLiveVisual: ...


class ReferenceScenarioTelemetryPort(Protocol):
    def prepare(
        self,
        scenario_id: str,
        *,
        incident_id: str,
        fixture_id: str,
        run_id: str,
        observed_at: datetime,
        emitted_at: datetime,
    ) -> ReferenceTelemetryPlan: ...

    async def emit(self, plan: ReferenceTelemetryPlan) -> Mapping[str, Any]: ...


@dataclass(frozen=True, slots=True)
class ReferenceScenarioRunRequest:
    scenario_id: str
    request_id: str
    incident_id: str
    fixture_id: str
    run_id: str

    @classmethod
    def from_mapping(
        cls,
        scenario_id: str,
        value: Mapping[str, Any],
    ) -> ReferenceScenarioRunRequest:
        if set(value) != {"schema", "request_id"} or value.get("schema") != (
            REFERENCE_SCENARIO_RUN_REQUEST_SCHEMA
        ):
            raise ReferenceDemoError("reference-run-request-invalid")
        request_id = value.get("request_id")
        if not isinstance(request_id, str) or _RUN_IDENTIFIER.fullmatch(request_id) is None:
            raise ReferenceDemoError("reference-run-request-invalid")
        binding_sha256 = hashlib.sha256(f"{scenario_id}\0{request_id}".encode()).hexdigest()
        return cls(
            scenario_id=scenario_id,
            request_id=request_id,
            incident_id=f"reference-incident-{binding_sha256[:24]}",
            fixture_id=REFERENCE_FIXTURE_ID,
            run_id=f"reference-run-{binding_sha256[24:48]}",
        )


@dataclass(frozen=True, slots=True)
class ReferenceRecoveryDecisionRequest:
    request_id: str
    decision: ApprovalDecision
    approval_phrase: str
    approval_nonce: str
    packet_id: str
    packet_sha256: str
    expected_state_sha256: str
    reconciliation_id: str
    action_intent_id: str
    action_intent_sha256: str

    @classmethod
    def from_mapping(
        cls,
        request_id: str,
        value: Mapping[str, Any],
    ) -> ReferenceRecoveryDecisionRequest:
        fields = {
            "schema",
            "request_id",
            "decision",
            "approval_phrase",
            "approval_nonce",
            "packet_id",
            "packet_sha256",
            "expected_state_sha256",
            "reconciliation_id",
            "action_intent_id",
            "action_intent_sha256",
        }
        decision = value.get("decision")
        phrase = value.get("approval_phrase")
        expected_phrase = (
            REFERENCE_APPROVAL_PHRASE if decision == "approved" else REFERENCE_DENIAL_PHRASE
        )
        if (
            _RUN_IDENTIFIER.fullmatch(request_id) is None
            or set(value) != fields
            or value.get("schema") != REFERENCE_RECOVERY_DECISION_REQUEST_SCHEMA
            or value.get("request_id") != request_id
            or decision not in {"approved", "denied"}
        ):
            raise ReferenceDemoError("reference-recovery-decision-request-invalid")
        if not isinstance(phrase, str) or not hmac.compare_digest(phrase, expected_phrase):
            raise ReferenceDemoError("reference-recovery-approval-phrase-invalid")
        nonce = value.get("approval_nonce")
        packet_id = value.get("packet_id")
        packet_sha256 = value.get("packet_sha256")
        expected_state_sha256 = value.get("expected_state_sha256")
        reconciliation_id = value.get("reconciliation_id")
        action_intent_id = value.get("action_intent_id")
        action_intent_sha256 = value.get("action_intent_sha256")
        if (
            not isinstance(nonce, str)
            or _RUN_IDENTIFIER.fullmatch(nonce) is None
            or not isinstance(packet_id, str)
            or _PACKET_ID.fullmatch(packet_id) is None
            or not isinstance(packet_sha256, str)
            or _DIGEST.fullmatch(packet_sha256) is None
            or not isinstance(expected_state_sha256, str)
            or _DIGEST.fullmatch(expected_state_sha256) is None
            or not isinstance(reconciliation_id, str)
            or _RECONCILIATION_ID.fullmatch(reconciliation_id) is None
            or not isinstance(action_intent_id, str)
            or _ACTION_INTENT_ID.fullmatch(action_intent_id) is None
            or not isinstance(action_intent_sha256, str)
            or _DIGEST.fullmatch(action_intent_sha256) is None
        ):
            raise ReferenceDemoError("reference-recovery-decision-request-invalid")
        return cls(
            request_id=request_id,
            decision=cast(ApprovalDecision, decision),
            approval_phrase=phrase,
            approval_nonce=nonce,
            packet_id=packet_id,
            packet_sha256=packet_sha256,
            expected_state_sha256=expected_state_sha256,
            reconciliation_id=reconciliation_id,
            action_intent_id=action_intent_id,
            action_intent_sha256=action_intent_sha256,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REFERENCE_RECOVERY_DECISION_REQUEST_SCHEMA,
            "request_id": self.request_id,
            "decision": self.decision,
            "approval_phrase": self.approval_phrase,
            "approval_nonce": self.approval_nonce,
            "packet_id": self.packet_id,
            "packet_sha256": self.packet_sha256,
            "expected_state_sha256": self.expected_state_sha256,
            "reconciliation_id": self.reconciliation_id,
            "action_intent_id": self.action_intent_id,
            "action_intent_sha256": self.action_intent_sha256,
        }


@dataclass(frozen=True, slots=True)
class _CachedReferenceDecision:
    request_sha256: str
    response: bytes | None = None
    error_code: str | None = None

    def __post_init__(self) -> None:
        if (self.response is None) == (self.error_code is None):
            raise ValueError("reference decision cache entry is invalid")


@dataclass(slots=True)
class _ReferenceRecoveryContext:
    packet: Mapping[str, Any]
    action_intent: ActionIntent
    initial_state: ReferenceRecoveryState
    recovery: ReferenceRecoveryService
    decisions: dict[str, _CachedReferenceDecision] = field(default_factory=dict)
    terminal_request_sha256: str | None = None
    live_visual: ReferenceLiveVisual | None = None


@dataclass(frozen=True, slots=True)
class _CachedReferenceRun:
    packet: bytes | None = None
    error_code: str | None = None
    recovery: _ReferenceRecoveryContext | None = None

    def __post_init__(self) -> None:
        if (self.packet is None) == (self.error_code is None) or (
            self.recovery is not None and self.packet is None
        ):
            raise ValueError("reference run cache entry is invalid")


class GeneratedReferenceScenarioTelemetry:
    def __init__(self, sink_factory: Callable[[], ReferenceTelemetrySink]) -> None:
        self._sink_factory = sink_factory

    def prepare(
        self,
        scenario_id: str,
        *,
        incident_id: str,
        fixture_id: str,
        run_id: str,
        observed_at: datetime,
        emitted_at: datetime,
    ) -> ReferenceTelemetryPlan:
        return build_generated_reference_telemetry_plan(
            scenario_id,
            incident_id=incident_id,
            run_id=run_id,
            fixture_id=fixture_id,
            observed_at=observed_at,
            emitted_at=emitted_at,
        )

    async def emit(self, plan: ReferenceTelemetryPlan) -> Mapping[str, Any]:
        return await asyncio.to_thread(self._emit, plan)

    def _emit(self, plan: ReferenceTelemetryPlan) -> Mapping[str, Any]:
        return emit_reference_telemetry(plan, self._sink_factory())


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(_canonical_json(value)).hexdigest()}"


def _validate_live_render_result(
    result: ReferenceLiveRenderResult,
    *,
    scenario_id: str,
    request_id: str,
    action_intent: Mapping[str, Any],
    approval: Mapping[str, Any],
) -> None:
    if not isinstance(result, ReferenceLiveRenderResult):
        raise ReferenceLiveRenderError("reference-live-render-result-invalid")
    document = result.document
    content_sha256 = f"sha256:{hashlib.sha256(result.png).hexdigest()}"
    body = {key: value for key, value in document.items() if key != "live_render_sha256"}
    digest_fields = (
        "action_intent_sha256",
        "approval_sha256",
        "source_sha256",
        "job_sha256",
        "worker_receipt_sha256",
        "output_sha256",
        "canonical_pixel_sha256",
        "expected_canonical_pixel_sha256",
        "visual_content_sha256",
        "live_render_sha256",
    )
    dependencies = document.get("dependencies")
    if (
        set(document) != _LIVE_RENDER_KEYS
        or document.get("schema") != "reference-live-render/v1"
        or document.get("scenario_id") != scenario_id
        or document.get("request_id") != request_id
        or document.get("action_intent_id") != action_intent.get("action_intent_id")
        or document.get("action_intent_sha256") != action_intent.get("derivation_sha256")
        or document.get("approval_id") != approval.get("approval_id")
        or document.get("approval_sha256") != approval.get("approval_sha256")
        or document.get("execution_target") != "single-host-simulator-worker"
        or any(
            not isinstance(document.get(field), str)
            or _DIGEST.fullmatch(cast(str, document[field])) is None
            for field in digest_fields
        )
        or document.get("canonical_pixel_sha256") != document.get("expected_canonical_pixel_sha256")
        or document.get("output_equivalent") is not True
        or document.get("visual_content_sha256") != content_sha256
        or document.get("visual_width") != 960
        or document.get("visual_height") != 506
        or not isinstance(dependencies, Mapping)
        or set(dependencies) != {"openimageio", "opencolorio"}
        or dependencies.get("openimageio") not in {"3.0.6.1", "3.1.17.0"}
        or dependencies.get("opencolorio") != "2.5.2"
        or isinstance(document.get("wall_nanoseconds"), bool)
        or not isinstance(document.get("wall_nanoseconds"), int)
        or cast(int, document["wall_nanoseconds"]) < 0
        or document.get("live_render_sha256") != _digest(body)
        or not 1 <= len(result.png) <= 5 * 1024 * 1024
        or not result.png.startswith(b"\x89PNG\r\n\x1a\n")
        or len(result.png) < 24
        or result.png[12:16] != b"IHDR"
        or struct.unpack(">II", result.png[16:24]) != (960, 506)
    ):
        raise ReferenceLiveRenderError("reference-live-render-result-invalid")


_EXPECTED_TO_JOB_FIELD = {
    "resource_sha256": "effective_resource_sha256",
    "config_sha256": "effective_config_sha256",
    "config_generation": "config_generation",
    "frame_pipeline_sha256": "frame_pipeline_sha256",
    "derivative_parent_sha256": "derivative_parent_sha256",
    "derivative_generation": "derivative_generation",
    "cache_key": "cache_key",
}
_CLASS_CHANGED_FIELDS = {
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
_CLASS_DERIVED_AFFECTED_MISMATCH_FIELDS = {
    IncidentClass.RESOURCE_RESOLUTION_DRIFT: ("frame_pipeline_sha256",),
    IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: ("frame_pipeline_sha256",),
    IncidentClass.STALE_DERIVATIVE_CACHE: (),
}


def _mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReferenceDemoError(code)
    return cast(Mapping[str, Any], value)


def _sequence_of_strings(value: Any, code: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or any(not isinstance(item, str) for item in value)
        or len(value) != len(set(value))
    ):
        raise ReferenceDemoError(code)
    return tuple(cast(list[str], value))


def _representative_job(
    *,
    packet_id: str,
    job_id: str,
    role: str,
    facts: Mapping[str, Any],
) -> ReferenceJobState:
    digest_fields = (
        "effective_resource_sha256",
        "effective_config_sha256",
        "frame_pipeline_sha256",
        "derivative_parent_sha256",
    )
    generations = (facts.get("config_generation"), facts.get("derivative_generation"))
    cache_key = facts.get("cache_key")
    if (
        any(
            not isinstance(facts.get(name), str) or _DIGEST.fullmatch(facts[name]) is None
            for name in digest_fields
        )
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in generations
        )
        or not isinstance(cache_key, str)
        or _RUN_IDENTIFIER.fullmatch(cache_key) is None
        or facts.get("reference_state")
        != ("reference_mismatch" if role == "affected" else "reference_match")
    ):
        raise ReferenceDemoError("reference-run-recovery-state-invalid")
    derivative_sha256 = _digest(
        {
            "schema": "reference-representative-derivative-state/v3",
            "packet_id": packet_id,
            "role": role,
            "job_id": job_id,
            "effective_resource_sha256": facts["effective_resource_sha256"],
            "effective_config_sha256": facts["effective_config_sha256"],
            "config_generation": facts["config_generation"],
            "frame_pipeline_sha256": facts["frame_pipeline_sha256"],
            "derivative_parent_sha256": facts["derivative_parent_sha256"],
            "derivative_generation": facts["derivative_generation"],
            "cache_key": cache_key,
        }
    )
    try:
        return ReferenceJobState(
            job_id=job_id,
            effective_resource_sha256=cast(str, facts["effective_resource_sha256"]),
            effective_config_sha256=cast(str, facts["effective_config_sha256"]),
            config_generation=cast(int, facts["config_generation"]),
            frame_sha256=cast(str, facts["frame_pipeline_sha256"]),
            derivative_parent_sha256=cast(str, facts["derivative_parent_sha256"]),
            derivative_generation=cast(int, facts["derivative_generation"]),
            cache_key=cache_key,
            derivative_sha256=derivative_sha256,
        )
    except ReferenceRecoveryError as error:
        raise ReferenceDemoError("reference-run-recovery-state-invalid") from error


def _reference_recovery_context(
    packet: Mapping[str, Any],
    *,
    approval_boundary: ReferenceHumanApprovalBoundary,
) -> _ReferenceRecoveryContext | None:
    if packet.get("status") != "resolved":
        return None
    code = "reference-run-recovery-state-invalid"
    try:
        action_document = _mapping(packet.get("action_intent"), code)
        intent = validate_reference_action_intent(action_document)
        expected = _mapping(packet.get("expected_state_assessment"), code)
        operational = _mapping(packet.get("operational_evidence_assessment"), code)
        reconciliation = _mapping(packet.get("diagnosis_reconciliation"), code)
        expected_scope = _mapping(expected.get("scope"), code)
        reconciliation_scope = _mapping(reconciliation.get("scope"), code)
        approved = _mapping(expected.get("approved"), code)
        job_facts = _mapping(operational.get("job_facts"), code)
        action_parameters = _mapping(action_document.get("parameters"), code)
        action_expected = _mapping(action_parameters.get("expected"), code)
        action_observed = _mapping(action_parameters.get("observed"), code)
        affected = _sequence_of_strings(expected_scope.get("affected_job_ids"), code)
        protected = _sequence_of_strings(expected_scope.get("safe_job_ids"), code)
        fact_ids = _sequence_of_strings(operational.get("fact_ids"), code)
        reconciliation_fact_ids = _sequence_of_strings(
            reconciliation.get("evidence_fact_ids"), code
        )
        packet_id = packet.get("packet_id")
        if (
            len(affected) != 1
            or len(protected) != 1
            or set(affected) & set(protected)
            or not isinstance(packet_id, str)
            or _PACKET_ID.fullmatch(packet_id) is None
            or expected.get("status") != "supported"
            or operational.get("status") != "supported"
            or reconciliation.get("status") != "supported"
            or packet.get("no_action_reason") is not None
            or packet.get("scenario_id")
            not in {
                "tos-resource-resolution-drift-v1",
                "tos-config-rollout-drift-v1",
                "tos-stale-derivative-cache-v1",
            }
            or reconciliation.get("reconciliation_id") != intent.reconciliation_id
            or reconciliation.get("incident_class") != intent.incident_class.value
            or reconciliation_scope != expected_scope
            or reconciliation.get("action_intent") != action_document
            or tuple(intent.affected_job_ids) != affected
            or tuple(sorted(fact_ids)) != intent.evidence_fact_ids
            or tuple(sorted(reconciliation_fact_ids)) != intent.evidence_fact_ids
            or set(job_facts) != set(affected) | set(protected)
            or set(approved) != set(_EXPECTED_TO_JOB_FIELD)
        ):
            raise ReferenceDemoError(code)
        affected_facts = _mapping(job_facts[affected[0]], code)
        protected_facts = _mapping(job_facts[protected[0]], code)
        changed_fields = _CLASS_CHANGED_FIELDS[intent.incident_class]
        derived_mismatch_fields = _CLASS_DERIVED_AFFECTED_MISMATCH_FIELDS[intent.incident_class]
        allowed_affected_mismatches = set(changed_fields) | set(derived_mismatch_fields)
        if (
            set(action_expected) != set(changed_fields)
            or set(action_observed) != set(changed_fields)
            or any(
                action_expected[field]
                != approved[
                    next(
                        expected_name
                        for expected_name, job_field in _EXPECTED_TO_JOB_FIELD.items()
                        if job_field == field
                    )
                ]
                or action_observed[field] != affected_facts.get(field)
                for field in changed_fields
            )
            or any(
                protected_facts.get(job_field) != approved[expected_name]
                for expected_name, job_field in _EXPECTED_TO_JOB_FIELD.items()
            )
            or any(
                affected_facts.get(field)
                == approved[
                    next(
                        expected_name
                        for expected_name, job_field in _EXPECTED_TO_JOB_FIELD.items()
                        if job_field == field
                    )
                ]
                for field in derived_mismatch_fields
            )
            or any(
                affected_facts.get(job_field) != approved[expected_name]
                for expected_name, job_field in _EXPECTED_TO_JOB_FIELD.items()
                if job_field not in allowed_affected_mismatches
            )
        ):
            raise ReferenceDemoError(code)
        state = ReferenceRecoveryState(
            scenario_id=cast(str, packet["scenario_id"]),
            incident_class=intent.incident_class,
            generation=1,
            affected_job_ids=affected,
            protected_job_ids=protected,
            jobs=(
                _representative_job(
                    packet_id=packet_id,
                    job_id=affected[0],
                    role="affected",
                    facts=affected_facts,
                ),
                _representative_job(
                    packet_id=packet_id,
                    job_id=protected[0],
                    role="protected",
                    facts=protected_facts,
                ),
            ),
        )
        return _ReferenceRecoveryContext(
            packet=packet,
            action_intent=intent,
            initial_state=state,
            recovery=ReferenceRecoveryService(
                states=(state,),
                approval_boundary=approval_boundary,
            ),
        )
    except ReferenceDemoError:
        raise
    except (KeyError, ReferenceRecoveryError, StopIteration, TypeError, ValueError) as error:
        raise ReferenceDemoError(code) from error


def _state_reference(state: ReferenceRecoveryState) -> dict[str, Any]:
    return {
        "generation": state.generation,
        "state_sha256": state.state_sha256,
        "protected_state_sha256": state.protected_state_sha256,
    }


def _reference_recovery_decision(
    *,
    context: _ReferenceRecoveryContext,
    request: ReferenceRecoveryDecisionRequest,
    approval: Mapping[str, Any],
    before: ReferenceRecoveryState,
    after: ReferenceRecoveryState,
    receipt: Mapping[str, Any] | None,
    live_render: Mapping[str, Any] | None,
) -> dict[str, Any]:
    packet = context.packet
    approver = _mapping(approval.get("approver"), "reference-run-recovery-state-invalid")
    if (
        approver.get("kind") != "human"
        or approver.get("identity_verified") is not False
        or approver.get("identity_assurance") != "unverified-public-demo-gesture"
        or approver.get("gesture") != "explicit-phrase-and-nonce"
        or "identity" in approver
        or (receipt is None) != (request.decision == "denied")
    ):
        raise ReferenceDemoError("reference-run-recovery-state-invalid")
    verification: dict[str, Any] | None = None
    if receipt is not None:
        receipt_fields = {
            "schema",
            "approval_id",
            "approval_sha256",
            "action_intent_id",
            "action_intent_sha256",
            "reconciliation_id",
            "scenario_id",
            "incident_class",
            "command",
            "before",
            "after",
            "affected_job_ids",
            "protected_job_ids",
            "mutations",
            "protected_state_unchanged",
            "action_intent_requires_human_approval",
            "action_intent_authorizes_execution",
            "verification",
            "result",
            "receipt_id",
            "receipt_sha256",
        }
        receipt_verification = _mapping(
            receipt.get("verification"), "reference-run-recovery-state-invalid"
        )
        try:
            verification = validate_reference_recovery_verification(receipt_verification)
        except ReferenceRecoveryError as error:
            raise ReferenceDemoError("reference-run-recovery-state-invalid") from error
        receipt_body = {
            key: value
            for key, value in receipt.items()
            if key not in {"receipt_id", "receipt_sha256"}
        }
        expected_receipt_sha256 = _digest(receipt_body)
        expected_field_checks = [
            {
                "field": field,
                "expected_value": context.action_intent.parameters["expected"][field],
                "matched_job_ids": list(context.action_intent.affected_job_ids),
            }
            for field in context.action_intent.parameters["changed_fields"]
        ]
        if (
            set(receipt) != receipt_fields
            or receipt.get("schema") != "reference-recovery-receipt/v3"
            or receipt.get("receipt_sha256") != expected_receipt_sha256
            or receipt.get("receipt_id")
            != f"reference-recovery:{expected_receipt_sha256.removeprefix('sha256:')}"
            or receipt.get("approval_id") != approval.get("approval_id")
            or receipt.get("approval_sha256") != approval.get("approval_sha256")
            or receipt.get("action_intent_id") != context.action_intent.action_intent_id
            or receipt.get("action_intent_sha256") != context.action_intent.derivation_sha256
            or receipt.get("reconciliation_id") != context.action_intent.reconciliation_id
            or receipt.get("scenario_id") != packet.get("scenario_id")
            or receipt.get("incident_class") != context.action_intent.incident_class.value
            or receipt.get("command") != context.action_intent.command
            or receipt.get("affected_job_ids") != list(before.affected_job_ids)
            or receipt.get("protected_job_ids") != list(before.protected_job_ids)
            or receipt.get("protected_state_unchanged") is not True
            or receipt.get("action_intent_requires_human_approval") is not True
            or receipt.get("action_intent_authorizes_execution") is not False
            or receipt.get("result") != "applied"
            or receipt.get("before") != _state_reference(before)
            or receipt.get("after") != _state_reference(after)
            or verification.get("before") != receipt.get("before")
            or verification.get("after") != receipt.get("after")
            or verification.get("scenario_id") != packet.get("scenario_id")
            or verification.get("action_intent_id") != context.action_intent.action_intent_id
            or verification.get("action_intent_sha256") != context.action_intent.derivation_sha256
            or verification.get("reconciliation_id") != context.action_intent.reconciliation_id
            or verification.get("affected_job_ids") != list(context.action_intent.affected_job_ids)
            or verification.get("affected_expected_field_checks") != expected_field_checks
        ):
            raise ReferenceDemoError("reference-run-recovery-state-invalid")
    body = {
        "schema": REFERENCE_RECOVERY_DECISION_SCHEMA,
        "scenario_id": packet["scenario_id"],
        "request_id": request.request_id,
        "run_id": packet["run_id"],
        "packet_id": packet["packet_id"],
        "packet_sha256": packet["derivation_sha256"],
        "decision": request.decision,
        "outcome": "applied" if receipt is not None else "denied",
        "approval": dict(approval),
        "before": _state_reference(before),
        "after": _state_reference(after),
        "protected_state_unchanged": (
            before.protected_state_sha256 == after.protected_state_sha256
        ),
        "receipt": None if receipt is None else dict(receipt),
        "verification": verification,
        "live_render": None if live_render is None else dict(live_render),
        "scope": {
            "kind": "representative-simulator-state",
            "affected_job_count": 1,
            "protected_job_count": 1,
            "establishes_full_population_scope": False,
        },
        "execution_boundary": {
            "approval_actor_kind": "human",
            "approval_gesture": "explicit-phrase-and-nonce",
            "identity_verified": False,
            "identity_assurance": "unverified-public-demo-gesture",
            "execution_target": "colortrace-simulator",
            "simulator_state_changed": receipt is not None,
            "production_access_used": False,
            "production_state_changed": False,
            "production_claim": "none",
        },
    }
    return {**body, "decision_sha256": _digest(body)}


def _authority() -> dict[str, str]:
    return {
        "schema": REFERENCE_AUTHORITY_SCHEMA,
        "catalog_facts": "sealed-reference-contracts",
        "incident_facts": "deterministic-validators",
        "model_role": "advisory",
        "evidence_access": "grafana-mcp-read-only",
        "action_approval": "human-only",
        "action_execution_target": "colortrace-simulator",
    }


def _provenance(manifest: ReferenceMediaManifest) -> dict[str, Any]:
    return {
        "schema": REFERENCE_PROVENANCE_SCHEMA,
        "media_reference": dict(reference_manifest_identity(manifest)),
        "attribution": manifest.attribution,
        "license": {
            "spdx": manifest.license_spdx,
            "url": manifest.license_url,
        },
        "scenario_contract": "reference-scenario/v1",
    }


def _scope_summary(scenario: ReferenceScenario) -> dict[str, int]:
    return {
        "artifact_count": scenario.artifact_count,
        "affected_artifact_count": len(scenario.affected_artifact_ids),
        "protected_artifact_count": len(scenario.protected_artifact_ids),
    }


def _scenario_summary(
    scenario: ReferenceScenario,
    previews: ReferencePreviewCatalog,
) -> dict[str, Any]:
    scenario_document = scenario.to_dict()
    return {
        "scenario_id": scenario.scenario_id,
        "scenario_sha256": scenario_document["scenario_sha256"],
        "title": scenario.title,
        "symptom": scenario.symptom,
        "incident_class": scenario.incident_class,
        "recovery_kind": scenario.recovery_kind,
        "scope": _scope_summary(scenario),
        "visuals": [
            previews.visual(scenario.scenario_id, kind).descriptor(scenario_id=scenario.scenario_id)
            for kind in _VISUAL_KINDS
        ],
    }


def _evidence_requirements(scenario: ReferenceScenario) -> dict[str, Any]:
    fact_fields = {
        "resource-resolution-drift/v1": (
            "runtime.effective_resource_sha256",
            "runtime.frame_pipeline_sha256",
        ),
        "configuration-rollout-drift/v1": (
            "runtime.effective_config_sha256",
            "runtime.config_generation",
            "runtime.frame_pipeline_sha256",
        ),
        "stale-derivative-cache/v1": (
            "runtime.frame_pipeline_sha256",
            "derivative.parent_sha256",
            "cache.generation",
            "cache.key",
        ),
    }[scenario.incident_class]
    return {
        "minimum_complementary_signal_classes": 2,
        "runtime_fact_source": "structured-grafana-observations",
        "required_fact_fields": list(fact_fields),
        "decision_authority": "deterministic-validators",
        "missing_conflicting_or_cross-run_evidence": "unresolved",
        "live_run_scope": {
            "kind": "representative-evidence",
            "affected_job_count": 1,
            "protected_job_count": 1,
            "population_affected_artifact_count": len(scenario.affected_artifact_ids),
            "population_protected_artifact_count": len(scenario.protected_artifact_ids),
            "establishes_full_population_scope": False,
        },
    }


class ReferenceDemoCatalog:
    def __init__(
        self,
        *,
        manifest: ReferenceMediaManifest | None = None,
        scenarios: Mapping[str, ReferenceScenario] | None = None,
        previews: ReferencePreviewCatalog | None = None,
        benchmark_result_path: Path = REFERENCE_RESULT_PATH,
    ) -> None:
        self._manifest = manifest or load_reference_media_manifest()
        selected = scenarios or reference_scenarios(self._manifest)
        self._scenarios = {key: selected[key] for key in sorted(selected)}
        self._benchmark_result_path = benchmark_result_path
        try:
            self._previews = previews or load_reference_preview_catalog(
                expected_reference_manifest_sha256=self._manifest.manifest_sha256
            )
        except ReferencePreviewError as error:
            raise ReferenceDemoError("reference-preview-unavailable") from error
        if (
            not self._scenarios
            or any(key != scenario.scenario_id for key, scenario in self._scenarios.items())
            or any(
                scenario.artifact_count != self._manifest.frame_count
                for scenario in self._scenarios.values()
            )
            or set(self._previews.scenarios) != set(self._scenarios)
        ):
            raise ReferenceDemoError("reference-scenario-catalog-invalid")

    def _scenario(self, scenario_id: str) -> ReferenceScenario:
        try:
            return self._scenarios[scenario_id]
        except KeyError:
            raise ReferenceDemoError("reference-scenario-not-found") from None

    def list_scenarios(self) -> dict[str, Any]:
        document = {
            "schema": REFERENCE_SCENARIO_LIST_SCHEMA,
            "collection_id": self._manifest.collection_id,
            "items": [
                _scenario_summary(scenario, self._previews) for scenario in self._scenarios.values()
            ],
            "provenance": _provenance(self._manifest),
            "authority": _authority(),
        }
        document["catalog_sha256"] = _digest(document)
        return document

    def get_scenario(self, scenario_id: str) -> dict[str, Any]:
        scenario = self._scenario(scenario_id)
        document = {
            "schema": REFERENCE_SCENARIO_DETAIL_SCHEMA,
            "scenario": scenario.to_dict(),
            "summary": _scenario_summary(scenario, self._previews),
            "evidence_requirements": _evidence_requirements(scenario),
            "recovery_boundary": {
                "intent": scenario.recovery_kind,
                "requires_human_approval": True,
                "execution_target": "colortrace-simulator",
                "catalog_executes_actions": False,
            },
            "provenance": _provenance(self._manifest),
            "authority": _authority(),
        }
        document["detail_sha256"] = _digest(document)
        return document

    def scenario_visual(self, scenario_id: str, kind: str) -> ReferenceVisual:
        scenario = self._scenario(scenario_id)
        if kind not in _VISUAL_KINDS:
            raise ReferenceDemoError("reference-visual-not-found")
        try:
            asset = self._previews.visual(scenario_id, kind)
        except ReferencePreviewError:
            raise ReferenceDemoError("reference-visual-not-found") from None
        scenario_sha256 = str(scenario.to_dict()["scenario_sha256"])
        return ReferenceVisual(
            content=asset.content,
            media_type=asset.media_type,
            sha256=asset.sha256,
            scenario_sha256=scenario_sha256,
            representation=asset.representation,
            pixel_evidence=asset.pixel_evidence,
        )

    def benchmark_suite(self) -> dict[str, Any]:
        try:
            result = load_reference_impact_result(
                expected_collection_id=self._manifest.collection_id,
                expected_manifest_sha256=self._manifest.manifest_sha256,
                path=self._benchmark_result_path,
            )
        except ReferenceResultError as error:
            if error.code != "reference-result-unavailable":
                raise ReferenceDemoError("reference-benchmark-result-invalid") from error
            result = None
        scenario_scope = [
            {
                "scenario_id": scenario.scenario_id,
                "scenario_sha256": scenario.to_dict()["scenario_sha256"],
                "incident_class": scenario.incident_class,
                "rerender_all_artifact_count": scenario.artifact_count,
                "targeted_artifact_count": len(scenario.affected_artifact_ids),
                "protected_artifact_count": len(scenario.protected_artifact_ids),
                "scope_reduction_basis_points": (
                    len(scenario.protected_artifact_ids) * 10_000 // scenario.artifact_count
                ),
            }
            for scenario in self._scenarios.values()
        ]
        document = {
            "schema": REFERENCE_BENCHMARK_SUITE_SCHEMA,
            "suite_id": "tears-of-steel-reference-suite-v1",
            "definition_state": "sealed",
            "result_state": "recorded" if result is not None else "not-reported",
            "result": result,
            "scenarios": scenario_scope,
            "acceptance_requirements": {
                "output_equivalence": "required",
                "protected_output_integrity": "required",
                "maximum_false_authorized_actions": 0,
                "minimum_resolvable_holdout_accuracy_basis_points": 9_500,
                "minimum_median_compute_avoided_basis_points": 4_000,
                "minimum_median_bytes_avoided_basis_points": 4_000,
            },
            "measurement_boundary": {
                "scope_reduction_is_measured_result": False,
                "reported_results_require_recorded_evaluator_output": True,
                "catalog_claims_observed_savings": result is not None,
                "live_run_scope": "representative-evidence-only",
            },
            "provenance": _provenance(self._manifest),
            "authority": {
                **_authority(),
                "benchmark_result_authority": "recorded-evaluator-output",
            },
        }
        document["suite_sha256"] = _digest(document)
        return document


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ReferenceDemoError("reference-run-clock-invalid")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validate_telemetry_plan(
    plan: ReferenceTelemetryPlan,
    request: ReferenceScenarioRunRequest,
    *,
    incident_class: str,
    observed_at: datetime,
    emitted_at: datetime,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if (
        plan.scenario_id != request.scenario_id
        or plan.incident_class != incident_class
        or plan.incident_id != request.incident_id
        or plan.fixture_id != request.fixture_id
        or plan.run_id != request.run_id
        or not plan.events
    ):
        raise ReferenceDemoError("reference-run-telemetry-unavailable")
    events_by_role: dict[str, dict[str, Any]] = {"affected": {}, "protected": {}}
    for event in plan.events:
        role = event.attributes.get("reference.scope_role")
        if role not in events_by_role or event.signal in events_by_role[role]:
            raise ReferenceDemoError("reference-run-telemetry-unavailable")
        if (
            event.scenario_id != request.scenario_id
            or event.correlation.get("incident_id") != request.incident_id
            or event.correlation.get("fixture_id") != request.fixture_id
            or event.correlation.get("run_id") != request.run_id
            or event.attributes.get("reference.incident_class") != incident_class
        ):
            raise ReferenceDemoError("reference-run-telemetry-unavailable")
        events_by_role[role][event.signal] = event
    expected_timestamp = _timestamp(observed_at)
    expected_emitted_timestamp = _timestamp(emitted_at)
    common_correlation_fields = (
        "incident_id",
        "fixture_id",
        "run_id",
        "job_id",
        "worker_id",
        "artifact_id",
        "trace_id",
        "config_sha256",
        "transform_id",
    )
    if len(plan.events) != 6 or any(
        set(events) != {"metric", "log", "trace"}
        or any(
            {event.correlation[field] for event in events.values()}
            != {events["metric"].correlation[field]}
            for field in common_correlation_fields
        )
        or events["log"].correlation.get("resource_sha256")
        != events["log"]
        .attributes.get("runtime.effective_resource_sha256", "")
        .removeprefix("sha256:")
        or events["metric"].correlation.get("resource_sha256") != "none"
        or events["trace"].correlation.get("resource_sha256") != "none"
        or {event.observed_at for event in events.values()} != {expected_timestamp}
        or {event.emitted_at for event in events.values()} != {expected_emitted_timestamp}
        for events in events_by_role.values()
    ):
        raise ReferenceDemoError("reference-run-telemetry-unavailable")
    affected_state = _telemetry_state(events_by_role["affected"])
    protected_state = _telemetry_state(events_by_role["protected"])
    match_attributes = {
        "resource_sha256": "declared_reference.effective_resource_matches_approved",
        "config_sha256": "declared_reference.effective_config_matches_approved",
        "config_generation": "declared_reference.config_generation_matches_approved",
        "frame_pipeline_sha256": "declared_reference.frame_pipeline_matches_approved",
        "derivative_parent_sha256": ("declared_reference.derivative_parent_matches_approved"),
        "derivative_generation": ("declared_reference.derivative_generation_matches_approved"),
        "cache_key": "declared_reference.cache_key_matches_approved",
    }
    expected_false_fields = {
        "resource-resolution-drift/v1": {"resource_sha256", "frame_pipeline_sha256"},
        "configuration-rollout-drift/v1": {
            "config_sha256",
            "config_generation",
            "frame_pipeline_sha256",
        },
        "stale-derivative-cache/v1": {
            "derivative_parent_sha256",
            "derivative_generation",
        },
    }
    approved_sha256 = _digest(protected_state)
    for role, state in (("affected", affected_state), ("protected", protected_state)):
        metric_attributes = events_by_role[role]["metric"].attributes
        expected_flags = {
            field: "true" if value == protected_state[field] else "false"
            for field, value in state.items()
        }
        observed_flags = {
            field: metric_attributes.get(attribute) for field, attribute in match_attributes.items()
        }
        if (
            metric_attributes.get("declared_reference.approved_state_sha256") != approved_sha256
            or observed_flags != expected_flags
            or metric_attributes.get("declared_reference.state")
            != ("reference_mismatch" if role == "affected" else "reference_match")
        ):
            raise ReferenceDemoError("reference-run-telemetry-unavailable")
    if {
        field for field, value in affected_state.items() if value != protected_state[field]
    } != expected_false_fields[incident_class] or events_by_role["affected"]["metric"].correlation[
        "job_id"
    ] == events_by_role["protected"]["metric"].correlation["job_id"]:
        raise ReferenceDemoError("reference-run-telemetry-unavailable")
    return events_by_role["affected"], events_by_role["protected"]


def _telemetry_state(events: Mapping[str, Any]) -> dict[str, str | int]:
    log_attributes = events["log"].attributes
    trace_attributes = events["trace"].attributes
    if log_attributes.get("runtime.frame_pipeline_sha256") != trace_attributes.get(
        "runtime.frame_pipeline_sha256"
    ) or log_attributes.get("cache.key") != trace_attributes.get("cache.key"):
        raise ReferenceDemoError("reference-run-telemetry-unavailable")
    try:
        return {
            "resource_sha256": log_attributes["runtime.effective_resource_sha256"],
            "config_sha256": log_attributes["runtime.effective_config_sha256"],
            "config_generation": int(log_attributes["runtime.config_generation"]),
            "frame_pipeline_sha256": trace_attributes["runtime.frame_pipeline_sha256"],
            "derivative_parent_sha256": trace_attributes["derivative.parent_sha256"],
            "derivative_generation": int(trace_attributes["cache.generation"]),
            "cache_key": trace_attributes["cache.key"],
        }
    except (KeyError, TypeError, ValueError) as error:
        raise ReferenceDemoError("reference-run-telemetry-unavailable") from error


def _build_alert(
    *,
    request: ReferenceScenarioRunRequest,
    affected: Mapping[str, Any],
    observed_at: datetime,
    retrieved_at: datetime,
    alert_binding: Mapping[str, str],
) -> dict[str, Any]:
    fields = (
        "fixture_id",
        "run_id",
        "job_id",
        "worker_id",
        "artifact_id",
        "trace_id",
        "config_sha256",
        "transform_id",
    )
    try:
        correlation = {key: affected["metric"].correlation[key] for key in fields}
    except KeyError as error:
        raise ReferenceDemoError("reference-run-telemetry-unavailable") from error
    alert_seed = f"{request.scenario_id}\0{request.incident_id}\0{request.run_id}".encode()
    return {
        "schema": "alert-intake/v1",
        "incident_id": request.incident_id,
        "alert_id": f"reference-alert-{hashlib.sha256(alert_seed).hexdigest()[:24]}",
        "alert_started_at": _timestamp(observed_at),
        "retrieved_at": _timestamp(retrieved_at),
        "measured_clock_skew_seconds": 0,
        "binding": dict(alert_binding),
        "correlation_keys": correlation,
        "predecessor_event_sha256": None,
    }


def _expected_state_from_telemetry(
    request: ReferenceScenarioRunRequest,
    *,
    intake: AlertIntake,
    protected: Mapping[str, Any],
) -> dict[str, Any]:
    intake_window = intake.window.to_dict()
    if (
        intake.incident_id != request.incident_id
        or intake.correlation_keys.get("fixture_id") != request.fixture_id
        or intake.correlation_keys.get("run_id") != request.run_id
    ):
        raise ReferenceDemoError("reference-run-telemetry-unavailable")
    approved = _telemetry_state(protected)
    body = {
        "schema": "reference-expected-state/v1",
        "scenario_id": request.scenario_id,
        "fixture_id": request.fixture_id,
        "run_id": request.run_id,
        "evidence_window": {
            "start": intake_window["start"],
            "end": intake_window["end"],
        },
        "approved": approved,
        "scope": {
            "affected_job_ids": [intake.correlation_keys["job_id"]],
            "safe_job_ids": [protected["metric"].correlation["job_id"]],
        },
    }
    expected_sha256 = _digest(body)
    return {
        **body,
        "expected_state_id": f"expected-state:{expected_sha256.removeprefix('sha256:')}",
        "expected_state_sha256": expected_sha256,
    }


def _validate_telemetry_receipt(
    receipt: Mapping[str, Any],
    *,
    plan: ReferenceTelemetryPlan,
) -> None:
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if (
        receipt.get("schema") != "reference-demonstration-telemetry-receipt/v1"
        or receipt.get("plan_sha256") != plan.plan_sha256
        or receipt.get("scenario_id") != plan.scenario_id
        or receipt.get("incident_id") != plan.incident_id
        or receipt.get("fixture_id") != plan.fixture_id
        or receipt.get("run_id") != plan.run_id
        or receipt.get("signals") != ["metric", "log", "trace"]
        or receipt.get("scope_roles") != ["affected", "protected"]
        or receipt.get("events") != [event.to_dict() for event in plan.events]
        or receipt.get("receipt_sha256") != _digest(receipt_body)
    ):
        raise ReferenceDemoError("reference-run-telemetry-unavailable")


class ReferenceScenarioRunService:
    def __init__(
        self,
        *,
        workflow: ReferenceInvestigationWorkflowPort,
        telemetry: ReferenceScenarioTelemetryPort,
        evidence_binding: Mapping[str, str],
        alert_rule_uid: str,
        scenarios: Mapping[str, ReferenceScenario] | None = None,
        clock: Callable[[], datetime] | None = None,
        telemetry_settle_seconds: float = 0.0,
        approval_boundary: ReferenceHumanApprovalBoundary | None = None,
        maximum_in_flight: int = REFERENCE_RUN_MAX_IN_FLIGHT,
        run_deadline_seconds: float = REFERENCE_RUN_DEADLINE_SECONDS,
        renderer: ReferenceLiveRenderer | None = None,
        live_render_timeout_seconds: float = _REFERENCE_LIVE_RENDER_TIMEOUT_SECONDS,
    ) -> None:
        selected = scenarios or reference_scenarios()
        self._scenarios = dict(selected)
        self._workflow = workflow
        self._telemetry = telemetry
        self._clock = clock or (lambda: datetime.now(UTC))
        self._approval_boundary = approval_boundary or ReferenceHumanApprovalBoundary(
            audience="colortrace-simulator",
            clock=self._clock,
        )
        self._telemetry_settle_seconds = telemetry_settle_seconds
        self._maximum_in_flight = maximum_in_flight
        self._run_deadline_seconds = run_deadline_seconds
        self._renderer = renderer
        self._live_render_timeout_seconds = live_render_timeout_seconds
        self._live_render_lock = threading.Lock()
        self._alert_binding = {
            **dict(evidence_binding),
            "alert_rule_uid": alert_rule_uid,
        }
        if set(self._alert_binding) != {
            "prometheus_datasource_uid",
            "loki_datasource_uid",
            "tempo_datasource_uid",
            "alert_rule_uid",
        } or any(not value for value in self._alert_binding.values()):
            raise ReferenceDemoError("reference-run-configuration-invalid")
        if (
            not 0 <= telemetry_settle_seconds <= 30
            or isinstance(maximum_in_flight, bool)
            or not 1 <= maximum_in_flight <= 32
            or isinstance(run_deadline_seconds, bool)
            or not 0 < run_deadline_seconds <= 300
            or isinstance(live_render_timeout_seconds, bool)
            or not 0 < live_render_timeout_seconds <= 60
            or frozenset(self._scenarios)
            != frozenset(
                {
                    "tos-resource-resolution-drift-v1",
                    "tos-config-rollout-drift-v1",
                    "tos-stale-derivative-cache-v1",
                }
            )
        ):
            raise ReferenceDemoError("reference-scenario-catalog-invalid")
        self._replay_lock = asyncio.Lock()
        self._decision_lock = asyncio.Lock()
        self._replay_cache: OrderedDict[tuple[str, str], _CachedReferenceRun] = OrderedDict()
        self._in_flight: dict[tuple[str, str], asyncio.Task[dict[str, Any]]] = {}

    def _remember_run(self, key: tuple[str, str], value: _CachedReferenceRun) -> None:
        self._replay_cache[key] = value
        self._replay_cache.move_to_end(key)
        while len(self._replay_cache) > _REFERENCE_RUN_REPLAY_CACHE_SIZE:
            self._replay_cache.popitem(last=False)

    async def _run_and_cache(
        self,
        key: tuple[str, str],
        request: ReferenceScenarioRunRequest,
    ) -> dict[str, Any]:
        try:
            async with asyncio.timeout(self._run_deadline_seconds):
                packet = await self._run_uncached(request)
                recovery = _reference_recovery_context(
                    packet,
                    approval_boundary=self._approval_boundary,
                )
                cached = _CachedReferenceRun(
                    packet=_canonical_json(packet),
                    recovery=recovery,
                )
        except TimeoutError:
            async with self._replay_lock:
                self._in_flight.pop(key, None)
            raise ReferenceDemoError("reference-run-deadline-exceeded") from None
        except ReferenceDemoError as error:
            async with self._replay_lock:
                self._remember_run(key, _CachedReferenceRun(error_code=error.code))
                self._in_flight.pop(key, None)
            raise
        except asyncio.CancelledError:
            async with self._replay_lock:
                self._in_flight.pop(key, None)
            raise
        async with self._replay_lock:
            self._remember_run(key, cached)
            self._in_flight.pop(key, None)
        return cast(dict[str, Any], json.loads(cast(bytes, cached.packet)))

    @staticmethod
    def _consume_task_exception(task: asyncio.Task[dict[str, Any]]) -> None:
        if not task.cancelled():
            task.exception()

    async def run_scenario(
        self,
        scenario_id: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        if scenario_id not in self._scenarios:
            raise ReferenceDemoError("reference-scenario-not-found")
        parsed = ReferenceScenarioRunRequest.from_mapping(scenario_id, request)
        replay_key = (scenario_id, parsed.request_id)
        async with self._replay_lock:
            cached = self._replay_cache.get(replay_key)
            if cached is not None:
                self._replay_cache.move_to_end(replay_key)
                if cached.error_code is not None:
                    raise ReferenceDemoError(cached.error_code)
                return cast(dict[str, Any], json.loads(cast(bytes, cached.packet)))
            task = self._in_flight.get(replay_key)
            if task is None:
                if len(self._in_flight) >= self._maximum_in_flight:
                    raise ReferenceDemoError("reference-run-overloaded")
                task = asyncio.create_task(self._run_and_cache(replay_key, parsed))
                task.add_done_callback(self._consume_task_exception)
                self._in_flight[replay_key] = task
        return await asyncio.shield(task)

    async def decide_scenario(
        self,
        scenario_id: str,
        request_id: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        if scenario_id not in self._scenarios:
            raise ReferenceDemoError("reference-scenario-not-found")
        parsed = ReferenceRecoveryDecisionRequest.from_mapping(request_id, request)
        replay_key = (scenario_id, request_id)
        async with self._replay_lock:
            pending = self._in_flight.get(replay_key)
        if pending is not None:
            try:
                await asyncio.shield(pending)
            except ReferenceDemoError:
                raise ReferenceDemoError("reference-run-not-found") from None
        async with self._decision_lock:
            async with self._replay_lock:
                cached = self._replay_cache.get(replay_key)
                if cached is not None:
                    self._replay_cache.move_to_end(replay_key)
            if cached is None or cached.packet is None:
                raise ReferenceDemoError("reference-run-not-found")
            context = cached.recovery
            if context is None:
                raise ReferenceDemoError("reference-recovery-run-unresolved")
            packet = context.packet
            expected = _mapping(
                packet.get("expected_state_assessment"), "reference-run-output-unavailable"
            )
            binding = (
                parsed.packet_id,
                parsed.packet_sha256,
                parsed.expected_state_sha256,
                parsed.reconciliation_id,
                parsed.action_intent_id,
                parsed.action_intent_sha256,
            )
            expected_binding = (
                packet.get("packet_id"),
                packet.get("derivation_sha256"),
                expected.get("expected_state_sha256"),
                context.action_intent.reconciliation_id,
                context.action_intent.action_intent_id,
                context.action_intent.derivation_sha256,
            )
            if binding != expected_binding:
                raise ReferenceDemoError("reference-recovery-decision-binding-conflict")
            request_sha256 = _digest(parsed.to_dict())
            previous = context.decisions.get(parsed.approval_nonce)
            if previous is not None:
                if not hmac.compare_digest(previous.request_sha256, request_sha256):
                    raise ReferenceDemoError("reference-recovery-decision-conflict")
                if previous.error_code is not None:
                    raise ReferenceDemoError(previous.error_code)
                return cast(dict[str, Any], json.loads(cast(bytes, previous.response)))
            if context.terminal_request_sha256 is not None:
                raise ReferenceDemoError("reference-recovery-decision-conflict")
            before = context.recovery.snapshot(scenario_id)
            live_result: ReferenceLiveRenderResult | None = None
            try:
                approval = self._approval_boundary.issue_public_demo_gesture(
                    context.action_intent,
                    before,
                    decision=parsed.decision,
                    approval_nonce=parsed.approval_nonce,
                    approval_phrase=parsed.approval_phrase,
                )
                if parsed.decision == "approved":
                    if self._renderer is None:
                        raise ReferenceLiveRenderError("reference-live-render-unavailable")
                    try:
                        live_result = await asyncio.wait_for(
                            asyncio.to_thread(
                                self._render_live_once,
                                scenario_id=scenario_id,
                                request_id=request_id,
                                action_intent=context.action_intent.to_dict(),
                                approval=approval.to_dict(),
                            ),
                            timeout=self._live_render_timeout_seconds,
                        )
                        _validate_live_render_result(
                            live_result,
                            scenario_id=scenario_id,
                            request_id=request_id,
                            action_intent=context.action_intent.to_dict(),
                            approval=approval.to_dict(),
                        )
                    except TimeoutError as error:
                        raise ReferenceLiveRenderError("reference-live-render-timeout") from error
                    receipt = context.recovery.execute(context.action_intent, approval)
                else:
                    receipt = None
                after = context.recovery.snapshot(scenario_id)
            except (ReferenceLiveRenderError, ReferenceRecoveryError) as error:
                context.decisions[parsed.approval_nonce] = _CachedReferenceDecision(
                    request_sha256=request_sha256,
                    error_code=error.code,
                )
                raise ReferenceDemoError(error.code) from error
            response = _reference_recovery_decision(
                context=context,
                request=parsed,
                approval=approval.to_dict(),
                before=before,
                after=after,
                receipt=receipt,
                live_render=None if live_result is None else live_result.document,
            )
            encoded = _canonical_json(response)
            context.decisions[parsed.approval_nonce] = _CachedReferenceDecision(
                request_sha256=request_sha256,
                response=encoded,
            )
            context.terminal_request_sha256 = request_sha256
            if live_result is not None:
                context.live_visual = ReferenceLiveVisual(
                    content=live_result.png,
                    sha256=cast(str, live_result.document["visual_content_sha256"]),
                    scenario_id=scenario_id,
                    request_id=request_id,
                    decision_sha256=cast(str, response["decision_sha256"]),
                    worker_receipt_sha256=cast(str, live_result.document["worker_receipt_sha256"]),
                )
            return cast(dict[str, Any], json.loads(encoded))

    def _render_live_once(
        self,
        *,
        scenario_id: str,
        request_id: str,
        action_intent: Mapping[str, Any],
        approval: Mapping[str, Any],
    ) -> ReferenceLiveRenderResult:
        if self._renderer is None or not self._live_render_lock.acquire(blocking=False):
            raise ReferenceLiveRenderError("reference-live-render-unavailable")
        try:
            return self._renderer.render(
                scenario_id=scenario_id,
                request_id=request_id,
                action_intent=action_intent,
                approval=approval,
            )
        finally:
            self._live_render_lock.release()

    def live_visual(self, scenario_id: str, request_id: str) -> ReferenceLiveVisual:
        context = self._replay_cache.get((scenario_id, request_id))
        if context is None or context.recovery is None or context.recovery.live_visual is None:
            raise ReferenceDemoError("reference-live-visual-not-found")
        return context.recovery.live_visual

    async def _run_uncached(
        self,
        parsed: ReferenceScenarioRunRequest,
    ) -> dict[str, Any]:
        scenario_id = parsed.scenario_id
        try:
            observed_at = self._clock()
            emitted_at = self._clock()
            plan = self._telemetry.prepare(
                scenario_id,
                incident_id=parsed.incident_id,
                fixture_id=parsed.fixture_id,
                run_id=parsed.run_id,
                observed_at=observed_at,
                emitted_at=emitted_at,
            )
            affected, protected = _validate_telemetry_plan(
                plan,
                parsed,
                incident_class=self._scenarios[scenario_id].incident_class,
                observed_at=observed_at,
                emitted_at=emitted_at,
            )
            receipt = await self._telemetry.emit(plan)
            _validate_telemetry_receipt(receipt, plan=plan)
            if self._telemetry_settle_seconds:
                await asyncio.sleep(self._telemetry_settle_seconds)
            alert = _build_alert(
                request=parsed,
                affected=affected,
                observed_at=observed_at,
                retrieved_at=self._clock(),
                alert_binding=self._alert_binding,
            )
            intake = AlertIntake.from_mapping(alert)
            expected_state = _expected_state_from_telemetry(
                parsed,
                intake=intake,
                protected=protected,
            )
        except ReferenceDemoError:
            raise
        except ContractError as error:
            raise ReferenceDemoError("reference-run-telemetry-unavailable") from error
        except Exception as error:
            raise ReferenceDemoError("reference-run-telemetry-unavailable") from error
        try:
            packet = await self._workflow.run(
                alert=alert,
                expected_state=expected_state,
            )
        except ReferenceInvestigationError as error:
            raise ReferenceDemoError("reference-run-unavailable") from error
        except Exception as error:
            raise ReferenceDemoError("reference-run-unavailable") from error
        try:
            validate_reference_response_packet(packet)
        except (ContractError, TypeError, ValueError) as error:
            raise ReferenceDemoError("reference-run-output-unavailable") from error
        expected_assessment = packet.get("expected_state_assessment")
        operational_assessment = packet.get("operational_evidence_assessment")
        reference_evidence = packet.get("reference_evidence")
        reconciliation = packet.get("diagnosis_reconciliation")
        packet_status = packet.get("status")
        operational_request_id = (
            operational_assessment.get("request_id")
            if isinstance(operational_assessment, Mapping)
            else None
        )
        operational_incident_id = (
            operational_assessment.get("incident_id")
            if isinstance(operational_assessment, Mapping)
            else None
        )
        reference_request_id = (
            reference_evidence.get("request_id")
            if isinstance(reference_evidence, Mapping)
            else None
        )
        if (
            packet.get("schema") != "response-packet/v3"
            or packet.get("scenario_id") != scenario_id
            or packet.get("incident_id") != parsed.incident_id
            or packet.get("fixture_id") != parsed.fixture_id
            or packet.get("run_id") != parsed.run_id
            or packet.get("fixed_window") != expected_state["evidence_window"]
            or not isinstance(expected_assessment, Mapping)
            or expected_assessment.get("expected_state_sha256")
            != expected_state["expected_state_sha256"]
            or expected_assessment.get("scope") != expected_state["scope"]
            or not isinstance(operational_assessment, Mapping)
            or not isinstance(reference_evidence, Mapping)
            or (
                packet_status == "resolved"
                and (
                    operational_request_id != reference_request_id
                    or operational_incident_id != parsed.incident_id
                )
            )
            or (
                packet_status == "unresolved"
                and (
                    operational_request_id not in {None, reference_request_id}
                    or operational_incident_id not in {None, parsed.incident_id}
                )
            )
            or (
                packet_status == "resolved"
                and (
                    not isinstance(reconciliation, Mapping)
                    or reconciliation.get("incident_class")
                    != self._scenarios[scenario_id].incident_class
                    or reconciliation.get("scope") != expected_state["scope"]
                )
            )
        ):
            raise ReferenceDemoError("reference-run-output-unavailable")
        return packet


__all__ = [
    "REFERENCE_APPROVAL_PHRASE",
    "REFERENCE_AUTHORITY_SCHEMA",
    "REFERENCE_BENCHMARK_SUITE_SCHEMA",
    "REFERENCE_DENIAL_PHRASE",
    "REFERENCE_PROVENANCE_SCHEMA",
    "REFERENCE_RECOVERY_DECISION_REQUEST_SCHEMA",
    "REFERENCE_RECOVERY_DECISION_SCHEMA",
    "REFERENCE_RUN_DEADLINE_SECONDS",
    "REFERENCE_RUN_MAX_IN_FLIGHT",
    "REFERENCE_SCENARIO_RUN_REQUEST_SCHEMA",
    "REFERENCE_SCENARIO_DETAIL_SCHEMA",
    "REFERENCE_SCENARIO_LIST_SCHEMA",
    "GeneratedReferenceScenarioTelemetry",
    "ReferenceDemoApi",
    "ReferenceDemoCatalog",
    "ReferenceDemoError",
    "ReferenceInvestigationWorkflowPort",
    "ReferenceRecoveryDecisionRequest",
    "ReferenceScenarioRunApi",
    "ReferenceScenarioRunRequest",
    "ReferenceScenarioRunService",
    "ReferenceScenarioTelemetryPort",
    "ReferenceVisual",
]
