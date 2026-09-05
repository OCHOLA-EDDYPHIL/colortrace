from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic as system_monotonic
from typing import Any, Protocol, cast

from colortrace_grafana_mcp import (
    ADAPTIVE_QUERY_KEYS,
    AdapterError,
    EvidenceBatch,
    ExecutionControls,
    NormalizedRuntimeObservation,
    RuntimeEvidenceProjection,
)
from colortrace_validator import (
    AssessmentStatus,
    DiagnosisReconciliation,
    ExpectedStateAssessment,
    IncidentClassAssessment,
    OperationalEvidenceAssessment,
    assess_expected_state,
    assess_incident_classes,
    assess_operational_evidence,
    reconcile_diagnosis,
)

from .contracts import (
    MODEL_ID,
    REFERENCE_POLICY_DOCUMENT,
    REFERENCE_POLICY_SHA256,
    REFERENCE_POLICY_VERSION,
    SCHEMA_ROOT,
    AlertIntake,
    ContractError,
    ReferenceModelSelection,
    canonical_json_bytes,
    finalize_reference_evidence,
    finalize_reference_response_packet,
    prefixed_sha256,
    sha256,
    strict_json_file,
    timestamp,
)
from .model import AllowedQueryKey, ModelCall, ModelFailure, ModelGateway

_BASELINE_QUERY = "alert.rule"
_POST_BASELINE_QUERIES = tuple(key for key in ADAPTIVE_QUERY_KEYS if key != _BASELINE_QUERY)
_EXACT_QUERIES = (
    "log.correlated-events",
    "metric.correlated-observations",
    "trace.by-id",
)
_COHORT_QUERIES = ("metric.worker-cohort", "log.config-cohort")
_QUERY_SIGNALS = {
    "log.correlated-events": "log",
    "log.config-cohort": "log",
    "metric.correlated-observations": "metric",
    "metric.worker-cohort": "metric",
    "trace.by-id": "trace",
}
_MAXIMUM_POST_BASELINE_CALLS = 3
_REFERENCE_ALERT_RULE_UID = "ct-reference-demo-divergence-v1"
_REFERENCE_FIXTURE_ID = "tears-of-steel-linear-exr-240-v1"
_REFERENCE_DATA_ORIGIN = "generated-demonstration-telemetry"
_MODEL_VISIBLE_RUNTIME_ATTRIBUTES = frozenset(
    {
        "declared_reference.state",
        "declared_reference.effective_resource_matches_approved",
        "declared_reference.effective_config_matches_approved",
        "declared_reference.config_generation_matches_approved",
        "declared_reference.frame_pipeline_matches_approved",
        "declared_reference.derivative_parent_matches_approved",
        "declared_reference.derivative_generation_matches_approved",
        "declared_reference.cache_key_matches_approved",
        "runtime.effective_resource_sha256",
        "runtime.effective_config_sha256",
        "runtime.config_generation",
        "runtime.frame_pipeline_sha256",
        "derivative.parent_sha256",
        "cache.generation",
        "cache.key",
    }
)


class ReferenceInvestigationError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ReferenceEvidenceCollection(Protocol):
    async def collect(self, query_key: str) -> Mapping[str, Any]: ...

    def result(self) -> Any: ...


class ReferenceEvidenceAdapter(Protocol):
    def open_collection(
        self,
        batch: EvidenceBatch,
        *,
        controls: ExecutionControls | None = None,
    ) -> AbstractAsyncContextManager[ReferenceEvidenceCollection]: ...

    def normalize_runtime_observations(
        self,
        batch: EvidenceBatch,
        envelopes: Sequence[Mapping[str, Any]],
    ) -> tuple[NormalizedRuntimeObservation, ...]: ...


@dataclass(frozen=True, slots=True)
class _AssessmentChain:
    expected: ExpectedStateAssessment
    operational: OperationalEvidenceAssessment
    classes: tuple[IncidentClassAssessment, ...]
    reconciliation: DiagnosisReconciliation


class _AgentTrace:
    def __init__(self, trace_id: str, monotonic: Callable[[], float]) -> None:
        self.trace_id = trace_id
        self._monotonic = monotonic
        self._spans: list[dict[str, Any]] = []

    def start(
        self,
        stage: str,
        *,
        query_key: str | None = None,
        attempts: int = 0,
        attempts_complete: bool = True,
        unobserved_model_calls: int = 0,
    ) -> tuple[int, float]:
        index = len(self._spans)
        self._spans.append(
            {
                "sequence": index,
                "stage": stage,
                "status": "unresolved",
                "duration_ms": 0,
                "query_key": query_key,
                "input_tokens": None,
                "output_tokens": None,
                "attempts": attempts,
                "attempts_complete": attempts_complete,
                "unobserved_model_calls": unobserved_model_calls,
                "error_code": None,
            }
        )
        return index, self._monotonic()

    def finish(
        self,
        token: tuple[int, float],
        *,
        status: str,
        error_code: str | None = None,
        attempts: int | None = None,
        attempts_complete: bool | None = None,
        unobserved_model_calls: int | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
    ) -> None:
        index, started = token
        span = self._spans[index]
        span["status"] = status
        span["duration_ms"] = min(
            120_000,
            max(0, int((self._monotonic() - started) * 1000)),
        )
        span["error_code"] = error_code
        span["input_tokens"] = input_tokens
        span["output_tokens"] = output_tokens
        if attempts is not None:
            span["attempts"] = attempts
        if attempts_complete is not None:
            span["attempts_complete"] = attempts_complete
        if unobserved_model_calls is not None:
            span["unobserved_model_calls"] = unobserved_model_calls

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "agent-trace/v2",
            "trace_id": self.trace_id,
            "spans": [dict(span) for span in self._spans],
        }

    @property
    def empty(self) -> bool:
        return not self._spans


def _plain_observation(value: NormalizedRuntimeObservation) -> dict[str, Any]:
    return value.to_dict()


def _assess(
    expected: ExpectedStateAssessment,
    observations: Sequence[NormalizedRuntimeObservation],
    *,
    request_id: str,
    incident_id: str,
) -> _AssessmentChain:
    operational = assess_operational_evidence(
        expected,
        [_plain_observation(value) for value in observations],
    )
    if operational.request_id not in {None, request_id} or operational.incident_id not in {
        None,
        incident_id,
    }:
        raise ReferenceInvestigationError("operational-evidence-binding-invalid")
    classes = assess_incident_classes(expected, operational)
    reconciliation = reconcile_diagnosis(expected, operational, classes)
    return _AssessmentChain(expected, operational, classes, reconciliation)


def _envelope_evidence_id(envelope: Mapping[str, Any]) -> str | None:
    value = envelope.get("evidence_id")
    if isinstance(value, str) and value.startswith("sha256:") and len(value) == 71:
        return value
    return None


def _collection_attempts(envelope: Mapping[str, Any]) -> int:
    value = envelope.get("collection")
    if not isinstance(value, Mapping):
        return 0
    attempts = value.get("attempts")
    return attempts if isinstance(attempts, int) and not isinstance(attempts, bool) else 0


def _collection_envelope_for_query(
    envelope: Mapping[str, Any] | None,
    query_key: str,
) -> Mapping[str, Any] | None:
    if envelope is None:
        return None
    observation = envelope.get("observation")
    if not isinstance(observation, Mapping) or observation.get("query_key") != query_key:
        return None
    return envelope


def _baseline_view(envelope: Mapping[str, Any]) -> dict[str, Any]:
    observation = envelope.get("observation")
    collection = envelope.get("collection")
    content = envelope.get("content")
    correlation = envelope.get("correlation_keys")
    evidence_id = _envelope_evidence_id(envelope)
    arguments = (
        observation.get("normalized_arguments") if isinstance(observation, Mapping) else None
    )
    if (
        not isinstance(observation, Mapping)
        or observation.get("query_key") != _BASELINE_QUERY
        or not isinstance(arguments, Mapping)
        or arguments.get("operation") != "get"
        or arguments.get("rule_uid") != _REFERENCE_ALERT_RULE_UID
        or arguments.get("limit_alerts") != 100
        or not isinstance(collection, Mapping)
        or collection.get("outcome") != "collected"
        or collection.get("error") is not None
        or not isinstance(content, Mapping)
        or content.get("uid") != _REFERENCE_ALERT_RULE_UID
        or not isinstance(content.get("annotations"), Mapping)
        or content["annotations"].get("reference_fixture_id") != _REFERENCE_FIXTURE_ID
        or content["annotations"].get("reference_data_origin") != _REFERENCE_DATA_ORIGIN
        or content["annotations"].get("evidence_scope") != "representative"
        or not isinstance(content.get("alerts"), list)
        or not isinstance(correlation, Mapping)
        or evidence_id is None
    ):
        raise ReferenceInvestigationError("baseline-evidence-invalid")
    if not isinstance(envelope.get("display_excerpt"), str):
        raise ReferenceInvestigationError("baseline-evidence-invalid")
    matching_alerts: list[Mapping[str, Any]] = []
    for alert in content["alerts"]:
        if (
            not isinstance(alert, Mapping)
            or not isinstance(alert.get("state"), str)
            or not isinstance(alert.get("labels"), Mapping)
        ):
            raise ReferenceInvestigationError("baseline-evidence-invalid")
        labels = cast(Mapping[str, Any], alert["labels"])
        if all(labels.get(name) == child for name, child in correlation.items()):
            matching_alerts.append(alert)
    states: set[str] = set()
    for alert in matching_alerts:
        state = str(alert["state"]).strip().lower()
        states.add(
            state
            if state in {"alerting", "firing", "pending", "normal", "recovering", "nodata", "error"}
            else "unknown"
        )
    if states & {"alerting", "firing"}:
        alert_state = "firing"
    elif "pending" in states:
        alert_state = "pending"
    elif states:
        alert_state = "not-firing"
    else:
        alert_state = "no-correlated-instance"
    return {
        "schema": "grafana-reference-baseline-view/v1",
        "query_key": _BASELINE_QUERY,
        "evidence_id": evidence_id,
        "rule_uid": _REFERENCE_ALERT_RULE_UID,
        "fixture_id": _REFERENCE_FIXTURE_ID,
        "evidence_scope": "representative",
        "alert_state": alert_state,
        "correlated_alert_instance_count": len(matching_alerts),
        "rule_alert_instance_count": len(content["alerts"]),
        "provider_excerpt_exposed": False,
        "trust": "untrusted-provider-data",
    }


def _coverage(
    expected: ExpectedStateAssessment,
    observations: Sequence[NormalizedRuntimeObservation],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for job_id in (*expected.affected_job_ids, *expected.safe_job_ids):
        selected = [value for value in observations if value.job_id == job_id]
        result.append(
            {
                "job_id": job_id,
                "expected_scope": (
                    "affected" if job_id in expected.affected_job_ids else "protected"
                ),
                "signals": sorted({value.signal for value in selected}),
                "fact_ids": sorted({value.fact_id for value in selected}),
            }
        )
    return result


def _model_observations(
    observations: Sequence[NormalizedRuntimeObservation],
    *,
    query_key: str,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for value in observations:
        if value.provenance.get("query_key") != query_key:
            continue
        result.append(
            {
                "fact_id": value.fact_id,
                "evidence_id": value.provenance["evidence_id"],
                "signal": value.signal,
                "job_id": value.job_id,
                "attributes": {
                    key: child
                    for key, child in value.attributes.items()
                    if key in _MODEL_VISIBLE_RUNTIME_ATTRIBUTES
                },
            }
        )
    return result


def _terminal_from_chain(chain: _AssessmentChain, *, calls_used: int) -> tuple[str, str]:
    if chain.reconciliation.status is AssessmentStatus.SUPPORTED:
        return "resolved", "sufficient-evidence"
    if chain.reconciliation.status is AssessmentStatus.CONFLICTING:
        return "unresolved", "conflicting-evidence"
    if calls_used >= _MAXIMUM_POST_BASELINE_CALLS:
        return "unresolved", "incomplete-evidence"
    return "continue", "incomplete-evidence"


def _trace_entry(
    *,
    sequence: int,
    selected_by: str,
    query_key: str,
    evidence_id: str | None,
    disposition: str,
    reason_codes: Sequence[str],
    chain: _AssessmentChain,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "selected_by": selected_by,
        "query_key": query_key,
        "evidence_id": evidence_id,
        "disposition": disposition,
        "reason_codes": sorted(set(reason_codes)),
        "operational_assessment_id": chain.operational.assessment_id,
        "reconciliation_id": chain.reconciliation.reconciliation_id,
    }


class ReferenceInvestigationWorkflow:
    def __init__(
        self,
        *,
        model: ModelGateway,
        evidence: ReferenceEvidenceAdapter,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        self._model = model
        self._evidence = evidence
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or system_monotonic

    async def run(
        self,
        *,
        alert: Mapping[str, Any],
        expected_state: Mapping[str, Any],
    ) -> dict[str, Any]:
        try:
            intake = AlertIntake.from_mapping(alert)
        except (ContractError, TypeError, ValueError) as error:
            raise ReferenceInvestigationError("invalid-intake") from error
        expected = assess_expected_state(expected_state)
        if expected.status is not AssessmentStatus.SUPPORTED:
            raise ReferenceInvestigationError("expected-state-invalid")
        batch = intake.adaptive_evidence_batch(ADAPTIVE_QUERY_KEYS)
        if (
            expected.fixture_id != batch.correlation_keys["fixture_id"]
            or expected.run_id != batch.correlation_keys["run_id"]
            or expected.window_start != timestamp(batch.window_start)
            or expected.window_end != timestamp(batch.window_end)
        ):
            raise ReferenceInvestigationError("expected-state-binding-invalid")

        trace_id = sha256(f"{intake.incident_id}\0{batch.request_id}".encode())[:32]
        agent_trace = _AgentTrace(trace_id, self._monotonic)
        observations: tuple[NormalizedRuntimeObservation, ...] = ()
        projection = RuntimeEvidenceProjection(batch.request_id, batch.incident_id, observations)
        chain = _assess(
            expected,
            observations,
            request_id=batch.request_id,
            incident_id=batch.incident_id,
        )
        evidence_ids: set[str] = set()
        envelopes: list[Mapping[str, Any]] = []
        selection_trace: list[dict[str, Any]] = []
        selected_queries: list[str] = []
        terminal = False
        terminal_reason = "incomplete-evidence"
        workflow_error: str | None = None
        model_selection: ReferenceModelSelection | None = None
        model_invocation: dict[str, Any] | None = None

        controls = ExecutionControls()
        try:
            async with self._evidence.open_collection(batch, controls=controls) as collection:
                baseline_span = agent_trace.start(
                    "grafana",
                    query_key=_BASELINE_QUERY,
                    attempts_complete=False,
                )
                baseline: Mapping[str, Any] | None = None
                try:
                    baseline = await asyncio.wait_for(
                        collection.collect(_BASELINE_QUERY),
                        timeout=cast(int, REFERENCE_POLICY_DOCUMENT["evidence_timeout_seconds"]),
                    )
                    envelopes.append(baseline)
                    baseline_id = _envelope_evidence_id(baseline)
                    if baseline_id is not None:
                        evidence_ids.add(baseline_id)
                    observations = self._evidence.normalize_runtime_observations(batch, envelopes)
                    projection = RuntimeEvidenceProjection(
                        batch.request_id,
                        batch.incident_id,
                        observations,
                    )
                    baseline_model_view = _baseline_view(baseline)
                    agent_trace.finish(
                        baseline_span,
                        status="ok",
                        attempts=_collection_attempts(baseline),
                        attempts_complete=True,
                    )
                    selection_trace.append(
                        _trace_entry(
                            sequence=0,
                            selected_by="policy",
                            query_key=_BASELINE_QUERY,
                            evidence_id=baseline_id,
                            disposition="continue",
                            reason_codes=("baseline-collected",),
                            chain=chain,
                        )
                    )
                except (
                    AdapterError,
                    ReferenceInvestigationError,
                    TimeoutError,
                    TypeError,
                ) as error:
                    failed_envelope = _collection_envelope_for_query(
                        baseline,
                        _BASELINE_QUERY,
                    )
                    agent_trace.finish(
                        baseline_span,
                        status="error",
                        error_code="evidence-unavailable",
                        attempts=(
                            _collection_attempts(failed_envelope)
                            if failed_envelope is not None
                            else 1
                            if isinstance(error, TimeoutError)
                            else 0
                        ),
                        attempts_complete=failed_envelope is not None,
                    )
                    selection_trace.append(
                        _trace_entry(
                            sequence=0,
                            selected_by="policy",
                            query_key=_BASELINE_QUERY,
                            evidence_id=(
                                _envelope_evidence_id(failed_envelope)
                                if failed_envelope is not None
                                else None
                            ),
                            disposition="unresolved",
                            reason_codes=("evidence-unavailable",),
                            chain=chain,
                        )
                    )
                    terminal = True
                    terminal_reason = "evidence-unavailable"
                    workflow_error = terminal_reason

                if not terminal:
                    model_payload = {
                        "input_contract": "evidence-selection-input/v3",
                        "policy_binding": {
                            "version": REFERENCE_POLICY_VERSION,
                            "sha256": REFERENCE_POLICY_SHA256,
                        },
                        "incident": {
                            "incident_id": intake.incident_id,
                            "fixture_id": expected.fixture_id,
                            "run_id": expected.run_id,
                            "affected_job_count": len(expected.affected_job_ids),
                            "protected_job_count": len(expected.safe_job_ids),
                        },
                        "alert_baseline": baseline_model_view,
                        "permitted_query_keys": list(_POST_BASELINE_QUERIES),
                        "exact_query_keys": list(_EXACT_QUERIES),
                        "cohort_query_keys": list(_COHORT_QUERIES),
                        "maximum_post_baseline_calls": _MAXIMUM_POST_BASELINE_CALLS,
                        "authority": "query-selection-only-no-provider-arguments-or-actions",
                    }
                    response_schema = strict_json_file(
                        SCHEMA_ROOT / "model-selection-v3.schema.json"
                    )
                    request_sha256 = prefixed_sha256(
                        canonical_json_bytes(
                            {"payload": model_payload, "response_schema": response_schema}
                        )
                    )
                    model_span = agent_trace.start("gemini", attempts_complete=False)

                    async def get_grafana_evidence(
                        query_key: AllowedQueryKey,
                    ) -> Mapping[str, Any]:
                        nonlocal chain
                        nonlocal observations
                        nonlocal projection
                        nonlocal terminal
                        nonlocal terminal_reason
                        nonlocal workflow_error
                        if (
                            terminal
                            or query_key not in _POST_BASELINE_QUERIES
                            or query_key in selected_queries
                            or len(selected_queries) >= _MAXIMUM_POST_BASELINE_CALLS
                        ):
                            terminal = True
                            terminal_reason = "invalid-evidence"
                            workflow_error = "invalid-model-request"
                            return {
                                "schema": "reference-evidence-tool-result/v1",
                                "query_key": query_key,
                                "deterministic_disposition": "unresolved",
                                "reason_code": terminal_reason,
                                "evidence_ids": [],
                                "remaining_query_keys": [],
                            }
                        selected_queries.append(query_key)
                        tool_span = agent_trace.start(
                            "grafana",
                            query_key=query_key,
                            attempts_complete=False,
                        )
                        envelope: Mapping[str, Any] | None = None
                        try:
                            envelope = await asyncio.wait_for(
                                collection.collect(query_key),
                                timeout=cast(
                                    int,
                                    REFERENCE_POLICY_DOCUMENT["evidence_timeout_seconds"],
                                ),
                            )
                            envelopes.append(envelope)
                            evidence_id = _envelope_evidence_id(envelope)
                            if evidence_id is not None:
                                evidence_ids.add(evidence_id)
                            observations = self._evidence.normalize_runtime_observations(
                                batch,
                                envelopes,
                            )
                            projection = RuntimeEvidenceProjection(
                                batch.request_id,
                                batch.incident_id,
                                observations,
                            )
                            agent_trace.finish(
                                tool_span,
                                status="ok",
                                attempts=_collection_attempts(envelope),
                                attempts_complete=True,
                            )
                        except (AdapterError, TimeoutError, TypeError) as error:
                            failed_envelope = _collection_envelope_for_query(
                                envelope,
                                query_key,
                            )
                            agent_trace.finish(
                                tool_span,
                                status="error",
                                error_code="evidence-unavailable",
                                attempts=(
                                    _collection_attempts(failed_envelope)
                                    if failed_envelope is not None
                                    else 1
                                    if isinstance(error, TimeoutError)
                                    else 0
                                ),
                                attempts_complete=failed_envelope is not None,
                            )
                            terminal = True
                            terminal_reason = "evidence-unavailable"
                            workflow_error = terminal_reason
                            selection_trace.append(
                                _trace_entry(
                                    sequence=len(selection_trace),
                                    selected_by="model",
                                    query_key=query_key,
                                    evidence_id=(
                                        _envelope_evidence_id(failed_envelope)
                                        if failed_envelope is not None
                                        else None
                                    ),
                                    disposition="unresolved",
                                    reason_codes=(terminal_reason,),
                                    chain=chain,
                                )
                            )
                            return {
                                "schema": "reference-evidence-tool-result/v1",
                                "query_key": query_key,
                                "deterministic_disposition": "unresolved",
                                "reason_code": terminal_reason,
                                "evidence_ids": sorted(evidence_ids),
                                "remaining_query_keys": [],
                            }

                        validation_span = agent_trace.start("validator", query_key=query_key)
                        chain = _assess(
                            expected,
                            observations,
                            request_id=batch.request_id,
                            incident_id=batch.incident_id,
                        )
                        validation_status = (
                            "ok"
                            if chain.operational.status is AssessmentStatus.SUPPORTED
                            else "unresolved"
                        )
                        agent_trace.finish(validation_span, status=validation_status)
                        reconciliation_span = agent_trace.start(
                            "reconciliation", query_key=query_key
                        )
                        disposition, reason = _terminal_from_chain(
                            chain,
                            calls_used=len(selected_queries),
                        )
                        agent_trace.finish(
                            reconciliation_span,
                            status="ok" if disposition == "resolved" else "unresolved",
                            error_code=None if disposition == "resolved" else reason,
                        )
                        terminal = disposition != "continue"
                        terminal_reason = reason
                        evidence_id = _envelope_evidence_id(envelopes[-1])
                        selection_trace.append(
                            _trace_entry(
                                sequence=len(selection_trace),
                                selected_by="model",
                                query_key=query_key,
                                evidence_id=evidence_id,
                                disposition=disposition,
                                reason_codes=(
                                    (reason, *chain.operational.reason_codes)
                                    if disposition != "resolved"
                                    else (reason,)
                                ),
                                chain=chain,
                            )
                        )
                        remaining = [
                            key for key in _POST_BASELINE_QUERIES if key not in selected_queries
                        ]
                        return {
                            "schema": "reference-evidence-tool-result/v1",
                            "query_key": query_key,
                            "signal_class": _QUERY_SIGNALS[query_key],
                            "evidence_ids": sorted(evidence_ids),
                            "normalized_observations": _model_observations(
                                observations,
                                query_key=query_key,
                            ),
                            "scope_coverage": _coverage(expected, observations),
                            "deterministic_disposition": disposition,
                            "reason_code": reason,
                            "supported_incident_class": (
                                chain.reconciliation.incident_class.value
                                if chain.reconciliation.incident_class is not None
                                else None
                            ),
                            "remaining_query_keys": remaining if not terminal else [],
                        }

                    try:
                        output = await asyncio.wait_for(
                            self._model.generate(
                                ModelCall(
                                    turn_kind="evidence-selection",
                                    payload=model_payload,
                                    response_schema=response_schema,
                                    maximum_output_tokens=cast(
                                        int,
                                        REFERENCE_POLICY_DOCUMENT["maximum_output_tokens"],
                                    ),
                                    evidence_tool=get_grafana_evidence,
                                )
                            ),
                            timeout=cast(
                                int,
                                REFERENCE_POLICY_DOCUMENT["model_timeout_seconds"],
                            ),
                        )
                        model_invocation = {
                            "schema": "model-tool-invocation/v3",
                            "provider": "vertex-ai",
                            "model": MODEL_ID,
                            "prompt_version": "evidence-selection/v3",
                            "request_sha256": request_sha256,
                            "output_sha256": prefixed_sha256(output.content),
                            "input_tokens": output.input_tokens,
                            "output_tokens": output.output_tokens,
                            "model_calls": output.model_calls,
                            "unobserved_model_calls": 0,
                            "status": "accepted",
                        }
                        try:
                            candidate = ReferenceModelSelection.from_bytes(
                                output.content,
                                allowed_evidence_ids=frozenset(evidence_ids),
                            )
                            if (
                                candidate.query_keys != (_BASELINE_QUERY, *selected_queries)
                                or candidate.stop_reason != terminal_reason
                                or not terminal
                                or output.model_calls
                                > cast(
                                    int,
                                    REFERENCE_POLICY_DOCUMENT["maximum_model_calls"],
                                )
                            ):
                                raise ContractError("model-output-invalid")
                            model_selection = candidate
                            agent_trace.finish(
                                model_span,
                                status="ok",
                                attempts=output.model_calls,
                                attempts_complete=True,
                                input_tokens=output.input_tokens,
                                output_tokens=output.output_tokens,
                            )
                        except ContractError:
                            model_invocation["status"] = "invalid"
                            workflow_error = "model-output-invalid"
                            agent_trace.finish(
                                model_span,
                                status="error",
                                error_code=workflow_error,
                                attempts=output.model_calls,
                                attempts_complete=True,
                                input_tokens=output.input_tokens,
                                output_tokens=output.output_tokens,
                            )
                    except ModelFailure as error:
                        workflow_error = "model-unavailable"
                        usage_complete = error.unobserved_model_calls == 0
                        model_invocation = {
                            "schema": "model-tool-invocation/v3",
                            "provider": "vertex-ai",
                            "model": MODEL_ID,
                            "prompt_version": "evidence-selection/v3",
                            "request_sha256": request_sha256,
                            "output_sha256": None,
                            "input_tokens": error.input_tokens if usage_complete else None,
                            "output_tokens": error.output_tokens if usage_complete else None,
                            "model_calls": error.model_calls,
                            "unobserved_model_calls": error.unobserved_model_calls,
                            "status": "failed",
                        }
                        agent_trace.finish(
                            model_span,
                            status="error",
                            error_code=workflow_error,
                            attempts=error.model_calls,
                            attempts_complete=True,
                            unobserved_model_calls=error.unobserved_model_calls,
                            input_tokens=error.input_tokens if usage_complete else None,
                            output_tokens=error.output_tokens if usage_complete else None,
                        )
                    except TimeoutError:
                        workflow_error = "model-unavailable"
                        model_invocation = {
                            "schema": "model-tool-invocation/v3",
                            "provider": "vertex-ai",
                            "model": MODEL_ID,
                            "prompt_version": "evidence-selection/v3",
                            "request_sha256": request_sha256,
                            "output_sha256": None,
                            "input_tokens": None,
                            "output_tokens": None,
                            "model_calls": 1,
                            "unobserved_model_calls": 1,
                            "status": "failed",
                        }
                        agent_trace.finish(
                            model_span,
                            status="error",
                            error_code=workflow_error,
                            attempts=1,
                            attempts_complete=False,
                            unobserved_model_calls=1,
                        )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            if isinstance(error, ReferenceInvestigationError):
                raise
            workflow_error = "evidence-unavailable"
            if agent_trace.empty:
                failed_span = agent_trace.start("grafana", query_key=_BASELINE_QUERY)
                agent_trace.finish(
                    failed_span,
                    status="error",
                    error_code=workflow_error,
                )
            if not selection_trace:
                selection_trace.append(
                    _trace_entry(
                        sequence=0,
                        selected_by="policy",
                        query_key=_BASELINE_QUERY,
                        evidence_id=None,
                        disposition="unresolved",
                        reason_codes=(workflow_error,),
                        chain=chain,
                    )
                )

        resolved = (
            workflow_error is None
            and model_selection is not None
            and model_invocation is not None
            and model_invocation["status"] == "accepted"
            and chain.reconciliation.status is AssessmentStatus.SUPPORTED
            and terminal_reason == "sufficient-evidence"
        )
        action_intent = (
            chain.reconciliation.action_intent.to_dict()
            if resolved and chain.reconciliation.action_intent is not None
            else None
        )
        no_action_reason = None if resolved else (workflow_error or terminal_reason)
        reference_evidence = finalize_reference_evidence(
            {
                "schema": "reference-evidence/v3",
                "request_id": batch.request_id,
                "incident_id": intake.incident_id,
                "scenario_id": expected.scenario_id,
                "fixture_id": expected.fixture_id,
                "run_id": expected.run_id,
                "source": "grafana-mcp",
                "structured_only": True,
                "query_keys": [entry["query_key"] for entry in selection_trace],
                "evidence_ids": sorted(evidence_ids),
                "expected_state_sha256": cast(str, expected.expected_state_sha256),
                "runtime_projection": projection.to_dict(),
            }
        )
        packet_body = {
            "schema": "response-packet/v3",
            "version": 3,
            "status": "resolved" if resolved else "unresolved",
            "incident_id": intake.incident_id,
            "scenario_id": expected.scenario_id,
            "fixture_id": expected.fixture_id,
            "run_id": expected.run_id,
            "policy_binding": {
                "version": REFERENCE_POLICY_VERSION,
                "sha256": REFERENCE_POLICY_SHA256,
            },
            "fixed_window": {
                "start": expected.window_start,
                "end": expected.window_end,
            },
            "evidence_ids": sorted(evidence_ids),
            "reference_evidence": reference_evidence,
            "runtime_evidence_projection": projection.to_dict(),
            "expected_state_assessment": expected.to_dict(),
            "operational_evidence_assessment": chain.operational.to_dict(),
            "incident_class_assessments": [value.to_dict() for value in chain.classes],
            "diagnosis_reconciliation": chain.reconciliation.to_dict(),
            "selection_trace": selection_trace,
            "model_selection": None if model_selection is None else model_selection.to_dict(),
            "model_invocation": model_invocation,
            "agent_trace": agent_trace.to_dict(),
            "authority_policy": [
                "gemini-query-selection-only",
                "grafana-read-only-evidence",
                "deterministic-validators-authoritative",
                "human-approval-required-for-action",
            ],
            "action_intent": action_intent,
            "no_action_reason": no_action_reason,
            "finalized_at": timestamp(self._clock().astimezone(UTC)),
        }
        return finalize_reference_response_packet(packet_body)


__all__ = [
    "ReferenceEvidenceAdapter",
    "ReferenceEvidenceCollection",
    "ReferenceInvestigationError",
    "ReferenceInvestigationWorkflow",
]
