from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import pytest
from colortrace_grafana_mcp import AdapterError, EvidenceBatch, NormalizedRuntimeObservation
from colortrace_investigation import (
    ContractError,
    ModelCall,
    ModelFailure,
    ModelOutput,
    ReferenceInvestigationWorkflow,
    finalize_reference_response_packet,
    validate_reference_response_packet,
)
from colortrace_investigation.model import _SYSTEM_INSTRUCTIONS


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical(value)).hexdigest()}"


def fixed_digest(character: str) -> str:
    return f"sha256:{character * 64}"


APPROVED: dict[str, str | int] = {
    "resource_sha256": fixed_digest("1"),
    "config_sha256": fixed_digest("2"),
    "config_generation": 11,
    "frame_pipeline_sha256": fixed_digest("3"),
    "derivative_parent_sha256": fixed_digest("4"),
    "derivative_generation": 7,
    "cache_key": "cache-reference-v1",
}


SCENARIOS = {
    "tos-resource-resolution-drift-v1": (
        "resource-resolution-drift/v1",
        ("metric.worker-cohort", "log.config-cohort"),
        "reconcile-resource",
    ),
    "tos-config-rollout-drift-v1": (
        "configuration-rollout-drift/v1",
        ("log.config-cohort", "trace.by-id", "metric.worker-cohort"),
        "pin-rollout",
    ),
    "tos-stale-derivative-cache-v1": (
        "stale-derivative-cache/v1",
        ("trace.by-id", "metric.worker-cohort", "log.config-cohort"),
        "invalidate-cache",
    ),
}


def alert() -> dict[str, Any]:
    return {
        "schema": "alert-intake/v1",
        "incident_id": "incident-reference-001",
        "alert_id": "alert-reference-001",
        "alert_started_at": "2026-09-04T12:05:00.000Z",
        "retrieved_at": "2026-09-04T12:05:00.000Z",
        "measured_clock_skew_seconds": 0,
        "binding": {
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
            "alert_rule_uid": "ct-reference-demo-divergence-v1",
        },
        "correlation_keys": {
            "fixture_id": "tears-of-steel-linear-exr-240-v1",
            "run_id": "run-reference-001",
            "job_id": "job-affected",
            "worker_id": "worker-reference",
            "artifact_id": "artifact-affected",
            "trace_id": "1" * 32,
            "config_sha256": "2" * 64,
            "transform_id": "look/main/v1",
        },
        "predecessor_event_sha256": None,
    }


def expected_state(scenario_id: str) -> dict[str, Any]:
    body = {
        "schema": "reference-expected-state/v1",
        "scenario_id": scenario_id,
        "fixture_id": "tears-of-steel-linear-exr-240-v1",
        "run_id": "run-reference-001",
        "evidence_window": {
            "start": "2026-09-04T12:00:00.000Z",
            "end": "2026-09-04T12:05:00.000Z",
        },
        "approved": dict(APPROVED),
        "scope": {
            "affected_job_ids": ["job-affected"],
            "safe_job_ids": ["job-safe"],
        },
    }
    value_sha256 = digest(body)
    return {
        **body,
        "expected_state_id": f"expected-state:{value_sha256.removeprefix('sha256:')}",
        "expected_state_sha256": value_sha256,
    }


class FakeCollection:
    def __init__(self) -> None:
        self.keys: list[str] = []

    async def collect(self, query_key: str) -> Mapping[str, Any]:
        self.keys.append(query_key)
        evidence_id = digest({"query_key": query_key})
        return {
            "observation": {
                "query_key": query_key,
                "normalized_arguments": (
                    {
                        "operation": "get",
                        "rule_uid": "ct-reference-demo-divergence-v1",
                        "limit_alerts": 100,
                    }
                    if query_key == "alert.rule"
                    else {}
                ),
            },
            "evidence_id": evidence_id,
            "display_excerpt": (
                "tos-resource-resolution-drift-v1 resource-resolution-drift/v1"
                if query_key == "alert.rule"
                else f"structured result for {query_key}"
            ),
            "content": (
                {
                    "uid": "ct-reference-demo-divergence-v1",
                    "annotations": {
                        "reference_fixture_id": "tears-of-steel-linear-exr-240-v1",
                        "reference_data_origin": "generated-demonstration-telemetry",
                        "evidence_scope": "representative",
                    },
                    "alerts": [
                        {
                            "state": "Alerting",
                            "labels": {
                                "fixture_id": "tears-of-steel-linear-exr-240-v1",
                                "run_id": "run-reference-001",
                                "job_id": "job-affected",
                                "worker_id": "worker-reference",
                                "artifact_id": "artifact-affected",
                                "trace_id": "1" * 32,
                                "config_sha256": "2" * 64,
                                "transform_id": "look/main/v1",
                            },
                        }
                    ],
                }
                if query_key == "alert.rule"
                else {}
            ),
            "correlation_keys": {
                "fixture_id": "tears-of-steel-linear-exr-240-v1",
                "run_id": "run-reference-001",
                "job_id": "job-affected",
                "worker_id": "worker-reference",
                "artifact_id": "artifact-affected",
                "trace_id": "1" * 32,
                "config_sha256": "2" * 64,
                "transform_id": "look/main/v1",
            },
            "collection": {"outcome": "collected", "error": None, "attempts": 1},
        }

    def result(self) -> object:
        return object()


class FakeEvidence:
    def __init__(self, incident_class: str) -> None:
        self.incident_class = incident_class
        self.collection = FakeCollection()

    @asynccontextmanager
    async def open_collection(self, batch: EvidenceBatch, *, controls: Any = None) -> Any:
        del batch, controls
        yield self.collection

    def normalize_runtime_observations(
        self,
        batch: EvidenceBatch,
        envelopes: Sequence[Mapping[str, Any]],
    ) -> tuple[NormalizedRuntimeObservation, ...]:
        observations: list[NormalizedRuntimeObservation] = []
        for envelope in envelopes:
            query_key = str(envelope["observation"]["query_key"])
            if query_key == "alert.rule":
                continue
            signal = {
                "metric.worker-cohort": "metric",
                "metric.correlated-observations": "metric",
                "log.config-cohort": "log",
                "log.correlated-events": "log",
                "trace.by-id": "trace",
            }[query_key]
            jobs = (
                ("job-affected", "job-safe")
                if query_key in {"metric.worker-cohort", "log.config-cohort"}
                else ("job-affected",)
            )
            for job_id in jobs:
                observations.append(
                    self._observation(
                        batch=batch,
                        query_key=query_key,
                        signal=signal,
                        job_id=job_id,
                        evidence_id=str(envelope["evidence_id"]),
                    )
                )
        return tuple(observations)

    def _observation(
        self,
        *,
        batch: EvidenceBatch,
        query_key: str,
        signal: str,
        job_id: str,
        evidence_id: str,
    ) -> NormalizedRuntimeObservation:
        affected = job_id == "job-affected"
        resource = str(APPROVED["resource_sha256"])
        config = str(APPROVED["config_sha256"])
        config_generation = int(APPROVED["config_generation"])
        pipeline = str(APPROVED["frame_pipeline_sha256"])
        derivative_parent = str(APPROVED["derivative_parent_sha256"])
        derivative_generation = int(APPROVED["derivative_generation"])
        if affected and self.incident_class == "resource-resolution-drift/v1":
            resource = fixed_digest("a")
            pipeline = fixed_digest("d")
        elif affected and self.incident_class == "configuration-rollout-drift/v1":
            config = fixed_digest("b")
            config_generation = 12
            pipeline = fixed_digest("d")
        elif affected and self.incident_class == "stale-derivative-cache/v1":
            derivative_parent = fixed_digest("c")
            derivative_generation = 6
        attributes = {
            "declared_reference.state": "reference_mismatch" if affected else "reference_match",
            "runtime.effective_resource_sha256": resource,
            "runtime.effective_config_sha256": config,
            "runtime.config_generation": str(config_generation),
            "runtime.frame_pipeline_sha256": pipeline,
            "derivative.parent_sha256": derivative_parent,
            "cache.generation": str(derivative_generation),
            "cache.key": str(APPROVED["cache_key"]),
            "reference.scenario_id": "tos-hidden-oracle-v1",
            "reference.incident_class": self.incident_class,
        }
        tool = {
            "metric": "query_prometheus",
            "log": "query_loki_logs",
            "trace": "tempo_get-trace",
        }[signal]
        return NormalizedRuntimeObservation(
            request_id=batch.request_id,
            incident_id=batch.incident_id,
            event_id=f"event-{query_key.replace('.', '-')}-{job_id}",
            signal=signal,  # type: ignore[arg-type]
            fixture_id=batch.correlation_keys["fixture_id"],
            run_id=batch.correlation_keys["run_id"],
            job_id=job_id,
            worker_id="worker-reference",
            trace_id="1" * 32 if affected else "2" * 32,
            artifact_id=f"artifact-{job_id}",
            config_sha256=str(APPROVED["config_sha256"]).removeprefix("sha256:"),
            resource_sha256=resource.removeprefix("sha256:"),
            transform_id="look/main/v1",
            observed_at="2026-09-04T12:01:00.000Z",
            emitted_at="2026-09-04T12:01:01.000Z",
            retrieved_at="2026-09-04T12:01:02.000Z",
            attributes=attributes,
            provenance={
                "query_key": query_key,
                "evidence_id": evidence_id,
                "event_sha256": evidence_id,
                "content_sha256": digest({"content": query_key}),
                "catalog_version": "grafana-evidence-query-catalog/v2",
                "catalog_sha256": digest({"catalog": "v2"}),
                "tool": tool,
                "normalized_arguments": {"query": query_key},
            },
        )


class UnavailableCollection(FakeCollection):
    async def collect(self, query_key: str) -> Mapping[str, Any]:
        del query_key
        raise AdapterError("evidence-unavailable")


class UnavailableEvidence(FakeEvidence):
    def __init__(self) -> None:
        super().__init__("resource-resolution-drift/v1")
        self.collection = UnavailableCollection()


class TimeoutCollection(FakeCollection):
    async def collect(self, query_key: str) -> Mapping[str, Any]:
        del query_key
        raise TimeoutError


class TimeoutEvidence(FakeEvidence):
    def __init__(self) -> None:
        super().__init__("resource-resolution-drift/v1")
        self.collection = TimeoutCollection()


class RetriedCollection(FakeCollection):
    async def collect(self, query_key: str) -> Mapping[str, Any]:
        envelope = dict(await super().collect(query_key))
        envelope["collection"] = {
            "outcome": "collected",
            "error": None,
            "attempts": 2,
        }
        return envelope


class NormalizationFailureEvidence(FakeEvidence):
    def __init__(self, fail_query_key: str) -> None:
        super().__init__("resource-resolution-drift/v1")
        self.collection = RetriedCollection()
        self.fail_query_key = fail_query_key

    def normalize_runtime_observations(
        self,
        batch: EvidenceBatch,
        envelopes: Sequence[Mapping[str, Any]],
    ) -> tuple[NormalizedRuntimeObservation, ...]:
        latest = envelopes[-1]
        if latest["observation"]["query_key"] == self.fail_query_key:
            raise AdapterError("runtime-observation-malformed")
        return super().normalize_runtime_observations(batch, envelopes)


class AdaptiveFakeModel:
    def __init__(
        self,
        query_plan: Sequence[str],
        incident_class: str,
        *,
        stop_early: bool = False,
        invalid_output: bool = False,
    ) -> None:
        self.query_plan = tuple(query_plan)
        self.incident_class = incident_class
        self.stop_early = stop_early
        self.invalid_output = invalid_output
        self.calls: list[ModelCall] = []
        self.tool_results: list[Mapping[str, Any]] = []

    async def generate(self, call: ModelCall) -> ModelOutput:
        self.calls.append(call)
        assert call.evidence_tool is not None
        returned: list[Mapping[str, Any]] = []
        for query_key in self.query_plan:
            returned.append(await call.evidence_tool(query_key))  # type: ignore[arg-type]
            if self.stop_early or returned[-1]["deterministic_disposition"] != "continue":
                break
        self.tool_results.extend(returned)
        if self.invalid_output:
            content = b'{"schema":"model-selection/v3"}'
        else:
            evidence_ids = list(returned[-1]["evidence_ids"])
            content = canonical(
                {
                    "schema": "model-selection/v3",
                    "hypotheses": [
                        {
                            "ordinal": 1,
                            "incident_class": self.incident_class,
                            "evidence_ids": evidence_ids[-2:],
                        }
                    ],
                    "query_keys": [
                        "alert.rule",
                        *(str(value["query_key"]) for value in returned),
                    ],
                    "stop_reason": str(returned[-1]["reason_code"]),
                }
            )
        return ModelOutput(content=content, input_tokens=720, output_tokens=96, model_calls=3)


class FailedModel:
    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    async def generate(self, call: ModelCall) -> ModelOutput:
        del call
        raise self.failure


@pytest.mark.parametrize(
    ("scenario_id", "incident_class", "query_plan", "command"),
    [(scenario_id, values[0], values[1], values[2]) for scenario_id, values in SCENARIOS.items()],
)
def test_reference_workflow_resolves_each_class_with_adaptive_structured_evidence(
    scenario_id: str,
    incident_class: str,
    query_plan: Sequence[str],
    command: str,
) -> None:
    evidence = FakeEvidence(incident_class)
    model = AdaptiveFakeModel(query_plan, incident_class)
    workflow = ReferenceInvestigationWorkflow(
        model=model,
        evidence=evidence,
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(alert=alert(), expected_state=expected_state(scenario_id))
    )

    assert packet["schema"] == "response-packet/v3"
    assert packet["status"] == "resolved"
    assert packet["diagnosis_reconciliation"]["incident_class"] == incident_class
    assert packet["action_intent"]["command"] == command
    assert packet["action_intent"]["target"] == "simulator"
    assert packet["action_intent"]["requires_human_approval"] is True
    assert packet["action_intent"]["authorizes_execution"] is False
    assert packet["model_selection"]["query_keys"] == [
        "alert.rule",
        *query_plan,
    ]
    assert packet["authority_policy"] == [
        "gemini-query-selection-only",
        "grafana-read-only-evidence",
        "deterministic-validators-authoritative",
        "human-approval-required-for-action",
    ]
    assert {span["stage"] for span in packet["agent_trace"]["spans"]} >= {
        "grafana",
        "gemini",
        "validator",
        "reconciliation",
    }
    assert packet["agent_trace"]["schema"] == "agent-trace/v2"
    assert all(span["attempts_complete"] is True for span in packet["agent_trace"]["spans"])
    assert packet["model_invocation"]["unobserved_model_calls"] == 0
    assert packet["reference_evidence"]["source"] == "grafana-mcp"
    assert packet["reference_evidence"]["structured_only"] is True
    assert packet["reference_evidence"]["query_keys"] == [
        entry["query_key"] for entry in packet["selection_trace"]
    ]
    assert model.calls[0].payload["alert_baseline"] == {
        "schema": "grafana-reference-baseline-view/v1",
        "query_key": "alert.rule",
        "evidence_id": digest({"query_key": "alert.rule"}),
        "rule_uid": "ct-reference-demo-divergence-v1",
        "fixture_id": "tears-of-steel-linear-exr-240-v1",
        "evidence_scope": "representative",
        "alert_state": "firing",
        "correlated_alert_instance_count": 1,
        "rule_alert_instance_count": 1,
        "provider_excerpt_exposed": False,
        "trust": "untrusted-provider-data",
    }
    assert (
        packet["reference_evidence"]["runtime_projection"] == packet["runtime_evidence_projection"]
    )
    validate_reference_response_packet(packet)


def test_model_hypothesis_never_overrides_deterministic_diagnosis() -> None:
    evidence = FakeEvidence("resource-resolution-drift/v1")
    model = AdaptiveFakeModel(
        SCENARIOS["tos-resource-resolution-drift-v1"][1],
        "stale-derivative-cache/v1",
    )
    workflow = ReferenceInvestigationWorkflow(
        model=model,
        evidence=evidence,
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(
            alert=alert(),
            expected_state=expected_state("tos-resource-resolution-drift-v1"),
        )
    )

    assert packet["status"] == "resolved"
    assert packet["model_selection"]["hypotheses"][0]["incident_class"] == (
        "stale-derivative-cache/v1"
    )
    assert packet["diagnosis_reconciliation"]["incident_class"] == ("resource-resolution-drift/v1")
    assert packet["action_intent"]["command"] == "reconcile-resource"


def test_model_cannot_read_scenario_or_incident_class_oracle_labels() -> None:
    scenario_id = "tos-resource-resolution-drift-v1"
    incident_class = "resource-resolution-drift/v1"
    model = AdaptiveFakeModel(SCENARIOS[scenario_id][1], incident_class)
    workflow = ReferenceInvestigationWorkflow(
        model=model,
        evidence=FakeEvidence(incident_class),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(alert=alert(), expected_state=expected_state(scenario_id))
    )

    assert packet["status"] == "resolved"
    model_input = json.dumps(model.calls[0].payload, sort_keys=True)
    model_results = json.dumps(model.tool_results, sort_keys=True)
    assert scenario_id not in model_input
    assert incident_class not in model_input
    assert "tos-hidden-oracle-v1" not in model_results
    assert "reference.scenario_id" not in model_results
    assert "reference.incident_class" not in model_results


@pytest.mark.parametrize("invalid_output", (False, True))
def test_incomplete_or_invalid_model_result_exposes_no_action(invalid_output: bool) -> None:
    scenario_id = "tos-resource-resolution-drift-v1"
    evidence = FakeEvidence("resource-resolution-drift/v1")
    model = AdaptiveFakeModel(
        ("metric.worker-cohort",),
        "resource-resolution-drift/v1",
        stop_early=not invalid_output,
        invalid_output=invalid_output,
    )
    workflow = ReferenceInvestigationWorkflow(
        model=model,
        evidence=evidence,
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(alert=alert(), expected_state=expected_state(scenario_id))
    )

    assert packet["status"] == "unresolved"
    assert packet["action_intent"] is None
    assert packet["no_action_reason"] == "model-output-invalid"
    validate_reference_response_packet(packet)


def test_model_failure_marks_partial_usage_unknown_and_preserves_total_attempts() -> None:
    workflow = ReferenceInvestigationWorkflow(
        model=FailedModel(
            ModelFailure(
                "service",
                transient=True,
                input_tokens=321,
                output_tokens=17,
                model_calls=2,
                unobserved_model_calls=1,
            )
        ),
        evidence=FakeEvidence("resource-resolution-drift/v1"),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(
            alert=alert(),
            expected_state=expected_state("tos-resource-resolution-drift-v1"),
        )
    )

    assert packet["status"] == "unresolved"
    assert packet["no_action_reason"] == "model-unavailable"
    assert packet["model_invocation"] == {
        "schema": "model-tool-invocation/v3",
        "provider": "vertex-ai",
        "model": "gemini-3.5-flash",
        "prompt_version": "evidence-selection/v3",
        "request_sha256": packet["model_invocation"]["request_sha256"],
        "output_sha256": None,
        "input_tokens": None,
        "output_tokens": None,
        "model_calls": 2,
        "unobserved_model_calls": 1,
        "status": "failed",
    }
    model_span = next(span for span in packet["agent_trace"]["spans"] if span["stage"] == "gemini")
    assert model_span["attempts"] == 2
    assert model_span["attempts_complete"] is True
    assert model_span["unobserved_model_calls"] == 1
    assert model_span["input_tokens"] is None
    assert model_span["output_tokens"] is None
    validate_reference_response_packet(packet)


def test_model_timeout_records_an_attempt_with_unknown_usage() -> None:
    workflow = ReferenceInvestigationWorkflow(
        model=FailedModel(TimeoutError()),
        evidence=FakeEvidence("resource-resolution-drift/v1"),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(
            alert=alert(),
            expected_state=expected_state("tos-resource-resolution-drift-v1"),
        )
    )

    invocation = packet["model_invocation"]
    assert packet["status"] == "unresolved"
    assert packet["no_action_reason"] == "model-unavailable"
    assert invocation["model_calls"] == 1
    assert invocation["unobserved_model_calls"] == 1
    assert invocation["input_tokens"] is None
    assert invocation["output_tokens"] is None
    model_span = next(span for span in packet["agent_trace"]["spans"] if span["stage"] == "gemini")
    assert model_span["attempts"] == 1
    assert model_span["attempts_complete"] is False
    assert model_span["unobserved_model_calls"] == 1
    validate_reference_response_packet(packet)


def test_unavailable_evidence_does_not_forge_operational_bindings() -> None:
    workflow = ReferenceInvestigationWorkflow(
        model=AdaptiveFakeModel((), "resource-resolution-drift/v1"),
        evidence=UnavailableEvidence(),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(
            alert=alert(),
            expected_state=expected_state("tos-resource-resolution-drift-v1"),
        )
    )

    operational = packet["operational_evidence_assessment"]
    assert packet["status"] == "unresolved"
    assert operational["request_id"] is None
    assert operational["incident_id"] is None
    assert packet["action_intent"] is None
    grafana_span = packet["agent_trace"]["spans"][0]
    assert grafana_span["attempts"] == 0
    assert grafana_span["attempts_complete"] is False
    validate_reference_response_packet(packet)


def test_grafana_timeout_records_one_known_lower_bound_attempt() -> None:
    workflow = ReferenceInvestigationWorkflow(
        model=AdaptiveFakeModel((), "resource-resolution-drift/v1"),
        evidence=TimeoutEvidence(),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(
            alert=alert(),
            expected_state=expected_state("tos-resource-resolution-drift-v1"),
        )
    )

    grafana_span = packet["agent_trace"]["spans"][0]
    assert grafana_span["attempts"] == 1
    assert grafana_span["attempts_complete"] is False
    validate_reference_response_packet(packet)


@pytest.mark.parametrize(
    ("fail_query_key", "query_plan"),
    [
        ("alert.rule", ()),
        ("metric.worker-cohort", ("metric.worker-cohort",)),
    ],
)
def test_grafana_error_after_collection_preserves_envelope_attempts(
    fail_query_key: str,
    query_plan: Sequence[str],
) -> None:
    workflow = ReferenceInvestigationWorkflow(
        model=AdaptiveFakeModel(query_plan, "resource-resolution-drift/v1"),
        evidence=NormalizationFailureEvidence(fail_query_key),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )

    packet = __import__("asyncio").run(
        workflow.run(
            alert=alert(),
            expected_state=expected_state("tos-resource-resolution-drift-v1"),
        )
    )

    grafana_span = next(
        span
        for span in packet["agent_trace"]["spans"]
        if span["stage"] == "grafana" and span["query_key"] == fail_query_key
    )
    trace_entry = next(
        entry for entry in packet["selection_trace"] if entry["query_key"] == fail_query_key
    )
    assert grafana_span["status"] == "error"
    assert grafana_span["attempts"] == 2
    assert grafana_span["attempts_complete"] is True
    assert trace_entry["evidence_id"] == digest({"query_key": fail_query_key})
    validate_reference_response_packet(packet)


@pytest.mark.parametrize("mutation", ("overcount", "partial-tokens", "non-model"))
def test_response_packet_rejects_inconsistent_usage_completeness(mutation: str) -> None:
    workflow = ReferenceInvestigationWorkflow(
        model=FailedModel(
            ModelFailure(
                "service",
                transient=True,
                input_tokens=321,
                output_tokens=17,
                model_calls=2,
                unobserved_model_calls=1,
            )
        ),
        evidence=FakeEvidence("resource-resolution-drift/v1"),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    packet = __import__("asyncio").run(
        workflow.run(
            alert=alert(),
            expected_state=expected_state("tos-resource-resolution-drift-v1"),
        )
    )
    body = json.loads(json.dumps(packet))
    body.pop("packet_id")
    body.pop("derivation_sha256")
    model_span = next(span for span in body["agent_trace"]["spans"] if span["stage"] == "gemini")
    if mutation == "overcount":
        body["model_invocation"]["unobserved_model_calls"] = 3
        model_span["unobserved_model_calls"] = 3
    elif mutation == "partial-tokens":
        body["model_invocation"]["input_tokens"] = 321
        body["model_invocation"]["output_tokens"] = 17
        model_span["input_tokens"] = 321
        model_span["output_tokens"] = 17
    else:
        body["agent_trace"]["spans"][0]["unobserved_model_calls"] = 1

    with pytest.raises(ContractError):
        finalize_reference_response_packet(body)


def test_response_packet_tampering_is_rejected() -> None:
    scenario_id = "tos-resource-resolution-drift-v1"
    workflow = ReferenceInvestigationWorkflow(
        model=AdaptiveFakeModel(
            SCENARIOS[scenario_id][1],
            "resource-resolution-drift/v1",
        ),
        evidence=FakeEvidence("resource-resolution-drift/v1"),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    packet = __import__("asyncio").run(
        workflow.run(alert=alert(), expected_state=expected_state(scenario_id))
    )
    packet["action_intent"]["authorizes_execution"] = True

    with pytest.raises(ContractError):
        validate_reference_response_packet(packet)


def test_readdressed_nested_action_tampering_is_rejected() -> None:
    scenario_id = "tos-resource-resolution-drift-v1"
    workflow = ReferenceInvestigationWorkflow(
        model=AdaptiveFakeModel(
            SCENARIOS[scenario_id][1],
            "resource-resolution-drift/v1",
        ),
        evidence=FakeEvidence("resource-resolution-drift/v1"),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    packet = __import__("asyncio").run(
        workflow.run(alert=alert(), expected_state=expected_state(scenario_id))
    )
    body = json.loads(json.dumps(packet))
    body.pop("packet_id")
    body.pop("derivation_sha256")
    replacement = fixed_digest("e")
    body["action_intent"]["parameters"]["observed"]["effective_resource_sha256"] = replacement
    body["diagnosis_reconciliation"]["action_intent"]["parameters"]["observed"][
        "effective_resource_sha256"
    ] = replacement

    with pytest.raises(ContractError, match="assessment-chain-binding"):
        finalize_reference_response_packet(body)


def test_reference_evidence_tampering_is_rejected_after_outer_packet_is_readdressed() -> None:
    scenario_id = "tos-resource-resolution-drift-v1"
    workflow = ReferenceInvestigationWorkflow(
        model=AdaptiveFakeModel(
            SCENARIOS[scenario_id][1],
            "resource-resolution-drift/v1",
        ),
        evidence=FakeEvidence("resource-resolution-drift/v1"),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    packet = __import__("asyncio").run(
        workflow.run(alert=alert(), expected_state=expected_state(scenario_id))
    )
    body = json.loads(json.dumps(packet))
    body.pop("packet_id")
    body.pop("derivation_sha256")
    body["reference_evidence"]["query_keys"] = ["alert.rule"]

    with pytest.raises(ContractError, match="reference-evidence-digest"):
        finalize_reference_response_packet(body)


def test_reference_model_policy_requires_bounded_adaptive_grafana_evidence() -> None:
    instruction = _SYSTEM_INSTRUCTIONS["evidence-selection/v3"]

    assert "get_grafana_evidence" in instruction
    assert "one permitted query_key at a time" in instruction
    assert "structured" in instruction
    assert "model-selection/v3" in instruction
    assert "Do not diagnose authoritatively" in instruction
