from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from colortrace_api import (
    REFERENCE_APPROVAL_PHRASE,
    REFERENCE_DENIAL_PHRASE,
    GeneratedReferenceScenarioTelemetry,
    ReferenceDemoCatalog,
    ReferenceDemoError,
    ReferenceScenarioRunService,
    create_app,
)
from colortrace_api import reference_demo as reference_demo_module
from colortrace_grafana_mcp import EvidenceBatch, NormalizedRuntimeObservation
from colortrace_investigation import ModelCall, ModelOutput, ReferenceInvestigationWorkflow
from colortrace_simulator import ReferenceHumanApprovalBoundary
from colortrace_telemetry import (
    MemoryReferenceTelemetrySink,
    build_generated_reference_telemetry_plan,
)
from colortrace_validator import ActionIntent, IncidentClass
from fastapi.testclient import TestClient


class IncidentService:
    def accept_alert(self, alert: Mapping[str, Any], principal: Any) -> dict[str, Any]:
        del alert, principal
        raise AssertionError("not called")

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        del limit, cursor
        return {"schema": "incident-list/v1", "items": [], "next_cursor": None}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return {"schema": "incident-view/v1", "incident_id": incident_id}

    def replay(self, incident_id: str) -> dict[str, Any]:
        return {"schema": "incident-replay/v1", "incident_id": incident_id}

    def workspace(self, incident_id: str) -> dict[str, Any]:
        return {"schema": "incident-workspace-source/v1", "incident_id": incident_id}


class NeverModel:
    async def generate(self, call: ModelCall) -> Any:
        del call
        raise AssertionError("model must not run without Grafana evidence")


class UnavailableEvidence:
    def __init__(self) -> None:
        self.opened = 0

    @asynccontextmanager
    async def open_collection(self, batch: Any, *, controls: Any = None) -> Any:
        del batch, controls
        self.opened += 1
        raise RuntimeError("Grafana unavailable")
        yield  # pragma: no cover

    def normalize_runtime_observations(self, batch: Any, envelopes: Any) -> tuple[()]:
        del batch, envelopes
        return ()


class GeneratedWorkflowCollection:
    def __init__(self, batch: EvidenceBatch, scenario_id: str, incident_class: str) -> None:
        self._batch = batch
        self._scenario_id = scenario_id
        self._incident_class = incident_class

    async def collect(self, query_key: str) -> Mapping[str, Any]:
        evidence_id = _digest_without({"query_key": query_key}, "unused")
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
                f"{self._scenario_id} {self._incident_class}"
                if query_key == "alert.rule"
                else f"generated reference result for {query_key}"
            ),
            "content": (
                {
                    "uid": "ct-reference-demo-divergence-v1",
                    "annotations": {
                        "reference_fixture_id": self._batch.correlation_keys["fixture_id"],
                        "reference_data_origin": "generated-demonstration-telemetry",
                        "evidence_scope": "representative",
                    },
                    "alerts": [
                        {
                            "state": "Alerting",
                            "labels": dict(self._batch.correlation_keys),
                        }
                    ],
                }
                if query_key == "alert.rule"
                else {}
            ),
            "correlation_keys": dict(self._batch.correlation_keys),
            "collection": {"outcome": "collected", "error": None, "attempts": 1},
        }

    def result(self) -> object:
        return object()


class GeneratedWorkflowEvidence:
    def __init__(self, scenario_id: str, incident_class: str) -> None:
        self._scenario_id = scenario_id
        self._incident_class = incident_class

    @asynccontextmanager
    async def open_collection(self, batch: EvidenceBatch, *, controls: Any = None) -> Any:
        del controls
        yield GeneratedWorkflowCollection(batch, self._scenario_id, self._incident_class)

    def normalize_runtime_observations(
        self,
        batch: EvidenceBatch,
        envelopes: Sequence[Mapping[str, Any]],
    ) -> tuple[NormalizedRuntimeObservation, ...]:
        plan = build_generated_reference_telemetry_plan(
            self._scenario_id,
            incident_id=batch.incident_id,
            fixture_id=batch.correlation_keys["fixture_id"],
            run_id=batch.correlation_keys["run_id"],
            observed_at=batch.window_start + timedelta(minutes=1),
            emitted_at=batch.window_start + timedelta(minutes=1, seconds=1),
        )
        observations: list[NormalizedRuntimeObservation] = []
        for envelope in envelopes:
            query_key = str(envelope["observation"]["query_key"])
            signal = {
                "metric.worker-cohort": "metric",
                "log.config-cohort": "log",
                "trace.by-id": "trace",
            }.get(query_key)
            if signal is None:
                continue
            evidence_id = str(envelope["evidence_id"])
            for event in plan.events:
                if event.signal != signal or (
                    signal == "trace" and event.attributes["reference.scope_role"] != "affected"
                ):
                    continue
                observations.append(
                    NormalizedRuntimeObservation(
                        request_id=batch.request_id,
                        incident_id=batch.incident_id,
                        event_id=event.event_id,
                        signal=event.signal,
                        fixture_id=event.correlation["fixture_id"],
                        run_id=event.correlation["run_id"],
                        job_id=event.correlation["job_id"],
                        worker_id=event.correlation["worker_id"],
                        trace_id=event.correlation["trace_id"],
                        artifact_id=event.correlation["artifact_id"],
                        config_sha256=event.correlation["config_sha256"],
                        resource_sha256=event.correlation["resource_sha256"],
                        transform_id=event.correlation["transform_id"],
                        observed_at=event.observed_at,
                        emitted_at=event.emitted_at,
                        retrieved_at=(
                            batch.window_end.isoformat(timespec="milliseconds").replace(
                                "+00:00", "Z"
                            )
                        ),
                        attributes=event.attributes,
                        provenance={
                            "query_key": query_key,
                            "evidence_id": evidence_id,
                            "event_sha256": evidence_id,
                            "content_sha256": _digest_without(
                                {"event_id": event.event_id}, "unused"
                            ),
                            "catalog_version": "grafana-evidence-query-catalog/v2",
                            "catalog_sha256": _digest_without({"catalog": "v2"}, "unused"),
                            "tool": {
                                "metric": "query_prometheus",
                                "log": "query_loki_logs",
                                "trace": "tempo_get-trace",
                            }[event.signal],
                            "normalized_arguments": {"query": query_key},
                        },
                    )
                )
        return tuple(observations)


class GeneratedWorkflowModel:
    def __init__(self, query_plan: Sequence[str], incident_class: str) -> None:
        self._query_plan = tuple(query_plan)
        self._incident_class = incident_class

    async def generate(self, call: ModelCall) -> ModelOutput:
        assert call.evidence_tool is not None
        returned: list[Mapping[str, Any]] = []
        for query_key in self._query_plan:
            result = await call.evidence_tool(query_key)  # type: ignore[arg-type]
            returned.append(result)
            if result["deterministic_disposition"] != "continue":
                break
        content = json.dumps(
            {
                "schema": "model-selection/v3",
                "hypotheses": [
                    {
                        "ordinal": 1,
                        "incident_class": self._incident_class,
                        "evidence_ids": list(returned[-1]["evidence_ids"])[-2:],
                    }
                ],
                "query_keys": [
                    "alert.rule",
                    *(str(value["query_key"]) for value in returned),
                ],
                "stop_reason": str(returned[-1]["reason_code"]),
            },
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return ModelOutput(content=content, input_tokens=720, output_tokens=96, model_calls=3)


class RecordingWorkflow:
    def __init__(self, delegate: ReferenceInvestigationWorkflow) -> None:
        self.delegate = delegate
        self.calls: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []

    async def run(
        self,
        *,
        alert: Mapping[str, Any],
        expected_state: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((alert, expected_state))
        return await self.delegate.run(alert=alert, expected_state=expected_state)


class InvalidOutputWorkflow:
    def __init__(self) -> None:
        self.calls = 0

    async def run(
        self,
        *,
        alert: Mapping[str, Any],
        expected_state: Mapping[str, Any],
    ) -> dict[str, Any]:
        del alert, expected_state
        self.calls += 1
        return {"schema": "response-packet/v3"}


class ResolvedWorkflow:
    def __init__(self, *, unrelated_mismatch: bool = False) -> None:
        self._unrelated_mismatch = unrelated_mismatch

    async def run(
        self,
        *,
        alert: Mapping[str, Any],
        expected_state: Mapping[str, Any],
    ) -> dict[str, Any]:
        scenario_id = str(expected_state["scenario_id"])
        incident_class = {
            "tos-resource-resolution-drift-v1": IncidentClass.RESOURCE_RESOLUTION_DRIFT,
            "tos-config-rollout-drift-v1": IncidentClass.CONFIGURATION_ROLLOUT_DRIFT,
            "tos-stale-derivative-cache-v1": IncidentClass.STALE_DERIVATIVE_CACHE,
        }[scenario_id]
        approved = dict(expected_state["approved"])
        expected_to_job = {
            "resource_sha256": "effective_resource_sha256",
            "config_sha256": "effective_config_sha256",
            "config_generation": "config_generation",
            "frame_pipeline_sha256": "frame_pipeline_sha256",
            "derivative_parent_sha256": "derivative_parent_sha256",
            "derivative_generation": "derivative_generation",
            "cache_key": "cache_key",
        }
        protected_facts = {
            job_field: approved[expected_field]
            for expected_field, job_field in expected_to_job.items()
        }
        affected_facts = dict(protected_facts)
        if incident_class is IncidentClass.RESOURCE_RESOLUTION_DRIFT:
            command = "reconcile-resource"
            changed_fields = ["effective_resource_sha256"]
            affected_facts["effective_resource_sha256"] = "sha256:" + "a" * 64
            affected_facts["frame_pipeline_sha256"] = "sha256:" + "d" * 64
        elif incident_class is IncidentClass.CONFIGURATION_ROLLOUT_DRIFT:
            command = "pin-rollout"
            changed_fields = ["config_generation", "effective_config_sha256"]
            affected_facts["config_generation"] = int(protected_facts["config_generation"]) + 1
            affected_facts["effective_config_sha256"] = "sha256:" + "b" * 64
            affected_facts["frame_pipeline_sha256"] = "sha256:" + "d" * 64
        else:
            command = "invalidate-cache"
            changed_fields = ["derivative_generation", "derivative_parent_sha256"]
            affected_facts["derivative_generation"] = (
                int(protected_facts["derivative_generation"]) + 1
            )
            affected_facts["derivative_parent_sha256"] = "sha256:" + "c" * 64
        if self._unrelated_mismatch:
            affected_facts["cache_key"] = "cache-unrelated-mismatch"
        affected_id = expected_state["scope"]["affected_job_ids"][0]
        protected_id = expected_state["scope"]["safe_job_ids"][0]
        fact_id = "runtime-fact:" + "d" * 64
        affected_facts.update(
            {
                "reference_state": "reference_mismatch",
                "fact_ids": [fact_id],
            }
        )
        protected_facts.update(
            {
                "reference_state": "reference_match",
                "fact_ids": [fact_id],
            }
        )
        expected_by_job = {
            job_field: expected_field for expected_field, job_field in expected_to_job.items()
        }
        parameters: dict[str, Any] = {
            "changed_fields": changed_fields,
            "expected": {field: approved[expected_by_job[field]] for field in changed_fields},
            "observed": {field: affected_facts[field] for field in changed_fields},
        }
        if incident_class is IncidentClass.STALE_DERIVATIVE_CACHE:
            parameters["cache_key"] = affected_facts["cache_key"]
        reconciliation_id = "diagnosis-reconciliation:" + "e" * 64
        action = ActionIntent(
            reconciliation_id=reconciliation_id,
            incident_class=incident_class,
            command=command,  # type: ignore[arg-type]
            affected_job_ids=(str(affected_id),),
            evidence_fact_ids=(fact_id,),
            parameters=parameters,
        ).to_dict()
        expected_assessment_id = "expected-assessment:" + "1" * 64
        operational_assessment_id = "operational-assessment:" + "2" * 64
        packet_sha256 = "sha256:" + "3" * 64
        return {
            "schema": "response-packet/v3",
            "packet_id": "response-packet:" + "3" * 64,
            "derivation_sha256": packet_sha256,
            "version": 3,
            "status": "resolved",
            "incident_id": alert["incident_id"],
            "scenario_id": scenario_id,
            "fixture_id": expected_state["fixture_id"],
            "run_id": expected_state["run_id"],
            "fixed_window": expected_state["evidence_window"],
            "expected_state_assessment": {
                "status": "supported",
                "assessment_id": expected_assessment_id,
                "expected_state_sha256": expected_state["expected_state_sha256"],
                "approved": approved,
                "scope": expected_state["scope"],
            },
            "operational_evidence_assessment": {
                "status": "supported",
                "assessment_id": operational_assessment_id,
                "expected_state_assessment_id": expected_assessment_id,
                "request_id": "request-evidence-001",
                "incident_id": alert["incident_id"],
                "job_facts": {
                    str(affected_id): affected_facts,
                    str(protected_id): protected_facts,
                },
                "fact_ids": [fact_id],
            },
            "reference_evidence": {"request_id": "request-evidence-001"},
            "diagnosis_reconciliation": {
                "status": "supported",
                "reconciliation_id": reconciliation_id,
                "incident_class": incident_class.value,
                "expected_state_assessment_id": expected_assessment_id,
                "operational_evidence_assessment_id": operational_assessment_id,
                "scope": expected_state["scope"],
                "evidence_fact_ids": [fact_id],
                "action_intent": action,
            },
            "action_intent": action,
            "no_action_reason": None,
        }


class BlockingWorkflow:
    def __init__(self, delegate: ReferenceInvestigationWorkflow) -> None:
        self.delegate = delegate
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0

    async def run(
        self,
        *,
        alert: Mapping[str, Any],
        expected_state: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return await self.delegate.run(alert=alert, expected_state=expected_state)


class CancellationWorkflow:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.calls = 0

    async def run(
        self,
        *,
        alert: Mapping[str, Any],
        expected_state: Mapping[str, Any],
    ) -> dict[str, Any]:
        del alert, expected_state
        self.calls += 1
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        raise AssertionError("unreachable")


def _reference_run_request(scenario_id: str) -> dict[str, Any]:
    return {
        "schema": "reference-scenario-run-request/v1",
        "request_id": f"request-{hashlib.sha256(scenario_id.encode()).hexdigest()[:24]}",
    }


def _decision_request(
    packet: Mapping[str, Any],
    *,
    request_id: str,
    decision: str = "approved",
    nonce: str = "reference-approval-001",
) -> dict[str, Any]:
    action = packet["action_intent"]
    expected = packet["expected_state_assessment"]
    reconciliation = packet["diagnosis_reconciliation"]
    return {
        "schema": "reference-recovery-decision-request/v1",
        "request_id": request_id,
        "decision": decision,
        "approval_phrase": (
            REFERENCE_APPROVAL_PHRASE if decision == "approved" else REFERENCE_DENIAL_PHRASE
        ),
        "approval_nonce": nonce,
        "packet_id": packet["packet_id"],
        "packet_sha256": packet["derivation_sha256"],
        "expected_state_sha256": expected["expected_state_sha256"],
        "reconciliation_id": reconciliation["reconciliation_id"],
        "action_intent_id": action["action_intent_id"],
        "action_intent_sha256": action["derivation_sha256"],
    }


def _resolved_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    approval_boundary: ReferenceHumanApprovalBoundary | None = None,
    workflow: Any = None,
) -> TestClient:
    monkeypatch.setattr(
        reference_demo_module,
        "validate_reference_response_packet",
        lambda _packet: None,
    )
    runs = ReferenceScenarioRunService(
        workflow=workflow or ResolvedWorkflow(),
        telemetry=GeneratedReferenceScenarioTelemetry(MemoryReferenceTelemetrySink),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
        },
        alert_rule_uid="ct-reference-demo-divergence-v1",
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
        approval_boundary=approval_boundary,
    )
    return TestClient(create_app(IncidentService(), reference_runs=runs))


def _digest_without(document: Mapping[str, Any], digest_field: str) -> str:
    source = {key: value for key, value in document.items() if key != digest_field}
    encoded = json.dumps(
        source,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def test_reference_catalog_lists_three_stable_scenarios_without_cache_paths() -> None:
    catalog = ReferenceDemoCatalog()

    first = catalog.list_scenarios()
    second = catalog.list_scenarios()

    assert first == second
    assert first["schema"] == "reference-scenario-list/v1"
    assert [item["scenario_id"] for item in first["items"]] == [
        "tos-config-rollout-drift-v1",
        "tos-resource-resolution-drift-v1",
        "tos-stale-derivative-cache-v1",
    ]
    assert {item["scope"]["affected_artifact_count"] for item in first["items"]} == {72}
    assert {item["scope"]["protected_artifact_count"] for item in first["items"]} == {168}
    assert first["catalog_sha256"] == _digest_without(first, "catalog_sha256")
    assert first["authority"] == {
        "schema": "reference-authority-boundary/v1",
        "catalog_facts": "sealed-reference-contracts",
        "incident_facts": "deterministic-validators",
        "model_role": "advisory",
        "evidence_access": "grafana-mcp-read-only",
        "action_approval": "human-only",
        "action_execution_target": "colortrace-simulator",
    }
    encoded = json.dumps(first)
    assert "cache_root" not in encoded
    assert "/home/" not in encoded


@pytest.mark.parametrize(
    ("scenario_id", "required_fields"),
    [
        (
            "tos-resource-resolution-drift-v1",
            {
                "runtime.effective_resource_sha256",
                "runtime.frame_pipeline_sha256",
            },
        ),
        (
            "tos-config-rollout-drift-v1",
            {
                "runtime.effective_config_sha256",
                "runtime.config_generation",
                "runtime.frame_pipeline_sha256",
            },
        ),
        (
            "tos-stale-derivative-cache-v1",
            {
                "runtime.frame_pipeline_sha256",
                "derivative.parent_sha256",
                "cache.generation",
                "cache.key",
            },
        ),
    ],
)
def test_reference_scenario_detail_exposes_evidence_and_recovery_authority(
    scenario_id: str,
    required_fields: set[str],
) -> None:
    detail = ReferenceDemoCatalog().get_scenario(scenario_id)

    assert detail["schema"] == "reference-scenario-detail/v1"
    assert detail["scenario"]["scenario_id"] == scenario_id
    assert detail["scenario"]["scope"]["affected_artifact_ids"]
    assert detail["scenario"]["scope"]["protected_artifact_ids"]
    assert set(detail["evidence_requirements"]["required_fact_fields"]) == required_fields
    assert detail["evidence_requirements"]["minimum_complementary_signal_classes"] == 2
    assert detail["evidence_requirements"]["live_run_scope"] == {
        "kind": "representative-evidence",
        "affected_job_count": 1,
        "protected_job_count": 1,
        "population_affected_artifact_count": 72,
        "population_protected_artifact_count": 168,
        "establishes_full_population_scope": False,
    }
    assert detail["recovery_boundary"] == {
        "intent": detail["scenario"]["recovery_kind"],
        "requires_human_approval": True,
        "execution_target": "colortrace-simulator",
        "catalog_executes_actions": False,
    }
    assert detail["detail_sha256"] == _digest_without(detail, "detail_sha256")


def test_reference_visual_is_deterministic_receipt_bound_pixel_evidence() -> None:
    catalog = ReferenceDemoCatalog()

    first = catalog.scenario_visual("tos-resource-resolution-drift-v1", "observed")
    second = catalog.scenario_visual("tos-resource-resolution-drift-v1", "observed")

    assert first == second
    assert first.media_type == "image/png"
    assert first.representation == "open-film-preview-png/v1"
    assert first.pixel_evidence is True
    assert first.sha256 == f"sha256:{hashlib.sha256(first.content).hexdigest()}"
    assert first.content.startswith(b"\x89PNG\r\n\x1a\n")
    descriptor = catalog.get_scenario("tos-resource-resolution-drift-v1")["summary"]["visuals"][1]
    assert descriptor["kind"] == "observed"
    assert descriptor["content_sha256"] == first.sha256
    assert descriptor["source_receipt_sha256"]
    assert descriptor["source_canonical_pixel_sha256"]


def test_reference_catalog_rejects_unknown_scenarios_and_visuals() -> None:
    catalog = ReferenceDemoCatalog()

    with pytest.raises(ReferenceDemoError, match="reference-scenario-not-found"):
        catalog.get_scenario("unknown")
    with pytest.raises(ReferenceDemoError, match="reference-visual-not-found"):
        catalog.scenario_visual("tos-resource-resolution-drift-v1", "unknown")


def test_reference_benchmark_suite_reports_source_bound_recorded_results() -> None:
    suite = ReferenceDemoCatalog().benchmark_suite()

    assert suite["schema"] == "reference-benchmark-suite/v1"
    assert suite["definition_state"] == "sealed"
    assert suite["result_state"] == "recorded"
    assert suite["result"]["schema"] == "reference-impact-benchmark/v3"
    assert suite["result"]["passed"] is True
    assert suite["result"]["evidence"]["execution_identity"]["source_revision"] == (
        "db6832bce8adf5b0f62527202cbd388fa1f18e70"
    )
    assert "model_comparison_research" not in suite["result"]
    assert suite["result"]["checks"]["output_equivalence"] is True
    assert suite["result"]["checks"]["protected_output_integrity"] is True
    assert suite["result"]["metrics"]["median_compute_avoided_basis_points"] == 7_000
    assert suite["result"]["metrics"]["median_application_bytes_avoided_basis_points"] == 4_167
    assert {scenario["scope_reduction_basis_points"] for scenario in suite["scenarios"]} == {7_000}
    assert suite["measurement_boundary"] == {
        "scope_reduction_is_measured_result": False,
        "reported_results_require_recorded_evaluator_output": True,
        "catalog_claims_observed_savings": True,
        "live_run_scope": "representative-evidence-only",
    }
    assert suite["authority"]["benchmark_result_authority"] == "recorded-evaluator-output"
    assert suite["suite_sha256"] == _digest_without(suite, "suite_sha256")


def test_reference_benchmark_route_fails_closed_on_invalid_recorded_result(
    tmp_path: Path,
) -> None:
    result_path = tmp_path / "reference-impact-benchmark.json"
    result_path.write_text("{}\n", encoding="utf-8")
    catalog = ReferenceDemoCatalog(benchmark_result_path=result_path)
    client = TestClient(create_app(IncidentService(), reference_demo=catalog))

    response = client.get("/v1/benchmarks/reference-suite")

    assert response.status_code == 503
    assert response.json() == {"code": "reference-benchmark-result-invalid"}


def test_reference_routes_are_additive_and_fail_closed_when_unconfigured() -> None:
    unavailable = TestClient(create_app(IncidentService()))
    assert unavailable.get("/v1/demo/scenarios").json() == {"code": "reference-demo-unavailable"}
    assert unavailable.post(
        "/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs",
        json=_reference_run_request("tos-resource-resolution-drift-v1"),
    ).json() == {"code": "reference-run-unavailable"}

    client = TestClient(create_app(IncidentService(), reference_demo=ReferenceDemoCatalog()))
    listed = client.get("/v1/demo/scenarios")
    assert listed.status_code == 200
    scenario_id = listed.json()["items"][0]["scenario_id"]

    detail = client.get(f"/v1/demo/scenarios/{scenario_id}")
    visual = client.get(f"/v1/demo/scenarios/{scenario_id}/visuals/diff")
    suite = client.get("/v1/benchmarks/reference-suite")

    assert detail.status_code == 200
    assert visual.status_code == 200
    assert visual.headers["content-type"].startswith("image/png")
    assert visual.headers["x-content-sha256"] == (
        f"sha256:{hashlib.sha256(visual.content).hexdigest()}"
    )
    assert visual.headers["x-colortrace-pixel-evidence"] == "true"
    assert visual.headers["x-colortrace-representation"] == ("open-film-difference-png/v1")
    assert suite.status_code == 200
    assert client.get("/v1/demo/scenarios/unknown").status_code == 404
    assert client.get(f"/v1/demo/scenarios/{scenario_id}/visuals/unknown").status_code == 404


@pytest.mark.parametrize(
    "scenario_id",
    (
        "tos-resource-resolution-drift-v1",
        "tos-config-rollout-drift-v1",
        "tos-stale-derivative-cache-v1",
    ),
)
def test_reference_run_emits_bound_telemetry_and_invokes_v3_workflow(
    scenario_id: str,
) -> None:
    evidence = UnavailableEvidence()
    workflow = RecordingWorkflow(
        ReferenceInvestigationWorkflow(
            model=NeverModel(),
            evidence=evidence,
            clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
        )
    )
    sink = MemoryReferenceTelemetrySink()
    runs = ReferenceScenarioRunService(
        workflow=workflow,
        telemetry=GeneratedReferenceScenarioTelemetry(lambda: sink),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
        },
        alert_rule_uid="ct-reference-demo-divergence-v1",
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    client = TestClient(
        create_app(
            IncidentService(),
            reference_demo=ReferenceDemoCatalog(),
            reference_runs=runs,
        )
    )

    response = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=_reference_run_request(scenario_id),
    )

    assert response.status_code == 200
    packet = response.json()
    assert packet["schema"] == "response-packet/v3"
    assert packet["scenario_id"] == scenario_id
    assert packet["status"] == "unresolved"
    assert packet["no_action_reason"] == "evidence-unavailable"
    assert packet["action_intent"] is None
    assert response.headers["x-colortrace-evidence-scope"] == "representative"
    assert response.headers["x-colortrace-affected-representatives"] == "1"
    assert response.headers["x-colortrace-protected-representatives"] == "1"
    assert "x-colortrace-population-scope" not in response.headers
    assert evidence.opened == 1
    assert len(workflow.calls) == 1
    alert, expected = workflow.calls[0]
    assert alert["incident_id"] == packet["incident_id"]
    assert alert["binding"] == {
        "prometheus_datasource_uid": "prometheus",
        "loki_datasource_uid": "loki",
        "tempo_datasource_uid": "tempo",
        "alert_rule_uid": "ct-reference-demo-divergence-v1",
    }
    assert scenario_id not in alert["alert_id"]
    assert expected["scenario_id"] == scenario_id
    assert expected["fixture_id"] == packet["fixture_id"]
    assert expected["run_id"] == packet["run_id"]
    assert expected["scope"]["affected_job_ids"]
    assert expected["scope"]["safe_job_ids"]
    assert expected["evidence_window"] == packet["fixed_window"]
    assert packet["operational_evidence_assessment"]["incident_id"] is None
    assert packet["operational_evidence_assessment"]["request_id"] is None
    assert len(sink.events) == 6
    assert {event["data_origin"] for event in sink.events} == {"generated-demonstration-telemetry"}

    replay = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=_reference_run_request(scenario_id),
    )
    assert replay.status_code == 200
    assert replay.json() == packet
    assert evidence.opened == 1
    assert len(workflow.calls) == 1
    assert len(sink.events) == 6


def test_reference_run_rejects_caller_supplied_binding_before_emitting() -> None:
    evidence = UnavailableEvidence()
    workflow = RecordingWorkflow(
        ReferenceInvestigationWorkflow(model=NeverModel(), evidence=evidence)
    )
    sink = MemoryReferenceTelemetrySink()
    runs = ReferenceScenarioRunService(
        workflow=workflow,
        telemetry=GeneratedReferenceScenarioTelemetry(lambda: sink),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
        },
        alert_rule_uid="ct-reference-demo-divergence-v1",
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    client = TestClient(create_app(IncidentService(), reference_runs=runs))
    request = _reference_run_request("tos-resource-resolution-drift-v1")
    request["binding"] = {"fixture_id": "other-fixture"}

    response = client.post(
        "/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs",
        json=request,
    )

    assert response.status_code == 400
    assert response.json() == {"code": "reference-run-request-invalid"}
    assert sink.events == []
    assert workflow.calls == []
    assert evidence.opened == 0


def test_reference_run_rejects_unknown_scenario_before_emitting() -> None:
    evidence = UnavailableEvidence()
    workflow = RecordingWorkflow(
        ReferenceInvestigationWorkflow(model=NeverModel(), evidence=evidence)
    )
    sink = MemoryReferenceTelemetrySink()
    runs = ReferenceScenarioRunService(
        workflow=workflow,
        telemetry=GeneratedReferenceScenarioTelemetry(lambda: sink),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
        },
        alert_rule_uid="ct-reference-demo-divergence-v1",
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    client = TestClient(create_app(IncidentService(), reference_runs=runs))

    response = client.post(
        "/v1/demo/scenarios/not-a-reference-scenario/runs",
        json=_reference_run_request("tos-resource-resolution-drift-v1"),
    )

    assert response.status_code == 404
    assert response.json() == {"code": "reference-scenario-not-found"}
    assert sink.events == []
    assert workflow.calls == []


def test_reference_run_rejects_invalid_workflow_output() -> None:
    workflow = InvalidOutputWorkflow()
    sink = MemoryReferenceTelemetrySink()
    runs = ReferenceScenarioRunService(
        workflow=workflow,
        telemetry=GeneratedReferenceScenarioTelemetry(lambda: sink),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
        },
        alert_rule_uid="ct-reference-demo-divergence-v1",
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    client = TestClient(create_app(IncidentService(), reference_runs=runs))

    response = client.post(
        "/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs",
        json=_reference_run_request("tos-resource-resolution-drift-v1"),
    )

    assert response.status_code == 503
    assert response.json() == {"code": "reference-run-output-unavailable"}
    assert workflow.calls == 1
    assert len(sink.events) == 6

    replay = client.post(
        "/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs",
        json=_reference_run_request("tos-resource-resolution-drift-v1"),
    )
    assert replay.status_code == 503
    assert replay.json() == {"code": "reference-run-output-unavailable"}
    assert workflow.calls == 1
    assert len(sink.events) == 6


@pytest.mark.parametrize(
    "scenario_id",
    (
        "tos-resource-resolution-drift-v1",
        "tos-config-rollout-drift-v1",
        "tos-stale-derivative-cache-v1",
    ),
)
def test_reference_recovery_approval_is_exact_simulator_only_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    scenario_id: str,
) -> None:
    client = _resolved_client(monkeypatch)
    run_request = _reference_run_request(scenario_id)
    packet_response = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=run_request,
    )
    assert packet_response.status_code == 200
    packet = packet_response.json()
    assert packet["status"] == "resolved"
    decision_request = _decision_request(packet, request_id=run_request["request_id"])
    path = f"/v1/demo/scenarios/{scenario_id}/runs/{run_request['request_id']}/decision"

    response = client.post(path, json=decision_request)

    assert response.status_code == 200
    decision = response.json()
    assert decision["schema"] == "reference-recovery-decision/v1"
    assert decision["outcome"] == "applied"
    assert decision["approval"]["decision"] == "approved"
    assert decision["approval"]["approver"]["kind"] == "human"
    assert decision["approval"]["approver"]["identity_verified"] is False
    assert decision["approval"]["approver"]["identity_assurance"] == (
        "unverified-public-demo-gesture"
    )
    assert decision["approval"]["approver"]["gesture"] == "explicit-phrase-and-nonce"
    assert "identity" not in decision["approval"]["approver"]
    assert decision["approval"]["action_intent_id"] == packet["action_intent"]["action_intent_id"]
    assert (
        decision["approval"]["reconciliation_id"]
        == packet["diagnosis_reconciliation"]["reconciliation_id"]
    )
    assert decision["approval"]["state_sha256"] == decision["before"]["state_sha256"]
    assert decision["before"]["generation"] == 1
    assert decision["after"]["generation"] == 2
    assert decision["before"]["state_sha256"] != decision["after"]["state_sha256"]
    assert decision["protected_state_unchanged"] is True
    assert (
        decision["before"]["protected_state_sha256"] == decision["after"]["protected_state_sha256"]
    )
    assert decision["receipt"]["result"] == "applied"
    assert decision["receipt"]["before"] == decision["before"]
    assert decision["receipt"]["after"] == decision["after"]
    verification = decision["verification"]
    assert verification == decision["receipt"]["verification"]
    assert set(verification) == {
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
    assert verification["verifier"] == "deterministic-simulator-state"
    assert verification["result"] == "verified"
    assert verification["before"] == decision["before"]
    assert verification["after"] == decision["after"]
    assert [check["field"] for check in verification["affected_expected_field_checks"]] == packet[
        "action_intent"
    ]["parameters"]["changed_fields"]
    assert verification["checks"] == {
        "generation_advanced_exactly_once": True,
        "all_affected_expected_fields_match": True,
        "protected_state_unchanged": True,
        "receipt_state_bindings_match": True,
    }
    assert verification["establishes_pixel_output"] is False
    assert verification["establishes_full_population_scope"] is False
    assert verification["production_evidence"] is False
    assert verification["verification_sha256"] == _digest_without(
        verification, "verification_sha256"
    )
    assert decision["scope"] == {
        "kind": "representative-simulator-state",
        "affected_job_count": 1,
        "protected_job_count": 1,
        "establishes_full_population_scope": False,
    }
    assert decision["execution_boundary"] == {
        "approval_actor_kind": "human",
        "approval_gesture": "explicit-phrase-and-nonce",
        "identity_verified": False,
        "identity_assurance": "unverified-public-demo-gesture",
        "execution_target": "colortrace-simulator",
        "simulator_state_changed": True,
        "production_access_used": False,
        "production_state_changed": False,
        "production_claim": "none",
    }
    assert response.headers["x-colortrace-execution-target"] == "colortrace-simulator"
    assert response.headers["x-colortrace-production-state-changed"] == "false"
    assert decision["decision_sha256"] == _digest_without(decision, "decision_sha256")

    replay = client.post(path, json=decision_request)
    assert replay.status_code == 200
    assert replay.json() == decision

    conflict = dict(decision_request)
    conflict["approval_nonce"] = "reference-approval-conflict"
    rejected = client.post(path, json=conflict)
    assert rejected.status_code == 409
    assert rejected.json() == {"code": "reference-recovery-decision-conflict"}
    assert client.post(path, json=decision_request).json() == decision


@pytest.mark.parametrize(
    ("scenario_id", "incident_class", "query_plan", "derived_frame_mismatch"),
    (
        (
            "tos-resource-resolution-drift-v1",
            "resource-resolution-drift/v1",
            ("metric.worker-cohort", "log.config-cohort"),
            True,
        ),
        (
            "tos-config-rollout-drift-v1",
            "configuration-rollout-drift/v1",
            ("log.config-cohort", "trace.by-id", "metric.worker-cohort"),
            True,
        ),
        (
            "tos-stale-derivative-cache-v1",
            "stale-derivative-cache/v1",
            ("trace.by-id", "metric.worker-cohort", "log.config-cohort"),
            False,
        ),
    ),
)
def test_reference_recovery_accepts_real_workflow_evidence_for_every_scenario(
    scenario_id: str,
    incident_class: str,
    query_plan: Sequence[str],
    derived_frame_mismatch: bool,
) -> None:
    sink = MemoryReferenceTelemetrySink()
    workflow = ReferenceInvestigationWorkflow(
        model=GeneratedWorkflowModel(query_plan, incident_class),
        evidence=GeneratedWorkflowEvidence(scenario_id, incident_class),
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    runs = ReferenceScenarioRunService(
        workflow=workflow,
        telemetry=GeneratedReferenceScenarioTelemetry(lambda: sink),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
        },
        alert_rule_uid="ct-reference-demo-divergence-v1",
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    client = TestClient(create_app(IncidentService(), reference_runs=runs))
    run_request = _reference_run_request(scenario_id)

    packet_response = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=run_request,
    )

    assert packet_response.status_code == 200
    packet = packet_response.json()
    assert packet["status"] == "resolved"
    affected_job_id = packet["expected_state_assessment"]["scope"]["affected_job_ids"][0]
    affected_facts = packet["operational_evidence_assessment"]["job_facts"][affected_job_id]
    approved_frame = packet["expected_state_assessment"]["approved"]["frame_pipeline_sha256"]
    assert (affected_facts["frame_pipeline_sha256"] != approved_frame) is (derived_frame_mismatch)

    decision = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs/{run_request['request_id']}/decision",
        json=_decision_request(packet, request_id=run_request["request_id"]),
    )

    assert decision.status_code == 200
    body = decision.json()
    assert body["outcome"] == "applied"
    assert body["verification"]["result"] == "verified"
    assert body["verification"]["verifier"] == "deterministic-simulator-state"
    assert body["protected_state_unchanged"] is True
    assert len(sink.events) == 6


def test_reference_recovery_context_still_rejects_unrelated_affected_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_id = "tos-resource-resolution-drift-v1"
    client = _resolved_client(
        monkeypatch,
        workflow=ResolvedWorkflow(unrelated_mismatch=True),
    )

    response = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=_reference_run_request(scenario_id),
    )

    assert response.status_code == 503
    assert response.json() == {"code": "reference-run-recovery-state-invalid"}


def test_reference_recovery_denial_is_terminal_and_never_mutates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_id = "tos-resource-resolution-drift-v1"
    client = _resolved_client(monkeypatch)
    run_request = _reference_run_request(scenario_id)
    packet = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=run_request,
    ).json()
    decision_request = _decision_request(
        packet,
        request_id=run_request["request_id"],
        decision="denied",
    )
    path = f"/v1/demo/scenarios/{scenario_id}/runs/{run_request['request_id']}/decision"

    response = client.post(path, json=decision_request)

    assert response.status_code == 200
    decision = response.json()
    assert decision["outcome"] == "denied"
    assert decision["approval"]["decision"] == "denied"
    assert decision["before"] == decision["after"]
    assert decision["protected_state_unchanged"] is True
    assert decision["receipt"] is None
    assert decision["verification"] is None
    assert decision["execution_boundary"]["simulator_state_changed"] is False
    assert client.post(path, json=decision_request).json() == decision

    conflicting_approval = _decision_request(
        packet,
        request_id=run_request["request_id"],
        nonce="reference-approval-after-denial",
    )
    rejected = client.post(path, json=conflicting_approval)
    assert rejected.status_code == 409
    assert rejected.json() == {"code": "reference-recovery-decision-conflict"}


def test_reference_recovery_rejects_phrase_and_binding_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scenario_id = "tos-config-rollout-drift-v1"
    client = _resolved_client(monkeypatch)
    run_request = _reference_run_request(scenario_id)
    packet = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=run_request,
    ).json()
    path = f"/v1/demo/scenarios/{scenario_id}/runs/{run_request['request_id']}/decision"
    request = _decision_request(packet, request_id=run_request["request_id"])

    wrong_phrase = dict(request)
    wrong_phrase["approval_phrase"] = "approve"
    rejected_phrase = client.post(path, json=wrong_phrase)
    assert rejected_phrase.status_code == 403
    assert rejected_phrase.json() == {"code": "reference-recovery-approval-phrase-invalid"}

    wrong_binding = dict(request)
    wrong_binding["expected_state_sha256"] = "sha256:" + "f" * 64
    rejected_binding = client.post(path, json=wrong_binding)
    assert rejected_binding.status_code == 409
    assert rejected_binding.json() == {"code": "reference-recovery-decision-binding-conflict"}

    accepted = client.post(path, json=request)
    assert accepted.status_code == 200
    assert accepted.json()["before"]["generation"] == 1
    assert accepted.json()["after"]["generation"] == 2


def test_reference_recovery_rejects_unresolved_run_without_mutation() -> None:
    evidence = UnavailableEvidence()
    runs = ReferenceScenarioRunService(
        workflow=ReferenceInvestigationWorkflow(model=NeverModel(), evidence=evidence),
        telemetry=GeneratedReferenceScenarioTelemetry(MemoryReferenceTelemetrySink),
        evidence_binding={
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
        },
        alert_rule_uid="ct-reference-demo-divergence-v1",
        clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
    )
    client = TestClient(create_app(IncidentService(), reference_runs=runs))
    scenario_id = "tos-stale-derivative-cache-v1"
    run_request = _reference_run_request(scenario_id)
    packet = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=run_request,
    ).json()
    assert packet["status"] == "unresolved"
    path = f"/v1/demo/scenarios/{scenario_id}/runs/{run_request['request_id']}/decision"
    request = {
        "schema": "reference-recovery-decision-request/v1",
        "request_id": run_request["request_id"],
        "decision": "approved",
        "approval_phrase": REFERENCE_APPROVAL_PHRASE,
        "approval_nonce": "reference-unresolved-approval",
        "packet_id": packet["packet_id"],
        "packet_sha256": packet["derivation_sha256"],
        "expected_state_sha256": packet["expected_state_assessment"]["expected_state_sha256"],
        "reconciliation_id": "diagnosis-reconciliation:" + "a" * 64,
        "action_intent_id": "action-intent:" + "b" * 64,
        "action_intent_sha256": "sha256:" + "c" * 64,
    }

    response = client.post(path, json=request)

    assert response.status_code == 409
    assert response.json() == {"code": "reference-recovery-run-unresolved"}


def test_reference_recovery_stale_approval_is_cached_without_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ApprovalClock:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self) -> datetime:
            self.calls += 1
            offset = 0 if self.calls == 1 else 6
            return datetime(2026, 9, 4, 12, offset, tzinfo=UTC)

    scenario_id = "tos-stale-derivative-cache-v1"
    approval_boundary = ReferenceHumanApprovalBoundary(
        audience="colortrace-simulator",
        clock=ApprovalClock(),
    )
    client = _resolved_client(monkeypatch, approval_boundary=approval_boundary)
    run_request = _reference_run_request(scenario_id)
    packet = client.post(
        f"/v1/demo/scenarios/{scenario_id}/runs",
        json=run_request,
    ).json()
    path = f"/v1/demo/scenarios/{scenario_id}/runs/{run_request['request_id']}/decision"
    stale = _decision_request(packet, request_id=run_request["request_id"])

    first = client.post(path, json=stale)
    replay = client.post(path, json=stale)

    assert first.status_code == replay.status_code == 409
    assert first.json() == replay.json() == {"code": "reference-approval-stale"}
    fresh = dict(stale)
    fresh["approval_nonce"] = "reference-approval-fresh"
    accepted = client.post(path, json=fresh)
    assert accepted.status_code == 200
    assert accepted.json()["before"]["generation"] == 1
    assert accepted.json()["after"]["generation"] == 2


def test_reference_run_capacity_fails_fast_and_cancelled_waiter_does_not_cancel_shared_run() -> (
    None
):
    async def exercise() -> None:
        evidence = UnavailableEvidence()
        workflow = BlockingWorkflow(
            ReferenceInvestigationWorkflow(model=NeverModel(), evidence=evidence)
        )
        runs = ReferenceScenarioRunService(
            workflow=workflow,
            telemetry=GeneratedReferenceScenarioTelemetry(MemoryReferenceTelemetrySink),
            evidence_binding={
                "prometheus_datasource_uid": "prometheus",
                "loki_datasource_uid": "loki",
                "tempo_datasource_uid": "tempo",
            },
            alert_rule_uid="ct-reference-demo-divergence-v1",
            clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
            maximum_in_flight=1,
        )
        scenario_id = "tos-resource-resolution-drift-v1"
        request = _reference_run_request(scenario_id)
        first = asyncio.create_task(runs.run_scenario(scenario_id, request))
        await asyncio.wait_for(workflow.started.wait(), timeout=1)
        shared_waiter = asyncio.create_task(runs.run_scenario(scenario_id, request))
        await asyncio.sleep(0)
        with pytest.raises(ReferenceDemoError, match="reference-run-overloaded") as overload:
            await runs.run_scenario(
                "tos-config-rollout-drift-v1",
                _reference_run_request("tos-config-rollout-drift-v1"),
            )
        assert overload.value.code == "reference-run-overloaded"
        shared_waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await shared_waiter
        workflow.release.set()
        packet = await first
        assert packet["status"] == "unresolved"
        replay = await runs.run_scenario(scenario_id, request)
        assert replay == packet
        assert workflow.calls == 1

    asyncio.run(exercise())


def test_reference_run_deadline_cancels_and_removes_in_flight_work() -> None:
    async def exercise() -> None:
        workflow = CancellationWorkflow()
        runs = ReferenceScenarioRunService(
            workflow=workflow,
            telemetry=GeneratedReferenceScenarioTelemetry(MemoryReferenceTelemetrySink),
            evidence_binding={
                "prometheus_datasource_uid": "prometheus",
                "loki_datasource_uid": "loki",
                "tempo_datasource_uid": "tempo",
            },
            alert_rule_uid="ct-reference-demo-divergence-v1",
            clock=lambda: datetime(2026, 9, 4, 12, 5, tzinfo=UTC),
            maximum_in_flight=1,
            run_deadline_seconds=0.25,
        )
        scenario_id = "tos-resource-resolution-drift-v1"
        request = _reference_run_request(scenario_id)
        with pytest.raises(ReferenceDemoError, match="reference-run-deadline-exceeded"):
            await runs.run_scenario(scenario_id, request)
        await asyncio.wait_for(workflow.cancelled.wait(), timeout=1)
        workflow.cancelled.clear()
        with pytest.raises(ReferenceDemoError, match="reference-run-deadline-exceeded"):
            await runs.run_scenario(scenario_id, request)
        await asyncio.wait_for(workflow.cancelled.wait(), timeout=1)
        assert workflow.calls == 2

    asyncio.run(exercise())
