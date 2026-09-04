from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from functools import cache
from typing import Any, cast

import pytest
from colortrace_evaluation.contracts import prefixed_sha256
from colortrace_evaluation.reference_campaign import (
    BenchmarkArtifactObservation,
    CaseKind,
    MutationKind,
    RecordedSelectionReceiptSet,
    ReferenceCampaignError,
    SelectionBudget,
    SelectionTrace,
    build_reference_impact_benchmark,
    compare_selection_policies,
    controlled_adaptive_selection_traces,
    record_reference_model_selections,
    reference_selection_input,
    run_recorded_reference_campaign,
    run_reference_campaign,
    sealed_reference_holdouts,
    verified_recorded_selection_traces,
)
from colortrace_fixture import reference_scenarios
from colortrace_investigation import (
    RECORDED_REFERENCE_SELECTION_TURN_KIND,
    ModelCall,
    ModelOutput,
)
from colortrace_validator import IncidentClass


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


class _RecordedSelectionModel:
    def __init__(self) -> None:
        self.calls: list[ModelCall] = []

    async def generate(self, call: ModelCall) -> ModelOutput:
        self.calls.append(call)
        assert call.turn_kind == RECORDED_REFERENCE_SELECTION_TURN_KIND
        assert call.evidence_tool is None
        approved = call.payload["approved"]
        initial = call.payload["initial_query"]
        assert isinstance(approved, dict)
        assert isinstance(initial, dict)
        observations = initial["observations"]
        assert isinstance(observations, list)
        affected = next(
            item
            for item in observations
            if isinstance(item, dict)
            and isinstance(item.get("attributes"), dict)
            and item["attributes"].get("declared_reference.state") == "reference_mismatch"
        )
        attributes = affected["attributes"]
        assert isinstance(attributes, dict)
        derivative_changed = (
            attributes["derivative.parent_sha256"] != approved["derivative_parent_sha256"]
            or int(attributes["cache.generation"]) != approved["derivative_generation"]
        )
        response = {
            "schema": "reference-recorded-model-selection/v1",
            "selection_input_sha256": call.payload["input_sha256"],
            "selected_query_key": (
                "trace.by-id" if derivative_changed else "log.correlated-events"
            ),
        }
        return ModelOutput(
            content=json.dumps(response, separators=(",", ":"), sort_keys=True).encode(),
            input_tokens=700,
            output_tokens=32,
            model_calls=1,
            provider_request_id=f"provider-request-{len(self.calls):02d}",
            provider_model_version="gemini-3.5-flash-20260904",
        )


@cache
def _recorded_campaign() -> tuple[
    RecordedSelectionReceiptSet,
    tuple[SelectionTrace, ...],
    dict[str, Any],
]:
    corpus = sealed_reference_holdouts()
    receipts = asyncio.run(
        record_reference_model_selections(
            model=_RecordedSelectionModel(),
            corpus=corpus,
            clock=lambda: datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
        )
    )
    traces = verified_recorded_selection_traces(corpus, receipts)
    return receipts, traces, run_recorded_reference_campaign(receipts, corpus)


def _receipt(
    scenario_id: str,
    incident_class: str,
    artifact_id: str,
    *,
    mode: str,
    canonical_pixel_sha256: str,
    output_sha256: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": "reference-render-receipt/v1",
        "job_id": f"{mode}-{artifact_id}",
        "scenario_id": scenario_id,
        "incident_class": incident_class,
        "trace_id": hashlib.sha256(f"{scenario_id}:{artifact_id}".encode()).hexdigest()[:32],
        "worker_id": "worker-reference-01",
        "artifact_id": artifact_id,
        "source_sha256": _digest(f"source:{artifact_id}"),
        "config_sha256": _digest(f"config:{scenario_id}"),
        "resource_sha256": _digest(f"resource:{scenario_id}"),
        "effective_generation": 7,
        "cache_key": f"cache:{artifact_id}:g7",
        "output_relative_path": f"{scenario_id}/{mode}/{artifact_id}.exr",
        "output_sha256": output_sha256,
        "canonical_pixel_sha256": canonical_pixel_sha256,
        "width": 10,
        "height": 10,
        "channels": 3,
        "pixel_work": 100,
        "bytes_read": 1000,
        "bytes_written": 500,
        "cpu_nanoseconds": 1_000_000,
        "wall_nanoseconds": 2_000_000,
        "dependencies": {
            "openimageio": "3.1.17.0",
            "opencolorio": "2.5.2",
        },
    }
    return {**body, "receipt_sha256": prefixed_sha256(body)}


def _benchmark_observations() -> tuple[BenchmarkArtifactObservation, ...]:
    result: list[BenchmarkArtifactObservation] = []
    for scenario in reference_scenarios().values():
        affected_ids = set(scenario.affected_artifact_ids)
        for artifact_id in (
            *scenario.affected_artifact_ids,
            *scenario.protected_artifact_ids,
        ):
            affected = artifact_id in affected_ids
            canonical = _digest(f"pixels:{scenario.scenario_id}:{artifact_id}")
            output = _digest(f"output:{scenario.scenario_id}:{artifact_id}")
            baseline = _receipt(
                scenario.scenario_id,
                scenario.incident_class,
                artifact_id,
                mode="baseline",
                canonical_pixel_sha256=canonical,
                output_sha256=output,
            )
            requires_render = affected
            selective = (
                _receipt(
                    scenario.scenario_id,
                    scenario.incident_class,
                    artifact_id,
                    mode="selective",
                    canonical_pixel_sha256=canonical,
                    output_sha256=output,
                )
                if requires_render
                else None
            )
            observed = None
            if affected:
                observed = _receipt(
                    scenario.scenario_id,
                    scenario.incident_class,
                    artifact_id,
                    mode="observed",
                    canonical_pixel_sha256=_digest(
                        f"observed-pixels:{scenario.scenario_id}:{artifact_id}"
                    ),
                    output_sha256=_digest(f"observed-output:{scenario.scenario_id}:{artifact_id}"),
                )
                if scenario.incident_class == "resource-resolution-drift/v1":
                    observed["resource_sha256"] = _digest(f"shadowed-resource:{artifact_id}")
                elif scenario.incident_class == "configuration-rollout-drift/v1":
                    observed["config_sha256"] = _digest(f"stale-config:{artifact_id}")
                    observed["effective_generation"] = 6
                else:
                    observed["source_sha256"] = _digest(f"stale-parent:{artifact_id}")
                observed_body = {
                    key: value for key, value in observed.items() if key != "receipt_sha256"
                }
                observed["receipt_sha256"] = prefixed_sha256(observed_body)
            preserved = output if selective is None else None
            preserved_pixels = canonical if selective is None else None
            result.append(
                BenchmarkArtifactObservation(
                    scenario_id=scenario.scenario_id,
                    artifact_id=artifact_id,
                    affected=affected,
                    baseline_receipt=baseline,
                    observed_receipt=observed,
                    selective_receipt=selective,
                    preserved_before_output_sha256=preserved,
                    preserved_after_output_sha256=preserved,
                    preserved_before_canonical_pixel_sha256=preserved_pixels,
                    preserved_after_canonical_pixel_sha256=preserved_pixels,
                    verification_bytes_read=100 if selective is None else 0,
                )
            )
    return tuple(result)


def test_sealed_holdouts_are_deterministic_balanced_and_include_mutations() -> None:
    first = sealed_reference_holdouts()
    second = sealed_reference_holdouts()

    assert first.to_dict() == second.to_dict()
    assert first.corpus_sha256 == second.corpus_sha256
    assert len(first.cases) == 87
    resolvable = [case for case in first.cases if case.kind is CaseKind.RESOLVABLE]
    assert Counter(case.source_incident_class for case in resolvable) == {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: 20,
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: 20,
        IncidentClass.STALE_DERIVATIVE_CACHE: 20,
    }
    assert Counter(
        case.source_incident_class for case in first.cases if case.kind is CaseKind.FAIL_CLOSED
    ) == {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: 9,
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: 9,
        IncidentClass.STALE_DERIVATIVE_CACHE: 9,
    }
    assert {case.mutation for case in first.cases if case.kind is CaseKind.FAIL_CLOSED} == {
        MutationKind.NO_EVIDENCE,
        MutationKind.ONE_SIGNAL,
        MutationKind.STALE_OBSERVATION,
        MutationKind.CROSS_RUN,
        MutationKind.CONFLICTING_EVENT,
        MutationKind.SCOPE_MISMATCH,
        MutationKind.MULTI_DIMENSION_DRIFT,
        MutationKind.NO_CAUSAL_DRIFT,
        MutationKind.MALFORMED_DIGEST,
    }


def test_campaign_meets_classification_authority_and_ablation_gates() -> None:
    report = run_reference_campaign()

    assert report["passed"] is False
    assert report["case_counts"] == {
        "total": 87,
        "resolvable": 60,
        "fail_closed": 27,
        "resolvable_by_class": {
            "resource-resolution-drift/v1": 20,
            "configuration-rollout-drift/v1": 20,
            "stale-derivative-cache/v1": 20,
        },
    }
    assert report["metrics"]["classification_accuracy_basis_points"] == 10_000
    assert report["metrics"]["negative_cases_failed_closed"] == 27
    assert report["metrics"]["false_action_intents"] == 0
    assert report["metrics"]["false_authorized_actions"] == 0
    assert report["metrics"]["display_text_mutations_resolved"] == 3
    assert report["checks"]["measurable_adaptive_advantage"] is False
    assert all(
        value for key, value in report["checks"].items() if key != "measurable_adaptive_advantage"
    )
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    assert report["report_sha256"] == prefixed_sha256(body)


def test_adaptive_control_beats_fixed_order_under_the_same_caps() -> None:
    corpus = sealed_reference_holdouts()
    report = compare_selection_policies(
        corpus,
        controlled_adaptive_selection_traces(corpus),
    )

    assert report["budget_comparison"] == {
        "same_query_budget": True,
        "same_normalized_byte_budget": True,
    }
    assert report["candidate"]["accuracy_basis_points"] == 10_000
    assert report["baseline"]["accuracy_basis_points"] == 6_666
    assert report["adaptive_advantage_basis_points"] == 3_334
    assert report["recorded_model_output_evaluated"] is False
    assert report["recorded_model_advantage_basis_points"] is None
    assert report["checks"]["recorded_model_output_evaluated"] is False
    assert report["checks"]["measurable_candidate_advantage"] is False


def test_selection_input_is_blinded_and_bound_to_the_trace() -> None:
    corpus = sealed_reference_holdouts()
    case = next(case for case in corpus.cases if case.kind is CaseKind.RESOLVABLE)
    value = reference_selection_input(case)
    encoded = str(value)

    assert case.scenario_id not in encoded
    assert case.source_incident_class.value not in encoded
    assert case.mutation.value not in encoded
    body = {key: child for key, child in value.items() if key != "input_sha256"}
    assert value["input_sha256"] == prefixed_sha256(body)
    trace = next(
        trace
        for trace in controlled_adaptive_selection_traces(corpus)
        if trace.case_id == case.case_id
    )
    assert trace.selection_input_sha256 == value["input_sha256"]


def test_recorded_model_output_is_distinguished_from_controlled_policy() -> None:
    corpus = sealed_reference_holdouts()
    receipts, recorded, campaign = _recorded_campaign()
    report = compare_selection_policies(corpus, recorded)

    assert report["recorded_model_output_evaluated"] is True
    assert report["recorded_model_advantage_basis_points"] == 3_334
    assert report["candidate"]["source"] == "recorded-model-output"
    assert report["candidate"]["recorded_receipt_count"] == 60
    assert report["candidate"]["recorded_receipt_set_sha256"] == (receipts.receipt_set_sha256)
    assert report["checks"]["recorded_model_output_evaluated"] is True
    assert campaign["passed"] is True


def test_recorded_selection_requires_complete_verified_no_retry_receipts() -> None:
    corpus = sealed_reference_holdouts()
    model = _RecordedSelectionModel()
    receipts = asyncio.run(
        record_reference_model_selections(
            model=model,
            corpus=corpus,
            clock=lambda: datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
        )
    )

    assert len(model.calls) == 60
    assert all(call.evidence_tool is None for call in model.calls)
    document = receipts.to_dict()
    assert document["resolvable_case_count"] == 60
    assert all(receipt["attempt_count"] == 1 for receipt in document["receipts"])
    assert all(receipt["retry_count"] == 0 for receipt in document["receipts"])
    assert all(receipt["model_calls"] == 1 for receipt in document["receipts"])
    assert len(verified_recorded_selection_traces(corpus, receipts)) == 60

    with pytest.raises(
        ReferenceCampaignError,
        match="reference-recorded-selection-unverified",
    ):
        SelectionTrace(
            case_id=corpus.cases[0].case_id,
            policy_id="forged-recording",
            source="recorded-model-output",
            selected_query_keys=("metric.correlated-observations", "log.correlated-events"),
            selection_input_sha256=reference_selection_input(corpus.cases[0])["input_sha256"],
            provider_trace_id=_digest("forged-provider"),
        )


def test_recorded_selection_rejects_rehashed_response_binding_tamper() -> None:
    corpus = sealed_reference_holdouts()
    receipts, _traces, _campaign = _recorded_campaign()
    document = receipts.to_dict()
    receipt = document["receipts"][0]
    receipt["selected_query_key"] = (
        "trace.by-id"
        if receipt["selected_query_key"] == "log.correlated-events"
        else "log.correlated-events"
    )
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = prefixed_sha256(receipt_body)
    set_body = {key: value for key, value in document.items() if key != "receipt_set_sha256"}
    document["receipt_set_sha256"] = prefixed_sha256(set_body)

    imported = RecordedSelectionReceiptSet.from_mapping(document)
    with pytest.raises(
        ReferenceCampaignError,
        match="reference-recorded-selection-receipt-binding-invalid",
    ):
        verified_recorded_selection_traces(corpus, imported)


def test_selection_comparison_rejects_incomplete_and_over_budget_inputs() -> None:
    corpus = sealed_reference_holdouts()
    traces = controlled_adaptive_selection_traces(corpus)

    with pytest.raises(ReferenceCampaignError, match="reference-selection-traces-incomplete"):
        compare_selection_policies(corpus, traces[:-1])
    tiny_budget = SelectionBudget(max_normalized_bytes_per_case=1)
    with pytest.raises(ReferenceCampaignError, match="reference-selection-byte-budget-exceeded"):
        compare_selection_policies(
            corpus,
            controlled_adaptive_selection_traces(corpus, budget=tiny_budget),
            budget=tiny_budget,
        )


def test_impact_benchmark_proves_equivalence_integrity_and_avoided_work() -> None:
    campaign = _recorded_campaign()[2]
    observations = _benchmark_observations()

    report = build_reference_impact_benchmark(
        observations,
        campaign,
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("controlled-reference-receipts"),
    )

    assert report["passed"] is True
    assert report["evidence"] == {
        "source": "controlled-receipt-set",
        "evidence_set_id": _digest("controlled-reference-receipts"),
        "recorded_worker_evidence": False,
        "observation_count": 720,
    }
    assert report["metrics"]["median_compute_avoided_basis_points"] == 7_000
    assert report["metrics"]["median_application_bytes_avoided_basis_points"] > 4_000
    assert report["timing"]["informational_only"] is True
    assert report["timing"]["excluded_from_acceptance"] is True
    assert all(report["checks"].values())


def test_impact_benchmark_reports_scenario_overhead_without_hiding_median_savings() -> None:
    campaign = _recorded_campaign()[2]
    observations = tuple(
        replace(observation, operation_bytes_read=4_000)
        if observation.scenario_id == "tos-stale-derivative-cache-v1" and observation.affected
        else observation
        for observation in _benchmark_observations()
    )

    report = build_reference_impact_benchmark(
        observations,
        campaign,
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("overhead-reference-receipts"),
    )
    stale = next(
        result
        for result in report["scenario_results"]
        if result["scenario_id"] == "tos-stale-derivative-cache-v1"
    )

    assert stale["application_bytes_avoided_basis_points"] < 0
    assert report["metrics"]["median_application_bytes_avoided_basis_points"] > 4_000
    assert report["checks"]["median_application_bytes_avoided_at_least_40_percent"] is True
    assert report["passed"] is True


def test_impact_benchmark_detects_output_and_protected_mutations() -> None:
    campaign = _recorded_campaign()[2]
    observations = list(_benchmark_observations())
    protected_index = next(
        index for index, observation in enumerate(observations) if not observation.affected
    )
    observations[protected_index] = replace(
        observations[protected_index],
        preserved_after_output_sha256=_digest("mutated-protected-output"),
    )

    report = build_reference_impact_benchmark(
        observations,
        campaign,
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("mutated-reference-receipts"),
    )

    assert report["passed"] is False
    assert report["checks"]["output_equivalence"] is False
    assert report["checks"]["protected_output_integrity"] is False

    rendered_index = next(
        index
        for index, observation in enumerate(observations)
        if observation.selective_receipt is not None
    )
    rendered = observations[rendered_index]
    selective = dict(cast(dict[str, Any], rendered.selective_receipt))
    selective["dependencies"] = dict(cast(Mapping[str, str], selective["dependencies"]))
    selective["output_sha256"] = _digest("byte-different-but-pixel-equivalent")
    selective_body = {key: value for key, value in selective.items() if key != "receipt_sha256"}
    selective["receipt_sha256"] = prefixed_sha256(selective_body)
    observations[rendered_index] = replace(rendered, selective_receipt=selective)

    byte_mismatch = build_reference_impact_benchmark(
        observations,
        campaign,
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("byte-mismatched-reference-receipts"),
    )
    assert byte_mismatch["passed"] is False
    assert byte_mismatch["checks"]["output_equivalence"] is False


def test_impact_benchmark_rejects_incomplete_scope_and_tampered_receipts() -> None:
    campaign = _recorded_campaign()[2]
    observations = list(_benchmark_observations())

    with pytest.raises(ReferenceCampaignError, match="reference-benchmark-scope-invalid"):
        build_reference_impact_benchmark(
            observations[:-1],
            campaign,
            evidence_source="controlled-receipt-set",
            evidence_set_id=_digest("incomplete-reference-receipts"),
        )

    first = observations[0]
    tampered = dict(first.baseline_receipt)
    tampered["bytes_read"] += 1
    with pytest.raises(ReferenceCampaignError, match="reference-benchmark-receipt-digest-invalid"):
        replace(first, baseline_receipt=tampered)


def test_stale_cache_scenario_rerenders_affected_and_preserves_protected() -> None:
    stale = [
        observation
        for observation in _benchmark_observations()
        if observation.scenario_id == "tos-stale-derivative-cache-v1"
    ]
    affected = [observation for observation in stale if observation.affected]
    protected = [observation for observation in stale if not observation.affected]

    assert len(stale) == 240
    assert len(affected) == 72
    assert len(protected) == 168
    assert all(observation.selective_receipt is not None for observation in affected)
    assert all(observation.selective_receipt is None for observation in protected)
    assert all(
        observation.preserved_before_output_sha256 == observation.preserved_after_output_sha256
        for observation in protected
    )
