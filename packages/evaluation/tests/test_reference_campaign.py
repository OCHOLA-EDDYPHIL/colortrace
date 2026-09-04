from __future__ import annotations

import asyncio
import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from functools import cache
from typing import Any, cast

import pytest
from colortrace_evaluation.contracts import prefixed_sha256
from colortrace_evaluation.reference_campaign import (
    RECORDED_SELECTION_MAXIMUM_RESPONSE_BYTES,
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
    verify_reference_campaign_report,
)
from colortrace_fixture import reference_scenarios
from colortrace_investigation import (
    RECORDED_REFERENCE_SELECTION_TURN_KIND,
    ModelCall,
    ModelFailure,
    ModelOutput,
)
from colortrace_validator import IncidentClass


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(child) for child in value]
    return value


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
            attributes["declared_reference.derivative_parent_matches_approved"] == "false"
            or attributes["declared_reference.derivative_generation_matches_approved"] == "false"
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


class _MixedRecordedSelectionModel(_RecordedSelectionModel):
    def __init__(self, journaled: list[dict[str, Any]]) -> None:
        super().__init__()
        self.journaled = journaled

    async def generate(self, call: ModelCall) -> ModelOutput:
        assert len(self.journaled) == len(self.calls)
        index = len(self.calls)
        if index == 3:
            self.calls.append(call)
            raise ModelFailure(
                "model-output-oversized",
                transient=False,
                input_tokens=700,
                output_tokens=128,
                model_calls=1,
                unobserved_model_calls=0,
                content=b"x" * 65_537,
                provider_request_id="provider-failed-request-04",
                provider_model_version="gemini-3.5-flash-20260904",
            )
        if index == 7:
            self.calls.append(call)
            raise ModelFailure(
                "transport",
                transient=True,
                input_tokens=None,
                output_tokens=None,
                model_calls=1,
                unobserved_model_calls=1,
            )
        output = await super().generate(call)
        response = json.loads(output.content)
        if index == 0:
            response["selection_input_sha256"] = _digest("model-echoed-wrong-case")
            return replace(
                output,
                content=json.dumps(response, separators=(",", ":"), sort_keys=True).encode(),
            )
        if index == 1:
            return replace(output, content=b'{"not":"finished"')
        if index == 2:
            raw = json.dumps(response, separators=(",", ":"), sort_keys=True).encode()
            return replace(
                output,
                content=raw + b" " * (RECORDED_SELECTION_MAXIMUM_RESPONSE_BYTES + 1 - len(raw)),
            )
        if index == 4:
            response["selected_query_key"] = "metric.not-permitted"
            return replace(
                output,
                content=json.dumps(response, separators=(",", ":"), sort_keys=True).encode(),
            )
        if index == 5:
            return replace(output, input_tokens=0)
        if index == 6:
            del response["schema"]
            return replace(
                output,
                content=json.dumps(response, separators=(",", ":"), sort_keys=True).encode(),
            )
        return output


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
    assert len(first.cases) == 99
    resolvable = [case for case in first.cases if case.kind is CaseKind.RESOLVABLE]
    assert Counter(case.source_incident_class for case in resolvable) == {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: 20,
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: 20,
        IncidentClass.STALE_DERIVATIVE_CACHE: 20,
    }
    assert Counter(
        case.source_incident_class for case in first.cases if case.kind is CaseKind.FAIL_CLOSED
    ) == {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: 13,
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: 13,
        IncidentClass.STALE_DERIVATIVE_CACHE: 13,
    }
    assert {case.mutation for case in first.cases if case.kind is CaseKind.FAIL_CLOSED} == {
        MutationKind.NO_EVIDENCE,
        MutationKind.ONE_SIGNAL,
        MutationKind.WRONG_SIGNAL_PAIR,
        MutationKind.MISSING_MATCH_FLAG,
        MutationKind.BASELINE_BINDING_MISMATCH,
        MutationKind.FLAG_DETAIL_CONTRADICTION,
        MutationKind.STALE_OBSERVATION,
        MutationKind.CROSS_RUN,
        MutationKind.CONFLICTING_EVENT,
        MutationKind.SCOPE_MISMATCH,
        MutationKind.MULTI_DIMENSION_DRIFT,
        MutationKind.APPROVED_CHANGE,
        MutationKind.MALFORMED_DIGEST,
    }


def test_campaign_meets_classification_authority_and_ablation_gates() -> None:
    report = run_reference_campaign()

    assert report["passed"] is False
    assert report["case_counts"] == {
        "total": 99,
        "resolvable": 60,
        "fail_closed": 39,
        "resolvable_by_class": {
            "resource-resolution-drift/v1": 20,
            "configuration-rollout-drift/v1": 20,
            "stale-derivative-cache/v1": 20,
        },
    }
    assert report["metrics"]["classification_accuracy_basis_points"] == 10_000
    assert report["metrics"]["negative_cases_failed_closed"] == 39
    assert report["metrics"]["false_action_intents"] == 0
    assert report["metrics"]["false_authorized_actions"] == 0
    assert report["metrics"]["display_text_mutations_resolved"] == 3
    assert report["checks"]["measurable_adaptive_advantage"] is False
    assert all(
        value for key, value in report["checks"].items() if key != "measurable_adaptive_advantage"
    )
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    assert report["report_sha256"] == prefixed_sha256(body)


def test_approved_change_controls_never_create_an_action_intent() -> None:
    controls = [
        result
        for result in run_reference_campaign()["case_results"]
        if result["mutation"] == MutationKind.APPROVED_CHANGE
    ]

    assert len(controls) == 3
    assert all(result["kind"] == CaseKind.FAIL_CLOSED for result in controls)
    assert all(result["status"] == "insufficient" for result in controls)
    assert all(result["incident_class"] is None for result in controls)
    assert all(result["action_intent_present"] is False for result in controls)
    assert all(result["authorizes_execution"] is False for result in controls)


@pytest.mark.parametrize(
    ("incident_class", "changed_fields"),
    (
        (IncidentClass.RESOURCE_RESOLUTION_DRIFT, {"resource_sha256"}),
        (
            IncidentClass.CONFIGURATION_ROLLOUT_DRIFT,
            {"config_sha256", "config_generation"},
        ),
        (
            IncidentClass.STALE_DERIVATIVE_CACHE,
            {"derivative_parent_sha256", "derivative_generation"},
        ),
    ),
)
def test_approved_change_controls_bind_authorized_state_transitions(
    incident_class: IncidentClass,
    changed_fields: set[str],
) -> None:
    case = next(
        item
        for item in sealed_reference_holdouts().cases
        if item.mutation is MutationKind.APPROVED_CHANGE
        and item.source_incident_class is incident_class
    )
    expected = _plain(case.expected_state)
    affected_job_id = cast(list[str], expected["scope"]["affected_job_ids"])[0]
    affected = [
        observation
        for observations in case.query_observations.values()
        for observation in observations
        if observation["job_id"] == affected_job_id
    ]
    safe = [
        observation
        for observations in case.query_observations.values()
        for observation in observations
        if observation["job_id"] != affected_job_id
    ]

    assert len(affected) == 2
    assert len(safe) == 2
    transitions = [
        _plain(observation["provenance"]["declared_reference_transition"])
        for observation in affected
    ]
    assert transitions[0] == transitions[1]
    transition = transitions[0]
    transition_body = {
        key: value for key, value in transition.items() if key != "transition_sha256"
    }
    assert transition["schema"] == "declared-reference-transition/v1"
    assert transition["transition_sha256"] == prefixed_sha256(transition_body)
    assert transition["prior_approved_state_sha256"] == prefixed_sha256(
        transition["prior_approved"]
    )
    assert transition["current_approved_state_sha256"] == prefixed_sha256(
        transition["current_approved"]
    )
    assert transition["current_approved"] == expected["approved"]
    assert set(transition["changed_fields"]) == changed_fields
    assert {
        key
        for key, value in transition["prior_approved"].items()
        if value != transition["current_approved"][key]
    } == changed_fields
    assert transition["scope"] == {
        "affected_job_ids": [affected_job_id],
        "affected_artifact_ids": [affected[0]["artifact_id"]],
    }
    assert transition["current_expected_state_id"] == expected["expected_state_id"]
    assert transition["current_expected_state_sha256"] == expected["expected_state_sha256"]
    assert transition["approval"] == {
        "role": "color-pipeline-supervisor",
        "status": "approved",
        "requested_at": "2026-09-04T11:55:00.000Z",
        "approved_at": "2026-09-04T11:58:00.000Z",
        "effective_at": "2026-09-04T12:00:00.000Z",
    }

    for observation in affected:
        attributes = _plain(observation["attributes"])
        provenance = _plain(observation["provenance"])
        if observation["signal"] == "metric":
            assert attributes["declared_reference.state"] == "reference_match"
            assert (
                attributes["declared_reference.approved_state_sha256"]
                == transition["current_approved_state_sha256"]
            )
            assert all(
                value == "true"
                for name, value in attributes.items()
                if name.startswith("declared_reference.") and name.endswith("_matches_approved")
            )
        elif observation["signal"] == "log":
            assert (
                attributes["runtime.effective_resource_sha256"]
                == expected["approved"]["resource_sha256"]
            )
            assert (
                attributes["runtime.effective_config_sha256"]
                == expected["approved"]["config_sha256"]
            )
            assert attributes["runtime.config_generation"] == str(
                expected["approved"]["config_generation"]
            )
            assert (
                attributes["runtime.frame_pipeline_sha256"]
                == expected["approved"]["frame_pipeline_sha256"]
            )
            assert attributes["cache.key"] == expected["approved"]["cache_key"]
        else:
            assert observation["signal"] == "trace"
            assert (
                attributes["runtime.frame_pipeline_sha256"]
                == expected["approved"]["frame_pipeline_sha256"]
            )
            assert (
                attributes["derivative.parent_sha256"]
                == expected["approved"]["derivative_parent_sha256"]
            )
            assert attributes["cache.generation"] == str(
                expected["approved"]["derivative_generation"]
            )
            assert attributes["cache.key"] == expected["approved"]["cache_key"]
        assert attributes["declared_reference.transition_sha256"] == transition["transition_sha256"]
        assert provenance["declared_reference_transition_sha256"] == transition["transition_sha256"]
        assert provenance["declared_reference_transition"] == transition
        evidence_sha256 = prefixed_sha256(
            {
                "event_id": observation["event_id"],
                "query_key": provenance["query_key"],
                "attributes": attributes,
            }
        )
        assert provenance["evidence_id"] == evidence_sha256
        assert provenance["event_sha256"] == evidence_sha256
        fact_body = {
            key: _plain(observation[key])
            for key in (
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
        }
        assert observation["fact_sha256"] == prefixed_sha256(fact_body)

    assert all(
        "declared_reference.transition_sha256" not in observation["attributes"]
        and "declared_reference_transition_sha256" not in observation["provenance"]
        and "declared_reference_transition" not in observation["provenance"]
        for observation in safe
    )


def test_legacy_no_causal_drift_control_remains_read_compatible() -> None:
    assert MutationKind("no-causal-drift") is MutationKind.NO_CAUSAL_DRIFT


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
    assert "mutation" not in value
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
    assert report["schema"] == "reference-policy-comparison/v2"
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


def test_recorded_selection_preserves_all_mixed_outcomes_and_fails_closed() -> None:
    corpus = sealed_reference_holdouts()
    journaled: list[dict[str, Any]] = []
    model = _MixedRecordedSelectionModel(journaled)
    receipts = asyncio.run(
        record_reference_model_selections(
            model=model,
            corpus=corpus,
            clock=lambda: datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
            receipt_callback=lambda receipt: journaled.append(_plain(receipt)),
        )
    )

    document = receipts.to_dict()
    assert len(model.calls) == 60
    assert len(journaled) == 60
    assert document["schema"] == "reference-recorded-model-selection-set/v2"
    assert document["maximum_response_bytes"] == 576
    assert document["maximum_failure_response_bytes"] == 1_048_576
    assert document["outcome_counts"] == {
        "accepted-query": 52,
        "domain-rejection": 6,
        "model-failure": 2,
    }
    assert journaled == document["receipts"]

    mismatch = document["receipts"][0]
    assert mismatch["outcome"] == "domain-rejection"
    assert mismatch["outcome_code"] == "input-binding-mismatch"
    assert mismatch["model_selection_input_sha256"] == _digest("model-echoed-wrong-case")
    assert mismatch["model_selection_input_matches_request"] is False
    assert mismatch["selection_input_sha256"] != mismatch["model_selection_input_sha256"]

    invalid_json = document["receipts"][1]
    assert invalid_json["outcome_code"] == "response-invalid-json"
    assert invalid_json["response_content"] == '{"not":"finished"'
    invalid_raw = invalid_json["response_content"].encode()
    assert invalid_json["response_byte_length"] == len(invalid_raw)
    assert invalid_json["response_sha256"] == (f"sha256:{hashlib.sha256(invalid_raw).hexdigest()}")

    oversize = document["receipts"][2]
    assert oversize["outcome_code"] == "response-oversize"
    assert oversize["response_byte_length"] == 577
    assert oversize["model_selection_input_matches_request"] is True
    failure = document["receipts"][3]
    assert failure["outcome"] == "model-failure"
    assert failure["model_failure_code"] == "model-output-oversized"
    assert failure["input_tokens"] == 700
    assert failure["output_tokens"] == 128
    assert failure["unobserved_model_calls"] == 0
    assert failure["response_content"] == "x" * 65_537
    assert failure["response_sha256"] == _digest("x" * 65_537)
    assert failure["response_byte_length"] == 65_537
    assert failure["provider_request_id"] == "provider-failed-request-04"
    assert failure["provider_model_version"] == "gemini-3.5-flash-20260904"
    assert document["receipts"][4]["outcome_code"] == "query-not-permitted"
    assert document["receipts"][5]["outcome_code"] == "invocation-invalid"
    assert document["receipts"][6]["outcome_code"] == "response-schema-invalid"
    unavailable_failure = document["receipts"][7]
    assert unavailable_failure["outcome"] == "model-failure"
    assert unavailable_failure["response_content"] is None
    assert unavailable_failure["response_sha256"] is None
    assert unavailable_failure["provider_request_id"] is None
    assert unavailable_failure["provider_model_version"] is None

    traces = verified_recorded_selection_traces(corpus, receipts)
    assert Counter(len(trace.selected_query_keys) for trace in traces) == {2: 52, 1: 8}
    comparison = compare_selection_policies(corpus, traces)
    rejected_case_ids = {
        receipt["case_id"]
        for receipt in document["receipts"]
        if receipt["outcome"] != "accepted-query"
    }
    rejected_results = [
        result
        for result in comparison["candidate"]["results"]
        if result["case_id"] in rejected_case_ids
    ]
    assert len(rejected_results) == 8
    assert all(result["resolved_correctly"] is False for result in rejected_results)
    assert all(result["status"] != "supported" for result in rejected_results)
    assert comparison["candidate"]["false_authorized_actions"] == 0

    tampered = receipts.to_dict()
    tampered_failure = next(
        receipt
        for receipt in tampered["receipts"]
        if receipt["outcome"] == "model-failure" and receipt["response_content"] is None
    )
    tampered_failure["unobserved_model_calls"] = 0
    failure_body = {
        key: value for key, value in tampered_failure.items() if key != "receipt_sha256"
    }
    tampered_failure["receipt_sha256"] = prefixed_sha256(failure_body)
    set_body = {key: value for key, value in tampered.items() if key != "receipt_set_sha256"}
    tampered["receipt_set_sha256"] = prefixed_sha256(set_body)
    with pytest.raises(
        ReferenceCampaignError,
        match="reference-recorded-selection-receipt-binding-invalid",
    ):
        verified_recorded_selection_traces(corpus, tampered)

    tampered = receipts.to_dict()
    observed_failure = next(
        receipt
        for receipt in tampered["receipts"]
        if receipt["outcome"] == "model-failure" and receipt["response_content"] is not None
    )
    observed_failure["response_content"] += " "
    failure_body = {
        key: value for key, value in observed_failure.items() if key != "receipt_sha256"
    }
    observed_failure["receipt_sha256"] = prefixed_sha256(failure_body)
    set_body = {key: value for key, value in tampered.items() if key != "receipt_set_sha256"}
    tampered["receipt_set_sha256"] = prefixed_sha256(set_body)
    with pytest.raises(
        ReferenceCampaignError,
        match="reference-recorded-selection-receipt-binding-invalid",
    ):
        verified_recorded_selection_traces(corpus, tampered)


@pytest.mark.parametrize(
    "field",
    ("request_content", "response_content", "response_byte_length", "outcome"),
)
def test_recorded_selection_v2_recomputes_attempt_bindings(field: str) -> None:
    corpus = sealed_reference_holdouts()
    receipts, _traces, _campaign = _recorded_campaign()
    document = receipts.to_dict()
    receipt = document["receipts"][0]
    if field == "request_content":
        receipt[field] += " "
    elif field == "response_content":
        receipt[field] += " "
    elif field == "response_byte_length":
        receipt[field] += 1
    else:
        receipt[field] = "domain-rejection"
        document["outcome_counts"]["accepted-query"] -= 1
        document["outcome_counts"]["domain-rejection"] += 1
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


def test_recorded_selection_v1_receipt_set_remains_read_compatible() -> None:
    corpus = sealed_reference_holdouts()
    current, _traces, _campaign = _recorded_campaign()
    current_document = current.to_dict()
    receipt_fields = (
        "corpus_id",
        "corpus_sha256",
        "resolvable_case_set_sha256",
        "case_id",
        "case_sha256",
        "selection_input_sha256",
        "request_content",
        "request_sha256",
        "response_schema_sha256",
        "response_content",
        "response_sha256",
        "selected_query_key",
        "provider",
        "model",
        "location",
        "model_profile_sha256",
        "prompt_version",
        "prompt_sha256",
        "provider_request_id",
        "provider_model_version",
        "input_tokens",
        "output_tokens",
        "model_calls",
        "attempt_count",
        "retry_count",
        "recorded_at",
    )
    legacy_receipts: list[dict[str, Any]] = []
    for current_receipt in current_document["receipts"]:
        body = {
            "schema": "reference-recorded-model-selection-receipt/v1",
            **{field: current_receipt[field] for field in receipt_fields},
        }
        legacy_receipts.append({**body, "receipt_sha256": prefixed_sha256(body)})
    legacy_body = {
        "schema": "reference-recorded-model-selection-set/v1",
        "corpus_id": current_document["corpus_id"],
        "corpus_sha256": current_document["corpus_sha256"],
        "resolvable_case_count": current_document["resolvable_case_count"],
        "resolvable_case_set_sha256": current_document["resolvable_case_set_sha256"],
        "budget": current_document["budget"],
        "model_profile": current_document["model_profile"],
        "model_profile_sha256": current_document["model_profile_sha256"],
        "response_schema_sha256": current_document["response_schema_sha256"],
        "receipts": legacy_receipts,
    }
    legacy = RecordedSelectionReceiptSet.from_mapping(
        {**legacy_body, "receipt_set_sha256": prefixed_sha256(legacy_body)}
    )

    traces = verified_recorded_selection_traces(corpus, legacy)
    assert len(traces) == 60
    assert all(len(trace.selected_query_keys) == 2 for trace in traces)
    assert all(trace.policy_id == "gemini-recorded-selection-v1" for trace in traces)


def test_recorded_selection_preserves_then_rejects_invalid_model_call_count() -> None:
    class RetriedSelectionModel(_RecordedSelectionModel):
        async def generate(self, call: ModelCall) -> ModelOutput:
            output = await super().generate(call)
            return replace(output, model_calls=2) if len(self.calls) == 1 else output

    corpus = sealed_reference_holdouts()
    journaled: list[dict[str, Any]] = []
    model = RetriedSelectionModel()
    receipts = asyncio.run(
        record_reference_model_selections(
            model=model,
            corpus=corpus,
            clock=lambda: datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
            receipt_callback=lambda receipt: journaled.append(_plain(receipt)),
        )
    )

    assert len(model.calls) == 60
    assert len(journaled) == 60
    assert journaled[0]["model_calls"] == 2
    assert journaled[0]["outcome_code"] == "invocation-invalid"
    with pytest.raises(
        ReferenceCampaignError,
        match="reference-recorded-selection-receipt-binding-invalid",
    ):
        verified_recorded_selection_traces(corpus, receipts)


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


@pytest.mark.parametrize("field", ("metrics", "passed", "advantage"))
def test_campaign_verification_rejects_resigned_summary_tamper(field: str) -> None:
    receipts, _traces, campaign = _recorded_campaign()
    tampered = deepcopy(campaign)
    if field == "metrics":
        tampered["metrics"]["classification_accuracy_basis_points"] = 9_999
    elif field == "passed":
        tampered["passed"] = False
    else:
        comparison = tampered["selection_comparison"]
        comparison["adaptive_advantage_basis_points"] = 3_333
        comparison["recorded_model_advantage_basis_points"] = 3_333
        comparison_body = {
            key: value for key, value in comparison.items() if key != "report_sha256"
        }
        comparison["report_sha256"] = prefixed_sha256(comparison_body)
    body = {key: value for key, value in tampered.items() if key != "report_sha256"}
    tampered["report_sha256"] = prefixed_sha256(body)

    with pytest.raises(
        ReferenceCampaignError,
        match="reference-campaign-report-recomputation-mismatch",
    ):
        verify_reference_campaign_report(tampered, receipt_set=receipts)


def test_campaign_verification_requires_receipts_for_recorded_model_claim() -> None:
    _receipts, _traces, campaign = _recorded_campaign()

    with pytest.raises(
        ReferenceCampaignError,
        match="reference-campaign-receipts-required",
    ):
        verify_reference_campaign_report(campaign)
    with pytest.raises(
        ReferenceCampaignError,
        match="reference-campaign-receipts-required",
    ):
        build_reference_impact_benchmark(
            _benchmark_observations(),
            campaign,
            evidence_source="controlled-receipt-set",
            evidence_set_id=_digest("unverified-campaign"),
        )


def test_public_impact_builder_cannot_assert_recorded_worker_evidence() -> None:
    receipts, _traces, campaign = _recorded_campaign()

    with pytest.raises(
        ReferenceCampaignError,
        match="reference-benchmark-recorded-evidence-unverified",
    ):
        build_reference_impact_benchmark(
            _benchmark_observations(),
            campaign,
            evidence_source="recorded-worker-receipts",
            evidence_set_id=_digest("self-reported-worker-evidence"),
            campaign_receipt_set=receipts,
        )


@pytest.mark.parametrize("binding", ("corpus", "case"))
def test_campaign_verification_rejects_resigned_receipt_binding(binding: str) -> None:
    receipts, _traces, campaign = _recorded_campaign()
    document = receipts.to_dict()
    if binding == "corpus":
        wrong = _digest("wrong-holdout-corpus")
        document["corpus_sha256"] = wrong
        for receipt in document["receipts"]:
            receipt["corpus_sha256"] = wrong
            receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            receipt["receipt_sha256"] = prefixed_sha256(receipt_body)
    else:
        receipt = document["receipts"][0]
        receipt["case_sha256"] = _digest("wrong-holdout-case")
        receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        receipt["receipt_sha256"] = prefixed_sha256(receipt_body)
    set_body = {key: value for key, value in document.items() if key != "receipt_set_sha256"}
    document["receipt_set_sha256"] = prefixed_sha256(set_body)

    with pytest.raises(ReferenceCampaignError, match="reference-recorded-selection-.*binding"):
        verify_reference_campaign_report(campaign, receipt_set=document)


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

    one_query = tuple(
        SelectionTrace(
            case_id=trace.case_id,
            policy_id="gemini-recorded-selection-v2",
            source="controlled-policy",
            selected_query_keys=("metric.correlated-observations",),
            selection_input_sha256=trace.selection_input_sha256,
        )
        for trace in traces
    )
    with pytest.raises(
        ReferenceCampaignError,
        match="reference-selection-query-budget-exceeded",
    ):
        compare_selection_policies(corpus, one_query)


def test_impact_benchmark_proves_equivalence_integrity_and_avoided_work() -> None:
    receipts, _traces, campaign = _recorded_campaign()
    observations = _benchmark_observations()

    report = build_reference_impact_benchmark(
        observations,
        campaign,
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("controlled-reference-receipts"),
        campaign_receipt_set=receipts,
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
    receipts, _traces, campaign = _recorded_campaign()
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
        campaign_receipt_set=receipts,
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
    receipts, _traces, campaign = _recorded_campaign()
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
        campaign_receipt_set=receipts,
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
        campaign_receipt_set=receipts,
    )
    assert byte_mismatch["passed"] is False
    assert byte_mismatch["checks"]["output_equivalence"] is False


def test_impact_benchmark_rejects_incomplete_scope_and_tampered_receipts() -> None:
    receipts, _traces, campaign = _recorded_campaign()
    observations = list(_benchmark_observations())

    with pytest.raises(ReferenceCampaignError, match="reference-benchmark-scope-invalid"):
        build_reference_impact_benchmark(
            observations[:-1],
            campaign,
            evidence_source="controlled-receipt-set",
            evidence_set_id=_digest("incomplete-reference-receipts"),
            campaign_receipt_set=receipts,
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
