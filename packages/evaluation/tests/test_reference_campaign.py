from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from typing import Any, cast

import pytest
from colortrace_evaluation.contracts import ContractError, prefixed_sha256, validate_schema
from colortrace_evaluation.reference_campaign import (
    BenchmarkArtifactObservation,
    CaseKind,
    MutationKind,
    ReferenceCampaignError,
    build_reference_impact_benchmark,
    run_reference_campaign,
    sealed_reference_holdouts,
    verify_reference_campaign_report,
)
from colortrace_fixture import reference_scenarios
from colortrace_validator import IncidentClass


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(child) for child in value]
    return value


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

    assert report["passed"] is True
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
    assert report["schema"] == "reference-campaign-report/v2"
    assert "selection_comparison" not in report
    assert all(report["checks"].values())
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


def test_campaign_verification_rejects_resigned_summary_tamper() -> None:
    campaign = run_reference_campaign()
    tampered = deepcopy(campaign)
    tampered["metrics"]["classification_accuracy_basis_points"] = 9_999
    body = {key: value for key, value in tampered.items() if key != "report_sha256"}
    tampered["report_sha256"] = prefixed_sha256(body)

    with pytest.raises(
        ReferenceCampaignError,
        match="reference-campaign-report-recomputation-mismatch",
    ):
        verify_reference_campaign_report(tampered)


def test_public_impact_builder_cannot_assert_recorded_worker_evidence() -> None:
    with pytest.raises(
        ReferenceCampaignError,
        match="reference-benchmark-recorded-evidence-unverified",
    ):
        build_reference_impact_benchmark(
            _benchmark_observations(),
            run_reference_campaign(),
            evidence_source="recorded-worker-receipts",
            evidence_set_id=_digest("self-reported-worker-evidence"),
        )


def test_impact_benchmark_proves_equivalence_integrity_and_avoided_work() -> None:
    campaign = run_reference_campaign()
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
        "execution_identity": None,
    }
    assert report["metrics"]["median_compute_avoided_basis_points"] == 7_000
    assert report["metrics"]["median_application_bytes_avoided_basis_points"] > 4_000
    assert report["timing"]["informational_only"] is True
    assert report["timing"]["excluded_from_acceptance"] is True
    assert all(report["checks"].values())


def test_impact_benchmark_contains_only_acceptance_dimensions() -> None:
    campaign = run_reference_campaign()

    assert campaign["passed"] is True
    assert "selection_comparison" not in campaign
    report = build_reference_impact_benchmark(
        _benchmark_observations(),
        campaign,
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("controlled-reference-receipts-with-negative-research"),
    )

    assert report["passed"] is True
    assert report["schema"] == "reference-impact-benchmark/v3"
    assert all(report["checks"].values())
    assert "model_comparison_research" not in report


@pytest.mark.parametrize("mode", ("container", "google-cloud-batch"))
def test_impact_benchmark_schema_accepts_canonical_image_execution_modes(mode: str) -> None:
    report = build_reference_impact_benchmark(
        _benchmark_observations(),
        run_reference_campaign(),
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("controlled-reference-receipts"),
    )
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    body["evidence"] = {
        "source": "recorded-worker-receipts",
        "evidence_set_id": _digest("recorded-reference-receipts"),
        "recorded_worker_evidence": True,
        "observation_count": 720,
        "execution_identity": {
            "mode": mode,
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "container_image_digest": _digest("image"),
            "identity_sha256": _digest("identity"),
        },
    }
    candidate = {**body, "report_sha256": prefixed_sha256(body)}

    validate_schema("reference-impact-benchmark-v3.schema.json", candidate)


@pytest.mark.parametrize(
    ("source", "recorded", "identity"),
    (
        (
            "controlled-receipt-set",
            True,
            {
                "mode": "host-python-module",
                "source_revision": "1" * 40,
                "source_tree": "2" * 40,
                "container_image_digest": None,
                "identity_sha256": _digest("identity"),
            },
        ),
        ("recorded-worker-receipts", False, None),
    ),
)
def test_impact_benchmark_schema_binds_evidence_source_to_attestation(
    source: str,
    recorded: bool,
    identity: Mapping[str, Any] | None,
) -> None:
    report = build_reference_impact_benchmark(
        _benchmark_observations(),
        run_reference_campaign(),
        evidence_source="controlled-receipt-set",
        evidence_set_id=_digest("controlled-reference-receipts"),
    )
    candidate = deepcopy(report)
    candidate["evidence"].update(
        {
            "source": source,
            "recorded_worker_evidence": recorded,
            "execution_identity": identity,
        }
    )

    with pytest.raises(ContractError, match="schema-invalid"):
        validate_schema("reference-impact-benchmark-v3.schema.json", candidate)


def test_impact_benchmark_reports_scenario_overhead_without_hiding_median_savings() -> None:
    campaign = run_reference_campaign()
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
    campaign = run_reference_campaign()
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
    campaign = run_reference_campaign()
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
