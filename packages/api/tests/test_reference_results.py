from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from colortrace_api.reference_demo import ReferenceDemoCatalog
from colortrace_api.reference_results import (
    ReferenceResultError,
    load_reference_impact_result,
)
from colortrace_fixture import load_reference_media_manifest

COLLECTION_ID = "tears-of-steel-linear-exr-240-v1"
MANIFEST_SHA256 = "sha256:" + "a" * 64
DIGEST = "sha256:" + "f" * 64


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _signed_savings(actual: int, baseline: int) -> int:
    return (baseline - actual) * 10_000 // baseline


def _resign(result: dict[str, Any]) -> None:
    body = {key: value for key, value in result.items() if key != "report_sha256"}
    result["report_sha256"] = f"sha256:{hashlib.sha256(_canonical(body)).hexdigest()}"


def _result() -> dict[str, Any]:
    scenario_classes = {
        "tos-config-rollout-drift-v1": "configuration-rollout-drift/v1",
        "tos-resource-resolution-drift-v1": "resource-resolution-drift/v1",
        "tos-stale-derivative-cache-v1": "stale-derivative-cache/v1",
    }
    identity = {
        "mode": "host-python-module",
        "source_revision": "d" * 40,
        "source_tree": "e" * 40,
        "container_image_digest": None,
    }
    body: dict[str, Any] = {
        "schema": "reference-impact-benchmark/v3",
        "reference_collection_id": COLLECTION_ID,
        "reference_manifest_sha256": MANIFEST_SHA256,
        "campaign_report_sha256": "sha256:" + "b" * 64,
        "evidence": {
            "source": "recorded-worker-receipts",
            "evidence_set_id": "sha256:" + "c" * 64,
            "recorded_worker_evidence": True,
            "observation_count": 720,
            "execution_identity": {
                **identity,
                "identity_sha256": (f"sha256:{hashlib.sha256(_canonical(identity)).hexdigest()}"),
            },
        },
        "campaign_summary": {
            "case_counts": {
                "total": 99,
                "resolvable": 60,
                "fail_closed": 39,
                "resolvable_by_class": {
                    "configuration-rollout-drift/v1": 20,
                    "resource-resolution-drift/v1": 20,
                    "stale-derivative-cache/v1": 20,
                },
            },
            "metrics": {
                "correct_resolvable_classifications": 60,
                "classification_accuracy_basis_points": 10_000,
                "negative_cases_failed_closed": 39,
                "false_action_intents": 0,
                "false_authorized_actions": 0,
                "display_text_mutations_resolved": 3,
                "display_text_mutation_count": 3,
            },
        },
        "thresholds": {
            "minimum_classification_accuracy_basis_points": 9_500,
            "minimum_median_compute_avoided_basis_points": 4_000,
            "minimum_median_application_bytes_avoided_basis_points": 4_000,
            "maximum_false_authorized_actions": 0,
        },
        "metrics": {
            "classification_accuracy_basis_points": 10_000,
            "false_authorized_actions": 0,
            "median_compute_avoided_basis_points": 7_000,
            "median_application_bytes_avoided_basis_points": 4_500,
        },
        "timing": {
            "informational_only": True,
            "excluded_from_acceptance": True,
            "baseline_cpu_nanoseconds": 4,
            "baseline_wall_nanoseconds": 5,
            "selective_cpu_nanoseconds": 2,
            "selective_wall_nanoseconds": 3,
        },
        "scenario_results": [
            {
                "scenario_id": scenario_id,
                "incident_class": incident_class,
                "artifact_count": 240,
                "affected_artifact_count": 72,
                "protected_artifact_count": 168,
                "baseline": {"pixel_work": 1_000, "application_bytes": 2_000},
                "selective": {"pixel_work": 300, "application_bytes": 1_100},
                "compute_avoided_basis_points": 7_000,
                "application_bytes_avoided_basis_points": 4_500,
                "output_equivalence": True,
                "protected_output_integrity": True,
            }
            for scenario_id, incident_class in scenario_classes.items()
        ],
        "checks": {
            "balanced_resolvable_classes": True,
            "classification_at_least_95_percent": True,
            "all_negative_cases_fail_closed": True,
            "display_text_cannot_change_authority": True,
            "zero_false_action_intents": True,
            "zero_false_authorized_actions": True,
            "output_equivalence": True,
            "protected_output_integrity": True,
            "median_compute_avoided_at_least_40_percent": True,
            "median_application_bytes_avoided_at_least_40_percent": True,
        },
        "passed": True,
    }
    stale = next(
        item
        for item in body["scenario_results"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    )
    stale["baseline"]["application_bytes"] = 2_001
    stale["selective"]["application_bytes"] = 2_201
    stale["application_bytes_avoided_basis_points"] = _signed_savings(2_201, 2_001)
    result = dict(body)
    _resign(result)
    return result


def _write(path: Path, result: dict[str, Any]) -> None:
    path.write_bytes(_canonical(result) + b"\n")


def _savings_only_failure() -> dict[str, Any]:
    result = _result()
    for scenario in result["scenario_results"]:
        if scenario["scenario_id"] == "tos-stale-derivative-cache-v1":
            continue
        scenario["selective"]["application_bytes"] = 1_300
        scenario["application_bytes_avoided_basis_points"] = 3_500
    result["metrics"]["median_application_bytes_avoided_basis_points"] = 3_500
    result["checks"]["median_application_bytes_avoided_at_least_40_percent"] = False
    result["passed"] = False
    _resign(result)
    return result


def test_recorded_impact_result_is_strictly_bound_and_defensively_copied(
    tmp_path: Path,
) -> None:
    path = tmp_path / "result.json"
    _write(path, _result())

    first = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )
    first["passed"] = False
    second = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )

    assert second["passed"] is True
    assert second["evidence"]["recorded_worker_evidence"] is True
    assert second["schema"] == "reference-impact-benchmark/v3"
    assert second["metrics"]["median_compute_avoided_basis_points"] == 7_000
    assert "model_comparison_research" not in second


def test_v3_product_result_preserves_only_release_acceptance_evidence(tmp_path: Path) -> None:
    path = tmp_path / "result.json"
    _write(path, _result())

    loaded = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )

    assert loaded["passed"] is True
    assert all(loaded["checks"].values())
    assert loaded["metrics"] == {
        "classification_accuracy_basis_points": 10_000,
        "false_authorized_actions": 0,
        "median_compute_avoided_basis_points": 7_000,
        "median_application_bytes_avoided_basis_points": 4_500,
    }
    assert "model_comparison_research" not in loaded


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["checks"].update({"all_negative_cases_fail_closed": False}),
        lambda value: value["checks"].update({"display_text_cannot_change_authority": False}),
        lambda value: value["checks"].update({"zero_false_action_intents": False}),
        lambda value: value["campaign_summary"]["metrics"].update({"false_action_intents": 1}),
        lambda value: (
            value["campaign_summary"]["case_counts"]["resolvable_by_class"].update(
                {
                    "configuration-rollout-drift/v1": 19,
                    "resource-resolution-drift/v1": 20,
                    "stale-derivative-cache/v1": 21,
                }
            ),
            value["checks"].update({"balanced_resolvable_classes": False}),
            value.update({"passed": False}),
        ),
        lambda value: value["evidence"]["execution_identity"].update({"source_revision": "f" * 40}),
    ),
)
def test_v3_result_rejects_resigned_acceptance_misrepresentation(
    tmp_path: Path,
    mutation: Any,
) -> None:
    result = _result()
    mutation(result)
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


@pytest.mark.parametrize(
    "legacy_schema",
    ("reference-impact-benchmark/v1", "reference-impact-benchmark/v2"),
)
def test_result_rejects_resigned_legacy_schema(tmp_path: Path, legacy_schema: str) -> None:
    result = _result()
    result["schema"] = legacy_schema
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.update({"model_comparison_research": {}}),
        lambda value: value["metrics"].update({"adaptive_advantage_basis_points": 1}),
        lambda value: value["metrics"].update({"recorded_model_advantage_basis_points": 1}),
        lambda value: value["checks"].update({"same_selection_budgets": True}),
        lambda value: value["checks"].update({"measurable_adaptive_advantage": True}),
    ),
)
def test_v3_result_rejects_resigned_comparison_fields(
    tmp_path: Path,
    mutation: Any,
) -> None:
    result = _result()
    mutation(result)
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


@pytest.mark.parametrize(
    ("mode", "image_digest"),
    (
        ("host-python-module", None),
        ("container", DIGEST),
        ("google-cloud-batch", DIGEST),
    ),
)
def test_v3_result_accepts_canonical_recorded_worker_execution_modes(
    tmp_path: Path,
    mode: str,
    image_digest: str | None,
) -> None:
    result = _result()
    identity = result["evidence"]["execution_identity"]
    identity.update({"mode": mode, "container_image_digest": image_digest})
    identity_body = {key: value for key, value in identity.items() if key != "identity_sha256"}
    identity["identity_sha256"] = f"sha256:{hashlib.sha256(_canonical(identity_body)).hexdigest()}"
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    loaded = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )

    assert loaded["evidence"]["execution_identity"]["mode"] == mode


def test_recorded_result_accepts_signed_stale_cache_bytes_without_weakening_median_gate(
    tmp_path: Path,
) -> None:
    result = _result()
    stale = next(
        item
        for item in result["scenario_results"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    )
    path = tmp_path / "result.json"
    _write(path, result)

    loaded = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )

    loaded_stale = next(
        item
        for item in loaded["scenario_results"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    )
    assert stale["selective"]["application_bytes"] > stale["baseline"]["application_bytes"]
    assert stale["application_bytes_avoided_basis_points"] == -1_000
    assert loaded_stale == stale
    assert loaded["metrics"]["median_application_bytes_avoided_basis_points"] == 4_500
    assert loaded["checks"]["median_application_bytes_avoided_at_least_40_percent"] is True


def test_recorded_result_accepts_savings_below_negative_ten_thousand(
    tmp_path: Path,
) -> None:
    result = _result()
    stale = next(
        item
        for item in result["scenario_results"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    )
    stale["baseline"]["application_bytes"] = 2_000
    stale["selective"]["application_bytes"] = 5_000
    stale["application_bytes_avoided_basis_points"] = -15_000
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    loaded = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )

    loaded_stale = next(
        item
        for item in loaded["scenario_results"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    )
    assert loaded_stale["application_bytes_avoided_basis_points"] == -15_000


def test_recorded_result_accepts_internally_consistent_savings_only_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "result.json"
    _write(path, _savings_only_failure())

    loaded = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )

    assert loaded["passed"] is False
    assert loaded["metrics"]["median_application_bytes_avoided_basis_points"] == 3_500
    assert loaded["checks"] == {
        "balanced_resolvable_classes": True,
        "classification_at_least_95_percent": True,
        "all_negative_cases_fail_closed": True,
        "display_text_cannot_change_authority": True,
        "zero_false_action_intents": True,
        "zero_false_authorized_actions": True,
        "output_equivalence": True,
        "protected_output_integrity": True,
        "median_compute_avoided_at_least_40_percent": True,
        "median_application_bytes_avoided_at_least_40_percent": False,
    }


def test_recorded_result_accepts_consistent_negative_median_savings_failure(
    tmp_path: Path,
) -> None:
    result = _result()
    for scenario in result["scenario_results"]:
        scenario["selective"]["application_bytes"] = 5_000
        scenario["application_bytes_avoided_basis_points"] = _signed_savings(
            5_000,
            scenario["baseline"]["application_bytes"],
        )
    result["metrics"]["median_application_bytes_avoided_basis_points"] = -15_000
    result["checks"]["median_application_bytes_avoided_at_least_40_percent"] = False
    result["passed"] = False
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    loaded = load_reference_impact_result(
        expected_collection_id=COLLECTION_ID,
        expected_manifest_sha256=MANIFEST_SHA256,
        path=path,
    )

    assert loaded["passed"] is False
    assert loaded["metrics"]["median_application_bytes_avoided_basis_points"] == -15_000


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["checks"].update(
            {"median_application_bytes_avoided_at_least_40_percent": True}
        ),
        lambda value: value.update({"passed": True}),
    ),
)
def test_recorded_result_rejects_resigned_savings_failure_inconsistency(
    tmp_path: Path,
    mutation: Any,
) -> None:
    result = _savings_only_failure()
    mutation(result)
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


def test_recorded_result_rejects_false_outcome_when_every_check_passes(
    tmp_path: Path,
) -> None:
    result = _result()
    result["passed"] = False
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["scenario_results"][0].update({"output_equivalence": False}),
        lambda value: value["scenario_results"][0].update({"protected_output_integrity": False}),
        lambda value: value["metrics"].update({"false_authorized_actions": 1}),
        lambda value: value["metrics"].update({"classification_accuracy_basis_points": 9_499}),
        lambda value: value["campaign_summary"]["metrics"].update(
            {"display_text_mutations_resolved": 2}
        ),
    ),
)
def test_recorded_result_rejects_resigned_derived_check_mismatch(
    tmp_path: Path,
    mutation: Any,
) -> None:
    result = _result()
    mutation(result)
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


def test_catalog_reports_consistent_failed_result_as_recorded(tmp_path: Path) -> None:
    manifest = load_reference_media_manifest()
    result = _savings_only_failure()
    result["reference_collection_id"] = manifest.collection_id
    result["reference_manifest_sha256"] = manifest.manifest_sha256
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    suite = ReferenceDemoCatalog(benchmark_result_path=path).benchmark_suite()

    assert suite["result_state"] == "recorded"
    assert suite["result"]["passed"] is False
    assert suite["measurement_boundary"]["catalog_claims_observed_savings"] is True


def test_recorded_result_rejects_resigned_signed_savings_tamper(tmp_path: Path) -> None:
    result = _result()
    stale = next(
        item
        for item in result["scenario_results"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    )
    stale["application_bytes_avoided_basis_points"] += 1
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


@pytest.mark.parametrize(
    "metric",
    (
        "median_compute_avoided_basis_points",
        "median_application_bytes_avoided_basis_points",
    ),
)
def test_recorded_result_rejects_resigned_summary_median_tamper(
    tmp_path: Path,
    metric: str,
) -> None:
    result = _result()
    result["metrics"][metric] += 1
    _resign(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["evidence"].update({"source": "controlled-receipt-set"}),
        lambda value: value["metrics"].update({"median_compute_avoided_basis_points": None}),
        lambda value: value["checks"].update({"output_equivalence": False}),
        lambda value: value["scenario_results"][0].update({"protected_output_integrity": False}),
        lambda value: value.update({"report_sha256": "sha256:" + "0" * 64}),
    ),
)
def test_result_rejects_unrecorded_failed_or_tampered_claims(
    tmp_path: Path,
    mutation: Any,
) -> None:
    result = _result()
    mutation(result)
    path = tmp_path / "result.json"
    _write(path, result)

    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=path,
        )


def test_result_rejects_symlink_and_noncanonical_json(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    _write(target, _result())
    link = tmp_path / "result.json"
    link.symlink_to(target)
    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=link,
        )

    target.write_text(json.dumps(_result(), indent=2), encoding="utf-8")
    with pytest.raises(ReferenceResultError, match="reference-result-invalid"):
        load_reference_impact_result(
            expected_collection_id=COLLECTION_ID,
            expected_manifest_sha256=MANIFEST_SHA256,
            path=target,
        )
