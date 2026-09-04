from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any, cast

REFERENCE_RESULT_PATH = (
    Path(__file__).with_name("reference_results") / "reference-impact-benchmark.json"
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_MAXIMUM_RESULT_BYTES = 128 * 1024
_SCENARIO_CLASSES = {
    "tos-config-rollout-drift-v1": "configuration-rollout-drift/v1",
    "tos-resource-resolution-drift-v1": "resource-resolution-drift/v1",
    "tos-stale-derivative-cache-v1": "stale-derivative-cache/v1",
}
_ROOT_KEYS = frozenset(
    {
        "schema",
        "reference_collection_id",
        "reference_manifest_sha256",
        "campaign_report_sha256",
        "evidence",
        "thresholds",
        "metrics",
        "timing",
        "scenario_results",
        "checks",
        "passed",
        "report_sha256",
    }
)
_METRIC_KEYS = frozenset(
    {
        "classification_accuracy_basis_points",
        "false_authorized_actions",
        "adaptive_advantage_basis_points",
        "recorded_model_advantage_basis_points",
        "median_compute_avoided_basis_points",
        "median_application_bytes_avoided_basis_points",
    }
)
_CHECK_KEYS = frozenset(
    {
        "campaign_acceptance_passed",
        "output_equivalence",
        "protected_output_integrity",
        "zero_false_authorized_actions",
        "classification_at_least_95_percent",
        "same_selection_budgets",
        "measurable_adaptive_advantage",
        "median_compute_avoided_at_least_40_percent",
        "median_application_bytes_avoided_at_least_40_percent",
    }
)
_SCENARIO_RESULT_KEYS = frozenset(
    {
        "scenario_id",
        "incident_class",
        "artifact_count",
        "affected_artifact_count",
        "protected_artifact_count",
        "baseline",
        "selective",
        "compute_avoided_basis_points",
        "application_bytes_avoided_basis_points",
        "output_equivalence",
        "protected_output_integrity",
    }
)


class ReferenceResultError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


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


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _mapping(value: Any, *, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReferenceResultError("reference-result-invalid")
    return cast(dict[str, Any], value)


def _integer(
    value: Any,
    *,
    minimum: int | None = 0,
    maximum: int | None = None,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or (minimum is not None and value < minimum)
        or (maximum is not None and value > maximum)
    ):
        raise ReferenceResultError("reference-result-invalid")
    return value


def _work(value: Any) -> dict[str, int]:
    selected = _mapping(value, keys=frozenset({"pixel_work", "application_bytes"}))
    return {
        "pixel_work": _integer(selected["pixel_work"]),
        "application_bytes": _integer(selected["application_bytes"]),
    }


def _validate_scenario_results(value: Any) -> tuple[int, int, bool, bool]:
    if not isinstance(value, list) or len(value) != len(_SCENARIO_CLASSES):
        raise ReferenceResultError("reference-result-invalid")
    scenario_ids: list[str] = []
    compute_avoided_values: list[int] = []
    application_bytes_avoided_values: list[int] = []
    output_equivalence_values: list[bool] = []
    protected_output_integrity_values: list[bool] = []
    for raw in value:
        result = _mapping(raw, keys=_SCENARIO_RESULT_KEYS)
        scenario_id = result.get("scenario_id")
        output_equivalence = result.get("output_equivalence")
        protected_output_integrity = result.get("protected_output_integrity")
        if (
            not isinstance(scenario_id, str)
            or result.get("incident_class") != _SCENARIO_CLASSES.get(scenario_id)
            or _integer(result.get("artifact_count")) != 240
            or _integer(result.get("affected_artifact_count")) != 72
            or _integer(result.get("protected_artifact_count")) != 168
            or not isinstance(output_equivalence, bool)
            or not isinstance(protected_output_integrity, bool)
        ):
            raise ReferenceResultError("reference-result-invalid")
        baseline = _work(result["baseline"])
        selective = _work(result["selective"])
        for work_key, savings_key in (
            ("pixel_work", "compute_avoided_basis_points"),
            ("application_bytes", "application_bytes_avoided_basis_points"),
        ):
            baseline_value = baseline[work_key]
            selective_value = selective[work_key]
            if baseline_value < 1:
                raise ReferenceResultError("reference-result-invalid")
            expected = (baseline_value - selective_value) * 10_000 // baseline_value
            measured = _integer(result[savings_key], minimum=None, maximum=10_000)
            if measured != expected:
                raise ReferenceResultError("reference-result-invalid")
            if savings_key == "compute_avoided_basis_points":
                compute_avoided_values.append(measured)
            else:
                application_bytes_avoided_values.append(measured)
        scenario_ids.append(scenario_id)
        output_equivalence_values.append(output_equivalence)
        protected_output_integrity_values.append(protected_output_integrity)
    if scenario_ids != sorted(_SCENARIO_CLASSES):
        raise ReferenceResultError("reference-result-invalid")
    return (
        sorted(compute_avoided_values)[1],
        sorted(application_bytes_avoided_values)[1],
        all(output_equivalence_values),
        all(protected_output_integrity_values),
    )


def _validate_result(
    result: dict[str, Any],
    *,
    expected_collection_id: str,
    expected_manifest_sha256: str,
) -> None:
    if (
        result.get("schema") != "reference-impact-benchmark/v1"
        or result.get("reference_collection_id") != expected_collection_id
        or result.get("reference_manifest_sha256") != expected_manifest_sha256
        or not isinstance(result.get("campaign_report_sha256"), str)
        or _DIGEST.fullmatch(result["campaign_report_sha256"]) is None
        or not isinstance(result.get("passed"), bool)
    ):
        raise ReferenceResultError("reference-result-invalid")

    evidence = _mapping(
        result.get("evidence"),
        keys=frozenset(
            {"source", "evidence_set_id", "recorded_worker_evidence", "observation_count"}
        ),
    )
    if (
        evidence.get("source") != "recorded-worker-receipts"
        or evidence.get("recorded_worker_evidence") is not True
        or _integer(evidence.get("observation_count")) != 720
        or not isinstance(evidence.get("evidence_set_id"), str)
        or _DIGEST.fullmatch(evidence["evidence_set_id"]) is None
    ):
        raise ReferenceResultError("reference-result-invalid")

    thresholds = _mapping(
        result.get("thresholds"),
        keys=frozenset(
            {
                "minimum_classification_accuracy_basis_points",
                "minimum_median_compute_avoided_basis_points",
                "minimum_median_application_bytes_avoided_basis_points",
                "maximum_false_authorized_actions",
            }
        ),
    )
    if thresholds != {
        "minimum_classification_accuracy_basis_points": 9_500,
        "minimum_median_compute_avoided_basis_points": 4_000,
        "minimum_median_application_bytes_avoided_basis_points": 4_000,
        "maximum_false_authorized_actions": 0,
    }:
        raise ReferenceResultError("reference-result-invalid")

    metrics = _mapping(result.get("metrics"), keys=_METRIC_KEYS)
    classification = _integer(metrics.get("classification_accuracy_basis_points"), maximum=10_000)
    false_actions = _integer(metrics.get("false_authorized_actions"))
    adaptive_advantage = _integer(
        metrics.get("adaptive_advantage_basis_points"),
        minimum=-10_000,
        maximum=10_000,
    )
    recorded_advantage = _integer(
        metrics.get("recorded_model_advantage_basis_points"),
        minimum=-10_000,
        maximum=10_000,
    )
    compute_avoided = _integer(
        metrics.get("median_compute_avoided_basis_points"),
        minimum=None,
        maximum=10_000,
    )
    bytes_avoided = _integer(
        metrics.get("median_application_bytes_avoided_basis_points"),
        minimum=None,
        maximum=10_000,
    )
    if adaptive_advantage != recorded_advantage:
        raise ReferenceResultError("reference-result-invalid")

    timing = _mapping(
        result.get("timing"),
        keys=frozenset(
            {
                "informational_only",
                "excluded_from_acceptance",
                "baseline_cpu_nanoseconds",
                "baseline_wall_nanoseconds",
                "selective_cpu_nanoseconds",
                "selective_wall_nanoseconds",
            }
        ),
    )
    if (
        timing.get("informational_only") is not True
        or timing.get("excluded_from_acceptance") is not True
    ):
        raise ReferenceResultError("reference-result-invalid")
    for key in (
        "baseline_cpu_nanoseconds",
        "baseline_wall_nanoseconds",
        "selective_cpu_nanoseconds",
        "selective_wall_nanoseconds",
    ):
        _integer(timing[key])

    checks = _mapping(result.get("checks"), keys=_CHECK_KEYS)
    if any(not isinstance(value, bool) for value in checks.values()):
        raise ReferenceResultError("reference-result-invalid")
    (
        scenario_compute_avoided,
        scenario_bytes_avoided,
        output_equivalence,
        protected_output_integrity,
    ) = _validate_scenario_results(result.get("scenario_results"))
    if compute_avoided != scenario_compute_avoided or bytes_avoided != scenario_bytes_avoided:
        raise ReferenceResultError("reference-result-invalid")
    derived_checks = {
        "output_equivalence": output_equivalence,
        "protected_output_integrity": protected_output_integrity,
        "zero_false_authorized_actions": false_actions == 0,
        "classification_at_least_95_percent": classification >= 9_500,
        "measurable_adaptive_advantage": recorded_advantage >= 1,
        "median_compute_avoided_at_least_40_percent": compute_avoided >= 4_000,
        "median_application_bytes_avoided_at_least_40_percent": bytes_avoided >= 4_000,
    }
    if any(checks[key] is not expected for key, expected in derived_checks.items()) or result[
        "passed"
    ] is not all(checks.values()):
        raise ReferenceResultError("reference-result-invalid")

    report_sha256 = result.get("report_sha256")
    body = {key: value for key, value in result.items() if key != "report_sha256"}
    if not isinstance(report_sha256, str) or report_sha256 != _digest(body):
        raise ReferenceResultError("reference-result-invalid")


def load_reference_impact_result(
    *,
    expected_collection_id: str,
    expected_manifest_sha256: str,
    path: Path = REFERENCE_RESULT_PATH,
) -> dict[str, Any]:
    if (
        _IDENTIFIER.fullmatch(expected_collection_id) is None
        or _DIGEST.fullmatch(expected_manifest_sha256) is None
    ):
        raise ReferenceResultError("reference-result-binding-invalid")
    try:
        metadata = path.lstat()
        content = path.read_bytes()
        result = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_float=lambda _value: (_ for _ in ()).throw(ValueError("floating point")),
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise ReferenceResultError("reference-result-unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 1 <= len(content) <= _MAXIMUM_RESULT_BYTES
        or not isinstance(result, dict)
        or set(result) != _ROOT_KEYS
        or content != _canonical_json(result) + b"\n"
    ):
        raise ReferenceResultError("reference-result-invalid")
    selected = cast(dict[str, Any], result)
    _validate_result(
        selected,
        expected_collection_id=expected_collection_id,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    return cast(dict[str, Any], json.loads(_canonical_json(selected)))


__all__ = [
    "REFERENCE_RESULT_PATH",
    "ReferenceResultError",
    "load_reference_impact_result",
]
