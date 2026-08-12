from __future__ import annotations

import copy
import importlib.metadata
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from colortrace_fixture.fixture import (
    CANONICAL_SEED,
    PERMUTED_SEED,
    SCHEMA_FILES,
    build_scenario,
    canonical_json_bytes,
    finalize_bundle_inputs,
    read_json,
    sha256_bytes,
    sha256_file,
)
from colortrace_validator.validator import (
    MAX_RESULT_BYTES,
    REASON_CODES,
    SCHEMA_ROOT,
    VALIDATOR_VERSION,
    build_request,
    classify_reference_metrics,
    validate_color_state,
    validate_result_contract,
)
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]


@pytest.fixture(scope="session")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Path]]:
    root = tmp_path_factory.mktemp("color-state-validator")
    definitions = {
        "canonical": {
            "variant_id": "canonical",
            "seed": CANONICAL_SEED,
        },
        "permuted": {
            "variant_id": "hidden-permuted",
            "seed": PERMUTED_SEED,
            "permuted": True,
        },
        "missing-resource": {
            "variant_id": "missing-resource",
            "seed": CANONICAL_SEED,
            "omit_resource_role": "b2",
        },
        "missing-reference": {
            "variant_id": "missing-reference",
            "seed": CANONICAL_SEED,
            "omit_reference_role": "b3",
        },
    }
    cases: dict[str, dict[str, Path]] = {}
    for name, kwargs in definitions.items():
        bundle = root / f"{name}-bundle"
        oracle_root = root / f"{name}-offline-truth"
        built = build_scenario(bundle, oracle_root=oracle_root, **kwargs)
        cases[name] = {"bundle": bundle, "oracle": built["oracle"]}
    return cases


def _write_json(path: Path, document: dict[str, Any]) -> str:
    encoded = canonical_json_bytes(document)
    path.write_bytes(encoded)
    return sha256_bytes(encoded)


def _make_writable(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        path.chmod(0o755 if path.is_dir() else 0o644)


def _clone_bundle(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    _make_writable(destination)
    return destination


def _runtime_manifest(bundle: Path) -> tuple[Path, dict[str, Any]]:
    path = bundle / "runtime/manifests/fixture-runtime-manifest.json"
    return path, read_json(path)


def _seal(bundle: Path) -> None:
    finalize_bundle_inputs(bundle)


def _run_cli(case: dict[str, Path], output_root: Path) -> tuple[dict[str, Any], float]:
    request = build_request(
        case["bundle"], request_id="request-validation", incident_id="incident-validation"
    )
    request_path = output_root / "request.json"
    result_path = output_root / "result.json"
    output_root.mkdir(parents=True, exist_ok=True)
    _write_json(request_path, request)
    command = [
        sys.executable,
        "-m",
        "colortrace_validator",
        "validate",
        "--bundle",
        str(case["bundle"]),
        "--request",
        str(request_path),
        "--output",
        str(result_path),
    ]
    assert all("offline-truth" not in value for value in command)
    oracle_root = case["oracle"].parent
    oracle_root.chmod(0o000)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=20,
            env={
                "PATH": os.environ.get("PATH", ""),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    finally:
        elapsed = time.monotonic() - started
        oracle_root.chmod(0o700)
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    assert completed.stdout == b""
    assert result_path.stat().st_size <= MAX_RESULT_BYTES
    result = read_json(result_path)
    validate_result_contract(result)
    return result, elapsed


@pytest.mark.parametrize("case_name", ["canonical", "permuted"])
def test_external_oracle_matches_only_after_validator_exit(
    generated: dict[str, dict[str, Path]], tmp_path: Path, case_name: str
) -> None:
    case = generated[case_name]
    result, elapsed = _run_cli(case, tmp_path / case_name)
    assert elapsed < 20
    oracle = read_json(case["oracle"])
    frames = result["scope"]["frames"]
    assert result["status"] == "resolved"
    assert {item["job_id"] for item in frames if item["state"] == "affected"} == set(
        oracle["directly_affected_jobs"]
    )
    assert {item["job_id"] for item in frames if item["state"] == "safe"} == set(
        oracle["safe_jobs"]
    )
    assert {
        item["artifact_id"]
        for item in result["scope"]["derivatives"]
        if item["state"] == "affected"
    } == set(oracle["affected_derivatives"])
    causal = next(item for item in result["claims"] if item["claim_type"] == "causal-resource")
    assert causal["state"] == "confirmed"
    assert causal["subject"]["value"] == oracle["causal_resource_sha256"]
    rejected = {item["claim_type"] for item in result["claims"] if item["state"] == "rejected"}
    assert rejected == {"nominal-config", "worker-alone", "distractor"}


def test_comparison_scope_and_claim_states_are_distinct_and_citable(
    generated: dict[str, dict[str, Path]],
) -> None:
    case = generated["canonical"]
    request = build_request(
        case["bundle"], request_id="request-states", incident_id="incident-states"
    )
    result = validate_color_state(case["bundle"], request)
    validate_result_contract(result)
    assert {item["state"] for item in result["comparisons"]} == {
        "reference_match",
        "reference_mismatch",
    }
    assert {item["state"] for item in result["scope"]["frames"]} == {"affected", "safe"}
    assert {item["state"] for item in result["claims"]} == {"confirmed", "rejected"}
    mismatch_workers = {
        item["worker_id"] for item in result["comparisons"] if item["state"] == "reference_mismatch"
    }
    assert any(
        item["worker_id"] in mismatch_workers and item["state"] == "safe"
        for item in result["scope"]["frames"]
    )
    cited = {item["evidence_id"] for item in result["evidence"]}
    assert all(set(item["evidence_ids"]) <= cited for item in result["claims"])
    assert all(set(item["contradiction_links"]) <= cited for item in result["claims"])
    assert all(
        item["deterministic_result_evidence_id"]
        == f"deterministic-result:{item['derivation_sha256']}"
        for item in result["claims"]
    )
    assert all(set(item["evidence_ids"]) <= cited for item in result["comparisons"])
    fixture = read_json(case["bundle"] / "runtime/manifests/fixture-runtime-manifest.json")
    telemetry = read_json(case["bundle"] / fixture["telemetry"]["manifest"])
    distractor = next(item for item in result["claims"] if item["claim_type"] == "distractor")
    comparisons_by_job = {item["job_id"]: item for item in result["comparisons"]}
    assert {
        evidence_id
        for job_id in telemetry["events"][0]["overlapping_job_ids"]
        for evidence_id in comparisons_by_job[job_id]["evidence_ids"]
    } <= set(distractor["evidence_ids"])
    derivative = result["scope"]["derivatives"][0]
    parent_comparison = next(
        item
        for item in result["comparisons"]
        if item["output_id"] == derivative["parent_artifact_id"]
    )
    assert set(parent_comparison["evidence_ids"]) <= set(derivative["evidence_ids"])


@pytest.mark.parametrize("case_name", ["missing-resource", "missing-reference"])
def test_missing_decisive_inputs_remain_unknown_and_unresolved(
    generated: dict[str, dict[str, Path]], tmp_path: Path, case_name: str
) -> None:
    case = generated[case_name]
    result, _elapsed = _run_cli(case, tmp_path / case_name)
    oracle = read_json(case["oracle"])
    expected_unknown = set(oracle["expected_unresolved_jobs"])
    assert result["status"] == "unresolved"
    assert {
        item["job_id"] for item in result["comparisons"] if item["state"] == "unresolved"
    } == expected_unknown
    assert expected_unknown <= {
        item["job_id"] for item in result["scope"]["frames"] if item["state"] == "unknown"
    }
    causal = next(item for item in result["claims"] if item["claim_type"] == "causal-resource")
    assert causal["state"] == "unresolved"
    assert causal["subject"]["value"] is None


def test_content_addressed_resource_contradiction_is_unresolved(
    generated: dict[str, dict[str, Path]], tmp_path: Path
) -> None:
    source = generated["canonical"]["bundle"]
    original_request = build_request(source, request_id="original", incident_id="contradiction")
    original = validate_color_state(source, original_request)
    target_id = next(
        item["job_id"] for item in original["comparisons"] if item["state"] == "reference_mismatch"
    )
    bundle = _clone_bundle(source, tmp_path / "resource-contradiction")
    runtime_path, runtime = _runtime_manifest(bundle)
    pointer = next(item for item in runtime["jobs"] if item["job_id"] == target_id)
    job_path = bundle / pointer["manifest"]
    job = read_json(job_path)
    resource_path = bundle / job["resource_manifest"]
    resource = read_json(resource_path)
    resource["ordered_resources"][0]["sha256"] = "0" * 64
    job["resource_manifest_sha256"] = _write_json(resource_path, resource)
    pointer["sha256"] = _write_json(job_path, job)
    _write_json(runtime_path, runtime)
    _seal(bundle)
    request = build_request(bundle, request_id="contradictory", incident_id="contradiction")
    result = validate_color_state(bundle, request)
    assert result["status"] == "unresolved"
    comparison = next(item for item in result["comparisons"] if item["job_id"] == target_id)
    assert comparison["state"] == "unresolved"
    assert "resolved-resource-digest-mismatch" in comparison["reason_codes"]
    assert result["scope"]["state"] == "unresolved"


def test_malformed_and_conflicting_telemetry_fail_closed(
    generated: dict[str, dict[str, Path]], tmp_path: Path
) -> None:
    for name, mutate in (
        ("malformed", lambda event: event.__setitem__("overlapping_job_ids", None)),
        ("wrong-worker", lambda event: event.__setitem__("worker_id", "conflicting-worker")),
    ):
        bundle = _clone_bundle(generated["canonical"]["bundle"], tmp_path / name)
        runtime_path, runtime = _runtime_manifest(bundle)
        telemetry_path = bundle / runtime["telemetry"]["manifest"]
        telemetry = read_json(telemetry_path)
        mutate(telemetry["events"][0])
        runtime["telemetry"]["sha256"] = _write_json(telemetry_path, telemetry)
        _write_json(runtime_path, runtime)
        _seal(bundle)
        request = build_request(bundle, request_id=f"request-{name}", incident_id="telemetry")
        result = validate_color_state(bundle, request)
        validate_result_contract(result)
        assert result["status"] == "unresolved"
        if name == "malformed":
            assert "telemetry-contract-invalid" in result["reason_codes"]
        else:
            distractor = next(
                item for item in result["claims"] if item["claim_type"] == "distractor"
            )
            assert distractor["state"] == "unresolved"
            assert "contradictory-authoritative-evidence" in distractor["reason_codes"]


def test_duplicate_lineage_edges_and_escaping_paths_fail_closed(
    generated: dict[str, dict[str, Path]], tmp_path: Path
) -> None:
    lineage_bundle = _clone_bundle(
        generated["canonical"]["bundle"], tmp_path / "lineage-contradiction"
    )
    runtime_path, runtime = _runtime_manifest(lineage_bundle)
    lineage_path = lineage_bundle / runtime["lineage"]["manifest"]
    lineage = read_json(lineage_path)
    render_edge = next(
        edge for edge in lineage["edges"] if edge["edge_type"] == "source-to-render/v1"
    )
    derivative_edge = next(
        edge for edge in lineage["edges"] if edge["edge_type"] == "lossless-derivative/v1"
    )
    lineage["edges"] = [copy.deepcopy(render_edge) for _ in range(6)] + [derivative_edge]
    runtime["lineage"]["sha256"] = _write_json(lineage_path, lineage)
    _write_json(runtime_path, runtime)
    _seal(lineage_bundle)
    lineage_request = build_request(
        lineage_bundle, request_id="duplicate-lineage", incident_id="lineage"
    )
    lineage_result = validate_color_state(lineage_bundle, lineage_request)
    assert lineage_result["scope"]["state"] == "unresolved"
    assert "exact-lineage-invalid" in lineage_result["scope"]["reason_codes"]

    path_bundle = _clone_bundle(generated["canonical"]["bundle"], tmp_path / "path-escape")
    runtime_path, runtime = _runtime_manifest(path_bundle)
    job_path = path_bundle / runtime["jobs"][0]["manifest"]
    job = read_json(job_path)
    job["resource_manifest"] = "../outside.json"
    runtime["jobs"][0]["sha256"] = _write_json(job_path, job)
    _write_json(runtime_path, runtime)
    _seal(path_bundle)
    path_request = build_request(path_bundle, request_id="escape", incident_id="path")
    path_result = validate_color_state(path_bundle, path_request)
    assert path_result["status"] == "unresolved"
    assert path_result["reason_codes"] == ["unsafe-path"]


def test_exact_tolerance_boundaries() -> None:
    assert (
        classify_reference_metrics(
            maximum_absolute_channel_error=0.000001,
            rmse=0.0000005,
            fraction_pixels_at_or_above_0_02=0.0,
            nearest_rank_p95=0.0,
        )
        == "reference_match"
    )
    assert (
        classify_reference_metrics(
            maximum_absolute_channel_error=0.000001000001,
            rmse=0.0000005,
            fraction_pixels_at_or_above_0_02=0.0,
            nearest_rank_p95=0.0,
        )
        == "unresolved"
    )
    assert (
        classify_reference_metrics(
            maximum_absolute_channel_error=0.04,
            rmse=0.01,
            fraction_pixels_at_or_above_0_02=0.10,
            nearest_rank_p95=0.04,
        )
        == "reference_mismatch"
    )
    assert (
        classify_reference_metrics(
            maximum_absolute_channel_error=0.04,
            rmse=0.01,
            fraction_pixels_at_or_above_0_02=0.099999,
            nearest_rank_p95=0.04,
        )
        == "unresolved"
    )


def test_replay_schema_registry_and_bounded_surface(generated: dict[str, dict[str, Path]]) -> None:
    case = generated["canonical"]
    request = build_request(case["bundle"], request_id="replay", incident_id="replay")
    first = validate_color_state(case["bundle"], request)
    second = validate_color_state(case["bundle"], request)
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert len(canonical_json_bytes(first)) <= MAX_RESULT_BYTES
    validate_result_contract(first)
    assert importlib.metadata.version("colortrace-validator") == VALIDATOR_VERSION
    reason_schema = read_json(SCHEMA_ROOT / "validation-reason-code-v1.schema.json")
    assert set(reason_schema["enum"]) == REASON_CODES
    assert {"fixture-telemetry/v1", "declared-approved-resources/v1"} <= set(SCHEMA_FILES)
    for schema_path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        Draft202012Validator.check_schema(read_json(schema_path))


def test_no_canonical_shortcut_or_external_runtime_surface() -> None:
    source = (Path(__file__).parents[1] / "src/colortrace_validator/validator.py").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "job-b-01",
        "artifact-b-02-derivative",
        "d249b3ecf486a773aeb16cc195550454019ec5b71adb6006bfb9d15a62453e48",
        "fixture-oracle/v1",
        "evaluate_scenario",
        "Grafana",
        "socket",
        "requests",
        "urllib",
    ):
        assert forbidden not in source
    assert sha256_file(Path(__file__))
