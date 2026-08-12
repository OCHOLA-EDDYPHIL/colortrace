from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import PyOpenColorIO as ocio
import pytest
from colortrace_fixture.fixture import (
    CANONICAL_SEED,
    COMPARISON_VERSION,
    FIXTURE_ID,
    FIXTURE_VERSION,
    OCIO_VERSION,
    PERMUTED_SEED,
    audit_bundle_paths,
    build_scenario,
    canonical_json_bytes,
    checked_relative_path,
    deterministic_tree_index,
    evaluate_scenario,
    read_json,
    run_isolated_validator,
    scan_oracle_leaks,
    sha256_file,
    validate_contract_instances,
)

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PACKAGE_ROOT / "src/colortrace_fixture/fixture.py"
PYTHON = Path(sys.executable)


@pytest.fixture(scope="session")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    root = tmp_path_factory.mktemp("fixtures")

    def create(name: str, *, seed: str, permuted: bool = False) -> dict[str, Any]:
        bundle = root / f"{name}-bundle"
        oracle_root = root / f"{name}-oracle"
        result = build_scenario(
            bundle,
            oracle_root=oracle_root,
            variant_id="hidden-a" if permuted else "canonical",
            seed=seed,
            permuted=permuted,
        )
        report = run_isolated_validator(SCRIPT, bundle, PYTHON)
        evaluation = evaluate_scenario(bundle, result["oracle"], report)["report"]
        return {
            "bundle": bundle,
            "oracle": result["oracle"],
            "report": report,
            "evaluation": evaluation,
        }

    return {
        "canonical": create("canonical", seed=CANONICAL_SEED),
        "replay": create("replay", seed=CANONICAL_SEED),
        "permuted": create("permuted", seed=PERMUTED_SEED, permuted=True),
    }


def manifests(bundle: Path, fixture: dict[str, Any]) -> list[dict[str, Any]]:
    return [read_json(bundle / item["manifest"]) for item in fixture["jobs"]]


def test_pinned_real_ocio_and_structural_resource_resolution(generated: dict[str, Any]) -> None:
    root = generated["canonical"]["bundle"]
    config_a = root / "runtime/workers/A/config/config.ocio"
    config_b = root / "runtime/workers/B/config/config.ocio"
    lut_a = root / "runtime/workers/A/config/luts/show_look.cube"
    lut_b = root / "runtime/workers/B/config/luts/show_look.cube"
    assert ocio.__version__ == OCIO_VERSION
    assert sha256_file(config_a) == sha256_file(config_b)
    assert sha256_file(lut_a) != sha256_file(lut_b)
    for config_path, expected_lut in ((config_a, lut_a), (config_b, lut_b)):
        config = ocio.Config.CreateFromFile(str(config_path))
        config.validate()
        resolved = Path(config.getCurrentContext().resolveFileLocation("show_look.cube"))
        assert resolved.resolve() == expected_lut.resolve()


def test_canonical_topology_correlation_lineage_and_distractor(generated: dict[str, Any]) -> None:
    root = generated["canonical"]["bundle"]
    fixture = read_json(root / "runtime/manifests/fixture-runtime-manifest.json")
    jobs = manifests(root, fixture)
    lineage = read_json(root / fixture["lineage"]["manifest"])
    telemetry = read_json(root / fixture["telemetry"]["manifest"])
    assert fixture["fixture_id"] == FIXTURE_ID
    assert fixture["fixture_version"] == FIXTURE_VERSION
    assert fixture["comparison_policy"] == COMPARISON_VERSION
    assert len(jobs) == 6
    assert sum(job["worker_id"] == "A" for job in jobs) == 2
    assert sum(job["worker_id"] == "B" for job in jobs) == 4
    assert all(job["process_outcome"] == "success" for job in jobs)
    assert all(job["run_id"] == fixture["run_id"] for job in jobs)
    assert all(re.fullmatch(r"[0-9a-f]{32}", job["trace_id"]) for job in jobs)
    assert all(int(job["trace_id"], 16) != 0 for job in jobs)
    render_edges = [edge for edge in lineage["edges"] if edge["edge_type"] == "source-to-render/v1"]
    derivative_edges = [
        edge for edge in lineage["edges"] if edge["edge_type"] == "lossless-derivative/v1"
    ]
    assert len(render_edges) == 6
    assert len(derivative_edges) == 1
    assert all("job_id" in edge and "correlation_id" in edge for edge in render_edges)
    assert telemetry["events"][0]["event_id"] == "distractor-01"
    assert set(telemetry["events"][0]["overlapping_job_ids"]) == {"job-b-01", "job-b-04"}


def test_comparison_report_is_observation_only_and_oracle_evaluation_passes(
    generated: dict[str, Any],
) -> None:
    report = generated["canonical"]["report"]
    evaluation = generated["canonical"]["evaluation"]
    assert {job["job_id"] for job in report["jobs"] if job["state"] == "reference_mismatch"} == {
        "job-b-01",
        "job-b-02",
        "job-b-03",
    }
    assert {job["job_id"] for job in report["jobs"] if job["state"] == "reference_match"} == {
        "job-a-01",
        "job-a-02",
        "job-b-04",
    }
    assert "cause" not in report
    assert "affected_jobs" not in report
    assert report["derivatives"][0]["state"] == "reference_mismatch"
    assert evaluation["pass"] is True
    assert evaluation["checks"]["rejected_causes"] == {
        "distractor": True,
        "nominal-config": True,
        "worker-alone": True,
    }


def test_full_same_seed_replay_and_complete_golden_map(generated: dict[str, Any]) -> None:
    canonical = generated["canonical"]
    replay = generated["replay"]
    subtrees = ("runtime", "references", "reports")
    canonical_index = deterministic_tree_index(canonical["bundle"], subtrees)
    replay_index = deterministic_tree_index(replay["bundle"], subtrees)
    assert canonical_index == replay_index
    assert "reports/landlock-receipt.json" not in canonical_index
    assert all("/tmp/" not in path and "pytest-" not in path for path in canonical_index)
    assert sha256_file(canonical["oracle"]) == sha256_file(replay["oracle"])

    golden = read_json(PACKAGE_ROOT / "fixtures/canonical-digests.json")
    source_pixels = {
        item["source_id"]: read_json(canonical["bundle"] / item["manifest"])[
            "canonical_pixel_sha256"
        ]
        for item in read_json(
            canonical["bundle"] / "runtime/manifests/fixture-runtime-manifest.json"
        )["sources"]
    }
    assert canonical_index == golden["files"]
    assert source_pixels == golden["source_pixel_sha256"]
    assert sha256_file(canonical["oracle"]) == golden["oracle_sha256"]
    assert (
        hashlib.sha256(canonical_json_bytes(canonical_index)).hexdigest() == golden["tree_sha256"]
    )


def test_permutation_removes_canonical_identities_but_preserves_rule(
    generated: dict[str, Any],
) -> None:
    canonical = generated["canonical"]
    permuted = generated["permuted"]
    canonical_fixture = read_json(
        canonical["bundle"] / "runtime/manifests/fixture-runtime-manifest.json"
    )
    permuted_fixture = read_json(
        permuted["bundle"] / "runtime/manifests/fixture-runtime-manifest.json"
    )
    canonical_jobs = manifests(canonical["bundle"], canonical_fixture)
    permuted_jobs = manifests(permuted["bundle"], permuted_fixture)
    assert {job["job_id"] for job in canonical_jobs}.isdisjoint(
        {job["job_id"] for job in permuted_jobs}
    )
    assert {job["worker_id"] for job in permuted_jobs}.isdisjoint({"A", "B"})
    assert {job["source_id"] for job in permuted_jobs}.isdisjoint(
        {"chart-01", "chart-02", "chart-03", "chart-04"}
    )
    assert [job["start_offset_seconds"] for job in canonical_jobs] != [
        job["start_offset_seconds"] for job in permuted_jobs
    ]
    assert sum(job["state"] == "reference_mismatch" for job in permuted["report"]["jobs"]) == 3
    assert sum(job["state"] == "reference_match" for job in permuted["report"]["jobs"]) == 3
    assert permuted["evaluation"]["pass"] is True


def test_missing_manifest_and_reference_are_unresolved(
    generated: dict[str, Any], tmp_path: Path
) -> None:
    case = generated["canonical"]
    root = tmp_path / "negative-bundle"
    shutil.copytree(case["bundle"], root)
    for path, job_id, reason in (
        (
            root / "runtime/manifests/resources/resource-job-b-02.json",
            "job-b-02",
            "missing-resolved-resource-manifest",
        ),
        (
            root / "references/manifests/reference-chart-03-look.json",
            "job-b-03",
            "missing-declared-reference",
        ),
    ):
        parent_mode = path.parent.stat().st_mode & 0o777
        path.parent.chmod(0o755)
        hidden = path.with_suffix(".hidden")
        path.rename(hidden)
        try:
            report = run_isolated_validator(SCRIPT, root, PYTHON)
            job = next(item for item in report["jobs"] if item["job_id"] == job_id)
            assert job["state"] == "unresolved"
            assert reason in job["reasons"]
        finally:
            hidden.rename(path)
            path.parent.chmod(parent_mode)


def test_landlock_oracle_and_mutability_boundary(generated: dict[str, Any]) -> None:
    case = generated["canonical"]
    root = case["bundle"]
    oracle_path = case["oracle"]
    assert not oracle_path.is_relative_to(root)
    assert not root.is_relative_to(oracle_path.parent)
    receipt = read_json(root / "reports/landlock-receipt.json")
    assert receipt["landlock_abi"] >= 1
    assert receipt["outside_bundle_read_denied"] is True
    assert receipt["runtime_inputs_read_only"] is True
    assert receipt["reports_write_scope"] is True
    invocation = read_json(root / "reports/validator-invocation-receipt.json")
    assert invocation["argv_contains_oracle_material"] is False
    assert invocation["environment_contains_oracle_material"] is False
    assert invocation["environment_keys"] == ["PATH", "PYTHONDONTWRITEBYTECODE"]
    assert all(
        (path.stat().st_mode & 0o222) == 0
        for path in (root / "runtime").rglob("*")
        if path.is_file()
    )
    assert all(
        (path.stat().st_mode & 0o222) == 0
        for path in (root / "references").rglob("*")
        if path.is_file()
    )
    oracle = read_json(oracle_path)
    assert scan_oracle_leaks(root, oracle_path, oracle)["pass"] is True
    bundle_text = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    for forbidden in (
        b"directly_affected_jobs",
        b"safe_jobs",
        b"causal_resource_sha256",
        b"shadowed_lut_sha256",
        b"fixture-oracle/v1",
    ):
        assert forbidden not in bundle_text


def test_path_policy_rejects_escape_symlink_hardlink_and_case_alias(
    generated: dict[str, Any], tmp_path: Path
) -> None:
    root = generated["canonical"]["bundle"]
    for value in ("../escape", "/absolute", "$EXPANDED/path", "nested/../escape"):
        with pytest.raises(ValueError, match="unsafe|escapes"):
            checked_relative_path(root, value)

    probe = tmp_path / "bundle"
    (probe / "runtime").mkdir(parents=True)
    (probe / "references").mkdir()
    (probe / "reports").mkdir()
    original = probe / "runtime/input.bin"
    original.write_bytes(b"input")
    original.chmod(0o444)
    symlink = probe / "runtime/link.bin"
    symlink.symlink_to(original)
    with pytest.raises(ValueError, match="symlink"):
        audit_bundle_paths(probe)
    symlink.unlink()
    hardlink = probe / "references/hard.bin"
    os.link(original, hardlink)
    with pytest.raises(ValueError, match="hard-linked|hard link"):
        audit_bundle_paths(probe)
    hardlink.unlink()
    case_alias = probe / "runtime/INPUT.bin"
    case_alias.write_bytes(b"other")
    case_alias.chmod(0o444)
    with pytest.raises(ValueError, match="case-alias"):
        audit_bundle_paths(probe)


def test_every_contract_instance_validates_against_checked_schema(
    generated: dict[str, Any],
) -> None:
    for case in generated.values():
        validate_contract_instances(case["bundle"], case["oracle"])


def test_per_asset_provenance_covers_runtime_and_references(generated: dict[str, Any]) -> None:
    root = generated["canonical"]["bundle"]
    provenance = read_json(root / "runtime/manifests/provenance.json")
    covered = {item["path"] for item in provenance["assets"] if "path" in item}
    actual = {
        path.relative_to(root).as_posix()
        for subtree in (root / "runtime", root / "references")
        for path in subtree.rglob("*")
        if path.is_file() and "manifests" not in path.parts
    }
    assert covered == actual
    assert all(item["license"] == "Apache-2.0" for item in provenance["assets"])
    assert provenance["proprietary_assets"] == []
    assert provenance["third_party"][0]["name"] == "OpenColorIO"
    assert provenance["third_party"][0]["version"] == "2.5.2"
    assert provenance["third_party"][0]["license"] == "BSD-3-Clause"
    notice = (PACKAGE_ROOT / "THIRD_PARTY_NOTICES").read_text(encoding="utf-8")
    assert "OpenColorIO 2.5.2" in notice
    assert "BSD 3-Clause" in notice


def test_canonical_json_rejects_floats() -> None:
    with pytest.raises(TypeError, match="manifest floats"):
        canonical_json_bytes({"value": 0.5})
    assert hashlib.sha256(canonical_json_bytes({"b": 2, "a": 1})).hexdigest() == (
        "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    )


def test_fixture_definition_is_small_generated_only_contract() -> None:
    definition = json.loads(
        (PACKAGE_ROOT / "fixtures/fixture-definition.json").read_text(encoding="utf-8")
    )
    assert definition["fixture_id"] == FIXTURE_ID
    assert definition["seed"] == CANONICAL_SEED
    assert len(definition["jobs"]) == 6
