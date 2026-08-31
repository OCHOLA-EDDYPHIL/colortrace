from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tomllib
import zipfile
from importlib import resources
from pathlib import Path
from typing import Any

import colortrace_fixture.fixture as fixture_module
import PyOpenColorIO as ocio
import pytest
from colortrace_fixture.fixture import (
    CANONICAL_SEED,
    COMPARISON_VERSION,
    FIXTURE_ID,
    FIXTURE_VERSION,
    FROZEN_CHART2_GENERATION_PATH,
    FROZEN_CHART2_GENERATION_SHA256,
    FROZEN_CHART2_PATH,
    FROZEN_CHART2_SHA256,
    FROZEN_PLATE_VERSION,
    GENERATED_CHART_VERSION,
    OCIO_VERSION,
    PERMUTED_SEED,
    SOURCE_PIXEL_BYTE_LENGTH,
    SOURCE_PIXEL_MAGIC,
    SOURCE_SET_VERSION,
    audit_bundle_paths,
    build_scenario,
    canonical_json_bytes,
    checked_relative_path,
    deterministic_tree_index,
    evaluate_scenario,
    load_frozen_chart2_samples,
    read_json,
    run_canonical_build_validator,
    run_isolated_validator,
    scan_oracle_leaks,
    sha256_file,
    source_pixel_bytes,
    validate_contract_document,
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


def canonical_build_input(
    generated: dict[str, Any], tmp_path: Path
) -> tuple[Path, tuple[Path, Path]]:
    root = tmp_path / "colortrace-fixture-a"
    shutil.copytree(generated["canonical"]["bundle"], root)
    reports = root / "reports"
    for name in (
        "landlock-receipt.json",
        "validator-invocation-receipt.json",
        "validator-receipt.json",
        "validator-report.json",
    ):
        (reports / name).unlink(missing_ok=True)
    shutil.rmtree(reports / "diffs", ignore_errors=True)
    return root, (
        tmp_path / "colortrace-oracle-a",
        tmp_path / "colortrace-oracle-b",
    )


def test_frozen_chart2_record_schema_candidates_selection_and_gates() -> None:
    generation = read_json(FROZEN_CHART2_GENERATION_PATH)
    validate_contract_document(generation)
    candidates = generation["candidates"]
    assert len(candidates) == 3
    assert [candidate["index"] for candidate in candidates] == [1, 2, 3]
    assert len({candidate["seed"] for candidate in candidates}) == 3
    assert len({candidate["raw_png_sha256"] for candidate in candidates}) == 3
    assert len({candidate["canonical_rgb16be_sha256"] for candidate in candidates}) == 3
    selected = [candidate for candidate in candidates if candidate["selected"]]
    assert len(selected) == 1
    assert selected[0]["index"] == generation["selection"]["selected_candidate_index"] == 1
    assert selected[0]["canonical_rgb16be_sha256"] == FROZEN_CHART2_SHA256
    assert generation["selection"]["asset"]["sha256"] == FROZEN_CHART2_SHA256
    assert generation["selection"]["visual_approval"] == {
        "approved": True,
        "authority": "project-owner",
        "decided_on": "2026-08-31",
    }
    assert generation["selection"]["license_decision"] == {
        "approved": True,
        "authority": "project-owner",
        "license": "Apache-2.0",
        "decided_on": "2026-08-31",
    }
    assert generation["terms_review"]["unique_output_guaranteed"] is False
    assert generation["terms_review"]["approved_for_apache_2_0_inclusion"] is True
    assert generation["seed_semantics"] == "best-effort-preview-not-reproducibility-guarantee"
    assert all(candidate["c2pa_chunk_present"] is True for candidate in candidates)
    for text_key, digest_key in (
        ("text", "sha256"),
        ("effective_text", "effective_sha256"),
        ("visual_exclusions", "visual_exclusions_sha256"),
    ):
        assert (
            hashlib.sha256(generation["prompt"][text_key].encode()).hexdigest()
            == generation["prompt"][digest_key]
        )


def test_frozen_chart2_asset_header_hash_and_rgb8_promotion() -> None:
    data = FROZEN_CHART2_PATH.read_bytes()
    samples = load_frozen_chart2_samples()
    assert len(data) == SOURCE_PIXEL_BYTE_LENGTH == 884751
    assert data[:8] == struct.pack(">II", 512, 288)
    assert data[8:15] == SOURCE_PIXEL_MAGIC
    assert hashlib.sha256(data).hexdigest() == FROZEN_CHART2_SHA256
    assert len(samples) == 512 * 288 * 3
    assert all(sample % 257 == 0 for sample in samples)
    assert source_pixel_bytes(samples) == data


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("prompt-hash", "text hash mismatch"),
        ("duplicate-seed", "unique seed"),
        ("selected-index", "selected candidate index mismatch"),
        ("second-selection", "schema validation failed"),
        ("visual-approval", "schema validation failed"),
        ("license-decision", "schema validation failed"),
        ("shadow-metrics", "color metrics fail policy"),
    ],
)
def test_frozen_chart2_record_loader_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str, message: str
) -> None:
    generation = read_json(FROZEN_CHART2_GENERATION_PATH)
    if mutation == "prompt-hash":
        generation["prompt"]["sha256"] = "0" * 64
    elif mutation == "duplicate-seed":
        generation["candidates"][1]["seed"] = generation["candidates"][0]["seed"]
    elif mutation == "selected-index":
        generation["selection"]["selected_candidate_index"] = 2
    elif mutation == "second-selection":
        generation["candidates"][1]["selected"] = True
    elif mutation == "visual-approval":
        generation["selection"]["visual_approval"]["approved"] = False
    elif mutation == "license-decision":
        generation["selection"]["license_decision"]["approved"] = False
    else:
        comparison = generation["candidates"][0]["shadowed_comparison"]
        comparison["maximum_absolute_channel_error"] = "0"
        comparison["fraction_pixels_at_or_above_0_02"] = "0"
        comparison["nearest_rank_p95"] = "0"
    generation_path = tmp_path / "chart-02-generation.json"
    generation_path.write_bytes(canonical_json_bytes(generation))
    monkeypatch.setattr(
        fixture_module,
        "FROZEN_CHART2_GENERATION_SHA256",
        sha256_file(generation_path),
    )
    with pytest.raises(ValueError, match=message):
        load_frozen_chart2_samples(FROZEN_CHART2_PATH, generation_path)


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("truncated", "length mismatch"),
        ("header", "header mismatch"),
        ("payload", "selected asset hash mismatch"),
    ],
)
def test_frozen_chart2_asset_loader_rejects_tampering(
    tmp_path: Path, mutation: str, message: str
) -> None:
    data = bytearray(FROZEN_CHART2_PATH.read_bytes())
    if mutation == "truncated":
        data.pop()
    elif mutation == "header":
        data[8] ^= 1
    else:
        data[-1] ^= 1
    asset_path = tmp_path / "chart-02.rgb16be"
    asset_path.write_bytes(data)
    with pytest.raises(ValueError, match=message):
        load_frozen_chart2_samples(asset_path, FROZEN_CHART2_GENERATION_PATH)


def test_frozen_chart2_loader_rejects_non_promoted_sample(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = bytearray(FROZEN_CHART2_PATH.read_bytes())
    data[16] ^= 1
    asset_path = tmp_path / "chart-02.rgb16be"
    asset_path.write_bytes(data)
    asset_sha256 = sha256_file(asset_path)
    generation = read_json(FROZEN_CHART2_GENERATION_PATH)
    generation["candidates"][0]["canonical_rgb16be_sha256"] = asset_sha256
    generation["selection"]["asset"]["sha256"] = asset_sha256
    generation_path = tmp_path / "chart-02-generation.json"
    generation_path.write_bytes(canonical_json_bytes(generation))
    monkeypatch.setattr(fixture_module, "FROZEN_CHART2_SHA256", asset_sha256)
    monkeypatch.setattr(
        fixture_module,
        "FROZEN_CHART2_GENERATION_SHA256",
        sha256_file(generation_path),
    )
    with pytest.raises(ValueError, match="RGB8-to-RGB16 promotions"):
        load_frozen_chart2_samples(asset_path, generation_path)


def test_build_provenance_schema_and_static_hash_bindings() -> None:
    provenance = read_json(PACKAGE_ROOT / "fixtures/provenance.json")
    validate_contract_document(provenance)
    assert provenance["source_set_generator"] == SOURCE_SET_VERSION
    assert [source["source_id"] for source in provenance["sources"]] == [
        "chart-01",
        "chart-02",
        "chart-03",
        "chart-04",
    ]
    frozen = provenance["sources"][1]
    assert frozen["generator"] == FROZEN_PLATE_VERSION
    assert frozen["asset_sha256"] == sha256_file(FROZEN_CHART2_PATH)
    assert frozen["generation_record_sha256"] == sha256_file(FROZEN_CHART2_GENERATION_PATH)
    assert provenance["generated_luts"]["generator"] == "generated-lut/v1"


def test_distribution_contains_frozen_assets_without_provider_or_decoder_dependency() -> None:
    package = resources.files("colortrace_fixture")
    for name, expected_sha256 in (
        ("chart-02.rgb16be", FROZEN_CHART2_SHA256),
        ("chart-02-generation.json", FROZEN_CHART2_GENERATION_SHA256),
    ):
        payload = package.joinpath("assets", name).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected_sha256
    configuration = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert configuration["project"]["dependencies"] == [
        "jsonschema==4.25.1",
        "OpenColorIO==2.5.2",
    ]


def test_built_wheel_contains_frozen_asset_record_and_schemas(tmp_path: Path) -> None:
    wheel_root = tmp_path / "wheel"
    completed = subprocess.run(
        [
            "uv",
            "build",
            "--offline",
            "--wheel",
            "--out-dir",
            str(wheel_root),
            str(PACKAGE_ROOT),
        ],
        check=False,
        text=True,
        capture_output=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout
    wheels = list(wheel_root.glob("*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as archive:
        expected = {
            "colortrace_fixture/assets/chart-02.rgb16be": FROZEN_CHART2_SHA256,
            "colortrace_fixture/assets/chart-02-generation.json": (FROZEN_CHART2_GENERATION_SHA256),
        }
        for member, digest in expected.items():
            assert hashlib.sha256(archive.read(member)).hexdigest() == digest
        names = set(archive.namelist())
        assert "colortrace_fixture/schemas/frozen-source-generation-v1.schema.json" in names
        assert "colortrace_fixture/schemas/fixture-build-provenance-v1.schema.json" in names


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
    assert fixture["source_set_generator"] == SOURCE_SET_VERSION
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


def test_runtime_source_generators_are_per_source_and_provenance_bound(
    generated: dict[str, Any],
) -> None:
    root = generated["canonical"]["bundle"]
    runtime = read_json(root / "runtime/manifests/fixture-runtime-manifest.json")
    sources = {
        pointer["source_id"]: read_json(root / pointer["manifest"])
        for pointer in runtime["sources"]
    }
    assert runtime["source_set_generator"] == SOURCE_SET_VERSION
    assert {source_id: source["generator"] for source_id, source in sources.items()} == {
        "chart-01": GENERATED_CHART_VERSION,
        "chart-02": FROZEN_PLATE_VERSION,
        "chart-03": GENERATED_CHART_VERSION,
        "chart-04": GENERATED_CHART_VERSION,
    }
    assert sources["chart-02"]["generation_record_sha256"] == FROZEN_CHART2_GENERATION_SHA256
    assert all(
        "generation_record_sha256" not in source
        for source_id, source in sources.items()
        if source_id != "chart-02"
    )
    provenance = read_json(root / runtime["provenance"]["manifest"])
    source_generators = {
        asset["asset_id"]: asset["generator"]
        for asset in provenance["assets"]
        if asset["asset_kind"] in {"canonical-source-pixels", "source-display-png"}
    }
    assert source_generators["source-pixels-chart-02"] == FROZEN_PLATE_VERSION
    assert source_generators["source-png-chart-02"] == FROZEN_PLATE_VERSION
    assert all(
        generator == GENERATED_CHART_VERSION
        for asset_id, generator in source_generators.items()
        if "chart-02" not in asset_id
    )


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


def test_frozen_plate_reference_match_shadowed_mismatch_and_scope(
    generated: dict[str, Any],
) -> None:
    root = generated["canonical"]["bundle"]
    runtime = read_json(root / "runtime/manifests/fixture-runtime-manifest.json")
    jobs = {job["job_id"]: job for job in manifests(root, runtime)}
    report = {job["job_id"]: job for job in generated["canonical"]["report"]["jobs"]}
    approved = jobs["job-a-02"]
    approved_reference = read_json(root / approved["declared_reference_manifest"])
    assert (root / approved["output_buffer"]).read_bytes() == (
        root / approved_reference["buffer"]
    ).read_bytes()
    assert report["job-a-02"]["comparison"] == {
        "state": "reference_match",
        "maximum_absolute_channel_error": "0",
        "rmse": "0",
        "fraction_pixels_at_or_above_0_02": "0",
        "nearest_rank_p95": "0",
        "pixels": 147456,
        "policy": COMPARISON_VERSION,
    }
    assert report["job-b-02"]["comparison"] == {
        "state": "reference_mismatch",
        "maximum_absolute_channel_error": "0.157725512981",
        "rmse": "0.0388545007753",
        "fraction_pixels_at_or_above_0_02": "0.901984320747",
        "nearest_rank_p95": "0.0952941179276",
        "pixels": 147456,
        "policy": COMPARISON_VERSION,
    }
    validator_report = generated["canonical"]["report"]
    affected = sum(job["state"] == "reference_mismatch" for job in validator_report["jobs"])
    affected += sum(
        derivative["state"] == "reference_mismatch"
        for derivative in validator_report["derivatives"]
    )
    safe = sum(job["state"] == "reference_match" for job in validator_report["jobs"])
    unknown = sum(job["state"] == "unresolved" for job in validator_report["jobs"])
    assert (affected, safe, unknown) == (4, 3, 0)


def test_full_same_seed_replay_and_complete_golden_map(generated: dict[str, Any]) -> None:
    canonical = generated["canonical"]
    replay = generated["replay"]
    subtrees = ("runtime", "references", "reports")
    canonical_index = deterministic_tree_index(canonical["bundle"], subtrees)
    replay_index = deterministic_tree_index(replay["bundle"], subtrees)
    assert len(canonical_index) == len(replay_index) == 65
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


def test_canonical_build_validator_matches_complete_golden_without_landlock(
    generated: dict[str, Any], tmp_path: Path
) -> None:
    root, oracle_roots = canonical_build_input(generated, tmp_path)
    golden_path = PACKAGE_ROOT / "fixtures/canonical-digests.json"
    report = run_canonical_build_validator(
        SCRIPT,
        root,
        PYTHON,
        golden_path,
        oracle_roots,
        require_privilege_drop=False,
    )
    golden = read_json(golden_path)
    assert deterministic_tree_index(root, ("runtime", "references", "reports")) == golden["files"]
    assert (
        hashlib.sha256(canonical_json_bytes(golden["files"])).hexdigest() == golden["tree_sha256"]
    )
    assert len(report["jobs"]) == 6
    assert sum(job["state"] == "reference_match" for job in report["jobs"]) == 3
    assert sum(job["state"] == "reference_mismatch" for job in report["jobs"]) == 3
    assert all(job["state"] != "unresolved" for job in report["jobs"])
    assert (root / "reports/validator-invocation-receipt.json").is_file()
    assert not (root / "reports/landlock-receipt.json").exists()


@pytest.mark.parametrize(
    "mutation",
    [
        "changed",
        "missing",
        "extra",
        "stale-landlock",
        "stale-receipt",
        "noncanonical",
        "writable-directory",
    ],
)
def test_canonical_build_validator_rejects_prevalidation_tree_drift(
    generated: dict[str, Any], tmp_path: Path, mutation: str
) -> None:
    root, oracle_roots = canonical_build_input(generated, tmp_path)
    input_path = root / "runtime/manifests/fixture-runtime-manifest.json"
    if mutation == "changed":
        input_path.chmod(0o600)
        input_path.write_bytes(input_path.read_bytes() + b"\n")
        input_path.chmod(0o444)
    elif mutation == "missing":
        parent_mode = input_path.parent.stat().st_mode & 0o777
        input_path.parent.chmod(0o755)
        input_path.unlink()
        input_path.parent.chmod(parent_mode)
    elif mutation == "extra":
        (root / "unexpected.txt").write_text("unexpected", encoding="utf-8")
    elif mutation == "stale-landlock":
        (root / "reports/landlock-receipt.json").write_text("{}", encoding="utf-8")
    elif mutation == "stale-receipt":
        (root / "reports/validator-invocation-receipt.json").write_text("{}", encoding="utf-8")
    elif mutation == "writable-directory":
        (root / "runtime/workers").chmod(0o777)
    else:
        fixture = read_json(input_path)
        fixture["variant_id"] = "not-canonical"
        input_path.chmod(0o600)
        input_path.write_bytes(canonical_json_bytes(fixture))
        input_path.chmod(0o444)
    with pytest.raises((RuntimeError, ValueError), match="canonical bundle|file map|writable"):
        run_canonical_build_validator(
            SCRIPT,
            root,
            PYTHON,
            PACKAGE_ROOT / "fixtures/canonical-digests.json",
            oracle_roots,
            require_privilege_drop=False,
        )


@pytest.mark.parametrize("kind", ["file", "directory", "dangling-symlink"])
def test_canonical_build_validator_rejects_present_oracle_sibling(
    generated: dict[str, Any], tmp_path: Path, kind: str
) -> None:
    root, oracle_roots = canonical_build_input(generated, tmp_path)
    oracle = oracle_roots[0]
    if kind == "file":
        oracle.write_text("truth", encoding="utf-8")
    elif kind == "directory":
        oracle.mkdir()
    else:
        oracle.symlink_to(tmp_path / "missing-oracle-target")
    with pytest.raises(RuntimeError, match="oracle root must be absent"):
        run_canonical_build_validator(
            SCRIPT,
            root,
            PYTHON,
            PACKAGE_ROOT / "fixtures/canonical-digests.json",
            oracle_roots,
            require_privilege_drop=False,
        )


def test_public_validator_remains_fail_closed_when_landlock_is_unavailable(
    generated: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validate_called = False

    def unavailable(_root: Path) -> int:
        raise OSError(errno.ENOSYS, "Landlock is unavailable")

    def unexpected_validate(_root: Path) -> dict[str, Any]:
        nonlocal validate_called
        validate_called = True
        return {}

    monkeypatch.setattr(fixture_module, "enter_bundle_landlock", unavailable)
    monkeypatch.setattr(fixture_module, "validate_existing", unexpected_validate)
    probe = tmp_path / "neutral-probe"
    probe.write_bytes(b"probe")
    with pytest.raises(OSError) as error:
        fixture_module.validate_landlocked_worker(generated["canonical"]["bundle"], probe)
    assert error.value.errno == errno.ENOSYS
    assert validate_called is False


def test_canonical_build_semantics_reject_unresolved_output(generated: dict[str, Any]) -> None:
    report = json.loads(json.dumps(generated["canonical"]["report"]))
    report["jobs"][0]["state"] = "unresolved"
    report["jobs"][0]["reasons"] = ["synthetic-test"]
    with pytest.raises(RuntimeError, match="job-state mismatch"):
        fixture_module._assert_canonical_report_semantics(report)


def test_canonical_build_failure_does_not_mutate_worker_hardlink_target(
    generated: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, oracle_roots = canonical_build_input(generated, tmp_path)
    reports = root / "reports"
    generation = reports / "generation-receipt.json"
    external = tmp_path / "external-worker-file"
    external.write_bytes(b"external")
    external.chmod(0o640)
    original_external = external.stat()
    original_modes = {
        path: (path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o777)
        for path in (root, reports, generation)
    }

    def hostile_worker(*args: Any, **kwargs: Any) -> Any:
        del kwargs
        os.link(external, reports / "validator-report.json")
        return fixture_module.subprocess.CompletedProcess(args[0], 1, "", "forced failure")

    monkeypatch.setattr(fixture_module.subprocess, "run", hostile_worker)
    with pytest.raises(RuntimeError, match="forced failure"):
        run_canonical_build_validator(
            SCRIPT,
            root,
            PYTHON,
            PACKAGE_ROOT / "fixtures/canonical-digests.json",
            oracle_roots,
            require_privilege_drop=False,
        )
    after_external = external.stat()
    assert (after_external.st_uid, after_external.st_gid, after_external.st_mode & 0o777) == (
        original_external.st_uid,
        original_external.st_gid,
        original_external.st_mode & 0o777,
    )
    assert {
        path: (path.stat().st_uid, path.stat().st_gid, path.stat().st_mode & 0o777)
        for path in (root, reports, generation)
    } == original_modes
    assert not list(tmp_path.glob(".validator-boundary-*"))


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


def test_fixture_definition_records_mixed_source_set() -> None:
    definition = json.loads(
        (PACKAGE_ROOT / "fixtures/fixture-definition.json").read_text(encoding="utf-8")
    )
    assert definition["fixture_id"] == FIXTURE_ID
    assert definition["seed"] == CANONICAL_SEED
    assert definition["source_set_generator"] == SOURCE_SET_VERSION
    assert {source["source_id"]: source["generator"] for source in definition["sources"]} == {
        "chart-01": GENERATED_CHART_VERSION,
        "chart-02": FROZEN_PLATE_VERSION,
        "chart-03": GENERATED_CHART_VERSION,
        "chart-04": GENERATED_CHART_VERSION,
    }
    assert len(definition["jobs"]) == 6
