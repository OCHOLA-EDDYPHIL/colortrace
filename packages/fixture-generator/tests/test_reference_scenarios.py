from __future__ import annotations

import hashlib
import json
from pathlib import Path

import PyOpenColorIO as ocio  # type: ignore[import-untyped]
import pytest
from colortrace_fixture import (
    ReferenceAssetError,
    load_reference_media_manifest,
    materialize_reference_color_variants,
    reference_render_job,
    reference_scenarios,
)


def test_reference_scenarios_are_mutually_exclusive_and_reproducible() -> None:
    first = reference_scenarios()
    second = reference_scenarios()

    assert tuple(first) == (
        "tos-resource-resolution-drift-v1",
        "tos-config-rollout-drift-v1",
        "tos-stale-derivative-cache-v1",
    )
    assert [scenario.incident_class for scenario in first.values()] == [
        "resource-resolution-drift/v1",
        "configuration-rollout-drift/v1",
        "stale-derivative-cache/v1",
    ]
    for scenario_id, scenario in first.items():
        assert scenario == second[scenario_id]
        assert len(scenario.affected_artifact_ids) == 72
        assert len(scenario.protected_artifact_ids) == 168
        assert scenario.artifact_count == 240
        assert not set(scenario.affected_artifact_ids).intersection(scenario.protected_artifact_ids)
        document = scenario.to_dict()
        digest = document.pop("scenario_sha256")
        encoded = json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        assert digest == f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def test_each_scenario_changes_only_its_declared_fault_dimension() -> None:
    scenarios = reference_scenarios()
    resource = scenarios["tos-resource-resolution-drift-v1"]
    rollout = scenarios["tos-config-rollout-drift-v1"]
    cache = scenarios["tos-stale-derivative-cache-v1"]

    assert (
        resource.resource_variant,
        resource.config_variant,
        resource.frame_pipeline_variant,
        resource.cache_variant,
    ) == ("shadowed", "approved", "drifted", "current")
    assert resource.observed_config_generation == resource.expected_config_generation
    assert resource.observed_derivative_generation == resource.expected_derivative_generation

    assert (
        rollout.resource_variant,
        rollout.config_variant,
        rollout.frame_pipeline_variant,
        rollout.cache_variant,
    ) == ("approved", "stale-rollout", "drifted", "current")
    assert rollout.observed_config_generation < rollout.expected_config_generation
    assert rollout.observed_derivative_generation == rollout.expected_derivative_generation

    assert (
        cache.resource_variant,
        cache.config_variant,
        cache.frame_pipeline_variant,
        cache.cache_variant,
    ) == ("approved", "approved", "approved", "stale")
    assert cache.observed_config_generation == cache.expected_config_generation
    assert cache.observed_derivative_generation < cache.expected_derivative_generation


def test_reference_color_variants_change_only_the_intended_inputs(tmp_path: Path) -> None:
    variants = materialize_reference_color_variants(tmp_path / "color")

    assert variants["approved"].config_sha256 == variants["shadowed"].config_sha256
    assert variants["approved"].resource_sha256 != variants["shadowed"].resource_sha256
    assert variants["approved"].config_sha256 != variants["stale-rollout"].config_sha256
    assert variants["approved"].resource_sha256 == variants["stale-rollout"].resource_sha256

    outputs: dict[str, tuple[float, ...]] = {}
    for name in ("approved", "shadowed", "stale-rollout"):
        variant = variants[name]
        ocio.ClearAllCaches()
        configuration = ocio.Config.CreateFromFile(
            str(tmp_path / "color" / variant.config_relative_path)
        )
        processor = configuration.getProcessor(
            variant.input_color_space,
            variant.output_color_space,
        ).getDefaultCPUProcessor()
        outputs[name] = tuple(processor.applyRGB([0.2, 0.4, 0.6]))
    assert outputs["approved"] != outputs["shadowed"]
    assert outputs["approved"] != outputs["stale-rollout"]


def test_reference_color_variants_reject_root_beneath_symlinked_parent(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ReferenceAssetError, match="reference-color-root-unsafe"):
        materialize_reference_color_variants(linked_parent / "color")


def test_reference_color_variants_reject_symlinked_variant_directory(
    tmp_path: Path,
) -> None:
    root = tmp_path / "color"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "approved").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ReferenceAssetError, match="reference-color-asset-conflict"):
        materialize_reference_color_variants(root)

    assert tuple(outside.iterdir()) == ()


def test_render_jobs_select_only_the_scenario_fault_variant(tmp_path: Path) -> None:
    manifest = load_reference_media_manifest()
    variants = materialize_reference_color_variants(tmp_path / "color")
    scenarios = reference_scenarios(manifest)
    frame_by_id = {
        f"frame:{frame.sequence_id}:{frame.frame:05d}": frame
        for sequence in manifest.sequences
        for frame in sequence.frames
    }

    for scenario in scenarios.values():
        affected_id = scenario.affected_artifact_ids[0]
        protected_id = scenario.protected_artifact_ids[0]
        affected = reference_render_job(
            frame=frame_by_id[affected_id],
            scenario=scenario,
            variants=variants,
            mode="observed",
            trace_id="1" * 32,
        )
        protected = reference_render_job(
            frame=frame_by_id[protected_id],
            scenario=scenario,
            variants=variants,
            mode="observed",
            trace_id="2" * 32,
        )
        recovered = reference_render_job(
            frame=frame_by_id[affected_id],
            scenario=scenario,
            variants=variants,
            mode="recovered",
            trace_id="3" * 32,
        )
        assert protected["color"] == recovered["color"]
        assert (
            protected["runtime"]["effective_generation"]
            == recovered["runtime"]["effective_generation"]
        )
        if scenario.incident_class == "stale-derivative-cache/v1":
            assert affected["color"] == recovered["color"]
            assert affected["runtime"] == recovered["runtime"]
        else:
            assert (
                affected["color"] != recovered["color"]
                or affected["runtime"] != recovered["runtime"]
            )
