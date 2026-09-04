from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any, cast

import pytest
from colortrace_evaluation import canonical_json_bytes, prefixed_sha256
from colortrace_evaluation.reference_campaign import (
    BenchmarkArtifactObservation,
    build_reference_impact_benchmark,
    record_reference_model_selections,
    run_recorded_reference_campaign,
    run_reference_campaign,
    sealed_reference_holdouts,
)
from colortrace_evaluation.reference_worker_benchmark import (
    PreparedReferenceBenchmarkSuite,
    ReferenceWorkerBenchmarkError,
    _provenance_record,
    _seal_provenance,
    _write_exact,
    run_reference_worker_benchmark,
)
from colortrace_fixture import (
    ReferenceColorVariant,
    ReferenceMediaVerification,
    load_reference_media_manifest,
    reference_render_job,
    reference_scenarios,
)
from colortrace_investigation import ModelCall, ModelOutput


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


class _RecordedSelectionModel:
    async def generate(self, call: ModelCall) -> ModelOutput:
        approved = cast(Mapping[str, Any], call.payload["approved"])
        initial = cast(Mapping[str, Any], call.payload["initial_query"])
        observations = cast(list[Mapping[str, Any]], initial["observations"])
        affected = next(
            item
            for item in observations
            if cast(Mapping[str, str], item["attributes"])["declared_reference.state"]
            == "reference_mismatch"
        )
        attributes = cast(Mapping[str, str], affected["attributes"])
        derivative_changed = (
            attributes["derivative.parent_sha256"] != approved["derivative_parent_sha256"]
            or int(attributes["cache.generation"]) != approved["derivative_generation"]
        )
        content = json.dumps(
            {
                "schema": "reference-recorded-model-selection/v1",
                "selection_input_sha256": call.payload["input_sha256"],
                "selected_query_key": (
                    "trace.by-id" if derivative_changed else "log.correlated-events"
                ),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return ModelOutput(
            content=content,
            input_tokens=700,
            output_tokens=32,
            provider_request_id=cast(str, call.payload["input_sha256"]),
            provider_model_version="gemini-3.5-flash-20260904",
        )


@cache
def _recorded_campaign() -> Mapping[str, Any]:
    corpus = sealed_reference_holdouts()
    receipts = asyncio.run(
        record_reference_model_selections(
            model=_RecordedSelectionModel(),
            corpus=corpus,
            clock=lambda: datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
        )
    )
    return run_recorded_reference_campaign(receipts, corpus)


def _suite(source_root: Path) -> PreparedReferenceBenchmarkSuite:
    manifest = load_reference_media_manifest()
    verification = ReferenceMediaVerification(
        collection_id=manifest.collection_id,
        manifest_sha256=manifest.manifest_sha256,
        license_spdx=manifest.license_spdx,
        source_notice_sha256=manifest.source_notice_sha256,
        cache_root=source_root.resolve().as_posix(),
        frame_count=manifest.frame_count,
        total_bytes=manifest.total_bytes,
        sequence_record_set_sha256={
            sequence.sequence_id: sequence.record_set_sha256 for sequence in manifest.sequences
        },
    )
    variants = {
        "approved": ReferenceColorVariant(
            name="approved",
            config_relative_path="approved/config.ocio",
            config_sha256=_digest("approved-config"),
            resource_relative_path="approved/luts/show_look.cube",
            resource_sha256=_digest("approved-resource"),
            config_generation=7,
        ),
        "shadowed": ReferenceColorVariant(
            name="shadowed",
            config_relative_path="shadowed/config.ocio",
            config_sha256=_digest("approved-config"),
            resource_relative_path="shadowed/luts/show_look.cube",
            resource_sha256=_digest("shadowed-resource"),
            config_generation=7,
        ),
        "stale-rollout": ReferenceColorVariant(
            name="stale-rollout",
            config_relative_path="stale-rollout/config.ocio",
            config_sha256=_digest("stale-config"),
            resource_relative_path="stale-rollout/luts/show_look.cube",
            resource_sha256=_digest("approved-resource"),
            config_generation=6,
        ),
    }
    return PreparedReferenceBenchmarkSuite(
        manifest=manifest,
        media_verification=verification,
        scenarios=reference_scenarios(manifest),
        variants=cast(Any, variants),
    )


class _PreparedSuite:
    def __init__(self, suite: PreparedReferenceBenchmarkSuite) -> None:
        self.suite = suite
        self.calls = 0

    def __call__(
        self,
        *,
        source_root: Path,
        config_root: Path,
    ) -> PreparedReferenceBenchmarkSuite:
        del source_root, config_root
        self.calls += 1
        return self.suite


class _FakeWorker:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(
        self,
        value: Mapping[str, Any],
        *,
        source_root: Path,
        config_root: Path,
        output_root: Path,
    ) -> Mapping[str, Any]:
        del source_root, config_root
        self.calls += 1
        source = cast(Mapping[str, Any], value["source"])
        color = cast(Mapping[str, Any], value["color"])
        runtime = cast(Mapping[str, Any], value["runtime"])
        output = cast(Mapping[str, Any], value["output"])
        pixel_identity = {
            "source_sha256": source["sha256"],
            "config_sha256": color["config_sha256"],
            "resource_sha256": color["resource_sha256"],
            "effective_generation": runtime["effective_generation"],
        }
        payload = canonical_json_bytes(pixel_identity)
        output_path = output_root / cast(str, output["relative_path"])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        assert not output_path.exists()
        output_path.write_bytes(payload)
        body = {
            "schema": "reference-render-receipt/v1",
            "job_id": value["job_id"],
            "scenario_id": value["scenario_id"],
            "incident_class": value["incident_class"],
            "trace_id": value["trace_id"],
            "worker_id": value["worker_id"],
            "artifact_id": value["artifact_id"],
            "source_sha256": source["sha256"],
            "config_sha256": color["config_sha256"],
            "resource_sha256": color["resource_sha256"],
            "effective_generation": runtime["effective_generation"],
            "cache_key": runtime["cache_key"],
            "output_relative_path": output["relative_path"],
            "output_sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
            "canonical_pixel_sha256": prefixed_sha256(pixel_identity),
            "width": 4,
            "height": 4,
            "channels": 3,
            "pixel_work": 16,
            "bytes_read": source["byte_length"],
            "bytes_written": len(payload),
            "cpu_nanoseconds": 16,
            "wall_nanoseconds": 32,
            "dependencies": {
                "openimageio": "3.1.17.0",
                "opencolorio": "2.5.2",
            },
        }
        return {**body, "receipt_sha256": prefixed_sha256(body)}


def _roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    roots = tuple(tmp_path / name for name in ("source", "config", "output"))
    for root in roots:
        root.mkdir()
    return cast(tuple[Path, Path, Path], roots)


@pytest.mark.parametrize("root_kind", ("source", "config", "output"))
def test_benchmark_rejects_root_beneath_symlinked_parent(
    tmp_path: Path,
    root_kind: str,
) -> None:
    ordinary = tmp_path / "ordinary"
    ordinary.mkdir()
    source_root, config_root, output_root = _roots(ordinary)
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    escaped_root = linked_parent / root_kind
    if root_kind != "output":
        escaped_root.resolve().mkdir()
    roots = {
        "source_root": escaped_root if root_kind == "source" else source_root,
        "config_root": escaped_root if root_kind == "config" else config_root,
        "output_root": escaped_root if root_kind == "output" else output_root,
    }

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-root-unsafe",
    ):
        run_reference_worker_benchmark(**roots)


def test_benchmark_write_does_not_create_beneath_symlinked_parent(tmp_path: Path) -> None:
    output_root = tmp_path / "output"
    output_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (output_root / "redirect").symlink_to(outside, target_is_directory=True)

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-path-invalid",
    ):
        _write_exact(
            output_root / "redirect" / "escaped" / "result.json",
            output_root,
            {"safe": True},
        )

    assert not (outside / "escaped").exists()


def test_benchmark_executes_complete_scope_and_resumes_exact_pairs(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    preparer = _PreparedSuite(suite)
    worker = _FakeWorker()
    campaign = _recorded_campaign()

    first = run_reference_worker_benchmark(
        source_root=source_root,
        config_root=config_root,
        output_root=output_root,
        campaign_report=campaign,
        report_relative_path="reports/impact.json",
        worker=worker,
        suite_preparer=preparer,
    )

    assert first["evidence"] == {
        "source": "controlled-receipt-set",
        "evidence_set_id": first["evidence"]["evidence_set_id"],
        "recorded_worker_evidence": False,
        "observation_count": 720,
    }
    assert first["passed"] is True
    assert worker.calls == 720 + (72 * 6)
    assert len(tuple((output_root / "receipts").rglob("*.json"))) == worker.calls
    assert len(tuple((output_root / "operations").rglob("*.json"))) == 72
    evidence_index = json.loads(
        (output_root / "reports" / "reference-worker-evidence-index.json").read_text(
            encoding="utf-8"
        )
    )
    evidence_body = {
        key: value for key, value in evidence_index.items() if key != "evidence_set_id"
    }
    assert evidence_index["schema"] == "reference-worker-evidence-set/v1"
    assert len(evidence_index["observations"]) == 720
    assert len(evidence_index["cache_invalidation_operation_sha256"]) == 72
    assert evidence_index["evidence_set_id"] == prefixed_sha256(evidence_body)
    assert first["evidence"]["evidence_set_id"] == evidence_index["evidence_set_id"]
    affected_evidence = [item for item in evidence_index["observations"] if item["affected"]]
    protected_evidence = [item for item in evidence_index["observations"] if not item["affected"]]
    assert len(affected_evidence) == 216
    assert all(item["observed_receipt"] is not None for item in affected_evidence)
    assert all(
        item["observed_receipt"]["canonical_pixel_sha256"]
        != item["baseline_receipt"]["canonical_pixel_sha256"]
        and item["observed_receipt"]["output_sha256"] != item["baseline_receipt"]["output_sha256"]
        for item in affected_evidence
    )
    assert all(item["observed_receipt"] is None for item in protected_evidence)
    provenance = json.loads(
        (output_root / "metadata" / "reference-worker-benchmark-provenance.json").read_text(
            encoding="utf-8"
        )
    )
    assert provenance["evidence_source"] == "controlled-receipt-set"
    assert provenance["worker_binding"] == "injected-worker"
    assert provenance["execution_mode"] == "injected-worker-callable"
    assert provenance["container_image_digest"] is None
    assert provenance["dependency_lock_sha256"].startswith("sha256:")
    assert provenance["implementation_sha256"] == prefixed_sha256(
        provenance["implementation_files"]
    )
    assert evidence_index["execution_provenance"] == provenance
    assert evidence_index["execution_provenance_sha256"] == provenance["provenance_sha256"]
    stale = next(
        item
        for item in first["scenario_results"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    )
    assert stale["selective"]["pixel_work"] == 72 * 16
    assert stale["compute_avoided_basis_points"] == 7_000
    assert stale["output_equivalence"] is True
    stale_evidence = [
        item
        for item in evidence_index["observations"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1"
    ]
    stale_affected = [item for item in stale_evidence if item["affected"]]
    stale_protected = [item for item in stale_evidence if not item["affected"]]
    assert len(stale_affected) == 72
    assert len(stale_protected) == 168
    assert all(item["selective_receipt"] is not None for item in stale_affected)
    assert all(
        item["cache_observed_receipt"]["receipt_sha256"]
        == item["cache_entry_before"]["source_receipt_sha256"]
        == item["observed_receipt"]["receipt_sha256"]
        for item in stale_affected
    )
    assert all(item["operation_compute_units"] == 0 for item in stale_affected)
    assert all(item["cache_entry_before"]["state"] == "stale" for item in stale_affected)
    assert all(item["cache_entry_after"]["state"] == "current" for item in stale_affected)
    assert all(item["cache_lookup_after_invalidation"] == "miss" for item in stale_affected)
    assert all(
        item["cache_entry_before"]["derivative_output_sha256"]
        != item["baseline_receipt"]["output_sha256"]
        and item["cache_entry_before"]["canonical_pixel_sha256"]
        != item["baseline_receipt"]["canonical_pixel_sha256"]
        for item in stale_affected
    )
    assert all(
        item["cache_invalidation_operation"]["invalidated_entry_sha256"]
        == item["cache_entry_before"]["entry_sha256"]
        for item in stale_affected
    )
    assert sorted(evidence_index["cache_invalidation_operation_sha256"]) == sorted(
        item["cache_invalidation_operation"]["operation_sha256"] for item in stale_affected
    )
    assert all(
        item["cache_entry_after"]["derivative_output_sha256"]
        == item["baseline_receipt"]["output_sha256"]
        and item["cache_entry_after"]["canonical_pixel_sha256"]
        == item["baseline_receipt"]["canonical_pixel_sha256"]
        for item in stale_affected
    )
    assert all(
        item["cache_entry_before"] == item["cache_entry_after"]
        and item["cache_observed_receipt"] is None
        and item["cache_invalidation_operation"] is None
        and item["cache_lookup_after_invalidation"] is None
        for item in stale_protected
    )

    reconstructed = tuple(
        BenchmarkArtifactObservation(
            scenario_id=item["scenario_id"],
            artifact_id=item["artifact_id"],
            affected=item["affected"],
            baseline_receipt=item["baseline_receipt"],
            observed_receipt=item["observed_receipt"],
            selective_receipt=item["selective_receipt"],
            preserved_before_output_sha256=item["preserved_before_output_sha256"],
            preserved_after_output_sha256=item["preserved_after_output_sha256"],
            preserved_before_canonical_pixel_sha256=(
                item["preserved_before_canonical_pixel_sha256"]
            ),
            preserved_after_canonical_pixel_sha256=(item["preserved_after_canonical_pixel_sha256"]),
            verification_bytes_read=item["verification_bytes_read"],
            operation_compute_units=item["operation_compute_units"],
            operation_bytes_read=item["operation_bytes_read"],
            operation_bytes_written=item["operation_bytes_written"],
            operation_cpu_nanoseconds=item["operation_cpu_nanoseconds"],
            operation_wall_nanoseconds=item["operation_wall_nanoseconds"],
        )
        for item in evidence_index["observations"]
    )
    recomputed = build_reference_impact_benchmark(
        reconstructed,
        campaign,
        evidence_source=evidence_index["source"],
        evidence_set_id=evidence_index["evidence_set_id"],
    )
    for key in ("metrics", "timing", "scenario_results", "checks", "passed"):
        assert recomputed[key] == first[key]

    resumed = run_reference_worker_benchmark(
        source_root=source_root,
        config_root=config_root,
        output_root=output_root,
        campaign_report=campaign,
        report_relative_path="reports/impact.json",
        worker=worker,
        suite_preparer=preparer,
    )

    assert resumed == first
    assert worker.calls == 1_152
    assert preparer.calls == 2

    first_output = next((output_root / "tos-config-rollout-drift-v1" / "expected").rglob("*.exr"))
    first_output.write_bytes(first_output.read_bytes() + b"tampered")
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-output-mismatch",
    ):
        run_reference_worker_benchmark(
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            campaign_report=campaign,
            worker=worker,
            suite_preparer=preparer,
        )
    assert worker.calls == 1_152


def test_partial_resume_pair_fails_before_worker_execution(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    preparer = _PreparedSuite(suite)
    worker = _FakeWorker()
    scenario = suite.scenarios[sorted(suite.scenarios)[0]]
    frame = suite.manifest.sequences[0].frames[0]
    job = reference_render_job(
        frame=frame,
        scenario=scenario,
        variants=suite.variants,
        mode="expected",
        trace_id="0" * 32,
    )
    output = cast(Mapping[str, Any], job["output"])
    path = output_root / cast(str, output["relative_path"])
    path.parent.mkdir(parents=True)
    path.write_bytes(b"orphan")
    provenance_path = output_root / "metadata" / "reference-worker-benchmark-provenance.json"
    provenance_path.parent.mkdir(parents=True)
    provenance_path.write_bytes(
        canonical_json_bytes(
            _provenance_record(
                suite,
                "controlled-receipt-set",
                sealed_suite=False,
                real_worker=False,
            )
        )
        + b"\n"
    )

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-resume-pair-incomplete",
    ):
        run_reference_worker_benchmark(
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            campaign_report=run_reference_campaign(),
            worker=worker,
            suite_preparer=preparer,
        )

    assert worker.calls == 0


def test_suite_requires_the_exact_sealed_population(tmp_path: Path) -> None:
    source_root, _config_root, _output_root = _roots(tmp_path)
    suite = _suite(source_root)
    scenarios = dict(suite.scenarios)
    scenarios.pop("tos-stale-derivative-cache-v1")

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-suite-invalid",
    ):
        PreparedReferenceBenchmarkSuite(
            manifest=suite.manifest,
            media_verification=suite.media_verification,
            scenarios=scenarios,
            variants=suite.variants,
        )


def test_controlled_receipts_cannot_be_promoted_to_recorded_evidence(tmp_path: Path) -> None:
    source_root, _config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    _seal_provenance(
        output_root,
        suite,
        "controlled-receipt-set",
        sealed_suite=False,
        real_worker=False,
    )

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-existing-output-conflict",
    ):
        _seal_provenance(
            output_root,
            suite,
            "recorded-worker-receipts",
            sealed_suite=True,
            real_worker=True,
        )
