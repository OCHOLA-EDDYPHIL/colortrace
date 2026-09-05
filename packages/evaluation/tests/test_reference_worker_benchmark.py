from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping
from copy import deepcopy
from functools import cache
from pathlib import Path
from typing import Any, cast

import colortrace_evaluation.reference_worker_benchmark as worker_benchmark
import pytest
from colortrace_evaluation import canonical_json_bytes, prefixed_sha256
from colortrace_evaluation.reference_campaign import (
    BenchmarkArtifactObservation,
    build_reference_impact_benchmark,
    run_reference_campaign,
)
from colortrace_evaluation.reference_worker_benchmark import (
    PreparedReferenceBenchmarkSuite,
    ReferenceWorkerBenchmarkError,
    _bound_real_worker,
    _provenance_record,
    _seal_provenance,
    _trusted_implementation_digest,
    _validate_receipt_for_job,
    _VerifiedReferenceWorkerEvidence,
    _write_exact,
    resolve_trusted_host_execution_identity,
    run_reference_worker_benchmark,
)
from colortrace_evaluation.reference_worker_benchmark import (
    verify_reference_worker_evidence_set as _verify_reference_worker_evidence_set_impl,
)
from colortrace_fixture import (
    ReferenceColorVariant,
    ReferenceMediaVerification,
    load_reference_media_manifest,
    reference_render_job,
    reference_scenarios,
)
from colortrace_simulator.reference_worker import ReferenceExecutionIdentity

SOURCE_REVISION = "1" * 40
SOURCE_TREE = "2" * 40
INJECTED_IDENTITY = ReferenceExecutionIdentity(
    mode="injected-worker-callable",
    source_revision=SOURCE_REVISION,
    source_tree=SOURCE_TREE,
    container_image_digest=None,
)
HOST_IDENTITY = ReferenceExecutionIdentity(
    mode="host-python-module",
    source_revision=SOURCE_REVISION,
    source_tree=SOURCE_TREE,
    container_image_digest=None,
)


def _verify_reference_worker_evidence_set(
    evidence_set: Mapping[str, Any],
    *,
    suite: PreparedReferenceBenchmarkSuite,
    output_root: Path,
    expected_execution_identity: ReferenceExecutionIdentity = INJECTED_IDENTITY,
) -> _VerifiedReferenceWorkerEvidence:
    return _verify_reference_worker_evidence_set_impl(
        evidence_set,
        suite=suite,
        output_root=output_root,
        expected_execution_identity=expected_execution_identity,
    )


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


@cache
def _campaign() -> Mapping[str, Any]:
    return run_reference_campaign()


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
        execution_identity: ReferenceExecutionIdentity | Mapping[str, Any],
    ) -> Mapping[str, Any]:
        del source_root, config_root
        self.calls += 1
        source = cast(Mapping[str, Any], value["source"])
        color = cast(Mapping[str, Any], value["color"])
        runtime = cast(Mapping[str, Any], value["runtime"])
        output = cast(Mapping[str, Any], value["output"])
        identity = (
            execution_identity
            if isinstance(execution_identity, ReferenceExecutionIdentity)
            else ReferenceExecutionIdentity.from_mapping(execution_identity)
        )
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
            "schema": "reference-render-receipt/v2",
            "job_sha256": prefixed_sha256(value),
            "execution_identity": identity.to_dict(),
            "execution_identity_sha256": identity.sha256,
            "job_id": value["job_id"],
            "scenario_id": value["scenario_id"],
            "incident_class": value["incident_class"],
            "trace_id": value["trace_id"],
            "worker_id": value["worker_id"],
            "artifact_id": value["artifact_id"],
            "source_sha256": source["sha256"],
            "config_sha256": color["config_sha256"],
            "resource_sha256": color["resource_sha256"],
            "input_color_space": color["input_color_space"],
            "output_color_space": color["output_color_space"],
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


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["/usr/bin/git", "-C", repository.as_posix(), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    return completed.stdout.strip()


def _resign_evidence(document: dict[str, Any]) -> None:
    body = {key: value for key, value in document.items() if key != "evidence_set_id"}
    document["evidence_set_id"] = prefixed_sha256(body)


def test_stale_parent_lookup_is_immediate_non_wrapping_and_fail_closed(
    tmp_path: Path,
) -> None:
    suite = _suite(tmp_path)
    scenario = suite.scenarios["tos-stale-derivative-cache-v1"]
    frame_by_artifact = {
        f"frame:{frame.sequence_id}:{frame.frame:05d}": frame
        for sequence in suite.manifest.sequences
        for frame in sequence.frames
    }
    predecessors = worker_benchmark._immediate_predecessor_by_artifact(
        suite.manifest,
        required_artifact_ids=scenario.affected_artifact_ids,
    )

    for artifact_id in scenario.affected_artifact_ids:
        frame = frame_by_artifact[artifact_id]
        predecessor = predecessors[artifact_id]
        assert predecessor.sequence_id == frame.sequence_id
        assert predecessor.frame == frame.frame - 1

    for sequence in suite.manifest.sequences:
        first = sequence.frames[0]
        first_artifact_id = f"frame:{first.sequence_id}:{first.frame:05d}"
        assert first_artifact_id not in predecessors
        assert first_artifact_id in scenario.protected_artifact_ids
        with pytest.raises(
            ReferenceWorkerBenchmarkError,
            match="reference-benchmark-stale-parent-missing",
        ):
            worker_benchmark._immediate_predecessor_by_artifact(
                suite.manifest,
                required_artifact_ids=(first_artifact_id,),
            )
        with pytest.raises(
            ReferenceWorkerBenchmarkError,
            match="reference-benchmark-stale-parent-invalid",
        ):
            worker_benchmark._stale_derivative_job(
                frame=first,
                stale_parent=sequence.frames[-1],
                scenario=scenario,
                variants=suite.variants,
                trace_id="0" * 32,
            )


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


def test_trusted_host_identity_ignores_git_environment_and_rejects_dirty_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "worker.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "ColorTrace Test")
    _git(repository, "config", "user.email", "test@colortrace.invalid")
    _git(repository, "add", "worker.py")
    _git(repository, "commit", "-m", "fixture")
    expected_revision = _git(repository, "rev-parse", "HEAD^{commit}")
    expected_tree = _git(repository, "rev-parse", "HEAD^{tree}")

    spoof = tmp_path / "spoof"
    spoof.mkdir()
    monkeypatch.setenv("PATH", spoof.as_posix())
    monkeypatch.setenv("GIT_DIR", spoof.as_posix())
    monkeypatch.setenv("GIT_WORK_TREE", spoof.as_posix())
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", spoof.as_posix())
    monkeypatch.setenv("COLORTRACE_SOURCE_REVISION", "8" * 40)
    monkeypatch.setenv("COLORTRACE_SOURCE_TREE", "9" * 40)
    identity = resolve_trusted_host_execution_identity(source)

    assert identity == ReferenceExecutionIdentity(
        mode="host-python-module",
        source_revision=expected_revision,
        source_tree=expected_tree,
        container_image_digest=None,
    )

    source.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-checkout-not-clean",
    ):
        resolve_trusted_host_execution_identity(source)


def test_trusted_host_identity_rejects_caller_owned_git_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_git = tmp_path / "git"
    fake_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_git.chmod(0o755)
    source = tmp_path / "worker.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")

    monkeypatch.setattr(worker_benchmark, "_TRUSTED_GIT", fake_git)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-git-untrusted",
    ):
        resolve_trusted_host_execution_identity(source)


def test_recorded_implementation_must_match_tracked_head_blob(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    source = repository / "worker.py"
    content = b"VALUE = 1\n"
    source.write_bytes(content)
    _git(repository, "init", "--initial-branch=main")
    _git(repository, "config", "user.name", "ColorTrace Test")
    _git(repository, "config", "user.email", "test@colortrace.invalid")
    _git(repository, "add", "worker.py")
    _git(repository, "commit", "-m", "fixture")

    assert _trusted_implementation_digest(repository, source) == (
        f"sha256:{hashlib.sha256(content).hexdigest()}"
    )

    source.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-implementation-untrusted",
    ):
        _trusted_implementation_digest(repository, source)

    outside = tmp_path / "outside.py"
    outside.write_text("VALUE = 1\n", encoding="utf-8")
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-implementation-untrusted",
    ):
        _trusted_implementation_digest(repository, outside)


def test_real_worker_binding_has_no_loader_substitution_seam(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not hasattr(worker_benchmark, "_load_real_worker")
    assert _bound_real_worker() is worker_benchmark.execute_reference_render_job

    monkeypatch.setattr(worker_benchmark, "execute_reference_render_job", _FakeWorker())
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-worker-binding-invalid",
    ):
        _bound_real_worker()


def test_recorded_benchmark_requires_external_expected_identity(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-expected-source-identity-required",
    ):
        run_reference_worker_benchmark(
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
        )


def test_recorded_benchmark_rejects_caller_supplied_identity(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-recorded-identity-caller-supplied",
    ):
        run_reference_worker_benchmark(
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            execution_identity=HOST_IDENTITY,
            expected_source_revision=SOURCE_REVISION,
            expected_source_tree=SOURCE_TREE,
        )


def test_recorded_benchmark_rejects_mismatched_expected_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    monkeypatch.setattr(
        worker_benchmark,
        "resolve_trusted_host_execution_identity",
        lambda: HOST_IDENTITY,
    )

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-expected-source-identity-mismatch",
    ):
        run_reference_worker_benchmark(
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            expected_source_revision="8" * 40,
            expected_source_tree=SOURCE_TREE,
        )


def test_recorded_benchmark_rejects_existing_output_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    monkeypatch.setattr(
        worker_benchmark,
        "resolve_trusted_host_execution_identity",
        lambda: HOST_IDENTITY,
    )

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-recorded-output-not-fresh",
    ):
        run_reference_worker_benchmark(
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            expected_source_revision=SOURCE_REVISION,
            expected_source_tree=SOURCE_TREE,
        )


def test_recorded_output_root_is_created_exclusively(tmp_path: Path) -> None:
    output_root = tmp_path / "fresh-output"

    created = worker_benchmark._fresh_output_root(output_root)

    assert created == output_root
    assert created.is_dir()
    assert list(created.iterdir()) == []
    assert created.stat().st_mode & 0o077 == 0
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-recorded-output-not-fresh",
    ):
        worker_benchmark._fresh_output_root(output_root)


def test_receipt_verifier_rejects_missing_and_tampered_execution_bindings(
    tmp_path: Path,
) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    scenario = suite.scenarios[sorted(suite.scenarios)[0]]
    frame = suite.manifest.sequences[0].frames[0]
    job = reference_render_job(
        frame=frame,
        scenario=scenario,
        variants=suite.variants,
        mode="expected",
        trace_id="0" * 32,
    )
    receipt = dict(
        _FakeWorker()(
            job,
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            execution_identity=INJECTED_IDENTITY,
        )
    )

    missing = deepcopy(receipt)
    del missing["job_sha256"]
    missing_body = {key: value for key, value in missing.items() if key != "receipt_sha256"}
    missing["receipt_sha256"] = prefixed_sha256(missing_body)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-worker-receipt-invalid",
    ):
        _validate_receipt_for_job(
            missing,
            job,
            output_root=output_root,
            execution_identity=INJECTED_IDENTITY,
        )

    wrong_job = deepcopy(receipt)
    wrong_job["job_sha256"] = _digest("different-job")
    wrong_job_body = {key: value for key, value in wrong_job.items() if key != "receipt_sha256"}
    wrong_job["receipt_sha256"] = prefixed_sha256(wrong_job_body)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-receipt-job-mismatch",
    ):
        _validate_receipt_for_job(
            wrong_job,
            job,
            output_root=output_root,
            execution_identity=INJECTED_IDENTITY,
        )

    mixed_identity = deepcopy(receipt)
    mixed_identity["execution_identity"]["source_tree"] = "9" * 40
    mixed_identity["execution_identity_sha256"] = prefixed_sha256(
        mixed_identity["execution_identity"]
    )
    mixed_body = {key: value for key, value in mixed_identity.items() if key != "receipt_sha256"}
    mixed_identity["receipt_sha256"] = prefixed_sha256(mixed_body)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-receipt-job-mismatch",
    ):
        _validate_receipt_for_job(
            mixed_identity,
            job,
            output_root=output_root,
            execution_identity=INJECTED_IDENTITY,
        )


def test_recorded_receipt_store_refuses_preseeded_pairs(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    scenario = suite.scenarios[sorted(suite.scenarios)[0]]
    frame = suite.manifest.sequences[0].frames[0]
    job = reference_render_job(
        frame=frame,
        scenario=scenario,
        variants=suite.variants,
        mode="expected",
        trace_id="0" * 32,
    )
    output_path = output_root / cast(
        str,
        cast(Mapping[str, Any], job["output"])["relative_path"],
    )
    receipt_path = output_root / worker_benchmark._receipt_relative_path(job, "baseline")
    output_path.parent.mkdir(parents=True)
    receipt_path.parent.mkdir(parents=True)
    output_path.write_bytes(b"preseeded-output")
    receipt_path.write_bytes(b"{}\n")
    worker = _FakeWorker()
    store = worker_benchmark._ReceiptStore(
        output_root=output_root,
        worker=worker,
        source_root=source_root,
        config_root=config_root,
        execution_identity=HOST_IDENTITY,
        allow_reuse=False,
    )

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-recorded-reuse-forbidden",
    ):
        store.obtain(job, phase="baseline")

    assert store.reused == 0
    assert store.executed == 0
    assert worker.calls == 0


def test_benchmark_executes_complete_scope_and_resumes_exact_pairs(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    preparer = _PreparedSuite(suite)
    worker = _FakeWorker()
    campaign = _campaign()

    first = run_reference_worker_benchmark(
        source_root=source_root,
        config_root=config_root,
        output_root=output_root,
        campaign_report=campaign,
        report_relative_path="reports/impact.json",
        worker=worker,
        suite_preparer=preparer,
        execution_identity=INJECTED_IDENTITY,
    )

    assert first["evidence"] == {
        "source": "controlled-receipt-set",
        "evidence_set_id": first["evidence"]["evidence_set_id"],
        "recorded_worker_evidence": False,
        "observation_count": 720,
        "execution_identity": None,
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
    assert evidence_index["schema"] == "reference-worker-evidence-set/v2"
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
    assert provenance["source_revision"] == SOURCE_REVISION
    assert provenance["source_tree"] == SOURCE_TREE
    assert provenance["execution_identity_sha256"] == INJECTED_IDENTITY.sha256
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
        execution_identity=INJECTED_IDENTITY,
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
            execution_identity=INJECTED_IDENTITY,
        )
    assert worker.calls == 1_152


def test_verifier_rejects_tampered_complete_controlled_evidence(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    preparer = _PreparedSuite(suite)
    worker = _FakeWorker()
    campaign = _campaign()

    report = run_reference_worker_benchmark(
        source_root=source_root,
        config_root=config_root,
        output_root=output_root,
        campaign_report=campaign,
        worker=worker,
        suite_preparer=preparer,
        execution_identity=INJECTED_IDENTITY,
    )
    evidence = json.loads(
        (output_root / "reports" / "reference-worker-evidence-index.json").read_text(
            encoding="utf-8"
        )
    )
    verified = _verify_reference_worker_evidence_set(
        evidence,
        suite=suite,
        output_root=output_root,
    )
    different_attestation = ReferenceExecutionIdentity(
        mode="host-python-module",
        source_revision="8" * 40,
        source_tree=SOURCE_TREE,
        container_image_digest=None,
    )
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-attestation-mismatch",
    ):
        _verify_reference_worker_evidence_set(
            evidence,
            suite=suite,
            output_root=output_root,
            expected_execution_identity=different_attestation,
        )

    assert report["evidence"] == {
        "source": "controlled-receipt-set",
        "evidence_set_id": verified.evidence_set_id,
        "recorded_worker_evidence": False,
        "observation_count": 720,
        "execution_identity": None,
    }
    assert verified.source == "controlled-receipt-set"
    assert verified.execution_identity == INJECTED_IDENTITY
    assert len(verified.observations) == 720
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-unverified",
    ):
        _VerifiedReferenceWorkerEvidence()

    mutable_receipt = cast(dict[str, Any], verified.observations[0].baseline_receipt)
    with pytest.raises(TypeError):
        mutable_receipt["pixel_work"] = 1

    reordered = deepcopy(evidence)
    reordered["observations"][0], reordered["observations"][1] = (
        reordered["observations"][1],
        reordered["observations"][0],
    )
    _resign_evidence(reordered)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-scope-invalid",
    ):
        _verify_reference_worker_evidence_set(
            reordered,
            suite=suite,
            output_root=output_root,
        )

    invented_id = deepcopy(evidence)
    invented_id["evidence_set_id"] = _digest("invented-evidence-id")
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-digest-invalid",
    ):
        _verify_reference_worker_evidence_set(
            invented_id,
            suite=suite,
            output_root=output_root,
        )

    resigned_receipt = deepcopy(evidence)
    receipt_observation = resigned_receipt["observations"][0]
    receipt = receipt_observation["baseline_receipt"]
    receipt["bytes_read"] += 1
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = prefixed_sha256(receipt_body)
    receipt_observation["baseline_receipt_sha256"] = receipt["receipt_sha256"]
    _resign_evidence(resigned_receipt)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-receipt-job-mismatch",
    ):
        _verify_reference_worker_evidence_set(
            resigned_receipt,
            suite=suite,
            output_root=output_root,
        )

    wrong_job_binding = deepcopy(evidence)
    receipt_observation = wrong_job_binding["observations"][0]
    receipt = receipt_observation["baseline_receipt"]
    receipt["job_sha256"] = _digest("different-job-payload")
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = prefixed_sha256(receipt_body)
    receipt_observation["baseline_receipt_sha256"] = receipt["receipt_sha256"]
    _resign_evidence(wrong_job_binding)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-receipt-job-mismatch",
    ):
        _verify_reference_worker_evidence_set(
            wrong_job_binding,
            suite=suite,
            output_root=output_root,
        )

    missing_execution_binding = deepcopy(evidence)
    receipt_observation = missing_execution_binding["observations"][0]
    receipt = receipt_observation["baseline_receipt"]
    del receipt["execution_identity"]
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = prefixed_sha256(receipt_body)
    receipt_observation["baseline_receipt_sha256"] = receipt["receipt_sha256"]
    _resign_evidence(missing_execution_binding)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-invalid",
    ):
        _verify_reference_worker_evidence_set(
            missing_execution_binding,
            suite=suite,
            output_root=output_root,
        )

    mixed_execution_binding = deepcopy(evidence)
    receipt_observation = mixed_execution_binding["observations"][0]
    receipt = receipt_observation["baseline_receipt"]
    receipt["execution_identity"]["source_tree"] = "9" * 40
    receipt["execution_identity_sha256"] = prefixed_sha256(receipt["execution_identity"])
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = prefixed_sha256(receipt_body)
    receipt_observation["baseline_receipt_sha256"] = receipt["receipt_sha256"]
    _resign_evidence(mixed_execution_binding)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-receipt-job-mismatch",
    ):
        _verify_reference_worker_evidence_set(
            mixed_execution_binding,
            suite=suite,
            output_root=output_root,
        )

    resigned_observation = deepcopy(evidence)
    stale = next(
        item
        for item in resigned_observation["observations"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1" and item["affected"]
    )
    stale["operation_bytes_read"] += 1
    _resign_evidence(resigned_observation)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-operation-invalid",
    ):
        _verify_reference_worker_evidence_set(
            resigned_observation,
            suite=suite,
            output_root=output_root,
        )

    resigned_cache_proof = deepcopy(evidence)
    stale = next(
        item
        for item in resigned_cache_proof["observations"]
        if item["scenario_id"] == "tos-stale-derivative-cache-v1" and item["affected"]
    )
    operation = stale["cache_invalidation_operation"]
    original_operation_sha256 = operation["operation_sha256"]
    operation["expected_parent_output_sha256"] = _digest("forged-parent-output")
    operation_body = {key: value for key, value in operation.items() if key != "operation_sha256"}
    operation["operation_sha256"] = prefixed_sha256(operation_body)
    operation_ids = resigned_cache_proof["cache_invalidation_operation_sha256"]
    operation_ids[operation_ids.index(original_operation_sha256)] = operation["operation_sha256"]
    _resign_evidence(resigned_cache_proof)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-cache-invalid",
    ):
        _verify_reference_worker_evidence_set(
            resigned_cache_proof,
            suite=suite,
            output_root=output_root,
        )

    resigned_provenance = deepcopy(evidence)
    provenance = resigned_provenance["execution_provenance"]
    provenance["runtime"]["platform_machine"] = "forged-machine"
    provenance_body = {
        key: value for key, value in provenance.items() if key != "provenance_sha256"
    }
    provenance["provenance_sha256"] = prefixed_sha256(provenance_body)
    resigned_provenance["execution_provenance_sha256"] = provenance["provenance_sha256"]
    _resign_evidence(resigned_provenance)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-provenance-invalid",
    ):
        _verify_reference_worker_evidence_set(
            resigned_provenance,
            suite=suite,
            output_root=output_root,
        )

    provenance_path = output_root / "metadata" / "reference-worker-benchmark-provenance.json"
    provenance_bytes = provenance_path.read_bytes()
    provenance_path.unlink()
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-file-unavailable",
    ):
        _verify_reference_worker_evidence_set(
            evidence,
            suite=suite,
            output_root=output_root,
        )
    provenance_path.write_bytes(provenance_bytes)

    persisted_provenance = json.loads(provenance_bytes)
    persisted_provenance["runtime"]["platform_machine"] = "mismatched-machine"
    persisted_body = {
        key: value for key, value in persisted_provenance.items() if key != "provenance_sha256"
    }
    persisted_provenance["provenance_sha256"] = prefixed_sha256(persisted_body)
    provenance_path.write_bytes(canonical_json_bytes(persisted_provenance) + b"\n")
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-evidence-provenance-invalid",
    ):
        _verify_reference_worker_evidence_set(
            evidence,
            suite=suite,
            output_root=output_root,
        )
    provenance_path.write_bytes(provenance_bytes)

    outside_provenance = tmp_path / "outside-provenance.json"
    outside_provenance.write_bytes(provenance_bytes)
    provenance_path.unlink()
    provenance_path.symlink_to(outside_provenance)
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-file-unsafe",
    ):
        _verify_reference_worker_evidence_set(
            evidence,
            suite=suite,
            output_root=output_root,
        )
    provenance_path.unlink()
    provenance_path.write_bytes(provenance_bytes)

    baseline = evidence["observations"][0]["baseline_receipt"]
    output_path = output_root / baseline["output_relative_path"]
    output_path.write_bytes(output_path.read_bytes() + b"tampered")
    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-output-mismatch",
    ):
        _verify_reference_worker_evidence_set(
            evidence,
            suite=suite,
            output_root=output_root,
        )


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
                execution_identity=INJECTED_IDENTITY,
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
            worker=worker,
            suite_preparer=preparer,
            execution_identity=INJECTED_IDENTITY,
        )

    assert worker.calls == 0


def test_injected_worker_requires_explicit_execution_identity(tmp_path: Path) -> None:
    source_root, config_root, output_root = _roots(tmp_path)
    worker = _FakeWorker()
    campaign = _campaign()

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-execution-identity-required",
    ):
        run_reference_worker_benchmark(
            source_root=source_root,
            config_root=config_root,
            output_root=output_root,
            campaign_report=campaign,
            worker=worker,
            suite_preparer=_PreparedSuite(_suite(source_root)),
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


def test_sealed_provenance_cannot_replace_an_existing_record(tmp_path: Path) -> None:
    source_root, _config_root, output_root = _roots(tmp_path)
    suite = _suite(source_root)
    _seal_provenance(
        output_root,
        suite,
        "controlled-receipt-set",
        sealed_suite=False,
        real_worker=False,
        execution_identity=INJECTED_IDENTITY,
    )

    with pytest.raises(
        ReferenceWorkerBenchmarkError,
        match="reference-benchmark-existing-output-conflict",
    ):
        _seal_provenance(
            output_root,
            suite,
            "controlled-receipt-set",
            sealed_suite=True,
            real_worker=False,
            execution_identity=INJECTED_IDENTITY,
        )
