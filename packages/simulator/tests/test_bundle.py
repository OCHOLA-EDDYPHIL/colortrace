from __future__ import annotations

import copy
import hashlib
import multiprocessing
import os
import shutil
import stat
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any

import colortrace_simulator.bundle as bundle_module
import pytest
from colortrace_fixture.fixture import (  # type: ignore[import-untyped]
    CANONICAL_SEED,
    build_scenario,
)
from colortrace_simulator.bundle import (
    LocalPublicationPort,
    SimulatorBundleError,
    canonical_json_bytes,
)
from colortrace_simulator.models import BoundSimulatorAction, DispatchIdentity
from colortrace_simulator.renderer import sha256_bytes


def _digest(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def _raw_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_canonical(path: Path, value: Any) -> str:
    raw = canonical_json_bytes(value)
    path.chmod(0o600)
    path.write_bytes(raw)
    return _raw_digest(raw)


@pytest.fixture(scope="session")
def canonical_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("simulator-fixture")
    fixture = root / "bundle"
    build_scenario(
        fixture,
        oracle_root=root / "oracle",
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    return fixture


def _copy_mutable(source: Path, target: Path) -> Path:
    shutil.copytree(source, target, copy_function=shutil.copyfile)
    for directory, child_directories, files in os.walk(target):
        current = Path(directory)
        current.chmod(0o700)
        for child in child_directories:
            (current / child).chmod(0o700)
        for filename in files:
            (current / filename).chmod(0o600)
    return target


def _action(plan: dict[str, Any], operation_id: str = "operation-1") -> BoundSimulatorAction:
    commands = tuple(plan["commands"])
    targets = tuple(plan["targets"])
    exclusions = tuple(plan["exclusions"])
    return BoundSimulatorAction(
        action_id=f"action-{operation_id}",
        identity=DispatchIdentity(
            task_key=f"task-{operation_id}",
            operation_id=operation_id,
            payload_sha256="sha256:" + "1" * 64,
        ),
        incident_id="incident-1",
        incident_version=7,
        plan_id="plan-1",
        plan_version=3,
        plan_sha256="sha256:" + "2" * 64,
        approval_id="approval-1",
        approval_sha256="sha256:" + "3" * 64,
        authorization_id="authorization-1",
        authorization_sha256="sha256:" + "4" * 64,
        consumption_id="consumption-1",
        consumption_sha256="sha256:" + "5" * 64,
        action_envelope_sha256=_digest(plan["envelope"]),
        commands_sha256=_digest(list(commands)),
        targets_sha256=_digest(list(targets)),
        exclusions_sha256=_digest(list(exclusions)),
        commands=commands,
        targets=targets,
        exclusions=exclusions,
        dispatch_bundle_sha256="sha256:" + "6" * 64,
    )


def _traces(action: BoundSimulatorAction) -> dict[str, str]:
    return {
        str(command["command_id"]): hashlib.sha256(
            f"trace:{action.identity.operation_id}:{command['command_id']}".encode()
        ).hexdigest()[:32]
        for command in action.commands
    }


def _port(tmp_path: Path, canonical_bundle: Path, **kwargs: Any) -> LocalPublicationPort:
    return LocalPublicationPort.bootstrap(
        root=tmp_path / "workspace",
        fixture_bundle=canonical_bundle,
        **kwargs,
    )


def _prepare(
    port: LocalPublicationPort,
    operation_id: str = "operation-1",
) -> tuple[BoundSimulatorAction, Any, Any]:
    plan = port.canonical_plan_inputs()
    action = _action(plan, operation_id)
    snapshot = port.snapshot_for_action(action)
    return action, snapshot, port.prepare(snapshot, _traces(action))


def _recovery_outcome(action: BoundSimulatorAction, prepared: Any) -> dict[str, Any]:
    body = {
        "schema": "simulator-action-outcome/v1",
        "action_id": f"simulator-action:{'a' * 64}",
        "task_key": f"dispatch-task:{'b' * 64}",
        "operation_id": action.identity.operation_id,
        "payload_sha256": action.identity.payload_sha256,
        "status": "succeeded",
        "reason_codes": [],
        "incident_id": action.incident_id,
        "incident_version": action.incident_version,
        "plan_id": action.plan_id,
        "plan_version": action.plan_version,
        "plan_sha256": action.plan_sha256,
        "approval_id": action.approval_id,
        "approval_sha256": action.approval_sha256,
        "authorization_id": action.authorization_id,
        "authorization_sha256": action.authorization_sha256,
        "consumption_id": action.consumption_id,
        "consumption_sha256": action.consumption_sha256,
        "admission_id": f"simulator-admission:{'c' * 64}",
        "admission_sha256": f"sha256:{'c' * 64}",
        "dispatch_bundle_sha256": action.dispatch_bundle_sha256,
        "action_envelope_sha256": action.action_envelope_sha256,
        "action_started_at": "2026-08-13T12:00:00.000Z",
        "publication_intent_id": f"simulator-publication-intent:{'d' * 64}",
        "publication_intent_sha256": f"sha256:{'d' * 64}",
        "publication_receipt_id": f"simulator-publication-receipt:{'e' * 64}",
        "publication_receipt_sha256": f"sha256:{'e' * 64}",
        "publication_promoted_at": "2026-08-13T12:00:01.000Z",
        "completed_at": "2026-08-13T12:00:02.000Z",
        "fixture_id": "colortrace-canonical",
        "predecessor_publication_pointer_sha256": prepared.predecessor_pointer_sha256,
        "predecessor_publication_generation": prepared.predecessor_generation,
        "candidate_publication_pointer_sha256": prepared.candidate_pointer_sha256,
        "candidate_publication_generation": prepared.candidate_generation,
        "source_generation": prepared.predecessor_generation,
        "candidate_generation": prepared.candidate_generation,
        "source_batch_id": prepared.source_batch_id,
        "source_batch_sha256": prepared.source_batch_sha256,
        "active_publication_pointer_sha256": prepared.candidate_pointer_sha256,
        "active_runtime_manifest_sha256": prepared.candidate_runtime_manifest_sha256,
        "candidate_fixture_manifest_sha256": prepared.candidate_fixture_manifest_sha256,
        "candidate_runtime_manifest_sha256": prepared.candidate_runtime_manifest_sha256,
        "candidate_lineage_manifest_sha256": prepared.candidate_lineage_manifest_sha256,
        "declared_resource_manifest_sha256": prepared.declared_resource_manifest_sha256,
        "preservation_manifest_sha256": prepared.preservation_manifest_sha256,
        "safe_complement_before_sha256": prepared.safe_complement_before_sha256,
        "safe_complement_after_sha256": prepared.safe_complement_after_sha256,
        "safe_complement_proof_sha256": prepared.safe_complement_proof_sha256,
        "candidate_seal_sha256": prepared.candidate_seal_sha256,
        "candidate_tree_sha256": prepared.candidate_tree_sha256,
        "targets": list(action.targets),
        "exclusions": list(action.exclusions),
        "command_outcomes": list(prepared.command_results),
        "new_trace_ids": sorted(result["trace_id"] for result in prepared.command_results),
    }
    outcome_sha256 = _digest(body)
    return {
        **body,
        "outcome_id": f"simulator-action-outcome:{outcome_sha256.removeprefix('sha256:')}",
        "outcome_sha256": outcome_sha256,
    }


def _promoted_recovery(
    port: LocalPublicationPort,
    operation_marker: str,
) -> tuple[dict[str, Any], Any]:
    operation_id = f"dispatch-operation:{operation_marker * 64}"
    action, _snapshot, prepared = _prepare(port, operation_id)
    return _finish_promoted_recovery(port, action, prepared)


def _finish_promoted_recovery(
    port: LocalPublicationPort,
    action: BoundSimulatorAction,
    prepared: Any,
) -> tuple[dict[str, Any], Any]:
    assert port.compare_and_swap(prepared).state == "promoted"
    outcome = _recovery_outcome(action, prepared)
    return outcome, port.snapshot_for_recovery(outcome)


def test_canonical_targeted_recovery_promotes_once_and_preserves_safe_work(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    plan = port.canonical_plan_inputs()
    assert len(plan["commands"]) == 5
    assert len(plan["targets"]) == 5
    assert len(plan["exclusions"]) == 3
    intent = [
        {key: value for key, value in command.items() if key != "action_envelope"}
        for command in plan["commands"]
    ]
    intent.sort(key=lambda command: str(command["command_id"]))
    assert plan["preservation_manifest"]["command_intent_sha256"] == _digest(intent)
    assert _digest(intent) != _digest(plan["commands"])

    action = _action(plan)
    snapshot = port.snapshot_for_action(action)
    prepared = port.prepare(snapshot, _traces(action))
    assert prepared.candidate_generation == 2
    assert prepared.safe_complement_before_sha256 == prepared.safe_complement_after_sha256
    assert len(prepared.command_results) == 5
    assert {result["result_kind"] for result in prepared.command_results} == {
        "quarantine",
        "frame",
        "derivative",
    }
    assert all(
        set(result)
        == {"schema", "command_id", "result_kind", "target", "trace_id", "before", "after"}
        for result in prepared.command_results
    )
    assert set(prepared.quarantine) == {
        "schema",
        "logical_path",
        "source_generation",
        "resource_sha256",
        "replacement_sha256",
        "quarantine_path",
        "size",
    }
    assert prepared.quarantine["quarantine_path"].startswith("runtime/quarantine/sha256/")

    promoted = port.compare_and_swap(prepared)
    assert promoted.state == "promoted"
    assert promoted.pointer_changed is True
    replay = port.compare_and_swap(prepared)
    assert replay.state == "already-promoted"
    assert replay.before_pointer_sha256 == replay.after_pointer_sha256
    assert replay.before_generation == replay.after_generation == 2
    inspected = port.inspect_operation(action.identity.operation_id)
    assert inspected.state == "promoted"
    assert inspected.prepared is not None
    assert inspected.prepared.candidate_seal_sha256 == prepared.candidate_seal_sha256


def test_authored_scenario_reset_is_response_loss_safe_and_replay_exact(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    _action_value, _snapshot, prepared = _prepare(port)
    assert port.compare_and_swap(prepared).state == "promoted"
    with pytest.raises(SimulatorBundleError, match="canonical-causal-resource-ambiguous"):
        port.canonical_plan_inputs()

    def lose_response(point: str) -> None:
        if point == "active-pointer-replaced":
            raise RuntimeError("simulated reset response loss")

    port.fault_hook = lose_response
    with pytest.raises(RuntimeError, match="simulated reset response loss"):
        port.restore_authored_scenario(operation_id="reset-operation-1")
    port.fault_hook = lambda _point: None

    replayed = port.restore_authored_scenario(operation_id="reset-operation-1")
    repeated = port.restore_authored_scenario(operation_id="reset-operation-1")

    assert replayed == repeated
    assert replayed["previous_pointer_sha256"] == prepared.candidate_pointer_sha256
    assert replayed["active_pointer_sha256"] == prepared.predecessor_pointer_sha256
    assert replayed["generation"] == 1
    assert len(port.canonical_plan_inputs()["commands"]) == 5


@pytest.mark.parametrize(
    ("fault_point", "expected_state"),
    [
        ("candidate-publication-durable", "sealed"),
        ("candidate-promotion-durable", "promoted"),
    ],
)
def test_crash_recovery_reconciles_exact_sealed_candidate(
    tmp_path: Path,
    canonical_bundle: Path,
    fault_point: str,
    expected_state: str,
) -> None:
    class Fault:
        armed = False

        def __call__(self, point: str) -> None:
            if self.armed and point == fault_point:
                self.armed = False
                raise RuntimeError(point)

    fault = Fault()
    port = _port(tmp_path, canonical_bundle, fault_hook=fault)
    action, _snapshot, prepared = _prepare(port, f"operation-{expected_state}")
    fault.armed = True
    with pytest.raises(RuntimeError, match=fault_point):
        port.compare_and_swap(prepared)

    recovered = LocalPublicationPort(tmp_path / "workspace")
    observed = recovered.inspect_operation(action.identity.operation_id)
    assert observed.state == expected_state
    result = recovered.compare_and_swap(prepared)
    assert result.state in {"promoted", "already-promoted"}
    if result.state == "already-promoted":
        assert result.promoted_at == result.observed_at
        assert result.promoted_at is not None
        assert result.promoted_at >= prepared.prepared_at
    final = recovered.inspect_operation(action.identity.operation_id)
    assert final.state == "promoted"
    assert final.prepared is not None
    assert final.prepared.publication_id == prepared.publication_id
    assert final.prepared.candidate_seal_sha256 == prepared.candidate_seal_sha256
    assert final.prepared.candidate_pointer_sha256 == prepared.candidate_pointer_sha256


def test_abrupt_process_death_reclaims_partial_stage_under_operation_lock(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    workspace = tmp_path / "workspace-abrupt"
    port = LocalPublicationPort.bootstrap(root=workspace, fixture_bundle=canonical_bundle)
    plan = port.canonical_plan_inputs()
    action = _action(plan, "operation-abrupt")
    traces = _traces(action)

    def killed_writer() -> None:
        def kill(point: str) -> None:
            if point == "candidate-copied":
                os._exit(17)

        child_port = LocalPublicationPort(workspace, fault_hook=kill)
        child_port.prepare(child_port.snapshot_for_action(action), traces)

    process = multiprocessing.get_context("fork").Process(target=killed_writer)
    process.start()
    process.join(timeout=30)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        pytest.fail("abrupt writer did not terminate")
    assert process.exitcode == 17
    token = hashlib.sha256(action.identity.operation_id.encode()).hexdigest()
    partial = workspace / "staging" / f"prep-{token}"
    assert partial.is_dir()
    assert not (partial / "manifests/candidate-seal.json").exists()

    recovered = LocalPublicationPort(workspace)
    prepared = recovered.prepare(recovered.snapshot_for_action(action), traces)
    assert prepared.operation_id == action.identity.operation_id
    assert recovered.inspect_operation(action.identity.operation_id).state == "staged"


def test_prepare_operation_lock_does_not_invert_publication_cas_lock(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    plan = port.canonical_plan_inputs()
    action = _action(plan, "operation-lock-order")
    snapshot = port.snapshot_for_action(action)
    publication_locked = threading.Event()
    prepare_pulsed = threading.Event()
    observed: list[bool] = []

    def hold_publication_lock() -> None:
        with port._publication_lock():
            publication_locked.set()
            observed.append(prepare_pulsed.wait(timeout=2))

    holder = threading.Thread(target=hold_publication_lock, daemon=True)
    holder.start()
    assert publication_locked.wait(timeout=2)

    def pulse() -> None:
        prepare_pulsed.set()
        raise SimulatorBundleError("lock-order-probe")

    with pytest.raises(SimulatorBundleError, match="lock-order-probe"):
        port.prepare(snapshot, _traces(action), heartbeat=pulse)
    holder.join(timeout=2)
    assert not holder.is_alive()
    assert observed == [True]


def test_recovery_closure_guard_accepts_exact_current_snapshot(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    outcome, recovery = _promoted_recovery(port, "a")

    entered = False
    with port.guard_recovery_closure(recovery, outcome):
        entered = True

    assert entered is True


def test_recovery_closure_guard_rejects_snapshot_after_newer_publication(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    action, _snapshot, prepared = _prepare(port, f"dispatch-operation:{'a' * 64}")
    _next_action, _next_snapshot, next_prepared = _prepare(
        port,
        f"dispatch-operation:{'b' * 64}",
    )
    outcome, recovery = _finish_promoted_recovery(port, action, prepared)
    next_publication = port._publication_root(next_prepared.publication_id)
    with port._publication_lock():
        bundle_module._rename_frozen_tree(
            port.root / next_prepared.candidate_ref,
            next_publication,
        )
        assert (
            port._write_active_pointer(next_prepared.candidate_pointer)
            == next_prepared.candidate_pointer_sha256
        )
        assert port._load_active_context().pointer_sha256 == (
            next_prepared.candidate_pointer_sha256
        )

    with pytest.raises(SimulatorBundleError, match="recovery-snapshot-stale"):
        with port.guard_recovery_closure(recovery, outcome):
            pytest.fail("stale recovery snapshot entered the closure guard")


def test_recovery_closure_guard_serializes_concurrent_publication(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    action, _snapshot, prepared = _prepare(port, f"dispatch-operation:{'a' * 64}")
    _next_action, _next_snapshot, next_prepared = _prepare(
        port,
        f"dispatch-operation:{'b' * 64}",
    )
    outcome, recovery = _finish_promoted_recovery(port, action, prepared)
    started = threading.Event()
    completed = threading.Event()
    promotions: list[Any] = []

    def promote() -> None:
        started.set()
        promotions.append(port.compare_and_swap(next_prepared))
        completed.set()

    worker = threading.Thread(target=promote, daemon=True)
    with port.guard_recovery_closure(recovery, outcome):
        worker.start()
        assert started.wait(timeout=2)
        assert not completed.wait(timeout=0.1)
        assert port._load_active_context().pointer_sha256 == recovery._active_pointer_sha256
    assert completed.wait(timeout=5)
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert [promotion.state for promotion in promotions] == ["conflict"]


def test_active_candidate_rejects_leaf_tamper_and_missing_control(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    action, snapshot, prepared = _prepare(port, "operation-integrity")
    assert port.compare_and_swap(prepared).state == "promoted"
    publication = (
        tmp_path
        / "workspace"
        / "publications"
        / f"pub-{prepared.publication_id.removeprefix('publication:')}"
    )

    safe_path = publication / str(snapshot.safe_complement_manifest["files"][0]["path"])
    safe_raw = safe_path.read_bytes()
    safe_path.chmod(0o600)
    safe_path.write_bytes(safe_raw + b"tamper")
    with pytest.raises(SimulatorBundleError):
        port.inspect_operation(action.identity.operation_id)
    safe_path.write_bytes(safe_raw)
    safe_path.chmod(0o400)

    manifests = publication / "manifests"
    proof = manifests / "safe-complement-proof.json"
    proof_raw = proof.read_bytes()
    manifests.chmod(0o700)
    proof.unlink()
    with pytest.raises(SimulatorBundleError):
        port.inspect_operation(action.identity.operation_id)
    proof.write_bytes(proof_raw)
    proof.chmod(0o400)
    manifests.chmod(0o500)
    assert port.inspect_operation(action.identity.operation_id).state == "promoted"


@pytest.mark.parametrize("record_kind", ["resource", "derivative"])
def test_trace_ids_are_fresh_across_every_persisted_action_record(
    tmp_path: Path,
    canonical_bundle: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_kind: str,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    plan = port.canonical_plan_inputs()
    action = _action(plan, f"operation-trace-{record_kind}")
    snapshot = port.snapshot_for_action(action)
    context = port._load_active_context()
    runtime = copy.deepcopy(context.runtime)
    reused = "a" * 32 if record_kind == "resource" else "b" * 32
    if record_kind == "resource":
        causal = plan["envelope"]["expected_resource_sha256"]
        next(item for item in runtime["resources"] if item["resource_sha256"] == causal)[
            "trace_id"
        ] = reused
    else:
        runtime["derivatives"][0]["trace_id"] = reused
    monkeypatch.setattr(port, "_load_active_context", lambda: replace(context, runtime=runtime))
    traces = _traces(action)
    traces[next(iter(traces))] = reused
    with pytest.raises(SimulatorBundleError, match="trace-id-not-fresh"):
        port.prepare(snapshot, traces)


def test_all_zero_trace_id_is_rejected_before_candidate_creation(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    plan = port.canonical_plan_inputs()
    action = _action(plan, "operation-zero-trace")
    snapshot = port.snapshot_for_action(action)
    traces = _traces(action)
    traces[next(iter(traces))] = "0" * 32

    with pytest.raises(SimulatorBundleError, match="trace-id-invalid"):
        port.prepare(snapshot, traces)
    assert list((tmp_path / "workspace/staging").iterdir()) == []


def test_stale_action_envelope_changes_no_publication_state(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    before = (tmp_path / "workspace/state/active.json").read_bytes()
    plan = copy.deepcopy(port.canonical_plan_inputs())
    plan["envelope"]["expected_publication_generation"] += 1
    for command in plan["commands"]:
        command["action_envelope"] = plan["envelope"]
    action = _action(plan, "operation-stale")
    with pytest.raises(SimulatorBundleError, match="action-envelope-stale"):
        port.snapshot_for_action(action)
    assert (tmp_path / "workspace/state/active.json").read_bytes() == before
    assert list((tmp_path / "workspace/staging").iterdir()) == []


def test_competing_sealed_candidate_loses_compare_and_swap_without_pointer_change(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    port = _port(tmp_path, canonical_bundle)
    plan = port.canonical_plan_inputs()
    first = _action(plan, "operation-winner")
    second = _action(plan, "operation-loser")
    first_prepared = port.prepare(port.snapshot_for_action(first), _traces(first))
    second_prepared = port.prepare(port.snapshot_for_action(second), _traces(second))
    winner = port.compare_and_swap(first_prepared)
    assert winner.state == "promoted"
    loser = port.compare_and_swap(second_prepared)
    assert loser.state == "conflict"
    assert loser.pointer_changed is False
    assert loser.before_pointer_sha256 == winner.after_pointer_sha256
    assert loser.before_pointer_sha256 == loser.after_pointer_sha256
    assert port.inspect_operation(second.identity.operation_id).state == "conflict"
    port.discard(second_prepared)
    assert port.inspect_operation(second.identity.operation_id).state == "not-found"
    assert list((tmp_path / "workspace/staging").iterdir()) == []


def test_cleanup_unlinks_injected_symlink_without_touching_target(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside.txt"
    outside.write_text("do not touch", encoding="utf-8")
    outside.chmod(0o640)

    class Injector:
        armed = False
        stage: Path | None = None

        def __call__(self, point: str) -> None:
            if self.armed and point == "candidate-copied":
                assert self.stage is not None
                os.symlink(outside, self.stage / "injected-link")
                raise RuntimeError("injected-fault")

    injector = Injector()
    port = LocalPublicationPort.bootstrap(
        root=workspace,
        fixture_bundle=canonical_bundle,
        fault_hook=injector,
    )
    plan = port.canonical_plan_inputs()
    action = _action(plan, "operation-cleanup")
    snapshot = port.snapshot_for_action(action)
    token = hashlib.sha256(action.identity.operation_id.encode()).hexdigest()
    injector.stage = workspace / "staging" / f"prep-{token}"
    injector.armed = True
    with pytest.raises(RuntimeError, match="injected-fault"):
        port.prepare(snapshot, _traces(action))
    assert injector.stage.exists() is False
    assert outside.read_text(encoding="utf-8") == "do not touch"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o640


def test_source_admission_rejects_unreferenced_runtime_file(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    fixture = _copy_mutable(canonical_bundle, tmp_path / "fixture-extra")
    (fixture / "runtime" / "unreferenced.bin").write_bytes(b"not manifest bound")
    with pytest.raises(SimulatorBundleError, match="fixture-file-closure-mismatch"):
        LocalPublicationPort.bootstrap(
            root=tmp_path / "workspace-extra",
            fixture_bundle=fixture,
        )


def test_source_admission_rejects_ambiguous_approved_resources(
    tmp_path: Path,
    canonical_bundle: Path,
) -> None:
    fixture = _copy_mutable(canonical_bundle, tmp_path / "fixture-ambiguous")
    approved_path = fixture / "runtime/workers/A/config/luts/show_look.cube"
    shadowed_path = fixture / "runtime/workers/B/config/luts/show_look.cube"
    approved = approved_path.read_bytes()
    shadowed_path.write_bytes(approved)
    approved_sha256 = _raw_digest(approved)

    fixture_path = fixture / "runtime/manifests/fixture-runtime-manifest.json"
    fixture_document = bundle_module._strict_json(fixture_path.read_bytes())
    for pointer in fixture_document["jobs"]:
        if not str(pointer["job_id"]).startswith("job-b-"):
            continue
        job_path = fixture / pointer["manifest"]
        job = bundle_module._strict_json(job_path.read_bytes())
        resource_path = fixture / job["resource_manifest"]
        resource = bundle_module._strict_json(resource_path.read_bytes())
        for entry in resource["ordered_resources"]:
            entry["sha256"] = approved_sha256
            entry["size"] = len(approved)
        job["resource_manifest_sha256"] = _write_canonical(resource_path, resource)
        pointer["sha256"] = _write_canonical(job_path, job)

    provenance_path = fixture / fixture_document["provenance"]["manifest"]
    provenance = bundle_module._strict_json(provenance_path.read_bytes())
    lut_asset = next(
        asset
        for asset in provenance["assets"]
        if asset.get("path") == "runtime/workers/B/config/luts/show_look.cube"
    )
    lut_asset["sha256"] = approved_sha256
    fixture_document["provenance"]["sha256"] = _write_canonical(
        provenance_path,
        provenance,
    )
    _write_canonical(fixture_path, fixture_document)

    with pytest.raises(SimulatorBundleError, match="approved-resource-ambiguous"):
        LocalPublicationPort.bootstrap(
            root=tmp_path / "workspace-ambiguous",
            fixture_bundle=fixture,
        )


def test_workspace_rejects_wrong_owner_identity_simulation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace-owner"
    workspace.mkdir(mode=0o700)
    actual_uid = os.getuid()
    monkeypatch.setattr(os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(SimulatorBundleError, match="workspace-owner-invalid"):
        LocalPublicationPort(workspace)
