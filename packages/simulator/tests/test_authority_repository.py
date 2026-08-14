from __future__ import annotations

import copy
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from colortrace_fixture.fixture import (  # type: ignore[import-untyped]
    CANONICAL_SEED,
    build_scenario,
)
from colortrace_response_plans import ResponsePlanError
from colortrace_response_plans.contracts import (
    build_audit_event,
    build_decision,
    build_dispatch_authorization,
    build_dispatch_consumption,
    build_plan,
    canonical_json_bytes,
    prefixed_sha256,
)
from colortrace_simulator.authority import (
    SIMULATOR_EXECUTOR_ROLE,
    SimulatorAuthorityBoundary,
    SimulatorAuthorityError,
    SimulatorExecutorBoundary,
)
from colortrace_simulator.bundle import LocalPublicationPort, SimulatorBundleError
from colortrace_simulator.models import (
    DispatchIdentity,
    PreparedPublication,
    PromotionResult,
    PublicationOperationState,
    StoredDispatchProof,
)
from colortrace_simulator.repository import SimulatorRepositoryError, SQLiteSimulatorRepository
from colortrace_simulator.service import SimulatorActionService
from colortrace_telemetry import MemoryActionTelemetrySink, emit_action_outcome

NOW = datetime(2026, 8, 13, 21, 0, tzinfo=UTC)
NOW_TEXT = "2026-08-13T21:00:00.000Z"
HUMAN = {
    "issuer": "https://identity.example.test",
    "subject": "operator",
    "audience": "colortrace-api",
    "kind": "human",
}
SERVICE = {
    "issuer": "https://identity.example.test",
    "subject": "dispatcher",
    "audience": "colortrace-api",
    "kind": "service",
}
EXECUTOR = {
    "issuer": "https://identity.example.test",
    "subject": "simulator-worker",
    "audience": "colortrace-api",
    "kind": "service",
}


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def target(kind: str, identifier: str) -> dict[str, str]:
    return {
        "schema": "simulator-target/v1",
        "namespace": "colortrace-simulator",
        "kind": kind,
        "id": identifier,
    }


def pointer(generation: int, marker: str) -> dict[str, Any]:
    return {
        "schema": "simulator-publication-pointer/v1",
        "operation_id": f"publication-{marker}",
        "generation": generation,
        "runtime_manifest_sha256": digest(marker),
    }


def plan_inputs() -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, Any]]]:
    predecessor = pointer(7, "3")
    predecessor_sha256 = prefixed_sha256(canonical_json_bytes(predecessor))
    envelope = {
        "schema": "simulator-action-envelope/v1",
        "fixture_id": "colortrace-canonical",
        "fixture_manifest_sha256": digest("0"),
        "fixture_generation": 7,
        "source_batch_id": "fixture-run-canonical",
        "source_batch_sha256": digest("1"),
        "runtime_manifest_sha256": digest("2"),
        "runtime_generation": 7,
        "expected_publication_pointer_sha256": predecessor_sha256,
        "expected_publication_generation": 7,
        "expected_resource_sha256": digest("a"),
        "replacement_resource_logical_path": "luts/show_look.cube",
        "replacement_resource_sha256": digest("4"),
        "declared_resource_manifest_sha256": digest("5"),
        "ocio_version": "2.5.2",
        "preservation_manifest_sha256": digest("6"),
        "safe_complement_sha256": digest("7"),
        "lineage_manifest_sha256": digest("8"),
        "lineage_generation": 7,
    }
    targets = [
        target("color-resource", digest("a")),
        target("frame", "frame-a"),
        target("frame", "frame-b"),
        target("frame", "frame-c"),
        target("derivative", "derivative-a"),
    ]
    exclusions = [target("frame", "frame-safe")]
    commands: list[dict[str, Any]] = [
        {
            "schema": "simulator-quarantine-command/v1",
            "command_id": "command-0-quarantine",
            "namespace": "colortrace-simulator",
            "target": targets[0],
            "action_envelope": envelope,
            "expected_resource_sha256": digest("a"),
            "mode": "quarantine-and-install-approved-replacement",
        }
    ]
    for index, selected in enumerate(targets[1:4], start=1):
        commands.append(
            {
                "schema": "simulator-targeted-rerender-command/v1",
                "command_id": f"command-{index}-frame",
                "namespace": "colortrace-simulator",
                "target": selected,
                "action_envelope": envelope,
                "job_id": f"job-{index}",
                "transform_id": "look/main/v1",
                "source_id": f"source-{index}",
                "source_manifest_sha256": digest("9"),
                "source_png_sha256": digest("b"),
                "expected_config_sha256": digest("c"),
                "expected_output_sha256": digest("d"),
                "expected_display_sha256": digest("e"),
                "lineage_parent_artifact_id": f"source-{index}",
            }
        )
    commands.append(
        {
            "schema": "simulator-targeted-rerender-command/v1",
            "command_id": "command-4-derivative",
            "namespace": "colortrace-simulator",
            "target": targets[4],
            "action_envelope": envelope,
            "job_id": "job-derivative",
            "transform_id": "look/main/v1",
            "source_id": "source-derivative",
            "source_manifest_sha256": digest("9"),
            "source_png_sha256": digest("d"),
            "expected_config_sha256": digest("e"),
            "expected_derivative_sha256": digest("f"),
            "expected_derivative_display_sha256": digest("0"),
            "lineage_parent_artifact_id": "frame-a",
        }
    )
    return targets, exclusions, commands


def dispatch_proof(
    inputs: tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, Any]]] | None = None,
) -> tuple[DispatchIdentity, StoredDispatchProof]:
    targets, exclusions, commands = plan_inputs() if inputs is None else inputs
    packet_sha = digest("6")
    plan = build_plan(
        incident_id="incident-simulator",
        incident_version=7,
        version=1,
        previous_plan_sha256=None,
        response_packet_id=f"response-packet:{packet_sha.removeprefix('sha256:')}",
        response_packet_sha256=packet_sha,
        deterministic_scope_sha256=digest("7"),
        targets=targets,
        exclusions=exclusions,
        commands=commands,
        unresolved_item_ids=(),
        blocking_unresolved_item_ids=(),
        unknown_target_ids=(),
        unresolved_acknowledged=False,
        created_by=HUMAN,
        created_at=NOW_TEXT,
    )
    approval = build_decision(
        plan=plan,
        outcome="approved",
        actor=HUMAN,
        idempotency_key="approve-simulator-plan",
        decided_at="2026-08-13T21:00:01.000Z",
        reason_code=None,
    )
    authorization = build_dispatch_authorization(
        plan=plan,
        approval=approval,
        actor=SERVICE,
        idempotency_key="authorize-simulator-plan",
        authorized_at="2026-08-13T21:00:02.000Z",
    )
    consumption = build_dispatch_consumption(
        authorization=authorization,
        plan=plan,
        approval=approval,
        actor=SERVICE,
        idempotency_key="consume-simulator-plan",
        consumed_at="2026-08-13T21:00:03.000Z",
    )
    records = {
        plan["plan_sha256"]: plan,
        approval["decision_sha256"]: approval,
        authorization["authorization_sha256"]: authorization,
        consumption["consumption_sha256"]: consumption,
    }
    events: list[dict[str, Any]] = []
    event_inputs = (
        ("plan.created", plan, plan["plan_sha256"], HUMAN, "create-simulator-plan", NOW_TEXT),
        (
            "plan.approved",
            approval,
            approval["decision_sha256"],
            HUMAN,
            "approve-simulator-plan",
            "2026-08-13T21:00:01.000Z",
        ),
        (
            "dispatch.authorized",
            authorization,
            authorization["authorization_sha256"],
            SERVICE,
            "authorize-simulator-plan",
            "2026-08-13T21:00:02.000Z",
        ),
        (
            "dispatch.consumed",
            consumption,
            consumption["consumption_sha256"],
            SERVICE,
            "consume-simulator-plan",
            "2026-08-13T21:00:03.000Z",
        ),
    )
    for event_type, _record, record_sha, actor, key, occurred_at in event_inputs:
        events.append(
            build_audit_event(
                previous=None if not events else events[-1],
                event_type=event_type,
                incident_id=plan["incident_id"],
                plan_id=plan["plan_id"],
                plan_version=plan["version"],
                plan_sha256=plan["plan_sha256"],
                record_sha256=record_sha,
                actor=actor,
                idempotency_key=key,
                occurred_at=occurred_at,
            )
        )
    identity = DispatchIdentity(
        task_key=authorization["task_key"],
        operation_id=authorization["operation_id"],
        payload_sha256=authorization["payload_sha256"],
    )
    return identity, StoredDispatchProof(
        plan=plan,
        approval=approval,
        authorization=authorization,
        consumption=consumption,
        audit_events=tuple(events),
        records=records,
        trusted_audit_head_sha256=events[-1]["event_sha256"],
    )


def prepared_publication(action: Any) -> PreparedPublication:
    _, _, commands = plan_inputs()
    predecessor = pointer(7, "3")
    candidate = pointer(8, "4")
    results: list[dict[str, Any]] = []
    for index, command in enumerate(commands):
        kind = command["target"]["kind"]
        if kind == "color-resource":
            result_kind = "quarantine"
            before = {"resource_sha256": digest("a")}
            after = {"resource_sha256": digest("4")}
        elif kind == "frame":
            result_kind = "frame"
            before = {"output_sha256": digest("d"), "display_sha256": digest("e")}
            after = {"output_sha256": digest("1"), "display_sha256": digest("2")}
        else:
            result_kind = "derivative"
            before = {
                "derivative_sha256": digest("f"),
                "derivative_display_sha256": digest("0"),
            }
            after = {
                "derivative_sha256": digest("3"),
                "derivative_display_sha256": digest("4"),
            }
        results.append(
            {
                "schema": "simulator-command-result/v1",
                "command_id": command["command_id"],
                "result_kind": result_kind,
                "target": command["target"],
                "trace_id": f"{index + 1:032x}",
                "before": before,
                "after": after,
            }
        )
    return PreparedPublication(
        operation_id=action.identity.operation_id,
        publication_id="publication-candidate-8",
        predecessor_pointer=predecessor,
        predecessor_pointer_sha256=prefixed_sha256(canonical_json_bytes(predecessor)),
        predecessor_generation=7,
        candidate_generation=8,
        source_batch_id="fixture-run-canonical",
        source_batch_sha256=digest("1"),
        candidate_fixture_manifest_sha256=digest("c"),
        candidate_runtime_manifest_sha256=digest("4"),
        candidate_lineage_manifest_sha256=digest("5"),
        declared_resource_manifest_sha256=digest("5"),
        preservation_manifest_sha256=digest("6"),
        safe_complement_before_sha256=digest("7"),
        safe_complement_after_sha256=digest("7"),
        safe_complement_proof_sha256=digest("8"),
        candidate_seal_sha256=digest("9"),
        candidate_tree_sha256=digest("b"),
        candidate_ref="runtime/publications/publication-candidate-8",
        quarantine={
            "schema": "simulator-quarantine-result/v1",
            "logical_path": "luts/show_look.cube",
            "source_generation": 7,
            "resource_sha256": digest("a"),
            "replacement_sha256": digest("4"),
            "quarantine_path": f"runtime/quarantine/sha256/{'a' * 64}.cube",
            "size": 128,
        },
        command_results=tuple(results),
        candidate_pointer=candidate,
        candidate_pointer_sha256=prefixed_sha256(canonical_json_bytes(candidate)),
        prepared_at="2026-08-13T21:00:06.000Z",
    )


def bound_bundle() -> Any:
    identity, proof = dispatch_proof()
    return SimulatorAuthorityBoundary().bind(identity, proof)


def test_authority_binds_only_exact_current_consumed_dispatch() -> None:
    identity, proof = dispatch_proof()
    bundle = SimulatorAuthorityBoundary().bind(identity, proof)
    assert bundle.action.identity == identity
    assert bundle.action.commands_sha256 == prefixed_sha256(
        canonical_json_bytes(proof.authorization["commands"])
    )
    assert SIMULATOR_EXECUTOR_ROLE == "simulator.executor"

    forged = DispatchIdentity(identity.task_key, identity.operation_id, digest("0"))
    with pytest.raises(SimulatorAuthorityError, match="dispatch-identity-conflict"):
        SimulatorAuthorityBoundary().bind(forged, proof)

    missing = copy.deepcopy(proof)
    missing = StoredDispatchProof(
        plan=missing.plan,
        approval=missing.approval,
        authorization=missing.authorization,
        consumption=missing.consumption,
        audit_events=missing.audit_events[:-1],
        records={
            key: value for key, value in missing.records.items() if value != missing.consumption
        },
        trusted_audit_head_sha256=missing.audit_events[-2]["event_sha256"],
    )
    with pytest.raises(SimulatorAuthorityError, match="dispatch-source-event-invalid"):
        SimulatorAuthorityBoundary().bind(identity, missing)

    targets, exclusions, commands = plan_inputs()
    unsupported_identity, unsupported = dispatch_proof((targets[:2], exclusions, commands[:2]))
    with pytest.raises(SimulatorAuthorityError, match="dispatch-profile-invalid"):
        SimulatorAuthorityBoundary().bind(unsupported_identity, unsupported)


def test_executor_capability_is_service_role_incident_bound() -> None:
    boundary = SimulatorExecutorBoundary()
    authorization = boundary.bind_verified_service(
        incident_id="incident-simulator",
        actor=EXECUTOR,
        roles=(SIMULATOR_EXECUTOR_ROLE,),
        incident_ids=("incident-simulator",),
        identity_verified=True,
    )
    assert boundary.assert_authorized(authorization, incident_id="incident-simulator") == EXECUTOR
    with pytest.raises(SimulatorAuthorityError, match="boundary-mismatch"):
        SimulatorExecutorBoundary().assert_authorized(
            authorization, incident_id="incident-simulator"
        )
    with pytest.raises(SimulatorAuthorityError, match="executor-role-required"):
        boundary.bind_verified_service(
            incident_id="incident-simulator",
            actor=EXECUTOR,
            roles=(),
            incident_ids=("incident-simulator",),
            identity_verified=True,
        )


def test_admission_is_immutable_authoritative_and_tamper_evident(tmp_path: Path) -> None:
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    bundle = bound_bundle()
    oidc_actor = {**EXECUTOR, "subject": "executor@example.test"}
    admission = repository.admit(bundle, executor_actor=oidc_actor, admitted_at=NOW)
    assert admission["executor_actor"] == oidc_actor
    assert admission["incident_version"] == 7
    actor_body = {
        "schema": "simulator-service-actor-reference/v1",
        "actor": oidc_actor,
    }
    expected_actor_id = (
        f"service-actor:{prefixed_sha256(canonical_json_bytes(actor_body)).removeprefix('sha256:')}"
    )
    assert repository.audit_history(bundle.action.identity)[0]["actor_id"] == expected_actor_id
    assert repository.replay_admission(bundle.action.identity) == admission
    assert (
        repository.admit(
            bundle,
            executor_actor={**EXECUTOR, "subject": "retry-worker"},
            admitted_at=NOW + timedelta(seconds=1),
        )
        == admission
    )
    altered = DispatchIdentity(
        bundle.action.identity.task_key,
        bundle.action.identity.operation_id,
        digest("0"),
    )
    with pytest.raises(SimulatorRepositoryError, match="idempotency-conflict"):
        repository.replay_admission(altered)

    with repository.transaction(write=True) as connection:
        connection.execute("PRAGMA recursive_triggers = OFF")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE simulator_admissions SET document = x'00'")
        connection.execute("DROP TRIGGER idempotency_no_update")
        connection.execute("UPDATE simulator_idempotency SET result = x'7b7d'")
    with pytest.raises(SimulatorRepositoryError, match="idempotency-result-invalid"):
        repository.replay_admission(bundle.action.identity)


def test_claim_reclaim_fences_stale_worker_and_preserves_intent_order(tmp_path: Path) -> None:
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    bundle = bound_bundle()
    repository.admit(bundle, executor_actor=EXECUTOR, admitted_at=NOW)
    first = repository.claim_action(bundle.action, owner="worker-a", now=NOW + timedelta(seconds=1))
    with pytest.raises(SimulatorRepositoryError, match="action-in-progress"):
        repository.claim_action(bundle.action, owner="worker-b", now=NOW + timedelta(seconds=2))
    second = repository.claim_action(
        bundle.action, owner="worker-b", now=NOW + timedelta(seconds=31)
    )
    assert second.generation == 2
    prepared = prepared_publication(bundle.action)
    with pytest.raises(SimulatorRepositoryError, match="claim-fenced"):
        repository.record_publication_intent(first, prepared, now=NOW + timedelta(seconds=32))
    intent = repository.record_publication_intent(second, prepared, now=NOW + timedelta(seconds=32))
    assert intent["claim_generation"] == 2
    assert intent["fixture_id"] == "colortrace-canonical"
    assert intent["predecessor_fixture_manifest_sha256"] == digest("0")
    assert intent["candidate_fixture_manifest_sha256"] == digest("c")

    callback_observed_intent = False

    def promote(value: PreparedPublication) -> PromotionResult:
        nonlocal callback_observed_intent
        callback_observed_intent = value == prepared
        return PromotionResult(
            state="promoted",
            before_pointer_sha256=value.predecessor_pointer_sha256,
            before_generation=value.predecessor_generation,
            after_pointer_sha256=value.candidate_pointer_sha256,
            after_generation=value.candidate_generation,
            pointer_changed=True,
            recovered=False,
            promoted_at="2026-08-13T21:00:33.000Z",
            observed_at="2026-08-13T21:00:33.000Z",
        )

    outcome = repository.reconcile_publication(
        second,
        now=NOW + timedelta(seconds=33),
        promote=promote,
    )
    assert callback_observed_intent
    assert outcome["status"] == "succeeded"
    assert outcome["incident_version"] == 7
    assert outcome["admission_id"].startswith("simulator-admission:")
    assert (
        outcome["admission_sha256"]
        == repository.replay_admission(bundle.action.identity)["admission_sha256"]
    )
    assert outcome["fixture_id"] == "colortrace-canonical"
    assert outcome["predecessor_publication_pointer_sha256"] == (
        prepared.predecessor_pointer_sha256
    )
    assert outcome["predecessor_publication_generation"] == 7
    assert outcome["candidate_publication_pointer_sha256"] == prepared.candidate_pointer_sha256
    assert outcome["candidate_publication_generation"] == 8
    assert outcome["source_batch_id"] == "fixture-run-canonical"
    assert outcome["source_batch_sha256"] == digest("1")
    assert outcome["candidate_fixture_manifest_sha256"] == digest("c")
    assert outcome["candidate_runtime_manifest_sha256"] == digest("4")
    assert outcome["candidate_lineage_manifest_sha256"] == digest("5")
    assert outcome["declared_resource_manifest_sha256"] == digest("5")
    assert outcome["safe_complement_proof_sha256"] == digest("8")
    assert outcome["candidate_seal_sha256"] == digest("9")
    assert outcome["candidate_tree_sha256"] == digest("b")
    assert len(outcome["command_outcomes"]) == 5
    assert len(outcome["new_trace_ids"]) == 5
    assert repository.outcome(bundle.action.identity) == outcome
    assert [event["event_type"] for event in repository.audit_history(bundle.action.identity)] == [
        "dispatch.admitted",
        "claim.acquired",
        "claim.reclaimed",
        "publication.prepared",
        "publication.promoted",
        "action.succeeded",
        "claim.completed",
    ]


def test_pending_action_scan_covers_queued_and_recoverable_work(tmp_path: Path) -> None:
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    bundle = bound_bundle()
    identity = bundle.action.identity
    repository.admit(bundle, executor_actor=EXECUTOR, admitted_at=NOW)
    assert repository.pending_action_identities() == [identity]

    claim = repository.claim_action(
        bundle.action,
        owner="worker-a",
        now=NOW + timedelta(seconds=1),
    )
    assert repository.pending_action_identities() == [identity]
    prepared = prepared_publication(bundle.action)
    repository.record_publication_intent(
        claim,
        prepared,
        now=NOW + timedelta(seconds=7),
    )
    assert repository.pending_action_identities() == [identity]
    repository.reconcile_publication(
        claim,
        now=NOW + timedelta(seconds=8),
        promote=lambda value: PromotionResult(
            state="promoted",
            before_pointer_sha256=value.predecessor_pointer_sha256,
            before_generation=value.predecessor_generation,
            after_pointer_sha256=value.candidate_pointer_sha256,
            after_generation=value.candidate_generation,
            pointer_changed=True,
            recovered=False,
            promoted_at="2026-08-13T21:00:08.000Z",
            observed_at="2026-08-13T21:00:08.000Z",
        ),
    )
    assert repository.pending_action_identities() == []
    with pytest.raises(SimulatorRepositoryError, match="pending-action-limit-invalid"):
        repository.pending_action_identities(limit=0)


def test_crash_after_pointer_swap_reconciles_without_new_intent(tmp_path: Path) -> None:
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    bundle = bound_bundle()
    repository.admit(bundle, executor_actor=EXECUTOR, admitted_at=NOW)
    claim = repository.claim_action(bundle.action, owner="worker-a", now=NOW + timedelta(seconds=1))
    prepared = prepared_publication(bundle.action)
    repository.record_publication_intent(claim, prepared, now=NOW + timedelta(seconds=2))
    pointer_changed = False

    def crash_after_swap(_value: PreparedPublication) -> PromotionResult:
        nonlocal pointer_changed
        pointer_changed = True
        raise RuntimeError("worker died after pointer rename")

    with pytest.raises(RuntimeError, match="worker died"):
        repository.reconcile_publication(
            claim,
            now=NOW + timedelta(seconds=3),
            promote=crash_after_swap,
        )
    assert pointer_changed
    assert repository.outcome(bundle.action.identity) is None

    reclaimed = repository.claim_action(
        bundle.action,
        owner="worker-b",
        now=NOW + timedelta(seconds=31),
    )
    assert reclaimed.phase == "reconcile"

    def inspect_active(value: PreparedPublication) -> PromotionResult:
        observed = "2026-08-13T21:00:32.000Z"
        return PromotionResult(
            state="already-promoted",
            before_pointer_sha256=value.candidate_pointer_sha256,
            before_generation=value.candidate_generation,
            after_pointer_sha256=value.candidate_pointer_sha256,
            after_generation=value.candidate_generation,
            pointer_changed=False,
            recovered=True,
            promoted_at=observed,
            observed_at=observed,
        )

    recovered = repository.reconcile_publication(
        reclaimed,
        now=NOW + timedelta(seconds=32),
        promote=inspect_active,
    )
    assert recovered["status"] == "succeeded"


def test_prepublication_failure_is_terminal_without_intent_or_active_mutation(
    tmp_path: Path,
) -> None:
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    bundle = bound_bundle()
    repository.admit(bundle, executor_actor=EXECUTOR, admitted_at=NOW)
    claim = repository.claim_action(
        bundle.action,
        owner="worker-a",
        now=NOW + timedelta(seconds=1),
    )
    outcome = repository.fail_action(
        claim,
        reason_codes=("publication-precondition-failed",),
        now=NOW + timedelta(seconds=2),
    )
    assert outcome["status"] == "failed"
    assert outcome["publication_intent_id"] is None
    for name in (
        "fixture_id",
        "predecessor_publication_pointer_sha256",
        "predecessor_publication_generation",
        "candidate_publication_pointer_sha256",
        "candidate_publication_generation",
        "source_generation",
        "candidate_generation",
        "source_batch_id",
        "source_batch_sha256",
        "active_publication_pointer_sha256",
        "active_runtime_manifest_sha256",
        "candidate_fixture_manifest_sha256",
        "candidate_runtime_manifest_sha256",
        "candidate_lineage_manifest_sha256",
        "declared_resource_manifest_sha256",
        "preservation_manifest_sha256",
        "safe_complement_before_sha256",
        "safe_complement_after_sha256",
        "safe_complement_proof_sha256",
        "candidate_seal_sha256",
        "candidate_tree_sha256",
    ):
        assert outcome[name] is None
    assert outcome["command_outcomes"] == []
    assert outcome["new_trace_ids"] == []
    assert [event["event_type"] for event in repository.audit_history(bundle.action.identity)][
        -2:
    ] == ["action.failed", "claim.completed"]


def test_publication_conflict_retains_authority_refs_but_no_candidate_projection(
    tmp_path: Path,
) -> None:
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    bundle = bound_bundle()
    repository.admit(bundle, executor_actor=EXECUTOR, admitted_at=NOW)
    claim = repository.claim_action(
        bundle.action,
        owner="worker-a",
        now=NOW + timedelta(seconds=1),
    )
    prepared = prepared_publication(bundle.action)
    repository.record_publication_intent(claim, prepared, now=NOW + timedelta(seconds=2))

    def conflict(_value: PreparedPublication) -> PromotionResult:
        return PromotionResult(
            state="conflict",
            before_pointer_sha256=digest("f"),
            before_generation=9,
            after_pointer_sha256=digest("f"),
            after_generation=9,
            pointer_changed=False,
            recovered=False,
            promoted_at=None,
            observed_at="2026-08-13T21:00:03.000Z",
        )

    outcome = repository.reconcile_publication(
        claim,
        now=NOW + timedelta(seconds=3),
        promote=conflict,
    )
    assert outcome["status"] == "failed"
    assert outcome["reason_codes"] == ["publication-pointer-conflict"]
    assert outcome["publication_intent_id"] is not None
    assert outcome["publication_receipt_id"] is not None
    assert outcome["candidate_publication_pointer_sha256"] is None
    assert outcome["candidate_fixture_manifest_sha256"] is None
    assert outcome["command_outcomes"] == []
    assert outcome["new_trace_ids"] == []


def test_running_row_clock_tamper_is_detected_before_terminalization(tmp_path: Path) -> None:
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    bundle = bound_bundle()
    repository.admit(bundle, executor_actor=EXECUTOR, admitted_at=NOW)
    repository.claim_action(
        bundle.action,
        owner="worker-a",
        now=NOW + timedelta(seconds=1),
    )
    with repository.transaction(write=True) as connection:
        connection.execute(
            "UPDATE simulator_actions SET updated_at = ? WHERE action_id = ?",
            ("2026-08-13T21:00:02.000Z", bundle.action.action_id),
        )
    with pytest.raises(SimulatorRepositoryError, match="stored-action-time-binding"):
        repository.load_action(bundle.action.identity)


def test_schema_drift_and_database_path_attacks_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "simulator.db"
    repository = SQLiteSimulatorRepository(database)
    repository.close()
    connection = sqlite3.connect(database)
    connection.execute("DROP TRIGGER simulator_actions_no_delete")
    connection.commit()
    connection.close()
    with pytest.raises(SimulatorRepositoryError, match="repository-schema-invalid"):
        SQLiteSimulatorRepository(database)

    target_path = tmp_path / "target.db"
    target_path.write_bytes(b"")
    target_path.chmod(0o600)
    link_path = tmp_path / "link.db"
    link_path.symlink_to(target_path)
    with pytest.raises(SimulatorRepositoryError, match="repository-path-invalid"):
        SQLiteSimulatorRepository(link_path)


class DispatchSource:
    def __init__(self, proof: StoredDispatchProof) -> None:
        self.proof = proof
        self.calls = 0
        self.failure: str | None = None

    def load_current_consumed(self, _identity: DispatchIdentity) -> StoredDispatchProof:
        self.calls += 1
        if self.failure is not None:
            raise ResponsePlanError(self.failure)
        return self.proof


class SequenceClock:
    def __init__(self, *values: datetime) -> None:
        self.values = iter(values)

    def __call__(self) -> datetime:
        return next(self.values)


class StepClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        selected = self.value
        self.value += timedelta(seconds=1)
        return selected


class Publication:
    def __init__(self) -> None:
        self.action: Any = None
        self.snapshot_calls = 0
        self.prepare_calls = 0
        self.promotion_calls = 0
        self.snapshot_failure: str | None = None
        self.crash_after_swap = False
        self.promoted = False
        self.conflict = False
        self.prepared: PreparedPublication | None = None
        self.discard_calls = 0
        self.heartbeat_probe: Any = None
        self.prepare_failure_after_heartbeat: str | None = None

    def snapshot_for_action(self, action: Any) -> Any:
        self.snapshot_calls += 1
        if self.snapshot_failure is not None:
            raise SimulatorBundleError(self.snapshot_failure)
        self.action = action
        return action

    def prepare(
        self,
        _snapshot: Any,
        trace_ids: Any,
        *,
        heartbeat: Any = None,
    ) -> PreparedPublication:
        self.prepare_calls += 1
        if heartbeat is not None:
            heartbeat()
        if self.heartbeat_probe is not None:
            self.heartbeat_probe()
        if self.prepare_failure_after_heartbeat is not None:
            raise SimulatorBundleError(self.prepare_failure_after_heartbeat)
        assert set(trace_ids) == {command["command_id"] for command in self.action.commands}
        self.prepared = prepared_publication(self.action)
        return self.prepared

    def compare_and_swap(self, value: PreparedPublication) -> PromotionResult:
        self.promotion_calls += 1
        if self.conflict:
            return PromotionResult(
                state="conflict",
                before_pointer_sha256=digest("f"),
                before_generation=9,
                after_pointer_sha256=digest("f"),
                after_generation=9,
                pointer_changed=False,
                recovered=False,
                promoted_at=None,
                observed_at="2026-08-13T21:00:08.000Z",
            )
        if self.promoted:
            observed = "2026-08-13T21:00:38.000Z"
            return PromotionResult(
                state="already-promoted",
                before_pointer_sha256=value.candidate_pointer_sha256,
                before_generation=value.candidate_generation,
                after_pointer_sha256=value.candidate_pointer_sha256,
                after_generation=value.candidate_generation,
                pointer_changed=False,
                recovered=True,
                promoted_at=observed,
                observed_at=observed,
            )
        self.promoted = True
        if self.crash_after_swap:
            raise RuntimeError("worker died after pointer swap")
        return PromotionResult(
            state="promoted",
            before_pointer_sha256=value.predecessor_pointer_sha256,
            before_generation=value.predecessor_generation,
            after_pointer_sha256=value.candidate_pointer_sha256,
            after_generation=value.candidate_generation,
            pointer_changed=True,
            recovered=False,
            promoted_at="2026-08-13T21:00:08.000Z",
            observed_at="2026-08-13T21:00:08.000Z",
        )

    def inspect_operation(self, operation_id: str) -> PublicationOperationState:
        if not self.conflict:
            raise AssertionError("only conflicted candidates require service cleanup")
        if self.prepared is None:
            return PublicationOperationState(state="not-found", prepared=None, promotion=None)
        assert operation_id == self.prepared.operation_id
        return PublicationOperationState(
            state="conflict",
            prepared=self.prepared,
            promotion=self.compare_and_swap(self.prepared),
        )

    def discard(self, prepared: PreparedPublication) -> None:
        assert prepared == self.prepared
        self.discard_calls += 1
        self.prepared = None


def executor_authorization(
    boundary: SimulatorExecutorBoundary,
    *,
    actor: dict[str, str] = EXECUTOR,
    incident_id: str = "incident-simulator",
) -> Any:
    return boundary.bind_verified_service(
        incident_id=incident_id,
        actor=actor,
        roles=(SIMULATOR_EXECUTOR_ROLE,),
        incident_ids=(incident_id,),
        identity_verified=True,
    )


def test_service_admits_executes_and_replays_once(tmp_path: Path) -> None:
    identity, proof = dispatch_proof()
    source = DispatchSource(proof)
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()
    observed: list[Mapping[str, Any]] = []
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=source,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=6),
            NOW + timedelta(seconds=7),
            NOW + timedelta(seconds=8),
            NOW + timedelta(seconds=9),
        ),
        trace_id_factory=iter(f"{index:032x}" for index in range(1, 6)).__next__,
        terminal_observer=observed.append,
    )
    admission = service.admit(identity, executor=executor_authorization(executor_boundary))
    outcome = service.execute(identity, owner="worker-a")

    assert admission["incident_id"] == "incident-simulator"
    assert outcome["status"] == "succeeded"
    assert outcome["new_trace_ids"] == [f"{index:032x}" for index in range(1, 6)]
    assert (
        publication.snapshot_calls == publication.prepare_calls == publication.promotion_calls == 1
    )
    assert observed == [outcome]

    retry_actor = {**EXECUTOR, "subject": "retry-worker"}
    assert (
        service.admit(
            identity,
            executor=executor_authorization(executor_boundary, actor=retry_actor),
        )
        == admission
    )
    assert service.execute(identity, owner="worker-b") == outcome
    assert source.calls == 2
    assert (
        publication.snapshot_calls == publication.prepare_calls == publication.promotion_calls == 1
    )
    assert observed == [outcome, outcome]


def test_service_precondition_and_replay_authority_fail_without_publication(
    tmp_path: Path,
) -> None:
    identity, proof = dispatch_proof()
    source = DispatchSource(proof)
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()
    publication.snapshot_failure = "action-envelope-stale"
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=source,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=6),
        ),
    )
    admission = service.admit(identity, executor=executor_authorization(executor_boundary))

    wrong_incident = executor_authorization(
        executor_boundary,
        incident_id="incident-other",
    )
    with pytest.raises(SimulatorAuthorityError, match="boundary-mismatch"):
        service.admit(identity, executor=wrong_incident)
    assert repository.replay_admission(identity) == admission
    assert source.calls == 1

    outcome = service.execute(identity, owner="worker-a")
    assert outcome["status"] == "failed"
    assert outcome["reason_codes"] == ["action-envelope-stale"]
    assert outcome["publication_intent_id"] is None
    assert publication.prepare_calls == publication.promotion_calls == 0
    assert source.calls == 2


def test_plan_edit_invalidation_blocks_admitted_action_before_publication(tmp_path: Path) -> None:
    identity, proof = dispatch_proof()
    source = DispatchSource(proof)
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=source,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=6),
        ),
    )
    service.admit(identity, executor=executor_authorization(executor_boundary))
    source.failure = "dispatch-current-plan-invalid"

    outcome = service.execute(identity, owner="worker-a")
    assert outcome["status"] == "failed"
    assert outcome["reason_codes"] == ["dispatch-authority-stale"]
    assert outcome["publication_intent_id"] is None
    assert publication.snapshot_calls == publication.prepare_calls == 0


def test_render_heartbeat_fences_duplicate_past_original_lease(tmp_path: Path) -> None:
    identity, proof = dispatch_proof()
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=DispatchSource(proof),
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=29),
            NOW + timedelta(seconds=30),
        ),
    )
    service.admit(identity, executor=executor_authorization(executor_boundary))

    def competing_claim() -> None:
        action = repository.load_action(identity)
        with pytest.raises(SimulatorRepositoryError, match="action-in-progress"):
            repository.claim_action(
                action,
                owner="worker-b",
                now=NOW + timedelta(seconds=36),
            )

    publication.heartbeat_probe = competing_claim
    publication.prepare_failure_after_heartbeat = "render-probe-stop"
    outcome = service.execute(identity, owner="worker-a")
    assert outcome["status"] == "failed"
    assert outcome["reason_codes"] == ["render-probe-stop"]
    assert publication.promotion_calls == 0


def test_service_reconciles_crash_after_pointer_swap_without_rerender(tmp_path: Path) -> None:
    identity, proof = dispatch_proof()
    source = DispatchSource(proof)
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()
    publication.crash_after_swap = True
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=source,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=6),
            NOW + timedelta(seconds=7),
            NOW + timedelta(seconds=8),
            NOW + timedelta(seconds=9),
            NOW + timedelta(seconds=37),
            NOW + timedelta(seconds=38),
        ),
        trace_id_factory=iter(f"{index:032x}" for index in range(1, 6)).__next__,
    )
    service.admit(identity, executor=executor_authorization(executor_boundary))
    with pytest.raises(RuntimeError, match="pointer swap"):
        service.execute(identity, owner="worker-a")

    publication.crash_after_swap = False
    recovered = service.execute(identity, owner="worker-b")
    assert recovered["status"] == "succeeded"
    assert publication.snapshot_calls == 1
    assert publication.prepare_calls == 1
    assert publication.promotion_calls == 2


def test_service_cleans_losing_candidate_after_durable_conflict(tmp_path: Path) -> None:
    identity, proof = dispatch_proof()
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()
    publication.conflict = True
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=DispatchSource(proof),
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=6),
            NOW + timedelta(seconds=7),
            NOW + timedelta(seconds=8),
            NOW + timedelta(seconds=9),
        ),
        trace_id_factory=iter(f"{index:032x}" for index in range(1, 6)).__next__,
    )
    service.admit(identity, executor=executor_authorization(executor_boundary))
    outcome = service.execute(identity, owner="worker-a")

    assert outcome["status"] == "failed"
    assert outcome["reason_codes"] == ["publication-pointer-conflict"]
    assert publication.discard_calls == 1
    assert publication.prepared is None
    assert service.execute(identity, owner="worker-b") == outcome
    assert publication.discard_calls == 1


class FailingTelemetrySink:
    def emit(self, _event: Any) -> None:
        raise RuntimeError("telemetry unavailable")

    def force_flush(self) -> None:
        raise AssertionError("flush is unreachable after emit failure")


def test_terminal_outbox_recovers_observer_crash_and_sink_failure_without_rerender(
    tmp_path: Path,
) -> None:
    identity, proof = dispatch_proof()
    database = tmp_path / "simulator.db"
    repository = SQLiteSimulatorRepository(database)
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()

    def crash_observer(_outcome: Mapping[str, Any]) -> None:
        raise RuntimeError("worker crashed after terminal commit")

    service = SimulatorActionService(
        repository=repository,
        dispatch_source=DispatchSource(proof),
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=6),
            NOW + timedelta(seconds=7),
            NOW + timedelta(seconds=8),
            NOW + timedelta(seconds=9),
        ),
        trace_id_factory=iter(f"{index:032x}" for index in range(1, 6)).__next__,
        terminal_observer=crash_observer,
    )
    service.admit(identity, executor=executor_authorization(executor_boundary))
    outcome = service.execute(identity, owner="worker-a")
    assert outcome["status"] == "succeeded"
    assert repository.telemetry_history(identity) == []
    assert repository.pending_telemetry_outcomes() == [outcome]
    repository.close()

    failed_repository = SQLiteSimulatorRepository(database)
    failed_service = SimulatorActionService(
        repository=failed_repository,
        dispatch_source=DispatchSource(proof),
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        terminal_observer=lambda value: emit_action_outcome(
            value,
            FailingTelemetrySink(),
            clock=lambda: NOW + timedelta(seconds=9),
        ),
    )
    assert failed_service.deliver_pending_telemetry() == 0
    assert [item["status"] for item in failed_repository.telemetry_history(identity)] == ["failed"]
    assert failed_repository.pending_telemetry_outcomes() == [outcome]
    failed_repository.close()

    delivered_repository = SQLiteSimulatorRepository(database)
    sink = MemoryActionTelemetrySink()
    delivered_service = SimulatorActionService(
        repository=delivered_repository,
        dispatch_source=DispatchSource(proof),
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        terminal_observer=lambda value: emit_action_outcome(
            value,
            sink,
            clock=lambda: NOW + timedelta(seconds=10),
        ),
    )
    assert delivered_service.deliver_pending_telemetry() == 1
    assert [item["status"] for item in delivered_repository.telemetry_history(identity)] == [
        "failed",
        "emitted",
    ]
    assert delivered_repository.pending_telemetry_outcomes() == []
    assert len(sink.events) == 17
    assert publication.prepare_calls == publication.promotion_calls == 1


def test_runtime_execution_defers_terminal_observation_to_bounded_outbox_drain(
    tmp_path: Path,
) -> None:
    identity, proof = dispatch_proof()
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    publication = Publication()
    sink = MemoryActionTelemetrySink()
    service = SimulatorActionService(
        repository=repository,
        dispatch_source=DispatchSource(proof),
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=SequenceClock(
            NOW + timedelta(seconds=4),
            NOW + timedelta(seconds=5),
            NOW + timedelta(seconds=6),
            NOW + timedelta(seconds=7),
            NOW + timedelta(seconds=8),
            NOW + timedelta(seconds=9),
        ),
        trace_id_factory=iter(f"{index:032x}" for index in range(1, 6)).__next__,
        terminal_observer=lambda value: emit_action_outcome(
            value,
            sink,
            clock=lambda: NOW + timedelta(seconds=10),
        ),
    )
    service.admit(identity, executor=executor_authorization(executor_boundary))
    outcome = service.execute(
        identity,
        owner="runtime-worker",
        observe_terminal=False,
    )
    assert outcome["status"] == "succeeded"
    assert sink.events == []
    assert repository.pending_telemetry_outcomes(limit=1) == [outcome]
    assert service.deliver_pending_telemetry(limit=1) == 1
    assert len(sink.events) == 17


def test_service_real_canonical_loop_preserves_safe_scope_and_emits_new_traces(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    build_scenario(
        fixture,
        oracle_root=tmp_path / "private-oracle",
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    clock = StepClock(NOW + timedelta(seconds=10))
    publication = LocalPublicationPort.bootstrap(
        root=tmp_path / "workspace",
        fixture_bundle=fixture,
        clock=clock,
    )
    inputs = publication.canonical_plan_inputs()
    identity, proof = dispatch_proof(
        (
            list(inputs["targets"]),
            list(inputs["exclusions"]),
            list(inputs["commands"]),
        )
    )
    repository = SQLiteSimulatorRepository(tmp_path / "simulator.db")
    executor_boundary = SimulatorExecutorBoundary()
    source = DispatchSource(proof)
    telemetry = MemoryActionTelemetrySink()
    receipts: list[dict[str, Any]] = []

    def observe(outcome: Mapping[str, Any]) -> Mapping[str, Any]:
        receipt = emit_action_outcome(outcome, telemetry, clock=clock)
        receipts.append(receipt)
        return receipt

    service = SimulatorActionService(
        repository=repository,
        dispatch_source=source,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor_boundary,
        publication=publication,
        clock=clock,
        trace_id_factory=iter(f"{index:032x}" for index in range(1, 6)).__next__,
        terminal_observer=observe,
    )
    bound = SimulatorAuthorityBoundary().bind(identity, proof).action
    assert bound.commands[0]["action_envelope"] == inputs["envelope"]
    context = publication._load_active_context()
    _resolved, _safe, safe_sha256, _preservation, preservation_sha256 = (
        publication._action_documents(
            context,
            bound.commands,
            bound.targets,
            bound.exclusions,
        )
    )
    expected = {
        "preservation_manifest_sha256": preservation_sha256,
        "safe_complement_sha256": safe_sha256,
    }
    mismatches = {
        key: (inputs["envelope"][key], value)
        for key, value in expected.items()
        if inputs["envelope"][key] != value
    }
    assert not mismatches, mismatches
    service.admit(identity, executor=executor_authorization(executor_boundary))
    outcome = service.execute(identity, owner="canonical-worker")

    assert outcome["status"] == "succeeded", outcome["reason_codes"]
    assert len(outcome["command_outcomes"]) == 5
    assert len(outcome["new_trace_ids"]) == 5
    assert len(outcome["exclusions"]) == 3
    assert outcome["safe_complement_before_sha256"] == outcome["safe_complement_after_sha256"]
    assert receipts[0]["status"] == "emitted"
    assert len(telemetry.events) == 21

    assert service.execute(identity, owner="retry-worker") == outcome
    assert len(telemetry.events) == 21
    assert [item["status"] for item in repository.telemetry_history(identity)] == ["emitted"]
    assert publication.inspect_operation(identity.operation_id).state == "promoted"
    assert [event["event_type"] for event in repository.audit_history(identity)][-3:] == [
        "publication.promoted",
        "action.succeeded",
        "claim.completed",
    ]
