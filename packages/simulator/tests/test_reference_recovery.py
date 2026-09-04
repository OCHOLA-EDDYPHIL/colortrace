from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import colortrace_simulator.reference_recovery as recovery_module
import pytest
from colortrace_simulator.authority import canonical_json_bytes, prefixed_sha256
from colortrace_simulator.reference_recovery import (
    ReferenceHumanApprovalBoundary,
    ReferenceJobState,
    ReferenceRecoveryError,
    ReferenceRecoveryService,
    ReferenceRecoveryState,
    validate_reference_action_intent,
    validate_reference_recovery_verification,
)
from colortrace_validator import ActionIntent, IncidentClass

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
ACTOR = {
    "issuer": "https://identity.example.test",
    "subject": "operator-reference",
    "audience": "colortrace-simulator",
    "kind": "human",
}


def _digest(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


class MutableClock:
    def __init__(self) -> None:
        self.value = NOW

    def __call__(self) -> datetime:
        return self.value


def _scenario_id(incident_class: IncidentClass) -> str:
    return {
        IncidentClass.RESOURCE_RESOLUTION_DRIFT: "tos-resource-resolution-drift-v1",
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT: "tos-config-rollout-drift-v1",
        IncidentClass.STALE_DERIVATIVE_CACHE: "tos-stale-derivative-cache-v1",
    }[incident_class]


def _action(
    incident_class: IncidentClass, *, affected: tuple[str, ...] = ("job-a", "job-b")
) -> ActionIntent:
    if incident_class is IncidentClass.RESOURCE_RESOLUTION_DRIFT:
        command = "reconcile-resource"
        parameters: dict[str, Any] = {
            "changed_fields": ["effective_resource_sha256"],
            "expected": {"effective_resource_sha256": _digest("resource-approved")},
            "observed": {"effective_resource_sha256": _digest("resource-shadowed")},
        }
    elif incident_class is IncidentClass.CONFIGURATION_ROLLOUT_DRIFT:
        command = "pin-rollout"
        parameters = {
            "changed_fields": ["config_generation", "effective_config_sha256"],
            "expected": {
                "config_generation": 7,
                "effective_config_sha256": _digest("config-approved"),
            },
            "observed": {
                "config_generation": 6,
                "effective_config_sha256": _digest("config-stale"),
            },
        }
    else:
        command = "invalidate-cache"
        parameters = {
            "changed_fields": ["derivative_generation", "derivative_parent_sha256"],
            "expected": {
                "derivative_generation": 7,
                "derivative_parent_sha256": _digest("parent-approved"),
            },
            "observed": {
                "derivative_generation": 6,
                "derivative_parent_sha256": _digest("parent-stale"),
            },
            "cache_key": "cache-reference-v1",
        }
    return ActionIntent(
        reconciliation_id="diagnosis-reconciliation:" + "a" * 64,
        incident_class=incident_class,
        command=command,  # type: ignore[arg-type]
        affected_job_ids=affected,
        evidence_fact_ids=("runtime-fact:" + "b" * 64,),
        parameters=parameters,
    )


def _job(job_id: str, incident_class: IncidentClass, *, affected: bool) -> ReferenceJobState:
    resource = _digest("resource-approved")
    config = _digest("config-approved")
    config_generation = 7
    frame = _digest(f"frame-approved:{job_id}")
    parent = frame
    derivative_generation = 7
    if affected and incident_class is IncidentClass.RESOURCE_RESOLUTION_DRIFT:
        resource = _digest("resource-shadowed")
        frame = _digest(f"frame-resource-drift:{job_id}")
        parent = frame
    elif affected and incident_class is IncidentClass.CONFIGURATION_ROLLOUT_DRIFT:
        config = _digest("config-stale")
        config_generation = 6
        frame = _digest(f"frame-config-drift:{job_id}")
        parent = frame
    elif affected and incident_class is IncidentClass.STALE_DERIVATIVE_CACHE:
        parent = _digest("parent-stale")
        derivative_generation = 6
    return ReferenceJobState(
        job_id=job_id,
        effective_resource_sha256=resource,
        effective_config_sha256=config,
        config_generation=config_generation,
        frame_sha256=frame,
        derivative_parent_sha256=parent,
        derivative_generation=derivative_generation,
        cache_key="cache-reference-v1",
        derivative_sha256=_digest(f"derivative-before:{job_id}"),
    )


def _state(incident_class: IncidentClass) -> ReferenceRecoveryState:
    return ReferenceRecoveryState(
        scenario_id=_scenario_id(incident_class),
        incident_class=incident_class,
        generation=1,
        affected_job_ids=("job-a", "job-b"),
        protected_job_ids=("job-safe-a", "job-safe-b"),
        jobs=tuple(
            _job(job_id, incident_class, affected=job_id.startswith("job-a") or job_id == "job-b")
            for job_id in ("job-a", "job-b", "job-safe-a", "job-safe-b")
        ),
    )


def _service(
    incident_class: IncidentClass,
) -> tuple[
    MutableClock,
    ReferenceHumanApprovalBoundary,
    ReferenceRecoveryService,
    ReferenceRecoveryState,
    ActionIntent,
]:
    clock = MutableClock()
    boundary = ReferenceHumanApprovalBoundary(
        audience="colortrace-simulator",
        clock=clock,
    )
    state = _state(incident_class)
    return (
        clock,
        boundary,
        ReferenceRecoveryService(states=(state,), approval_boundary=boundary),
        state,
        _action(incident_class),
    )


def _approve(
    boundary: ReferenceHumanApprovalBoundary,
    state: ReferenceRecoveryState,
    action: ActionIntent,
    *,
    nonce: str = "approval-001",
    decision: str = "approved",
) -> Any:
    return boundary.issue(
        action,
        state,
        actor=ACTOR,
        identity_verified=True,
        decision=decision,  # type: ignore[arg-type]
        approval_nonce=nonce,
    )


@pytest.mark.parametrize("incident_class", tuple(IncidentClass))
def test_recovery_changes_only_the_scenario_specific_affected_state(
    incident_class: IncidentClass,
) -> None:
    _clock, boundary, service, before, action = _service(incident_class)
    approval = _approve(boundary, before, action)

    receipt = service.execute(action, approval)
    after = service.snapshot(before.scenario_id)

    assert receipt["result"] == "applied"
    assert receipt["action_intent_id"] == action.action_intent_id
    assert receipt["approval_id"] == approval.approval_id
    assert receipt["before"]["state_sha256"] == before.state_sha256
    assert receipt["after"]["state_sha256"] == after.state_sha256
    assert after.generation == before.generation + 1
    assert after.protected_state_sha256 == before.protected_state_sha256
    assert [after.job(job_id) for job_id in before.protected_job_ids] == [
        before.job(job_id) for job_id in before.protected_job_ids
    ]
    verification = receipt["verification"]
    assert verification["schema"] == "reference-recovery-verification/v1"
    assert verification["verifier"] == "deterministic-simulator-state"
    assert verification["result"] == "verified"
    assert verification["before"] == receipt["before"]
    assert verification["after"] == receipt["after"]
    assert verification["affected_job_ids"] == list(before.affected_job_ids)
    assert [check["field"] for check in verification["affected_expected_field_checks"]] == list(
        action.parameters["changed_fields"]
    )
    assert all(
        check["expected_value"] == action.parameters["expected"][check["field"]]
        and check["matched_job_ids"] == list(before.affected_job_ids)
        for check in verification["affected_expected_field_checks"]
    )
    assert verification["checks"] == {
        "generation_advanced_exactly_once": True,
        "all_affected_expected_fields_match": True,
        "protected_state_unchanged": True,
        "receipt_state_bindings_match": True,
    }
    assert verification["establishes_pixel_output"] is False
    assert verification["establishes_full_population_scope"] is False
    assert verification["production_evidence"] is False
    verification_body = {
        key: value for key, value in verification.items() if key != "verification_sha256"
    }
    assert verification["verification_sha256"] == prefixed_sha256(
        canonical_json_bytes(verification_body)
    )
    assert validate_reference_recovery_verification(verification) == verification
    for job_id in before.affected_job_ids:
        old = before.job(job_id)
        new = after.job(job_id)
        if incident_class is IncidentClass.RESOURCE_RESOLUTION_DRIFT:
            assert (
                new.effective_resource_sha256
                == action.parameters["expected"]["effective_resource_sha256"]
            )
            assert new.frame_sha256 != old.frame_sha256
            assert new.derivative_sha256 != old.derivative_sha256
        elif incident_class is IncidentClass.CONFIGURATION_ROLLOUT_DRIFT:
            assert (
                new.effective_config_sha256
                == action.parameters["expected"]["effective_config_sha256"]
            )
            assert new.config_generation == 7
            assert new.frame_sha256 != old.frame_sha256
            assert new.derivative_sha256 != old.derivative_sha256
        else:
            assert new.frame_sha256 == old.frame_sha256
            assert new.effective_resource_sha256 == old.effective_resource_sha256
            assert new.effective_config_sha256 == old.effective_config_sha256
            assert (
                new.derivative_parent_sha256
                == action.parameters["expected"]["derivative_parent_sha256"]
            )
            assert new.derivative_generation == 7
            assert new.derivative_sha256 != old.derivative_sha256
    body = {
        key: value for key, value in receipt.items() if key not in {"receipt_id", "receipt_sha256"}
    }
    assert receipt["receipt_sha256"] == prefixed_sha256(canonical_json_bytes(body))
    assert receipt["receipt_id"].endswith(receipt["receipt_sha256"].removeprefix("sha256:"))


def test_recovery_verification_expected_field_failure_is_atomic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clock, boundary, service, before, action = _service(IncidentClass.RESOURCE_RESOLUTION_DRIFT)
    approval = _approve(boundary, before, action)
    real_apply = recovery_module._apply_recovery

    def mismatched_apply(
        state: ReferenceRecoveryState,
        intent: ActionIntent,
    ) -> ReferenceRecoveryState:
        after = real_apply(state, intent)
        corrupted = replace(
            after.job("job-a"),
            effective_resource_sha256=_digest("verification-mismatch"),
        )
        return replace(
            after,
            jobs=tuple(corrupted if job.job_id == corrupted.job_id else job for job in after.jobs),
        )

    monkeypatch.setattr(recovery_module, "_apply_recovery", mismatched_apply)
    with pytest.raises(ReferenceRecoveryError, match="reference-recovery-verification-failed"):
        service.execute(action, approval)
    assert service.snapshot(before.scenario_id) == before

    monkeypatch.setattr(recovery_module, "_apply_recovery", real_apply)
    assert service.execute(action, approval)["verification"]["result"] == "verified"


def test_recovery_verification_receipt_binding_failure_is_atomic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clock, boundary, service, before, action = _service(IncidentClass.CONFIGURATION_ROLLOUT_DRIFT)
    approval = _approve(boundary, before, action)
    real_reference = recovery_module._receipt_state_reference

    def mismatched_reference(state: ReferenceRecoveryState) -> dict[str, Any]:
        reference = real_reference(state)
        if state.generation == before.generation + 1:
            reference["generation"] += 1
        return reference

    monkeypatch.setattr(recovery_module, "_receipt_state_reference", mismatched_reference)
    with pytest.raises(ReferenceRecoveryError, match="reference-recovery-verification-failed"):
        service.execute(action, approval)
    assert service.snapshot(before.scenario_id) == before

    monkeypatch.setattr(recovery_module, "_receipt_state_reference", real_reference)
    receipt = service.execute(action, approval)
    tampered = dict(receipt["verification"])
    tampered["production_evidence"] = True
    with pytest.raises(ReferenceRecoveryError, match="reference-recovery-verification-invalid"):
        validate_reference_recovery_verification(tampered)


def test_recovery_is_atomic_and_idempotent_under_concurrent_replay() -> None:
    _clock, boundary, service, before, action = _service(IncidentClass.RESOURCE_RESOLUTION_DRIFT)
    approval = _approve(boundary, before, action)

    with ThreadPoolExecutor(max_workers=8) as pool:
        receipts = tuple(pool.map(lambda _index: service.execute(action, approval), range(16)))

    assert all(receipt == receipts[0] for receipt in receipts)
    assert service.snapshot(before.scenario_id).generation == 2
    assert service.execute(action.to_dict(), approval) == receipts[0]
    assert service.snapshot(before.scenario_id).generation == 2


def test_denied_unverified_and_expired_approvals_never_mutate() -> None:
    clock, boundary, service, before, action = _service(IncidentClass.CONFIGURATION_ROLLOUT_DRIFT)
    denied = _approve(boundary, before, action, decision="denied")
    with pytest.raises(ReferenceRecoveryError, match="reference-approval-denied"):
        service.execute(action, denied)
    assert service.snapshot(before.scenario_id) == before

    with pytest.raises(ReferenceRecoveryError, match="reference-approval-authority-invalid"):
        boundary.issue(
            action,
            before,
            actor=ACTOR,
            identity_verified=False,
            decision="approved",
            approval_nonce="unverified",
        )
    assert service.snapshot(before.scenario_id) == before

    expiring = boundary.issue(
        action,
        before,
        actor=ACTOR,
        identity_verified=True,
        decision="approved",
        approval_nonce="expiring",
        ttl=timedelta(seconds=1),
    )
    clock.value += timedelta(seconds=1)
    with pytest.raises(ReferenceRecoveryError, match="reference-approval-stale"):
        service.execute(action, expiring)
    assert service.snapshot(before.scenario_id) == before


def test_tampered_or_mismatched_approval_and_intent_never_mutate() -> None:
    _clock, boundary, service, before, action = _service(IncidentClass.STALE_DERIVATIVE_CACHE)
    approval = _approve(boundary, before, action)
    tampered_approval = replace(approval, approval_nonce="tampered")
    with pytest.raises(ReferenceRecoveryError, match="reference-approval-untrusted"):
        service.execute(action, tampered_approval)
    assert service.snapshot(before.scenario_id) == before

    tampered_intent = action.to_dict()
    tampered_intent["action_intent_id"] = "action-intent:" + "f" * 64
    with pytest.raises(ReferenceRecoveryError, match="reference-action-intent-invalid"):
        service.execute(tampered_intent, approval)
    assert service.snapshot(before.scenario_id) == before

    other_action = _action(IncidentClass.STALE_DERIVATIVE_CACHE, affected=("job-a",))
    with pytest.raises(ReferenceRecoveryError, match="reference-approval-intent-mismatch"):
        service.execute(other_action, approval)
    assert service.snapshot(before.scenario_id) == before


def test_exact_affected_set_and_current_state_are_required() -> None:
    _clock, boundary, service, before, action = _service(IncidentClass.RESOURCE_RESOLUTION_DRIFT)
    subset = _action(IncidentClass.RESOURCE_RESOLUTION_DRIFT, affected=("job-a",))
    with pytest.raises(ReferenceRecoveryError, match="reference-approval-authority-invalid"):
        _approve(boundary, before, subset)

    first = _approve(boundary, before, action, nonce="approval-first")
    stale = _approve(boundary, before, action, nonce="approval-stale")
    service.execute(action, first)
    current = service.snapshot(before.scenario_id)
    with pytest.raises(ReferenceRecoveryError, match="reference-approval-state-mismatch"):
        service.execute(action, stale)
    assert service.snapshot(before.scenario_id) == current


def test_state_precondition_mismatch_is_rejected_without_mutation() -> None:
    _clock, boundary, _service_instance, before, action = _service(
        IncidentClass.RESOURCE_RESOLUTION_DRIFT
    )
    mismatched_job = replace(
        before.job("job-a"),
        effective_resource_sha256=_digest("different-observed-resource"),
    )
    mismatched = ReferenceRecoveryState(
        scenario_id=before.scenario_id,
        incident_class=before.incident_class,
        generation=before.generation,
        affected_job_ids=before.affected_job_ids,
        protected_job_ids=before.protected_job_ids,
        jobs=tuple(
            mismatched_job if job.job_id == mismatched_job.job_id else job for job in before.jobs
        ),
    )
    service = ReferenceRecoveryService(states=(mismatched,), approval_boundary=boundary)
    approval = _approve(boundary, mismatched, action)

    with pytest.raises(ReferenceRecoveryError, match="reference-action-precondition-mismatch"):
        service.execute(action, approval)
    assert service.snapshot(mismatched.scenario_id) == mismatched


def test_self_addressed_approval_binds_exact_intent_and_state() -> None:
    _clock, boundary, _service_instance, state, action = _service(
        IncidentClass.CONFIGURATION_ROLLOUT_DRIFT
    )
    approval = _approve(boundary, state, action)
    document = approval.to_dict()
    body = {
        key: value
        for key, value in document.items()
        if key not in {"approval_id", "approval_sha256"}
    }

    assert document["approval_sha256"] == prefixed_sha256(canonical_json_bytes(body))
    assert document["approval_id"].endswith(document["approval_sha256"].removeprefix("sha256:"))
    assert document["approver"]["identity_verified"] is True
    assert document["approver"]["identity_assurance"] == "verified-identity"
    assert document["approver"]["identity"] == {
        "issuer": ACTOR["issuer"],
        "subject": ACTOR["subject"],
    }
    assert "gesture" not in document["approver"]
    assert document["action_intent_id"] == action.action_intent_id
    assert document["action_intent_sha256"] == action.derivation_sha256
    assert document["state_sha256"] == state.state_sha256
    assert document["protected_state_sha256"] == state.protected_state_sha256
    assert validate_reference_action_intent(action.to_dict()).to_dict() == action.to_dict()


def test_public_demo_gesture_is_explicit_but_never_claims_verified_identity() -> None:
    _clock, boundary, service, before, action = _service(IncidentClass.RESOURCE_RESOLUTION_DRIFT)
    with pytest.raises(ReferenceRecoveryError, match="reference-approval-gesture-invalid"):
        boundary.issue_public_demo_gesture(
            action,
            before,
            decision="approved",
            approval_nonce="public-gesture-invalid",
            approval_phrase="approve",
        )
    assert service.snapshot(before.scenario_id) == before

    approval = boundary.issue_public_demo_gesture(
        action,
        before,
        decision="approved",
        approval_nonce="public-gesture-001",
        approval_phrase="APPROVE_COLORTRACE_SIMULATOR_ACTION",
    )
    document = approval.to_dict()

    assert document["approver"] == {
        "audience": "colortrace-simulator",
        "kind": "human",
        "identity_verified": False,
        "identity_assurance": "unverified-public-demo-gesture",
        "gesture": "explicit-phrase-and-nonce",
    }
    assert service.execute(action, approval)["result"] == "applied"


def test_successful_replay_returns_original_receipt_after_approval_expiry() -> None:
    clock, boundary, service, before, action = _service(IncidentClass.STALE_DERIVATIVE_CACHE)
    approval = boundary.issue(
        action,
        before,
        actor=ACTOR,
        identity_verified=True,
        decision="approved",
        approval_nonce="short-lived",
        ttl=timedelta(seconds=1),
    )
    receipt = service.execute(action, approval)
    clock.value += timedelta(minutes=1)

    assert service.execute(action, approval) == receipt
    assert service.snapshot(before.scenario_id).generation == 2
