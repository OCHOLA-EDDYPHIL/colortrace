from __future__ import annotations

import copy
import sqlite3
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from colortrace_recovery import (
    ACTIVE_PUBLICATION_SCHEMA,
    ARTIFACT_ROLE_COUNTS,
    ARTIFACT_SCHEMA,
    CHECK_NAMES,
    RecoveryClosureService,
    RecoveryError,
    RecoveryIdentityBoundary,
    RecoveryPrincipal,
    RecoveryVerificationService,
    SQLiteRecoveryRepository,
    assess_post_action_observations,
    build_check_result,
    build_evidence_record,
    build_evidence_request,
    build_recovery_packet,
    build_verification_snapshot,
    canonical_json_bytes,
    document_sha256,
)
from colortrace_telemetry.action_emitter import build_action_events
from colortrace_telemetry.contract import canonical_json_bytes as telemetry_json_bytes
from colortrace_telemetry.contract import sha256_bytes


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def target(kind: str, identifier: str) -> dict[str, str]:
    return {
        "schema": "simulator-target/v1",
        "namespace": "colortrace-simulator",
        "kind": kind,
        "id": identifier,
    }


def command_result(
    command_id: str,
    result_kind: str,
    selected_target: Mapping[str, str],
    trace_id: str,
    before: Mapping[str, str],
    after: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "schema": "simulator-command-result/v1",
        "command_id": command_id,
        "result_kind": result_kind,
        "target": dict(selected_target),
        "trace_id": trace_id,
        "before": dict(before),
        "after": dict(after),
    }


def seal_outcome(outcome: dict[str, Any]) -> dict[str, Any]:
    body = {
        key: child for key, child in outcome.items() if key not in {"outcome_id", "outcome_sha256"}
    }
    suffix = sha256_bytes(telemetry_json_bytes(body))
    outcome["outcome_id"] = f"simulator-action-outcome:{suffix}"
    outcome["outcome_sha256"] = f"sha256:{suffix}"
    return outcome


def successful_outcome() -> dict[str, Any]:
    targets = [
        target("color-resource", digest("1")),
        target("derivative", "derivative-affected"),
        target("frame", "frame-affected-a"),
        target("frame", "frame-affected-b"),
        target("frame", "frame-affected-c"),
    ]
    exclusions = [
        target("frame", "frame-safe-a"),
        target("frame", "frame-safe-b"),
        target("frame", "frame-safe-c"),
    ]
    commands = [
        command_result(
            "command-01-quarantine",
            "quarantine",
            targets[0],
            "1" * 32,
            {"resource_sha256": digest("1")},
            {"resource_sha256": digest("2")},
        ),
        command_result(
            "command-02-derivative",
            "derivative",
            targets[1],
            "2" * 32,
            {"derivative_sha256": digest("3"), "derivative_display_sha256": digest("4")},
            {"derivative_sha256": digest("5"), "derivative_display_sha256": digest("6")},
        ),
        command_result(
            "command-03-frame-a",
            "frame",
            targets[2],
            "3" * 32,
            {"output_sha256": digest("7"), "display_sha256": digest("8")},
            {"output_sha256": digest("9"), "display_sha256": digest("a")},
        ),
        command_result(
            "command-04-frame-b",
            "frame",
            targets[3],
            "4" * 32,
            {"output_sha256": digest("b"), "display_sha256": digest("c")},
            {"output_sha256": digest("d"), "display_sha256": digest("e")},
        ),
        command_result(
            "command-05-frame-c",
            "frame",
            targets[4],
            "5" * 32,
            {"output_sha256": digest("f"), "display_sha256": digest("1")},
            {"output_sha256": digest("2"), "display_sha256": digest("3")},
        ),
    ]
    return seal_outcome(
        {
            "schema": "simulator-action-outcome/v1",
            "outcome_id": "pending",
            "outcome_sha256": digest("0"),
            "admission_id": f"simulator-admission:{'1' * 64}",
            "admission_sha256": digest("1"),
            "action_id": f"simulator-action:{'2' * 64}",
            "task_key": f"dispatch-task:{'3' * 64}",
            "operation_id": f"dispatch-operation:{'3' * 64}",
            "payload_sha256": digest("4"),
            "status": "succeeded",
            "reason_codes": [],
            "fixture_id": "ct-shadowed-lut-v1",
            "incident_id": "incident-action-01",
            "incident_version": 4,
            "plan_id": f"response-plan:{'5' * 64}",
            "plan_version": 2,
            "plan_sha256": digest("5"),
            "approval_id": f"response-plan-decision:{'6' * 64}",
            "approval_sha256": digest("6"),
            "authorization_id": f"dispatch-authorization:{'7' * 64}",
            "authorization_sha256": digest("7"),
            "consumption_id": f"dispatch-consumption:{'8' * 64}",
            "consumption_sha256": digest("8"),
            "dispatch_bundle_sha256": digest("9"),
            "action_envelope_sha256": digest("a"),
            "action_started_at": "2026-08-13T12:00:00.000Z",
            "publication_intent_id": f"simulator-publication-intent:{'a' * 64}",
            "publication_intent_sha256": digest("a"),
            "publication_receipt_id": f"simulator-publication-receipt:{'b' * 64}",
            "publication_receipt_sha256": digest("b"),
            "publication_promoted_at": "2026-08-13T12:00:01.000Z",
            "completed_at": "2026-08-13T12:00:02.000Z",
            "predecessor_publication_pointer_sha256": digest("c"),
            "predecessor_publication_generation": 7,
            "candidate_publication_pointer_sha256": digest("d"),
            "candidate_publication_generation": 8,
            "source_generation": 7,
            "candidate_generation": 8,
            "source_batch_id": "fixture-run-canonical",
            "source_batch_sha256": digest("e"),
            "candidate_fixture_manifest_sha256": digest("f"),
            "candidate_runtime_manifest_sha256": digest("1"),
            "candidate_lineage_manifest_sha256": digest("2"),
            "declared_resource_manifest_sha256": digest("3"),
            "active_publication_pointer_sha256": digest("d"),
            "active_runtime_manifest_sha256": digest("1"),
            "preservation_manifest_sha256": digest("4"),
            "safe_complement_before_sha256": digest("5"),
            "safe_complement_after_sha256": digest("5"),
            "safe_complement_proof_sha256": digest("6"),
            "candidate_seal_sha256": digest("7"),
            "candidate_tree_sha256": digest("8"),
            "targets": targets,
            "exclusions": exclusions,
            "command_outcomes": commands,
            "new_trace_ids": [f"{index:x}" * 32 for index in range(1, 6)],
        }
    )


BASE = datetime(2026, 8, 13, 12, 0, 3, tzinfo=UTC)


class Clock:
    def __init__(self, now: datetime = BASE) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def active_publication(outcome: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": ACTIVE_PUBLICATION_SCHEMA,
        "publication_id": "publication-recovered-01",
        "observed_at": "2026-08-13T12:00:02.500Z",
        "generation": outcome["candidate_publication_generation"],
        "pointer_sha256": outcome["active_publication_pointer_sha256"],
        "runtime_manifest_sha256": outcome["active_runtime_manifest_sha256"],
        "fixture_manifest_sha256": outcome["candidate_fixture_manifest_sha256"],
        "lineage_manifest_sha256": outcome["candidate_lineage_manifest_sha256"],
        "declared_resource_manifest_sha256": outcome["declared_resource_manifest_sha256"],
        "preservation_manifest_sha256": outcome["preservation_manifest_sha256"],
        "safe_complement_sha256": outcome["safe_complement_after_sha256"],
        "safe_complement_proof_sha256": outcome["safe_complement_proof_sha256"],
        "candidate_seal_sha256": outcome["candidate_seal_sha256"],
        "candidate_tree_sha256": outcome["candidate_tree_sha256"],
    }


def artifacts(outcome: Mapping[str, Any]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    index = 0
    for role, count in ARTIFACT_ROLE_COUNTS.items():
        for role_index in range(count):
            index += 1
            values.append(
                {
                    "schema": ARTIFACT_SCHEMA,
                    "artifact_id": f"artifact:{role}:{role_index}",
                    "role": role,
                    "target": None,
                    "sha256": f"sha256:{index:064x}",
                    "size": index,
                    "publication_pointer_sha256": outcome["active_publication_pointer_sha256"],
                }
            )
    return sorted(values, key=lambda value: (str(value["role"]), str(value["artifact_id"])))


def snapshot_for(outcome: Mapping[str, Any]) -> dict[str, Any]:
    return build_verification_snapshot(
        outcome,
        active_publication(outcome),
        artifacts(outcome),
        created_at=BASE,
    )


def evidence_request_for(snapshot: Mapping[str, Any], *, at: datetime = BASE) -> dict[str, Any]:
    return build_evidence_request(
        snapshot,
        binding={
            "prometheus_datasource_uid": "prometheus-main",
            "loki_datasource_uid": "loki-main",
            "tempo_datasource_uid": "tempo-main",
        },
        catalog_sha256=digest("c"),
        evaluation_started_at=at,
    )


def evidence_records(outcome: Mapping[str, Any]) -> list[dict[str, Any]]:
    events = build_action_events(outcome, emitted_at="2026-08-13T12:00:03.000Z")
    values: list[dict[str, Any]] = []
    for event in events:
        document = event.to_dict()
        observation = cast(Mapping[str, Any], document["observation"])
        if observation["schema"] == "simulator-command-observation/v1":
            result = cast(Mapping[str, Any], observation["result"])
            subject_kind: Literal["command", "safe"] = "command"
            subject_id = cast(str, result["command_id"])
        else:
            subject_kind = "safe"
            subject_id = cast(str, cast(Mapping[str, Any], observation["target"])["id"])
        values.append(
            build_evidence_record(
                event_id=cast(str, document["event_id"]),
                signal=cast(Literal["metric", "log", "trace"], document["signal"]),
                subject_kind=subject_kind,
                subject_id=subject_id,
                trace_id=cast(Mapping[str, Any], document["correlation"])["trace_id"],
                outcome_id=cast(str, outcome["outcome_id"]),
                outcome_sha256=cast(str, outcome["outcome_sha256"]),
                action_id=cast(str, outcome["action_id"]),
                operation_id=cast(str, outcome["operation_id"]),
                observed_at=cast(str, document["observed_at"]),
                emitted_at=cast(str, document["emitted_at"]),
                retrieved_at="2026-08-13T12:00:04.000Z",
                clock_provenance="local-host-utc",
                clock_skew_milliseconds=0,
                truncated=False,
                source_label=f"grafana.{document['signal']}",
                source_envelope=document,
            )
        )
    return values


def checks_for(
    snapshot: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    *,
    override: tuple[str, Literal["failed", "unresolved"], Sequence[str]] | None = None,
) -> list[dict[str, Any]]:
    artifact_ids = [
        cast(str, value["artifact_id"])
        for value in cast(list[Mapping[str, Any]], snapshot["verification_artifacts"])
    ]
    evidence_ids = [cast(str, value["evidence_id"]) for value in records]
    results: list[dict[str, Any]] = []
    for index, name in enumerate(CHECK_NAMES):
        state: Literal["passed", "failed", "unresolved"] = "passed"
        reasons: Sequence[str] = ()
        if override is not None and override[0] == name:
            state = override[1]
            reasons = override[2]
        results.append(
            build_check_result(
                name,
                state,
                normalized_inputs_sha256=f"sha256:{index + 40:064x}",
                evidence_ids=evidence_ids if name == "post-action-telemetry-correlation" else (),
                artifact_ids=(
                    artifact_ids
                    if name == "safe-complement-preservation"
                    else (artifact_ids[index],)
                    if name != "post-action-telemetry-correlation"
                    else ()
                ),
                reason_codes=reasons,
            )
        )
    return results


def principal(
    boundary: RecoveryIdentityBoundary,
    *,
    kind: Literal["human", "service", "model"],
    roles: frozenset[str],
    incident_ids: frozenset[str] = frozenset({"incident-action-01"}),
) -> RecoveryPrincipal:
    return boundary.bind_verified_claims(
        issuer="https://issuer.example",
        subject=f"{kind}-subject",
        display_name=f"{kind.title()} Subject",
        audience="colortrace-api",
        kind=kind,
        roles=roles,
        incident_ids=incident_ids,
        credential_sha256=digest("f"),
        expires_at=BASE + timedelta(hours=1),
        credential_verified=True,
        now=BASE,
    )


def setup_services(
    tmp_path: Path,
) -> tuple[
    SQLiteRecoveryRepository,
    RecoveryVerificationService,
    RecoveryClosureService,
    RecoveryIdentityBoundary,
    Clock,
]:
    repository = SQLiteRecoveryRepository(tmp_path / "recovery.sqlite3")
    boundary = RecoveryIdentityBoundary(
        trusted_issuers=frozenset({"https://issuer.example"}),
        audience="colortrace-api",
    )
    clock = Clock()
    return (
        repository,
        RecoveryVerificationService(
            repository=repository,
            identity_boundary=boundary,
            clock=clock,
        ),
        RecoveryClosureService(
            repository=repository,
            identity_boundary=boundary,
            clock=clock,
        ),
        boundary,
        clock,
    )


def complete(
    verification: RecoveryVerificationService,
    verifier: RecoveryPrincipal,
    snapshot: Mapping[str, Any],
    request: Mapping[str, Any],
    records: list[dict[str, Any]],
    *,
    override: tuple[str, Literal["failed", "unresolved"], Sequence[str]] | None = None,
) -> tuple[Any, dict[str, Any]]:
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key=f"verification-{request['request_sha256']}",
    )
    claim = verification.claim_verification(verifier, attempt.workflow_id, owner="worker-1")
    packet = build_recovery_packet(
        snapshot,
        request,
        checks_for(snapshot, records, override=override),
        workflow_id=attempt.workflow_id,
        workflow_version=claim.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    return claim, verification.complete_verification(
        verifier,
        claim,
        packet,
        evidence_records=records,
    )


def test_verified_packet_persists_resolvable_aggregate_and_human_closes(tmp_path: Path) -> None:
    repository, verification, closure, boundary, clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    closer = principal(boundary, kind="human", roles=frozenset({"recovery.closer"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    records = evidence_records(outcome)
    _claim, packet = complete(verification, verifier, snapshot, request, records)

    aggregate = repository.durable_aggregate(packet["workflow_id"])
    assert packet["status"] == "recovery_verified"
    assert {value["evidence_id"] for value in aggregate["evidence"]} == set(packet["evidence_ids"])
    assert (
        aggregate["snapshot"]["action_outcome"]["safe_complement_before_sha256"]
        == (aggregate["snapshot"]["action_outcome"]["safe_complement_after_sha256"])
    )

    clock.now = BASE + timedelta(seconds=3)
    close_request = {
        "schema": "recovery-closure-request/v1",
        "expected_incident_version": packet["incident_version"],
        "expected_workflow_version": packet["workflow_version"],
        "expected_packet_id": packet["packet_id"],
        "expected_packet_sha256": packet["packet_sha256"],
        "expected_outcome_id": packet["outcome_id"],
        "expected_outcome_sha256": packet["outcome_sha256"],
        "reason": "Deterministic recovery checks and fresh evidence were reviewed.",
        "idempotency_key": "closure-01",
    }
    result = closure.close(closer, packet["workflow_id"], close_request)
    assert result["actor"]["subject"] == "human-subject"
    assert result["authorized_role"] == "recovery.closer"
    assert closure.close(closer, packet["workflow_id"], close_request) == result
    assert (
        repository.durable_aggregate_for_incident("incident-action-01")["review"]["status"]
        == "closed"
    )
    assert [event["event_type"] for event in repository.audit_history(packet["workflow_id"])] == [
        "verification.requested",
        "verification.claimed",
        "verification.completed",
        "recovery.closed",
    ]

    changed = {**close_request, "reason": "Changed replay reason."}
    with pytest.raises(RecoveryError, match="idempotency-conflict"):
        closure.close(closer, packet["workflow_id"], changed)
    for statement, code in (
        (
            "UPDATE recovery_closures SET result_sha256 = result_sha256 WHERE workflow_id = ?",
            "recovery-closure-append-only",
        ),
        (
            "DELETE FROM recovery_closures WHERE workflow_id = ?",
            "recovery-closure-append-only",
        ),
        (
            "DELETE FROM recovery_attempts WHERE workflow_id = ?",
            "recovery-attempt-lifecycle",
        ),
        (
            "DELETE FROM recovery_workflows WHERE workflow_id = ?",
            "recovery-workflow-lifecycle",
        ),
    ):
        with pytest.raises(sqlite3.IntegrityError, match=code):
            with repository.transaction(write=True) as connection:
                connection.execute(statement, (packet["workflow_id"],))


def test_closure_idempotency_replay_cannot_cross_workflow_authority(tmp_path: Path) -> None:
    repository, verification, closure, boundary, clock = setup_services(tmp_path)
    incident_ids = frozenset({"incident-action-01", "incident-action-02"})
    verifier = principal(
        boundary,
        kind="service",
        roles=frozenset({"recovery.verifier"}),
        incident_ids=incident_ids,
    )
    closer = principal(
        boundary,
        kind="human",
        roles=frozenset({"recovery.closer"}),
        incident_ids=incident_ids,
    )

    first_outcome = successful_outcome()
    first_snapshot = snapshot_for(first_outcome)
    first_request = evidence_request_for(first_snapshot)
    _first_claim, first_packet = complete(
        verification,
        verifier,
        first_snapshot,
        first_request,
        evidence_records(first_outcome),
    )

    second_outcome = successful_outcome()
    second_outcome["incident_id"] = "incident-action-02"
    seal_outcome(second_outcome)
    second_snapshot = snapshot_for(second_outcome)
    second_request = evidence_request_for(second_snapshot)
    _second_claim, second_packet = complete(
        verification,
        verifier,
        second_snapshot,
        second_request,
        evidence_records(second_outcome),
    )

    clock.now = BASE + timedelta(seconds=3)
    first_close = {
        "schema": "recovery-closure-request/v1",
        "expected_incident_version": first_packet["incident_version"],
        "expected_workflow_version": first_packet["workflow_version"],
        "expected_packet_id": first_packet["packet_id"],
        "expected_packet_sha256": first_packet["packet_sha256"],
        "expected_outcome_id": first_packet["outcome_id"],
        "expected_outcome_sha256": first_packet["outcome_sha256"],
        "reason": "Reviewed first workflow.",
        "idempotency_key": "workflow-scoped-close",
    }
    closure.close(closer, first_packet["workflow_id"], first_close)

    with pytest.raises(RecoveryError, match="idempotency-conflict"):
        closure.close(closer, second_packet["workflow_id"], first_close)
    assert repository.review(second_packet["workflow_id"])["status"] == "recovery_verified"


@pytest.mark.parametrize(
    ("check", "state", "reason", "expected"),
    [
        ("approved-resource-state", "failed", "resource-state-mismatch", "recovery_failed"),
        ("exact-typed-lineage", "unresolved", "lineage-evidence-missing", "recovery_unresolved"),
    ],
)
def test_packet_status_precedence(
    tmp_path: Path,
    check: str,
    state: Literal["failed", "unresolved"],
    reason: str,
    expected: str,
) -> None:
    _repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    _claim, packet = complete(
        verification,
        verifier,
        snapshot,
        request,
        evidence_records(outcome),
        override=(check, state, (reason,)),
    )
    assert packet["status"] == expected
    assert packet["eligible_for_closure"] is False


def test_missing_and_pre_action_evidence_are_unresolved(tmp_path: Path) -> None:
    _repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    state, reasons, ids = assess_post_action_observations(
        snapshot,
        [],
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    assert state == "unresolved"
    assert "observation-set-incomplete" in reasons
    assert ids == ()
    _claim, packet = complete(
        verification,
        verifier,
        snapshot,
        request,
        [],
        override=("post-action-telemetry-correlation", "unresolved", reasons),
    )
    assert packet["status"] == "recovery_unresolved"

    pre_action = evidence_records(outcome)
    changed = copy.deepcopy(pre_action[0])
    changed["observed_at"] = outcome["action_started_at"]
    changed["emitted_at"] = outcome["action_started_at"]
    body = {
        key: value
        for key, value in changed.items()
        if key not in {"evidence_id", "evidence_sha256"}
    }
    changed["evidence_sha256"] = document_sha256(body)
    changed["evidence_id"] = (
        f"recovery-evidence:{changed['evidence_sha256'].removeprefix('sha256:')}"
    )
    pre_action[0] = changed
    assessed, pre_reasons, _ = assess_post_action_observations(
        snapshot,
        pre_action,
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    assert assessed == "unresolved"
    assert "pre-action-observation" in pre_reasons


def test_identical_duplicate_event_dedupes_but_conflict_is_unresolved() -> None:
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    records = evidence_records(outcome)
    duplicated = [*records, copy.deepcopy(records[0])]
    state, reasons, ids = assess_post_action_observations(
        snapshot,
        duplicated,
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    assert state == "passed"
    assert reasons == ()
    assert len(ids) == 21

    conflicting = copy.deepcopy(records[0])
    conflicting["source_label"] = "grafana.conflicting"
    body = {
        key: value
        for key, value in conflicting.items()
        if key not in {"evidence_id", "evidence_sha256"}
    }
    conflicting["evidence_sha256"] = document_sha256(body)
    conflicting["evidence_id"] = (
        f"recovery-evidence:{conflicting['evidence_sha256'].removeprefix('sha256:')}"
    )
    state, reasons, _ids = assess_post_action_observations(
        snapshot,
        [*records, conflicting],
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    assert state == "unresolved"
    assert "observation-event-conflict" in reasons


def test_observation_subject_substitution_fails_exact_event_authority() -> None:
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    records = evidence_records(outcome)
    substituted = copy.deepcopy(records)
    substituted[0]["subject_id"] = "forged-command"
    body = {
        key: value
        for key, value in substituted[0].items()
        if key not in {"evidence_id", "evidence_sha256"}
    }
    substituted[0]["evidence_sha256"] = document_sha256(body)
    substituted[0]["evidence_id"] = (
        f"recovery-evidence:{substituted[0]['evidence_sha256'].removeprefix('sha256:')}"
    )
    state, reasons, _ids = assess_post_action_observations(
        snapshot,
        substituted,
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    assert state == "failed"
    assert "observation-authority-mismatch" in reasons

    duplicate_subject = copy.deepcopy(records)
    duplicate_subject[3]["subject_id"] = duplicate_subject[0]["subject_id"]
    body = {
        key: value
        for key, value in duplicate_subject[3].items()
        if key not in {"evidence_id", "evidence_sha256"}
    }
    duplicate_subject[3]["evidence_sha256"] = document_sha256(body)
    duplicate_subject[3]["evidence_id"] = (
        f"recovery-evidence:{duplicate_subject[3]['evidence_sha256'].removeprefix('sha256:')}"
    )
    state, reasons, _ids = assess_post_action_observations(
        snapshot,
        duplicate_subject,
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    assert state == "failed"
    assert "observation-authority-mismatch" in reasons

    with pytest.raises(RecoveryError, match="evaluation-time-invalid"):
        assess_post_action_observations(
            snapshot,
            records,
            evaluation_started_at=datetime(2026, 8, 13, 12, 0, 3),
            evaluation_completed_at=BASE + timedelta(seconds=2),
        )


def test_claim_expiry_reclaims_and_fences_stale_worker(tmp_path: Path) -> None:
    _repository, verification, _closure, boundary, clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="fencing-attempt",
    )
    stale = verification.claim_verification(verifier, attempt.workflow_id, owner="worker-old")
    clock.now = BASE + timedelta(seconds=31)
    current = verification.claim_verification(verifier, attempt.workflow_id, owner="worker-new")
    records = evidence_records(outcome)
    stale_packet = build_recovery_packet(
        snapshot,
        request,
        checks_for(snapshot, records),
        workflow_id=attempt.workflow_id,
        workflow_version=stale.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    with pytest.raises(RecoveryError, match="claim-fenced"):
        verification.complete_verification(
            verifier,
            stale,
            stale_packet,
            evidence_records=records,
        )
    current_packet = build_recovery_packet(
        snapshot,
        request,
        checks_for(snapshot, records),
        workflow_id=attempt.workflow_id,
        workflow_version=current.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    assert (
        verification.complete_verification(
            verifier,
            current,
            current_packet,
            evidence_records=records,
        )["status"]
        == "recovery_verified"
    )


def test_completion_fences_at_lease_boundary_but_late_unresolved_is_durable(
    tmp_path: Path,
) -> None:
    fenced_root = tmp_path / "fenced"
    fenced_root.mkdir()
    _repository, verification, _closure, boundary, clock = setup_services(fenced_root)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    records = evidence_records(outcome)
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="lease-boundary",
    )
    claim = verification.claim_verification(verifier, attempt.workflow_id, owner="worker")
    verified = build_recovery_packet(
        snapshot,
        request,
        checks_for(snapshot, records),
        workflow_id=attempt.workflow_id,
        workflow_version=claim.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    clock.now = BASE + timedelta(seconds=30)
    with pytest.raises(RecoveryError, match="claim-fenced"):
        verification.complete_verification(
            verifier,
            claim,
            verified,
            evidence_records=records,
        )

    unresolved_root = tmp_path / "unresolved"
    unresolved_root.mkdir()
    repository, verification, _closure, boundary, clock = setup_services(unresolved_root)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="late-unresolved",
    )
    claim = verification.claim_verification(verifier, attempt.workflow_id, owner="worker")
    state, reasons, _ids = assess_post_action_observations(
        snapshot,
        [],
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=60),
    )
    assert state == "unresolved"
    unresolved = build_recovery_packet(
        snapshot,
        request,
        checks_for(
            snapshot,
            [],
            override=("post-action-telemetry-correlation", "unresolved", reasons),
        ),
        workflow_id=attempt.workflow_id,
        workflow_version=claim.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=60),
    )
    clock.now = BASE + timedelta(minutes=11)
    assert (
        verification.complete_verification(
            verifier,
            claim,
            unresolved,
            evidence_records=(),
        )["status"]
        == "recovery_unresolved"
    )
    assert repository.review(attempt.workflow_id)["status"] == "recovery_unresolved"


@pytest.mark.parametrize(
    "drift_sql",
    [
        "DROP TRIGGER recovery_audit_no_delete",
        "ALTER TABLE recovery_workflows ADD COLUMN drift_marker TEXT",
    ],
)
def test_repository_reopen_rejects_exact_schema_manifest_drift(
    tmp_path: Path,
    drift_sql: str,
) -> None:
    database = tmp_path / "recovery.sqlite3"
    repository = SQLiteRecoveryRepository(database)
    repository.close()
    connection = sqlite3.connect(database)
    connection.execute(drift_sql)
    connection.commit()
    connection.close()
    with pytest.raises(RecoveryError, match="database-schema-invalid"):
        SQLiteRecoveryRepository(database)


def test_closure_rejects_service_model_missing_role_and_stale_version(tmp_path: Path) -> None:
    _repository, verification, closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    _claim, packet = complete(verification, verifier, snapshot, request, evidence_records(outcome))
    body = {
        "schema": "recovery-closure-request/v1",
        "expected_incident_version": packet["incident_version"],
        "expected_workflow_version": packet["workflow_version"] + 1,
        "expected_packet_id": packet["packet_id"],
        "expected_packet_sha256": packet["packet_sha256"],
        "expected_outcome_id": packet["outcome_id"],
        "expected_outcome_sha256": packet["outcome_sha256"],
        "reason": "Reviewed.",
        "idempotency_key": "unauthorized-close",
    }
    service_closer = principal(
        boundary,
        kind="service",
        roles=frozenset({"recovery.closer"}),
    )
    with pytest.raises(RecoveryError, match="closure-human-required"):
        closure.close(service_closer, packet["workflow_id"], body)
    model = principal(boundary, kind="model", roles=frozenset({"recovery.closer"}))
    with pytest.raises(RecoveryError, match="model-authority-forbidden"):
        closure.close(model, packet["workflow_id"], body)
    human = principal(boundary, kind="human", roles=frozenset({"response-plan.approver"}))
    with pytest.raises(RecoveryError, match="closer-role-required"):
        closure.close(human, packet["workflow_id"], body)
    closer = principal(boundary, kind="human", roles=frozenset({"recovery.closer"}))
    with pytest.raises(RecoveryError, match="closure-expected-version-conflict"):
        closure.close(closer, packet["workflow_id"], body)


def test_citations_must_resolve_once_and_stored_snapshot_tamper_fails(tmp_path: Path) -> None:
    repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    records = evidence_records(outcome)
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="citation-attempt",
    )
    claim = verification.claim_verification(verifier, attempt.workflow_id, owner="worker-1")
    packet = build_recovery_packet(
        snapshot,
        request,
        checks_for(snapshot, records),
        workflow_id=attempt.workflow_id,
        workflow_version=claim.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    with pytest.raises(RecoveryError, match="evidence-citation-unresolved"):
        verification.complete_verification(
            verifier,
            claim,
            packet,
            evidence_records=records[:-1],
        )
    with pytest.raises(RecoveryError, match="evidence-citation-duplicate"):
        verification.complete_verification(
            verifier,
            claim,
            packet,
            evidence_records=[*records, records[0]],
        )
    verification.complete_verification(verifier, claim, packet, evidence_records=records)

    tampered = copy.deepcopy(snapshot)
    tampered["created_at"] = "2026-08-13T12:00:03.500Z"
    with repository.transaction(write=True) as connection:
        connection.execute(
            "UPDATE recovery_workflows SET snapshot_document = ? WHERE workflow_id = ?",
            (canonical_json_bytes(tampered), attempt.workflow_id),
        )
    with pytest.raises(RecoveryError, match="snapshot-digest-invalid"):
        repository.durable_aggregate(attempt.workflow_id)


def test_active_binding_and_complete_outcome_contract_fail_closed() -> None:
    outcome = successful_outcome()
    active = active_publication(outcome)
    active["pointer_sha256"] = digest("0")
    with pytest.raises(RecoveryError, match="active-publication-binding-invalid"):
        build_verification_snapshot(outcome, active, artifacts(outcome), created_at=BASE)

    widened = copy.deepcopy(outcome)
    widened["unexpected_authority"] = True
    seal_outcome(widened)
    with pytest.raises(RecoveryError, match="action-outcome-invalid"):
        snapshot_for(widened)


def test_new_outcome_requires_terminal_old_workflow_and_preserves_history(tmp_path: Path) -> None:
    repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    first_outcome = successful_outcome()
    first_snapshot = snapshot_for(first_outcome)
    first_request = evidence_request_for(first_snapshot)
    _claim, first_packet = complete(
        verification,
        verifier,
        first_snapshot,
        first_request,
        evidence_records(first_outcome),
        override=("approved-resource-state", "failed", ("resource-state-mismatch",)),
    )
    assert first_packet["status"] == "recovery_failed"

    second_outcome = copy.deepcopy(first_outcome)
    second_outcome["action_id"] = f"simulator-action:{'9' * 64}"
    second_outcome["task_key"] = f"dispatch-task:{'9' * 64}"
    second_outcome["operation_id"] = f"dispatch-operation:{'9' * 64}"
    second_outcome["payload_sha256"] = digest("9")
    seal_outcome(second_outcome)
    second_snapshot = snapshot_for(second_outcome)
    second_request = evidence_request_for(second_snapshot, at=BASE + timedelta(milliseconds=100))
    second = verification.request_verification(
        verifier,
        second_snapshot,
        second_request,
        idempotency_key="second-outcome",
    )
    assert second.workflow_id != first_packet["workflow_id"]
    assert repository.durable_aggregate(first_packet["workflow_id"])["review"]["status"] == (
        "recovery_failed"
    )
    assert (
        repository.durable_aggregate_for_incident("incident-action-01")["review"]["workflow_id"]
        == second.workflow_id
    )

    third_outcome = copy.deepcopy(second_outcome)
    third_outcome["action_id"] = f"simulator-action:{'a' * 64}"
    third_outcome["task_key"] = f"dispatch-task:{'a' * 64}"
    third_outcome["operation_id"] = f"dispatch-operation:{'a' * 64}"
    third_outcome["payload_sha256"] = digest("a")
    seal_outcome(third_outcome)
    third_snapshot = snapshot_for(third_outcome)
    with pytest.raises(RecoveryError, match="active-recovery-workflow-conflict"):
        verification.request_verification(
            verifier,
            third_snapshot,
            evidence_request_for(third_snapshot, at=BASE + timedelta(milliseconds=200)),
            idempotency_key="third-outcome",
        )


def test_registration_replay_returns_exact_historical_attempt(tmp_path: Path) -> None:
    _repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    first_request = evidence_request_for(snapshot)
    state, reasons, _ids = assess_post_action_observations(
        snapshot,
        [],
        evaluation_started_at=BASE,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    first_claim, packet = complete(
        verification,
        verifier,
        snapshot,
        first_request,
        [],
        override=("post-action-telemetry-correlation", state, reasons),
    )
    assert packet["status"] == "recovery_unresolved"

    second_request = evidence_request_for(snapshot, at=BASE + timedelta(milliseconds=100))
    second = verification.request_verification(
        verifier,
        snapshot,
        second_request,
        idempotency_key="verification-second-attempt",
    )
    replay = verification.request_verification(
        verifier,
        snapshot,
        first_request,
        idempotency_key=f"verification-{first_request['request_sha256']}",
    )
    assert replay.attempt_id == first_claim.attempt_id
    assert replay.attempt_number == 1
    assert replay.workflow_version == 1
    assert second.attempt_id != replay.attempt_id
    assert second.attempt_number == 2
    with pytest.raises(RecoveryError, match="idempotency-conflict"):
        verification.request_verification(
            verifier,
            snapshot,
            second_request,
            idempotency_key=f"verification-{first_request['request_sha256']}",
        )


def test_new_outcome_rejects_tampered_prior_workflow_status(tmp_path: Path) -> None:
    _repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    first_outcome = successful_outcome()
    first_snapshot = snapshot_for(first_outcome)
    first = verification.request_verification(
        verifier,
        first_snapshot,
        evidence_request_for(first_snapshot),
        idempotency_key="tampered-prior-workflow",
    )
    connection = sqlite3.connect(tmp_path / "recovery.sqlite3")
    connection.execute(
        "UPDATE recovery_workflows SET status = 'recovery_failed' WHERE workflow_id = ?",
        (first.workflow_id,),
    )
    connection.commit()
    connection.close()

    second_outcome = copy.deepcopy(first_outcome)
    second_outcome["action_id"] = f"simulator-action:{'b' * 64}"
    second_outcome["task_key"] = f"dispatch-task:{'b' * 64}"
    second_outcome["operation_id"] = f"dispatch-operation:{'b' * 64}"
    second_outcome["payload_sha256"] = digest("b")
    seal_outcome(second_outcome)
    second_snapshot = snapshot_for(second_outcome)
    with pytest.raises(RecoveryError, match="stored-attempt-lifecycle-invalid"):
        verification.request_verification(
            verifier,
            second_snapshot,
            evidence_request_for(second_snapshot, at=BASE + timedelta(milliseconds=100)),
            idempotency_key="blocked-second-outcome",
        )


def test_append_only_evidence_and_audit_tables_reject_tamper(tmp_path: Path) -> None:
    repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    _claim, packet = complete(verification, verifier, snapshot, request, evidence_records(outcome))
    with pytest.raises(sqlite3.IntegrityError, match="recovery-evidence-append-only"):
        with repository.transaction(write=True) as connection:
            connection.execute(
                "UPDATE recovery_evidence_records SET sequence = sequence + 100 "
                "WHERE workflow_id = ?",
                (packet["workflow_id"],),
            )
    with pytest.raises(sqlite3.IntegrityError, match="recovery-audit-append-only"):
        with repository.transaction(write=True) as connection:
            connection.execute(
                "DELETE FROM recovery_audit_events WHERE workflow_id = ?",
                (packet["workflow_id"],),
            )
    with pytest.raises(
        sqlite3.IntegrityError,
        match="recovery-audit-head-(append-only|invalid)",
    ):
        with repository.transaction(write=True) as connection:
            connection.execute(
                "DELETE FROM recovery_audit_heads WHERE workflow_id = ?",
                (packet["workflow_id"],),
            )
    with pytest.raises(sqlite3.IntegrityError, match="recovery-audit-head-invalid"):
        with repository.transaction(write=True) as connection:
            connection.execute(
                "UPDATE recovery_audit_heads SET sequence = sequence WHERE workflow_id = ?",
                (packet["workflow_id"],),
            )
    with pytest.raises(sqlite3.IntegrityError, match="recovery-audit-sequence-invalid"):
        with repository.transaction(write=True) as connection:
            connection.execute(
                "INSERT INTO recovery_audit_events("
                "workflow_id, sequence, event_sha256, document) VALUES(?, ?, ?, ?)",
                (packet["workflow_id"], 99, digest("e"), b"{}"),
            )
    with pytest.raises(sqlite3.IntegrityError, match="recovery-evidence-append-only"):
        with repository.transaction(write=True) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO recovery_evidence_records "
                "SELECT * FROM recovery_evidence_records WHERE workflow_id = ?",
                (packet["workflow_id"],),
            )


def test_claim_renewal_must_strictly_extend_the_existing_lease(tmp_path: Path) -> None:
    repository, verification, _closure, boundary, clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="renew-clock-regression",
    )
    claim = verification.claim_verification(verifier, attempt.workflow_id, owner="worker-1")
    actor = boundary.assert_verifier(
        verifier,
        incident_id=attempt.incident_id,
        now=BASE,
    )

    with pytest.raises(RecoveryError, match="claim-clock-regression"):
        repository.renew_claim(
            claim,
            actor=actor,
            now="2026-08-13T12:00:02.000Z",
        )
    clock.now = BASE + timedelta(seconds=1)
    renewed = verification.renew_claim(verifier, claim)
    assert renewed.workflow_version == claim.workflow_version + 1
    assert [event["event_type"] for event in repository.audit_history(attempt.workflow_id)] == [
        "verification.requested",
        "verification.claimed",
        "verification.renewed",
    ]
    connection = sqlite3.connect(tmp_path / "recovery.sqlite3")
    connection.execute(
        "UPDATE recovery_attempts SET updated_at = '2036-08-13T12:00:03.000Z', "
        "claim_expires_at = '2036-08-13T12:00:33.000Z' WHERE attempt_id = ?",
        (attempt.attempt_id,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(RecoveryError, match="stored-claim-lifecycle-invalid"):
        repository.review(attempt.workflow_id)


def test_completion_rejects_time_before_the_current_claim(tmp_path: Path) -> None:
    repository, verification, _closure, boundary, clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    records = evidence_records(outcome)
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="completion-clock-regression",
    )
    claim = verification.claim_verification(verifier, attempt.workflow_id, owner="worker-1")
    packet = build_recovery_packet(
        snapshot,
        request,
        checks_for(snapshot, records),
        workflow_id=attempt.workflow_id,
        workflow_version=claim.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    clock.now = BASE - timedelta(seconds=1)

    with pytest.raises(RecoveryError, match="claim-clock-regression"):
        verification.complete_verification(
            verifier,
            claim,
            packet,
            evidence_records=records,
        )
    assert repository.review(attempt.workflow_id)["status"] == "verification_running"


def _completed_recovery_database(tmp_path: Path) -> tuple[Path, str]:
    repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    _claim, packet = complete(
        verification,
        verifier,
        snapshot,
        request,
        evidence_records(outcome),
    )
    repository.close()
    return tmp_path / "recovery.sqlite3", cast(str, packet["workflow_id"])


V3_GUARD_TRIGGERS = (
    "recovery_claim_lease_baseline_no_update",
    "recovery_claim_lease_baseline_no_delete",
    "recovery_claim_lease_baseline_no_replace",
    "recovery_claim_lease_baseline_no_insert",
    "recovery_audit_insert_no_replace",
    "recovery_audit_insert_next",
    "recovery_audit_head_insert_no_replace",
    "recovery_audit_head_insert_exact",
    "recovery_audit_head_advance_exact",
    "recovery_audit_head_no_delete",
    "recovery_evidence_insert_no_replace",
    "recovery_workflow_no_delete",
    "recovery_workflow_insert_no_replace",
    "recovery_attempt_no_delete",
    "recovery_attempt_insert_no_replace",
    "recovery_closure_no_update",
    "recovery_closure_no_delete",
    "recovery_closure_insert_no_replace",
)
V3_SCHEMA_TABLES = ("recovery_claim_lease_baselines",)


def test_default_external_connection_cannot_replace_append_only_rows(tmp_path: Path) -> None:
    database, workflow_id = _completed_recovery_database(tmp_path)
    connection = sqlite3.connect(database)
    assert connection.execute("PRAGMA recursive_triggers").fetchone()[0] == 0
    with pytest.raises(sqlite3.IntegrityError, match="recovery-evidence-append-only"):
        connection.execute(
            "INSERT OR REPLACE INTO recovery_evidence_records "
            "SELECT * FROM recovery_evidence_records WHERE workflow_id = ?",
            (workflow_id,),
        )
    connection.rollback()
    with pytest.raises(
        sqlite3.IntegrityError,
        match="recovery-audit-head-(append-only|invalid)",
    ):
        connection.execute(
            "INSERT OR REPLACE INTO recovery_audit_heads "
            "SELECT * FROM recovery_audit_heads WHERE workflow_id = ?",
            (workflow_id,),
        )
    connection.rollback()
    with pytest.raises(
        sqlite3.IntegrityError,
        match="recovery-claim-lease-baseline-migration-only",
    ):
        connection.execute(
            "INSERT INTO recovery_claim_lease_baselines("
            "attempt_id, after_sequence, attempt_status, claim_generation, claim_owner, "
            "lease_expires_at, updated_at) "
            "SELECT attempt_id, 3, 'complete', claim_generation, claim_owner, "
            "'2036-08-13T12:00:33.000Z', updated_at FROM recovery_attempts "
            "WHERE workflow_id = ?",
            (workflow_id,),
        )
    connection.rollback()
    connection.close()


def _rewrite_with_restored_triggers(
    database: Path,
    trigger_names: tuple[str, ...],
    statements: tuple[tuple[str, tuple[Any, ...]], ...],
) -> None:
    connection = sqlite3.connect(database)
    triggers = {
        cast(str, name): cast(str, sql)
        for name, sql in connection.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' "
            f"AND name IN ({','.join('?' for _ in trigger_names)})",
            trigger_names,
        )
    }
    assert set(triggers) == set(trigger_names)
    for name in trigger_names:
        connection.execute(f'DROP TRIGGER "{name}"')
    for statement, parameters in statements:
        connection.execute(statement, parameters)
    for name in trigger_names:
        connection.execute(triggers[name])
    connection.commit()
    connection.close()


def test_valid_v2_database_migrates_once_and_reopens_with_exact_v3_guards(
    tmp_path: Path,
) -> None:
    database, workflow_id = _completed_recovery_database(tmp_path)
    connection = sqlite3.connect(database)
    for name in V3_GUARD_TRIGGERS:
        connection.execute(f'DROP TRIGGER "{name}"')
    for name in V3_SCHEMA_TABLES:
        connection.execute(f'DROP TABLE "{name}"')
    connection.execute("PRAGMA user_version = 2")
    connection.commit()
    connection.close()

    migrated = SQLiteRecoveryRepository(database)
    assert migrated.review(workflow_id)["status"] == "recovery_verified"
    with migrated.transaction(write=False) as migrated_connection:
        assert migrated_connection.execute("PRAGMA user_version").fetchone()[0] == 3
        triggers = {
            row[0]
            for row in migrated_connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'recovery_%'"
            )
        }
    assert set(V3_GUARD_TRIGGERS).issubset(triggers)
    migrated.close()
    reopened = SQLiteRecoveryRepository(database)
    assert reopened.review(workflow_id)["status"] == "recovery_verified"


def test_v2_running_renewal_migrates_with_an_immutable_lease_baseline(tmp_path: Path) -> None:
    repository, verification, _closure, boundary, _clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="v2-running-renewal",
    )
    verification.claim_verification(verifier, attempt.workflow_id, owner="worker-1")
    repository.close()
    database = tmp_path / "recovery.sqlite3"
    connection = sqlite3.connect(database)
    for name in V3_GUARD_TRIGGERS:
        connection.execute(f'DROP TRIGGER "{name}"')
    for name in V3_SCHEMA_TABLES:
        connection.execute(f'DROP TABLE "{name}"')
    connection.execute("PRAGMA user_version = 2")
    connection.execute(
        "UPDATE recovery_attempts SET updated_at = '2026-08-13T12:00:04.000Z', "
        "claim_expires_at = '2026-08-13T12:00:34.000Z' WHERE attempt_id = ?",
        (attempt.attempt_id,),
    )
    connection.commit()
    connection.close()

    migrated = SQLiteRecoveryRepository(database)
    assert migrated.review(attempt.workflow_id)["status"] == "verification_running"
    with migrated.transaction(write=False) as migrated_connection:
        row = migrated_connection.execute(
            "SELECT updated_at, claim_expires_at FROM recovery_attempts WHERE attempt_id = ?",
            (attempt.attempt_id,),
        ).fetchone()
    assert row["updated_at"] == "2026-08-13T12:00:04.000Z"
    assert row["claim_expires_at"] == "2026-08-13T12:00:34.000Z"


def test_v2_completed_renewal_migrates_with_an_immutable_lease_baseline(tmp_path: Path) -> None:
    repository, verification, _closure, boundary, clock = setup_services(tmp_path)
    verifier = principal(boundary, kind="service", roles=frozenset({"recovery.verifier"}))
    outcome = successful_outcome()
    snapshot = snapshot_for(outcome)
    request = evidence_request_for(snapshot)
    records = evidence_records(outcome)
    attempt = verification.request_verification(
        verifier,
        snapshot,
        request,
        idempotency_key="v2-completed-renewal",
    )
    claim = verification.claim_verification(verifier, attempt.workflow_id, owner="worker-1")
    packet = build_recovery_packet(
        snapshot,
        request,
        checks_for(snapshot, records),
        workflow_id=attempt.workflow_id,
        workflow_version=claim.workflow_version + 1,
        attempt_id=attempt.attempt_id,
        attempt_number=attempt.attempt_number,
        evaluation_completed_at=BASE + timedelta(seconds=2),
    )
    clock.now = BASE + timedelta(seconds=2)
    verification.complete_verification(
        verifier,
        claim,
        packet,
        evidence_records=records,
    )
    repository.close()
    database = tmp_path / "recovery.sqlite3"
    connection = sqlite3.connect(database)
    for name in V3_GUARD_TRIGGERS:
        connection.execute(f'DROP TRIGGER "{name}"')
    for name in V3_SCHEMA_TABLES:
        connection.execute(f'DROP TABLE "{name}"')
    connection.execute("PRAGMA user_version = 2")
    connection.execute(
        "UPDATE recovery_attempts SET claim_expires_at = '2026-08-13T12:00:34.000Z' "
        "WHERE attempt_id = ?",
        (attempt.attempt_id,),
    )
    connection.commit()
    connection.close()

    migrated = SQLiteRecoveryRepository(database)
    assert migrated.review(attempt.workflow_id)["status"] == "recovery_verified"
    with migrated.transaction(write=False) as migrated_connection:
        stored_expiry = migrated_connection.execute(
            "SELECT claim_expires_at FROM recovery_attempts WHERE attempt_id = ?",
            (attempt.attempt_id,),
        ).fetchone()[0]
    assert stored_expiry == "2026-08-13T12:00:34.000Z"


def test_invalid_v2_migration_rolls_back_schema_and_version_before_rejection(
    tmp_path: Path,
) -> None:
    database, _workflow_id = _completed_recovery_database(tmp_path)
    connection = sqlite3.connect(database)
    for name in V3_GUARD_TRIGGERS:
        connection.execute(f'DROP TRIGGER "{name}"')
    for name in V3_SCHEMA_TABLES:
        connection.execute(f'DROP TABLE "{name}"')
    connection.execute("PRAGMA user_version = 2")
    connection.execute(
        "INSERT INTO recovery_evidence_records("
        "evidence_id, workflow_id, attempt_id, sequence, evidence_sha256, document) "
        "VALUES('orphan-evidence', 'orphan-workflow', 'orphan-attempt', 1, ?, ?)",
        (digest("c"), b"{}"),
    )
    connection.commit()
    connection.close()

    with pytest.raises(RecoveryError, match="database-integrity-invalid"):
        SQLiteRecoveryRepository(database)
    connection = sqlite3.connect(database)
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    remaining = {
        row[0]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }
    connection.close()
    assert not set(V3_GUARD_TRIGGERS) & remaining


@pytest.mark.parametrize(
    "tamper",
    [
        "missing-head",
        "row-mismatch",
        "orphan-tail",
        "attempt-mismatch",
        "workflow-status",
        "lease-extension",
    ],
)
def test_reads_reconcile_exact_rows_head_and_lifecycle(
    tmp_path: Path,
    tamper: str,
) -> None:
    database, workflow_id = _completed_recovery_database(tmp_path)
    if tamper == "missing-head":
        _rewrite_with_restored_triggers(
            database,
            ("recovery_audit_head_no_delete",),
            (("DELETE FROM recovery_audit_heads WHERE workflow_id = ?", (workflow_id,)),),
        )
    elif tamper == "row-mismatch":
        _rewrite_with_restored_triggers(
            database,
            ("recovery_audit_no_update",),
            (
                (
                    "UPDATE recovery_audit_events SET event_sha256 = ? "
                    "WHERE workflow_id = ? AND sequence = 1",
                    (digest("d"), workflow_id),
                ),
            ),
        )
    elif tamper == "orphan-tail":
        connection = sqlite3.connect(database)
        connection.execute(
            "INSERT INTO recovery_audit_events("
            "workflow_id, sequence, event_sha256, document) VALUES(?, 4, ?, ?)",
            (workflow_id, digest("e"), b"{}"),
        )
        connection.commit()
        connection.close()
    elif tamper == "attempt-mismatch":
        connection = sqlite3.connect(database)
        connection.execute(
            "UPDATE recovery_attempts SET claim_generation = claim_generation + 1 "
            "WHERE workflow_id = ?",
            (workflow_id,),
        )
        connection.commit()
        connection.close()
    elif tamper == "workflow-status":
        connection = sqlite3.connect(database)
        connection.execute(
            "UPDATE recovery_workflows SET status = 'recovery_unresolved' WHERE workflow_id = ?",
            (workflow_id,),
        )
        connection.commit()
        connection.close()
    else:
        connection = sqlite3.connect(database)
        connection.execute(
            "UPDATE recovery_attempts SET claim_expires_at = '2036-08-13T12:00:33.000Z' "
            "WHERE workflow_id = ?",
            (workflow_id,),
        )
        connection.commit()
        connection.close()

    repository = SQLiteRecoveryRepository(database)
    with pytest.raises(RecoveryError):
        repository.review(workflow_id)


def test_coordinated_tail_and_head_rewind_fails_after_triggers_are_restored(
    tmp_path: Path,
) -> None:
    database, workflow_id = _completed_recovery_database(tmp_path)
    connection = sqlite3.connect(database)
    prior = connection.execute(
        "SELECT event_sha256 FROM recovery_audit_events WHERE workflow_id = ? AND sequence = 2",
        (workflow_id,),
    ).fetchone()
    connection.close()
    assert prior is not None
    _rewrite_with_restored_triggers(
        database,
        ("recovery_audit_no_delete", "recovery_audit_head_advance_exact"),
        (
            (
                "UPDATE recovery_audit_heads SET sequence = 2, event_sha256 = ? "
                "WHERE workflow_id = ?",
                (prior[0], workflow_id),
            ),
            (
                "DELETE FROM recovery_audit_events WHERE workflow_id = ? AND sequence = 3",
                (workflow_id,),
            ),
        ),
    )

    repository = SQLiteRecoveryRepository(database)
    with pytest.raises(RecoveryError, match="stored-audit-lifecycle-invalid"):
        repository.review(workflow_id)
