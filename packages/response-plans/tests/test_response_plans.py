from __future__ import annotations

import concurrent.futures
import copy
import sqlite3
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from colortrace_response_plans import (
    APPROVER_ROLE,
    DISPATCHER_ROLE,
    EDITOR_ROLE,
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    ResponsePlanError,
    ResponsePlanService,
    SQLiteResponsePlanRepository,
    VerifiedPrincipal,
    validate_audit_chain,
    validate_decision,
    validate_dispatch_authorization,
    validate_plan,
)
from colortrace_response_plans.contracts import (
    build_decision,
    build_dispatch_authorization,
    build_plan,
    canonical_json_bytes,
    component_digest,
    prefixed_sha256,
)

NOW = datetime(2026, 8, 13, 15, 0, tzinfo=UTC)
INCIDENT_ID = "incident-response-plan"
PACKET_SHA256 = f"sha256:{'6' * 64}"
PACKET_ID = f"response-packet:{'6' * 64}"
SCOPE_SHA256 = f"sha256:{'7' * 64}"
IDENTITY_BOUNDARY = OIDCTrustBoundary(
    trusted_issuers=frozenset({"https://identity.example.test"}),
    audience="colortrace-api",
)
CANONICAL_AUTHORITY_BOUNDARY = CanonicalAuthorityBoundary()


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def target(
    kind: str, identifier: str, *, namespace: str = "colortrace-simulator"
) -> dict[str, str]:
    return {
        "schema": "simulator-target/v1",
        "namespace": namespace,
        "kind": kind,
        "id": identifier,
    }


def action_envelope() -> dict[str, Any]:
    return {
        "schema": "simulator-action-envelope/v1",
        "fixture_id": "colortrace-canonical",
        "fixture_manifest_sha256": digest("0"),
        "fixture_generation": 7,
        "source_batch_id": "fixture-run-canonical",
        "source_batch_sha256": digest("1"),
        "runtime_manifest_sha256": digest("2"),
        "runtime_generation": 7,
        "expected_publication_pointer_sha256": digest("3"),
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


def plan_inputs() -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, Any]]]:
    targets = [
        target("color-resource", digest("a")),
        target("frame", "frame-affected-a"),
        target("derivative", "derivative-affected-a"),
    ]
    exclusions = [
        target("frame", "frame-safe-a"),
        target("frame", "frame-safe-b"),
    ]
    commands: list[dict[str, Any]] = [
        {
            "schema": "simulator-quarantine-command/v1",
            "command_id": "command-quarantine-resource",
            "namespace": "colortrace-simulator",
            "target": targets[0],
            "action_envelope": action_envelope(),
            "expected_resource_sha256": digest("a"),
            "mode": "quarantine-and-install-approved-replacement",
        },
        {
            "schema": "simulator-targeted-rerender-command/v1",
            "command_id": "command-rerender-frame",
            "namespace": "colortrace-simulator",
            "target": targets[1],
            "action_envelope": action_envelope(),
            "job_id": "job-frame-affected-a",
            "transform_id": "look/main/v1",
            "source_id": "source-frame-affected-a",
            "source_manifest_sha256": digest("9"),
            "source_png_sha256": digest("b"),
            "expected_config_sha256": digest("c"),
            "expected_output_sha256": digest("d"),
            "expected_display_sha256": digest("e"),
            "lineage_parent_artifact_id": "source-frame-affected-a",
        },
        {
            "schema": "simulator-targeted-rerender-command/v1",
            "command_id": "command-rerender-derivative",
            "namespace": "colortrace-simulator",
            "target": targets[2],
            "action_envelope": action_envelope(),
            "job_id": "job-derivative-affected-a",
            "transform_id": "look/main/v1",
            "source_id": "source-derivative-affected-a",
            "source_manifest_sha256": digest("9"),
            "source_png_sha256": digest("d"),
            "expected_config_sha256": digest("e"),
            "expected_derivative_sha256": digest("f"),
            "expected_derivative_display_sha256": digest("0"),
            "lineage_parent_artifact_id": "frame-affected-a",
        },
    ]
    return targets, exclusions, commands


def principal(
    role: str,
    *,
    subject: str,
    kind: str = "human",
    incidents: frozenset[str] = frozenset({INCIDENT_ID}),
) -> VerifiedPrincipal:
    return IDENTITY_BOUNDARY.bind_verified_claims(
        issuer="https://identity.example.test",
        subject=subject,
        audience="colortrace-api",
        kind=kind,
        roles=frozenset({role}),
        incident_ids=incidents,
        credential_sha256=digest("8"),
        expires_at=NOW + timedelta(hours=1),
        credential_verified=True,
        now=NOW,
    )


@pytest.fixture
def editor() -> VerifiedPrincipal:
    return principal(EDITOR_ROLE, subject="operator-editor")


@pytest.fixture
def approver() -> VerifiedPrincipal:
    return principal(APPROVER_ROLE, subject="operator-approver")


@pytest.fixture
def dispatcher() -> VerifiedPrincipal:
    return principal(DISPATCHER_ROLE, subject="worker-dispatcher", kind="service")


def prepare_repository(
    database: str | Path = ":memory:",
    *,
    unresolved_item_ids: Sequence[str] = (),
    blocking_unresolved_item_ids: Sequence[str] = (),
    unknown_target_ids: Sequence[str] = (),
) -> SQLiteResponsePlanRepository:
    repository = SQLiteResponsePlanRepository(
        database, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY
    )
    incident = CANONICAL_AUTHORITY_BOUNDARY.bind_incident_snapshot(
        incident_id=INCIDENT_ID,
        incident_version=7,
        canonical_state_verified=True,
    )
    repository.register_incident(incident)
    targets, exclusions, _ = plan_inputs()
    repository.register_response_packet(
        CANONICAL_AUTHORITY_BOUNDARY.bind_response_packet(
            incident=incident,
            packet_id=PACKET_ID,
            packet_sha256=PACKET_SHA256,
            deterministic_scope_sha256=SCOPE_SHA256,
            targets=tuple(targets),
            exclusions=tuple(exclusions),
            unresolved_item_ids=tuple(unresolved_item_ids),
            blocking_unresolved_item_ids=tuple(blocking_unresolved_item_ids),
            unknown_target_ids=tuple(unknown_target_ids),
            canonical_state_verified=True,
        )
    )
    return repository


def make_service(repository: SQLiteResponsePlanRepository) -> ResponsePlanService:
    return ResponsePlanService(
        repository=repository,
        identity_boundary=IDENTITY_BOUNDARY,
        clock=lambda: NOW,
    )


@pytest.fixture
def repository() -> SQLiteResponsePlanRepository:
    return prepare_repository()


@pytest.fixture
def service(repository: SQLiteResponsePlanRepository) -> ResponsePlanService:
    return make_service(repository)


def create_plan(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    *,
    idempotency_key: str = "create-response-plan",
    unresolved_acknowledged: bool = False,
) -> dict[str, Any]:
    targets, exclusions, commands = plan_inputs()
    return service.create_plan(
        editor,
        incident_id=INCIDENT_ID,
        expected_incident_version=7,
        expected_plan_version=0,
        response_packet_id=PACKET_ID,
        response_packet_sha256=PACKET_SHA256,
        deterministic_scope_sha256=SCOPE_SHA256,
        targets=targets,
        exclusions=exclusions,
        commands=commands,
        unresolved_acknowledged=unresolved_acknowledged,
        idempotency_key=idempotency_key,
    )


def create_with_inputs(
    service: ResponsePlanService,
    selected: VerifiedPrincipal | None,
    *,
    targets: Sequence[Mapping[str, Any]],
    exclusions: Sequence[Mapping[str, Any]],
    commands: Sequence[Mapping[str, Any]],
    idempotency_key: str,
) -> dict[str, Any]:
    return service.create_plan(
        selected,
        incident_id=INCIDENT_ID,
        expected_incident_version=7,
        expected_plan_version=0,
        response_packet_id=PACKET_ID,
        response_packet_sha256=PACKET_SHA256,
        deterministic_scope_sha256=SCOPE_SHA256,
        targets=targets,
        exclusions=exclusions,
        commands=commands,
        idempotency_key=idempotency_key,
    )


def approve_plan(
    service: ResponsePlanService,
    approver: VerifiedPrincipal,
    plan: Mapping[str, Any],
    *,
    idempotency_key: str = "approve-response-plan",
) -> dict[str, Any]:
    return service.approve_plan(
        approver,
        incident_id=INCIDENT_ID,
        expected_incident_version=plan["incident_version"],
        expected_plan_version=plan["version"],
        expected_plan_sha256=plan["plan_sha256"],
        idempotency_key=idempotency_key,
    )


def dispatch_plan(
    service: ResponsePlanService,
    dispatcher: VerifiedPrincipal,
    plan: Mapping[str, Any],
    *,
    idempotency_key: str = "dispatch-response-plan",
) -> dict[str, Any]:
    return service.authorize_dispatch(
        dispatcher,
        incident_id=INCIDENT_ID,
        expected_incident_version=plan["incident_version"],
        expected_plan_version=plan["version"],
        expected_plan_sha256=plan["plan_sha256"],
        idempotency_key=idempotency_key,
    )


def edit_plan(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    plan: Mapping[str, Any],
    *,
    idempotency_key: str = "edit-response-plan",
    unresolved_acknowledged: bool = False,
) -> dict[str, Any]:
    targets, exclusions, commands = plan_inputs()
    return service.edit_plan(
        editor,
        incident_id=INCIDENT_ID,
        expected_incident_version=plan["incident_version"],
        expected_plan_version=plan["version"],
        expected_plan_sha256=plan["plan_sha256"],
        response_packet_id=PACKET_ID,
        response_packet_sha256=PACKET_SHA256,
        deterministic_scope_sha256=SCOPE_SHA256,
        targets=targets,
        exclusions=exclusions,
        commands=commands,
        unresolved_acknowledged=unresolved_acknowledged,
        idempotency_key=idempotency_key,
    )


def assert_idempotency_replay_rejects_tampering(
    repository: SQLiteResponsePlanRepository,
    *,
    idempotency_key: str,
    authoritative: Mapping[str, Any],
    forged_results: Sequence[Mapping[str, Any]],
    replay: Callable[[], dict[str, Any]],
) -> None:
    for forged in forged_results:
        with repository.transaction(write=True) as connection:
            cursor = connection.execute(
                "UPDATE response_plan_idempotency SET result = ? WHERE idempotency_key = ?",
                (canonical_json_bytes(forged), idempotency_key),
            )
            assert cursor.rowcount == 1
        try:
            with pytest.raises(ResponsePlanError, match="idempotency-result-invalid"):
                replay()
        finally:
            with repository.transaction(write=True) as connection:
                connection.execute(
                    "UPDATE response_plan_idempotency SET result = ? WHERE idempotency_key = ?",
                    (canonical_json_bytes(authoritative), idempotency_key),
                )
    assert replay() == authoritative


def test_approval_and_dispatch_bind_exact_plan_scope_commands_and_actor(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor, unresolved_acknowledged=True)
    validate_plan(plan)
    approval = approve_plan(service, approver, plan)
    validate_decision(approval, plan=plan)

    assert approval["incident_id"] == plan["incident_id"]
    assert approval["incident_version"] == plan["incident_version"]
    assert approval["plan_version"] == plan["version"]
    assert approval["plan_sha256"] == plan["plan_sha256"]
    assert approval["targets"] == plan["targets"]
    assert approval["exclusions"] == plan["exclusions"]
    assert approval["commands"] == plan["commands"]
    assert approval["unresolved_item_ids"] == plan["unresolved_item_ids"]
    assert approval["unresolved_acknowledged"] is True
    assert approval["actor"]["subject"] == approver.subject
    assert approval["idempotency_key"] == "approve-response-plan"

    authorization = dispatch_plan(service, dispatcher, plan)
    validate_dispatch_authorization(authorization, plan=plan, approval=approval)
    assert authorization["targets"] == plan["targets"]
    assert authorization["exclusions"] == plan["exclusions"]
    assert authorization["commands"] == plan["commands"]
    assert authorization["approval_id"] == approval["decision_id"]
    assert authorization["actor"]["subject"] == dispatcher.subject

    plan["targets"][0]["id"] = "caller-mutated"
    assert service.current_plan(INCIDENT_ID)["targets"][0]["id"] != "caller-mutated"
    events = service.audit_history(INCIDENT_ID)
    assert [event["event_type"] for event in events] == [
        "plan.created",
        "plan.approved",
        "dispatch.authorized",
    ]
    validate_audit_chain(events)


def test_edit_creates_immutable_version_and_invalidates_prior_approval(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    first = create_plan(service, editor)
    first_snapshot = copy.deepcopy(first)
    first_approval = approve_plan(service, approver, first)
    second = edit_plan(service, editor, first)

    assert second["version"] == 2
    assert second["previous_plan_sha256"] == first["plan_sha256"]
    assert second["plan_sha256"] != first["plan_sha256"]
    assert service.plan_version(INCIDENT_ID, 1) == first_snapshot
    assert service.decision(INCIDENT_ID, 1) == first_approval
    assert service.decision(INCIDENT_ID, 2) is None

    with pytest.raises(ResponsePlanError, match="expected-version-conflict"):
        dispatch_plan(service, dispatcher, first, idempotency_key="dispatch-stale-version")
    with pytest.raises(ResponsePlanError, match="plan-not-approved"):
        dispatch_plan(service, dispatcher, second, idempotency_key="dispatch-edited-plan")

    second_approval = approve_plan(service, approver, second, idempotency_key="approve-edited-plan")
    authorization = dispatch_plan(
        service, dispatcher, second, idempotency_key="dispatch-edited-approved-plan"
    )
    assert authorization["approval_id"] == second_approval["decision_id"]
    assert [event["event_type"] for event in service.audit_history(INCIDENT_ID)] == [
        "plan.created",
        "plan.approved",
        "plan.edited",
        "plan.approved",
        "dispatch.authorized",
    ]


def test_unapproved_and_rejected_plans_cannot_dispatch(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    with pytest.raises(ResponsePlanError, match="plan-not-approved"):
        dispatch_plan(service, dispatcher, plan, idempotency_key="dispatch-unapproved")

    rejection = service.reject_plan(
        approver,
        incident_id=INCIDENT_ID,
        expected_incident_version=7,
        expected_plan_version=1,
        expected_plan_sha256=plan["plan_sha256"],
        reason_code="unsafe-scope",
        idempotency_key="reject-response-plan",
    )
    assert rejection["outcome"] == "rejected"
    with pytest.raises(ResponsePlanError, match="plan-rejected"):
        dispatch_plan(service, dispatcher, plan, idempotency_key="dispatch-rejected")


def test_unresolved_items_require_explicit_acknowledgement_before_approval(
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
) -> None:
    service = make_service(prepare_repository(unresolved_item_ids=("nondecisive-residual-risk",)))
    first = create_plan(
        service,
        editor,
        unresolved_acknowledged=False,
    )
    with pytest.raises(ResponsePlanError, match="unresolved-acknowledgement-required"):
        approve_plan(service, approver, first)

    second = edit_plan(
        service,
        editor,
        first,
        unresolved_acknowledged=True,
    )
    approval = approve_plan(service, approver, second, idempotency_key="approve-acknowledged")
    assert approval["unresolved_acknowledged"] is True


def test_anonymous_public_wrong_role_idor_and_model_mutations_fail_closed(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    targets, exclusions, commands = plan_inputs()

    def unauthorized_create(selected: VerifiedPrincipal | None) -> dict[str, Any]:
        return create_with_inputs(
            service,
            selected,
            targets=targets,
            exclusions=exclusions,
            commands=commands,
            idempotency_key="unauthorized-create",
        )

    with pytest.raises(ResponsePlanError, match="authentication-required"):
        unauthorized_create(None)
    viewer = principal("incident.viewer", subject="public-viewer")
    with pytest.raises(ResponsePlanError, match="role-required"):
        unauthorized_create(viewer)
    outsider = principal(
        EDITOR_ROLE,
        subject="other-incident-editor",
        incidents=frozenset({"incident-other"}),
    )
    with pytest.raises(ResponsePlanError, match="incident-access-denied"):
        unauthorized_create(outsider)
    model_editor = principal(EDITOR_ROLE, subject="model-editor", kind="model")
    with pytest.raises(ResponsePlanError, match="model-authority-forbidden"):
        unauthorized_create(model_editor)

    plan = create_plan(service, editor)
    with pytest.raises(ResponsePlanError, match="authentication-required"):
        service.approve_plan(
            None,
            incident_id=INCIDENT_ID,
            expected_incident_version=7,
            expected_plan_version=1,
            expected_plan_sha256=plan["plan_sha256"],
            idempotency_key="anonymous-approval",
        )
    service_approver = principal(APPROVER_ROLE, subject="service-approver", kind="service")
    with pytest.raises(ResponsePlanError, match="human-approval-required"):
        approve_plan(service, service_approver, plan, idempotency_key="service-approval")
    model_approver = principal(APPROVER_ROLE, subject="model-approver", kind="model")
    with pytest.raises(ResponsePlanError, match="model-authority-forbidden"):
        approve_plan(service, model_approver, plan, idempotency_key="model-approval")
    other_approver = principal(
        APPROVER_ROLE,
        subject="other-incident-approver",
        incidents=frozenset({"incident-other"}),
    )
    with pytest.raises(ResponsePlanError, match="incident-access-denied"):
        approve_plan(service, other_approver, plan, idempotency_key="idor-approval")
    with pytest.raises(ResponsePlanError, match="authentication-required"):
        service.authorize_dispatch(
            None,
            incident_id=INCIDENT_ID,
            expected_incident_version=7,
            expected_plan_version=1,
            expected_plan_sha256=plan["plan_sha256"],
            idempotency_key="anonymous-dispatch",
        )
    with pytest.raises(ResponsePlanError, match="role-required"):
        dispatch_plan(service, approver, plan, idempotency_key="wrong-role-dispatch")
    assert dispatcher.kind == "service"
    assert service.current_plan(INCIDENT_ID) == plan


def test_only_exact_typed_simulator_commands_and_targets_are_accepted(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
) -> None:
    targets, exclusions, commands = plan_inputs()

    malicious = copy.deepcopy(commands)
    malicious[0]["shell"] = "shutdown --all"
    with pytest.raises(ResponsePlanError, match="schema-validation"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=malicious,
            idempotency_key="free-form-command",
        )

    production_targets = copy.deepcopy(targets)
    production_targets[0]["namespace"] = "production"
    with pytest.raises(ResponsePlanError, match="production-target-forbidden"):
        create_with_inputs(
            service,
            editor,
            targets=production_targets,
            exclusions=exclusions,
            commands=commands,
            idempotency_key="production-target",
        )

    overlapping_exclusions = [*exclusions, targets[1]]
    with pytest.raises(ResponsePlanError, match="target-exclusion-overlap"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=overlapping_exclusions,
            commands=commands,
            idempotency_key="overlapping-scope",
        )

    wrong_quarantine_target = copy.deepcopy(commands)
    wrong_quarantine_target[0]["target"] = targets[1]
    with pytest.raises(ResponsePlanError, match="schema-validation"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=wrong_quarantine_target,
            idempotency_key="wrong-quarantine-target",
        )

    crossed_rerender_alternative = copy.deepcopy(commands)
    crossed_rerender_alternative[1]["target"] = targets[2]
    with pytest.raises(ResponsePlanError, match="schema-validation"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=crossed_rerender_alternative,
            idempotency_key="crossed-rerender-alternative",
        )

    conflicting_envelope = copy.deepcopy(commands)
    conflicting_envelope[1]["action_envelope"]["expected_publication_pointer_sha256"] = digest("f")
    with pytest.raises(ResponsePlanError, match="action-envelope-conflict"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=conflicting_envelope,
            idempotency_key="conflicting-action-envelope",
        )

    mismatched_generations = copy.deepcopy(commands)
    for command in mismatched_generations:
        command["action_envelope"]["expected_publication_generation"] = 8
    with pytest.raises(ResponsePlanError, match="action-generation-conflict"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=mismatched_generations,
            idempotency_key="mismatched-action-generation",
        )

    incomplete_preconditions = copy.deepcopy(commands)
    incomplete_preconditions[1].pop("expected_output_sha256")
    with pytest.raises(ResponsePlanError, match="schema-validation"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=incomplete_preconditions,
            idempotency_key="missing-old-output-digest",
        )

    wrong_replacement = copy.deepcopy(commands)
    for command in wrong_replacement:
        command["action_envelope"]["replacement_resource_sha256"] = digest("a")
    with pytest.raises(ResponsePlanError, match="replacement-resource-unchanged"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=wrong_replacement,
            idempotency_key="unchanged-replacement-resource",
        )

    missing_target_command = commands[:-1]
    with pytest.raises(ResponsePlanError, match="command-target-binding"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=missing_target_command,
            idempotency_key="missing-target-command",
        )


def test_expected_versions_hashes_and_concurrent_approval_reject_stale_writes(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    with pytest.raises(ResponsePlanError, match="expected-version-conflict"):
        service.approve_plan(
            approver,
            incident_id=INCIDENT_ID,
            expected_incident_version=6,
            expected_plan_version=1,
            expected_plan_sha256=plan["plan_sha256"],
            idempotency_key="stale-incident-version",
        )
    with pytest.raises(ResponsePlanError, match="plan-hash-conflict"):
        service.approve_plan(
            approver,
            incident_id=INCIDENT_ID,
            expected_incident_version=7,
            expected_plan_version=1,
            expected_plan_sha256=digest("f"),
            idempotency_key="stale-plan-hash",
        )

    def concurrent_approval(key: str) -> tuple[str, str]:
        try:
            decision = approve_plan(service, approver, plan, idempotency_key=key)
        except ResponsePlanError as error:
            return "error", error.code
        return "approved", decision["decision_id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = [
            future.result(timeout=5)
            for future in (
                executor.submit(concurrent_approval, "concurrent-approval-a"),
                executor.submit(concurrent_approval, "concurrent-approval-b"),
            )
        ]
    assert len([result for result in results if result[0] == "approved"]) == 1
    assert ("error", "plan-decision-conflict") in results
    assert [event["event_type"] for event in service.audit_history(INCIDENT_ID)].count(
        "plan.approved"
    ) == 1

    def concurrent_edit(key: str) -> tuple[str, str]:
        try:
            edited = edit_plan(service, editor, plan, idempotency_key=key)
        except ResponsePlanError as error:
            return "error", error.code
        return "edited", str(edited["version"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        edit_results = [
            future.result(timeout=5)
            for future in (
                executor.submit(concurrent_edit, "concurrent-edit-a"),
                executor.submit(concurrent_edit, "concurrent-edit-b"),
            )
        ]
    assert ("edited", "2") in edit_results
    assert ("error", "expected-version-conflict") in edit_results


def test_idempotent_replay_is_exact_and_conflicting_key_use_is_rejected(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    first = create_plan(service, editor)
    duplicate = create_plan(service, editor)
    assert duplicate == first
    assert len(service.audit_history(INCIDENT_ID)) == 1

    targets, exclusions, commands = plan_inputs()
    changed_commands = copy.deepcopy(commands)
    changed_commands[0]["expected_resource_sha256"] = digest("9")
    with pytest.raises(ResponsePlanError, match="idempotency-conflict"):
        create_with_inputs(
            service,
            editor,
            targets=targets,
            exclusions=exclusions,
            commands=changed_commands,
            idempotency_key="create-response-plan",
        )

    approval = approve_plan(service, approver, first)
    assert approve_plan(service, approver, first) == approval
    alternate_approver = principal(APPROVER_ROLE, subject="alternate-approver")
    with pytest.raises(ResponsePlanError, match="idempotency-conflict"):
        approve_plan(service, alternate_approver, first)

    authorization = dispatch_plan(service, dispatcher, first)
    assert dispatch_plan(service, dispatcher, first) == authorization
    assert [event["event_type"] for event in service.audit_history(INCIDENT_ID)] == [
        "plan.created",
        "plan.approved",
        "dispatch.authorized",
    ]


def test_every_idempotency_replay_rejects_arbitrary_and_crossed_results(
    service: ResponsePlanService,
    repository: SQLiteResponsePlanRepository,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    arbitrary = {"forged": "valid-json"}
    first = create_plan(service, editor)
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="create-response-plan",
        authoritative=first,
        forged_results=(arbitrary,),
        replay=lambda: create_plan(service, editor),
    )

    approval = approve_plan(service, approver, first)
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="create-response-plan",
        authoritative=first,
        forged_results=(approval,),
        replay=lambda: create_plan(service, editor),
    )
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="approve-response-plan",
        authoritative=approval,
        forged_results=(arbitrary, first),
        replay=lambda: approve_plan(service, approver, first),
    )

    authorization = dispatch_plan(service, dispatcher, first)
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="dispatch-response-plan",
        authoritative=authorization,
        forged_results=(arbitrary, approval),
        replay=lambda: dispatch_plan(service, dispatcher, first),
    )

    def replay_consumption() -> dict[str, Any]:
        return service.consume_dispatch_authorization(
            dispatcher,
            incident_id=INCIDENT_ID,
            authorization_id=authorization["authorization_id"],
            expected_incident_version=first["incident_version"],
            expected_plan_version=first["version"],
            expected_plan_sha256=first["plan_sha256"],
            expected_task_key=authorization["task_key"],
            expected_payload_sha256=authorization["payload_sha256"],
            idempotency_key="consume-replay-integrity",
        )

    consumption = replay_consumption()
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="consume-replay-integrity",
        authoritative=consumption,
        forged_results=(arbitrary, authorization),
        replay=replay_consumption,
    )

    def replay_consumption_alias() -> dict[str, Any]:
        return service.consume_dispatch_authorization(
            dispatcher,
            incident_id=INCIDENT_ID,
            authorization_id=authorization["authorization_id"],
            expected_incident_version=first["incident_version"],
            expected_plan_version=first["version"],
            expected_plan_sha256=first["plan_sha256"],
            expected_task_key=authorization["task_key"],
            expected_payload_sha256=authorization["payload_sha256"],
            idempotency_key="consume-replay-alias",
        )

    assert replay_consumption_alias() == consumption
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="consume-replay-alias",
        authoritative=consumption,
        forged_results=(arbitrary, authorization),
        replay=replay_consumption_alias,
    )

    second = edit_plan(service, editor, first)
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="edit-response-plan",
        authoritative=second,
        forged_results=(arbitrary, consumption),
        replay=lambda: edit_plan(service, editor, first),
    )

    def replay_rejection() -> dict[str, Any]:
        return service.reject_plan(
            approver,
            incident_id=INCIDENT_ID,
            expected_incident_version=second["incident_version"],
            expected_plan_version=second["version"],
            expected_plan_sha256=second["plan_sha256"],
            reason_code="unsafe-scope",
            idempotency_key="reject-replay-integrity",
        )

    rejection = replay_rejection()
    assert_idempotency_replay_rejects_tampering(
        repository,
        idempotency_key="reject-replay-integrity",
        authoritative=rejection,
        forged_results=(arbitrary, second),
        replay=replay_rejection,
    )


def test_audit_plan_decision_and_authorization_tampering_is_detected(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    approval = approve_plan(service, approver, plan)
    authorization = dispatch_plan(service, dispatcher, plan)
    events = service.audit_history(INCIDENT_ID)
    validate_audit_chain(events)

    tampered_events = copy.deepcopy(events)
    tampered_events[1]["record_sha256"] = digest("0")
    with pytest.raises(ResponsePlanError, match="audit-chain-binding"):
        validate_audit_chain(tampered_events)

    tampered_plan = copy.deepcopy(plan)
    tampered_plan["commands"][0]["expected_resource_sha256"] = digest("0")
    with pytest.raises(ResponsePlanError, match="plan-digest"):
        validate_plan(tampered_plan)

    tampered_approval = copy.deepcopy(approval)
    tampered_approval["plan_sha256"] = digest("0")
    with pytest.raises(ResponsePlanError, match="decision-digest"):
        validate_decision(tampered_approval, plan=plan)

    tampered_authorization = copy.deepcopy(authorization)
    tampered_authorization["commands"][0]["expected_resource_sha256"] = digest("0")
    with pytest.raises(ResponsePlanError, match="dispatch-authorization-digest"):
        validate_dispatch_authorization(
            tampered_authorization,
            plan=plan,
            approval=approval,
        )


def contract_plan(
    editor: VerifiedPrincipal,
    *,
    unresolved_item_ids: Sequence[str] = (),
    blocking_unresolved_item_ids: Sequence[str] = (),
    unknown_target_ids: Sequence[str] = (),
    unresolved_acknowledged: bool = False,
) -> dict[str, Any]:
    targets, exclusions, commands = plan_inputs()
    return build_plan(
        incident_id=INCIDENT_ID,
        incident_version=7,
        version=1,
        previous_plan_sha256=None,
        response_packet_id=PACKET_ID,
        response_packet_sha256=PACKET_SHA256,
        deterministic_scope_sha256=SCOPE_SHA256,
        targets=targets,
        exclusions=exclusions,
        commands=commands,
        unresolved_item_ids=unresolved_item_ids,
        blocking_unresolved_item_ids=blocking_unresolved_item_ids,
        unknown_target_ids=unknown_target_ids,
        unresolved_acknowledged=unresolved_acknowledged,
        created_by=editor.actor(),
        created_at="2026-08-13T15:00:00Z",
    )


def self_consistent_decision(
    plan: Mapping[str, Any],
    actor: VerifiedPrincipal,
    *,
    outcome: str,
    reason_code: str | None,
) -> dict[str, Any]:
    body = {
        "schema": "response-plan-decision/v1",
        "outcome": outcome,
        "incident_id": plan["incident_id"],
        "incident_version": plan["incident_version"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "response_packet_id": plan["response_packet_id"],
        "response_packet_sha256": plan["response_packet_sha256"],
        "deterministic_scope_sha256": plan["deterministic_scope_sha256"],
        "targets": plan["targets"],
        "exclusions": plan["exclusions"],
        "commands": plan["commands"],
        "targets_sha256": component_digest(plan, "targets"),
        "exclusions_sha256": component_digest(plan, "exclusions"),
        "commands_sha256": component_digest(plan, "commands"),
        "unresolved_item_ids": plan["unresolved_item_ids"],
        "blocking_unresolved_item_ids": plan["blocking_unresolved_item_ids"],
        "unknown_target_ids": plan["unknown_target_ids"],
        "unresolved_acknowledged": plan["unresolved_acknowledged"],
        "reason_code": reason_code,
        "actor": actor.actor(),
        "idempotency_key": "self-consistent-decision",
        "decided_at": "2026-08-13T15:00:00Z",
    }
    decision_sha256 = prefixed_sha256(canonical_json_bytes(body))
    return {
        **body,
        "decision_id": f"plan-decision:{decision_sha256.removeprefix('sha256:')}",
        "decision_sha256": decision_sha256,
    }


def self_consistent_authorization(
    plan: Mapping[str, Any],
    decision: Mapping[str, Any],
    dispatcher: VerifiedPrincipal,
) -> dict[str, Any]:
    body = {
        "schema": "response-plan-dispatch-authorization/v1",
        "authorization_policy": "response-plan-dispatch-policy/v1",
        "authorized_role": DISPATCHER_ROLE,
        "operation_id": f"dispatch-operation:{'1' * 64}",
        "task_key": f"dispatch-task:{'2' * 64}",
        "payload_sha256": digest("3"),
        "incident_id": plan["incident_id"],
        "incident_version": plan["incident_version"],
        "plan_id": plan["plan_id"],
        "plan_version": plan["version"],
        "plan_sha256": plan["plan_sha256"],
        "response_packet_id": plan["response_packet_id"],
        "response_packet_sha256": plan["response_packet_sha256"],
        "deterministic_scope_sha256": plan["deterministic_scope_sha256"],
        "approval_id": decision["decision_id"],
        "approval_sha256": decision["decision_sha256"],
        "targets": plan["targets"],
        "exclusions": plan["exclusions"],
        "commands": plan["commands"],
        "unresolved_item_ids": plan["unresolved_item_ids"],
        "blocking_unresolved_item_ids": plan["blocking_unresolved_item_ids"],
        "unknown_target_ids": plan["unknown_target_ids"],
        "unresolved_acknowledged": plan["unresolved_acknowledged"],
        "actor": dispatcher.actor(),
        "idempotency_key": "self-consistent-authorization",
        "authorized_at": "2026-08-13T15:00:00Z",
    }
    authorization_sha256 = prefixed_sha256(canonical_json_bytes(body))
    return {
        **body,
        "authorization_id": (
            f"dispatch-authorization:{authorization_sha256.removeprefix('sha256:')}"
        ),
        "authorization_sha256": authorization_sha256,
    }


def test_rejected_and_semantically_invalid_decisions_never_validate_for_dispatch(
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = contract_plan(editor)
    rejection = build_decision(
        plan=plan,
        outcome="rejected",
        actor=approver.actor(),
        idempotency_key="rejected-decision",
        decided_at="2026-08-13T15:00:00Z",
        reason_code="unsafe-scope",
    )
    forged_authorization = self_consistent_authorization(plan, rejection, dispatcher)
    with pytest.raises(ResponsePlanError, match="plan-not-approved"):
        validate_dispatch_authorization(
            forged_authorization,
            plan=plan,
            approval=rejection,
        )

    approval = build_decision(
        plan=plan,
        outcome="approved",
        actor=approver.actor(),
        idempotency_key="valid-approval",
        decided_at="2026-08-13T15:00:00Z",
        reason_code=None,
    )
    human_authorization = self_consistent_authorization(plan, approval, dispatcher)
    human_authorization["actor"] = approver.actor()
    human_body = {
        key: value
        for key, value in human_authorization.items()
        if key not in {"authorization_id", "authorization_sha256"}
    }
    human_digest = prefixed_sha256(canonical_json_bytes(human_body))
    human_authorization["authorization_sha256"] = human_digest
    human_authorization["authorization_id"] = (
        f"dispatch-authorization:{human_digest.removeprefix('sha256:')}"
    )
    with pytest.raises(ResponsePlanError, match="schema-validation"):
        validate_dispatch_authorization(
            human_authorization,
            plan=plan,
            approval=approval,
        )

    wrong_policy = self_consistent_authorization(plan, approval, dispatcher)
    wrong_policy["authorized_role"] = "incident.viewer"
    policy_body = {
        key: value
        for key, value in wrong_policy.items()
        if key not in {"authorization_id", "authorization_sha256"}
    }
    policy_digest = prefixed_sha256(canonical_json_bytes(policy_body))
    wrong_policy["authorization_sha256"] = policy_digest
    wrong_policy["authorization_id"] = (
        f"dispatch-authorization:{policy_digest.removeprefix('sha256:')}"
    )
    with pytest.raises(ResponsePlanError, match="schema-validation"):
        validate_dispatch_authorization(wrong_policy, plan=plan, approval=approval)

    unacknowledged = contract_plan(
        editor,
        unresolved_item_ids=("nondecisive-residual-risk",),
        unresolved_acknowledged=False,
    )
    forged_approval = self_consistent_decision(
        unacknowledged,
        approver,
        outcome="approved",
        reason_code=None,
    )
    with pytest.raises(ResponsePlanError, match="unresolved-acknowledgement-required"):
        validate_decision(forged_approval, plan=unacknowledged)


@pytest.mark.parametrize(
    ("blocking_unresolved_item_ids", "unknown_target_ids", "error_code"),
    [
        (("decisive-evidence-missing",), (), "blocking-unresolved-evidence"),
        ((), ("unknown-target",), "unknown-targets-prohibited"),
    ],
)
def test_blocking_evidence_and_unknown_targets_prohibit_plan_creation_and_approval(
    blocking_unresolved_item_ids: Sequence[str],
    unknown_target_ids: Sequence[str],
    error_code: str,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
) -> None:
    service = make_service(
        prepare_repository(
            blocking_unresolved_item_ids=blocking_unresolved_item_ids,
            unknown_target_ids=unknown_target_ids,
        )
    )
    with pytest.raises(ResponsePlanError, match=error_code):
        create_plan(service, editor, unresolved_acknowledged=True)

    plan = contract_plan(
        editor,
        blocking_unresolved_item_ids=blocking_unresolved_item_ids,
        unknown_target_ids=unknown_target_ids,
        unresolved_acknowledged=True,
    )
    with pytest.raises(ResponsePlanError, match=error_code):
        build_decision(
            plan=plan,
            outcome="approved",
            actor=approver.actor(),
            idempotency_key="blocked-approval",
            decided_at="2026-08-13T15:00:00Z",
            reason_code=None,
        )


def test_plan_scope_is_exactly_bound_to_registered_canonical_packet(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
) -> None:
    targets, exclusions, commands = plan_inputs()
    with pytest.raises(ResponsePlanError, match="response-packet-binding-conflict"):
        service.create_plan(
            editor,
            incident_id=INCIDENT_ID,
            expected_incident_version=7,
            expected_plan_version=0,
            response_packet_id=PACKET_ID,
            response_packet_sha256=digest("0"),
            deterministic_scope_sha256=SCOPE_SHA256,
            targets=targets,
            exclusions=exclusions,
            commands=commands,
            idempotency_key="wrong-packet-digest",
        )

    expanded_targets = copy.deepcopy(targets)
    expanded_commands = copy.deepcopy(commands)
    expanded_targets[1]["id"] = "frame-unapproved-expansion"
    expanded_commands[1]["target"] = expanded_targets[1]
    with pytest.raises(ResponsePlanError, match="deterministic-scope-binding-conflict"):
        create_with_inputs(
            service,
            editor,
            targets=expanded_targets,
            exclusions=exclusions,
            commands=expanded_commands,
            idempotency_key="scope-expansion",
        )


def test_distinct_keys_cannot_mint_duplicate_dispatch_authorizations(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    approve_plan(service, approver, plan)
    first = dispatch_plan(service, dispatcher, plan, idempotency_key="dispatch-first")
    with pytest.raises(ResponsePlanError, match="dispatch-authorization-conflict"):
        dispatch_plan(service, dispatcher, plan, idempotency_key="dispatch-second")
    assert first["operation_id"].startswith("dispatch-operation:")
    assert [event["event_type"] for event in service.audit_history(INCIDENT_ID)].count(
        "dispatch.authorized"
    ) == 1


def test_dispatch_consumption_rechecks_current_authority_and_is_once_only(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    approve_plan(service, approver, plan)
    authorization = dispatch_plan(service, dispatcher, plan)
    with pytest.raises(ResponsePlanError, match="dispatch-payload-conflict"):
        service.consume_dispatch_authorization(
            dispatcher,
            incident_id=INCIDENT_ID,
            authorization_id=authorization["authorization_id"],
            expected_incident_version=7,
            expected_plan_version=1,
            expected_plan_sha256=plan["plan_sha256"],
            expected_task_key=authorization["task_key"],
            expected_payload_sha256=digest("0"),
            idempotency_key="consume-wrong-payload",
        )
    consumption = service.consume_dispatch_authorization(
        dispatcher,
        incident_id=INCIDENT_ID,
        authorization_id=authorization["authorization_id"],
        expected_incident_version=7,
        expected_plan_version=1,
        expected_plan_sha256=plan["plan_sha256"],
        expected_task_key=authorization["task_key"],
        expected_payload_sha256=authorization["payload_sha256"],
        idempotency_key="consume-first",
    )
    duplicate = service.consume_dispatch_authorization(
        dispatcher,
        incident_id=INCIDENT_ID,
        authorization_id=authorization["authorization_id"],
        expected_incident_version=7,
        expected_plan_version=1,
        expected_plan_sha256=plan["plan_sha256"],
        expected_task_key=authorization["task_key"],
        expected_payload_sha256=authorization["payload_sha256"],
        idempotency_key="consume-duplicate-delivery",
    )
    assert duplicate == consumption
    assert [event["event_type"] for event in service.audit_history(INCIDENT_ID)].count(
        "dispatch.consumed"
    ) == 1
    edit_plan(service, editor, plan, idempotency_key="edit-after-consumption")
    with pytest.raises(ResponsePlanError, match="expected-version-conflict"):
        service.consume_dispatch_authorization(
            dispatcher,
            incident_id=INCIDENT_ID,
            authorization_id=authorization["authorization_id"],
            expected_incident_version=7,
            expected_plan_version=1,
            expected_plan_sha256=plan["plan_sha256"],
            expected_task_key=authorization["task_key"],
            expected_payload_sha256=authorization["payload_sha256"],
            idempotency_key="consume-first",
        )


def test_current_consumed_dispatch_is_one_transactional_current_authority_view(
    service: ResponsePlanService,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    approval = approve_plan(service, approver, plan)
    authorization = dispatch_plan(service, dispatcher, plan)
    identity = {
        "task_key": authorization["task_key"],
        "operation_id": authorization["operation_id"],
        "payload_sha256": authorization["payload_sha256"],
    }
    with pytest.raises(ResponsePlanError, match="dispatch-authorization-not-consumed"):
        service.current_consumed_dispatch(**identity)

    consumption = service.consume_dispatch_authorization(
        dispatcher,
        incident_id=INCIDENT_ID,
        authorization_id=authorization["authorization_id"],
        expected_incident_version=7,
        expected_plan_version=1,
        expected_plan_sha256=plan["plan_sha256"],
        expected_task_key=authorization["task_key"],
        expected_payload_sha256=authorization["payload_sha256"],
        idempotency_key="consume-for-execution",
    )
    proof = service.current_consumed_dispatch(**identity)
    assert proof["plan"] == plan
    assert proof["approval"] == approval
    assert proof["authorization"] == authorization
    assert proof["consumption"] == consumption
    assert proof["audit_events"][-1]["event_type"] == "dispatch.consumed"
    assert proof["trusted_audit_head_sha256"] == proof["audit_events"][-1]["event_sha256"]
    assert proof["dispatch_consumed_event_sha256"] == proof["audit_events"][-1]["event_sha256"]
    proof_body = {key: value for key, value in proof.items() if key != "proof_sha256"}
    assert proof["proof_sha256"] == prefixed_sha256(canonical_json_bytes(proof_body))
    assert set(proof["records"]) == {
        plan["plan_sha256"],
        approval["decision_sha256"],
        authorization["authorization_sha256"],
        consumption["consumption_sha256"],
    }

    with pytest.raises(ResponsePlanError, match="dispatch-task-key-conflict"):
        service.current_consumed_dispatch(**{**identity, "task_key": "different-task"})
    edit_plan(service, editor, plan, idempotency_key="edit-after-execution-load")
    with pytest.raises(ResponsePlanError, match="dispatch-authorization-stale"):
        service.current_consumed_dispatch(**identity)


def test_forged_consume_replay_cannot_report_an_unconsumed_authorization(
    service: ResponsePlanService,
    repository: SQLiteResponsePlanRepository,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    approve_plan(service, approver, plan)
    authorization = dispatch_plan(service, dispatcher, plan)
    key = "forged-consume-replay"
    request = {
        "operation": "dispatch.consume",
        "actor": dispatcher.actor(),
        "incident_id": INCIDENT_ID,
        "authorization_id": authorization["authorization_id"],
        "expected_incident_version": plan["incident_version"],
        "expected_plan_version": plan["version"],
        "expected_plan_sha256": plan["plan_sha256"],
        "expected_task_key": authorization["task_key"],
        "expected_payload_sha256": authorization["payload_sha256"],
        "idempotency_key": key,
    }
    with repository.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO response_plan_idempotency("
            "idempotency_key, request_sha256, result) VALUES (?, ?, ?)",
            (
                key,
                prefixed_sha256(canonical_json_bytes(request)),
                canonical_json_bytes(authorization),
            ),
        )

    with pytest.raises(ResponsePlanError, match="idempotency-result-invalid"):
        service.consume_dispatch_authorization(
            dispatcher,
            incident_id=INCIDENT_ID,
            authorization_id=authorization["authorization_id"],
            expected_incident_version=plan["incident_version"],
            expected_plan_version=plan["version"],
            expected_plan_sha256=plan["plan_sha256"],
            expected_task_key=authorization["task_key"],
            expected_payload_sha256=authorization["payload_sha256"],
            idempotency_key=key,
        )
    assert "dispatch.consumed" not in {
        event["event_type"] for event in service.audit_history(INCIDENT_ID)
    }


def test_plan_edit_invalidates_unconsumed_authorization(
    service: ResponsePlanService,
    repository: SQLiteResponsePlanRepository,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    first = create_plan(service, editor)
    approval = approve_plan(service, approver, first)
    authorization = dispatch_plan(service, dispatcher, first)
    edit_plan(service, editor, first)
    validate_dispatch_authorization(authorization, plan=first, approval=approval)
    with pytest.raises(ResponsePlanError, match="expected-version-conflict"):
        dispatch_plan(service, dispatcher, first)
    with pytest.raises(ResponsePlanError, match="expected-version-conflict"):
        service.consume_dispatch_authorization(
            dispatcher,
            incident_id=INCIDENT_ID,
            authorization_id=authorization["authorization_id"],
            expected_incident_version=7,
            expected_plan_version=1,
            expected_plan_sha256=first["plan_sha256"],
            expected_task_key=authorization["task_key"],
            expected_payload_sha256=authorization["payload_sha256"],
            idempotency_key="consume-stale-authorization",
        )
    with repository.transaction(write=False) as connection:
        row = connection.execute(
            "SELECT status FROM dispatch_authorizations WHERE authorization_id = ?",
            (authorization["authorization_id"],),
        ).fetchone()
        assert row is not None
        assert row["status"] == "invalidated"


def test_verified_identity_and_canonical_authority_boundaries_reject_forgery(
    service: ResponsePlanService,
    repository: SQLiteResponsePlanRepository,
    editor: VerifiedPrincipal,
) -> None:
    with pytest.raises(ResponsePlanError, match="principal-issuer-untrusted"):
        IDENTITY_BOUNDARY.bind_verified_claims(
            issuer="https://attacker.invalid",
            subject="attacker",
            audience="colortrace-api",
            kind="human",
            roles=frozenset({EDITOR_ROLE}),
            incident_ids=frozenset({INCIDENT_ID}),
            credential_sha256=digest("8"),
            expires_at=NOW + timedelta(hours=1),
            credential_verified=True,
            now=NOW,
        )
    with pytest.raises(ResponsePlanError, match="principal-audience-untrusted"):
        IDENTITY_BOUNDARY.bind_verified_claims(
            issuer="https://identity.example.test",
            subject="attacker",
            audience="wrong-audience",
            kind="human",
            roles=frozenset({EDITOR_ROLE}),
            incident_ids=frozenset({INCIDENT_ID}),
            credential_sha256=digest("8"),
            expires_at=NOW + timedelta(hours=1),
            credential_verified=True,
            now=NOW,
        )
    with pytest.raises(ResponsePlanError, match="principal-credential-expired"):
        IDENTITY_BOUNDARY.bind_verified_claims(
            issuer="https://identity.example.test",
            subject="expired",
            audience="colortrace-api",
            kind="human",
            roles=frozenset({EDITOR_ROLE}),
            incident_ids=frozenset({INCIDENT_ID}),
            credential_sha256=digest("8"),
            expires_at=NOW,
            credential_verified=True,
            now=NOW,
        )
    forged = VerifiedPrincipal(
        issuer=editor.issuer,
        subject="forged",
        audience=editor.audience,
        kind="human",
        roles=frozenset({EDITOR_ROLE}),
        incident_ids=frozenset({INCIDENT_ID}),
        credential_sha256=digest("8"),
        expires_at=NOW + timedelta(hours=1),
        _trust_token=object(),
    )
    targets, exclusions, commands = plan_inputs()
    with pytest.raises(ResponsePlanError, match="principal-trust-boundary-mismatch"):
        create_with_inputs(
            service,
            forged,
            targets=targets,
            exclusions=exclusions,
            commands=commands,
            idempotency_key="forged-principal",
        )

    untrusted_boundary = CanonicalAuthorityBoundary()
    untrusted_incident = untrusted_boundary.bind_incident_snapshot(
        incident_id=INCIDENT_ID,
        incident_version=7,
        canonical_state_verified=True,
    )
    untrusted_packet = untrusted_boundary.bind_response_packet(
        incident=untrusted_incident,
        packet_id="untrusted-packet",
        packet_sha256=digest("4"),
        deterministic_scope_sha256=digest("5"),
        targets=targets,
        exclusions=exclusions,
        canonical_state_verified=True,
    )
    with pytest.raises(ResponsePlanError, match="canonical-authority-boundary-mismatch"):
        repository.register_response_packet(untrusted_packet)
    with pytest.raises(ResponsePlanError, match="canonical-state-not-verified"):
        CANONICAL_AUTHORITY_BOUNDARY.bind_incident_snapshot(
            incident_id=INCIDENT_ID,
            incident_version=8,
            canonical_state_verified=False,
        )


def test_live_incident_version_not_plan_snapshot_controls_approval(
    service: ResponsePlanService,
    repository: SQLiteResponsePlanRepository,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    current = CANONICAL_AUTHORITY_BOUNDARY.bind_incident_snapshot(
        incident_id=INCIDENT_ID,
        incident_version=8,
        canonical_state_verified=True,
    )
    repository.advance_incident(current, expected_incident_version=7)
    with pytest.raises(ResponsePlanError, match="expected-version-conflict"):
        approve_plan(service, approver, plan)
    with pytest.raises(ResponsePlanError, match="expected-version-conflict"):
        service.approve_plan(
            approver,
            incident_id=INCIDENT_ID,
            expected_incident_version=8,
            expected_plan_version=1,
            expected_plan_sha256=plan["plan_sha256"],
            idempotency_key="approve-stale-plan-current-incident",
        )


def test_file_repository_survives_restart_and_preserves_replay(
    tmp_path: Path,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    database = tmp_path / "response-plans.sqlite3"
    first_repository = prepare_repository(database)
    first_service = make_service(first_repository)
    plan = create_plan(first_service, editor)
    approval = approve_plan(first_service, approver, plan)
    authorization = dispatch_plan(first_service, dispatcher, plan)
    first_repository.close()

    assert database.stat().st_mode & 0o077 == 0
    second_repository = SQLiteResponsePlanRepository(
        database, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY
    )
    second_service = make_service(second_repository)
    assert create_plan(second_service, editor) == plan
    assert approve_plan(second_service, approver, plan) == approval
    assert dispatch_plan(second_service, dispatcher, plan) == authorization
    with pytest.raises(ResponsePlanError, match="dispatch-authorization-conflict"):
        dispatch_plan(
            second_service,
            dispatcher,
            plan,
            idempotency_key="different-key-after-restart",
        )
    assert len(second_service.audit_history(INCIDENT_ID)) == 3
    second_repository.close()


def test_file_repository_rejects_insecure_symlink_and_unknown_schema(tmp_path: Path) -> None:
    insecure = tmp_path / "insecure.sqlite3"
    insecure.touch(mode=0o600)
    insecure.chmod(0o644)
    with pytest.raises(ResponsePlanError, match="repository-permissions-invalid"):
        SQLiteResponsePlanRepository(insecure, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY)

    unknown = tmp_path / "unknown.sqlite3"
    unknown.touch(mode=0o600)
    with pytest.raises(ResponsePlanError, match="repository-schema-invalid"):
        SQLiteResponsePlanRepository(unknown, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY)

    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    symlink = tmp_path / "link.sqlite3"
    symlink.symlink_to(target)
    with pytest.raises(ResponsePlanError, match="repository-path-invalid"):
        SQLiteResponsePlanRepository(symlink, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY)


@pytest.mark.parametrize(
    "drift_statement",
    (
        "ALTER TABLE response_plan_idempotency ADD COLUMN attacker_note TEXT",
        "CREATE INDEX response_plan_attacker_index ON response_plans (incident_id)",
    ),
    ids=("table-definition", "index-definition"),
)
def test_file_repository_rejects_table_and_index_definition_drift(
    tmp_path: Path, drift_statement: str
) -> None:
    database = tmp_path / "definition-drift.sqlite3"
    repository = prepare_repository(database)
    repository.close()

    with sqlite3.connect(database) as connection:
        connection.execute(drift_statement)

    with pytest.raises(ResponsePlanError, match="repository-schema-invalid"):
        SQLiteResponsePlanRepository(database, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY)


def test_file_repository_rejects_noop_audit_trigger_and_rewound_tail(
    tmp_path: Path,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    database = tmp_path / "rewound-audit.sqlite3"
    repository = prepare_repository(database)
    service = make_service(repository)
    plan = create_plan(service, editor)
    approve_plan(service, approver, plan)
    dispatch_plan(service, dispatcher, plan)
    events = service.audit_history(INCIDENT_ID)
    repository.close()

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER response_plan_audit_no_delete")
        connection.execute(
            "CREATE TRIGGER response_plan_audit_no_delete "
            "BEFORE DELETE ON response_plan_audit_events BEGIN SELECT 1; END"
        )
        connection.execute(
            "DELETE FROM response_plan_audit_events WHERE incident_id = ? AND sequence = 3",
            (INCIDENT_ID,),
        )
        connection.execute(
            "UPDATE response_plan_audit_heads SET sequence = 2, event_sha256 = ? "
            "WHERE incident_id = ?",
            (events[1]["event_sha256"], INCIDENT_ID),
        )

    with pytest.raises(ResponsePlanError, match="repository-schema-invalid"):
        SQLiteResponsePlanRepository(database, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY)


def test_cross_connection_concurrent_approval_is_serialized(
    tmp_path: Path,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
) -> None:
    database = tmp_path / "concurrent.sqlite3"
    first_repository = prepare_repository(database)
    second_repository = SQLiteResponsePlanRepository(
        database, authority_boundary=CANONICAL_AUTHORITY_BOUNDARY
    )
    first_service = make_service(first_repository)
    second_service = make_service(second_repository)
    plan = create_plan(first_service, editor)

    def decide(selected: ResponsePlanService, key: str) -> tuple[str, str]:
        try:
            result = approve_plan(selected, approver, plan, idempotency_key=key)
        except ResponsePlanError as error:
            return "error", error.code
        return "approved", result["decision_id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        results = [
            future.result(timeout=5)
            for future in (
                executor.submit(decide, first_service, "cross-connection-a"),
                executor.submit(decide, second_service, "cross-connection-b"),
            )
        ]
    assert len([result for result in results if result[0] == "approved"]) == 1
    assert ("error", "plan-decision-conflict") in results
    first_repository.close()
    second_repository.close()


def test_repository_lock_failure_is_typed_and_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "locked.sqlite3"
    first_repository = prepare_repository(database)
    second_repository = SQLiteResponsePlanRepository(
        database,
        authority_boundary=CANONICAL_AUTHORITY_BOUNDARY,
        busy_timeout_ms=1,
    )
    with first_repository.transaction(write=True):
        with pytest.raises(ResponsePlanError, match="repository-unavailable"):
            with second_repository.transaction(write=True):
                pytest.fail("locked transaction unexpectedly opened")
    first_repository.close()
    second_repository.close()


def test_audit_head_record_reconciliation_and_append_only_storage(
    service: ResponsePlanService,
    repository: SQLiteResponsePlanRepository,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    plan = create_plan(service, editor)
    approval = approve_plan(service, approver, plan)
    authorization = dispatch_plan(service, dispatcher, plan)
    events = service.audit_history(INCIDENT_ID)
    records = {
        plan["plan_sha256"]: plan,
        approval["decision_sha256"]: approval,
        authorization["authorization_sha256"]: authorization,
    }
    validate_audit_chain(
        events,
        trusted_head_sha256=events[-1]["event_sha256"],
        records=records,
    )
    with pytest.raises(ResponsePlanError, match="audit-head-mismatch"):
        validate_audit_chain(
            events[:-1],
            trusted_head_sha256=events[-1]["event_sha256"],
            records=records,
        )
    missing = dict(records)
    del missing[approval["decision_sha256"]]
    with pytest.raises(ResponsePlanError, match="audit-record-missing"):
        validate_audit_chain(
            events,
            trusted_head_sha256=events[-1]["event_sha256"],
            records=missing,
        )
    with pytest.raises(ResponsePlanError, match="repository-integrity-error"):
        with repository.transaction(write=True) as connection:
            connection.execute(
                "DELETE FROM response_plan_audit_events WHERE incident_id = ? AND sequence = 3",
                (INCIDENT_ID,),
            )


def test_audit_history_rejects_structurally_valid_orphan_authorization(
    service: ResponsePlanService,
    repository: SQLiteResponsePlanRepository,
    editor: VerifiedPrincipal,
    approver: VerifiedPrincipal,
    dispatcher: VerifiedPrincipal,
) -> None:
    first = create_plan(service, editor)
    approve_plan(service, approver, first)
    second = edit_plan(service, editor, first, idempotency_key="edit-for-orphan")
    second_approval = approve_plan(
        service,
        approver,
        second,
        idempotency_key="approve-for-orphan",
    )
    orphan = build_dispatch_authorization(
        plan=second,
        approval=second_approval,
        actor=dispatcher.actor(),
        idempotency_key="orphan-authorization",
        authorized_at="2026-08-13T15:00:00.000Z",
    )
    with repository.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO dispatch_authorizations("
            "authorization_id, operation_id, incident_id, plan_version, status, document) "
            "VALUES (?, ?, ?, ?, 'authorized', ?)",
            (
                orphan["authorization_id"],
                orphan["operation_id"],
                INCIDENT_ID,
                second["version"],
                canonical_json_bytes(orphan),
            ),
        )

    with pytest.raises(ResponsePlanError, match="audit-record-orphan"):
        service.audit_history(INCIDENT_ID)
