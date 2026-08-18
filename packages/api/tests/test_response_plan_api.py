from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from colortrace_api import Principal, ResponsePlanCoordinator, create_app
from colortrace_response_plans import (
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    ResponsePlanError,
    SQLiteResponsePlanRepository,
)
from colortrace_simulator import DispatchIdentity
from fastapi.testclient import TestClient

NOW = datetime(2026, 8, 13, 18, 0, tzinfo=UTC)
INCIDENT_ID = "incident-plan-api"
PACKET_DIGEST = f"sha256:{'6' * 64}"
PACKET_ID = f"response-packet:{'6' * 64}"
CAUSAL_DIGEST = f"sha256:{'7' * 64}"
VALIDATOR_CAUSAL_DIGEST = CAUSAL_DIGEST.removeprefix("sha256:")


class IncidentService:
    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]:
        raise AssertionError("not used")

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        return {"schema": "incident-list/v1", "items": [], "next_cursor": None}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return {"schema": "incident-view/v1", "incident_id": incident_id}

    def workspace(self, incident_id: str) -> dict[str, Any]:
        return {"schema": "incident-workspace-source/v1", "incident_id": incident_id}

    def replay(self, incident_id: str) -> dict[str, Any]:
        return {
            "schema": "incident-replay/v1",
            "incident": {
                "incident_id": incident_id,
                "status": "resolved",
                "version": 7,
            },
            "packet": {
                "packet_id": PACKET_ID,
                "incident_id": incident_id,
                "status": "resolved",
                "derivation_sha256": PACKET_DIGEST,
                "candidate_plan": {
                    "targets": [
                        {"kind": "frame", "id": "frame-affected"},
                        {"kind": "derivative", "id": "derivative-affected"},
                    ]
                },
                "scope": {
                    "state": "resolved",
                    "policy": "single-causal-resource-scope/v1",
                    "affected": [
                        {"kind": "frame", "id": "frame-affected"},
                        {"kind": "derivative", "id": "derivative-affected"},
                    ],
                    "safe": [{"kind": "frame", "id": "frame-safe"}],
                    "unknown": [],
                    "reason_codes": [],
                },
                "unresolved_items": [],
            },
            "validator_results": [{"scope": {"causal_resource_sha256": VALIDATOR_CAUSAL_DIGEST}}],
        }


class Verifier:
    def verify(self, token: str) -> Principal:
        role, kind, incidents = {
            "editor": ("response-plan.editor", "human", frozenset({INCIDENT_ID})),
            "approver": ("response-plan.approver", "human", frozenset({INCIDENT_ID})),
            "dispatcher": (
                "response-plan.dispatcher",
                "service",
                frozenset({INCIDENT_ID}),
            ),
            "other-editor": (
                "response-plan.editor",
                "human",
                frozenset({"incident-other"}),
            ),
            "expired": ("response-plan.approver", "human", frozenset({INCIDENT_ID})),
        }[token]
        return Principal(
            subject=f"{token}@example.test",
            display_name=token,
            roles=frozenset({role}),
            issuer="https://identity.example.test",
            audience="colortrace-api",
            principal_kind=kind,  # type: ignore[arg-type]
            incident_ids=incidents,
            credential_sha256=f"sha256:{'8' * 64}",
            expires_at=NOW - timedelta(seconds=1)
            if token == "expired"
            else NOW + timedelta(hours=1),
        )


def client_with_plans() -> tuple[TestClient, SQLiteResponsePlanRepository, ResponsePlanCoordinator]:
    service = IncidentService()
    authority = CanonicalAuthorityBoundary()
    repository = SQLiteResponsePlanRepository(":memory:", authority_boundary=authority)
    plans = ResponsePlanCoordinator(
        incident_reader=service,
        repository=repository,
        authority_boundary=authority,
        identity_boundary=OIDCTrustBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-api",
        ),
        clock=lambda: NOW,
    )
    return (
        TestClient(create_app(service, token_verifier=Verifier(), response_plans=plans)),
        repository,
        plans,
    )


def client_with_repository() -> tuple[TestClient, SQLiteResponsePlanRepository]:
    api_client, repository, _plans = client_with_plans()
    return api_client, repository


def client() -> TestClient:
    return client_with_repository()[0]


def assert_repository_empty(repository: SQLiteResponsePlanRepository) -> None:
    tables = (
        "authority_incidents",
        "response_packet_authority",
        "response_plans",
        "response_plan_decisions",
        "dispatch_authorizations",
        "response_plan_audit_events",
        "response_plan_audit_heads",
        "response_plan_idempotency",
    )
    with repository.transaction(write=False) as connection:
        assert {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in tables
        } == dict.fromkeys(tables, 0)


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def action_envelope() -> dict[str, Any]:
    return {
        "schema": "simulator-action-envelope/v1",
        "fixture_id": "colortrace-plan-api",
        "fixture_manifest_sha256": f"sha256:{'0' * 64}",
        "fixture_generation": 7,
        "source_batch_id": "fixture-run-plan-api",
        "source_batch_sha256": f"sha256:{'1' * 64}",
        "runtime_manifest_sha256": f"sha256:{'2' * 64}",
        "runtime_generation": 7,
        "expected_publication_pointer_sha256": f"sha256:{'3' * 64}",
        "expected_publication_generation": 7,
        "expected_resource_sha256": CAUSAL_DIGEST,
        "replacement_resource_logical_path": "luts/show_look.cube",
        "replacement_resource_sha256": f"sha256:{'4' * 64}",
        "declared_resource_manifest_sha256": f"sha256:{'5' * 64}",
        "ocio_version": "2.5.2",
        "preservation_manifest_sha256": f"sha256:{'6' * 64}",
        "safe_complement_sha256": f"sha256:{'7' * 64}",
        "lineage_manifest_sha256": f"sha256:{'8' * 64}",
        "lineage_generation": 7,
    }


def commands(targets: list[dict[str, str]]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for target in targets:
        if target["kind"] == "color-resource":
            values.append(
                {
                    "schema": "simulator-quarantine-command/v1",
                    "command_id": "quarantine-causal-resource",
                    "namespace": "colortrace-simulator",
                    "target": target,
                    "action_envelope": action_envelope(),
                    "expected_resource_sha256": CAUSAL_DIGEST,
                    "mode": "quarantine-and-install-approved-replacement",
                }
            )
        else:
            values.append(
                {
                    "schema": "simulator-targeted-rerender-command/v1",
                    "command_id": f"rerender-{target['kind']}",
                    "namespace": "colortrace-simulator",
                    "target": target,
                    "action_envelope": action_envelope(),
                    "job_id": f"job-{target['kind']}",
                    "transform_id": "look/main/v1",
                    "source_id": f"source-{target['kind']}",
                    "source_manifest_sha256": f"sha256:{'b' * 64}",
                    "source_png_sha256": f"sha256:{'9' * 64}",
                    "expected_config_sha256": f"sha256:{'a' * 64}",
                    "lineage_parent_artifact_id": f"parent-{target['kind']}",
                    **(
                        {
                            "expected_output_sha256": f"sha256:{'c' * 64}",
                            "expected_display_sha256": f"sha256:{'d' * 64}",
                        }
                        if target["kind"] == "frame"
                        else {
                            "expected_derivative_sha256": f"sha256:{'c' * 64}",
                            "expected_derivative_display_sha256": f"sha256:{'d' * 64}",
                        }
                    ),
                }
            )
    return values


def create_body(api_client: TestClient) -> dict[str, Any]:
    draft = api_client.get(f"/v1/incidents/{INCIDENT_ID}/response-plan/draft").json()
    return {
        "expected_incident_version": draft["incident_version"],
        "expected_plan_version": 0,
        "response_packet_id": draft["response_packet_id"],
        "response_packet_sha256": draft["response_packet_sha256"],
        "deterministic_scope_sha256": draft["deterministic_scope_sha256"],
        "targets": draft["targets"],
        "exclusions": draft["exclusions"],
        "commands": commands(draft["targets"]),
        "unresolved_acknowledged": False,
        "idempotency_key": "create-plan-api",
    }


def test_validator_causal_digest_must_be_canonical_bare_hex(tmp_path: Path) -> None:
    class PrefixedIncidentService(IncidentService):
        def replay(self, incident_id: str) -> dict[str, Any]:
            replay = super().replay(incident_id)
            replay["validator_results"][0]["scope"]["causal_resource_sha256"] = CAUSAL_DIGEST
            return replay

    authority = CanonicalAuthorityBoundary()
    coordinator = ResponsePlanCoordinator(
        incident_reader=PrefixedIncidentService(),
        repository=SQLiteResponsePlanRepository(
            tmp_path / "response-plans.sqlite3", authority_boundary=authority
        ),
        authority_boundary=authority,
        identity_boundary=OIDCTrustBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-api",
        ),
    )

    with pytest.raises(ResponsePlanError, match="canonical-scope-invalid"):
        coordinator.draft(INCIDENT_ID)


def test_absent_plan_is_a_side_effect_free_not_found() -> None:
    api_client, repository = client_with_repository()

    response = api_client.get(f"/v1/incidents/{INCIDENT_ID}/response-plan")

    assert response.status_code == 404
    assert response.json() == {"code": "plan-not-found"}
    assert_repository_empty(repository)


def test_public_can_review_but_cannot_create_or_decide_and_idor_fails() -> None:
    api_client, repository = client_with_repository()
    body = create_body(api_client)

    assert (
        api_client.post(f"/v1/incidents/{INCIDENT_ID}/response-plan", json=body).status_code == 401
    )
    forbidden = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=body,
        headers=headers("other-editor"),
    )
    assert forbidden.status_code == 403
    assert forbidden.json() == {"code": "incident-access-denied"}
    assert_repository_empty(repository)

    created = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=body,
        headers=headers("editor"),
    )
    assert created.status_code == 201
    review = api_client.get(f"/v1/incidents/{INCIDENT_ID}/response-plan")
    assert review.status_code == 200
    assert review.json()["state"] == "pending"
    assert review.json()["plan"] == created.json()
    assert (
        api_client.post(
            f"/v1/incidents/{INCIDENT_ID}/response-plan/approve",
            json={},
        ).status_code
        == 401
    )


def test_idor_edit_denial_has_no_authority_or_mutation_side_effects() -> None:
    api_client, repository = client_with_repository()
    body = {
        **create_body(api_client),
        "expected_plan_version": 1,
        "expected_plan_sha256": f"sha256:{'f' * 64}",
        "idempotency_key": "forbidden-edit-plan-api",
    }

    forbidden = api_client.put(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=body,
        headers=headers("other-editor"),
    )

    assert forbidden.status_code == 403
    assert forbidden.json() == {"code": "incident-access-denied"}
    assert_repository_empty(repository)


def test_approval_binds_expected_version_edit_invalidates_and_rejection_blocks_dispatch() -> None:
    api_client = client()
    body = create_body(api_client)
    plan = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=body,
        headers=headers("editor"),
    ).json()
    approval_body = {
        "expected_incident_version": 7,
        "expected_plan_version": 1,
        "expected_plan_sha256": plan["plan_sha256"],
        "idempotency_key": "approve-plan-api",
    }
    stale = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/approve",
        json={**approval_body, "expected_plan_version": 2},
        headers=headers("approver"),
    )
    assert stale.status_code == 409
    approved = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/approve",
        json=approval_body,
        headers=headers("approver"),
    )
    assert approved.status_code == 200
    assert approved.json()["outcome"] == "approved"

    edit_body = {
        **body,
        "expected_plan_version": 1,
        "expected_plan_sha256": plan["plan_sha256"],
        "idempotency_key": "edit-plan-api",
    }
    edited = api_client.put(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=edit_body,
        headers=headers("editor"),
    )
    assert edited.status_code == 200
    assert edited.json()["version"] == 2
    assert api_client.get(f"/v1/incidents/{INCIDENT_ID}/response-plan").json()["state"] == "pending"

    rejection = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/reject",
        json={
            "expected_incident_version": 7,
            "expected_plan_version": 2,
            "expected_plan_sha256": edited.json()["plan_sha256"],
            "reason_code": "unsafe-scope",
            "idempotency_key": "reject-plan-api",
        },
        headers=headers("approver"),
    )
    assert rejection.status_code == 200
    assert rejection.json()["outcome"] == "rejected"
    dispatch = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-authorizations",
        json={
            "expected_incident_version": 7,
            "expected_plan_version": 2,
            "expected_plan_sha256": edited.json()["plan_sha256"],
            "idempotency_key": "dispatch-rejected-plan",
        },
        headers=headers("dispatcher"),
    )
    assert dispatch.status_code == 409
    assert dispatch.json() == {"code": "plan-rejected"}


def test_service_only_dispatch_is_single_use_and_authoritative_replay_is_exact() -> None:
    api_client = client()
    plan = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=create_body(api_client),
        headers=headers("editor"),
    ).json()
    api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/approve",
        json={
            "expected_incident_version": 7,
            "expected_plan_version": 1,
            "expected_plan_sha256": plan["plan_sha256"],
            "idempotency_key": "approve-dispatch-plan",
        },
        headers=headers("approver"),
    )
    request = {
        "expected_incident_version": 7,
        "expected_plan_version": 1,
        "expected_plan_sha256": plan["plan_sha256"],
        "idempotency_key": "authorize-dispatch-plan",
    }
    human = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-authorizations",
        json=request,
        headers=headers("approver"),
    )
    assert human.status_code == 403
    authorization = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-authorizations",
        json=request,
        headers=headers("dispatcher"),
    ).json()
    consume_request = {
        "authorization_id": authorization["authorization_id"],
        "expected_incident_version": 7,
        "expected_plan_version": 1,
        "expected_plan_sha256": plan["plan_sha256"],
        "expected_task_key": authorization["task_key"],
        "expected_payload_sha256": authorization["payload_sha256"],
        "idempotency_key": "consume-dispatch-plan",
    }
    first = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-consumptions",
        json=consume_request,
        headers=headers("dispatcher"),
    )
    replay = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-consumptions",
        json=consume_request,
        headers=headers("dispatcher"),
    )
    assert first.status_code == 200
    assert replay.json() == first.json()
    authorization_replay = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-authorizations",
        json=request,
        headers=headers("dispatcher"),
    )
    assert authorization_replay.status_code == 200
    assert authorization_replay.json() == authorization
    history = api_client.get(f"/v1/incidents/{INCIDENT_ID}/response-plan").json()["audit_events"]
    assert [event["event_type"] for event in history].count("dispatch.consumed") == 1


def test_simulator_source_loads_only_the_exact_current_consumed_dispatch() -> None:
    api_client, _repository, plans = client_with_plans()
    plan = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=create_body(api_client),
        headers=headers("editor"),
    ).json()
    approval = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/approve",
        json={
            "expected_incident_version": 7,
            "expected_plan_version": 1,
            "expected_plan_sha256": plan["plan_sha256"],
            "idempotency_key": "approve-simulator-source",
        },
        headers=headers("approver"),
    ).json()
    authorization = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-authorizations",
        json={
            "expected_incident_version": 7,
            "expected_plan_version": 1,
            "expected_plan_sha256": plan["plan_sha256"],
            "idempotency_key": "authorize-simulator-source",
        },
        headers=headers("dispatcher"),
    ).json()
    consumption = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-consumptions",
        json={
            "authorization_id": authorization["authorization_id"],
            "expected_incident_version": 7,
            "expected_plan_version": 1,
            "expected_plan_sha256": plan["plan_sha256"],
            "expected_task_key": authorization["task_key"],
            "expected_payload_sha256": authorization["payload_sha256"],
            "idempotency_key": "consume-simulator-source",
        },
        headers=headers("dispatcher"),
    ).json()
    proof = plans.load_current_consumed(
        DispatchIdentity(
            task_key=authorization["task_key"],
            operation_id=authorization["operation_id"],
            payload_sha256=authorization["payload_sha256"],
        )
    )
    assert proof.plan == plan
    assert proof.approval == approval
    assert proof.authorization == authorization
    assert proof.consumption == consumption
    assert proof.audit_events[-1]["event_type"] == "dispatch.consumed"
    assert proof.trusted_audit_head_sha256 == proof.audit_events[-1]["event_sha256"]


def test_expired_credential_and_unexpected_request_fields_fail_closed() -> None:
    api_client = client()
    body = create_body(api_client)
    body["free_form_command"] = "rm -rf"
    malformed = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=body,
        headers=headers("editor"),
    )
    assert malformed.status_code == 400
    assert malformed.json() == {"code": "request-invalid"}

    valid = create_body(api_client)
    plan = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan",
        json=valid,
        headers=headers("editor"),
    ).json()
    expired = api_client.post(
        f"/v1/incidents/{INCIDENT_ID}/response-plan/approve",
        json={
            "expected_incident_version": 7,
            "expected_plan_version": 1,
            "expected_plan_sha256": plan["plan_sha256"],
            "idempotency_key": "expired-approval",
        },
        headers=headers("expired"),
    )
    assert expired.status_code == 401
    assert expired.json() == {"code": "principal-credential-expired"}
