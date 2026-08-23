from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from colortrace_api import (
    APPROVAL_REQUEST_SCHEMA,
    CANONICAL_SCENARIO,
    CLOSURE_REQUEST_SCHEMA,
    EXECUTION_SCHEMA,
    PREPARATION_SCHEMA,
    RESET_REQUEST_SCHEMA,
    RUN_REQUEST_SCHEMA,
    DemoFacade,
    DemoFacadeError,
    Principal,
    SQLiteDemoRunStore,
    create_app,
)
from colortrace_recovery import document_sha256
from fastapi.testclient import TestClient

SOURCE_COMMIT = "a" * 40
RUN_IDS = (
    "demo-run-11111111111111111111111111111111",
    "demo-run-22222222222222222222222222222222",
)
NONCE = "n" * 32
INCIDENT_VERSION = 7
PLAN_VERSION = 3
PLAN_SHA256 = f"sha256:{'1' * 64}"
TARGET_SHA256 = f"sha256:{'2' * 64}"
OUTCOME_ID = f"simulator-action-outcome:{'3' * 64}"
OUTCOME_SHA256 = f"sha256:{'3' * 64}"
WORKFLOW_ID = f"recovery-workflow:{'4' * 64}"
WORKFLOW_VERSION = 2
PACKET_ID = f"recovery-packet:{'5' * 64}"
PACKET_SHA256 = f"sha256:{'5' * 64}"


class ManualClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


def _png(label: str) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + label.encode("ascii")


def _write_visuals(root: Path) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for kind in ("expected", "observed", "recovered", "diff"):
        content = _png(kind)
        path = root / f"{kind}.png"
        path.write_bytes(content)
        result[kind] = {
            "kind": kind,
            "path": path.name,
            "sha256": f"sha256:{hashlib.sha256(content).hexdigest()}",
            "media_type": "image/png",
        }
    return result


class FakeWorkflow:
    def __init__(self, visuals: Mapping[str, Mapping[str, str]]) -> None:
        self.visuals = visuals
        self.prepare_calls: list[Mapping[str, Any]] = []
        self.execute_calls: list[Mapping[str, Any]] = []
        self.reconcile_calls: list[Mapping[str, Any]] = []
        self.execute_error: BaseException | None = None
        self.reconciliation: Mapping[str, Any] | None = None

    def preparation(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": PREPARATION_SCHEMA,
            "run_id": request["run_id"],
            "incident_id": request["incident_id"],
            "incident_version": INCIDENT_VERSION,
            "plan_version": PLAN_VERSION,
            "plan_sha256": PLAN_SHA256,
            "target_sha256": TARGET_SHA256,
            "visuals": [dict(self.visuals[kind]) for kind in ("expected", "observed", "diff")],
        }

    def execution(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": EXECUTION_SCHEMA,
            "run_id": request["run_id"],
            "incident_id": request["incident_id"],
            "incident_version": request["incident_version"],
            "outcome_id": OUTCOME_ID,
            "outcome_sha256": OUTCOME_SHA256,
            "workflow_id": WORKFLOW_ID,
            "workflow_version": WORKFLOW_VERSION,
            "packet_id": PACKET_ID,
            "packet_sha256": PACKET_SHA256,
            "visuals": [dict(self.visuals["recovered"])],
        }

    def prepare(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.prepare_calls.append(request)
        return self.preparation(request)

    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.execute_calls.append(request)
        if self.execute_error is not None:
            raise self.execute_error
        return self.execution(request)

    def reconcile(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        self.reconcile_calls.append(request)
        return self.reconciliation


class FakeRecovery:
    def __init__(self) -> None:
        self.calls: list[tuple[Principal, str, Mapping[str, Any]]] = []
        self.result: dict[str, Any] | None = None
        self.close_error: BaseException | None = None

    def review(self, incident_id: str) -> dict[str, Any]:
        return {
            "schema": "recovery-review/v1",
            "incident_id": incident_id,
            "closure": self.result,
        }

    def close(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((principal, incident_id, body))
        result_body = {
            "schema": "recovery-closure-result/v1",
            "incident_id": incident_id,
            "workflow_id": WORKFLOW_ID,
            "workflow_version_before": WORKFLOW_VERSION,
            "workflow_version_after": WORKFLOW_VERSION + 1,
            "packet_id": PACKET_ID,
            "packet_sha256": PACKET_SHA256,
            "outcome_id": OUTCOME_ID,
            "outcome_sha256": OUTCOME_SHA256,
            "actor": {
                "issuer": principal.issuer,
                "subject": principal.subject,
                "audience": principal.audience,
                "display_name": principal.display_name,
                "kind": "human",
            },
            "authorized_role": "recovery.closer",
            "reason": body["reason"],
            "closed_at": "2026-08-23T12:00:00.000Z",
            "idempotency_key": body["idempotency_key"],
            "audit_event_id": f"recovery-audit:{'7' * 64}",
            "audit_event_sha256": f"sha256:{'7' * 64}",
        }
        digest = document_sha256(result_body)
        self.result = {
            **result_body,
            "closure_id": f"recovery-closure:{digest.removeprefix('sha256:')}",
            "closure_sha256": digest,
        }
        if self.close_error is not None:
            raise self.close_error
        return self.result


def _principal(run_id: str = RUN_IDS[0]) -> Principal:
    return Principal(
        subject="demo-operator@example.test",
        display_name="Demo operator",
        roles=frozenset({"recovery.closer"}),
        issuer="https://identity.example.test",
        audience="colortrace-api",
        principal_kind="human",
        incident_ids=frozenset({f"incident-demo-{run_id.removeprefix('demo-run-')}"}),
        credential_sha256=f"sha256:{'9' * 64}",
        expires_at=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
    )


def _facade(
    tmp_path: Path,
    *,
    clock: ManualClock | None = None,
    workflow: FakeWorkflow | None = None,
    run_ids: tuple[str, ...] = RUN_IDS,
) -> tuple[DemoFacade, FakeWorkflow, FakeRecovery, ManualClock, Path]:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir(exist_ok=True)
    visuals = _write_visuals(visual_root)
    selected_workflow = workflow or FakeWorkflow(visuals)
    selected_clock = clock or ManualClock()
    recovery = FakeRecovery()
    values = iter(run_ids)
    facade = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=selected_workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(run_ids[0]),
        clock=selected_clock,
        run_id_factory=values.__next__,
        nonce_factory=lambda: NONCE,
    )
    return facade, selected_workflow, recovery, selected_clock, visual_root


def _start(facade: DemoFacade) -> dict[str, Any]:
    return facade.start({"schema": RUN_REQUEST_SCHEMA, "scenario_id": CANONICAL_SCENARIO})


def _approval(started: Mapping[str, Any]) -> dict[str, Any]:
    approval = started["approval"]
    assert isinstance(approval, Mapping)
    return {
        "schema": APPROVAL_REQUEST_SCHEMA,
        "approval_nonce": started["approval_nonce"],
        "approval_phrase": approval["phrase"],
        "expected_run_version": started["version"],
        "expected_incident_version": approval["incident_version"],
        "expected_plan_version": approval["plan_version"],
        "expected_plan_sha256": approval["plan_sha256"],
        "expected_target_sha256": approval["target_sha256"],
        "idempotency_key": "demo-approve-1",
    }


def _closure(recovered: Mapping[str, Any]) -> dict[str, Any]:
    recovery = recovered["recovery"]
    assert isinstance(recovery, Mapping)
    approval = recovered["approval"]
    assert isinstance(approval, Mapping)
    return {
        "schema": CLOSURE_REQUEST_SCHEMA,
        "expected_run_version": recovered["version"],
        "expected_incident_version": approval["incident_version"],
        "expected_workflow_version": recovery["workflow_version"],
        "expected_packet_id": recovery["packet_id"],
        "expected_packet_sha256": recovery["packet_sha256"],
        "expected_outcome_id": recovery["outcome_id"],
        "expected_outcome_sha256": recovery["outcome_sha256"],
        "reason": "The verified recovery evidence is complete.",
        "idempotency_key": "demo-close-1",
    }


def test_durable_run_binds_approval_execution_closure_and_receipt(tmp_path: Path) -> None:
    facade, workflow, recovery, _clock, _root = _facade(tmp_path)

    started = _start(facade)

    assert started["phase"] == "awaiting-approval"
    assert started["version"] == 2
    assert started["run_id"] == RUN_IDS[0]
    assert started["incident_id"] == "incident-demo-11111111111111111111111111111111"
    assert started["scenario_id"] == CANONICAL_SCENARIO
    assert started["source_commit"] == SOURCE_COMMIT
    assert started["approval_nonce"] == NONCE
    assert started["poll"] == {
        "href": f"/v1/demo/runs/{RUN_IDS[0]}",
        "after_milliseconds": 1_000,
    }
    assert "approval_nonce" not in facade.get(RUN_IDS[0])

    with pytest.raises(DemoFacadeError, match="demo-active-run-exists"):
        _start(facade)

    approval = _approval(started)
    recovered = facade.approve(RUN_IDS[0], approval)
    replayed_recovery = facade.approve(RUN_IDS[0], approval)

    assert replayed_recovery == recovered
    assert recovered["phase"] == "awaiting-closure"
    assert recovered["version"] == 4
    assert len(workflow.execute_calls) == 1
    assert workflow.execute_calls[0] == {
        "schema": "colortrace-demo-execution-request/v1",
        "run_id": RUN_IDS[0],
        "incident_id": started["incident_id"],
        "incident_version": INCIDENT_VERSION,
        "plan_version": PLAN_VERSION,
        "plan_sha256": PLAN_SHA256,
        "target_sha256": TARGET_SHA256,
        "idempotency_key": "demo-approve-1",
    }

    closure = _closure(recovered)
    closed = facade.close(RUN_IDS[0], closure)
    replayed_close = facade.close(RUN_IDS[0], closure)

    assert replayed_close == closed
    assert closed["phase"] == "closed"
    assert closed["version"] == 6
    assert closed["terminal"] is True
    assert len(recovery.calls) == 1
    assert recovery.calls[0][1] == started["incident_id"]
    assert recovery.calls[0][2] == {
        "schema": "recovery-closure-request/v1",
        **{key: closure[key] for key in closure if key not in {"schema", "expected_run_version"}},
    }

    receipt = facade.receipt(RUN_IDS[0])
    assert receipt["phase"] == "closed"
    assert receipt["run_version"] == 6
    assert recovery.result is not None
    assert receipt["bindings"]["closure_id"] == recovery.result["closure_id"]
    assert receipt["bindings"]["closure_sha256"] == recovery.result["closure_sha256"]
    assert {visual["kind"] for visual in receipt["visuals"]} == {
        "expected",
        "observed",
        "recovered",
        "diff",
    }


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("approval_nonce", "x" * 32, "demo-approval-nonce-invalid"),
        ("approval_phrase", "APPROVE", "demo-approval-phrase-invalid"),
        ("expected_run_version", 99, "demo-run-version-conflict"),
        ("expected_incident_version", 99, "demo-approval-binding-conflict"),
        ("expected_plan_version", 99, "demo-approval-binding-conflict"),
        ("expected_plan_sha256", f"sha256:{'e' * 64}", "demo-approval-binding-conflict"),
        ("expected_target_sha256", f"sha256:{'e' * 64}", "demo-approval-binding-conflict"),
    ],
)
def test_approval_rejects_stale_or_forged_bindings_before_execution(
    tmp_path: Path,
    field: str,
    value: Any,
    code: str,
) -> None:
    facade, workflow, _recovery, _clock, _root = _facade(tmp_path)
    started = _start(facade)
    request = _approval(started)
    request[field] = value

    with pytest.raises(DemoFacadeError, match=code):
        facade.approve(RUN_IDS[0], request)

    assert workflow.execute_calls == []
    assert facade.get(RUN_IDS[0])["phase"] == "awaiting-approval"


def test_operation_idempotency_key_cannot_be_rebound(tmp_path: Path) -> None:
    facade, workflow, _recovery, _clock, _root = _facade(tmp_path)
    started = _start(facade)
    request = _approval(started)
    facade.approve(RUN_IDS[0], request)
    request["idempotency_key"] = "demo-approve-other"

    with pytest.raises(DemoFacadeError, match="demo-idempotency-conflict"):
        facade.approve(RUN_IDS[0], request)

    assert len(workflow.execute_calls) == 1


def test_visuals_are_allowlisted_and_revalidated_on_every_read(tmp_path: Path) -> None:
    facade, _workflow, _recovery, _clock, visual_root = _facade(tmp_path)
    started = _start(facade)

    expected = facade.visual(RUN_IDS[0], "expected")
    assert expected.content == _png("expected")
    assert expected.media_type == "image/png"
    with pytest.raises(DemoFacadeError, match="demo-visual-not-found"):
        facade.visual(RUN_IDS[0], "recovered")
    with pytest.raises(DemoFacadeError, match="demo-visual-kind-invalid"):
        facade.visual(RUN_IDS[0], "private-oracle")

    facade.approve(RUN_IDS[0], _approval(started))
    assert facade.visual(RUN_IDS[0], "recovered").content == _png("recovered")
    (visual_root / "recovered.png").write_bytes(_png("tampered"))
    with pytest.raises(DemoFacadeError, match="demo-visual-digest-conflict"):
        facade.visual(RUN_IDS[0], "recovered")


def test_expired_lease_releases_lock_and_preserves_receipt(tmp_path: Path) -> None:
    clock = ManualClock()
    facade, _workflow, _recovery, _clock, _root = _facade(tmp_path, clock=clock)
    _start(facade)
    clock.value += timedelta(minutes=15, milliseconds=1)

    expired = facade.get(RUN_IDS[0])

    assert expired["phase"] == "expired"
    assert expired["terminal_reason"] == "lease-expired"
    assert facade.receipt(RUN_IDS[0])["phase"] == "expired"
    replacement = _start(facade)
    assert replacement["run_id"] == RUN_IDS[1]


def test_reset_requires_terminal_state_and_does_not_change_receipt(tmp_path: Path) -> None:
    facade, _workflow, _recovery, clock, _root = _facade(tmp_path)
    started = _start(facade)
    reset = {
        "schema": RESET_REQUEST_SCHEMA,
        "expected_run_version": started["version"],
        "idempotency_key": "reset-1",
    }
    with pytest.raises(DemoFacadeError, match="demo-reset-not-terminal"):
        facade.reset(RUN_IDS[0], reset)
    clock.value += timedelta(minutes=16)
    expired = facade.get(RUN_IDS[0])
    receipt_before = facade.receipt(RUN_IDS[0])
    reset["expected_run_version"] = expired["version"]

    first = facade.reset(RUN_IDS[0], reset)
    second = facade.reset(RUN_IDS[0], reset)

    assert first == second
    assert first["reset"] is True
    assert facade.get(RUN_IDS[0])["reset"] is True
    assert facade.receipt(RUN_IDS[0]) == receipt_before


def test_startup_reconciles_an_interrupted_execution_without_replay(tmp_path: Path) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    workflow.execute_error = SystemExit("simulated process stop")

    with pytest.raises(SystemExit, match="simulated process stop"):
        facade.approve(RUN_IDS[0], _approval(started))

    assert facade.get(RUN_IDS[0])["phase"] == "executing"
    resumed_workflow = FakeWorkflow(workflow.visuals)
    resumed_workflow.reconciliation = resumed_workflow.execution(
        {
            "run_id": RUN_IDS[0],
            "incident_id": started["incident_id"],
            "incident_version": INCIDENT_VERSION,
        }
    )
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=resumed_workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(),
        clock=clock,
    )

    assert resumed.get(RUN_IDS[0])["phase"] == "awaiting-closure"
    assert resumed_workflow.reconcile_calls == [
        {
            "schema": "colortrace-demo-reconciliation-request/v1",
            "run_id": RUN_IDS[0],
            "incident_id": started["incident_id"],
            "phase": "executing",
            "run_version": 3,
        }
    ]
    assert workflow.execute_calls and resumed_workflow.execute_calls == []


def test_startup_reconciles_an_interrupted_closure_from_durable_recovery(
    tmp_path: Path,
) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))
    recovery.close_error = SystemExit("simulated response loss")

    with pytest.raises(SystemExit, match="simulated response loss"):
        facade.close(RUN_IDS[0], _closure(recovered))

    assert facade.get(RUN_IDS[0])["phase"] == "closing"
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(),
        clock=clock,
    )

    assert resumed.get(RUN_IDS[0])["phase"] == "closed"
    assert recovery.result is not None
    assert resumed.receipt(RUN_IDS[0])["bindings"]["closure_id"] == recovery.result["closure_id"]


def test_receipt_and_visual_rows_are_append_only(tmp_path: Path) -> None:
    facade, _workflow, _recovery, _clock, _root = _facade(tmp_path)
    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))
    facade.close(RUN_IDS[0], _closure(recovered))

    with sqlite3.connect(tmp_path / "demo.sqlite3") as connection:
        with pytest.raises(sqlite3.IntegrityError, match="demo-receipts-immutable"):
            connection.execute(
                "UPDATE demo_receipts SET receipt_sha256 = ? WHERE run_id = ?",
                (f"sha256:{'f' * 64}", RUN_IDS[0]),
            )
        with pytest.raises(sqlite3.IntegrityError, match="demo-visuals-no-delete"):
            connection.execute("DELETE FROM demo_visuals WHERE run_id = ?", (RUN_IDS[0],))


class IncidentService:
    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]:
        raise AssertionError((alert, principal))

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        return {"schema": "incident-list/v1", "items": [], "next_cursor": None}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError(incident_id)

    def replay(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError(incident_id)

    def workspace(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError(incident_id)


def test_demo_routes_enforce_json_origin_and_bounded_visual_kinds(tmp_path: Path) -> None:
    facade, _workflow, _recovery, _clock, _root = _facade(tmp_path)
    client = TestClient(create_app(IncidentService(), demo=facade))
    body = {"schema": RUN_REQUEST_SCHEMA, "scenario_id": CANONICAL_SCENARIO}

    denied = client.post(
        "/v1/demo/runs",
        json=body,
        headers={"Origin": "https://other.example.test"},
    )
    wrong_media = client.post(
        "/v1/demo/runs",
        content='{"schema":"colortrace-demo-run-request/v1"}',
        headers={"Content-Type": "text/plain"},
    )
    duplicate = client.post(
        "/v1/demo/runs",
        content=(
            '{"schema":"colortrace-demo-run-request/v1",'
            '"scenario_id":"ct-shadowed-lut-v1:canonical",'
            '"scenario_id":"ct-shadowed-lut-v1:canonical"}'
        ),
        headers={"Content-Type": "application/json"},
    )
    oversized = client.post(
        "/v1/demo/runs",
        content=b"{" + b" " * 16_384 + b"}",
        headers={"Content-Type": "application/json"},
    )
    started = client.post(
        "/v1/demo/runs",
        json=body,
        headers={"Origin": "http://testserver"},
    )

    assert denied.status_code == 403
    assert denied.json() == {"code": "demo-origin-denied"}
    assert wrong_media.status_code == 415
    assert wrong_media.json() == {"code": "demo-content-type-invalid"}
    assert duplicate.status_code == 400
    assert duplicate.json() == {"code": "demo-request-invalid"}
    assert oversized.status_code == 413
    assert oversized.json() == {"code": "demo-request-too-large"}
    assert started.status_code == 201
    assert client.get(f"/v1/demo/runs/{RUN_IDS[0]}").status_code == 200
    visual = client.get(f"/v1/demo/runs/{RUN_IDS[0]}/visuals/expected")
    assert visual.status_code == 200
    assert visual.content == _png("expected")
    assert visual.headers["content-type"] == "image/png"
    assert visual.headers["x-content-sha256"].startswith("sha256:")
    assert client.get(f"/v1/demo/runs/{RUN_IDS[0]}/visuals/oracle").status_code == 400
