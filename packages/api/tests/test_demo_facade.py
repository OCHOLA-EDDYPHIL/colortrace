from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from colortrace_api import (
    APPROVAL_REQUEST_SCHEMA,
    CANONICAL_SCENARIO,
    CLOSURE_REQUEST_SCHEMA,
    EXECUTION_PROOF_SCHEMA,
    EXECUTION_SCHEMA,
    INVESTIGATION_PROOF_SCHEMA,
    PREPARATION_SCHEMA,
    RESET_REQUEST_SCHEMA,
    RUN_REQUEST_SCHEMA,
    DemoFacade,
    DemoFacadeError,
    Principal,
    SQLiteDemoRunStore,
    create_app,
)
from colortrace_api.runtime import _runtime_lifespan
from colortrace_api.simulator_runtime import LocalSimulatorRuntime
from colortrace_recovery import CHECK_NAMES, RecoveryError, document_sha256
from colortrace_simulator import DispatchIdentity
from colortrace_simulator.repository import SimulatorRepositoryError
from fastapi.testclient import TestClient

SOURCE_COMMIT = "a" * 40
RUN_IDS = (
    "demo-run-11111111111111111111111111111111",
    "demo-run-22222222222222222222222222222222",
)
NONCE = "n" * 32
SECOND_NONCE = "m" * 32
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
        self.prepare_error: BaseException | None = None
        self.execute_error: BaseException | None = None
        self.reconcile_error: BaseException | None = None
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
            "plan_version": request["plan_version"],
            "plan_sha256": request["plan_sha256"],
            "target_sha256": request["target_sha256"],
            "idempotency_key": request["idempotency_key"],
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
        if self.prepare_error is not None:
            raise self.prepare_error
        return self.preparation(request)

    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.execute_calls.append(request)
        if self.execute_error is not None:
            raise self.execute_error
        return self.execution(request)

    def reconcile(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        self.reconcile_calls.append(request)
        if self.reconcile_error is not None:
            raise self.reconcile_error
        return self.reconciliation


class ProofWorkflow(FakeWorkflow):
    def preparation(self, request: Mapping[str, Any]) -> dict[str, Any]:
        result = super().preparation(request)
        query_tools = (
            ("alert.rule", "alerting_manage_rules"),
            ("log.correlated-events", "query_loki_logs"),
            ("metric.correlated-observations", "query_prometheus"),
            ("trace.by-id", "tempo_get-trace"),
        )
        result["investigation"] = {
            "schema": INVESTIGATION_PROOF_SCHEMA,
            "packet_id": f"response-packet:{'6' * 64}",
            "packet_sha256": f"sha256:{'6' * 64}",
            "status": "resolved",
            "model_invocations": [
                {
                    "invocation_id": f"model-invocation:{digit * 64}",
                    "turn_kind": turn,
                    "model": "gemini-3.5-flash",
                    "framework": "google-adk",
                    "result_class": "accepted",
                    "inventory_sha256": f"sha256:{'7' * 64}",
                    "output_sha256": f"sha256:{digit * 64}",
                    "trace_id": digit * 32,
                }
                for digit, turn in (
                    ("8", "evidence-selection"),
                    ("9", "response-drafting"),
                )
            ],
            "evidence": [
                {
                    "evidence_id": f"sha256:{index * 64}",
                    "query_key": query,
                    "tool": tool,
                    "inventory_sha256": f"sha256:{'7' * 64}",
                    "content_sha256": f"sha256:{index * 64}",
                    "freshness": "current",
                }
                for index, (query, tool) in zip("abcd", query_tools, strict=True)
            ],
            "validators": [
                {
                    "result_id": f"validator-result:{'e' * 64}",
                    "validator": "colortrace-validator",
                    "validator_version": "1.0.0",
                    "status": "resolved",
                    "derivation_sha256": f"sha256:{'e' * 64}",
                }
            ],
            "scope": {
                "state": "resolved",
                "affected_count": 4,
                "safe_count": 3,
                "unknown_count": 0,
            },
            "budget_use": {
                "elapsed_ms": 1,
                "model_turns": 2,
                "input_tokens": 100,
                "output_tokens": 20,
                "mcp_attempts": 4,
                "validator_calls": 6,
            },
            "plan": {
                "status": "pending",
                "version": PLAN_VERSION,
                "plan_sha256": PLAN_SHA256,
                "target_sha256": TARGET_SHA256,
            },
        }
        return result

    def execution(self, request: Mapping[str, Any]) -> dict[str, Any]:
        result = super().execution(request)
        result["execution"] = {
            "schema": EXECUTION_PROOF_SCHEMA,
            "action": {
                "action_id": f"simulator-action:{'a' * 64}",
                "status": "succeeded",
                "outcome_id": OUTCOME_ID,
                "outcome_sha256": OUTCOME_SHA256,
                "publication_generation_before": 1,
                "publication_generation_after": 2,
                "affected_count": 4,
                "safe_count": 3,
                "safe_complement_before_sha256": f"sha256:{'b' * 64}",
                "safe_complement_after_sha256": f"sha256:{'b' * 64}",
                "safe_complement_proof_sha256": f"sha256:{'c' * 64}",
                "publication_receipt_sha256": f"sha256:{'d' * 64}",
            },
            "recovery": {
                "status": "recovery_verified",
                "workflow_id": WORKFLOW_ID,
                "workflow_version": WORKFLOW_VERSION,
                "packet_id": PACKET_ID,
                "packet_sha256": PACKET_SHA256,
                "evidence_count": 21,
                "evidence_request_sha256": f"sha256:{'e' * 64}",
                "checks": [
                    {
                        "check": check,
                        "status": "passed",
                        "result_sha256": f"sha256:{index:064x}",
                    }
                    for index, check in enumerate(CHECK_NAMES, start=1)
                ],
            },
        }
        return result


class ProoflessExecutionWorkflow(ProofWorkflow):
    def execution(self, request: Mapping[str, Any]) -> dict[str, Any]:
        return FakeWorkflow.execution(self, request)


class NonCurrentEvidenceWorkflow(ProofWorkflow):
    def __init__(self, visuals: Mapping[str, Mapping[str, str]], *, freshness: str) -> None:
        super().__init__(visuals)
        self.freshness = freshness

    def preparation(self, request: Mapping[str, Any]) -> dict[str, Any]:
        result = super().preparation(request)
        investigation = result["investigation"]
        assert isinstance(investigation, dict)
        evidence = investigation["evidence"]
        assert isinstance(evidence, list)
        first = evidence[0]
        assert isinstance(first, dict)
        first["freshness"] = self.freshness
        return result


class BlockingProofWorkflow(ProofWorkflow):
    def __init__(self, visuals: Mapping[str, Mapping[str, str]]) -> None:
        super().__init__(visuals)
        self.prepare_entered = threading.Event()
        self.release_prepare = threading.Event()

    def prepare(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.prepare_calls.append(request)
        self.prepare_entered.set()
        if not self.release_prepare.wait(timeout=5):
            raise TimeoutError("test prepare release timed out")
        return self.preparation(request)

    def reconcile(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        self.reconcile_calls.append(request)
        operation_request = request["operation_request"]
        assert isinstance(operation_request, Mapping)
        return self.preparation(operation_request)


class FakeRecovery:
    def __init__(self) -> None:
        self.calls: list[tuple[Principal, str, Mapping[str, Any]]] = []
        self.result: dict[str, Any] | None = None
        self.review_error: BaseException | None = None
        self.close_error_before_result: BaseException | None = None
        self.close_error: BaseException | None = None

    def review(self, incident_id: str) -> dict[str, Any]:
        if self.review_error is not None:
            raise self.review_error
        return {
            "schema": "recovery-review/v1",
            "incident_id": incident_id,
            "snapshot": {"incident_id": incident_id},
            "closure": self.result,
        }

    def close(
        self,
        principal: Principal,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        self.calls.append((principal, incident_id, body))
        if self.close_error_before_result is not None:
            raise self.close_error_before_result
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


class FakeScenarioReset:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def restore_authored_scenario(self, *, operation_id: str) -> Mapping[str, Any]:
        self.calls.append(operation_id)
        return {
            "schema": "simulator-authored-scenario-reset/v1",
            "operation_id": operation_id,
            "fixture_id": "colortrace-canonical",
            "source_batch_sha256": f"sha256:{'a' * 64}",
            "previous_pointer_sha256": f"sha256:{'b' * 64}",
            "active_pointer_sha256": f"sha256:{'c' * 64}",
            "generation": 1,
        }


class ResponseLossScenarioReset(FakeScenarioReset):
    def __init__(self) -> None:
        super().__init__()
        self.fail_once = True

    def restore_authored_scenario(self, *, operation_id: str) -> Mapping[str, Any]:
        result = super().restore_authored_scenario(operation_id=operation_id)
        if self.fail_once:
            self.fail_once = False
            raise SystemExit("simulated reset response loss")
        return result


@dataclass
class QueuedExecutionState:
    identity: DispatchIdentity
    pending: bool = True
    outcome: dict[str, Any] | None = None
    executed: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)


class QueuedExecutionRepository:
    def __init__(self, state: QueuedExecutionState) -> None:
        self.state = state

    def pending_action_identities(self, *, limit: int = 100) -> list[DispatchIdentity]:
        del limit
        with self.state.lock:
            return [self.state.identity] if self.state.pending else []

    def close(self) -> None:
        return None


class QueuedExecutionService:
    def __init__(self, state: QueuedExecutionState) -> None:
        self.state = state

    def execute(
        self,
        identity: DispatchIdentity,
        *,
        owner: str,
        observe_terminal: bool = True,
    ) -> dict[str, Any]:
        del owner, observe_terminal
        with self.state.lock:
            assert identity == self.state.identity
            self.state.pending = False
            self.state.outcome = {"status": "succeeded"}
            self.state.executed.set()
            return self.state.outcome

    def deliver_pending_telemetry(self, *, limit: int = 100) -> int:
        del limit
        return 0


class QuietTelemetrySink:
    def shutdown(self) -> None:
        return None


class RunnerAwareProofWorkflow(ProofWorkflow):
    def __init__(
        self,
        visuals: Mapping[str, Mapping[str, str]],
        state: QueuedExecutionState,
    ) -> None:
        super().__init__(visuals)
        self.state = state
        self.runtime: LocalSimulatorRuntime | None = None

    def execute(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        self.execute_calls.append(request)
        raise SystemExit("simulated process stop")

    def reconcile(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        self.reconcile_calls.append(request)
        if self.runtime is None or not self.runtime.runner.thread_alive:
            raise SimulatorRepositoryError("simulator-runner-unavailable")
        if not self.state.executed.wait(timeout=2):
            raise SimulatorRepositoryError("simulator-action-in-progress")
        operation_request = request.get("operation_request")
        if not isinstance(operation_request, Mapping):
            raise DemoFacadeError("demo-reconciliation-request-invalid")
        return self.execution(operation_request)


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
    scenario_reset: FakeScenarioReset | None = None,
    run_ids: tuple[str, ...] = RUN_IDS,
) -> tuple[DemoFacade, FakeWorkflow, FakeRecovery, ManualClock, Path]:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir(exist_ok=True)
    visuals = _write_visuals(visual_root)
    selected_workflow = workflow or ProofWorkflow(visuals)
    selected_clock = clock or ManualClock()
    recovery = FakeRecovery()
    values = iter(run_ids)
    facade = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=selected_workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        scenario_reset=scenario_reset or FakeScenarioReset(),
        closure_principal=_principal(run_ids[0]),
        clock=selected_clock,
        run_id_factory=values.__next__,
    )
    return facade, selected_workflow, recovery, selected_clock, visual_root


def _start_body(
    *,
    nonce: str = NONCE,
    idempotency_key: str = "demo-start-1",
) -> dict[str, Any]:
    return {
        "schema": RUN_REQUEST_SCHEMA,
        "scenario_id": CANONICAL_SCENARIO,
        "approval_nonce": nonce,
        "idempotency_key": idempotency_key,
    }


def _start(
    facade: DemoFacade,
    *,
    nonce: str = NONCE,
    idempotency_key: str = "demo-start-1",
) -> dict[str, Any]:
    return facade.start(_start_body(nonce=nonce, idempotency_key=idempotency_key))


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
    assert set(started["visual_comparison"]) == {"expected", "observed", "diff"}
    assert started["visual_comparison"]["observed"]["href"] == (
        f"/v1/demo/runs/{RUN_IDS[0]}/visuals/observed"
    )
    assert started["visual_comparison"]["observed"]["label"] == ("illustrative-authored-fixture")
    assert "approval_nonce" not in facade.get(RUN_IDS[0])

    assert _start(facade) == started
    with pytest.raises(DemoFacadeError, match="demo-active-run-exists") as conflict:
        _start(
            facade,
            nonce=SECOND_NONCE,
            idempotency_key="demo-start-2",
        )
    assert conflict.value.run_id == RUN_IDS[0]

    approval = _approval(started)
    recovered = facade.approve(RUN_IDS[0], approval)
    replayed_recovery = facade.approve(RUN_IDS[0], approval)

    assert replayed_recovery == recovered
    assert recovered["phase"] == "awaiting-closure"
    assert recovered["version"] == 4
    assert set(recovered["visual_comparison"]) == {
        "expected",
        "observed",
        "recovered",
        "diff",
    }
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


def test_start_retry_after_response_loss_recovers_nonce_and_can_approve(
    tmp_path: Path,
) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)

    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(),
        clock=clock,
    )
    replayed = _start(resumed)

    assert replayed == started
    assert replayed["approval_nonce"] == NONCE
    assert len(workflow.prepare_calls) == 1
    assert resumed.approve(RUN_IDS[0], _approval(replayed))["phase"] == "awaiting-closure"

    with sqlite3.connect(tmp_path / "demo.sqlite3") as connection:
        stored = connection.execute(
            "SELECT approval_nonce_sha256, start_request_sha256 FROM demo_runs WHERE run_id = ?",
            (RUN_IDS[0],),
        ).fetchone()
        delegated = connection.execute(
            "SELECT delegated_request_document FROM demo_operations WHERE run_id = ?",
            (RUN_IDS[0],),
        ).fetchall()
    assert stored is not None
    assert NONCE not in "".join(stored)
    assert all(NONCE.encode("ascii") not in row[0] for row in delegated)


def test_start_idempotency_key_cannot_be_rebound(tmp_path: Path) -> None:
    facade, workflow, _recovery, _clock, _root = _facade(tmp_path)
    _start(facade)

    with pytest.raises(DemoFacadeError, match="demo-idempotency-conflict"):
        _start(facade, nonce=SECOND_NONCE)

    assert len(workflow.prepare_calls) == 1


def test_bounded_proofs_are_persisted_projected_and_receipted(tmp_path: Path) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    workflow = ProofWorkflow(_write_visuals(visual_root))
    facade, _workflow, _recovery, _clock, _root = _facade(
        tmp_path,
        workflow=workflow,
    )

    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))

    assert started["investigation"]["scope"] == {
        "state": "resolved",
        "affected_count": 4,
        "safe_count": 3,
        "unknown_count": 0,
    }
    assert [item["query_key"] for item in started["investigation"]["evidence"]] == [
        "alert.rule",
        "log.correlated-events",
        "metric.correlated-observations",
        "trace.by-id",
    ]
    assert (
        recovered["execution"]["action"]["safe_complement_before_sha256"]
        == (recovered["execution"]["action"]["safe_complement_after_sha256"])
    )
    assert recovered["execution"]["recovery"]["evidence_count"] == 21

    closed = facade.close(RUN_IDS[0], _closure(recovered))
    receipt = facade.receipt(RUN_IDS[0])

    assert closed["investigation"] == started["investigation"]
    assert closed["execution"] == recovered["execution"]
    assert [item["stage"] for item in receipt["proofs"]] == [
        "execution",
        "investigation",
    ]
    assert all(item["sha256"].startswith("sha256:") for item in receipt["proofs"])

    with sqlite3.connect(tmp_path / "demo.sqlite3") as connection:
        with pytest.raises(sqlite3.IntegrityError, match="demo-proofs-immutable"):
            connection.execute(
                "UPDATE demo_proofs SET proof_sha256 = ? WHERE run_id = ?",
                (f"sha256:{'f' * 64}", RUN_IDS[0]),
            )


def test_proofless_preparation_is_rejected_and_terminalized(tmp_path: Path) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    workflow = FakeWorkflow(_write_visuals(visual_root))
    facade, _workflow, _recovery, _clock, _root = _facade(tmp_path, workflow=workflow)

    with pytest.raises(DemoFacadeError, match="demo-preparation-invalid"):
        _start(facade)

    assert facade.get(RUN_IDS[0])["phase"] == "unresolved"
    assert facade.receipt(RUN_IDS[0])["proofs"] == []
    with pytest.raises(DemoFacadeError, match="demo-reset-required") as conflict:
        _start(
            facade,
            nonce=SECOND_NONCE,
            idempotency_key="demo-start-2",
        )
    assert conflict.value.run_id == RUN_IDS[0]


@pytest.mark.parametrize("freshness", ["stale", "unresolved"])
def test_preparation_rejects_noncurrent_evidence_and_terminalizes(
    tmp_path: Path,
    freshness: str,
) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    workflow = NonCurrentEvidenceWorkflow(_write_visuals(visual_root), freshness=freshness)
    facade, _workflow, _recovery, _clock, _root = _facade(tmp_path, workflow=workflow)

    with pytest.raises(DemoFacadeError, match="demo-investigation-proof-binding-invalid"):
        _start(facade)

    assert workflow.execute_calls == []
    assert facade.get(RUN_IDS[0])["phase"] == "unresolved"
    assert facade.receipt(RUN_IDS[0])["proofs"] == []


def test_proofless_execution_is_rejected_and_terminalized(tmp_path: Path) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    workflow = ProoflessExecutionWorkflow(_write_visuals(visual_root))
    facade, _workflow, _recovery, _clock, _root = _facade(tmp_path, workflow=workflow)
    started = _start(facade)

    with pytest.raises(DemoFacadeError, match="demo-execution-invalid"):
        facade.approve(RUN_IDS[0], _approval(started))

    assert facade.get(RUN_IDS[0])["phase"] == "unresolved"
    assert [item["stage"] for item in facade.receipt(RUN_IDS[0])["proofs"]] == ["investigation"]


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


def test_operation_idempotency_binds_the_complete_versioned_request(tmp_path: Path) -> None:
    facade, workflow, recovery, _clock, _root = _facade(tmp_path)
    started = _start(facade)
    approval = _approval(started)
    recovered = facade.approve(RUN_IDS[0], approval)

    changed_approval = {**approval, "expected_run_version": approval["expected_run_version"] + 1}
    with pytest.raises(DemoFacadeError, match="demo-idempotency-conflict"):
        facade.approve(RUN_IDS[0], changed_approval)

    closure = _closure(recovered)
    facade.close(RUN_IDS[0], closure)
    changed_closure = {**closure, "expected_run_version": closure["expected_run_version"] + 1}
    with pytest.raises(DemoFacadeError, match="demo-idempotency-conflict"):
        facade.close(RUN_IDS[0], changed_closure)

    assert len(workflow.execute_calls) == 1
    assert len(recovery.calls) == 1


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
    facade.reset(
        RUN_IDS[0],
        {
            "schema": RESET_REQUEST_SCHEMA,
            "expected_run_version": expired["version"],
            "idempotency_key": "reset-expired-1",
        },
    )
    replacement = _start(
        facade,
        nonce=SECOND_NONCE,
        idempotency_key="demo-start-2",
    )
    assert replacement["run_id"] == RUN_IDS[1]


def test_reset_requires_terminal_state_and_does_not_change_receipt(tmp_path: Path) -> None:
    scenario_reset = FakeScenarioReset()
    facade, _workflow, _recovery, clock, _root = _facade(
        tmp_path,
        scenario_reset=scenario_reset,
    )
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
    assert first["restoration"]["generation"] == 1
    assert len(scenario_reset.calls) == 1
    assert facade.get(RUN_IDS[0])["reset"] is True
    assert facade.receipt(RUN_IDS[0]) == receipt_before


def test_reset_restores_scenario_for_two_complete_runs_and_preserves_first_receipt(
    tmp_path: Path,
) -> None:
    scenario_reset = FakeScenarioReset()
    facade, _workflow, _recovery, _clock, _root = _facade(
        tmp_path,
        scenario_reset=scenario_reset,
    )
    first = _start(facade)
    first_recovered = facade.approve(RUN_IDS[0], _approval(first))
    first_closed = facade.close(RUN_IDS[0], _closure(first_recovered))
    first_receipt = facade.receipt(RUN_IDS[0])
    facade.reset(
        RUN_IDS[0],
        {
            "schema": RESET_REQUEST_SCHEMA,
            "expected_run_version": first_closed["version"],
            "idempotency_key": "reset-first-run",
        },
    )

    second = _start(
        facade,
        nonce=SECOND_NONCE,
        idempotency_key="demo-start-2",
    )
    second_recovered = facade.approve(RUN_IDS[1], _approval(second))
    second_closed = facade.close(RUN_IDS[1], _closure(second_recovered))
    facade.reset(
        RUN_IDS[1],
        {
            "schema": RESET_REQUEST_SCHEMA,
            "expected_run_version": second_closed["version"],
            "idempotency_key": "reset-first-run",
        },
    )

    assert second_closed["phase"] == "closed"
    assert facade.receipt(RUN_IDS[0]) == first_receipt
    assert facade.receipt(RUN_IDS[1])["run_id"] == RUN_IDS[1]
    assert len(scenario_reset.calls) == 2
    assert len(set(scenario_reset.calls)) == 2


def test_startup_replays_pending_reset_after_process_response_loss(tmp_path: Path) -> None:
    scenario_reset = ResponseLossScenarioReset()
    facade, workflow, recovery, clock, visual_root = _facade(
        tmp_path,
        scenario_reset=scenario_reset,
    )
    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))
    closed = facade.close(RUN_IDS[0], _closure(recovered))
    request = {
        "schema": RESET_REQUEST_SCHEMA,
        "expected_run_version": closed["version"],
        "idempotency_key": "reset-response-loss",
    }

    with pytest.raises(SystemExit, match="simulated reset response loss"):
        facade.reset(RUN_IDS[0], request)

    pending = SQLiteDemoRunStore(tmp_path / "demo.sqlite3").pending_reset()
    assert pending is not None
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        scenario_reset=scenario_reset,
        closure_principal=_principal(),
        clock=clock,
        reconcile_on_startup=False,
    )

    resumed.reconcile_startup()

    assert resumed.get(RUN_IDS[0])["reset"] is True
    assert resumed.reset(RUN_IDS[0], request)["reset"] is True
    assert len(scenario_reset.calls) == 2
    assert scenario_reset.calls[0] == scenario_reset.calls[1]
    assert SQLiteDemoRunStore(tmp_path / "demo.sqlite3").pending_reset() is None


def test_startup_reconciles_an_interrupted_execution_without_replay(tmp_path: Path) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    workflow.execute_error = SystemExit("simulated process stop")

    with pytest.raises(SystemExit, match="simulated process stop"):
        facade.approve(RUN_IDS[0], _approval(started))

    assert facade.get(RUN_IDS[0])["phase"] == "executing"
    resumed_workflow = ProofWorkflow(workflow.visuals)
    resumed_workflow.reconciliation = resumed_workflow.execution(workflow.execute_calls[0])
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
            "operation": "approve",
            "idempotency_key": "demo-approve-1",
            "operation_request_sha256": document_sha256(workflow.execute_calls[0]),
            "operation_request": workflow.execute_calls[0],
            "lease_expired": False,
        }
    ]
    assert workflow.execute_calls and resumed_workflow.execute_calls == []


def test_foreground_prepare_and_get_reconciliation_are_process_serialized(
    tmp_path: Path,
) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    workflow = BlockingProofWorkflow(_write_visuals(visual_root))
    facade, _workflow, recovery, clock, _root = _facade(tmp_path, workflow=workflow)
    reader = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(),
        clock=clock,
        reconcile_on_startup=False,
    )
    started: list[dict[str, Any]] = []
    observed: list[dict[str, Any]] = []
    errors: list[BaseException] = []
    get_entered = threading.Event()

    def run_start() -> None:
        try:
            started.append(_start(facade))
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    def run_get() -> None:
        try:
            get_entered.set()
            observed.append(reader.get(RUN_IDS[0]))
        except BaseException as error:  # pragma: no cover - asserted below
            errors.append(error)

    starter = threading.Thread(target=run_start)
    getter = threading.Thread(target=run_get)
    starter.start()
    assert workflow.prepare_entered.wait(timeout=2)
    getter.start()
    assert get_entered.wait(timeout=2)
    workflow.release_prepare.set()
    starter.join(timeout=5)
    getter.join(timeout=5)

    assert not starter.is_alive() and not getter.is_alive()
    assert errors == []
    assert started[0]["phase"] == "awaiting-approval"
    assert observed[0]["phase"] == "awaiting-approval"
    assert len(workflow.prepare_calls) == 1
    assert workflow.reconcile_calls == []


def test_startup_reconciles_an_interrupted_closure_from_durable_recovery(
    tmp_path: Path,
) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))
    recovery.close_error = SystemExit("simulated response loss")

    with pytest.raises(SystemExit, match="simulated response loss"):
        facade.close(RUN_IDS[0], _closure(recovered))

    assert SQLiteDemoRunStore(tmp_path / "demo.sqlite3").transient(now=clock())["phase"] == (
        "closing"
    )
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


def test_startup_resumes_exact_close_request_after_crash_before_side_effect(
    tmp_path: Path,
) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))
    request = _closure(recovered)
    recovery.close_error_before_result = SystemExit("simulated process stop")

    with pytest.raises(SystemExit, match="simulated process stop"):
        facade.close(RUN_IDS[0], request)

    assert recovery.result is None
    recovery.close_error_before_result = None
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
    assert len(recovery.calls) == 2
    assert recovery.calls[0][2] == recovery.calls[1][2]
    assert recovery.calls[1][2]["idempotency_key"] == request["idempotency_key"]


def test_prepare_response_loss_reconciles_exact_request_after_lease(tmp_path: Path) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    workflow = ProofWorkflow(_write_visuals(visual_root))
    workflow.prepare_error = ConnectionError("response lost")
    clock = ManualClock()
    facade = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        clock=clock,
        run_id_factory=iter(RUN_IDS).__next__,
    )

    with pytest.raises(DemoFacadeError, match="demo-operation-uncertain"):
        _start(facade)

    workflow.prepare_error = None
    workflow.reconciliation = workflow.preparation(workflow.prepare_calls[0])
    clock.value += timedelta(minutes=16)
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        clock=clock,
    )

    replayed = _start(resumed)
    assert replayed["phase"] == "awaiting-approval"
    assert replayed["approval_nonce"] == NONCE
    request = workflow.reconcile_calls[0]
    assert request["operation"] == "prepare"
    assert request["operation_request"] == workflow.prepare_calls[0]
    assert request["operation_request_sha256"] == document_sha256(workflow.prepare_calls[0])
    assert request["lease_expired"] is True
    assert resumed.approve(RUN_IDS[0], _approval(replayed))["phase"] == "awaiting-closure"


def test_known_alert_failure_terminalizes_with_receipt_and_unlocks(tmp_path: Path) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    workflow = ProofWorkflow(_write_visuals(visual_root))
    workflow.prepare_error = DemoFacadeError("demo-alert-timeout")
    clock = ManualClock()
    scenario_reset = FakeScenarioReset()
    facade = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        scenario_reset=scenario_reset,
        clock=clock,
        run_id_factory=iter(RUN_IDS).__next__,
    )

    with pytest.raises(DemoFacadeError, match="demo-alert-timeout"):
        _start(facade)

    failed = facade.get(RUN_IDS[0])
    assert failed["phase"] == "unresolved"
    assert failed["terminal_reason"] == "demo-alert-timeout"
    assert facade.receipt(RUN_IDS[0])["reason_code"] == "demo-alert-timeout"
    workflow.prepare_error = None
    facade.reset(
        RUN_IDS[0],
        {
            "schema": RESET_REQUEST_SCHEMA,
            "expected_run_version": failed["version"],
            "idempotency_key": "reset-alert-failure",
        },
    )
    assert (
        _start(
            facade,
            nonce=SECOND_NONCE,
            idempotency_key="demo-start-2",
        )["run_id"]
        == RUN_IDS[1]
    )


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (RecoveryError("recovery-unresolved"), "recovery-unresolved"),
        (
            SimulatorRepositoryError("simulator-runner-unavailable"),
            "simulator-runner-unavailable",
        ),
    ],
)
def test_known_execution_domain_failures_terminalize(
    tmp_path: Path,
    error: BaseException,
    reason: str,
) -> None:
    facade, workflow, _recovery, _clock, _root = _facade(tmp_path)
    started = _start(facade)
    workflow.execute_error = error

    with pytest.raises(DemoFacadeError, match="demo-operation-failed"):
        facade.approve(RUN_IDS[0], _approval(started))

    failed = facade.get(RUN_IDS[0])
    assert failed["phase"] == "unresolved"
    assert failed["terminal_reason"] == reason


def test_expired_inconclusive_execution_terminalizes_and_unlocks(tmp_path: Path) -> None:
    facade, workflow, _recovery, clock, _root = _facade(
        tmp_path,
        run_ids=(RUN_IDS[0], RUN_IDS[1], RUN_IDS[1]),
    )
    started = _start(facade)
    workflow.execute_error = ConnectionError("response lost")
    with pytest.raises(DemoFacadeError, match="demo-operation-uncertain"):
        facade.approve(RUN_IDS[0], _approval(started))
    workflow.execute_error = None
    workflow.reconcile_error = ConnectionError("recovery unavailable")
    clock.value += timedelta(minutes=16)

    failed = _start(facade)

    assert failed["phase"] == "unresolved"
    assert failed["terminal_reason"] == "restart-reconciliation-timeout"
    assert facade.receipt(RUN_IDS[0])["reason_code"] == "restart-reconciliation-timeout"
    workflow.reconcile_error = None
    facade.reset(
        RUN_IDS[0],
        {
            "schema": RESET_REQUEST_SCHEMA,
            "expected_run_version": failed["version"],
            "idempotency_key": "reset-execution-timeout",
        },
    )
    replacement = _start(
        facade,
        nonce=SECOND_NONCE,
        idempotency_key="demo-start-2",
    )
    assert replacement["run_id"] == RUN_IDS[1]


def test_execution_response_loss_reconciles_exact_request_after_lease(tmp_path: Path) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    workflow.execute_error = ConnectionError("response lost")

    with pytest.raises(DemoFacadeError, match="demo-operation-uncertain"):
        facade.approve(RUN_IDS[0], _approval(started))

    workflow.execute_error = None
    workflow.reconciliation = workflow.execution(workflow.execute_calls[0])
    clock.value += timedelta(minutes=16)
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(),
        clock=clock,
    )

    assert resumed.get(RUN_IDS[0])["phase"] == "awaiting-closure"
    assert len(workflow.execute_calls) == 1
    request = workflow.reconcile_calls[0]
    assert request["operation_request"] == workflow.execute_calls[0]
    assert request["idempotency_key"] == "demo-approve-1"
    assert request["lease_expired"] is True


def test_closure_response_loss_reconciles_authoritative_result_after_lease(
    tmp_path: Path,
) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))
    recovery.close_error = ConnectionError("response lost")

    with pytest.raises(DemoFacadeError, match="demo-operation-uncertain"):
        facade.close(RUN_IDS[0], _closure(recovered))

    recovery.close_error = None
    clock.value += timedelta(minutes=16)
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(),
        clock=clock,
    )

    assert len(recovery.calls) == 1
    assert resumed.get(RUN_IDS[0])["phase"] == "closed"
    assert recovery.result is not None
    assert resumed.receipt(RUN_IDS[0])["bindings"]["closure_id"] == recovery.result["closure_id"]


def test_temporary_closure_lookup_failure_stays_locked_and_later_heals(tmp_path: Path) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    started = _start(facade)
    recovered = facade.approve(RUN_IDS[0], _approval(started))
    recovery.close_error = SystemExit("process stopped")
    with pytest.raises(SystemExit, match="process stopped"):
        facade.close(RUN_IDS[0], _closure(recovered))
    recovery.close_error = None
    recovery.review_error = ConnectionError("temporarily unavailable")
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        closure_principal=_principal(),
        clock=clock,
    )
    assert resumed.get(RUN_IDS[0])["phase"] == "closing"
    with pytest.raises(DemoFacadeError, match="demo-active-run-exists"):
        _start(
            resumed,
            nonce=SECOND_NONCE,
            idempotency_key="demo-start-2",
        )

    recovery.review_error = None
    assert resumed.get(RUN_IDS[0])["phase"] == "closed"


def test_active_run_cannot_cross_source_commit_binding(tmp_path: Path) -> None:
    facade, workflow, recovery, clock, visual_root = _facade(tmp_path)
    _start(facade)

    with pytest.raises(DemoFacadeError, match="demo-build-binding-conflict"):
        DemoFacade(
            store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
            workflow=workflow,
            source_commit="b" * 40,
            visual_root=visual_root,
            recovery=recovery,
            closure_principal=_principal(),
            clock=clock,
        )

    assert workflow.execute_calls == []


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


def test_runtime_starts_worker_before_reconciling_persisted_execution(
    tmp_path: Path,
) -> None:
    visual_root = tmp_path / "visuals"
    visual_root.mkdir()
    state = QueuedExecutionState(
        DispatchIdentity(
            task_key=f"dispatch-task:{'1' * 64}",
            operation_id=f"dispatch-operation:{'2' * 64}",
            payload_sha256=f"sha256:{'3' * 64}",
        )
    )
    workflow = RunnerAwareProofWorkflow(_write_visuals(visual_root), state)
    clock = ManualClock()
    recovery = FakeRecovery()
    facade = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        scenario_reset=FakeScenarioReset(),
        closure_principal=_principal(),
        clock=clock,
        run_id_factory=iter(RUN_IDS).__next__,
    )
    started = _start(facade)
    with pytest.raises(SystemExit, match="simulated process stop"):
        facade.approve(RUN_IDS[0], _approval(started))
    transient = SQLiteDemoRunStore(tmp_path / "demo.sqlite3").transient(now=clock())
    assert transient is not None and transient["phase"] == "executing"

    runtime = LocalSimulatorRuntime(
        repository=QueuedExecutionRepository(state),
        service=QueuedExecutionService(state),
        telemetry_sink=QuietTelemetrySink(),
        poll_seconds=0.01,
        join_timeout_seconds=2,
    )
    workflow.runtime = runtime
    resumed = DemoFacade(
        store=SQLiteDemoRunStore(tmp_path / "demo.sqlite3"),
        workflow=workflow,
        source_commit=SOURCE_COMMIT,
        visual_root=visual_root,
        recovery=recovery,
        scenario_reset=FakeScenarioReset(),
        closure_principal=_principal(),
        clock=clock,
        reconcile_on_startup=False,
    )
    app = create_app(
        IncidentService(),
        demo=resumed,
        lifespan=_runtime_lifespan(runtime, resumed),
    )

    with TestClient(app):
        projection = resumed.get(RUN_IDS[0])
        assert projection["phase"] == "awaiting-closure"
        assert state.outcome == {"status": "succeeded"}
        with pytest.raises(DemoFacadeError, match="demo-receipt-not-ready"):
            resumed.receipt(RUN_IDS[0])

    assert len(workflow.reconcile_calls) == 1


class FailingDemo:
    def __init__(self, code: str) -> None:
        self.code = code

    def start(self, _body: Mapping[str, Any]) -> dict[str, Any]:
        raise DemoFacadeError(self.code)


def test_demo_routes_enforce_json_origin_and_bounded_visual_kinds(tmp_path: Path) -> None:
    facade, _workflow, _recovery, _clock, _root = _facade(
        tmp_path,
        run_ids=(RUN_IDS[0], RUN_IDS[1], RUN_IDS[1]),
    )
    app = create_app(IncidentService(), demo=facade)
    client = TestClient(app)
    fresh_client = TestClient(app)
    body = _start_body()

    denied = client.post(
        "/v1/demo/runs",
        json=body,
        headers={"Origin": "https://other.example.test"},
    )
    wrong_media = client.post(
        "/v1/demo/runs",
        content=f'{{"schema":"{RUN_REQUEST_SCHEMA}"}}',
        headers={"Content-Type": "text/plain"},
    )
    duplicate = client.post(
        "/v1/demo/runs",
        content=(
            f'{{"schema":"{RUN_REQUEST_SCHEMA}",'
            '"scenario_id":"ct-shadowed-lut-v1:canonical",'
            '"scenario_id":"ct-shadowed-lut-v1:canonical",'
            f'"approval_nonce":"{NONCE}",'
            '"idempotency_key":"demo-start-1"}'
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
    active_conflict = fresh_client.post(
        "/v1/demo/runs",
        json=_start_body(nonce=SECOND_NONCE, idempotency_key="demo-start-2"),
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
    assert active_conflict.status_code == 409
    assert active_conflict.json() == {
        "code": "demo-active-run-exists",
        "run_id": RUN_IDS[0],
    }
    recovered_active = fresh_client.get(f"/v1/demo/runs/{active_conflict.json()['run_id']}")
    assert recovered_active.status_code == 200
    assert recovered_active.json()["phase"] == "awaiting-approval"
    visual = client.get(f"/v1/demo/runs/{RUN_IDS[0]}/visuals/expected")
    assert visual.status_code == 200
    assert visual.content == _png("expected")
    assert visual.headers["content-type"] == "image/png"
    assert visual.headers["x-content-sha256"].startswith("sha256:")
    assert client.get(f"/v1/demo/runs/{RUN_IDS[0]}/visuals/oracle").status_code == 400

    recovered = facade.approve(RUN_IDS[0], _approval(started.json()))
    closed = facade.close(RUN_IDS[0], _closure(recovered))
    terminal_client = TestClient(app)
    terminal_conflict = terminal_client.post(
        "/v1/demo/runs",
        json=_start_body(nonce=SECOND_NONCE, idempotency_key="demo-start-3"),
        headers={"Origin": "http://testserver"},
    )

    assert closed["phase"] == "closed"
    assert terminal_conflict.status_code == 409
    assert terminal_conflict.json() == {
        "code": "demo-reset-required",
        "run_id": RUN_IDS[0],
    }
    recovered_terminal = terminal_client.get(f"/v1/demo/runs/{terminal_conflict.json()['run_id']}")
    assert recovered_terminal.status_code == 200
    assert recovered_terminal.json()["phase"] == "closed"


@pytest.mark.parametrize(
    "code",
    (
        "demo-operation-uncertain",
        "demo-reset-uncertain",
        "demo-reset-unavailable",
        "demo-simulator-unavailable",
    ),
)
def test_demo_routes_report_retryable_failures_as_unavailable(code: str) -> None:
    client = TestClient(create_app(IncidentService(), demo=FailingDemo(code)))

    response = client.post("/v1/demo/runs", json={})

    assert response.status_code == 503
    assert response.json() == {"code": code}
