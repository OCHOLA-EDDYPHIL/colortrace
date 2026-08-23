from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from colortrace_api import (
    Principal,
    ResponsePlanCoordinator,
    SimulatorActionCoordinator,
    create_app,
)
from colortrace_api.runtime import (
    ApiRuntimeConfig,
    ApiRuntimeConfigurationError,
    create_application,
)
from colortrace_api.simulator_runtime import LocalSimulatorRuntime, SimulatorSerialRunner
from colortrace_fixture.fixture import (  # type: ignore[import-untyped]
    CANONICAL_SEED,
    build_scenario,
)
from colortrace_response_plans import (
    CanonicalAuthorityBoundary,
    OIDCTrustBoundary,
    SQLiteResponsePlanRepository,
)
from colortrace_simulator import DispatchIdentity, SimulatorActionService
from colortrace_simulator.authority import (
    ExecutorAuthorization,
    SimulatorAuthorityBoundary,
    SimulatorExecutorBoundary,
)
from colortrace_simulator.bundle import LocalPublicationPort
from colortrace_simulator.repository import SimulatorRepositoryError, SQLiteSimulatorRepository
from colortrace_telemetry import MemoryActionTelemetrySink, emit_action_outcome
from fastapi.testclient import TestClient
from jwt import PyJWK

NOW = datetime(2026, 8, 13, 22, 0, tzinfo=UTC)
INCIDENT_ID = "incident-runtime-simulator"
IDENTITY = DispatchIdentity(
    task_key=f"dispatch-task:{'1' * 64}",
    operation_id=f"dispatch-operation:{'2' * 64}",
    payload_sha256=f"sha256:{'3' * 64}",
)


@dataclass
class DurableState:
    pending: list[DispatchIdentity] = field(default_factory=list)
    outcomes: dict[DispatchIdentity, dict[str, Any]] = field(default_factory=dict)
    telemetry_pending: set[DispatchIdentity] = field(default_factory=set)
    telemetry_delivered: set[DispatchIdentity] = field(default_factory=set)
    execution_owners: list[str] = field(default_factory=list)
    lifecycle: list[str] = field(default_factory=list)
    execute_event: threading.Event = field(default_factory=threading.Event)
    telemetry_event: threading.Event = field(default_factory=threading.Event)
    lock: threading.Lock = field(default_factory=threading.Lock)


class RuntimeRepository:
    def __init__(self, state: DurableState) -> None:
        self.state = state

    def pending_action_identities(self, *, limit: int = 100) -> list[DispatchIdentity]:
        with self.state.lock:
            return list(self.state.pending[:limit])

    def close(self) -> None:
        self.state.lifecycle.append("repository.close")


def admission(identity: DispatchIdentity) -> dict[str, Any]:
    return {
        "schema": "simulator-action-admission/v1",
        "admission_id": f"simulator-admission:{'5' * 64}",
        "action_id": f"simulator-action:{'4' * 64}",
        "task_key": identity.task_key,
        "operation_id": identity.operation_id,
        "payload_sha256": identity.payload_sha256,
        "dispatch_bundle_sha256": f"sha256:{'6' * 64}",
        "incident_id": INCIDENT_ID,
        "incident_version": 7,
        "plan_id": f"response-plan:{'7' * 64}",
        "plan_version": 3,
        "plan_sha256": f"sha256:{'8' * 64}",
        "approval_id": f"plan-decision:{'9' * 64}",
        "approval_sha256": f"sha256:{'a' * 64}",
        "authorization_id": f"dispatch-authorization:{'b' * 64}",
        "authorization_sha256": f"sha256:{'c' * 64}",
        "consumption_id": f"dispatch-consumption:{'d' * 64}",
        "consumption_sha256": f"sha256:{'e' * 64}",
        "executor_actor": {
            "issuer": "https://identity.example.test",
            "subject": "executor@example.test",
            "audience": "colortrace-api",
            "kind": "service",
        },
        "admitted_at": "2026-08-13T22:00:00.000Z",
        "admission_sha256": f"sha256:{'f' * 64}",
    }


class RuntimeService:
    def __init__(self, state: DurableState, *, telemetry_available: bool) -> None:
        self.state = state
        self.telemetry_available = telemetry_available

    def admit(
        self,
        identity: DispatchIdentity,
        *,
        executor: ExecutorAuthorization,
    ) -> dict[str, Any]:
        del executor
        with self.state.lock:
            if identity not in self.state.pending and identity not in self.state.outcomes:
                self.state.pending.append(identity)
        return admission(identity)

    def execute(
        self,
        identity: DispatchIdentity,
        *,
        owner: str,
        observe_terminal: bool = True,
    ) -> dict[str, Any]:
        assert observe_terminal is False
        with self.state.lock:
            existing = self.state.outcomes.get(identity)
            if existing is not None:
                return existing
            assert identity in self.state.pending
            self.state.pending.remove(identity)
            outcome = {
                "schema": "simulator-action-outcome/v1",
                "status": "succeeded",
                "task_key": identity.task_key,
                "operation_id": identity.operation_id,
                "payload_sha256": identity.payload_sha256,
            }
            self.state.outcomes[identity] = outcome
            self.state.telemetry_pending.add(identity)
            self.state.execution_owners.append(owner)
            self.state.lifecycle.append("action.execute")
            self.state.execute_event.set()
            return outcome

    def deliver_pending_telemetry(self, *, limit: int = 100) -> int:
        self.state.lifecycle.append("telemetry.drain")
        if not self.telemetry_available:
            return 0
        with self.state.lock:
            selected = list(self.state.telemetry_pending)[:limit]
            for identity in selected:
                self.state.telemetry_pending.remove(identity)
                self.state.telemetry_delivered.add(identity)
            if selected:
                self.state.telemetry_event.set()
            return len(selected)


class TelemetrySink:
    def __init__(self, state: DurableState) -> None:
        self.state = state

    def shutdown(self) -> None:
        self.state.lifecycle.append("sink.shutdown")


class ResetPublication:
    def __init__(self, state: DurableState) -> None:
        self.state = state

    def restore_authored_scenario(self, *, operation_id: str) -> Mapping[str, Any]:
        assert self.state.pending == []
        self.state.lifecycle.append("publication.reset")
        return {"operation_id": operation_id}


class IncidentService:
    def accept_alert(self, alert: Mapping[str, Any], principal: Principal) -> dict[str, Any]:
        raise AssertionError("not used")

    def list_incidents(self, *, limit: int, cursor: str | None) -> dict[str, Any]:
        return {"schema": "incident-list/v1", "items": [], "next_cursor": None}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")

    def replay(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")

    def workspace(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")


class Verifier:
    def verify(self, token: str) -> Principal:
        assert token == "executor"
        return Principal(
            subject="executor@example.test",
            display_name="executor",
            roles=frozenset({"simulator.executor"}),
            issuer="https://identity.example.test",
            audience="colortrace-api",
            principal_kind="service",
            incident_ids=frozenset({INCIDENT_ID}),
            credential_sha256=f"sha256:{'8' * 64}",
            expires_at=NOW + timedelta(hours=1),
        )


class NeverResolver:
    def resolve(self, kid: str) -> PyJWK:
        raise AssertionError(f"unexpected JWKS resolution for {kid}")


class FactoryStore:
    def accept_alert(
        self,
        alert: Mapping[str, Any],
        *,
        now: str,
        human_actor: Mapping[str, Any] | None = None,
    ) -> Any:
        raise AssertionError("not used")

    def list_incidents(self, *, limit: int, cursor: str | None, now: str) -> dict[str, Any]:
        return {"schema": "incident-list/v1", "items": [], "next_cursor": None}

    def incident_view(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")

    def replay(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")

    def incident_workspace(self, incident_id: str) -> dict[str, Any]:
        raise AssertionError("not used")


def executor_boundary() -> SimulatorExecutorBoundary:
    return SimulatorExecutorBoundary()


def runtime_app(
    state: DurableState,
    *,
    telemetry_available: bool,
) -> tuple[Any, LocalSimulatorRuntime, SimulatorExecutorBoundary]:
    boundary = executor_boundary()
    service = RuntimeService(state, telemetry_available=telemetry_available)
    runtime = LocalSimulatorRuntime(
        repository=RuntimeRepository(state),
        service=service,
        telemetry_sink=TelemetrySink(state),
        poll_seconds=0.01,
        join_timeout_seconds=2,
    )
    coordinator = SimulatorActionCoordinator(
        service=runtime.admission_service,
        executor_boundary=boundary,
        identity_boundary=OIDCTrustBoundary(
            trusted_issuers=frozenset({"https://identity.example.test"}),
            audience="colortrace-api",
        ),
        clock=lambda: NOW,
    )
    app = create_app(
        IncidentService(),
        token_verifier=Verifier(),
        simulator_actions=coordinator,
        lifespan=runtime.lifespan,
    )
    return app, runtime, boundary


def request_body() -> dict[str, str]:
    return {
        "schema": "simulator-action-admission-request/v1",
        "task_key": IDENTITY.task_key,
        "operation_id": IDENTITY.operation_id,
        "payload_sha256": IDENTITY.payload_sha256,
    }


def test_runtime_admission_wakes_serial_exactly_once_execution_and_joins() -> None:
    state = DurableState()
    app, runtime, boundary = runtime_app(state, telemetry_available=True)
    path = f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions"
    with TestClient(app) as client:
        first = client.post(
            path,
            json=request_body(),
            headers={"Authorization": "Bearer executor"},
        )
        assert first.status_code == 202
        assert state.execute_event.wait(timeout=2)
        replay = client.post(
            path,
            json=request_body(),
            headers={"Authorization": "Bearer executor"},
        )
        assert replay.json() == first.json()
        assert state.telemetry_event.wait(timeout=2)
        assert state.outcomes[IDENTITY]["status"] == "succeeded"
        assert len(state.execution_owners) == 1
        assert state.execution_owners[0].startswith("local-api-simulator-")
        assert state.lifecycle.index("action.execute") < max(
            index for index, event in enumerate(state.lifecycle) if event == "telemetry.drain"
        )
        assert runtime.runner.thread_alive
    assert not runtime.runner.thread_alive
    assert state.lifecycle[-3:] == [
        "telemetry.drain",
        "sink.shutdown",
        "repository.close",
    ]

    capability = boundary.bind_verified_service(
        incident_id=INCIDENT_ID,
        actor={
            "issuer": "https://identity.example.test",
            "subject": "executor@example.test",
            "audience": "colortrace-api",
            "kind": "service",
        },
        roles=("simulator.executor",),
        incident_ids=(INCIDENT_ID,),
        identity_verified=True,
    )
    with pytest.raises(SimulatorRepositoryError, match="simulator-runner-unavailable"):
        runtime.admission_service.admit(IDENTITY, executor=capability)


def test_startup_recovers_durable_telemetry_without_reexecution() -> None:
    state = DurableState()
    first_app, first_runtime, _boundary = runtime_app(state, telemetry_available=False)
    path = f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions"
    with TestClient(first_app) as client:
        response = client.post(
            path,
            json=request_body(),
            headers={"Authorization": "Bearer executor"},
        )
        assert response.status_code == 202
        assert state.execute_event.wait(timeout=2)
    assert not first_runtime.runner.thread_alive
    assert state.telemetry_pending == {IDENTITY}
    assert state.telemetry_delivered == set()
    assert len(state.execution_owners) == 1

    second_app, second_runtime, _boundary = runtime_app(state, telemetry_available=True)
    with TestClient(second_app):
        assert state.telemetry_event.wait(timeout=2)
        assert state.telemetry_delivered == {IDENTITY}
        assert state.telemetry_pending == set()
        assert len(state.execution_owners) == 1
    assert not second_runtime.runner.thread_alive


def test_startup_scan_executes_a_durably_queued_action() -> None:
    state = DurableState(pending=[IDENTITY])
    app, runtime, _boundary = runtime_app(state, telemetry_available=True)
    with TestClient(app):
        assert state.execute_event.wait(timeout=2)
        assert state.outcomes[IDENTITY]["status"] == "succeeded"
        assert len(state.execution_owners) == 1
    assert not runtime.runner.thread_alive


def test_authored_reset_drains_queued_actions_before_restoring_publication() -> None:
    state = DurableState(pending=[IDENTITY])
    publication = ResetPublication(state)
    runtime = LocalSimulatorRuntime(
        repository=RuntimeRepository(state),
        service=RuntimeService(state, telemetry_available=True),
        telemetry_sink=TelemetrySink(state),
        recovery_publication=publication,
        join_timeout_seconds=2,
    )

    result = runtime.restore_authored_scenario(operation_id="demo-reset-operation")

    assert result == {"operation_id": "demo-reset-operation"}
    assert state.pending == []
    assert state.outcomes[IDENTITY]["status"] == "succeeded"
    assert state.lifecycle.index("action.execute") < state.lifecycle.index("publication.reset")


class FatalRepository(RuntimeRepository):
    def __init__(self, state: DurableState) -> None:
        super().__init__(state)
        self.called = threading.Event()
        self.allow_exit = threading.Event()

    def pending_action_identities(self, *, limit: int = 100) -> list[DispatchIdentity]:
        del limit
        self.called.set()
        assert self.allow_exit.wait(timeout=2)
        raise SystemExit


def executor_capability(boundary: SimulatorExecutorBoundary) -> ExecutorAuthorization:
    return boundary.bind_verified_service(
        incident_id=INCIDENT_ID,
        actor={
            "issuer": "https://identity.example.test",
            "subject": "executor@example.test",
            "audience": "colortrace-api",
            "kind": "service",
        },
        roles=("simulator.executor",),
        incident_ids=(INCIDENT_ID,),
        identity_verified=True,
    )


def test_dead_worker_rejects_intake_and_close_remains_retryable_after_timeout() -> None:
    dead_state = DurableState()
    fatal_repository = FatalRepository(dead_state)
    dead_runner = SimulatorSerialRunner(
        repository=fatal_repository,
        service=RuntimeService(dead_state, telemetry_available=True),
        poll_seconds=0.01,
        join_timeout_seconds=2,
    )
    dead_runner.start()
    assert fatal_repository.called.wait(timeout=2)
    fatal_repository.allow_exit.set()
    deadline = time.monotonic() + 2
    while dead_runner.thread_alive and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not dead_runner.thread_alive
    with pytest.raises(SimulatorRepositoryError, match="simulator-runner-unavailable"):
        dead_runner.admit(
            IDENTITY,
            executor=executor_capability(executor_boundary()),
        )
    dead_runner.close()

    race_state = DurableState()
    race_repository = FatalRepository(race_state)
    admission_entered = threading.Event()
    admission_release = threading.Event()

    class SlowAdmissionService(RuntimeService):
        def admit(
            self,
            identity: DispatchIdentity,
            *,
            executor: ExecutorAuthorization,
        ) -> dict[str, Any]:
            result = super().admit(identity, executor=executor)
            admission_entered.set()
            assert admission_release.wait(timeout=2)
            return result

    race_runner = SimulatorSerialRunner(
        repository=race_repository,
        service=SlowAdmissionService(race_state, telemetry_available=True),
        poll_seconds=0.01,
        join_timeout_seconds=2,
    )
    race_runner.start()
    assert race_repository.called.wait(timeout=2)
    errors: list[BaseException] = []

    def admit_while_worker_exits() -> None:
        try:
            race_runner.admit(
                IDENTITY,
                executor=executor_capability(executor_boundary()),
            )
        except BaseException as error:
            errors.append(error)

    intake = threading.Thread(target=admit_while_worker_exits)
    intake.start()
    assert admission_entered.wait(timeout=2)
    race_repository.allow_exit.set()
    deadline = time.monotonic() + 2
    while race_runner.thread_alive and time.monotonic() < deadline:
        time.sleep(0.01)
    admission_release.set()
    intake.join(timeout=2)
    assert len(errors) == 1
    assert isinstance(errors[0], SimulatorRepositoryError)
    assert str(errors[0]) == "simulator-runner-unavailable"
    assert race_state.pending == [IDENTITY]
    race_runner.close()

    blocked_state = DurableState(pending=[IDENTITY])
    release = threading.Event()
    entered = threading.Event()
    finished = threading.Event()

    class BlockingService(RuntimeService):
        def execute(
            self,
            identity: DispatchIdentity,
            *,
            owner: str,
            observe_terminal: bool = True,
        ) -> dict[str, Any]:
            entered.set()
            assert release.wait(timeout=2)
            outcome = super().execute(
                identity,
                owner=owner,
                observe_terminal=observe_terminal,
            )
            finished.set()
            return outcome

    blocked_runner = SimulatorSerialRunner(
        repository=RuntimeRepository(blocked_state),
        service=BlockingService(blocked_state, telemetry_available=True),
        poll_seconds=0.01,
        join_timeout_seconds=0.01,
    )
    blocked_runner.start()
    assert entered.wait(timeout=2)
    with pytest.raises(RuntimeError, match="simulator-runner-shutdown-timeout"):
        blocked_runner.close()
    assert blocked_runner.thread_alive
    release.set()
    assert finished.wait(timeout=2)
    deadline = time.monotonic() + 2
    while blocked_runner.thread_alive and time.monotonic() < deadline:
        time.sleep(0.01)
    blocked_runner.close()
    assert not blocked_runner.thread_alive


def runtime_environment(tmp_path: Path) -> dict[str, str]:
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    return {
        "COLORTRACE_DATABASE_PATH": str(tmp_path / "incidents.sqlite3"),
        "COLORTRACE_RESPONSE_PLAN_DATABASE_PATH": str(tmp_path / "plans.sqlite3"),
        "COLORTRACE_RECOVERY_DATABASE_PATH": str(tmp_path / "recovery.sqlite3"),
        "COLORTRACE_OIDC_ISSUER": "https://identity.example.test",
        "COLORTRACE_OIDC_AUDIENCE": "colortrace-api",
        "COLORTRACE_OIDC_JWKS_URI": "https://identity.example.test/jwks",
        "COLORTRACE_SIMULATOR_MODE": "local",
        "COLORTRACE_SIMULATOR_DATABASE_PATH": str(tmp_path / "simulator.sqlite3"),
        "COLORTRACE_SIMULATOR_WORKSPACE_PATH": str(tmp_path / "simulator-workspace"),
        "COLORTRACE_SIMULATOR_FIXTURE_BUNDLE_PATH": str(fixture),
    }


def test_application_factory_requires_complete_explicit_local_configuration(
    tmp_path: Path,
) -> None:
    values = runtime_environment(tmp_path)
    config = ApiRuntimeConfig.from_environment(values)
    assert config.simulator_mode == "local"
    assert config.simulator_database_path == tmp_path / "simulator.sqlite3"

    incomplete = dict(values)
    incomplete.pop("COLORTRACE_SIMULATOR_DATABASE_PATH")
    with pytest.raises(ApiRuntimeConfigurationError):
        ApiRuntimeConfig.from_environment(incomplete)

    disabled_with_path = dict(values)
    disabled_with_path["COLORTRACE_SIMULATOR_MODE"] = "disabled"
    with pytest.raises(ApiRuntimeConfigurationError, match="simulator-configuration-invalid"):
        ApiRuntimeConfig.from_environment(disabled_with_path)

    overlap = dict(values)
    overlap_workspace = tmp_path / "overlap-workspace"
    overlap_workspace.mkdir()
    overlap["COLORTRACE_SIMULATOR_WORKSPACE_PATH"] = str(overlap_workspace)
    overlap["COLORTRACE_SIMULATOR_DATABASE_PATH"] = str(overlap_workspace / "simulator.sqlite3")
    with pytest.raises(ApiRuntimeConfigurationError, match="simulator-path-overlap"):
        create_application(
            overlap,
            store_factory=lambda _path: FactoryStore(),
            resolver_factory=lambda _uri: NeverResolver(),
            local_simulator_factory=lambda **_options: pytest.fail(
                "overlapping paths must fail before construction"
            ),
            clock=lambda: NOW,
        )

    state = DurableState()
    configured_runtime = LocalSimulatorRuntime(
        repository=RuntimeRepository(state),
        service=RuntimeService(state, telemetry_available=True),
        telemetry_sink=TelemetrySink(state),
        poll_seconds=0.01,
        join_timeout_seconds=2,
    )
    observed: dict[str, Any] = {}

    def local_factory(**options: Any) -> LocalSimulatorRuntime:
        observed.update(options)
        return configured_runtime

    app = create_application(
        values,
        store_factory=lambda _path: FactoryStore(),
        resolver_factory=lambda _uri: NeverResolver(),
        local_simulator_factory=local_factory,
        clock=lambda: NOW,
    )
    assert app.state.local_simulator_runtime is configured_runtime
    assert observed["database_path"] == tmp_path / "simulator.sqlite3"
    assert observed["workspace_path"] == tmp_path / "simulator-workspace"
    assert observed["fixture_bundle_path"] == tmp_path / "fixture"
    assert observed["otlp_endpoint"] is None

    disabled = {key: value for key, value in values.items() if key.startswith("COLORTRACE_OIDC")}
    disabled.update(
        {
            "COLORTRACE_DATABASE_PATH": str(tmp_path / "disabled-incidents.sqlite3"),
            "COLORTRACE_RESPONSE_PLAN_DATABASE_PATH": str(tmp_path / "disabled-plans.sqlite3"),
            "COLORTRACE_RECOVERY_DATABASE_PATH": str(tmp_path / "disabled-recovery.sqlite3"),
        }
    )
    default_app = create_application(
        disabled,
        store_factory=lambda _path: FactoryStore(),
        resolver_factory=lambda _uri: NeverResolver(),
        local_simulator_factory=lambda **_options: pytest.fail("simulator must stay disabled"),
        clock=lambda: NOW,
    )
    assert default_app.state.local_simulator_runtime is None

    disabled_client = TestClient(create_app(IncidentService(), token_verifier=Verifier()))
    disabled_response = disabled_client.post(
        f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions",
        json=request_body(),
        headers={"Authorization": "Bearer executor"},
    )
    assert disabled_response.status_code == 404
    assert disabled_response.json() == {"code": "simulator-actions-unavailable"}


class StepClock:
    def __init__(self, value: datetime) -> None:
        self.value = value
        self.lock = threading.Lock()

    def __call__(self) -> datetime:
        with self.lock:
            selected = self.value
            self.value += timedelta(seconds=1)
            return selected


class CanonicalIncidentService(IncidentService):
    def __init__(
        self,
        *,
        affected: list[dict[str, str]],
        safe: list[dict[str, str]],
        causal_resource_sha256: str,
    ) -> None:
        self.affected = affected
        self.safe = safe
        self.causal_resource_sha256 = causal_resource_sha256

    def replay(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == INCIDENT_ID
        return {
            "schema": "incident-replay/v1",
            "incident": {
                "incident_id": incident_id,
                "status": "resolved",
                "version": 7,
            },
            "packet": {
                "packet_id": f"response-packet:{'6' * 64}",
                "incident_id": incident_id,
                "status": "resolved",
                "derivation_sha256": f"sha256:{'6' * 64}",
                "candidate_plan": {"targets": self.affected},
                "scope": {
                    "state": "resolved",
                    "policy": "single-causal-resource-scope/v1",
                    "affected": self.affected,
                    "safe": self.safe,
                    "unknown": [],
                    "reason_codes": [],
                },
                "unresolved_items": [],
            },
            "validator_results": [
                {"scope": {"causal_resource_sha256": self.causal_resource_sha256}}
            ],
        }


class FullVerifier:
    def verify(self, token: str) -> Principal:
        role, kind = {
            "editor": ("response-plan.editor", "human"),
            "approver": ("response-plan.approver", "human"),
            "dispatcher": ("response-plan.dispatcher", "service"),
            "executor": ("simulator.executor", "service"),
        }[token]
        return Principal(
            subject=f"{token}@example.test",
            display_name=token,
            roles=frozenset({role}),
            issuer="https://identity.example.test",
            audience="colortrace-api",
            principal_kind=kind,  # type: ignore[arg-type]
            incident_ids=frozenset({INCIDENT_ID}),
            credential_sha256=f"sha256:{'8' * 64}",
            expires_at=NOW + timedelta(days=1),
        )


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_real_plan_source_service_and_local_publication_compose_through_http(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "canonical-fixture"
    build_scenario(
        fixture,
        oracle_root=tmp_path / "private-oracle",
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    clock = StepClock(NOW)
    publication = LocalPublicationPort.bootstrap(
        root=tmp_path / "publication-workspace",
        fixture_bundle=fixture,
        clock=clock,
    )
    plan_inputs = publication.canonical_plan_inputs()
    targets = list(plan_inputs["targets"])
    exclusions = list(plan_inputs["exclusions"])
    affected = [
        {"kind": str(target["kind"]), "id": str(target["id"])}
        for target in targets
        if target["kind"] != "color-resource"
    ]
    safe = [{"kind": str(target["kind"]), "id": str(target["id"])} for target in exclusions]
    causal = next(str(target["id"]) for target in targets if target["kind"] == "color-resource")
    incidents = CanonicalIncidentService(
        affected=affected,
        safe=safe,
        causal_resource_sha256=causal.removeprefix("sha256:"),
    )
    identity_boundary = OIDCTrustBoundary(
        trusted_issuers=frozenset({"https://identity.example.test"}),
        audience="colortrace-api",
    )
    plan_authority = CanonicalAuthorityBoundary()
    plans = ResponsePlanCoordinator(
        incident_reader=incidents,
        repository=SQLiteResponsePlanRepository(
            tmp_path / "response-plans.sqlite3",
            authority_boundary=plan_authority,
        ),
        authority_boundary=plan_authority,
        identity_boundary=identity_boundary,
        clock=clock,
    )
    simulator_repository = SQLiteSimulatorRepository(tmp_path / "simulator.sqlite3")
    executor = SimulatorExecutorBoundary()
    telemetry = MemoryActionTelemetrySink()

    def observe(outcome: Mapping[str, Any]) -> object:
        return emit_action_outcome(outcome, telemetry, clock=clock)

    simulator = SimulatorActionService(
        repository=simulator_repository,
        dispatch_source=plans,
        authority_boundary=SimulatorAuthorityBoundary(),
        executor_boundary=executor,
        publication=publication,
        clock=clock,
        terminal_observer=observe,
    )
    local_runtime = LocalSimulatorRuntime(
        repository=simulator_repository,
        service=simulator,
        telemetry_sink=telemetry,
        poll_seconds=0.01,
        join_timeout_seconds=30,
    )
    simulator_actions = SimulatorActionCoordinator(
        service=local_runtime.admission_service,
        executor_boundary=executor,
        identity_boundary=identity_boundary,
        clock=clock,
    )
    app = create_app(
        incidents,
        token_verifier=FullVerifier(),
        response_plans=plans,
        simulator_actions=simulator_actions,
        lifespan=local_runtime.lifespan,
    )
    with TestClient(app) as client:
        draft = client.get(f"/v1/incidents/{INCIDENT_ID}/response-plan/draft").json()
        assert draft["targets"] == targets
        assert draft["exclusions"] == exclusions
        plan = client.post(
            f"/v1/incidents/{INCIDENT_ID}/response-plan",
            json={
                "expected_incident_version": 7,
                "expected_plan_version": 0,
                "response_packet_id": draft["response_packet_id"],
                "response_packet_sha256": draft["response_packet_sha256"],
                "deterministic_scope_sha256": draft["deterministic_scope_sha256"],
                "targets": draft["targets"],
                "exclusions": draft["exclusions"],
                "commands": plan_inputs["commands"],
                "unresolved_acknowledged": False,
                "idempotency_key": "runtime-create-plan",
            },
            headers=auth("editor"),
        ).json()
        approval = client.post(
            f"/v1/incidents/{INCIDENT_ID}/response-plan/approve",
            json={
                "expected_incident_version": 7,
                "expected_plan_version": 1,
                "expected_plan_sha256": plan["plan_sha256"],
                "idempotency_key": "runtime-approve-plan",
            },
            headers=auth("approver"),
        )
        assert approval.status_code == 200
        authorization = client.post(
            f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-authorizations",
            json={
                "expected_incident_version": 7,
                "expected_plan_version": 1,
                "expected_plan_sha256": plan["plan_sha256"],
                "idempotency_key": "runtime-authorize-plan",
            },
            headers=auth("dispatcher"),
        ).json()
        consumption = client.post(
            f"/v1/incidents/{INCIDENT_ID}/response-plan/dispatch-consumptions",
            json={
                "authorization_id": authorization["authorization_id"],
                "expected_incident_version": 7,
                "expected_plan_version": 1,
                "expected_plan_sha256": plan["plan_sha256"],
                "expected_task_key": authorization["task_key"],
                "expected_payload_sha256": authorization["payload_sha256"],
                "idempotency_key": "runtime-consume-plan",
            },
            headers=auth("dispatcher"),
        )
        assert consumption.status_code == 200
        identity = DispatchIdentity(
            task_key=authorization["task_key"],
            operation_id=authorization["operation_id"],
            payload_sha256=authorization["payload_sha256"],
        )
        body = {
            "schema": "simulator-action-admission-request/v1",
            "task_key": identity.task_key,
            "operation_id": identity.operation_id,
            "payload_sha256": identity.payload_sha256,
        }
        admitted = client.post(
            f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions",
            json=body,
            headers=auth("executor"),
        )
        assert admitted.status_code == 202
        deadline = time.monotonic() + 30
        outcome: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            outcome = simulator_repository.outcome(identity)
            if outcome is not None and simulator_repository.telemetry_delivered(identity):
                break
            time.sleep(0.02)
        assert outcome is not None
        assert outcome["status"] == "succeeded", outcome["reason_codes"]
        assert outcome["candidate_publication_generation"] == 2
        assert len(outcome["command_outcomes"]) == 5
        assert len(outcome["exclusions"]) == 3
        assert simulator_repository.telemetry_delivered(identity)
        replay = client.post(
            f"/internal/v1/incidents/{INCIDENT_ID}/simulator-actions",
            json=body,
            headers=auth("executor"),
        )
        assert replay.json() == admitted.json()
        assert [
            event["event_type"] for event in simulator_repository.audit_history(identity)
        ].count("action.succeeded") == 1
        assert len(telemetry.events) == 21
