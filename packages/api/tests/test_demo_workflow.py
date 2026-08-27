from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from colortrace_api.demo_facade import INVESTIGATION_PROOF_SCHEMA, DemoFacadeError
from colortrace_api.demo_workflow import CanonicalDemoWorkflow, GrafanaMcpAlertProbe
from colortrace_recovery import CHECK_NAMES, RecoveryError, canonical_json_bytes
from colortrace_response_plans import ResponsePlanError
from colortrace_vertical_slice import SliceContractError


def _digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonical_json_bytes(value)).hexdigest()}"


def _noop_sleep(_seconds: float) -> None:
    pass


def _png(label: str) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + label.encode("ascii")


def _target(kind: str, identifier: str) -> dict[str, str]:
    return {
        "schema": "simulator-target/v1",
        "namespace": "colortrace-simulator",
        "kind": kind,
        "id": identifier,
    }


def _plan_inputs() -> dict[str, Any]:
    config = f"sha256:{'2' * 64}"
    targets = [
        _target("color-resource", f"sha256:{'3' * 64}"),
        *(_target("frame", f"frame-{index}") for index in range(3)),
        _target("derivative", "derivative-1"),
    ]
    exclusions = [_target("frame", f"safe-{index}") for index in range(3)]
    envelope = {
        "schema": "simulator-action-envelope/v1",
        "fixture_id": "ct-shadowed-lut-v1:canonical",
        "fixture_manifest_sha256": f"sha256:{'0' * 64}",
        "fixture_generation": 1,
        "source_batch_id": "fixture-run-canonical",
        "source_batch_sha256": f"sha256:{'1' * 64}",
        "runtime_manifest_sha256": f"sha256:{'2' * 64}",
        "runtime_generation": 1,
        "expected_publication_pointer_sha256": f"sha256:{'3' * 64}",
        "expected_publication_generation": 1,
        "expected_resource_sha256": f"sha256:{'3' * 64}",
        "replacement_resource_logical_path": "luts/show_look.cube",
        "replacement_resource_sha256": f"sha256:{'4' * 64}",
        "declared_resource_manifest_sha256": f"sha256:{'5' * 64}",
        "ocio_version": "2.5.2",
        "preservation_manifest_sha256": f"sha256:{'6' * 64}",
        "safe_complement_sha256": f"sha256:{'5' * 64}",
        "lineage_manifest_sha256": f"sha256:{'8' * 64}",
        "lineage_generation": 1,
    }
    commands: list[dict[str, Any]] = [
        {
            "schema": "simulator-quarantine-command/v1",
            "command_id": "quarantine-resource",
            "namespace": "colortrace-simulator",
            "target": targets[0],
            "expected_resource_sha256": envelope["expected_resource_sha256"],
            "mode": "quarantine-and-install-approved-replacement",
            "action_envelope": envelope,
        }
    ]
    for index, target in enumerate(targets[1:4], start=1):
        commands.append(
            {
                "schema": "simulator-targeted-rerender-command/v1",
                "command_id": f"rerender-frame-{index}",
                "namespace": "colortrace-simulator",
                "target": target,
                "job_id": f"job-b-0{index}",
                "transform_id": "look/main/v1",
                "source_id": f"chart-0{index}",
                "source_manifest_sha256": f"sha256:{index:064x}",
                "source_png_sha256": f"sha256:{index + 3:064x}",
                "expected_config_sha256": config,
                "expected_output_sha256": f"sha256:{index + 6:064x}",
                "expected_display_sha256": f"sha256:{index + 9:064x}",
                "lineage_parent_artifact_id": f"source-chart-0{index}",
                "action_envelope": envelope,
            }
        )
    commands.append(
        {
            "schema": "simulator-targeted-rerender-command/v1",
            "command_id": "rerender-derivative",
            "namespace": "colortrace-simulator",
            "target": targets[4],
            "job_id": "job-b-02",
            "transform_id": "look/main/v1",
            "source_id": "chart-02",
            "source_manifest_sha256": f"sha256:{'6' * 64}",
            "source_png_sha256": f"sha256:{'7' * 64}",
            "expected_config_sha256": config,
            "expected_derivative_sha256": f"sha256:{'8' * 64}",
            "expected_derivative_display_sha256": f"sha256:{'9' * 64}",
            "lineage_parent_artifact_id": "output-job-b-02",
            "action_envelope": envelope,
        }
    )
    return {"targets": targets, "exclusions": exclusions, "commands": commands}


def _packet(incident_id: str) -> dict[str, Any]:
    return {
        "packet_id": f"response-packet:{'1' * 64}",
        "derivation_sha256": f"sha256:{'1' * 64}",
        "status": "resolved",
        "candidate_plan": {"targets": []},
        "invocation_records": [
            {
                "invocation_id": f"model-invocation:{digit * 64}",
                "turn_kind": turn,
                "model": "gemini-3.5-flash",
                "framework": "google-adk",
                "result_class": "accepted",
                "tool_inventory_version": f"sha256:{'3' * 64}",
                "output_sha256": f"sha256:{digit * 64}",
                "trace_id": digit * 32,
            }
            for digit, turn in (("4", "evidence-selection"), ("5", "response-drafting"))
        ],
        "deterministic_results": [
            {
                "result_id": f"validation-result:{'6' * 64}",
                "validator": "colortrace-validator",
                "validator_version": "1.0.0",
                "status": "resolved",
                "derivation_sha256": "6" * 64,
            }
        ],
        "claims": [
            {
                "claim_id": f"claim:{'7' * 64}",
                "claim_type": "causal-resource",
                "subject": {"kind": "resource-sha256", "value": "3" * 64},
                "state": "confirmed",
                "reason_codes": ["causal-resource-confirmed"],
                "evidence_ids": [f"sha256:{'a' * 64}"],
                "deterministic_result_evidence_id": f"deterministic-result:{'7' * 64}",
                "source_validator_result_id": f"validation-result:{'6' * 64}",
            },
            {
                "claim_id": f"claim:{'8' * 64}",
                "claim_type": "nominal-config",
                "subject": {"kind": "config-sha256", "value": "2" * 64},
                "state": "rejected",
                "reason_codes": ["nominal-config-authoritatively-rejected"],
                "evidence_ids": [f"sha256:{'b' * 64}"],
                "deterministic_result_evidence_id": f"deterministic-result:{'8' * 64}",
                "source_validator_result_id": f"validation-result:{'6' * 64}",
            },
        ],
        "scope": {
            "state": "resolved",
            "affected": [{"kind": "frame", "id": f"frame-{index}"} for index in range(3)]
            + [{"kind": "derivative", "id": "derivative-1"}],
            "safe": [{"kind": "frame", "id": f"safe-{index}"} for index in range(3)],
            "unknown": [],
        },
        "budget_use": {
            "elapsed_ms": 100,
            "model_turns": 2,
            "input_tokens": 200,
            "output_tokens": 30,
            "mcp_attempts": 4,
            "validator_calls": 6,
        },
        "unresolved_items": [],
        "incident_id": incident_id,
    }


def _evidence(incident_id: str) -> list[dict[str, Any]]:
    query_tools = (
        ("alert.rule", "alerting_manage_rules"),
        ("log.correlated-events", "query_loki_logs"),
        ("metric.correlated-observations", "query_prometheus"),
        ("trace.by-id", "tempo_get-trace"),
    )
    return [
        {
            "evidence_id": f"sha256:{digit * 64}",
            "incident_id": incident_id,
            "source": {"tool": tool, "inventory_version": f"sha256:{'3' * 64}"},
            "observation": {"query_key": query},
            "timing": {"freshness": "unresolved"},
            "content_sha256": f"sha256:{digit * 64}",
            "display_excerpt": f"Current {query} evidence.",
        }
        for digit, (query, tool) in zip("abcd", query_tools, strict=True)
    ]


class FakeIncidents:
    def __init__(self, incident_id: str, *, state: str) -> None:
        self.incident_id = incident_id
        self.state = state
        self.alerts: list[Mapping[str, Any]] = []
        self.packet = _packet(incident_id)

    def replay(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == self.incident_id
        if self.state == "missing":
            raise SliceContractError("incident-not-found")
        if self.state == "incomplete":
            raise SliceContractError("incident-incomplete")
        return {
            "packet": self.packet,
            "task": {"task_id": "task-demo"},
            "evidence": _evidence(incident_id),
        }

    def accept_alert(self, alert: Mapping[str, Any]) -> dict[str, Any]:
        self.alerts.append(alert)
        self.state = "incomplete"
        return {"task_id": "task-demo"}

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == self.incident_id
        return {"task": {"task_id": "task-demo"}}


class FakeInvestigation:
    def __init__(self, incidents: FakeIncidents) -> None:
        self.incidents = incidents
        self.calls: list[tuple[str, Path]] = []

    async def execute(self, task_id: str, *, bundle_root: Path) -> dict[str, Any]:
        self.calls.append((task_id, bundle_root))
        self.incidents.state = "ready"
        return self.incidents.packet


class FakeAlertSource:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def emit(self, *, run_id: str, incident_id: str) -> Mapping[str, Any]:
        self.calls.append((run_id, incident_id))
        return {"schema": "alert-intake/v1", "incident_id": incident_id}


class FakePlans:
    def __init__(self) -> None:
        self.plan: dict[str, Any] | None = None
        self.create_bodies: list[Mapping[str, Any]] = []

    def review(self, incident_id: str) -> dict[str, Any]:
        del incident_id
        if self.plan is None:
            raise ResponsePlanError("plan-not-found")
        return {"state": "pending", "plan": self.plan}

    def draft(self, incident_id: str) -> dict[str, Any]:
        inputs = _plan_inputs()
        return {
            "incident_id": incident_id,
            "incident_version": 7,
            "response_packet_id": f"response-packet:{'1' * 64}",
            "response_packet_sha256": f"sha256:{'1' * 64}",
            "deterministic_scope_sha256": f"sha256:{'2' * 64}",
            "targets": inputs["targets"],
            "exclusions": inputs["exclusions"],
        }

    def create(
        self,
        principal: object,
        incident_id: str,
        body: Mapping[str, Any],
    ) -> dict[str, Any]:
        del principal
        self.create_bodies.append(body)
        self.plan = {
            "incident_id": incident_id,
            "incident_version": 7,
            "version": 1,
            "plan_sha256": f"sha256:{'7' * 64}",
            "targets": list(body["targets"]),
            "exclusions": list(body["exclusions"]),
            "commands": list(body["commands"]),
        }
        return self.plan


class FakePublication:
    def __init__(self, root: Path) -> None:
        self.root = root

    def canonical_plan_inputs(self) -> dict[str, Any]:
        return _plan_inputs()


class FakeRuntime:
    def __init__(self, publication: FakePublication) -> None:
        self.recovery_publication = publication


class ExecutingPlans:
    def __init__(self, plan: Mapping[str, Any]) -> None:
        self.plan = dict(plan)
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def review(self, incident_id: str) -> dict[str, Any]:
        assert incident_id == self.plan["incident_id"]
        return {"state": "pending", "plan": self.plan}

    def approve(
        self, _principal: object, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        assert incident_id == self.plan["incident_id"]
        self.calls.append(("approve", body))
        return {"state": "approved"}

    def authorize_dispatch(
        self, _principal: object, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        assert incident_id == self.plan["incident_id"]
        self.calls.append(("authorize", body))
        return {
            "authorization_id": f"dispatch-authorization:{'8' * 64}",
            "task_key": f"dispatch-task:{'9' * 64}",
            "operation_id": f"dispatch-operation:{'a' * 64}",
            "payload_sha256": f"sha256:{'b' * 64}",
        }

    def consume_dispatch(
        self, _principal: object, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        assert incident_id == self.plan["incident_id"]
        self.calls.append(("consume", body))
        return {"state": "consumed"}


class FakeSimulatorActions:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def admit(
        self, _principal: object, incident_id: str, body: Mapping[str, Any]
    ) -> dict[str, Any]:
        self.calls.append((incident_id, body))
        return {"state": "admitted"}


class FakeSimulatorService:
    def __init__(self, outcome: Mapping[str, Any]) -> None:
        self.outcome = dict(outcome)
        self.execute_calls: list[tuple[Any, str]] = []
        self.delivery_calls = 0

    def execute(self, identity: Any, *, owner: str) -> dict[str, Any]:
        self.execute_calls.append((identity, owner))
        return self.outcome

    def deliver_pending_telemetry(self, *, limit: int) -> int:
        assert limit == 100
        self.delivery_calls += 1
        return 1


class FakeOutcomeRepository:
    def __init__(self, outcome: Mapping[str, Any] | None = None) -> None:
        self.outcome = outcome
        self.calls: list[str] = []

    def outcome_for_incident(self, incident_id: str) -> Mapping[str, Any] | None:
        self.calls.append(incident_id)
        return self.outcome


class ExecutingRuntime:
    def __init__(
        self,
        publication: FakePublication,
        service: FakeSimulatorService,
        repository: FakeOutcomeRepository,
    ) -> None:
        self.recovery_publication = publication
        self.service = service
        self.repository = repository

    def execute(self, identity: Any, *, owner: str) -> dict[str, Any]:
        return self.service.execute(identity, owner=owner)


def _recovery_packet() -> dict[str, Any]:
    return {
        "status": "recovery_verified",
        "workflow_id": f"recovery-workflow:{'c' * 64}",
        "workflow_version": 2,
        "packet_id": f"recovery-packet:{'d' * 64}",
        "packet_sha256": f"sha256:{'d' * 64}",
        "evidence_request_sha256": f"sha256:{'e' * 64}",
        "check_results": [
            {
                "check": check,
                "state": "passed",
                "result_sha256": f"sha256:{index:064x}",
            }
            for index, check in enumerate(CHECK_NAMES, start=1)
        ],
    }


class FakeWorkflowRecovery:
    def __init__(self) -> None:
        self.ready = False
        self.error_code = "recovery-workflow-not-found"
        self.packet = _recovery_packet()

    def review(self, _incident_id: str) -> dict[str, Any]:
        if not self.ready:
            raise RecoveryError(self.error_code)
        return {
            "packet": self.packet,
            "evidence_records": [{"evidence_id": index} for index in range(21)],
        }


class FakeRecoveryRunner:
    def __init__(self, recovery: FakeWorkflowRecovery) -> None:
        self.recovery = recovery
        self.calls: list[Mapping[str, Any]] = []

    def verify(
        self,
        _principal: object,
        incident_id: str,
        *,
        expected_incident_version: int,
        expected_outcome_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "incident_id": incident_id,
                "expected_incident_version": expected_incident_version,
                "expected_outcome_sha256": expected_outcome_sha256,
                "idempotency_key": idempotency_key,
            }
        )
        self.recovery.ready = True
        return self.recovery.packet


class FakeRecoveryIdentity:
    def bind_verified_claims(self, **claims: Any) -> object:
        assert claims["credential_verified"] is True
        return object()


def _fixture(root: Path) -> None:
    files = {
        "references/display/reference-chart-02-look.png": _png("expected"),
        "runtime/display/output-job-b-02.png": _png("observed"),
        "reports/diffs/job-b-02.png": _png("diff"),
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for job_id, worker_id, lut in (
        ("job-a-02", "A", "1" * 64),
        ("job-b-02", "B", "2" * 64),
    ):
        resource_path = f"runtime/manifests/resources/resource-{job_id}.json"
        job_path = root / "runtime" / "manifests" / "jobs" / f"{job_id}.json"
        job_path.parent.mkdir(parents=True, exist_ok=True)
        job_path.write_text(
            json.dumps(
                {
                    "schema": "fixture-job/v1",
                    "job_id": job_id,
                    "worker_id": worker_id,
                    "source_id": "chart-02",
                    "transform_id": "look/main/v1",
                    "process_outcome": "success",
                    "exit_code": 0,
                    "nominal_config_sha256": "2" * 64,
                    "resource_manifest": resource_path,
                }
            ),
            encoding="utf-8",
        )
        resource = root / resource_path
        resource.parent.mkdir(parents=True, exist_ok=True)
        resource.write_text(
            json.dumps(
                {
                    "schema": "resolved-resource-manifest/v1",
                    "job_id": job_id,
                    "worker_id": worker_id,
                    "transform_id": "look/main/v1",
                    "nominal_config_sha256": "2" * 64,
                    "captured_before_and_after_processing": True,
                    "inputs_unchanged": True,
                    "ordered_resources": [
                        {
                            "logical_path": "luts/show_look.cube",
                            "sha256": lut,
                            "read_only": True,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )


def _workflow(
    tmp_path: Path,
    *,
    state: str,
) -> tuple[CanonicalDemoWorkflow, FakeIncidents, FakeInvestigation, FakeAlertSource]:
    fixture = tmp_path / "fixture"
    visual_root = tmp_path / "visuals"
    publication_root = tmp_path / "publication"
    _fixture(fixture)
    visual_root.mkdir(mode=0o700)
    publication_root.mkdir()
    incident_id = "incident-demo-11111111111111111111111111111111"
    incidents = FakeIncidents(incident_id, state=state)
    investigation = FakeInvestigation(incidents)
    alert_source = FakeAlertSource()
    workflow = CanonicalDemoWorkflow(
        incidents=cast(Any, incidents),
        investigation=cast(Any, investigation),
        response_plans=cast(Any, FakePlans()),
        simulator_actions=cast(Any, object()),
        simulator_runtime=cast(Any, FakeRuntime(FakePublication(publication_root))),
        recovery=cast(Any, object()),
        recovery_runner=cast(Any, object()),
        recovery_identity=cast(Any, object()),
        alert_source=alert_source,
        fixture_bundle=fixture,
        visual_root=visual_root,
        issuer="https://identity.example.test",
        audience="colortrace-api",
    )
    return workflow, incidents, investigation, alert_source


def _preparation_request() -> dict[str, Any]:
    return {
        "run_id": "demo-run-11111111111111111111111111111111",
        "incident_id": "incident-demo-11111111111111111111111111111111",
        "idempotency_key": "prepare:demo-run-11111111111111111111111111111111",
    }


def _alert_intake(now: datetime) -> dict[str, Any]:
    instant = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {
        "schema": "alert-intake/v1",
        "incident_id": "incident-demo-11111111111111111111111111111111",
        "alert_id": "alert-demo-run-11111111111111111111111111111111",
        "alert_started_at": instant,
        "retrieved_at": instant,
        "measured_clock_skew_seconds": 0,
        "binding": {
            "prometheus_datasource_uid": "prometheus",
            "loki_datasource_uid": "loki",
            "tempo_datasource_uid": "tempo",
            "alert_rule_uid": "ct-declared-reference-divergence-v1",
        },
        "correlation_keys": {
            "fixture_id": "ct-shadowed-lut-v1",
            "run_id": "demo-run-11111111111111111111111111111111",
            "job_id": "job-b-02",
            "worker_id": "worker-b",
            "artifact_id": "output-job-b-02",
            "trace_id": "1" * 32,
            "config_sha256": "2" * 64,
            "transform_id": "look",
        },
        "predecessor_event_sha256": None,
    }


class FakeAlertEvidence:
    def __init__(self, alerts: list[list[Mapping[str, Any]]]) -> None:
        self.alerts = alerts
        self.calls: list[Any] = []

    async def collect(self, batch: Any) -> Any:
        self.calls.append(batch)
        selected = self.alerts.pop(0) if self.alerts else []
        return SimpleNamespace(
            envelopes=(
                {
                    "collection": {"outcome": "collected"},
                    "content": {"alerts": selected},
                },
            )
        )


def test_alert_probe_waits_for_exact_firing_grafana_instance() -> None:
    now = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
    intake = _alert_intake(now)
    correlation = cast(dict[str, str], intake["correlation_keys"])
    evidence = FakeAlertEvidence(
        [
            [],
            [
                {
                    "labels": {**correlation, "grafana_folder": "ColorTrace"},
                    "annotations": {},
                    "state": "firing",
                    "activeAt": intake["alert_started_at"],
                    "value": "1",
                }
            ],
        ]
    )
    elapsed = 0.0

    def monotonic() -> float:
        return elapsed

    def clock() -> datetime:
        return now + timedelta(seconds=elapsed)

    def sleep(seconds: float) -> None:
        nonlocal elapsed
        elapsed += seconds

    probe = GrafanaMcpAlertProbe(
        evidence=cast(Any, evidence),
        clock=clock,
        monotonic=monotonic,
        sleeper=sleep,
        timeout_seconds=5,
        poll_seconds=1,
    )

    accepted = probe.wait_for_firing(intake)

    assert accepted["alert_started_at"] == intake["alert_started_at"]
    assert accepted["retrieved_at"] == "2026-08-23T12:00:01.000Z"
    assert len(evidence.calls) == 2
    assert all(batch.query_keys == ("alert.rule",) for batch in evidence.calls)


def test_alert_probe_stamps_retrieval_after_new_firing_instance() -> None:
    now = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
    intake = _alert_intake(now)
    correlation = cast(dict[str, str], intake["correlation_keys"])
    elapsed = 0.0

    class BoundaryEvidence:
        async def collect(self, batch: Any) -> Any:
            nonlocal elapsed
            elapsed = 1.0
            return SimpleNamespace(
                envelopes=(
                    {
                        "collection": {"outcome": "collected"},
                        "content": {
                            "alerts": [
                                {
                                    "labels": correlation,
                                    "annotations": {},
                                    "state": "firing",
                                    "activeAt": "2026-08-23T12:00:00.500Z",
                                    "value": "1",
                                }
                            ]
                        },
                    },
                )
            )

    accepted = GrafanaMcpAlertProbe(
        evidence=cast(Any, BoundaryEvidence()),
        clock=lambda: now + timedelta(seconds=elapsed),
    ).wait_for_firing(intake)

    assert accepted["alert_started_at"] == "2026-08-23T12:00:00.500Z"
    assert accepted["retrieved_at"] == "2026-08-23T12:00:01.000Z"


def test_alert_probe_fails_closed_when_no_matching_instance_fires() -> None:
    now = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)
    intake = _alert_intake(now)
    evidence = FakeAlertEvidence([[], []])
    elapsed = 0.0

    def sleep(seconds: float) -> None:
        nonlocal elapsed
        elapsed += seconds

    probe = GrafanaMcpAlertProbe(
        evidence=cast(Any, evidence),
        clock=lambda: now + timedelta(seconds=elapsed),
        monotonic=lambda: elapsed,
        sleeper=sleep,
        timeout_seconds=1,
        poll_seconds=1,
    )

    try:
        probe.wait_for_firing(intake)
    except DemoFacadeError as error:
        assert error.code == "demo-alert-timeout"
    else:  # pragma: no cover - explicit fail-closed assertion
        raise AssertionError("a missing Grafana alert must not start investigation")


def test_prepare_emits_once_and_projects_bounded_live_proof(tmp_path: Path) -> None:
    workflow, incidents, investigation, alerts = _workflow(tmp_path, state="missing")

    result = workflow.prepare(_preparation_request())

    assert alerts.calls == [
        (
            "demo-run-11111111111111111111111111111111",
            "incident-demo-11111111111111111111111111111111",
        )
    ]
    assert len(incidents.alerts) == 1
    assert investigation.calls == [("task-demo", tmp_path / "fixture")]
    assert result["investigation"]["schema"] == INVESTIGATION_PROOF_SCHEMA
    assert result["investigation"]["scope"] == {
        "state": "resolved",
        "affected_count": 4,
        "safe_count": 3,
        "unknown_count": 0,
    }
    assert {item["freshness"] for item in result["investigation"]["evidence"]} == {"current"}
    assert result["target_sha256"] == _digest(_plan_inputs()["targets"])
    assert {item["kind"] for item in result["visuals"]} == {
        "expected",
        "observed",
        "diff",
    }


def test_prepare_reconciliation_resumes_durable_task_without_reemitting(tmp_path: Path) -> None:
    workflow, _incidents, investigation, alerts = _workflow(tmp_path, state="incomplete")
    operation_request = _preparation_request()

    result = workflow.reconcile(
        {
            "operation": "prepare",
            "operation_request": operation_request,
        }
    )

    assert result is not None
    assert alerts.calls == []
    assert investigation.calls == [("task-demo", tmp_path / "fixture")]


def test_recovered_visual_resolves_the_sealed_publication_directory(tmp_path: Path) -> None:
    workflow, _incidents, _investigation, _alerts = _workflow(tmp_path, state="ready")
    publication = cast(Any, workflow)._simulator_runtime.recovery_publication
    publication_id = f"publication:{'a' * 64}"
    publication_root = publication.root / "publications" / f"pub-{'a' * 64}"
    (publication.root / "state").mkdir()
    (publication_root / "manifests").mkdir(parents=True)
    (publication_root / "runtime" / "frames" / "f0002").mkdir(parents=True)
    (publication.root / "state" / "active.json").write_text(
        json.dumps({"publication_id": publication_id}),
        encoding="utf-8",
    )
    (publication_root / "manifests" / "runtime.json").write_text(
        json.dumps(
            {
                "frames": [
                    {
                        "job_id": "job-b-02",
                        "display_path": "runtime/frames/f0002/display.png",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    recovered = _png("recovered")
    (publication_root / "runtime" / "frames" / "f0002" / "display.png").write_bytes(recovered)

    descriptor = cast(Any, workflow)._recovered_visual("demo-run-11111111111111111111111111111111")

    assert descriptor["kind"] == "recovered"
    assert descriptor["sha256"] == f"sha256:{hashlib.sha256(recovered).hexdigest()}"


def _write_recovered_publication(publication: FakePublication) -> None:
    publication_id = f"publication:{'a' * 64}"
    selected = publication.root / "publications" / f"pub-{'a' * 64}"
    (publication.root / "state").mkdir()
    (selected / "manifests").mkdir(parents=True)
    (selected / "runtime" / "frames" / "f0002").mkdir(parents=True)
    (publication.root / "state" / "active.json").write_text(
        json.dumps({"publication_id": publication_id}),
        encoding="utf-8",
    )
    (selected / "manifests" / "runtime.json").write_text(
        json.dumps(
            {
                "frames": [
                    {
                        "job_id": "job-b-02",
                        "display_path": "runtime/frames/f0002/display.png",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (selected / "runtime" / "frames" / "f0002" / "display.png").write_bytes(_png("recovered"))


def _successful_outcome() -> dict[str, Any]:
    return {
        "action_id": f"simulator-action:{'1' * 64}",
        "status": "succeeded",
        "outcome_id": f"simulator-action-outcome:{'2' * 64}",
        "outcome_sha256": f"sha256:{'2' * 64}",
        "predecessor_publication_generation": 1,
        "candidate_publication_generation": 2,
        "targets": [
            {"kind": "color-resource", "id": "show-look"},
            {"kind": "derivative", "id": "derivative-1"},
            *({"kind": "frame", "id": f"affected-{index}"} for index in range(3)),
        ],
        "exclusions": [{"kind": "frame", "id": f"safe-{index}"} for index in range(3)],
        "safe_complement_before_sha256": f"sha256:{'3' * 64}",
        "safe_complement_after_sha256": f"sha256:{'3' * 64}",
        "safe_complement_proof_sha256": f"sha256:{'4' * 64}",
        "publication_receipt_sha256": f"sha256:{'5' * 64}",
    }


def _executing_workflow(
    tmp_path: Path,
    *,
    recovery_settle_seconds: float = 0.0,
    sleeper: Callable[[float], None] = _noop_sleep,
) -> tuple[
    CanonicalDemoWorkflow,
    ExecutingPlans,
    FakeSimulatorActions,
    FakeSimulatorService,
    FakeOutcomeRepository,
    FakeWorkflowRecovery,
    FakeRecoveryRunner,
]:
    fixture = tmp_path / "fixture"
    visual_root = tmp_path / "visuals"
    publication_root = tmp_path / "publication"
    _fixture(fixture)
    visual_root.mkdir(mode=0o700)
    publication_root.mkdir()
    publication = FakePublication(publication_root)
    _write_recovered_publication(publication)
    incident_id = "incident-demo-11111111111111111111111111111111"
    targets = [{"kind": "frame", "id": "frame-1"}]
    plans = ExecutingPlans(
        {
            "incident_id": incident_id,
            "version": 1,
            "plan_sha256": f"sha256:{'7' * 64}",
            "targets": targets,
        }
    )
    outcome = _successful_outcome()
    simulator = FakeSimulatorService(outcome)
    repository = FakeOutcomeRepository()
    actions = FakeSimulatorActions()
    recovery = FakeWorkflowRecovery()
    runner = FakeRecoveryRunner(recovery)
    workflow = CanonicalDemoWorkflow(
        incidents=cast(Any, object()),
        investigation=cast(Any, object()),
        response_plans=cast(Any, plans),
        simulator_actions=cast(Any, actions),
        simulator_runtime=cast(Any, ExecutingRuntime(publication, simulator, repository)),
        recovery=cast(Any, recovery),
        recovery_runner=cast(Any, runner),
        recovery_identity=cast(Any, FakeRecoveryIdentity()),
        alert_source=cast(Any, object()),
        fixture_bundle=fixture,
        visual_root=visual_root,
        issuer="https://identity.example.test",
        audience="colortrace-api",
        recovery_settle_seconds=recovery_settle_seconds,
        sleeper=sleeper,
    )
    return workflow, plans, actions, simulator, repository, recovery, runner


def _execution_request() -> dict[str, Any]:
    return {
        "schema": "colortrace-demo-execution-request/v1",
        "run_id": "demo-run-11111111111111111111111111111111",
        "incident_id": "incident-demo-11111111111111111111111111111111",
        "incident_version": 7,
        "plan_version": 1,
        "plan_sha256": f"sha256:{'7' * 64}",
        "target_sha256": _digest([{"kind": "frame", "id": "frame-1"}]),
        "idempotency_key": "demo-approve-1",
    }


def test_execute_binds_authority_action_recovery_and_visual(tmp_path: Path) -> None:
    workflow, plans, actions, simulator, _repository, _recovery, runner = _executing_workflow(
        tmp_path
    )
    request = _execution_request()

    result = workflow.execute(request)

    assert [name for name, _body in plans.calls] == ["approve", "authorize", "consume"]
    assert len(actions.calls) == 1
    assert actions.calls[0][1]["task_key"] == f"dispatch-task:{'9' * 64}"
    assert len(simulator.execute_calls) == 1
    assert simulator.execute_calls[0][1] == "canonical-demo"
    assert simulator.delivery_calls == 1
    assert len(runner.calls) == 1
    assert runner.calls[0]["expected_outcome_sha256"] == f"sha256:{'2' * 64}"
    assert result["execution"]["action"]["affected_count"] == 4
    assert result["execution"]["action"]["safe_count"] == 3
    assert result["execution"]["recovery"]["evidence_count"] == 21
    assert len(result["execution"]["recovery"]["checks"]) == 7
    assert result["visuals"][0]["kind"] == "recovered"


def test_execute_waits_for_post_action_telemetry_before_recovery(tmp_path: Path) -> None:
    waits: list[float] = []
    dependencies: dict[str, Any] = {}

    def settle(seconds: float) -> None:
        assert dependencies["simulator"].delivery_calls == 1
        assert dependencies["runner"].calls == []
        waits.append(seconds)

    workflow, _plans, _actions, simulator, _repository, _recovery, runner = _executing_workflow(
        tmp_path,
        recovery_settle_seconds=10.0,
        sleeper=settle,
    )
    dependencies.update(simulator=simulator, runner=runner)

    workflow.execute(_execution_request())

    assert waits == [10.0]
    assert len(runner.calls) == 1


def test_execute_reconciliation_uses_authoritative_outcome_without_reexecution(
    tmp_path: Path,
) -> None:
    workflow, _plans, actions, simulator, repository, recovery, runner = _executing_workflow(
        tmp_path
    )
    outcome = _successful_outcome()
    repository.outcome = outcome
    recovery.ready = True
    request = _execution_request()

    result = workflow.reconcile({"operation": "approve", "operation_request": request})

    assert result is not None
    assert repository.calls == [request["incident_id"]]
    assert actions.calls == []
    assert simulator.execute_calls == []
    assert runner.calls == []
    assert result["outcome_sha256"] == outcome["outcome_sha256"]


def test_recovery_read_corruption_is_not_treated_as_a_missing_workflow(
    tmp_path: Path,
) -> None:
    workflow, _plans, _actions, _simulator, _repository, recovery, runner = _executing_workflow(
        tmp_path
    )
    recovery.error_code = "stored-recovery-aggregate-invalid"

    try:
        cast(Any, workflow)._verified_packet(
            _execution_request(),
            _successful_outcome(),
        )
    except RecoveryError as error:
        assert error.code == "stored-recovery-aggregate-invalid"
    else:  # pragma: no cover - explicit fail-closed assertion
        raise AssertionError("corrupt recovery state must propagate")

    assert runner.calls == []
