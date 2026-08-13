from __future__ import annotations

import asyncio
import concurrent.futures
import json
import sqlite3
import threading
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from colortrace_fixture import CANONICAL_SEED, build_scenario
from colortrace_grafana_mcp import adapter as mcp_subject
from colortrace_investigation import (
    ColorStateValidatorGateway,
    InvestigationPolicy,
    ModelCall,
    ModelOutput,
)
from colortrace_vertical_slice import (
    CLAIM_LEASE_SECONDS,
    SliceContractError,
    SqliteIncidentStore,
    VerticalSliceApi,
    VerticalSliceWorker,
    run_vertical_slice,
    validate_claim_events,
    validate_replay,
)
from mcp import types

NOW = datetime(2026, 8, 13, 12, 5, tzinfo=UTC)
EVENT_TIME = NOW - timedelta(minutes=3)
BINDING = {
    "prometheus_datasource_uid": "prometheus-main",
    "loki_datasource_uid": "loki-main",
    "tempo_datasource_uid": "tempo-main",
    "alert_rule_uid": "ct-alert-main",
}


def instant(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def bundle_correlation(bundle: Path) -> dict[str, str]:
    fixture = json.loads((bundle / "runtime/manifests/fixture-runtime-manifest.json").read_text())
    pointer = sorted(fixture["jobs"], key=lambda item: item["job_id"])[0]
    job = json.loads((bundle / pointer["manifest"]).read_text())
    return {
        "fixture_id": fixture["fixture_id"],
        "run_id": fixture["run_id"],
        "job_id": job["job_id"],
        "worker_id": job["worker_id"],
        "artifact_id": job["output_id"],
        "trace_id": job["trace_id"],
        "config_sha256": job["nominal_config_sha256"],
        "transform_id": job["transform_id"],
    }


def alert(correlation: Mapping[str, str], *, incident_id: str = "incident-001") -> dict[str, Any]:
    return {
        "schema": "alert-intake/v1",
        "incident_id": incident_id,
        "alert_id": f"{incident_id}-alert",
        "alert_started_at": instant(NOW - timedelta(minutes=5)),
        "retrieved_at": instant(NOW),
        "measured_clock_skew_seconds": 1,
        "binding": BINDING,
        "correlation_keys": dict(correlation),
        "predecessor_event_sha256": None,
    }


@pytest.fixture(scope="session")
def policy() -> InvestigationPolicy:
    return InvestigationPolicy.load(
        Path("config/investigation/investigation-policy.json"),
        Path("config/investigation/model-profile.json"),
    )


@pytest.fixture(scope="session")
def canonical_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("vertical-slice-bundle")
    bundle = root / "runtime-bundle"
    build_scenario(
        bundle,
        oracle_root=root / "offline-oracle",
        variant_id="canonical",
        seed=CANONICAL_SEED,
    )
    return bundle


@pytest.fixture(scope="session")
def missing_resource_bundle(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("vertical-slice-missing-resource")
    bundle = root / "runtime-bundle"
    build_scenario(
        bundle,
        oracle_root=root / "offline-truth",
        variant_id="missing-resource",
        seed=CANONICAL_SEED,
        omit_resource_role="b2",
    )
    return bundle


class FakeModel:
    def __init__(self, *, delay: float = 0) -> None:
        self.delay = delay

    async def generate(self, call: ModelCall) -> ModelOutput:
        if self.delay:
            await asyncio.sleep(self.delay)
        if call.turn_kind == "evidence-selection":
            value = {
                "schema": "model-selection/v1",
                "hypothesis_keys": [
                    "color-resource-drift",
                    "nominal-config-drift",
                    "unrelated-event",
                    "worker-only-failure",
                ],
                "query_keys": list(mcp_subject.QUERY_KEYS),
            }
        else:
            value = {
                "schema": "model-advisory/v1",
                "summary": "The cited deterministic result identifies the bounded scope.",
                "evidence_ids": [
                    item
                    for item in call.payload["allowed_evidence_ids"]
                    if isinstance(item, str) and item.startswith("sha256:")
                ][:4],
            }
        return ModelOutput(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
            1000,
            100,
        )


class LateDraftingTimeoutModel(FakeModel):
    def __init__(self) -> None:
        super().__init__()
        self.turns: list[str] = []

    async def generate(self, call: ModelCall) -> ModelOutput:
        self.turns.append(call.turn_kind)
        if call.turn_kind == "response-drafting":
            await asyncio.sleep(60)
        return await super().generate(call)


class BlockingModel(FakeModel):
    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()

    async def generate(self, call: ModelCall) -> ModelOutput:
        self.started.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")


class FixedValidator:
    def __init__(self, result: Mapping[str, Any]) -> None:
        self.result = json.loads(json.dumps(result))

    def validate(self, bundle_root: Path, *, incident_id: str) -> dict[str, Any]:
        assert bundle_root.is_dir()
        assert self.result["incident_id"] == incident_id
        return json.loads(json.dumps(self.result))


class FakeSession:
    def __init__(self, tracker: FakeEvidence) -> None:
        self.tracker = tracker

    async def list_tools(self, cursor: str | None = None) -> types.ListToolsResult:
        assert cursor is None
        return types.ListToolsResult(tools=[])

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> types.CallToolResult:
        assert arguments is not None
        assert read_timeout_seconds == timedelta(seconds=20)
        if self.tracker.missing_trace and name == "tempo_get-trace":
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text="trace not found")],
            )
        payload = self._payload(name, arguments)
        meta = (
            {"encoding": "json", "type": "trace", "version": "2"}
            if name == "tempo_get-trace"
            else None
        )
        return types.CallToolResult(
            _meta=meta,
            content=[
                types.TextContent(
                    type="text",
                    text=json.dumps(payload, sort_keys=True, separators=(",", ":")),
                )
            ],
        )

    def _payload(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        correlation = self.tracker.correlation
        if name == "query_prometheus":
            return {
                "data": [
                    {
                        "metric": correlation,
                        "value": [int(EVENT_TIME.timestamp()), "1"],
                    }
                ],
                "warnings": [],
            }
        if name == "query_loki_logs":
            return {
                "data": [
                    {
                        "timestamp": instant(EVENT_TIME),
                        "line": json.dumps(
                            {**correlation, "event": "declared-reference-observation"},
                            sort_keys=True,
                        ),
                        "labels": {"service_name": "colortrace-simulator"},
                        "structuredMetadata": correlation,
                    }
                ],
                "metadata": {
                    "linesReturned": 1,
                    "maxLinesAllowed": 200,
                    "resultsTruncated": False,
                    "totalLinesScanned": 1,
                    "startTime": arguments["startRfc3339"],
                    "endTime": arguments["endRfc3339"],
                },
            }
        if name == "tempo_get-trace":
            start = str(int(EVENT_TIME.timestamp() * 1_000_000_000))
            end = str(int((EVENT_TIME + timedelta(seconds=1)).timestamp() * 1_000_000_000))
            return {
                "trace": {
                    "traceId": correlation["trace_id"],
                    "services": [
                        {
                            "serviceName": "colortrace-simulator",
                            "resource": correlation,
                            "scopes": [
                                {
                                    "name": "colortrace.telemetry",
                                    "spans": [
                                        {
                                            "spanId": "2" * 16,
                                            "name": "fixture.process",
                                            "startTimeUnixNano": start,
                                            "endTimeUnixNano": end,
                                            "attributes": correlation,
                                            "events": [],
                                            "status": {},
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
                "metrics": {"inspectedBytes": 1},
                "status": "COMPLETE",
            }
        if name == "alerting_manage_rules":
            return {
                "uid": arguments["rule_uid"],
                "title": "ColorTrace correlation alert",
                "labels": correlation,
                "annotations": {},
                "data": [],
                "alerts": [
                    {
                        "labels": correlation,
                        "annotations": {},
                        "state": "firing",
                        "activeAt": instant(EVENT_TIME),
                        "value": "1",
                    }
                ],
            }
        raise AssertionError(name)


class FakeEvidence:
    def __init__(self, correlation: Mapping[str, str], *, missing_trace: bool = False) -> None:
        self.correlation = dict(correlation)
        self.missing_trace = missing_trace

    async def collect(
        self,
        batch: mcp_subject.EvidenceBatch,
        *,
        controls: mcp_subject.ExecutionControls | None = None,
    ) -> mcp_subject.BatchResult:
        session = FakeSession(self)

        @asynccontextmanager
        async def factory(
            _runtime: mcp_subject.OfficialMcpRuntime,
        ) -> AsyncIterator[FakeSession]:
            yield session

        runtime = mcp_subject.OfficialMcpRuntime(
            "https://grafana.invalid",
            Path("/private/viewer.token"),
            Path("/usr/local/bin/mcp-grafana"),
            b"unit-test-viewer-token",
            mcp_subject._RUNTIME_VERIFICATION,
        )
        adapter = mcp_subject.EvidenceAdapter(
            runtime=runtime,
            catalog=mcp_subject.QueryCatalog.load(Path("config/grafana-mcp/query-catalog.json")),
            session_factory=factory,
            clock=lambda: NOW,
        )
        inventory = mcp_subject.FrozenInventory("sha256:" + "a" * 64, mcp_subject.TOOL_PINS)

        async def load_inventory(_session: FakeSession) -> mcp_subject.FrozenInventory:
            return inventory

        with patch.object(mcp_subject, "_load_inventory", new=load_inventory):
            return await adapter.collect(batch, controls=controls)


def worker(
    store: SqliteIncidentStore,
    policy: InvestigationPolicy,
    correlation: Mapping[str, str],
    *,
    missing_trace: bool = False,
    model_delay: float = 0,
    service_timeout: float = 121,
) -> VerticalSliceWorker:
    return VerticalSliceWorker(
        store,
        policy=policy,
        model=FakeModel(delay=model_delay),
        evidence=FakeEvidence(correlation, missing_trace=missing_trace),
        validator=ColorStateValidatorGateway(),
        clock=lambda: NOW,
        service_timeout_seconds=service_timeout,
    )


def downgrade_store_to_v1(database: Path) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE claim_events")
        connection.execute("ALTER TABLE tasks DROP COLUMN claim_expires_at")
        connection.execute("ALTER TABLE tasks DROP COLUMN claim_generation")
        connection.execute("ALTER TABLE tasks DROP COLUMN claim_owner")
        connection.execute("UPDATE store_metadata SET schema_version = 1 WHERE singleton = 1")


def test_canonical_slice_persists_exact_replay_and_idempotent_duplicate(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    store = SqliteIncidentStore(tmp_path / "incidents.sqlite3")
    api = VerticalSliceApi(store, clock=lambda: NOW)
    selected_worker = worker(store, policy, correlation)
    intake = alert(correlation)

    packet = asyncio.run(
        run_vertical_slice(
            api=api,
            worker=selected_worker,
            alert=intake,
            bundle_root=canonical_bundle,
        )
    )
    replay = api.replay("incident-001")

    assert packet["status"] == "resolved"
    assert replay["packet"] == packet
    assert replay["alert"] == intake
    assert len(replay["evidence_batches"]) == 1
    assert len(replay["evidence"]) == 4
    assert (
        replay["validator_results"][0]["result_id"]
        == packet["deterministic_results"][0]["result_id"]
    )
    assert replay["invocations"] == packet["invocation_records"]
    assert [event["event_type"] for event in replay["trace_events"]] == [
        "api.intake.accepted",
        "task.queued",
        "worker.started",
        "packet.persisted",
        "incident.completed",
    ]
    assert {event["trace_id"] for event in replay["trace_events"]} == {correlation["trace_id"]}
    validate_replay(replay)

    duplicate = api.accept_alert(intake)
    duplicate_packet = asyncio.run(
        selected_worker.execute(duplicate["task_id"], bundle_root=canonical_bundle)
    )
    assert duplicate["duplicate"] is True
    assert duplicate_packet == packet
    assert api.replay("incident-001") == replay
    assert "offline-oracle" not in (tmp_path / "incidents.sqlite3").read_bytes().decode(
        "utf-8", errors="ignore"
    )


def test_missing_trace_finishes_unresolved_and_replays_provenance(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    store = SqliteIncidentStore(tmp_path / "missing-trace.sqlite3")
    api = VerticalSliceApi(store, clock=lambda: NOW)
    packet = asyncio.run(
        run_vertical_slice(
            api=api,
            worker=worker(store, policy, correlation, missing_trace=True),
            alert=alert(correlation, incident_id="incident-missing-trace"),
            bundle_root=canonical_bundle,
        )
    )

    assert packet["status"] == "unresolved"
    assert packet["candidate_plan"] is None
    assert packet["scope"]["state"] == "unresolved"
    assert packet["claims"][0]["state"] == "unresolved"
    assert "evidence-unavailable" in {item["code"] for item in packet["unresolved_items"]}
    replay = api.replay("incident-missing-trace")
    assert replay["packet"] == packet
    assert len(replay["evidence"]) == 4
    assert replay["validator_results"] == []
    validate_replay(replay)


def test_unresolved_validator_claims_remain_bound_in_persisted_replay(
    policy: InvestigationPolicy,
    missing_resource_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(missing_resource_bundle)
    store = SqliteIncidentStore(tmp_path / "unresolved-validator.sqlite3")
    api = VerticalSliceApi(store, clock=lambda: NOW)

    packet = asyncio.run(
        run_vertical_slice(
            api=api,
            worker=worker(store, policy, correlation),
            alert=alert(correlation, incident_id="incident-unresolved-validator"),
            bundle_root=missing_resource_bundle,
        )
    )
    replay = api.replay("incident-unresolved-validator")

    assert packet["status"] == "unresolved"
    assert packet["deterministic_results"][0]["status"] == "unresolved"
    result_id = packet["deterministic_results"][0]["result_id"]
    validator_result = replay["validator_results"][0]
    assert {
        claim["deterministic_result_evidence_id"]
        for claim in validator_result["claims"]
        if claim["deterministic_result_evidence_id"] is not None
    } <= set(packet["evidence_ids"])
    assert replay["packet"] == packet
    assert validator_result["result_id"] == result_id
    validate_replay(replay)


def test_service_timeout_is_durable_and_clean_reset_is_exact(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    store = SqliteIncidentStore(tmp_path / "timeout.sqlite3")
    api = VerticalSliceApi(store, clock=lambda: NOW)
    packet = asyncio.run(
        run_vertical_slice(
            api=api,
            worker=worker(
                store,
                policy,
                correlation,
                model_delay=0.1,
                service_timeout=0.01,
            ),
            alert=alert(correlation, incident_id="incident-timeout"),
            bundle_root=canonical_bundle,
        )
    )

    assert packet["status"] == "unresolved"
    assert packet["no_action_reason"] == "budget-exhausted"
    assert packet["unresolved_items"] == [
        {"code": "service-timeout", "stage": "worker", "evidence_ids": []}
    ]
    validate_replay(api.replay("incident-timeout"))

    reset = api.reset()
    assert reset["incidents"] == 1
    assert reset["tasks"] == 1
    assert reset["packets"] == 1
    assert reset["trace_events"] == 5
    store.assert_empty()
    with pytest.raises(SliceContractError, match="incident-not-found"):
        api.get_incident("incident-timeout")


def test_late_drafting_timeout_preserves_completed_provenance(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    store = SqliteIncidentStore(tmp_path / "late-timeout.sqlite3")
    api = VerticalSliceApi(store, clock=lambda: NOW)
    model = LateDraftingTimeoutModel()
    validator_result = ColorStateValidatorGateway().validate(
        canonical_bundle, incident_id="incident-late-timeout"
    )
    selected_worker = VerticalSliceWorker(
        store,
        policy=policy,
        model=model,
        evidence=FakeEvidence(correlation),
        validator=FixedValidator(validator_result),
        clock=lambda: NOW,
        service_timeout_seconds=1,
    )

    packet = asyncio.run(
        run_vertical_slice(
            api=api,
            worker=selected_worker,
            alert=alert(correlation, incident_id="incident-late-timeout"),
            bundle_root=canonical_bundle,
        )
    )
    replay = api.replay("incident-late-timeout")

    assert model.turns == ["evidence-selection", "response-drafting"]
    assert packet["status"] == "unresolved"
    assert len(packet["evidence_ids"]) >= 4
    assert len(packet["deterministic_results"]) == 1
    assert len(replay["validator_results"]) == 1
    assert [item["turn_kind"] for item in packet["invocation_records"]] == [
        "evidence-selection",
        "response-drafting",
    ]
    assert packet["invocation_records"][1]["result_class"] == "failed"
    assert packet["invocation_records"][1]["error_code"] == "cancelled"
    assert packet["budget_use"]["model_turns"] == 2
    assert packet["budget_use"]["input_tokens"] == 1000
    assert packet["budget_use"]["output_tokens"] == 100
    assert packet["budget_use"]["unavailable_input_tokens_reserved"] > 0
    assert packet["budget_use"]["unavailable_output_tokens_reserved"] == 1792
    assert packet["budget_use"]["mcp_attempts"] == 4
    assert packet["budget_use"]["validator_calls"] == 5
    assert packet["budget_use"]["elapsed_ms"] >= 900
    assert "drafting" in packet["state_history"]
    assert replay["invocations"] == packet["invocation_records"]
    validate_replay(replay)


def test_duplicate_identity_conflict_and_oracle_path_fail_closed(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    store = SqliteIncidentStore(tmp_path / "conflict.sqlite3")
    api = VerticalSliceApi(store, clock=lambda: NOW)
    first = alert(correlation, incident_id="incident-conflict")
    api.accept_alert(first)
    changed = {**first, "alert_id": "different-alert"}
    with pytest.raises(SliceContractError, match="idempotency-conflict"):
        api.accept_alert(changed)

    oracle_store = SqliteIncidentStore(tmp_path / "oracle.sqlite3")
    oracle_api = VerticalSliceApi(oracle_store, clock=lambda: NOW)
    oracle_packet = asyncio.run(
        run_vertical_slice(
            api=oracle_api,
            worker=worker(oracle_store, policy, correlation),
            alert=alert(correlation, incident_id="incident-oracle-control"),
            bundle_root=canonical_bundle.parent / "offline-oracle",
        )
    )
    assert oracle_packet["status"] == "unresolved"
    assert "oracle-boundary" in {item["code"] for item in oracle_packet["unresolved_items"]}
    assert oracle_packet["candidate_plan"] is None


def test_replay_detects_persisted_packet_tampering(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    database = tmp_path / "tamper.sqlite3"
    store = SqliteIncidentStore(database)
    api = VerticalSliceApi(store, clock=lambda: NOW)
    asyncio.run(
        run_vertical_slice(
            api=api,
            worker=worker(store, policy, correlation),
            alert=alert(correlation, incident_id="incident-tamper"),
            bundle_root=canonical_bundle,
        )
    )
    task_id = api.get_incident("incident-tamper")["task"]["task_id"]
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE packets SET document_json = ? WHERE incident_id = ?",
            (b"{}", "incident-tamper"),
        )
    with pytest.raises(SliceContractError, match="stored-packet-digest"):
        store.completed_packet(task_id)
    with pytest.raises(SliceContractError, match="stored-packet-digest"):
        api.get_incident("incident-tamper")
    with pytest.raises(SliceContractError, match="stored-packet-digest"):
        api.replay("incident-tamper")


def test_claim_heartbeat_extends_lease_and_exact_expiry_reclaims(
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    store = SqliteIncidentStore(tmp_path / "claim-heartbeat.sqlite3")
    accepted = VerticalSliceApi(store, clock=lambda: NOW).accept_alert(
        alert(correlation, incident_id="incident-claim-heartbeat")
    )
    task_id = accepted["task_id"]

    first = store.claim_task(task_id, owner="worker:first", now=instant(NOW))
    assert first.claim_generation == 1
    assert first.claim_expires_at == instant(NOW + timedelta(seconds=CLAIM_LEASE_SECONDS))

    store.renew_claim(first, now=instant(NOW + timedelta(seconds=10)))
    history = store.claim_history(task_id)
    assert [event["event_type"] for event in history] == [
        "claim.acquired",
        "claim.renewed",
    ]
    assert history[-1]["lease_expires_at"] == instant(NOW + timedelta(seconds=40))
    validate_claim_events(
        history,
        task_id=task_id,
        incident_id="incident-claim-heartbeat",
    )

    with pytest.raises(SliceContractError, match="task-in-progress"):
        store.claim_task(
            task_id,
            owner="worker:early",
            now=instant(NOW + timedelta(seconds=30)),
        )
    second = store.claim_task(
        task_id,
        owner="worker:second",
        now=instant(NOW + timedelta(seconds=40)),
    )
    assert second.claim_generation == 2
    with pytest.raises(SliceContractError, match="claim-fenced"):
        store.renew_claim(first, now=instant(NOW + timedelta(seconds=41)))


def test_expired_claim_has_one_atomic_concurrent_reclaimer(
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    database = tmp_path / "concurrent-reclaim.sqlite3"
    store = SqliteIncidentStore(database)
    task_id = VerticalSliceApi(store, clock=lambda: NOW).accept_alert(
        alert(correlation, incident_id="incident-concurrent-reclaim")
    )["task_id"]
    store.claim_task(task_id, owner="worker:crashed", now=instant(NOW))
    contenders = (SqliteIncidentStore(database), SqliteIncidentStore(database))
    barrier = threading.Barrier(2)

    def reclaim(selected: SqliteIncidentStore, owner: str) -> tuple[str, int | str]:
        barrier.wait(timeout=2)
        try:
            work = selected.claim_task(
                task_id,
                owner=owner,
                now=instant(NOW + timedelta(seconds=CLAIM_LEASE_SECONDS)),
            )
        except SliceContractError as error:
            return "error", error.code
        return "claimed", work.claim_generation

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(reclaim, selected, f"worker:contender-{index}")
            for index, selected in enumerate(contenders, start=1)
        ]
        results = [future.result(timeout=5) for future in futures]

    assert sorted(results) == [("claimed", 2), ("error", "task-in-progress")]
    assert [event["event_type"] for event in store.claim_history(task_id)] == [
        "claim.acquired",
        "claim.reclaimed",
    ]


def test_concurrent_duplicate_returns_packet_when_completion_wins_claim_race(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    database = tmp_path / "completion-duplicate-race.sqlite3"
    primary_store = SqliteIncidentStore(database)
    duplicate_store = SqliteIncidentStore(database)
    api = VerticalSliceApi(primary_store, clock=lambda: NOW)
    task_id = api.accept_alert(
        alert(correlation, incident_id="incident-completion-duplicate-race")
    )["task_id"]
    primary = worker(primary_store, policy, correlation)
    duplicate = worker(duplicate_store, policy, correlation)
    precheck_complete = threading.Event()
    allow_claim = threading.Event()
    original_completed_packet = duplicate_store.completed_packet
    completed_packet_calls = 0

    def delayed_completed_packet(selected_task_id: str) -> dict[str, Any] | None:
        nonlocal completed_packet_calls
        completed_packet_calls += 1
        if completed_packet_calls == 1:
            precheck_complete.set()
            if not allow_claim.wait(timeout=5):
                raise AssertionError("completion race was not released")
            return None
        return original_completed_packet(selected_task_id)

    with patch.object(duplicate_store, "completed_packet", side_effect=delayed_completed_packet):
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            duplicate_result = executor.submit(
                asyncio.run,
                duplicate.execute(task_id, bundle_root=canonical_bundle),
            )
            assert precheck_complete.wait(timeout=5)
            packet = asyncio.run(primary.execute(task_id, bundle_root=canonical_bundle))
            allow_claim.set()
            assert duplicate_result.result(timeout=10) == packet

    assert completed_packet_calls == 2
    assert api.replay("incident-completion-duplicate-race")["packet"] == packet


def test_graceful_cancellation_expires_claim_for_immediate_reclaim(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    store = SqliteIncidentStore(tmp_path / "cancelled-claim.sqlite3")
    api = VerticalSliceApi(store, clock=lambda: NOW)
    task_id = api.accept_alert(alert(correlation, incident_id="incident-cancelled-claim"))[
        "task_id"
    ]
    model = BlockingModel()
    selected_worker = VerticalSliceWorker(
        store,
        policy=policy,
        model=model,
        evidence=FakeEvidence(correlation),
        validator=ColorStateValidatorGateway(),
        clock=lambda: NOW,
        owner_id="worker:cancelled",
    )

    async def cancel_running_work() -> None:
        running = asyncio.create_task(
            selected_worker.execute(task_id, bundle_root=canonical_bundle)
        )
        await asyncio.wait_for(model.started.wait(), timeout=2)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    asyncio.run(cancel_running_work())

    history = store.claim_history(task_id)
    assert [event["event_type"] for event in history] == [
        "claim.acquired",
        "claim.cancelled",
    ]
    assert history[-1]["lease_expires_at"] == instant(NOW)
    reclaimed = store.claim_task(task_id, owner="worker:replacement", now=instant(NOW))
    assert reclaimed.claim_generation == 2


def test_stale_completion_is_fenced_without_partial_persistence(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    intake = alert(correlation, incident_id="incident-stale-completion")
    source = SqliteIncidentStore(tmp_path / "stale-source.sqlite3")
    source_api = VerticalSliceApi(source, clock=lambda: NOW)
    packet = asyncio.run(
        run_vertical_slice(
            api=source_api,
            worker=worker(source, policy, correlation),
            alert=intake,
            bundle_root=canonical_bundle,
        )
    )
    replay = source_api.replay("incident-stale-completion")

    database = tmp_path / "stale-target.sqlite3"
    target = SqliteIncidentStore(database)
    task_id = VerticalSliceApi(target, clock=lambda: NOW).accept_alert(intake)["task_id"]
    stale = target.claim_task(task_id, owner="worker:stale", now=instant(NOW))
    target.renew_claim(stale, now=instant(NOW + timedelta(seconds=10)))
    with pytest.raises(SliceContractError, match="claim-clock-regression"):
        target.complete_task(
            stale,
            packet=packet,
            evidence=replay["evidence"],
            evidence_batches=replay["evidence_batches"],
            validator_results=replay["validator_results"],
            now=instant(NOW + timedelta(seconds=5)),
        )
    target.expire_claim(stale, now=instant(NOW + timedelta(seconds=20)))
    with pytest.raises(SliceContractError, match="claim-clock-regression"):
        target.complete_task(
            stale,
            packet=packet,
            evidence=replay["evidence"],
            evidence_batches=replay["evidence_batches"],
            validator_results=replay["validator_results"],
            now=instant(NOW + timedelta(seconds=15)),
        )
    expiry_time = instant(NOW + timedelta(seconds=20))
    with pytest.raises(SliceContractError, match="claim-expired"):
        target.complete_task(
            stale,
            packet=packet,
            evidence=replay["evidence"],
            evidence_batches=replay["evidence_batches"],
            validator_results=replay["validator_results"],
            now=expiry_time,
        )
    current = target.claim_task(
        task_id,
        owner="worker:current",
        now=expiry_time,
    )
    completion_time = instant(NOW + timedelta(seconds=CLAIM_LEASE_SECONDS + 1))

    with pytest.raises(SliceContractError, match="claim-fenced"):
        target.complete_task(
            stale,
            packet=packet,
            evidence=replay["evidence"],
            evidence_batches=replay["evidence_batches"],
            validator_results=replay["validator_results"],
            now=completion_time,
        )
    with sqlite3.connect(database) as connection:
        counts = [
            connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in ("evidence", "evidence_batches", "validator_results", "packets")
        ]
    assert counts == [0, 0, 0, 0]
    assert target.incident_view("incident-stale-completion")["incident"]["status"] == "running"

    completed = target.complete_task(
        current,
        packet=packet,
        evidence=replay["evidence"],
        evidence_batches=replay["evidence_batches"],
        validator_results=replay["validator_results"],
        now=completion_time,
    )
    assert completed == packet
    assert target.replay("incident-stale-completion")["packet"] == packet
    assert [event["event_type"] for event in target.claim_history(task_id)] == [
        "claim.acquired",
        "claim.renewed",
        "claim.cancelled",
        "claim.reclaimed",
        "claim.completed",
    ]


def test_running_v1_claim_migrates_and_reclaims_at_exact_expiry(
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    database = tmp_path / "running-v1.sqlite3"
    store = SqliteIncidentStore(database)
    task_id = VerticalSliceApi(store, clock=lambda: NOW).accept_alert(
        alert(correlation, incident_id="incident-running-v1")
    )["task_id"]
    store.claim_task(task_id, owner="worker:lost-before-migration", now=instant(NOW))
    downgrade_store_to_v1(database)

    migrated = SqliteIncidentStore(database)
    migrated_history = migrated.claim_history(task_id)
    assert [event["event_type"] for event in migrated_history] == ["claim.migrated"]
    assert migrated_history[0]["owner"] == "migration:v1"
    assert migrated_history[0]["lease_expires_at"] == instant(
        NOW + timedelta(seconds=CLAIM_LEASE_SECONDS)
    )
    reclaimed = migrated.claim_task(
        task_id,
        owner="worker:after-migration",
        now=instant(NOW + timedelta(seconds=CLAIM_LEASE_SECONDS)),
    )
    assert reclaimed.claim_generation == 2
    with sqlite3.connect(database) as connection:
        version = connection.execute(
            "SELECT schema_version FROM store_metadata WHERE singleton = 1"
        ).fetchone()[0]
        trace_count = connection.execute("SELECT count(*) FROM trace_events").fetchone()[0]
    assert version == 2
    assert trace_count == 3


def test_running_claim_rejects_missing_or_truncated_claim_history(
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    missing_database = tmp_path / "missing-claim-history.sqlite3"
    missing = SqliteIncidentStore(missing_database)
    missing_task = VerticalSliceApi(missing, clock=lambda: NOW).accept_alert(
        alert(correlation, incident_id="incident-missing-claim-history")
    )["task_id"]
    missing.claim_task(missing_task, owner="worker:missing-history", now=instant(NOW))
    with sqlite3.connect(missing_database) as connection:
        connection.execute("DELETE FROM claim_events WHERE task_id = ?", (missing_task,))
    with pytest.raises(SliceContractError, match="stored-claim-state-binding"):
        SqliteIncidentStore(missing_database)

    truncated_database = tmp_path / "truncated-claim-history.sqlite3"
    truncated = SqliteIncidentStore(truncated_database)
    truncated_task = VerticalSliceApi(truncated, clock=lambda: NOW).accept_alert(
        alert(correlation, incident_id="incident-truncated-claim-history")
    )["task_id"]
    work = truncated.claim_task(truncated_task, owner="worker:truncated-history", now=instant(NOW))
    truncated.renew_claim(work, now=instant(NOW + timedelta(seconds=10)))
    with sqlite3.connect(truncated_database) as connection:
        connection.execute(
            "DELETE FROM claim_events WHERE task_id = ? AND sequence = 2", (truncated_task,)
        )
    with pytest.raises(SliceContractError, match="stored-claim-state-binding"):
        SqliteIncidentStore(truncated_database)


def test_v1_migration_rolls_back_schema_and_version_on_failure(
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    database = tmp_path / "failed-v1-migration.sqlite3"
    store = SqliteIncidentStore(database)
    task_id = VerticalSliceApi(store, clock=lambda: NOW).accept_alert(
        alert(correlation, incident_id="incident-failed-v1-migration")
    )["task_id"]
    store.claim_task(task_id, owner="worker:lost", now=instant(NOW))
    downgrade_store_to_v1(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE tasks SET updated_at = 'not-a-time' WHERE task_id = ?", (task_id,)
        )

    with pytest.raises(SliceContractError, match="stored-claim-time-invalid"):
        SqliteIncidentStore(database)

    with sqlite3.connect(database) as connection:
        version = connection.execute(
            "SELECT schema_version FROM store_metadata WHERE singleton = 1"
        ).fetchone()[0]
        columns = {row[1] for row in connection.execute("PRAGMA table_info(tasks)").fetchall()}
        claim_table = connection.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'claim_events'"
        ).fetchone()
    assert version == 1
    assert not {"claim_owner", "claim_generation", "claim_expires_at"} & columns
    assert claim_table is None


def test_completed_v1_migration_preserves_replay_bytes_and_duplicate_idempotency(
    policy: InvestigationPolicy,
    canonical_bundle: Path,
    tmp_path: Path,
) -> None:
    correlation = bundle_correlation(canonical_bundle)
    database = tmp_path / "completed-v1.sqlite3"
    store = SqliteIncidentStore(database)
    api = VerticalSliceApi(store, clock=lambda: NOW)
    intake = alert(correlation, incident_id="incident-completed-v1")
    packet = asyncio.run(
        run_vertical_slice(
            api=api,
            worker=worker(store, policy, correlation),
            alert=intake,
            bundle_root=canonical_bundle,
        )
    )
    before = json.dumps(
        api.replay("incident-completed-v1"), sort_keys=True, separators=(",", ":")
    ).encode()
    downgrade_store_to_v1(database)

    migrated = SqliteIncidentStore(database)
    migrated_api = VerticalSliceApi(migrated, clock=lambda: NOW)
    after = json.dumps(
        migrated_api.replay("incident-completed-v1"), sort_keys=True, separators=(",", ":")
    ).encode()
    assert after == before
    duplicate = migrated_api.accept_alert(intake)
    assert duplicate["duplicate"] is True
    assert migrated.claim_history(duplicate["task_id"]) == []
    assert migrated.completed_packet(duplicate["task_id"]) == packet


def test_openapi_preserves_intake_and_packet_contract_surfaces() -> None:
    openapi = json.loads(Path("packages/contracts/openapi.json").read_text())
    alert_schema = json.loads(
        Path(
            "packages/investigation/src/colortrace_investigation/schemas/"
            "alert-intake-v1.schema.json"
        ).read_text()
    )
    packet_schema = json.loads(
        Path(
            "packages/investigation/src/colortrace_investigation/schemas/"
            "response-packet-v1.schema.json"
        ).read_text()
    )
    schemas = openapi["components"]["schemas"]

    assert schemas["AlertIntake"]["required"] == alert_schema["required"]
    assert set(schemas["AlertIntake"]["properties"]) == set(alert_schema["properties"])
    assert schemas["ResponsePacket"]["required"] == packet_schema["required"]
    assert set(schemas["ResponsePacket"]["properties"]) == set(packet_schema["properties"])
    assert (
        schemas["ResponsePacket"]["properties"]["status"] == packet_schema["properties"]["status"]
    )
    assert (
        schemas["Claim"]["properties"]["state"]
        == packet_schema["$defs"]["claim"]["properties"]["state"]
    )
    packet_properties = schemas["ResponsePacket"]["properties"]
    assert packet_properties["deterministic_results"]["items"]["$ref"].endswith(
        "/DeterministicResult"
    )
    assert packet_properties["invocation_records"]["items"]["$ref"].endswith("/ModelInvocation")
    assert packet_properties["unresolved_items"]["items"]["$ref"].endswith("/UnresolvedItem")
    replay_properties = schemas["IncidentReplay"]["properties"]
    assert replay_properties["evidence"]["items"]["$ref"].endswith("/EvidenceEnvelope")
    assert replay_properties["validator_results"]["items"]["$ref"].endswith("/ValidatorResult")
    assert replay_properties["invocations"]["items"]["$ref"].endswith("/ModelInvocation")
    assert schemas["TraceEvent"]["properties"]["event_type"]["enum"] == list(
        (
            "api.intake.accepted",
            "task.queued",
            "worker.started",
            "packet.persisted",
            "incident.completed",
        )
    )
