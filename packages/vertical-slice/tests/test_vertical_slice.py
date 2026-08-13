from __future__ import annotations

import asyncio
import json
import sqlite3
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
    SliceContractError,
    SqliteIncidentStore,
    VerticalSliceApi,
    VerticalSliceWorker,
    run_vertical_slice,
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
