from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import colortrace_telemetry.cli as telemetry_cli
import colortrace_telemetry.observer as observer
import pytest
import yaml  # type: ignore[import-untyped]
from colortrace_telemetry.contract import (
    CORRELATION_VERSION,
    DeliveryPlan,
    canonical_json_bytes,
    load_candidate_binding,
    load_runtime_jobs,
    sha256_bytes,
    sha256_file,
    validate_schema,
)
from colortrace_telemetry.emitter import MemorySink, emit_plans
from colortrace_telemetry.observer import (
    BackendEndpoints,
    BackendUnavailable,
    observe_without_grafana,
    telemetry_isolation_receipt,
    wait_for_grafana_readiness,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
ALERT_UID = "ct-declared-reference-divergence-v1"


def _ready_ruler_payload(*, interval: str = "10s") -> dict[str, object]:
    return {
        "ColorTrace": [
            {
                "interval": interval,
                "rules": [{"grafana_alert": {"uid": ALERT_UID}}],
            }
        ]
    }


def _write_json(root: Path, relative: str, value: dict[str, Any]) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))
    return path


def _digest(value: str) -> str:
    return sha256_bytes(value.encode("ascii"))


@pytest.fixture()
def scenario(tmp_path: Path) -> Path:
    root = tmp_path / "runtime-bundle"
    job_pointers: list[dict[str, str]] = []
    report_jobs: list[dict[str, Any]] = []
    diff_images: list[dict[str, Any]] = []
    for index in range(6):
        job_id = f"job-{index + 1}"
        worker_id = "A" if index < 2 else "B"
        output_id = f"output-{index + 1}"
        transform_id = "identity/v1" if index == 5 else "look/main/v1"
        config_digest = _digest(f"config-{worker_id}")
        ordered_resources = (
            []
            if transform_id == "identity/v1"
            else [
                {
                    "logical_path": "luts/show_look.cube",
                    "resolved_root_relative_path": "config/luts/show_look.cube",
                    "sha256": _digest(f"resource-{worker_id}"),
                    "size": 32,
                    "read_only": True,
                }
            ]
        )
        resource = {
            "schema": "resolved-resource-manifest/v1",
            "job_id": job_id,
            "run_id": "fixture-run-01",
            "worker_id": worker_id,
            "nominal_config_sha256": config_digest,
            "config_root_relative_path": f"runtime/workers/{worker_id}/config",
            "transform_id": transform_id,
            "ordered_resources": ordered_resources,
            "captured_before_and_after_processing": True,
            "inputs_unchanged": True,
        }
        resource_relative = f"runtime/manifests/resources/{job_id}.json"
        resource_path = _write_json(root, resource_relative, resource)
        output_relative = f"runtime/outputs/{job_id}.bin"
        output_path = root / output_relative
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(f"output-{index}".encode("ascii"))
        output_digest = sha256_file(output_path)
        diff_path = root / f"reports/diffs/{job_id}.png"
        diff_path.parent.mkdir(parents=True, exist_ok=True)
        diff_path.write_bytes(b"synthetic-diff-png-" + str(index).encode("ascii"))
        diff_images.append(
            {
                "job_id": job_id,
                "path": f"reports/diffs/{job_id}.png",
                "sha256": sha256_file(diff_path),
                "authoritative": False,
            }
        )
        job = {
            "schema": "fixture-job/v1",
            "fixture_id": "ct-shadowed-lut-v1",
            "fixture_version": "colortrace-fixture/v1",
            "variant_id": "synthetic-test",
            "seed_sha256": _digest("seed"),
            "job_id": job_id,
            "run_id": "fixture-run-01",
            "worker_id": worker_id,
            "source_id": f"source-{index + 1}",
            "shot_id": f"shot-{index + 1}",
            "frame_id": f"frame-{index + 1}",
            "correlation_id": f"correlation-{index + 1}",
            "trace_id": f"{index + 1:032x}",
            "transform_id": transform_id,
            "start_offset_seconds": index,
            "duration_seconds": 1,
            "process_outcome": "success",
            "exit_code": 0,
            "ocio_version": "2.5.2",
            "processor_identity_sha256": _digest(f"processor-{index}"),
            "nominal_config_sha256": config_digest,
            "resource_manifest": resource_relative,
            "resource_manifest_sha256": sha256_file(resource_path),
            "source_manifest": f"runtime/manifests/sources/source-{index + 1}.json",
            "output_id": output_id,
            "output_buffer": output_relative,
            "output_buffer_sha256": output_digest,
            "display_png": f"runtime/outputs/{job_id}.png",
            "display_png_sha256": _digest(f"display-{index}"),
            "display_authoritative": False,
            "declared_reference_id": f"reference-{index + 1}",
            "declared_reference_manifest": f"references/reference-{index + 1}.json",
            "declared_reference_manifest_sha256": _digest(f"reference-{index}"),
        }
        job_relative = f"runtime/manifests/jobs/{job_id}.json"
        job_path = _write_json(root, job_relative, job)
        job_digest = sha256_file(job_path)
        job_pointers.append({"job_id": job_id, "manifest": job_relative, "sha256": job_digest})
        state = "reference_mismatch" if index in {2, 3, 4} else "reference_match"
        comparison = {
            "state": state,
            "maximum_absolute_channel_error": "0.1" if state.endswith("mismatch") else "0",
            "rmse": "0.05" if state.endswith("mismatch") else "0",
            "fraction_pixels_at_or_above_0_02": ("0.5" if state.endswith("mismatch") else "0"),
            "nearest_rank_p95": "0.1" if state.endswith("mismatch") else "0",
            "pixels": 16,
            "policy": "declared-reference-comparison/v1",
        }
        report_jobs.append(
            {
                "job_id": job_id,
                "worker_id": worker_id,
                "output_id": output_id,
                "transform_id": transform_id,
                "nominal_config_sha256": config_digest,
                "state": state,
                "comparison": comparison,
                "reasons": [],
                "resource_manifest_sha256": sha256_file(resource_path),
                "resolved_resource_sha256": (
                    ordered_resources[0]["sha256"] if ordered_resources else None
                ),
                "evidence": [job_digest, output_digest],
            }
        )

    lineage_path = _write_json(
        root,
        "runtime/manifests/lineage.json",
        {
            "schema": "artifact-lineage/v1",
            "edges": [
                *[
                    {
                        "edge_type": "source-to-render/v1",
                        "parent_artifact_id": f"source-{index + 1}",
                        "child_artifact_id": f"output-{index + 1}",
                        "job_id": f"job-{index + 1}",
                        "correlation_id": f"correlation-{index + 1}",
                    }
                    for index in range(6)
                ],
                {
                    "edge_type": "lossless-derivative/v1",
                    "parent_artifact_id": "output-1",
                    "child_artifact_id": "derivative-1",
                },
            ],
            "artifacts": [
                *[
                    {
                        "artifact_id": f"output-{index + 1}",
                        "artifact_type": "authoritative-render-output",
                        "job_id": f"job-{index + 1}",
                    }
                    for index in range(6)
                ],
                {
                    "artifact_id": "derivative-1",
                    "artifact_type": "lossless-derivative",
                    "buffer": "runtime/outputs/derivative-1.bin",
                    "sha256": _digest("derivative"),
                    "display": "runtime/outputs/derivative-1.png",
                    "display_sha256": _digest("derivative-display"),
                    "generator": "lossless-float-copy/v1",
                },
            ],
        },
    )
    fixture_telemetry_path = _write_json(
        root,
        "runtime/manifests/telemetry.json",
        {
            "schema": "fixture-telemetry/v1",
            "events": [
                {
                    "event_id": "event-1",
                    "worker_id": "A",
                    "start_offset_seconds": 0,
                    "duration_seconds": 15,
                    "overlapping_job_ids": ["job-1", "job-2"],
                    "measurements": {
                        "worker.cpu.utilization": "0.94",
                        "render.queue_wait_ms": "1800",
                    },
                    "resource_edges": [],
                    "lineage_edges": [],
                    "output_mutation": False,
                }
            ],
        },
    )
    fixture = {
        "schema": "fixture-runtime-manifest/v1",
        "fixture_id": "ct-shadowed-lut-v1",
        "fixture_version": "colortrace-fixture/v1",
        "variant_id": "synthetic-test",
        "run_id": "fixture-run-01",
        "seed_sha256": _digest("seed"),
        "schedule_origin": "2026-08-12T00:00:00Z",
        "image_generator": "generated-chart/v1",
        "float_buffer": "rgb-float32-buffer/v1",
        "comparison_policy": "declared-reference-comparison/v1",
        "ocio_version": "2.5.2",
        "worker_configs": [
            {"worker_id": worker, "config_sha256": _digest(f"config-{worker}"), "config": worker}
            for worker in ("A", "B")
        ],
        "sources": [
            {
                "source_id": f"source-{index}",
                "manifest": f"source-{index}",
                "sha256": _digest(f"source-{index}"),
            }
            for index in range(1, 5)
        ],
        "jobs": job_pointers,
        "lineage": {
            "manifest": "runtime/manifests/lineage.json",
            "sha256": sha256_file(lineage_path),
        },
        "telemetry": {
            "manifest": "runtime/manifests/telemetry.json",
            "sha256": sha256_file(fixture_telemetry_path),
        },
        "provenance": {"manifest": "provenance.json", "sha256": _digest("provenance")},
        "declared_resources": {
            "manifest": "resources.json",
            "sha256": _digest("resources"),
        },
    }
    _write_json(root, "runtime/manifests/fixture-runtime-manifest.json", fixture)
    report = {
        "schema": "fixture-validator-report/v1",
        "fixture_id": "ct-shadowed-lut-v1",
        "variant_id": "synthetic-test",
        "ocio_version": "2.5.2",
        "comparison_policy": "declared-reference-comparison/v1",
        "jobs": report_jobs,
        "derivatives": [
            {
                "artifact_id": "derivative-1",
                "parent_artifact_id": "output-1",
                "state": "reference_match",
                "policy": "exact-lineage-propagation/v1",
                "evidence": [sha256_file(lineage_path)],
            }
        ],
        "telemetry_events": [
            {
                "event_id": "event-1",
                "overlapping_job_ids": ["job-1", "job-2"],
                "resource_edges": [],
                "lineage_edges": [],
                "output_mutation": False,
                "evidence": [sha256_file(fixture_telemetry_path)],
            }
        ],
        "diff_images": diff_images,
    }
    report_path = _write_json(root, "reports/validator-report.json", report)
    _write_json(
        root,
        "reports/validator-receipt.json",
        {
            "schema": "validator-receipt/v1",
            "report": "reports/validator-report.json",
            "report_sha256": sha256_file(report_path),
            "truth_material_inside_runtime_bundle": False,
        },
    )
    return root


def _resign_report(scenario: Path, report: dict[str, Any]) -> None:
    report_path = scenario / "reports/validator-report.json"
    report_path.write_bytes(canonical_json_bytes(report))
    receipt_path = scenario / "reports/validator-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["report_sha256"] = sha256_file(report_path)
    receipt_path.write_bytes(canonical_json_bytes(receipt))


def test_runtime_binding_projects_strict_observations(scenario: Path) -> None:
    runtime = load_runtime_jobs(scenario)
    assert len(runtime.jobs) == 6
    assert Counter(job.observation.state for job in runtime.jobs) == {
        "reference_match": 3,
        "reference_mismatch": 3,
    }
    first_run_trace_ids: list[str] = []
    second_run_trace_ids: list[str] = []
    for job in runtime.jobs:
        correlation = job.correlation("telemetry-run-00").to_dict()
        assert tuple(correlation) == (
            "fixture_id",
            "run_id",
            "job_id",
            "worker_id",
            "artifact_id",
            "trace_id",
            "config_sha256",
            "resource_sha256",
            "transform_id",
        )
        assert job.correlation().trace_id == job.trace_id
        assert job.correlation(runtime.source_run_id).trace_id == job.trace_id
        assert job.correlation("telemetry-run-00").trace_id == correlation["trace_id"]
        assert correlation["trace_id"] != job.trace_id
        first_run_trace_ids.append(correlation["trace_id"])
        second_run_trace_ids.append(job.correlation("telemetry-run-01").trace_id)
    assert len(set(first_run_trace_ids)) == 6
    assert len(set(second_run_trace_ids)) == 6
    assert set(first_run_trace_ids).isdisjoint(second_run_trace_ids)


def test_report_contract_rejects_unversioned_fields(scenario: Path) -> None:
    report_path = scenario / "reports/validator-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["jobs"][0]["classification"] = "synthetic"
    _resign_report(scenario, report)
    with pytest.raises(ValueError, match="schema.*validation failed"):
        load_runtime_jobs(scenario)
    with pytest.raises(ValueError, match="schema.*validation failed"):
        load_candidate_binding(scenario)


def test_nested_report_field_cannot_smuggle_uncontracted_material(scenario: Path) -> None:
    report_path = scenario / "reports/validator-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["telemetry_events"][0]["oracle_association"] = {
        "affected_jobs": ["job-1"],
        "causal_explanation": "uncontracted",
    }
    _resign_report(scenario, report)
    with pytest.raises(ValueError, match="schema.*validation failed"):
        load_runtime_jobs(scenario)


def test_report_contract_rejects_wrong_ocio_version(scenario: Path) -> None:
    report_path = scenario / "reports/validator-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["ocio_version"] = "2.5.3"
    _resign_report(scenario, report)
    with pytest.raises(ValueError, match="schema.*validation failed"):
        load_runtime_jobs(scenario)


@pytest.mark.parametrize(
    "tamper",
    (
        "derivative-id",
        "derivative-state",
        "event-id",
        "event-overlap",
        "diff-path-and-digest",
        "resolved-reasons",
        "unresolved-reasons-empty",
        "unresolved-reason-mismatch",
        "diff-membership",
    ),
)
def test_schema_valid_nested_value_tampering_is_not_self_authenticating(
    scenario: Path, tamper: str
) -> None:
    report_path = scenario / "reports/validator-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if tamper == "derivative-id":
        report["derivatives"][0]["artifact_id"] = "schema-valid-covert-association"
    elif tamper == "derivative-state":
        report["derivatives"][0]["state"] = "reference_mismatch"
    elif tamper == "event-id":
        report["telemetry_events"][0]["event_id"] = "schema-valid-covert-event"
    elif tamper == "event-overlap":
        report["telemetry_events"][0]["overlapping_job_ids"] = ["job-1", "job-3"]
    elif tamper == "diff-path-and-digest":
        report["diff_images"][0]["path"] = report["diff_images"][1]["path"]
        report["diff_images"][0]["sha256"] = report["diff_images"][1]["sha256"]
    elif tamper == "resolved-reasons":
        report["jobs"][0]["reasons"] = ["missing-declared-reference"]
    elif tamper == "unresolved-reasons-empty":
        report["jobs"][0]["state"] = "unresolved"
        report["jobs"][0]["comparison"] = {
            "state": "unresolved",
            "reason": "missing-declared-reference",
        }
    elif tamper == "unresolved-reason-mismatch":
        report["jobs"][0]["state"] = "unresolved"
        report["jobs"][0]["comparison"] = {
            "state": "unresolved",
            "reason": "missing-declared-reference",
        }
        report["jobs"][0]["reasons"] = ["missing-resolved-resource-manifest"]
    elif tamper == "diff-membership":
        report["diff_images"].pop()
    else:  # pragma: no cover - the parameter list is closed above
        raise AssertionError(tamper)
    _resign_report(scenario, report)
    with pytest.raises(ValueError, match="projection|diff image|comparison"):
        load_runtime_jobs(scenario)
    if tamper == "derivative-id":
        with pytest.raises(ValueError, match="projection"):
            load_candidate_binding(scenario)


def test_fifty_run_delivery_matrix_is_observable_without_waiting(scenario: Path) -> None:
    runtime = load_runtime_jobs(scenario)
    plans = tuple(
        DeliveryPlan.build(runtime, case_index=index, run_id=f"telemetry-run-{index:02d}")
        for index in range(50)
    )
    assert all(len(plan.instructions) == 18 for plan in plans)
    for signal in ("metric", "log", "trace"):
        signal_outcomes = {
            row.outcome for plan in plans for row in plan.instructions if row.signal == signal
        }
        assert signal_outcomes == {
            "on_time",
            "late",
            "duplicate",
            "missing",
        }
    late = [row for plan in plans for row in plan.instructions if row.outcome == "late"]
    assert late
    assert all(11_000 <= row.delay_ms <= 40_000 for row in late)

    sink = MemorySink()
    receipt = emit_plans(runtime, plans, sink)
    assert len(receipt["runs"]) == 50
    for event in sink.events:
        if event["delivery_delay_ms"]:
            scheduled = datetime.fromisoformat(event["scheduled_at"].replace("Z", "+00:00"))
            emitted = datetime.fromisoformat(event["emitted_at"].replace("Z", "+00:00"))
            assert int((emitted - scheduled).total_seconds() * 1000) >= 11_000


def test_no_grafana_is_candidate_bound_and_fact_free(scenario: Path) -> None:
    candidate = load_candidate_binding(scenario)
    result = observe_without_grafana(
        BackendEndpoints(*("http://127.0.0.1:1" for _ in range(5))),
        candidate,
        "0" * 64,
    )
    assert result["candidate"]["correlation_contract"] == CORRELATION_VERSION
    assert result["candidate"]["source_fixture_manifest_sha256"] == sha256_file(
        scenario / "runtime/manifests/fixture-runtime-manifest.json"
    )
    assert result["outcome"] == "unavailable"
    assert result["decisive_operational_facts"] == []


def test_telemetry_process_has_no_private_fixture_mount() -> None:
    receipt = telemetry_isolation_receipt()
    assert receipt["private_probe_read_outcome"] == "not-mounted"
    assert receipt["workspace_truth_material_paths"] == []
    assert receipt["pass"] is True


def test_no_grafana_rejects_reachable_plain_text_backend(scenario: Path) -> None:
    class ReadyHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ready")

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), ReadyHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with pytest.raises(ValueError, match="unexpectedly reached"):
            observe_without_grafana(
                BackendEndpoints(*(base for _ in range(5))),
                load_candidate_binding(scenario),
                "0" * 64,
            )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


class _ReadinessClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_grafana_readiness_waits_for_delayed_ruler_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _ReadinessClock()
    paths: list[str] = []

    def delayed_get(
        base: str,
        path: str,
        *,
        query: object = None,
        timeout_seconds: float = 5.0,
    ) -> dict[str, object]:
        del base, query, timeout_seconds
        paths.append(path)
        if path == "/api/ruler/grafana/api/v1/rules":
            if paths.count(path) == 1:
                return {}
            return _ready_ruler_payload()
        return {}

    monkeypatch.setattr(observer, "_json_get", delayed_get)
    endpoints = BackendEndpoints(*(f"http://127.0.0.1:{port}" for port in range(1, 6)))

    wait_for_grafana_readiness(
        endpoints,
        timeout_seconds=2.0,
        poll_seconds=0.25,
        monotonic=clock.monotonic,
        sleep=clock.sleep,
    )

    assert paths == [
        "/api/health",
        "/api/ruler/grafana/api/v1/rules",
        "/api/health",
        "/api/ruler/grafana/api/v1/rules",
        "/api/health",
        "/api/ruler/grafana/api/v1/rules",
        "/api/health",
        "/api/ruler/grafana/api/v1/rules",
    ]
    assert clock.sleeps == [0.25, 0.25, 0.25]


def test_grafana_readiness_timeout_is_bounded_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _ReadinessClock()
    calls = 0

    def unavailable_get(*args: object, **kwargs: object) -> object:
        nonlocal calls
        del args, kwargs
        calls += 1
        raise BackendUnavailable("backend unavailable: http://user:secret@example.invalid/private")

    monkeypatch.setattr(observer, "_json_get", unavailable_get)
    endpoints = BackendEndpoints(*(f"http://127.0.0.1:{port}" for port in range(1, 6)))

    with pytest.raises(
        BackendUnavailable,
        match=(
            r"^Grafana readiness gate timed out "
            r"\(target_rule_count=unavailable, observed_intervals=unavailable\)$"
        ),
    ) as error:
        wait_for_grafana_readiness(
            endpoints,
            timeout_seconds=0.5,
            poll_seconds=0.2,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

    assert clock.now == pytest.approx(0.5)
    assert calls == 3
    assert "secret" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_grafana_readiness_timeout_reports_target_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _ReadinessClock()

    def wrong_interval_get(
        base: str,
        path: str,
        *,
        query: object = None,
        timeout_seconds: float = 5.0,
    ) -> object:
        del base, query, timeout_seconds
        return _ready_ruler_payload(interval="60s") if path.endswith("/rules") else {}

    monkeypatch.setattr(observer, "_json_get", wrong_interval_get)
    endpoints = BackendEndpoints(*(f"http://127.0.0.1:{port}" for port in range(1, 6)))

    with pytest.raises(
        BackendUnavailable,
        match=(
            r"^Grafana readiness gate timed out "
            r"\(target_rule_count=1, observed_intervals=60s\)$"
        ),
    ):
        wait_for_grafana_readiness(
            endpoints,
            timeout_seconds=0.5,
            poll_seconds=0.2,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )


def test_grafana_readiness_uses_only_exact_grafana_api_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []

    def available_get(
        base: str,
        path: str,
        *,
        query: object = None,
        timeout_seconds: float = 5.0,
    ) -> object:
        del query
        assert 0 < timeout_seconds <= 5.0
        calls.append((base, path))
        return _ready_ruler_payload() if path.endswith("/rules") else {}

    monkeypatch.setattr(observer, "_json_get", available_get)
    endpoints = BackendEndpoints(
        otlp="http://otlp.invalid",
        prometheus="http://prometheus.invalid",
        loki="http://loki.invalid",
        tempo="http://tempo.invalid",
        grafana="http://grafana.invalid",
    )

    wait_for_grafana_readiness(endpoints, required_consecutive_matches=1)

    assert calls == [
        ("http://grafana.invalid", "/api/health"),
        ("http://grafana.invalid", "/api/ruler/grafana/api/v1/rules"),
    ]


def test_integration_admits_readiness_before_one_shot_emission_and_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[str] = []
    runtime = object()
    plans: tuple[object, ...] = ()
    receipt: dict[str, Any] = {"runs": []}
    report: dict[str, Any] = {}

    def readiness(endpoints: BackendEndpoints, **kwargs: object) -> None:
        del endpoints
        assert kwargs == {"stack_config_path": Path("config/telemetry/local-stack.json")}
        calls.append("readiness")

    def emit(runtime_value: object, plans_value: object, sink: object) -> dict[str, Any]:
        del sink
        assert runtime_value is runtime
        assert plans_value is plans
        calls.append("emit")
        return receipt

    def verify(
        receipt_value: object, endpoints: BackendEndpoints, **kwargs: object
    ) -> dict[str, Any]:
        del endpoints, kwargs
        assert receipt_value is receipt
        calls.append("verify")
        return report

    monkeypatch.setattr(telemetry_cli, "_plans", lambda scenario, runs: (runtime, plans))
    monkeypatch.setattr(telemetry_cli, "wait_for_grafana_readiness", readiness)
    monkeypatch.setattr(telemetry_cli, "OtelSink", lambda endpoint: object())
    monkeypatch.setattr(telemetry_cli, "emit_plans", emit)
    monkeypatch.setattr(telemetry_cli, "verify_real_backends", verify)
    monkeypatch.setattr(telemetry_cli, "_write", lambda path, value: None)

    assert (
        telemetry_cli.main(
            [
                "integration",
                "--scenario",
                str(tmp_path / "scenario"),
                "--isolation-receipt",
                str(tmp_path / "isolation.json"),
            ]
        )
        == 0
    )
    assert calls == ["readiness", "emit", "verify"]


def test_local_stack_and_alert_contracts_are_pinned() -> None:
    stack = json.loads(
        (REPOSITORY_ROOT / "config/telemetry/local-stack.json").read_text(encoding="utf-8")
    )
    assert stack["scope"] == "local-50-run-backend-suite-only"
    assert stack["contracts"]["alert"] == "grafana-alert-contract/v1"
    assert stack["components"]["grafana"] == "13.1.1"
    assert stack["live_target"] == {
        "grafana": "13.2.0",
        "scheduler_source_revision": "6197d8e5f34898d2c8e4108f927b48ca8255b722",
        "required_scheduler_interval_seconds": 60,
        "local_live_parity_claimed": False,
        "unsupported_drift_outcome": "unresolved",
    }
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "config/telemetry/compose.yaml").read_text(encoding="utf-8")
    )
    image = compose["services"]["telemetry-backend"]["image"]
    assert image.endswith(
        "@sha256:bb182ac3174a20923fa58f00d1790fa71eb06cc0150078c0b0e8feb9e6611492"
    )
    alert = yaml.safe_load(
        (REPOSITORY_ROOT / "config/telemetry/grafana-alerting.yaml").read_text(encoding="utf-8")
    )
    group = alert["groups"][0]
    rule = group["rules"][0]
    expression = rule["data"][0]["model"]["expr"]
    assert group["interval"] == "10s"
    assert rule["for"] == "10s"
    assert rule["noDataState"] == "NoData"
    assert rule["execErrState"] == "Error"
    assert "executionErrorState" not in rule
    assert [query["queryType"] for query in rule["data"]] == ["", "", ""]
    for query in rule["data"][1:]:
        assert query["model"]["intervalMs"] == 1000
        assert query["model"]["maxDataPoints"] == 43200
    assert rule["data"][0]["relativeTimeRange"] == {"from": 600, "to": 0}
    assert "colortrace_declared_reference_observations_total" in expression
    assert 'declared_reference_state="reference_mismatch"' in expression
    assert "resource_sha256" not in expression
    alert_contract = json.loads(
        (REPOSITORY_ROOT / "config/telemetry/alert-contract.json").read_text(encoding="utf-8")
    )
    query_templates = json.loads(
        (REPOSITORY_ROOT / "config/telemetry/query-templates.json").read_text(encoding="utf-8")
    )
    scheduler_interval = alert_contract["scheduler_interval_seconds"]
    pending_period = alert_contract["pending_period_seconds"]
    assert scheduler_interval == stack["verification"]["alert_scheduler_interval_seconds"]
    assert scheduler_interval == query_templates["alert"]["scheduler_interval_seconds"]
    assert group["interval"] == f"{scheduler_interval}s"
    assert rule["for"] == f"{pending_period}s"
    assert stack["verification"]["late_minimum_milliseconds"] > scheduler_interval * 1000
    validate_schema("grafana-alert-contract-v1.schema.json", alert_contract)


def test_grafana_alert_contract_binds_interval_to_exact_rule_group(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = json.loads(
        (REPOSITORY_ROOT / "config/telemetry/alert-contract.json").read_text(encoding="utf-8")
    )
    alert = yaml.safe_load(
        (REPOSITORY_ROOT / "config/telemetry/grafana-alerting.yaml").read_text(encoding="utf-8")
    )
    provisioned_rule = alert["groups"][0]["rules"][0]
    ruler_groups = {
        "ColorTrace": [
            {
                "interval": "10s",
                "rules": [{"grafana_alert": {"uid": "unrelated-rule"}}],
            },
            {
                "interval": "60s",
                "rules": [{"grafana_alert": {"uid": contract["uid"]}}],
            },
        ]
    }

    def grafana_get(base: str, path: str, **kwargs: object) -> object:
        del base
        assert kwargs == {"timeout_seconds": 15.0}
        if path.startswith("/api/v1/provisioning/alert-rules/"):
            return provisioned_rule
        assert path == "/api/ruler/grafana/api/v1/rules"
        return ruler_groups

    monkeypatch.setattr(observer, "_json_get", grafana_get)
    endpoints = BackendEndpoints(*(f"http://127.0.0.1:{port}" for port in range(1, 6)))
    with pytest.raises(
        AssertionError,
        match=(
            r"scheduler interval differs from its contract "
            r"\(target_rule_count=1, observed_intervals=60s\)"
        ),
    ):
        observer._alert_contract(endpoints, contract)


def test_grafana_alert_contract_rejects_pending_period_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contract = json.loads(
        (REPOSITORY_ROOT / "config/telemetry/alert-contract.json").read_text(encoding="utf-8")
    )
    alert = yaml.safe_load(
        (REPOSITORY_ROOT / "config/telemetry/grafana-alerting.yaml").read_text(encoding="utf-8")
    )
    provisioned_rule = alert["groups"][0]["rules"][0]
    provisioned_rule["for"] = "0s"

    monkeypatch.setattr(
        observer,
        "_json_get",
        lambda *args, **kwargs: provisioned_rule,
    )
    endpoints = BackendEndpoints(*(f"http://127.0.0.1:{port}" for port in range(1, 6)))
    with pytest.raises(AssertionError, match="pending period differs"):
        observer._alert_contract(endpoints, contract)


@pytest.mark.parametrize(
    "state_fields",
    (
        {"executionErrorState": "Error"},
        {"execErrState": "Alerting"},
    ),
    ids=("unsupported-field", "default-state"),
)
def test_grafana_alert_contract_rejects_execution_error_state_drift(
    monkeypatch: pytest.MonkeyPatch, state_fields: dict[str, str]
) -> None:
    contract = json.loads(
        (REPOSITORY_ROOT / "config/telemetry/alert-contract.json").read_text(encoding="utf-8")
    )
    rule = {
        "uid": contract["uid"],
        "noDataState": contract["no_data_state"],
        **state_fields,
    }
    monkeypatch.setattr(observer, "_json_get", lambda *args, **kwargs: rule)
    endpoints = BackendEndpoints(*(f"http://127.0.0.1:{port}" for port in range(1, 6)))
    with pytest.raises(AssertionError, match="execution errors"):
        observer._alert_contract(endpoints, contract)


def test_grafana_managed_rule_firing_shape_is_recognized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    labels = {
        field: "synthetic"
        for field in (
            "fixture_id",
            "run_id",
            "job_id",
            "worker_id",
            "artifact_id",
            "trace_id",
            "config_sha256",
            "transform_id",
        )
    }
    labels["fixture_id"] = "ct-shadowed-lut-v1"
    labels["run_id"] = "telemetry-run-00"
    payload = {
        "data": {
            "groups": [
                {
                    "rules": [
                        {
                            "name": "ColorTrace declared-reference visual divergence",
                            "state": "firing",
                            "alerts": [{"labels": labels, "state": "Alerting"}],
                        }
                    ]
                }
            ]
        }
    }
    monkeypatch.setattr(observer, "_json_get", lambda *args, **kwargs: payload)
    endpoints = BackendEndpoints(*(f"http://127.0.0.1:{port}" for port in range(1, 6)))
    assert observer._wait_alert_firing(endpoints, 0.1) is True
