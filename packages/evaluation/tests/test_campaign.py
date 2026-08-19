from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from colortrace_evaluation import campaign as subject
from colortrace_evaluation.campaign import (
    EvaluationError,
    aggregate_campaign,
    build_alert,
    build_campaign_plan,
    build_manual_no_gemini_control,
    build_no_grafana_control,
    build_run_record,
    prepare_fixture,
)
from colortrace_evaluation.contracts import canonical_json_bytes, prefixed_sha256

COMMIT = "1" * 40
TREE = "2" * 40
NOW = "2026-08-19T00:00:00Z"


def plan() -> dict[str, Any]:
    return build_campaign_plan(
        candidate_commit=COMMIT,
        candidate_tree=TREE,
        campaign_seed="phase3-reliability-01",
        created_at=NOW,
    )


def seal(body: dict[str, Any], id_key: str, prefix: str) -> dict[str, Any]:
    digest = prefixed_sha256(body)
    return {**body, id_key: f"{prefix}:{digest.removeprefix('sha256:')}", "sha256": digest}


def artifact(root: Path, relative: str, content: bytes) -> dict[str, str]:
    import hashlib

    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {"path": relative, "sha256": f"sha256:{hashlib.sha256(content).hexdigest()}"}


def json_artifact(root: Path, relative: str, value: dict[str, Any]) -> dict[str, str]:
    return artifact(root, relative, canonical_json_bytes(value) + b"\n")


def test_plan_predeclares_exact_coverage_and_randomized_order() -> None:
    first = plan()
    second = plan()
    assert first == second
    specs = first["specs"]
    assert len(specs) == 50
    assert len({item["spec_id"] for item in specs}) == 50
    assert {item["execution_order"] for item in specs} == set(range(1, 51))
    assert Counter(item["family"] for item in specs) == {
        "canonical": 10,
        "hidden": 20,
        "missing-resource": 8,
        "missing-reference": 6,
        "recovery-failure": 6,
    }
    assert [item["spec_id"] for item in specs] != [f"eval-{index:02d}" for index in range(1, 51)]
    assert all(item["coverage"][-2:] == ["model-sampled", "order-randomized"] for item in specs)


def test_plan_candidate_or_seal_drift_is_rejected(tmp_path: Path) -> None:
    value = plan()
    value["candidate"]["commit"] = "3" * 40
    with pytest.raises(EvaluationError, match="plan-digest-invalid"):
        aggregate_campaign(plan=value, records=[], controls=[], artifact_root=tmp_path)


def packet() -> dict[str, Any]:
    causal = "a" * 64
    return {
        "claims": [
            {
                "claim_type": "causal-resource",
                "subject": {"kind": "resource-sha256", "value": causal},
                "state": "confirmed",
                "policy": "deterministic-claim/v1",
                "reason_codes": [],
            },
            {
                "claim_type": "distractor",
                "subject": {"kind": "event-id", "value": "noise"},
                "state": "rejected",
                "policy": "deterministic-claim/v1",
                "reason_codes": ["non-causal"],
            },
        ],
        "scope": {
            "state": "resolved",
            "policy": "single-causal-resource-scope/v1",
            "affected": [
                {"kind": "frame", "id": "job-1"},
                {"kind": "derivative", "id": "derivative-1"},
            ],
            "safe": [{"kind": "frame", "id": "job-2"}],
            "unknown": [],
            "reason_codes": [],
        },
        "budget_use": {"trusted_transient_retries": 0},
    }


def test_run_record_recomputes_truth_metrics_and_binds_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subject, "validate_response_packet", lambda value: None)
    raw = tmp_path / "packet.json"
    raw.write_bytes(canonical_json_bytes(packet()) + b"\n")
    oracle = {
        "causal_resource_sha256": "a" * 64,
        "directly_affected_jobs": ["job-1"],
        "affected_derivatives": ["derivative-1"],
        "safe_jobs": ["job-2"],
    }
    observation = {
        "outcome": "resolved",
        "attempt": 1,
        "retry_count": 0,
        "trace_correlation_failure": False,
        "unsupported_diagnoses": [],
        "unauthorized_actions": 0,
        "duplicate_actions": 0,
        "primary_action_count": 1,
        "replay_action_count": 0,
    }
    oracle_path = tmp_path / "oracle.json"
    oracle_path.write_bytes(canonical_json_bytes(oracle) + b"\n")
    observation_path = tmp_path / "observation.json"
    observation_path.write_bytes(canonical_json_bytes(observation) + b"\n")
    value = plan()
    canonical_spec = next(item for item in value["specs"] if item["family"] == "canonical")
    observation.update(
        {
            "schema": "reliability-run-observation/v1",
            "plan_sha256": value["sha256"],
            "spec_id": canonical_spec["spec_id"],
            "candidate": value["candidate"],
            "sources": {
                "execution_sha256": "sha256:" + "1" * 64,
                "replay_sha256": "sha256:" + "2" * 64,
                "action_evidence_sha256": None,
                "recovery_aggregate_sha256": None,
            },
        }
    )
    observation_path.write_bytes(canonical_json_bytes(observation) + b"\n")
    record = build_run_record(
        plan=value,
        spec_id=canonical_spec["spec_id"],
        packet=packet(),
        oracle=oracle,
        observation=observation,
        run_root=tmp_path,
        packet_path=raw,
        oracle_path=oracle_path,
        observation_path=observation_path,
        action_evidence_path=None,
        artifact_paths=[raw, oracle_path, observation_path],
        started_at=NOW,
        finished_at="2026-08-19T00:00:05Z",
    )
    assert record["metrics"]["root_cause"]["correct"] is True
    assert record["metrics"]["affected_precision"] == {"numerator": 2, "denominator": 2}
    assert record["metrics"]["safe_recall"] == {"numerator": 1, "denominator": 1}
    assert record["source_artifacts"]["packet"]["path"] == "packet.json"

    observation["retry_count"] = 1
    observation_path.write_bytes(canonical_json_bytes(observation) + b"\n")
    with pytest.raises(EvaluationError, match="retry-observation-mismatch"):
        build_run_record(
            plan=value,
            spec_id=canonical_spec["spec_id"],
            packet=packet(),
            oracle=oracle,
            observation=observation,
            run_root=tmp_path,
            packet_path=raw,
            oracle_path=oracle_path,
            observation_path=observation_path,
            action_evidence_path=None,
            artifact_paths=[raw, oracle_path, observation_path],
            started_at=NOW,
            finished_at="2026-08-19T00:00:05Z",
        )


def test_prepared_missing_evidence_fixture_is_bound_to_the_sealed_slot(tmp_path: Path) -> None:
    value = plan()
    spec = next(item for item in value["specs"] if item["family"] == "missing-resource")
    receipt = prepare_fixture(plan=value, spec_id=spec["spec_id"], campaign_root=tmp_path)
    assert receipt["plan_sha256"] == value["sha256"]
    assert receipt["execution_order"] == spec["execution_order"]
    assert len(receipt["artifacts"]) == 9
    assert all((tmp_path / item["path"]).is_file() for item in receipt["artifacts"])
    oracle = (tmp_path / receipt["oracle"] / "fixture-oracle.json").read_text()
    assert '"expected_unresolved_jobs":[' in oracle

    from colortrace_telemetry.contract import DeliveryPlan, load_runtime_jobs
    from colortrace_telemetry.emitter import MemorySink, emit_plans

    runtime = load_runtime_jobs(tmp_path / receipt["telemetry_bundle"])
    emission = emit_plans(
        runtime,
        (DeliveryPlan.build(runtime, case_index=0, run_id=f"run-{spec['spec_id']}"),),
        MemorySink(),
    )
    alert = build_alert(
        plan=value,
        spec_id=spec["spec_id"],
        emission_receipt=emission,
        binding={
            "prometheus_datasource_uid": "prometheus-main",
            "loki_datasource_uid": "loki-main",
            "tempo_datasource_uid": "tempo-main",
            "alert_rule_uid": "ct-alert-main",
        },
    )
    assert alert["incident_id"] == f"phase3-{spec['spec_id']}"
    assert alert["correlation_keys"]["run_id"] == f"run-{spec['spec_id']}"


def test_controls_recompute_quality_from_inspectable_observations(tmp_path: Path) -> None:
    value = plan()
    no_grafana = {
        "schema": "no-grafana-observation/v1",
        "candidate": {
            "fixture_id": "ct-shadowed-lut-v1",
            "source_run_id": "control-no-grafana",
            "correlation_contract": "correlation-contract/v1",
            "source_fixture_manifest_sha256": "a" * 64,
            "source_validator_report_sha256": "b" * 64,
        },
        "isolation_receipt_sha256": "c" * 64,
        "outcome": "unavailable",
        "signals": {
            "metric": "unavailable",
            "log": "unavailable",
            "trace": "unavailable",
            "alert": "unavailable",
        },
        "decisive_operational_facts": [],
    }
    no_grafana_path = tmp_path / "controls" / "no-grafana-observation.json"
    no_grafana_path.parent.mkdir(parents=True)
    no_grafana_path.write_bytes(canonical_json_bytes(no_grafana) + b"\n")
    no_grafana_control = build_no_grafana_control(
        plan=value,
        observation=no_grafana,
        observation_path=no_grafana_path,
        artifact_root=tmp_path,
        started_at=NOW,
        finished_at="2026-08-19T00:00:01Z",
    )
    assert no_grafana_control["provider_calls"] == {"vertex": 0, "grafana": 0}
    assert no_grafana_control["quality"]["decisive_operational_facts"] == 0

    expected = {
        "causal_resource_sha256": "d" * 64,
        "affected": [{"kind": "frame", "id": "job-1"}],
        "safe": [{"kind": "frame", "id": "job-2"}],
    }
    manual = {
        "schema": "manual-no-gemini-observation/v1",
        "candidate": value["candidate"],
        "started_at": NOW,
        "finished_at": "2026-08-19T00:02:00Z",
        "grafana_read_calls": 4,
        "expected": expected,
        "observed": expected,
        "decisive_operational_facts": ["The declared reference differs from the affected frame."],
        "limitations": ["One synthetic fixture was inspected by one human operator."],
    }
    manual_path = tmp_path / "controls" / "manual-observation.json"
    manual_path.write_bytes(canonical_json_bytes(manual) + b"\n")
    manual_control = build_manual_no_gemini_control(
        plan=value,
        observation=manual,
        observation_path=manual_path,
        artifact_root=tmp_path,
    )
    assert manual_control["operator_kind"] == "human"
    assert manual_control["elapsed_ms"] == 120_000
    assert manual_control["quality"] == {
        "root_cause_correct": True,
        "affected_scope_exact": True,
        "safe_scope_exact": True,
        "decisive_operational_facts": 1,
    }


def run_records(value: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for spec in value["specs"]:
        expected = spec["expected_outcome"]
        packet_value = {"schema": "test-packet/v1", "spec_id": spec["spec_id"]}
        oracle_value = {"schema": "test-oracle/v1", "spec_id": spec["spec_id"]}
        observation_value = {"schema": "test-observation/v1", "spec_id": spec["spec_id"]}
        packet_artifact = json_artifact(root, f"runs/{spec['spec_id']}/packet.json", packet_value)
        oracle_artifact = json_artifact(root, f"runs/{spec['spec_id']}/oracle.json", oracle_value)
        observation_artifact = json_artifact(
            root, f"runs/{spec['spec_id']}/observation.json", observation_value
        )
        body = {
            "schema": "reliability-run-record/v1",
            "plan_sha256": value["sha256"],
            "spec_id": spec["spec_id"],
            "execution_order": spec["execution_order"],
            "candidate": value["candidate"],
            "attempt": 1,
            "retry_count": 0,
            "started_at": NOW,
            "finished_at": "2026-08-19T00:00:05Z",
            "expected_outcome": expected,
            "observed_outcome": expected,
            "outcome_matches": True,
            "metrics": {
                "root_cause": {"expected": "a" * 64, "observed": "a" * 64, "correct": True},
                "affected_precision": {"numerator": 4, "denominator": 4},
                "affected_recall": {"numerator": 4, "denominator": 4},
                "safe_precision": {"numerator": 3, "denominator": 3},
                "safe_recall": {"numerator": 3, "denominator": 3},
                "trace_correlation_failure": False,
                "unsupported_diagnoses": [],
                "unauthorized_actions": 0,
                "duplicate_actions": 0,
                "primary_action_count": 1 if expected == "resolved" else 0,
                "replay_action_count": 0,
                "confirmed_facts_sha256": (
                    "sha256:" + ("b" * 64 if spec["family"] == "canonical" else spec["order_key"])
                ),
            },
            "packet_sha256": prefixed_sha256(packet_value),
            "oracle_sha256": prefixed_sha256(oracle_value),
            "observation_sha256": prefixed_sha256(observation_value),
            "action_evidence_sha256": None,
            "source_artifacts": {
                "packet": packet_artifact,
                "oracle": oracle_artifact,
                "observation": observation_artifact,
                "action_evidence": None,
            },
            "artifacts": [packet_artifact, oracle_artifact, observation_artifact],
        }
        records.append(seal(body, "record_id", "reliability-run"))
    return records


def controls(root: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for kind, outcome in (("manual-no-gemini", "resolved"), ("no-grafana", "unavailable")):
        body = {
            "schema": "reliability-control-record/v1",
            "kind": kind,
            "candidate": {"commit": COMMIT, "tree": TREE},
            "operator_kind": "automation-assisted",
            "started_at": NOW,
            "finished_at": "2026-08-19T00:00:03Z",
            "elapsed_ms": 3000,
            "outcome": outcome,
            "quality": {
                "root_cause_correct": kind == "manual-no-gemini",
                "affected_scope_exact": kind == "manual-no-gemini",
                "safe_scope_exact": kind == "manual-no-gemini",
                "decisive_operational_facts": 4 if kind == "manual-no-gemini" else 0,
            },
            "provider_calls": {"vertex": 0, "grafana": 4 if kind == "manual-no-gemini" else 0},
            "limitations": ["Automation-assisted measurement; no human timing claim is made."],
            "artifacts": [artifact(root, f"controls/{kind}.json", kind.encode())],
        }
        values.append(seal(body, "control_id", "reliability-control"))
    return values


def test_aggregate_recomputes_all_thresholds_and_rejects_cherry_picking(
    tmp_path: Path,
) -> None:
    value = plan()
    records = run_records(value, tmp_path)
    control_records = controls(tmp_path)
    report = aggregate_campaign(
        plan=value,
        records=records,
        controls=control_records,
        artifact_root=tmp_path,
    )
    assert report["pass"] is True
    assert report["run_count"] == 50
    assert all(report["checks"].values())

    with pytest.raises(EvaluationError, match="campaign-record-set-incomplete"):
        aggregate_campaign(
            plan=value,
            records=records[:-1],
            controls=control_records,
            artifact_root=tmp_path,
        )


def test_aggregate_reports_failure_without_hiding_the_records(tmp_path: Path) -> None:
    value = plan()
    records = run_records(value, tmp_path)
    for index in (0, 1):
        body = {
            key: item for key, item in records[index].items() if key not in {"record_id", "sha256"}
        }
        body["metrics"]["trace_correlation_failure"] = True
        records[index] = seal(body, "record_id", "reliability-run")
    report = aggregate_campaign(
        plan=value,
        records=records,
        controls=controls(tmp_path),
        artifact_root=tmp_path,
    )
    assert report["pass"] is False
    assert report["observations"]["trace_correlation_failures"] == 2
    assert report["checks"]["trace_correlation_within_limit"] is False
    assert len(report["record_sha256s"]) == 50


def test_canonical_confirmed_fact_instability_fails(tmp_path: Path) -> None:
    value = plan()
    records = run_records(value, tmp_path)
    canonical_id = next(item["spec_id"] for item in value["specs"] if item["family"] == "canonical")
    index = next(index for index, item in enumerate(records) if item["spec_id"] == canonical_id)
    body = {key: item for key, item in records[index].items() if key not in {"record_id", "sha256"}}
    body["metrics"]["confirmed_facts_sha256"] = "sha256:" + "9" * 64
    records[index] = seal(body, "record_id", "reliability-run")
    report = aggregate_campaign(
        plan=value,
        records=records,
        controls=controls(tmp_path),
        artifact_root=tmp_path,
    )
    assert report["pass"] is False
    assert report["checks"]["confirmed_facts_stable"] is False


def test_aggregate_reopens_named_sources_and_rejects_post_record_tamper(tmp_path: Path) -> None:
    value = plan()
    records = run_records(value, tmp_path)
    source = tmp_path / records[0]["source_artifacts"]["packet"]["path"]
    source.write_bytes(b"{}\n")
    with pytest.raises(EvaluationError, match="artifact-digest-invalid"):
        aggregate_campaign(
            plan=value,
            records=records,
            controls=controls(tmp_path),
            artifact_root=tmp_path,
        )


def test_strict_json_rejects_duplicate_keys(tmp_path: Path) -> None:
    from colortrace_evaluation.contracts import ContractError, strict_json_file

    path = tmp_path / "duplicate.json"
    path.write_text('{"value":1,"value":2}\n', encoding="utf-8")
    with pytest.raises(ContractError, match="duplicate-json-key"):
        strict_json_file(path)
