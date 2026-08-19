from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from colortrace_evaluation import action_runner as subject
from colortrace_evaluation.action_runner import execute_recovery_failure_case
from colortrace_evaluation.campaign import build_campaign_plan
from colortrace_evaluation.contracts import canonical_json_bytes
from colortrace_fixture import CANONICAL_SEED, build_scenario
from colortrace_simulator.bundle import LocalPublicationPort


def _plan() -> dict[str, Any]:
    return build_campaign_plan(
        candidate_commit="1" * 40,
        candidate_tree="2" * 40,
        campaign_seed="action-runner-test",
        created_at="2026-08-19T00:00:00Z",
    )


def test_recovery_case_composes_native_authority_action_replay_and_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "runtime-bundle"
    build_scenario(
        bundle,
        oracle_root=tmp_path / "offline-oracle",
        variant_id="action-runner",
        seed=CANONICAL_SEED,
    )
    preview = LocalPublicationPort.bootstrap(
        root=tmp_path / "preview-publication",
        fixture_bundle=bundle,
    ).canonical_plan_inputs()
    affected = [
        {"kind": target["kind"], "id": target["id"]}
        for target in preview["targets"]
        if target["kind"] != "color-resource"
    ]
    safe = [{"kind": target["kind"], "id": target["id"]} for target in preview["exclusions"]]
    causal = next(
        target["id"] for target in preview["targets"] if target["kind"] == "color-resource"
    ).removeprefix("sha256:")
    replay = {
        "schema": "incident-replay/v1",
        "incident": {
            "incident_id": "phase3-recovery-test",
            "status": "resolved",
            "version": 3,
        },
        "packet": {
            "packet_id": "response-packet:" + "b" * 64,
            "incident_id": "phase3-recovery-test",
            "status": "resolved",
            "derivation_sha256": "sha256:" + "b" * 64,
            "candidate_plan": {"targets": affected},
            "scope": {
                "state": "resolved",
                "policy": "single-causal-resource-scope/v1",
                "affected": affected,
                "safe": safe,
                "unknown": [],
                "reason_codes": [],
            },
            "unresolved_items": [],
        },
        "validator_results": [{"scope": {"causal_resource_sha256": causal}}],
    }
    replay_path = tmp_path / "replay.json"
    replay_path.write_bytes(canonical_json_bytes(replay) + b"\n")
    run_root = tmp_path / "run"
    run_root.mkdir()
    monkeypatch.setattr(subject, "validate_replay", lambda value: None)
    value = _plan()
    spec = next(item for item in value["specs"] if item["family"] == "recovery-failure")

    evidence = execute_recovery_failure_case(
        plan=value,
        spec_id=spec["spec_id"],
        replay_path=replay_path,
        fixture_bundle=bundle,
        run_root=run_root,
        query_catalog_path=Path("config/grafana-mcp/query-catalog.json"),
    )

    assert (
        evidence["response_plan_proof"]["plan"]["response_packet_sha256"]
        == (replay["packet"]["derivation_sha256"])
    )
    assert evidence["simulator"]["primary_outcome"]["status"] == "succeeded"
    assert evidence["simulator"]["primary_outcome"] == evidence["simulator"]["replay_outcome"]
    assert evidence["simulator"]["admission"]["executor_actor"]["kind"] == "service"
    assert evidence["recovery_aggregate"]["packet"]["status"] == "recovery_unresolved"
