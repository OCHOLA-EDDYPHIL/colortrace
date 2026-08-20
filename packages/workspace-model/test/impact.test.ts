import { describe, expect, it } from "vitest";

import { projectFixtureImpact } from "../src/impact.ts";
import { projectIncidentReplay } from "../src/project.ts";
import type { ImpactRecoveryRecord } from "../src/impact.ts";
import { canonicalReplayFixture, cloneReplayFixture } from "./fixtures.ts";

const recovery: ImpactRecoveryRecord = {
  incident_id: canonicalReplayFixture.incident.incident_id,
  outcome_id: "simulator-action-outcome:recorded",
  packet_id: "recovery-packet:recorded",
  action_started_at: "2026-08-13T12:01:00.000Z",
  evaluation_completed_at: "2026-08-13T12:02:30.250Z",
  command_outcomes: [
    { result_kind: "quarantine" },
    { result_kind: "frame" },
    { result_kind: "frame" },
    { result_kind: "frame" },
    { result_kind: "derivative" },
  ],
};

describe("projectFixtureImpact", () => {
  it("calculates the golden fixture only from bound recorded values", () => {
    const report = projectFixtureImpact(projectIncidentReplay(canonicalReplayFixture), recovery);

    expect(report).toMatchInlineSnapshot(`
      {
        "bindings": {
          "recovery_outcome_id": "simulator-action-outcome:recorded",
          "recovery_packet_id": "recovery-packet:recorded",
        },
        "hypothetical": {
          "assumption": "Every observed affected or verified-safe source frame would be rerendered once.",
          "name": "rerender-all-observed-source-frames",
          "source_frame_rerenders": {
            "unit": "items",
            "value": 6,
          },
          "source_frame_rerenders_avoided": {
            "unit": "items",
            "value": 3,
          },
        },
        "incident": {
          "id": "incident-canonical",
          "scope_policy": "single-causal-resource-scope/v1",
          "version": 3,
        },
        "limitations": [
          "Synthetic simulator fixture only; these values are not production benchmarks.",
          "Provider cost and compute time are not present in the incident or recovery records.",
        ],
        "observed": {
          "affected_derivatives": {
            "unit": "items",
            "value": 1,
          },
          "affected_frames": {
            "unit": "items",
            "value": 3,
          },
          "compute_time": {
            "unit": "milliseconds",
            "value": null,
          },
          "derivative_rerender_outcomes": {
            "unit": "items",
            "value": 1,
          },
          "frame_rerender_outcomes": {
            "unit": "items",
            "value": 3,
          },
          "investigation_elapsed": {
            "unit": "milliseconds",
            "value": 38000,
          },
          "provider_cost": {
            "unit": "USD",
            "value": null,
          },
          "recovery_elapsed": {
            "unit": "milliseconds",
            "value": 90250,
          },
          "verified_safe_frames": {
            "unit": "items",
            "value": 3,
          },
        },
        "policy": "fixture-observed-impact/v1",
        "schema": "fixture-impact-report/v1",
      }
    `);
  });

  it("keeps missing, invalid, and mismatched run values unknown", () => {
    const replay = cloneReplayFixture();
    const workspace = projectIncidentReplay({
      ...replay,
      packet: { ...replay.packet, finalized_at: "invalid" },
    });
    const mismatched = { ...recovery, incident_id: "another-incident" };

    const report = projectFixtureImpact(workspace, mismatched);

    expect(report.observed.investigation_elapsed.value).toBeNull();
    expect(report.observed.recovery_elapsed.value).toBeNull();
    expect(report.observed.frame_rerender_outcomes.value).toBeNull();
    expect(report.observed.provider_cost.value).toBeNull();
    expect(report.observed.compute_time.value).toBeNull();
    expect(report.hypothetical.source_frame_rerenders_avoided.value).toBeNull();
    expect(report.limitations).toContain(
      "The available recovery run belongs to a different incident.",
    );
  });

  it("rejects negative elapsed boundaries instead of inventing a duration", () => {
    const report = projectFixtureImpact(projectIncidentReplay(canonicalReplayFixture), {
      ...recovery,
      evaluation_completed_at: "2026-08-13T12:00:59.999Z",
    });

    expect(report.observed.recovery_elapsed.value).toBeNull();
  });
});
