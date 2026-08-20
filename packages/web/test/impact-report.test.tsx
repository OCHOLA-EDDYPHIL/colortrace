import { projectFixtureImpact, projectIncidentReplay } from "@colortrace/workspace-model";
import { canonicalReplayFixture } from "@colortrace/workspace-model/test-fixtures";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { formatImpactCount, formatImpactDuration, ImpactReport } from "../src/impact-report.tsx";

const report = projectFixtureImpact(projectIncidentReplay(canonicalReplayFixture), {
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
});

afterEach(cleanup);

describe("ImpactReport", () => {
  it("visually and semantically separates observed records from the hypothetical", () => {
    render(<ImpactReport report={report} />);

    const observed = screen
      .getByRole("heading", { name: "Recorded incident and run values" })
      .closest("section");
    const hypothetical = screen
      .getByRole("heading", { name: "Rerender every observed source frame" })
      .closest("aside");
    expect(observed).toHaveClass("impact-report__observed");
    expect(hypothetical).toHaveClass("impact-report__hypothetical");
    expect(within(observed as HTMLElement).getAllByText("3", { selector: "dd" })).toHaveLength(3);
    expect(within(hypothetical as HTMLElement).getByText("Hypothetical comparison")).toBeVisible();
    expect(hypothetical).toHaveTextContent("not an observed cost, time saving");
  });

  it("keeps absent cost and compute time visibly unknown", () => {
    render(<ImpactReport report={report} />);

    const providerCost = screen.getByText("Provider cost").closest("div");
    const computeTime = screen.getByText("Compute time").closest("div");
    expect(providerCost).toHaveTextContent("Not recorded");
    expect(computeTime).toHaveTextContent("Not recorded");
  });

  it("makes calculation rules, record bindings, and limitations inspectable", () => {
    render(<ImpactReport report={report} />);

    expect(screen.getByText("Calculation policy, bindings, and limitations")).toBeVisible();
    expect(screen.getByText("fixture-observed-impact/v1")).toBeInTheDocument();
    expect(screen.getByText("simulator-action-outcome:recorded")).toBeInTheDocument();
    expect(screen.getByText(/not production benchmarks/i)).toBeInTheDocument();
  });

  it("uses explicit units and deterministic rounding", () => {
    expect(formatImpactCount(12_345)).toBe("12,345");
    expect(formatImpactCount(null)).toBe("Not recorded");
    expect(formatImpactDuration(999)).toBe("999 ms");
    expect(formatImpactDuration(1_000)).toBe("1 s");
    expect(formatImpactDuration(90_250)).toBe("90.3 s");
    expect(formatImpactDuration(null)).toBe("Not recorded");
  });

  it("locks claim copy to fixture-level facts and explicit caveats", () => {
    const { container } = render(<ImpactReport report={report} />);
    const copy = container.textContent?.replaceAll(/\s+/gu, " ").trim();

    expect(copy).toMatchInlineSnapshot(
      `"Synthetic fixture reportIncident-level impactNot a production benchmarkThese figures describe this recorded simulator incident only. Missing measurements remain unknown.Observed recordsRecorded incident and run valuesAffected frames3Verified-safe frames3Affected derivatives1Frame rerender outcomes3Derivative rerender outcomes1Investigation elapsed38 sRecovery elapsed90.3 sProvider costNot recordedCompute timeNot recordedHypothetical comparisonRerender every observed source frameEvery observed affected or verified-safe source frame would be rerendered once.Assumed source-frame rerenders6Rerenders avoided under assumption3This arithmetic is not an observed cost, time saving, or production forecast.Calculation policy, bindings, and limitationsCalculation policyPolicyfixture-observed-impact/v1Observed scopeCount deterministic scope nodes only when scope is resolved and parity is verified.Observed rerendersCount persisted simulator command outcomes by result kind; do not infer unrecorded work.Elapsed timeSubtract incident.created_at from incident.finalized_at only when both are valid ordered timestamps. Subtract action_started_at from evaluation_completed_at only for a recovery record bound to the same incident.Unknown valuesKeep absent cost, compute-time, timestamp, scope, and run values null.Display unitsRetain durations as integer milliseconds; display seconds rounded to the nearest tenth only when needed.Recorded bindingsIncidentincident-canonical@v3Scope policysingle-causal-resource-scope/v1Recovery outcomesimulator-action-outcome:recordedRecovery packetrecovery-packet:recordedLimitationsSynthetic simulator fixture only; these values are not production benchmarks.Provider cost and compute time are not present in the incident or recovery records."`,
    );
    expect(copy).not.toMatch(/\bROI\b|industry-wide|annual savings|energy reduction/iu);
  });
});
