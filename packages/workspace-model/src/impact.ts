import type { InvestigationWorkspace } from "./types.ts";

export const FIXTURE_IMPACT_CALCULATION_POLICY = {
  schema: "fixture-impact-calculation-policy/v1",
  policy_id: "fixture-observed-impact/v1",
  observed_scope:
    "Count deterministic scope nodes only when scope is resolved and parity is verified.",
  observed_rerenders:
    "Count persisted simulator command outcomes by result kind; do not infer unrecorded work.",
  investigation_elapsed:
    "Subtract incident.created_at from incident.finalized_at only when both are valid ordered timestamps.",
  recovery_elapsed:
    "Subtract action_started_at from evaluation_completed_at only for a recovery record bound to the same incident.",
  counterfactual:
    "Assume every observed affected or verified-safe source frame would be rerendered; subtract recorded frame rerender outcomes.",
  unknowns: "Keep absent cost, compute-time, timestamp, scope, and run values null.",
  display_rounding:
    "Retain durations as integer milliseconds; display seconds rounded to the nearest tenth only when needed.",
} as const;

export type ImpactRecoveryRecord = {
  readonly incident_id: string;
  readonly outcome_id: string;
  readonly packet_id: string | null;
  readonly action_started_at: string;
  readonly evaluation_completed_at: string | null;
  readonly command_outcomes: readonly {
    readonly result_kind: "derivative" | "frame" | "quarantine";
  }[];
};

type CountMetric = {
  readonly unit: "items";
  readonly value: number | null;
};

type DurationMetric = {
  readonly unit: "milliseconds";
  readonly value: number | null;
};

type CostMetric = {
  readonly unit: "USD";
  readonly value: null;
};

export type FixtureImpactReport = {
  readonly schema: "fixture-impact-report/v1";
  readonly policy: "fixture-observed-impact/v1";
  readonly incident: {
    readonly id: string;
    readonly version: number;
    readonly scope_policy: string;
  };
  readonly bindings: {
    readonly recovery_outcome_id: string | null;
    readonly recovery_packet_id: string | null;
  };
  readonly observed: {
    readonly affected_frames: CountMetric;
    readonly affected_derivatives: CountMetric;
    readonly verified_safe_frames: CountMetric;
    readonly frame_rerender_outcomes: CountMetric;
    readonly derivative_rerender_outcomes: CountMetric;
    readonly investigation_elapsed: DurationMetric;
    readonly recovery_elapsed: DurationMetric;
    readonly provider_cost: CostMetric;
    readonly compute_time: DurationMetric;
  };
  readonly hypothetical: {
    readonly name: "rerender-all-observed-source-frames";
    readonly assumption: string;
    readonly source_frame_rerenders: CountMetric;
    readonly source_frame_rerenders_avoided: CountMetric;
  };
  readonly limitations: readonly string[];
};

function elapsedMilliseconds(start: string, end: string): number | null {
  const startValue = Date.parse(start);
  const endValue = Date.parse(end);
  if (!Number.isFinite(startValue) || !Number.isFinite(endValue) || endValue < startValue) {
    return null;
  }
  return endValue - startValue;
}

export function projectFixtureImpact(
  workspace: InvestigationWorkspace,
  recovery: ImpactRecoveryRecord | null,
): FixtureImpactReport {
  const scopeVerified =
    workspace.scope.state === "resolved" && workspace.scope.parity.status === "verified";
  const affectedFrames = scopeVerified
    ? workspace.scope.nodes.filter(
        (node) => node.kind === "frame" && node.classification === "affected",
      ).length
    : null;
  const affectedDerivatives = scopeVerified
    ? workspace.scope.nodes.filter(
        (node) => node.kind === "derivative" && node.classification === "affected",
      ).length
    : null;
  const safeFrames = scopeVerified
    ? workspace.scope.nodes.filter(
        (node) => node.kind === "frame" && node.classification === "safe",
      ).length
    : null;
  const matchingRecovery = recovery?.incident_id === workspace.incident.id ? recovery : null;
  const frameRerenders =
    matchingRecovery === null
      ? null
      : matchingRecovery.command_outcomes.filter((outcome) => outcome.result_kind === "frame")
          .length;
  const derivativeRerenders =
    matchingRecovery === null
      ? null
      : matchingRecovery.command_outcomes.filter((outcome) => outcome.result_kind === "derivative")
          .length;
  const counterfactualTotal =
    affectedFrames === null || safeFrames === null ? null : affectedFrames + safeFrames;
  const counterfactualAvoided =
    counterfactualTotal === null || frameRerenders === null || frameRerenders > counterfactualTotal
      ? null
      : counterfactualTotal - frameRerenders;
  const limitations = [
    "Synthetic simulator fixture only; these values are not production benchmarks.",
    "Provider cost and compute time are not present in the incident or recovery records.",
  ];
  if (!scopeVerified) limitations.push("Deterministic scope is not resolved with verified parity.");
  if (recovery === null) limitations.push("No persisted recovery run is available.");
  if (recovery !== null && matchingRecovery === null) {
    limitations.push("The available recovery run belongs to a different incident.");
  }

  return {
    schema: "fixture-impact-report/v1",
    policy: FIXTURE_IMPACT_CALCULATION_POLICY.policy_id,
    incident: {
      id: workspace.incident.id,
      version: workspace.incident.version,
      scope_policy: workspace.scope.policy,
    },
    bindings: {
      recovery_outcome_id: matchingRecovery?.outcome_id ?? null,
      recovery_packet_id: matchingRecovery?.packet_id ?? null,
    },
    observed: {
      affected_frames: { unit: "items", value: affectedFrames },
      affected_derivatives: { unit: "items", value: affectedDerivatives },
      verified_safe_frames: { unit: "items", value: safeFrames },
      frame_rerender_outcomes: { unit: "items", value: frameRerenders },
      derivative_rerender_outcomes: { unit: "items", value: derivativeRerenders },
      investigation_elapsed: {
        unit: "milliseconds",
        value: elapsedMilliseconds(workspace.incident.created_at, workspace.incident.finalized_at),
      },
      recovery_elapsed: {
        unit: "milliseconds",
        value:
          matchingRecovery?.evaluation_completed_at === null || matchingRecovery === null
            ? null
            : elapsedMilliseconds(
                matchingRecovery.action_started_at,
                matchingRecovery.evaluation_completed_at,
              ),
      },
      provider_cost: { unit: "USD", value: null },
      compute_time: { unit: "milliseconds", value: null },
    },
    hypothetical: {
      name: "rerender-all-observed-source-frames",
      assumption: "Every observed affected or verified-safe source frame would be rerendered once.",
      source_frame_rerenders: { unit: "items", value: counterfactualTotal },
      source_frame_rerenders_avoided: { unit: "items", value: counterfactualAvoided },
    },
    limitations,
  };
}
