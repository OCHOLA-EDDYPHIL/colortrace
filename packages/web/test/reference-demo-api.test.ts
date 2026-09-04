import { describe, expect, it } from "vitest";

import {
  createReferenceDemoAdapter,
  type ReferenceBenchmarkSuite,
  type ReferenceIncidentClass,
  type ReferenceScenarioId,
} from "../src/reference-demo-api.ts";

const DIGEST = `sha256:${"a".repeat(64)}`;
const SCENARIOS: readonly {
  scenarioId: ReferenceScenarioId;
  incidentClass: ReferenceIncidentClass;
}[] = [
  {
    scenarioId: "tos-config-rollout-drift-v1",
    incidentClass: "configuration-rollout-drift/v1",
  },
  {
    scenarioId: "tos-resource-resolution-drift-v1",
    incidentClass: "resource-resolution-drift/v1",
  },
  {
    scenarioId: "tos-stale-derivative-cache-v1",
    incidentClass: "stale-derivative-cache/v1",
  },
];

function failedSavingsSuite(negativeMedian = false): ReferenceBenchmarkSuite {
  const applicationBytes = negativeMedian
    ? SCENARIOS.map(() => ({ baseline: 1_000, selective: 2_500, avoided: -15_000 }))
    : [
        { baseline: 1_000, selective: 650, avoided: 3_500 },
        { baseline: 1_000, selective: 650, avoided: 3_500 },
        { baseline: 1_000, selective: 1_100, avoided: -1_000 },
      ];
  const medianApplicationBytes = negativeMedian ? -15_000 : 3_500;
  return {
    schema: "reference-benchmark-suite/v1",
    suite_id: "tears-of-steel-reference-suite-v1",
    definition_state: "sealed",
    result_state: "recorded",
    scenarios: SCENARIOS.map(({ scenarioId, incidentClass }) => ({
      scenario_id: scenarioId,
      scenario_sha256: DIGEST,
      incident_class: incidentClass,
      rerender_all_artifact_count: 240,
      targeted_artifact_count: 72,
      protected_artifact_count: 168,
      scope_reduction_basis_points: 7_000,
    })),
    acceptance_requirements: {
      output_equivalence: "required",
      protected_output_integrity: "required",
      maximum_false_authorized_actions: 0,
      minimum_resolvable_holdout_accuracy_basis_points: 9_500,
      minimum_median_compute_avoided_basis_points: 4_000,
      minimum_median_bytes_avoided_basis_points: 4_000,
    },
    measurement_boundary: {
      scope_reduction_is_measured_result: false,
      reported_results_require_recorded_evaluator_output: true,
      catalog_claims_observed_savings: true,
      live_run_scope: "representative-evidence-only",
    },
    result: {
      schema: "reference-impact-benchmark/v1",
      reference_collection_id: "tears-of-steel-linear-exr-240-v1",
      reference_manifest_sha256: DIGEST,
      campaign_report_sha256: DIGEST,
      evidence: {
        source: "recorded-worker-receipts",
        evidence_set_id: DIGEST,
        recorded_worker_evidence: true,
        observation_count: 720,
      },
      thresholds: {
        minimum_classification_accuracy_basis_points: 9_500,
        minimum_median_compute_avoided_basis_points: 4_000,
        minimum_median_application_bytes_avoided_basis_points: 4_000,
        maximum_false_authorized_actions: 0,
      },
      metrics: {
        classification_accuracy_basis_points: 10_000,
        false_authorized_actions: 0,
        adaptive_advantage_basis_points: 3_334,
        recorded_model_advantage_basis_points: 3_334,
        median_compute_avoided_basis_points: 7_000,
        median_application_bytes_avoided_basis_points: medianApplicationBytes,
      },
      timing: {
        informational_only: true,
        excluded_from_acceptance: true,
        baseline_cpu_nanoseconds: 4,
        baseline_wall_nanoseconds: 5,
        selective_cpu_nanoseconds: 2,
        selective_wall_nanoseconds: 3,
      },
      scenario_results: SCENARIOS.map(({ scenarioId, incidentClass }, index) => {
        const bytes = applicationBytes[index];
        if (bytes === undefined) throw new Error("missing application byte fixture");
        return {
          scenario_id: scenarioId,
          incident_class: incidentClass,
          artifact_count: 240,
          affected_artifact_count: 72,
          protected_artifact_count: 168,
          baseline: { pixel_work: 1_000, application_bytes: bytes.baseline },
          selective: { pixel_work: 300, application_bytes: bytes.selective },
          compute_avoided_basis_points: 7_000,
          application_bytes_avoided_basis_points: bytes.avoided,
          output_equivalence: true,
          protected_output_integrity: true,
        };
      }),
      checks: {
        campaign_acceptance_passed: true,
        output_equivalence: true,
        protected_output_integrity: true,
        zero_false_authorized_actions: true,
        classification_at_least_95_percent: true,
        same_selection_budgets: true,
        measurable_adaptive_advantage: true,
        median_compute_avoided_at_least_40_percent: true,
        median_application_bytes_avoided_at_least_40_percent: false,
      },
      passed: false,
      report_sha256: DIGEST,
    },
    provenance: {
      attribution: "Tears of Steel © Blender Foundation | mango.blender.org",
      license: {
        spdx: "CC-BY-3.0",
        url: "https://creativecommons.org/licenses/by/3.0/",
      },
    },
    authority: {
      schema: "reference-authority-boundary/v1",
      catalog_facts: "sealed-reference-contracts",
      incident_facts: "deterministic-validators",
      model_role: "advisory",
      evidence_access: "grafana-mcp-read-only",
      action_approval: "human-only",
      action_execution_target: "colortrace-simulator",
      benchmark_result_authority: "recorded-evaluator-output",
    },
    suite_sha256: DIGEST,
  };
}

function adapterFor(suite: ReferenceBenchmarkSuite) {
  return createReferenceDemoAdapter({
    baseUrl: "https://colortrace.example",
    fetch: async () => Response.json(suite),
    sha256: async () => DIGEST,
  });
}

describe("reference benchmark adapter", () => {
  it("accepts a consistent recorded savings-only failure", async () => {
    const suite = await adapterFor(failedSavingsSuite()).benchmarkSuite();

    expect(suite.result_state).toBe("recorded");
    expect(suite.result).toMatchObject({
      passed: false,
      metrics: { median_application_bytes_avoided_basis_points: 3_500 },
      checks: {
        output_equivalence: true,
        protected_output_integrity: true,
        zero_false_authorized_actions: true,
        median_application_bytes_avoided_at_least_40_percent: false,
      },
    });
  });

  it("accepts a consistent recorded negative median savings failure", async () => {
    const suite = await adapterFor(failedSavingsSuite(true)).benchmarkSuite();

    expect(suite.result).toMatchObject({
      passed: false,
      metrics: { median_application_bytes_avoided_basis_points: -15_000 },
    });
  });

  it("rejects a recorded failure whose threshold check contradicts its metric", async () => {
    const suite = failedSavingsSuite();
    if (suite.result === null) throw new Error("missing result fixture");
    const malformed: ReferenceBenchmarkSuite = {
      ...suite,
      result: {
        ...suite.result,
        checks: {
          ...suite.result.checks,
          median_application_bytes_avoided_at_least_40_percent: true,
        },
        passed: true,
      },
    };

    await expect(adapterFor(malformed).benchmarkSuite()).rejects.toMatchObject({
      code: "reference-response-invalid",
    });
  });
});
