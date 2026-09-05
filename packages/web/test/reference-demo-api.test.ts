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

function passingV2Suite(): ReferenceBenchmarkSuite {
  const suite = failedSavingsSuite();
  if (suite.result?.schema !== "reference-impact-benchmark/v1") {
    throw new Error("missing legacy result fixture");
  }
  const scenarioResults = suite.result.scenario_results.map((item) => ({
    ...item,
    selective: { ...item.selective, application_bytes: 500 },
    application_bytes_avoided_basis_points: 5_000,
  }));
  return {
    ...suite,
    result: {
      ...suite.result,
      schema: "reference-impact-benchmark/v2",
      campaign_summary: {
        case_counts: {
          total: 99,
          resolvable: 60,
          fail_closed: 39,
          resolvable_by_class: {
            "configuration-rollout-drift/v1": 20,
            "resource-resolution-drift/v1": 20,
            "stale-derivative-cache/v1": 20,
          },
        },
        metrics: {
          correct_resolvable_classifications: 60,
          classification_accuracy_basis_points: 10_000,
          negative_cases_failed_closed: 39,
          false_action_intents: 0,
          false_authorized_actions: 0,
          display_text_mutations_resolved: 3,
          display_text_mutation_count: 3,
        },
      },
      evidence: {
        ...suite.result.evidence,
        execution_identity: {
          mode: "host-python-module",
          source_revision: "b".repeat(40),
          source_tree: "c".repeat(40),
          container_image_digest: null,
          identity_sha256: DIGEST,
        },
      },
      metrics: {
        classification_accuracy_basis_points: 10_000,
        false_authorized_actions: 0,
        median_compute_avoided_basis_points: 7_000,
        median_application_bytes_avoided_basis_points: 5_000,
      },
      scenario_results: scenarioResults,
      checks: {
        balanced_resolvable_classes: true,
        classification_at_least_95_percent: true,
        all_negative_cases_fail_closed: true,
        display_text_cannot_change_authority: true,
        zero_false_action_intents: true,
        zero_false_authorized_actions: true,
        output_equivalence: true,
        protected_output_integrity: true,
        median_compute_avoided_at_least_40_percent: true,
        median_application_bytes_avoided_at_least_40_percent: true,
      },
      model_comparison_research: {
        status: "recorded-underperformed-baseline",
        excluded_from_release_acceptance: true,
        same_selection_budgets: true,
        recorded_model_output_evaluated: true,
        candidate_accuracy_basis_points: 666,
        fixed_baseline_accuracy_basis_points: 6_666,
        candidate_delta_basis_points: -6_000,
        measurable_candidate_advantage: false,
      },
      passed: true,
    },
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
  it("accepts a passing product benchmark with negative model research excluded", async () => {
    const suite = await adapterFor(passingV2Suite()).benchmarkSuite();

    expect(suite.result).toMatchObject({
      schema: "reference-impact-benchmark/v2",
      passed: true,
      checks: { zero_false_authorized_actions: true },
      model_comparison_research: {
        status: "recorded-underperformed-baseline",
        excluded_from_release_acceptance: true,
        candidate_delta_basis_points: -6_000,
        measurable_candidate_advantage: false,
      },
    });
  });

  it.each(["container", "google-cloud-batch"] as const)(
    "accepts canonical %s worker evidence",
    async (mode) => {
      const fixture = passingV2Suite();
      if (fixture.result?.schema !== "reference-impact-benchmark/v2") {
        throw new Error("missing current result fixture");
      }
      const suite = await adapterFor({
        ...fixture,
        result: {
          ...fixture.result,
          evidence: {
            ...fixture.result.evidence,
            execution_identity: {
              ...fixture.result.evidence.execution_identity,
              mode,
              container_image_digest: DIGEST,
            },
          },
        },
      }).benchmarkSuite();

      expect(suite.result?.evidence).toMatchObject({
        execution_identity: { mode, container_image_digest: DIGEST },
      });
    },
  );

  it("rejects a resigned v2 release check that contradicts its campaign summary", async () => {
    const fixture = passingV2Suite();
    if (fixture.result?.schema !== "reference-impact-benchmark/v2") {
      throw new Error("missing current result fixture");
    }
    const malformed: ReferenceBenchmarkSuite = {
      ...fixture,
      result: {
        ...fixture.result,
        checks: { ...fixture.result.checks, all_negative_cases_fail_closed: false },
        passed: false,
      },
    };

    await expect(adapterFor(malformed).benchmarkSuite()).rejects.toMatchObject({
      code: "reference-response-invalid",
    });
  });

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
    if (suite.result?.schema !== "reference-impact-benchmark/v1") {
      throw new Error("missing legacy result fixture");
    }
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
