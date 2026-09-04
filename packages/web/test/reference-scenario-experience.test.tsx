import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createReferenceDemoAdapter,
  REFERENCE_SCENARIO_IDS,
  type ReferenceAuthority,
  type ReferenceBenchmarkSuite,
  type ReferenceDemoAdapter,
  type ReferenceIncidentClass,
  type ReferenceRecoveryKind,
  type ReferenceScenarioDetail,
  type ReferenceScenarioId,
  type ReferenceScenarioList,
  type ReferenceScenarioSummary,
} from "../src/reference-demo-api.ts";
import {
  parseReferenceResponsePacket,
  type ReferenceResponsePacket,
  type ReferenceRunStatus,
} from "../src/reference-run-contract.ts";
import {
  parseReferenceRecoveryDecision,
  REFERENCE_APPROVAL_PHRASE,
  REFERENCE_DENIAL_PHRASE,
  type ReferenceRecoveryChoice,
  type ReferenceRecoveryDecision,
} from "../src/reference-recovery-contract.ts";
import { ReferenceScenarioExperience } from "../src/reference-scenario-experience.tsx";

afterEach(cleanup);

const DIGEST = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const DIGEST_C = `sha256:${"c".repeat(64)}`;
const REQUEST_ID = "123e4567-e89b-12d3-a456-426614174000";
const APPROVAL_NONCE = "123e4567-e89b-12d3-a456-426614174099";
const RUN_INCIDENT_ID = `reference-incident-${"a".repeat(24)}`;
const RUN_ID = `reference-run-${"a".repeat(24)}`;
const TITLES: Readonly<Record<ReferenceScenarioId, string>> = {
  "tos-resource-resolution-drift-v1": "A successful render resolved the wrong look resource",
  "tos-config-rollout-drift-v1": "A stale color configuration remained active",
  "tos-stale-derivative-cache-v1": "Correct frames served stale review derivatives",
};
const INCIDENTS: Readonly<Record<ReferenceScenarioId, ReferenceIncidentClass>> = {
  "tos-resource-resolution-drift-v1": "resource-resolution-drift/v1",
  "tos-config-rollout-drift-v1": "configuration-rollout-drift/v1",
  "tos-stale-derivative-cache-v1": "stale-derivative-cache/v1",
};
const RECOVERIES: Readonly<Record<ReferenceScenarioId, ReferenceRecoveryKind>> = {
  "tos-resource-resolution-drift-v1": "reconcile-resource",
  "tos-config-rollout-drift-v1": "pin-rollout",
  "tos-stale-derivative-cache-v1": "invalidate-cache",
};
const FACTS: Readonly<Record<ReferenceScenarioId, readonly string[]>> = {
  "tos-resource-resolution-drift-v1": [
    "runtime.effective_resource_sha256",
    "runtime.frame_pipeline_sha256",
  ],
  "tos-config-rollout-drift-v1": [
    "runtime.effective_config_sha256",
    "runtime.config_generation",
    "runtime.frame_pipeline_sha256",
  ],
  "tos-stale-derivative-cache-v1": [
    "runtime.frame_pipeline_sha256",
    "derivative.parent_sha256",
    "cache.generation",
    "cache.key",
  ],
};

const AUTHORITY: ReferenceAuthority = {
  schema: "reference-authority-boundary/v1",
  catalog_facts: "sealed-reference-contracts",
  incident_facts: "deterministic-validators",
  model_role: "advisory",
  evidence_access: "grafana-mcp-read-only",
  action_approval: "human-only",
  action_execution_target: "colortrace-simulator",
};

const PROVENANCE = {
  attribution: "Tears of Steel © Blender Foundation | mango.blender.org",
  license: { spdx: "CC-BY-3.0", url: "https://creativecommons.org/licenses/by/3.0/" },
} as const;

function summary(scenarioId: ReferenceScenarioId): ReferenceScenarioSummary {
  const incidentClass = INCIDENTS[scenarioId];
  const symptom = {
    "resource-resolution-drift/v1":
      "Frames completed, but a worker resolved a different LUT than the approved reference.",
    "configuration-rollout-drift/v1":
      "Frames completed under an older configuration generation while the LUT stayed current.",
    "stale-derivative-cache/v1":
      "The frame pipeline matched the reference, but cached derivatives came from older parents.",
  }[incidentClass];
  return {
    scenario_id: scenarioId,
    scenario_sha256: DIGEST,
    title: TITLES[scenarioId],
    symptom,
    incident_class: incidentClass,
    recovery_kind: RECOVERIES[scenarioId],
    scope: {
      artifact_count: 240,
      affected_artifact_count: 72,
      protected_artifact_count: 168,
    },
    visuals: (["expected", "observed", "recovered", "diff"] as const).map((kind) => {
      const isDifference = kind === "diff";
      const isStaleObserved = scenarioId === "tos-stale-derivative-cache-v1" && kind === "observed";
      const isStaleSource =
        scenarioId === "tos-stale-derivative-cache-v1" && (isStaleObserved || isDifference);
      const servedArtifactId =
        scenarioId === "tos-stale-derivative-cache-v1" ? "frame:03_2a:00003" : "frame:03_2a:00000";
      const sourceArtifactId = isStaleSource ? "frame:03_2a:00002" : servedArtifactId;
      const sourceArtifactIds = isDifference
        ? ([servedArtifactId, sourceArtifactId] as const)
        : ([sourceArtifactId] as const);
      const sourceDigests = isDifference ? ([DIGEST, DIGEST] as const) : ([DIGEST] as const);
      return {
        kind,
        href: `/v1/demo/scenarios/${scenarioId}/visuals/${kind}`,
        content_sha256: DIGEST,
        representation: isDifference
          ? ("open-film-difference-png/v1" as const)
          : ("open-film-preview-png/v1" as const),
        pixel_evidence: true as const,
        width: 960 as const,
        height: 506 as const,
        served_artifact_id: servedArtifactId,
        source_artifact_ids: sourceArtifactIds,
        source_relation: isDifference
          ? ("amplified-absolute-display-difference-8x" as const)
          : isStaleObserved
            ? ("stale-parent" as const)
            : ("current" as const),
        source_receipt_sha256: sourceDigests,
        source_output_sha256: sourceDigests,
        source_canonical_pixel_sha256: sourceDigests,
      };
    }),
  };
}

function scenarioList(): ReferenceScenarioList {
  return {
    schema: "reference-scenario-list/v1",
    collection_id: "tears-of-steel-linear-exr-240-v1",
    items: REFERENCE_SCENARIO_IDS.map(summary),
    provenance: PROVENANCE,
    authority: AUTHORITY,
    catalog_sha256: DIGEST,
  };
}

function scenarioDetail(scenarioId: ReferenceScenarioId): ReferenceScenarioDetail {
  return {
    schema: "reference-scenario-detail/v1",
    summary: summary(scenarioId),
    evidence_requirements: {
      minimum_complementary_signal_classes: 2,
      runtime_fact_source: "structured-grafana-observations",
      required_fact_fields: FACTS[scenarioId],
      decision_authority: "deterministic-validators",
      "missing_conflicting_or_cross-run_evidence": "unresolved",
    },
    recovery_boundary: {
      intent: RECOVERIES[scenarioId],
      requires_human_approval: true,
      execution_target: "colortrace-simulator",
      catalog_executes_actions: false,
    },
    provenance: PROVENANCE,
    authority: AUTHORITY,
    detail_sha256: DIGEST,
  };
}

function benchmarkSuite(): ReferenceBenchmarkSuite {
  return {
    schema: "reference-benchmark-suite/v1",
    suite_id: "tears-of-steel-reference-suite-v1",
    definition_state: "sealed",
    result_state: "not-reported",
    scenarios: REFERENCE_SCENARIO_IDS.map((scenarioId) => ({
      scenario_id: scenarioId,
      scenario_sha256: DIGEST,
      incident_class: INCIDENTS[scenarioId],
      rerender_all_artifact_count: 240,
      targeted_artifact_count: 72,
      protected_artifact_count: 168,
      scope_reduction_basis_points: 7000,
    })),
    acceptance_requirements: {
      output_equivalence: "required",
      protected_output_integrity: "required",
      maximum_false_authorized_actions: 0,
      minimum_resolvable_holdout_accuracy_basis_points: 9500,
      minimum_median_compute_avoided_basis_points: 4000,
      minimum_median_bytes_avoided_basis_points: 4000,
    },
    measurement_boundary: {
      scope_reduction_is_measured_result: false,
      reported_results_require_recorded_evaluator_output: true,
      catalog_claims_observed_savings: false,
      live_run_scope: "representative-evidence-only",
    },
    result: null,
    provenance: PROVENANCE,
    authority: {
      ...AUTHORITY,
      benchmark_result_authority: "recorded-evaluator-output",
    },
    suite_sha256: DIGEST,
  };
}

function recordedBenchmarkSuite(passed = true): ReferenceBenchmarkSuite {
  const suite = benchmarkSuite();
  const result: NonNullable<ReferenceBenchmarkSuite["result"]> = {
    schema: "reference-impact-benchmark/v1",
    reference_collection_id: "tears-of-steel-linear-exr-240-v1",
    reference_manifest_sha256: DIGEST,
    campaign_report_sha256: DIGEST_B,
    evidence: {
      source: "recorded-worker-receipts",
      evidence_set_id: DIGEST_C,
      recorded_worker_evidence: true,
      observation_count: 720,
    },
    thresholds: {
      minimum_classification_accuracy_basis_points: 9500,
      minimum_median_compute_avoided_basis_points: 4000,
      minimum_median_application_bytes_avoided_basis_points: 4000,
      maximum_false_authorized_actions: 0,
    },
    metrics: {
      classification_accuracy_basis_points: 10_000,
      false_authorized_actions: 0,
      adaptive_advantage_basis_points: 3334,
      recorded_model_advantage_basis_points: 3334,
      median_compute_avoided_basis_points: 7000,
      median_application_bytes_avoided_basis_points: 6500,
    },
    timing: {
      informational_only: true,
      excluded_from_acceptance: true,
      baseline_cpu_nanoseconds: 2_400_000,
      baseline_wall_nanoseconds: 2_800_000,
      selective_cpu_nanoseconds: 720_000,
      selective_wall_nanoseconds: 840_000,
    },
    scenario_results: REFERENCE_SCENARIO_IDS.map((scenarioId, index) => ({
      scenario_id: scenarioId,
      incident_class: INCIDENTS[scenarioId],
      artifact_count: 240,
      affected_artifact_count: 72,
      protected_artifact_count: 168,
      baseline: { pixel_work: 1000, application_bytes: index === 2 ? 10_000 : 1000 },
      selective: { pixel_work: 300, application_bytes: index === 2 ? 11_032 : 350 },
      compute_avoided_basis_points: 7000,
      application_bytes_avoided_basis_points: index === 2 ? -1032 : 6500,
      output_equivalence: passed || index !== 0,
      protected_output_integrity: true,
    })),
    checks: {
      campaign_acceptance_passed: true,
      output_equivalence: passed,
      protected_output_integrity: true,
      zero_false_authorized_actions: true,
      classification_at_least_95_percent: true,
      same_selection_budgets: true,
      measurable_adaptive_advantage: true,
      median_compute_avoided_at_least_40_percent: true,
      median_application_bytes_avoided_at_least_40_percent: true,
    },
    passed,
    report_sha256: DIGEST,
  };
  return {
    ...suite,
    result_state: "recorded",
    measurement_boundary: {
      ...suite.measurement_boundary,
      catalog_claims_observed_savings: true,
    },
    result,
  };
}

function recordedSavingsMissSuite(): ReferenceBenchmarkSuite {
  const suite = recordedBenchmarkSuite();
  if (suite.result === null) throw new Error("missing recorded benchmark result");
  return {
    ...suite,
    result: {
      ...suite.result,
      metrics: {
        ...suite.result.metrics,
        median_application_bytes_avoided_basis_points: 3500,
      },
      scenario_results: suite.result.scenario_results.map((item, index) =>
        index === 2
          ? item
          : {
              ...item,
              selective: { ...item.selective, application_bytes: 650 },
              application_bytes_avoided_basis_points: 3500,
            },
      ),
      checks: {
        ...suite.result.checks,
        median_application_bytes_avoided_at_least_40_percent: false,
      },
      passed: false,
    },
  };
}

function actionParameters(incidentClass: ReferenceIncidentClass): Record<string, unknown> {
  switch (incidentClass) {
    case "resource-resolution-drift/v1":
      return {
        changed_fields: ["effective_resource_sha256"],
        expected: { effective_resource_sha256: DIGEST },
        observed: { effective_resource_sha256: DIGEST_B },
      };
    case "configuration-rollout-drift/v1":
      return {
        changed_fields: ["config_generation", "effective_config_sha256"],
        expected: { config_generation: 7, effective_config_sha256: DIGEST },
        observed: { config_generation: 6, effective_config_sha256: DIGEST_B },
      };
    case "stale-derivative-cache/v1":
      return {
        cache_key: "cache:03_2a:00003:g7",
        changed_fields: ["derivative_generation", "derivative_parent_sha256"],
        expected: { derivative_generation: 7, derivative_parent_sha256: DIGEST },
        observed: { derivative_generation: 6, derivative_parent_sha256: DIGEST_B },
      };
  }
}

function runtimeAttributes(
  scenarioId: ReferenceScenarioId,
  role: "affected" | "protected",
  signal: "metric" | "log" | "trace",
): Readonly<Record<string, string>> {
  const affected = role === "affected";
  if (signal === "metric") {
    const resourceMismatch = scenarioId === "tos-resource-resolution-drift-v1" && affected;
    const configMismatch = scenarioId === "tos-config-rollout-drift-v1" && affected;
    const derivativeMismatch = scenarioId === "tos-stale-derivative-cache-v1" && affected;
    const pipelineMismatch = scenarioId !== "tos-stale-derivative-cache-v1" && affected;
    return {
      "declared_reference.state": affected ? "reference_mismatch" : "reference_match",
      "declared_reference.approved_state_sha256": DIGEST,
      "declared_reference.effective_resource_matches_approved": String(!resourceMismatch),
      "declared_reference.effective_config_matches_approved": String(!configMismatch),
      "declared_reference.config_generation_matches_approved": String(!configMismatch),
      "declared_reference.frame_pipeline_matches_approved": String(!pipelineMismatch),
      "declared_reference.derivative_parent_matches_approved": String(!derivativeMismatch),
      "declared_reference.derivative_generation_matches_approved": String(!derivativeMismatch),
      "declared_reference.cache_key_matches_approved": "true",
      "reference.evidence_scope": "representative",
      "reference.affected_representative_count": "1",
      "reference.protected_representative_count": "1",
      "reference.population_affected_artifact_count": "72",
      "reference.population_protected_artifact_count": "168",
    };
  }
  if (signal === "log") {
    return {
      "runtime.effective_resource_sha256":
        scenarioId === "tos-resource-resolution-drift-v1" && affected ? DIGEST_B : DIGEST,
      "runtime.effective_config_sha256":
        scenarioId === "tos-config-rollout-drift-v1" && affected ? DIGEST_B : DIGEST,
      "runtime.config_generation":
        scenarioId === "tos-config-rollout-drift-v1" && affected ? "6" : "7",
      "runtime.frame_pipeline_sha256":
        scenarioId !== "tos-stale-derivative-cache-v1" && affected ? DIGEST_B : DIGEST,
      "cache.key": "cache:03_2a:00003:g7",
    };
  }
  return {
    "runtime.frame_pipeline_sha256": DIGEST,
    "derivative.parent_sha256":
      scenarioId === "tos-stale-derivative-cache-v1" && affected ? DIGEST_B : DIGEST,
    "cache.generation": scenarioId === "tos-stale-derivative-cache-v1" && affected ? "6" : "7",
    "cache.key": "cache:03_2a:00003:g7",
  };
}

type RuntimeQueryKey = "metric.worker-cohort" | "log.config-cohort" | "trace.by-id";

function runtimeObservation(
  scenarioId: ReferenceScenarioId,
  queryKey: RuntimeQueryKey,
  queryIndex: number,
  role: "affected" | "protected",
): Readonly<Record<string, unknown>> {
  const roleIndex = role === "affected" ? 0 : 1;
  const factHex = ["d", "e", "f", "9"][queryIndex * 2 + roleIndex] ?? "8";
  const evidenceId = queryIndex === 0 ? DIGEST_B : DIGEST_C;
  const jobId = role === "affected" ? "job-affected-001" : "job-safe-001";
  const signal =
    queryKey === "metric.worker-cohort" ? "metric" : queryKey === "trace.by-id" ? "trace" : "log";
  const attributes = runtimeAttributes(scenarioId, role, signal);
  const resourceSha256 =
    signal === "log"
      ? String(attributes["runtime.effective_resource_sha256"]).slice("sha256:".length)
      : "none";
  return {
    schema: "normalized-runtime-observation/v1",
    request_id: "evidence-request-001",
    incident_id: RUN_INCIDENT_ID,
    event_id: `event-${queryIndex}-${role}`,
    signal,
    fixture_id: "tears-of-steel-linear-exr-240-v1",
    run_id: RUN_ID,
    job_id: jobId,
    worker_id: `worker-${role}`,
    trace_id: role === "affected" ? "1".repeat(32) : "2".repeat(32),
    artifact_id: role === "affected" ? "frame:03_2a:00000" : "frame:04_5f:00108",
    config_sha256: "a".repeat(64),
    resource_sha256: resourceSha256,
    transform_id: "display-transform-reference",
    observed_at: "2026-09-04T12:01:00.000Z",
    emitted_at: "2026-09-04T12:01:01.000Z",
    retrieved_at: "2026-09-04T12:05:00.000Z",
    attributes,
    provenance: {
      query_key: queryKey,
      evidence_id: evidenceId,
      event_sha256: evidenceId,
      content_sha256: DIGEST,
      catalog_version: "grafana-evidence-query-catalog/v2",
      catalog_sha256: DIGEST,
      tool:
        queryKey === "metric.worker-cohort"
          ? "query_prometheus"
          : queryKey === "trace.by-id"
            ? "tempo_get-trace"
            : "query_loki_logs",
      normalized_arguments: {
        query: queryKey,
        provider_payload: "not retained by the browser projection",
      },
    },
    fact_id: `runtime-fact:${factHex.repeat(64)}`,
    fact_sha256: `sha256:${factHex.repeat(64)}`,
  };
}

function rawResponsePacket(
  scenarioId: ReferenceScenarioId,
  status: ReferenceRunStatus = "resolved",
  selectedRuntimeQueryKeys?: readonly RuntimeQueryKey[],
): Readonly<Record<string, unknown>> {
  const incidentClass = INCIDENTS[scenarioId];
  const expectedAssessmentId = `expected-assessment:${"a".repeat(64)}`;
  const operationalAssessmentId = `operational-assessment:${"b".repeat(64)}`;
  const reconciliationId = `diagnosis-reconciliation:${"c".repeat(64)}`;
  const runtimeQueryKeys: readonly RuntimeQueryKey[] =
    status === "resolved"
      ? (selectedRuntimeQueryKeys ?? [
          "metric.worker-cohort",
          scenarioId === "tos-stale-derivative-cache-v1" ? "trace.by-id" : "log.config-cohort",
        ])
      : [];
  const runtimeEvidenceIds = [DIGEST_B, DIGEST_C].slice(0, runtimeQueryKeys.length);
  const evidenceIds = status === "resolved" ? [DIGEST, ...runtimeEvidenceIds] : [];
  const traceQueryKeys = ["alert.rule", ...runtimeQueryKeys];
  const representativeAffectedJobIds = ["job-affected-001"];
  const representativeSafeJobIds = ["job-safe-001"];
  const affectedJobIds = status === "resolved" ? representativeAffectedJobIds : [];
  const safeJobIds = status === "resolved" ? representativeSafeJobIds : [];
  const evidenceFactIds = status === "resolved" ? [`runtime-fact:${"d".repeat(64)}`] : [];
  const actionIntent =
    status === "resolved"
      ? {
          schema: "simulator-action-intent/v1",
          reconciliation_id: reconciliationId,
          incident_class: incidentClass,
          command: RECOVERIES[scenarioId],
          target: "simulator",
          requires_human_approval: true,
          authorizes_execution: false,
          affected_job_ids: affectedJobIds,
          evidence_fact_ids: evidenceFactIds,
          parameters: actionParameters(incidentClass),
          action_intent_id: `action-intent:${"e".repeat(64)}`,
          derivation_sha256: `sha256:${"e".repeat(64)}`,
        }
      : null;
  const projection = {
    schema: "runtime-evidence-projection/v1",
    request_id: "evidence-request-001",
    incident_id: RUN_INCIDENT_ID,
    query_keys: runtimeQueryKeys,
    evidence_ids: evidenceIds.slice(1),
    observations:
      status === "resolved"
        ? runtimeQueryKeys.flatMap((queryKey, index) => [
            runtimeObservation(scenarioId, queryKey, index, "affected"),
            runtimeObservation(scenarioId, queryKey, index, "protected"),
          ])
        : [],
    projection_sha256: DIGEST,
  };
  const classAssessments = [
    "resource-resolution-drift/v1",
    "configuration-rollout-drift/v1",
    "stale-derivative-cache/v1",
  ].map((className, index) => {
    const supported = status === "resolved" && className === incidentClass;
    const hex = ["1", "2", "3"][index] ?? "1";
    return {
      schema: "incident-class-assessment/v1",
      status: supported ? "supported" : status === "resolved" ? "rejected" : "insufficient",
      incident_class: className,
      expected_state_assessment_id: expectedAssessmentId,
      operational_evidence_assessment_id: operationalAssessmentId,
      scope: { affected_job_ids: affectedJobIds, safe_job_ids: safeJobIds },
      evidence_fact_ids: evidenceFactIds,
      cause: supported ? { changed_fields: actionParameters(incidentClass).changed_fields } : {},
      reason_codes: [supported ? "incident-class-supported" : "incident-class-not-supported"],
      assessment_id: `class-assessment:${hex.repeat(64)}`,
      derivation_sha256: `sha256:${hex.repeat(64)}`,
    };
  });
  const selectionTrace = traceQueryKeys.map((queryKey, index) => ({
    sequence: index,
    selected_by: index === 0 ? "policy" : "model",
    query_key: queryKey,
    evidence_id: status === "resolved" ? evidenceIds[index] : null,
    disposition:
      status === "resolved"
        ? index === traceQueryKeys.length - 1
          ? "resolved"
          : "continue"
        : "unresolved",
    reason_codes:
      status === "resolved"
        ? [index === traceQueryKeys.length - 1 ? "sufficient-evidence" : "evidence-collected"]
        : ["evidence-unavailable"],
    operational_assessment_id: operationalAssessmentId,
    reconciliation_id: reconciliationId,
  }));
  const modelInvocation =
    status === "resolved"
      ? {
          schema: "model-tool-invocation/v3",
          provider: "vertex-ai",
          model: "gemini-3.5-flash",
          prompt_version: "evidence-selection/v3",
          request_sha256: DIGEST,
          output_sha256: DIGEST_B,
          input_tokens: 720,
          output_tokens: 96,
          model_calls: 3,
          unobserved_model_calls: 0,
          status: "accepted",
        }
      : null;
  const spans =
    status === "resolved"
      ? [
          ["grafana", "ok", "alert.rule", 12, 1, null, null, null],
          ["gemini", "ok", null, 38, 3, null, 720, 96],
          ...runtimeQueryKeys.flatMap((queryKey, index) => {
            const terminal = index === runtimeQueryKeys.length - 1;
            return [
              ["grafana", "ok", queryKey, 18, 1, null, null, null],
              ["validator", terminal ? "ok" : "unresolved", queryKey, 2, 0, null, null, null],
              [
                "reconciliation",
                terminal ? "ok" : "unresolved",
                queryKey,
                1,
                0,
                terminal ? null : "incomplete-evidence",
                null,
                null,
              ],
            ];
          }),
        ]
      : [["grafana", "error", "alert.rule", 21, 0, "evidence-unavailable", null, null]];

  return {
    schema: "response-packet/v3",
    packet_id: `response-packet:${"a".repeat(64)}`,
    version: 3,
    status,
    incident_id: RUN_INCIDENT_ID,
    scenario_id: scenarioId,
    fixture_id: "tears-of-steel-linear-exr-240-v1",
    run_id: RUN_ID,
    policy_binding: { version: "reference-investigation/v1", sha256: DIGEST },
    fixed_window: { start: "2026-09-04T12:00:00.000Z", end: "2026-09-04T12:05:00.000Z" },
    evidence_ids: evidenceIds,
    reference_evidence: {
      schema: "reference-evidence/v3",
      evidence_bundle_id: `reference-evidence:${"a".repeat(64)}`,
      request_id: "evidence-request-001",
      incident_id: RUN_INCIDENT_ID,
      scenario_id: scenarioId,
      fixture_id: "tears-of-steel-linear-exr-240-v1",
      run_id: RUN_ID,
      source: "grafana-mcp",
      structured_only: true,
      query_keys: traceQueryKeys,
      evidence_ids: evidenceIds,
      expected_state_sha256: DIGEST,
      runtime_projection: projection,
      derivation_sha256: DIGEST,
    },
    runtime_evidence_projection: projection,
    expected_state_assessment: {
      schema: "expected-state-assessment/v1",
      status: "supported",
      expected_state_id: `expected-state:${"a".repeat(64)}`,
      expected_state_sha256: DIGEST,
      scenario_id: scenarioId,
      fixture_id: "tears-of-steel-linear-exr-240-v1",
      run_id: RUN_ID,
      evidence_window: { start: "2026-09-04T12:00:00.000Z", end: "2026-09-04T12:05:00.000Z" },
      approved: {
        resource_sha256: DIGEST,
        config_sha256: DIGEST,
        config_generation: 7,
        frame_pipeline_sha256: DIGEST,
        derivative_parent_sha256: DIGEST,
        derivative_generation: 7,
        cache_key: "cache:03_2a:00003:g7",
      },
      scope: {
        affected_job_ids: representativeAffectedJobIds,
        safe_job_ids: representativeSafeJobIds,
      },
      reason_codes: ["expected-state-supported"],
      assessment_id: expectedAssessmentId,
      derivation_sha256: DIGEST,
    },
    operational_evidence_assessment: {
      schema: "operational-evidence-assessment/v1",
      status: status === "resolved" ? "supported" : "insufficient",
      expected_state_assessment_id: expectedAssessmentId,
      request_id: status === "resolved" ? "evidence-request-001" : null,
      incident_id: status === "resolved" ? RUN_INCIDENT_ID : null,
      fixture_id: "tears-of-steel-linear-exr-240-v1",
      run_id: RUN_ID,
      job_facts:
        status === "resolved"
          ? {
              "job-affected-001": {
                signals: [
                  ...new Set(
                    runtimeQueryKeys.map((key) =>
                      key.startsWith("metric") ? "metric" : key.startsWith("log") ? "log" : "trace",
                    ),
                  ),
                ].sort(),
              },
            }
          : {},
      fact_ids: evidenceFactIds,
      evidence_ids: evidenceIds.slice(1),
      reason_codes: [status === "resolved" ? "operational-evidence-supported" : "evidence-missing"],
      assessment_id: operationalAssessmentId,
      derivation_sha256: `sha256:${"b".repeat(64)}`,
    },
    incident_class_assessments: classAssessments,
    diagnosis_reconciliation: {
      schema: "diagnosis-reconciliation/v1",
      reconciliation_id: reconciliationId,
      status: status === "resolved" ? "supported" : "insufficient",
      incident_class: status === "resolved" ? incidentClass : null,
      expected_state_assessment_id: expectedAssessmentId,
      operational_evidence_assessment_id: operationalAssessmentId,
      class_assessment_ids: classAssessments.map((item) => item.assessment_id),
      scope: { affected_job_ids: affectedJobIds, safe_job_ids: safeJobIds },
      evidence_fact_ids: evidenceFactIds,
      reason_codes: [status === "resolved" ? "diagnosis-supported" : "evidence-missing"],
      action_intent: actionIntent,
      derivation_sha256: DIGEST_C,
    },
    selection_trace: selectionTrace,
    model_selection:
      status === "resolved"
        ? {
            schema: "model-selection/v3",
            trust: "untrusted-model-output",
            hypotheses: [
              { ordinal: 1, incident_class: incidentClass, evidence_ids: evidenceIds.slice(1) },
            ],
            query_keys: traceQueryKeys,
            stop_reason: "sufficient-evidence",
            output_sha256: DIGEST_B,
          }
        : null,
    model_invocation: modelInvocation,
    agent_trace: {
      schema: "agent-trace/v2",
      trace_id: "1".repeat(32),
      spans: spans.map(
        (
          [stage, spanStatus, queryKey, durationMs, attempts, errorCode, inputTokens, outputTokens],
          index,
        ) => ({
          sequence: index,
          stage,
          status: spanStatus,
          duration_ms: durationMs,
          query_key: queryKey,
          input_tokens: inputTokens,
          output_tokens: outputTokens,
          attempts,
          attempts_complete: status === "resolved",
          unobserved_model_calls: 0,
          error_code: errorCode,
        }),
      ),
    },
    authority_policy: [
      "gemini-query-selection-only",
      "grafana-read-only-evidence",
      "deterministic-validators-authoritative",
      "human-approval-required-for-action",
    ],
    action_intent: actionIntent,
    no_action_reason: status === "resolved" ? null : "evidence-unavailable",
    finalized_at: "2026-09-04T12:05:00.000Z",
    derivation_sha256: DIGEST,
  };
}

function replaceRuntimeObservations(
  packet: Readonly<Record<string, unknown>>,
  observations: readonly Readonly<Record<string, unknown>>[],
): Readonly<Record<string, unknown>> {
  const projection = packet.runtime_evidence_projection as Readonly<Record<string, unknown>>;
  const replacement = { ...projection, observations };
  const referenceEvidence = packet.reference_evidence as Readonly<Record<string, unknown>>;
  return {
    ...packet,
    runtime_evidence_projection: replacement,
    reference_evidence: { ...referenceEvidence, runtime_projection: replacement },
  };
}

async function parsedResponsePacket(
  scenarioId: ReferenceScenarioId,
  status: ReferenceRunStatus = "resolved",
): Promise<ReferenceResponsePacket> {
  return parseReferenceResponsePacket(
    rawResponsePacket(scenarioId, status),
    scenarioId,
    REQUEST_ID,
    async () => DIGEST,
  );
}

function rawPartialUsagePacket(): Record<string, unknown> {
  const raw = rawResponsePacket("tos-resource-resolution-drift-v1", "unresolved");
  const trace = raw.agent_trace as Readonly<Record<string, unknown>>;
  const spans = trace.spans as readonly Readonly<Record<string, unknown>>[];
  return {
    ...raw,
    no_action_reason: "model-unavailable",
    model_invocation: {
      schema: "model-tool-invocation/v3",
      provider: "vertex-ai",
      model: "gemini-3.5-flash",
      prompt_version: "evidence-selection/v3",
      request_sha256: DIGEST,
      output_sha256: null,
      input_tokens: null,
      output_tokens: null,
      model_calls: 2,
      unobserved_model_calls: 1,
      status: "failed",
    },
    agent_trace: {
      ...trace,
      spans: [
        { ...spans[0], attempts: 1, attempts_complete: false },
        {
          sequence: 1,
          stage: "gemini",
          status: "error",
          duration_ms: 22,
          query_key: null,
          input_tokens: null,
          output_tokens: null,
          attempts: 2,
          attempts_complete: true,
          unobserved_model_calls: 1,
          error_code: "model-unavailable",
        },
      ],
    },
  };
}

async function parsedPartialUsagePacket(): Promise<ReferenceResponsePacket> {
  return parseReferenceResponsePacket(
    rawPartialUsagePacket(),
    "tos-resource-resolution-drift-v1",
    REQUEST_ID,
    async () => DIGEST,
  );
}

function rawRecoveryDecision(
  packet: ReferenceResponsePacket,
  decision: ReferenceRecoveryChoice,
): Readonly<Record<string, unknown>> {
  const intent = packet.action_intent;
  if (intent === null) throw new Error("resolved packet fixture requires an action intent");
  const before = {
    generation: 1,
    state_sha256: DIGEST_B,
    protected_state_sha256: DIGEST_C,
  };
  const after =
    decision === "approved"
      ? { generation: 2, state_sha256: DIGEST, protected_state_sha256: DIGEST_C }
      : before;
  const approval = {
    schema: "reference-human-approval/v3",
    decision,
    approver: {
      audience: "colortrace-simulator",
      kind: "human",
      identity_verified: false,
      identity_assurance: "unverified-public-demo-gesture",
      gesture: "explicit-phrase-and-nonce",
    },
    approval_nonce: APPROVAL_NONCE,
    issued_at: "2026-09-04T12:05:01.000Z",
    expires_at: "2026-09-04T12:10:01.000Z",
    action_intent_id: intent.action_intent_id,
    action_intent_sha256: intent.derivation_sha256,
    reconciliation_id: intent.reconciliation_id,
    scenario_id: packet.scenario_id,
    incident_class: intent.incident_class,
    command: intent.command,
    affected_job_ids: intent.affected_job_ids,
    state_generation: before.generation,
    state_sha256: before.state_sha256,
    protected_state_sha256: before.protected_state_sha256,
    approval_id: `reference-approval:${"a".repeat(64)}`,
    approval_sha256: DIGEST,
  };
  const expectedFields = {
    "resource-resolution-drift/v1": ["effective_resource_sha256"],
    "configuration-rollout-drift/v1": ["config_generation", "effective_config_sha256"],
    "stale-derivative-cache/v1": ["derivative_generation", "derivative_parent_sha256"],
  }[intent.incident_class];
  const expected = intent.parameters.expected;
  if (typeof expected !== "object" || expected === null || Array.isArray(expected)) {
    throw new Error("missing expected action parameters");
  }
  const verification =
    decision === "approved"
      ? {
          schema: "reference-recovery-verification/v1",
          verifier: "deterministic-simulator-state",
          result: "verified",
          scenario_id: packet.scenario_id,
          incident_class: intent.incident_class,
          action_intent_id: intent.action_intent_id,
          action_intent_sha256: intent.derivation_sha256,
          reconciliation_id: intent.reconciliation_id,
          before,
          after,
          affected_job_ids: [...intent.affected_job_ids].sort(),
          affected_expected_field_checks: expectedFields.map((field) => ({
            field,
            expected_value: (expected as Readonly<Record<string, unknown>>)[field],
            matched_job_ids: [...intent.affected_job_ids].sort(),
          })),
          checks: {
            generation_advanced_exactly_once: true,
            all_affected_expected_fields_match: true,
            protected_state_unchanged: true,
            receipt_state_bindings_match: true,
          },
          establishes_pixel_output: false,
          establishes_full_population_scope: false,
          production_evidence: false,
          verification_sha256: DIGEST,
        }
      : null;
  const receipt =
    decision === "approved"
      ? {
          schema: "reference-recovery-receipt/v3",
          approval_id: approval.approval_id,
          approval_sha256: approval.approval_sha256,
          action_intent_id: intent.action_intent_id,
          action_intent_sha256: intent.derivation_sha256,
          reconciliation_id: intent.reconciliation_id,
          scenario_id: packet.scenario_id,
          incident_class: intent.incident_class,
          command: intent.command,
          before,
          after,
          affected_job_ids: intent.affected_job_ids,
          protected_job_ids: packet.diagnosis_reconciliation.scope.safe_job_ids,
          mutations: [
            {
              job_id: intent.affected_job_ids[0],
              before_job_state_sha256: DIGEST_B,
              after_job_state_sha256: DIGEST_C,
              changed_components:
                intent.incident_class === "stale-derivative-cache/v1"
                  ? ["derivative"]
                  : ["frame", "derivative"],
            },
          ],
          protected_state_unchanged: true,
          action_intent_requires_human_approval: true,
          action_intent_authorizes_execution: false,
          verification,
          result: "applied",
          receipt_id: `reference-recovery:${"a".repeat(64)}`,
          receipt_sha256: DIGEST,
        }
      : null;
  return {
    schema: "reference-recovery-decision/v1",
    scenario_id: packet.scenario_id,
    request_id: packet.request_id,
    run_id: packet.run_id,
    packet_id: packet.packet_id,
    packet_sha256: packet.derivation_sha256,
    decision,
    outcome: decision === "approved" ? "applied" : "denied",
    approval,
    before,
    after,
    protected_state_unchanged: true,
    receipt,
    verification,
    scope: {
      kind: "representative-simulator-state",
      affected_job_count: 1,
      protected_job_count: 1,
      establishes_full_population_scope: false,
    },
    execution_boundary: {
      approval_actor_kind: "human",
      approval_gesture: "explicit-phrase-and-nonce",
      identity_verified: false,
      identity_assurance: "unverified-public-demo-gesture",
      execution_target: "colortrace-simulator",
      simulator_state_changed: decision === "approved",
      production_access_used: false,
      production_state_changed: false,
      production_claim: "none",
    },
    decision_sha256: DIGEST,
  };
}

async function parsedRecoveryDecision(
  packet: ReferenceResponsePacket,
  decision: ReferenceRecoveryChoice,
): Promise<ReferenceRecoveryDecision> {
  return parseReferenceRecoveryDecision(
    rawRecoveryDecision(packet, decision),
    packet,
    decision,
    APPROVAL_NONCE,
    async () => DIGEST,
  );
}

function adapterFixture(overrides: Partial<ReferenceDemoAdapter> = {}): ReferenceDemoAdapter {
  return {
    listScenarios: vi.fn(async () => scenarioList()),
    getScenario: vi.fn(async (scenarioId) => scenarioDetail(scenarioId)),
    benchmarkSuite: vi.fn(async () => benchmarkSuite()),
    runScenario: vi.fn(async (scenarioId) => parsedResponsePacket(scenarioId)),
    decideRecovery: vi.fn(async (packet, decision) => parsedRecoveryDecision(packet, decision)),
    loadVisual: vi.fn(
      async (
        descriptor: Parameters<ReferenceDemoAdapter["loadVisual"]>[0],
        scenarioSha256: string,
      ) => ({
        kind: descriptor.kind,
        content_sha256: DIGEST,
        scenario_sha256: scenarioSha256,
        representation: descriptor.representation,
        pixel_evidence: true as const,
        width: 960 as const,
        height: 506 as const,
        served_artifact_id: descriptor.served_artifact_id,
        source_relation: descriptor.source_relation,
        src: `blob:${descriptor.kind}`,
      }),
    ),
    releaseVisual: vi.fn(),
    ...overrides,
  };
}

describe("reference scenario experience", () => {
  it("makes each failure, scope, authority boundary, and pending benchmark explicit", async () => {
    const adapter = adapterFixture();
    render(<ReferenceScenarioExperience adapter={adapter} />);

    expect(
      await screen.findByRole("heading", {
        name: "A successful render resolved the wrong look resource",
      }),
    ).toBeVisible();
    expect(screen.getByLabelText("Scenario scope")).toHaveTextContent(
      /72 affected.*168 protected.*240 total/su,
    );
    expect(screen.getByText("Effective resource digest")).toBeVisible();
    expect(
      screen.getByRole("heading", {
        name: "Gemini may select → Grafana can return → validators decide → human may authorize",
      }),
    ).toBeVisible();
    expect(await screen.findAllByText("PNG hash verified · pixel evidence")).toHaveLength(3);
    expect(await screen.findByAltText(/Expected state open-film pixel preview/iu)).toBeVisible();
    expect(screen.getByText(/absolute display-pixel difference is amplified 8×/iu)).toBeVisible();
    const expectedProvenanceSummary = screen.getAllByText("Pixel provenance")[0] as HTMLElement;
    fireEvent.click(expectedProvenanceSummary);
    const expectedProvenance = expectedProvenanceSummary.closest("details");
    if (expectedProvenance === null) throw new Error("missing expected provenance");
    expect(within(expectedProvenance).getByText("frame:03_2a:00000")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Recovered" }));
    expect(await screen.findByAltText(/Recovered output open-film pixel preview/iu)).toBeVisible();
    expect(
      screen.getByText(/worker-produced pixel evidence bound to its source receipt/iu),
    ).toBeVisible();
    expect(screen.getByText("No measured result")).toBeVisible();
    const requirements = screen.getByRole("region", { name: "Benchmark requirements" });
    expect(requirements).toHaveTextContent(/Required\s*equivalent recovered outputs/u);
    expect(requirements).toHaveTextContent(/Unchanged\s*required protected outputs/u);
    expect(requirements).toHaveTextContent(/0\s*maximum false-authorized actions/u);
    expect(requirements).toHaveTextContent(
      /≥95%\s*required correct resolution on resolvable holdouts/u,
    );
    expect(screen.getByText(/only after those correctness and safety gates pass/iu)).toBeVisible();
    expect(
      screen.getByText(/does not report compute, byte, time, cost, or accuracy results/u),
    ).toBeVisible();

    fireEvent.click(screen.getByText("Inspect the bounded query and evidence contract"));
    expect(screen.getByText("runtime.effective_resource_sha256")).toBeVisible();
    expect(screen.getByText(/does not claim a diagnosis.*live results/iu)).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: /configuration rollout.*72 affected/iu }));
    expect(
      await screen.findByRole("heading", {
        name: "A stale color configuration remained active",
      }),
    ).toBeVisible();
    expect(screen.getByText("Effective config digest + generation")).toBeVisible();
    await waitFor(() => expect(adapter.releaseVisual).toHaveBeenCalledTimes(4));
    fireEvent.click(screen.getByText("Inspect the bounded query and evidence contract"));
    expect(screen.getByText("runtime.config_generation")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: /derivative cache.*72 affected/iu }));
    expect(
      await screen.findByRole("heading", {
        name: "Correct frames served stale review derivatives",
      }),
    ).toBeVisible();
    expect(screen.getByText("Derivative parent + cache generation")).toBeVisible();
    expect(screen.getByText(/rebuild only affected derivatives/iu)).toBeVisible();
    expect(
      screen.getByText(/prior-parent review derivative served by the stale cache/iu),
    ).toBeVisible();
    fireEvent.click(screen.getByText("Inspect the bounded query and evidence contract"));
    expect(screen.getByText("runtime.frame_pipeline_sha256")).toBeVisible();
    expect(screen.getByText("derivative.parent_sha256")).toBeVisible();
  });

  it("shows a bounded unavailable state instead of implying benchmark success", async () => {
    const adapter = adapterFixture({
      benchmarkSuite: vi.fn(async () => {
        throw new Error("unavailable");
      }),
    });
    render(<ReferenceScenarioExperience adapter={adapter} />);

    expect(
      await screen.findByRole("heading", { name: "Benchmark definition unavailable" }),
    ).toBeVisible();
    expect(screen.getByText(/No result is being shown/u)).toBeVisible();
    expect(screen.queryByText("No measured result")).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading the sealed benchmark definition/u)).not.toBeInTheDocument();
  });

  it.each([
    [true, "Core mission gates passed", "Impact target passed", "Full impact benchmark · passed"],
    [
      false,
      "Core mission gates failed",
      "Core mission failed",
      "Full impact benchmark · not passed",
    ],
  ])(
    "renders a strictly recorded benchmark result when passed=%s",
    async (passed, heading, badge, fullStatus) => {
      render(
        <ReferenceScenarioExperience
          adapter={adapterFixture({
            benchmarkSuite: vi.fn(async () => recordedBenchmarkSuite(passed)),
          })}
        />,
      );

      expect(await screen.findByRole("heading", { name: heading })).toBeVisible();
      expect(
        screen.getByText(badge, { selector: ".reference-benchmark__heading > span" }),
      ).toBeVisible();
      expect(screen.getByText(fullStatus)).toBeVisible();
      expect(
        screen.getByText(/recorded worker receipts · 720 artifact observations/iu),
      ).toBeVisible();
      expect(
        screen.getByText(/60 model-output receipts replayed against sealed holdouts/iu),
      ).toBeVisible();
      expect(screen.getByText(/provider execution is not independently attested/iu)).toBeVisible();
      expect(
        screen.getByText(/compute and byte avoidance are separate impact targets/iu),
      ).toBeVisible();
      expect(screen.getByText(/recorded evaluator output/iu)).toBeVisible();
      expect(
        screen.getByText(
          /39 fail-closed control cases tested separately.*explicitly approved state transitions.*insufficient or ambiguous evidence/iu,
        ),
      ).toBeVisible();
      expect(
        screen.getByText(
          /deterministic validator classification on 60 resolvable sealed holdouts/iu,
        ),
      ).toBeVisible();
      expect(screen.queryByText(/attested evaluator output/iu)).not.toBeInTheDocument();
      expect(screen.getByText("100%")).toBeVisible();
      expect(screen.getByText("0")).toBeVisible();
      expect(screen.getByText("+33.34%")).toBeVisible();
      expect(screen.getAllByText("70%")).toHaveLength(4);
      expect(screen.getAllByText("65%")).toHaveLength(3);
      expect(screen.getByText("-10.32%")).toBeVisible();
      expect(
        screen.getByText(
          /negative scenario value means net verification or invalidation overhead/iu,
        ),
      ).toBeVisible();
      expect(screen.getAllByText("Intact")).toHaveLength(3);
      expect(screen.getByText(/timing \(excluded from acceptance\)/iu)).toBeVisible();
      expect(screen.queryByText("No measured result")).not.toBeInTheDocument();
    },
  );

  it("keeps core mission success distinct from a missed secondary impact target", async () => {
    render(
      <ReferenceScenarioExperience
        adapter={adapterFixture({
          benchmarkSuite: vi.fn(async () => recordedSavingsMissSuite()),
        })}
      />,
    );

    expect(await screen.findByRole("heading", { name: "Core mission gates passed" })).toBeVisible();
    expect(
      screen.getByText("Impact target not met", {
        selector: ".reference-benchmark__heading > span",
      }),
    ).toBeVisible();
    expect(screen.getByText("Full impact benchmark · not passed")).toBeVisible();
    expect(
      screen.getByText(/compute and byte avoidance are separate impact targets/iu),
    ).toBeVisible();
  });

  it("presents the live adaptive path, Grafana proof, deterministic result, and safe intent", async () => {
    const runScenario = vi.fn(async (scenarioId: ReferenceScenarioId) =>
      parsedResponsePacket(scenarioId),
    );
    render(<ReferenceScenarioExperience adapter={adapterFixture({ runScenario })} />);

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));

    expect(await screen.findByRole("heading", { name: "Investigation resolved" })).toBeVisible();
    expect(runScenario).toHaveBeenCalledWith(
      "tos-resource-resolution-drift-v1",
      expect.any(AbortSignal),
    );
    expect(screen.getByText("metric + log signal coverage")).toBeVisible();
    expect(screen.getAllByText("Gemini selected").length).toBeGreaterThan(0);
    expect(screen.getByText("vertex-ai · gemini-3.5-flash")).toBeVisible();
    expect(screen.getByText("1 affected + 1 protected")).toBeVisible();
    expect(screen.getByText("not a 72-frame execution")).toBeVisible();
    expect(screen.getByText(/does not execute the full 72-frame catalog scenario/iu)).toBeVisible();
    const correlationTable = screen.getByRole("table", {
      name: /Affected and protected Grafana evidence/iu,
    });
    expect(within(correlationTable).getAllByText("affected", { selector: "strong" })).toHaveLength(
      2,
    );
    expect(within(correlationTable).getAllByText("protected", { selector: "strong" })).toHaveLength(
      2,
    );
    expect(within(correlationTable).getAllByText("job-affected-001")).toHaveLength(2);
    expect(within(correlationTable).getAllByText("1".repeat(32))).toHaveLength(2);
    expect(within(correlationTable).getAllByText("2026-09-04T12:01:00.000Z")).toHaveLength(4);
    expect(within(correlationTable).getAllByText("runtime.effective_resource_sha256")).toHaveLength(
      2,
    );
    expect(within(correlationTable).getAllByText("metric.worker-cohort")).toHaveLength(2);
    expect(within(correlationTable).getAllByText("metric")).toHaveLength(2);
    expect(within(correlationTable).getAllByText(DIGEST_B)).toHaveLength(4);
    expect(correlationTable).not.toHaveTextContent("reference.scenario_id");
    expect(correlationTable).not.toHaveTextContent("reference.incident_class");
    expect(correlationTable).not.toHaveTextContent("provider_payload");
    expect(screen.getAllByText(DIGEST_C).length).toBeGreaterThan(0);
    expect(screen.getByText("38 ms")).toBeVisible();
    expect(screen.getByText("Internal agent trace")).toBeVisible();
    expect(screen.getAllByText("incomplete-evidence").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "reconcile-resource" })).toBeVisible();
    expect(screen.getByText("Required", { selector: "dd" })).toBeVisible();
    expect(screen.getByText("No")).toBeVisible();
    expect(
      screen.getByText(/No approval was requested or granted, and no recovery ran/iu),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve simulator action" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Deny without change" })).toBeEnabled();
    expect(screen.getByText(REFERENCE_APPROVAL_PHRASE)).toBeVisible();
    expect(screen.getByText(REFERENCE_DENIAL_PHRASE)).toBeVisible();
    expect(
      screen.getByText(
        "Gemini selected queries → Grafana returned evidence → validators decided → human approval still required.",
      ),
    ).toBeVisible();
  });

  it("labels incomplete provider usage and lower-bound attempts without inventing zeros", async () => {
    const packet = await parsedPartialUsagePacket();
    render(
      <ReferenceScenarioExperience
        adapter={adapterFixture({ runScenario: vi.fn(async () => packet) })}
      />,
    );

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));

    expect(
      await screen.findByText(
        "2 model calls · partial usage observed; exact token totals unavailable (1 call unobserved)",
      ),
    ).toBeVisible();
    expect(screen.getByText("at least 1 attempt")).toBeVisible();
    expect(screen.queryByText("0 in / 0 out")).not.toBeInTheDocument();
  });

  it("records approval and shows only the verified representative simulator result", async () => {
    const packet = await parsedResponsePacket("tos-resource-resolution-drift-v1");
    let resolveDecision: (decision: ReferenceRecoveryDecision) => void = () => undefined;
    const pendingDecision = new Promise<ReferenceRecoveryDecision>((resolve) => {
      resolveDecision = resolve;
    });
    const decideRecovery = vi.fn(
      async (
        _packet: ReferenceResponsePacket,
        _choice: ReferenceRecoveryChoice,
        _signal?: AbortSignal,
      ) => pendingDecision,
    );
    render(
      <ReferenceScenarioExperience
        adapter={adapterFixture({
          decideRecovery,
          runScenario: vi.fn(async () => packet),
        })}
      />,
    );

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));
    await screen.findByRole("heading", { name: "Investigation resolved" });
    fireEvent.click(screen.getByRole("button", { name: "Approve simulator action" }));

    expect(screen.getByRole("status")).toHaveTextContent(/waiting for the simulator/iu);
    expect(screen.getByRole("button", { name: "Approve simulator action" })).toBeDisabled();
    expect(decideRecovery).toHaveBeenCalledWith(packet, "approved", expect.any(AbortSignal));

    resolveDecision(await parsedRecoveryDecision(packet, "approved"));
    expect(
      await screen.findByRole("heading", { name: "Representative simulator recovery applied" }),
    ).toBeVisible();
    expect(screen.getByText("1 → 2")).toBeVisible();
    expect(screen.getByText("Unchanged", { selector: "dd" })).toBeVisible();
    expect(screen.getByText(`reference-recovery:${"a".repeat(64)}`)).toBeVisible();
    expect(screen.getByText("Fresh simulator state verified")).toBeVisible();
    expect(screen.getByText(/intent-expected fields matched/iu)).toBeVisible();
    expect(screen.getByText(/does not establish a rerender, pixel output/iu)).toBeVisible();
    expect(screen.getByText(/Representative scope only: 1 affected exemplar/iu)).toBeVisible();
    expect(screen.getByText(/Identity was not verified/iu)).toBeVisible();
    expect(screen.getByText(/Production untouched: no production access was used/iu)).toBeVisible();
    expect(
      screen.getByText(/human demo gesture recorded.*fresh simulator state verified/iu),
    ).toBeVisible();
    expect(
      screen.queryByText(/human approval still required.*human demo gesture recorded/iu),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Approve simulator action" }),
    ).not.toBeInTheDocument();
  });

  it("records denial without changing simulator state or issuing recovery proof", async () => {
    const packet = await parsedResponsePacket("tos-resource-resolution-drift-v1");
    const decideRecovery = vi.fn(async () => parsedRecoveryDecision(packet, "denied"));
    render(
      <ReferenceScenarioExperience
        adapter={adapterFixture({
          decideRecovery,
          runScenario: vi.fn(async () => packet),
        })}
      />,
    );

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));
    await screen.findByRole("heading", { name: "Investigation resolved" });
    fireEvent.click(screen.getByRole("button", { name: "Deny without change" }));

    expect(
      await screen.findByRole("heading", { name: "Recovery denied; simulator unchanged" }),
    ).toBeVisible();
    expect(decideRecovery).toHaveBeenCalledWith(packet, "denied", expect.any(AbortSignal));
    expect(screen.getByText("1 → 1")).toBeVisible();
    expect(screen.getAllByText("Not issued")).toHaveLength(2);
    expect(
      screen.getByText(/No recovery receipt or post-action verification was issued/iu),
    ).toBeVisible();
    expect(screen.queryByText("Fresh simulator state verified")).not.toBeInTheDocument();
    expect(screen.getByText(/human denial recorded → simulator unchanged/iu)).toBeVisible();
  });

  it("fails closed when a recovery decision response is unavailable or malformed", async () => {
    const decideRecovery = vi.fn(async () => {
      throw new Error("malformed");
    });
    render(<ReferenceScenarioExperience adapter={adapterFixture({ decideRecovery })} />);

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));
    await screen.findByRole("heading", { name: "Investigation resolved" });
    fireEvent.click(screen.getByRole("button", { name: "Approve simulator action" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /Decision unavailable or invalid.*No applied or denied outcome/iu,
    );
    expect(
      screen.queryByRole("heading", { name: "Representative simulator recovery applied" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Fresh simulator state verified")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve simulator action" })).toBeEnabled();
  });

  it("shows an unresolved live run without manufacturing an action", async () => {
    const runScenario = vi.fn(async (scenarioId: ReferenceScenarioId) =>
      parsedResponsePacket(scenarioId, "unresolved"),
    );
    render(<ReferenceScenarioExperience adapter={adapterFixture({ runScenario })} />);

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));

    expect(
      await screen.findByRole("heading", { name: "Investigation remains unresolved" }),
    ).toBeVisible();
    expect(screen.getByText("No action intent")).toBeVisible();
    expect(screen.getAllByText("evidence-unavailable").length).toBeGreaterThan(0);
    expect(screen.getByText(/No approval was requested, and no recovery ran/iu)).toBeVisible();
    expect(screen.queryByRole("heading", { name: "reconcile-resource" })).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Approve simulator action" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Deny without change" })).not.toBeInTheDocument();
    const authority = screen.getByText(
      "Gemini not invoked → Grafana evidence unavailable → validators reported insufficient evidence → no action available for approval.",
    );
    expect(authority).toBeVisible();
    expect(authority).not.toHaveTextContent("Gemini selected");
    expect(authority).not.toHaveTextContent("Grafana returned");
    expect(authority).not.toHaveTextContent("validators decided");
  });

  it("fails closed when the live response cannot be validated", async () => {
    const runScenario = vi.fn(async () => {
      throw new Error("malformed");
    });
    render(<ReferenceScenarioExperience adapter={adapterFixture({ runScenario })} />);

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));

    expect(await screen.findByText(/Live investigation unavailable or invalid/iu)).toBeVisible();
    expect(screen.queryByText("Investigation resolved")).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "reconcile-resource" })).not.toBeInTheDocument();
  });

  it("aborts and discards an in-flight run when the selected scenario changes", async () => {
    const oldPacket = await parsedResponsePacket("tos-resource-resolution-drift-v1");
    let resolveRun: (packet: ReferenceResponsePacket) => void = () => undefined;
    let runSignal: AbortSignal | undefined;
    const pendingRun = new Promise<ReferenceResponsePacket>((resolve) => {
      resolveRun = resolve;
    });
    const runScenario = vi.fn(async (_scenarioId: ReferenceScenarioId, signal?: AbortSignal) => {
      runSignal = signal;
      return pendingRun;
    });
    render(<ReferenceScenarioExperience adapter={adapterFixture({ runScenario })} />);

    await screen.findByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live investigation" }));
    expect(screen.getByRole("status")).toHaveTextContent(/waiting for the bounded investigation/iu);
    fireEvent.click(screen.getByRole("button", { name: /configuration rollout.*72 affected/iu }));

    expect(runSignal?.aborted).toBe(true);
    resolveRun(oldPacket);
    await screen.findByRole("heading", { name: "A stale color configuration remained active" });
    await waitFor(() => {
      expect(
        screen.queryByRole("heading", { name: "Investigation resolved" }),
      ).not.toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: "Run live investigation" })).toBeEnabled();
  });
});

describe("reference demo API adapter", () => {
  it.each([
    ["unobserved calls above the total", { unobserved_model_calls: 3 }],
    ["exact tokens for incomplete usage", { input_tokens: 321, output_tokens: 17 }],
  ])("rejects model usage with %s", async (_label, invocationMutation) => {
    const raw = rawPartialUsagePacket();
    const invocation = raw.model_invocation as Readonly<Record<string, unknown>>;

    await expect(
      parseReferenceResponsePacket(
        { ...raw, model_invocation: { ...invocation, ...invocationMutation } },
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it("rejects model usage metadata on a non-model span", async () => {
    const raw = rawPartialUsagePacket();
    const trace = raw.agent_trace as Readonly<Record<string, unknown>>;
    const spans = trace.spans as readonly Readonly<Record<string, unknown>>[];

    await expect(
      parseReferenceResponsePacket(
        {
          ...raw,
          agent_trace: {
            ...trace,
            spans: [{ ...spans[0], unobserved_model_calls: 1 }, ...spans.slice(1)],
          },
        },
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it.each([
    [
      "tos-resource-resolution-drift-v1",
      ["runtime.effective_resource_sha256", "runtime.frame_pipeline_sha256"],
    ],
    [
      "tos-config-rollout-drift-v1",
      [
        "runtime.effective_config_sha256",
        "runtime.config_generation",
        "runtime.frame_pipeline_sha256",
      ],
    ],
    [
      "tos-stale-derivative-cache-v1",
      [
        "runtime.frame_pipeline_sha256",
        "derivative.parent_sha256",
        "cache.generation",
        "cache.key",
      ],
    ],
  ] as const)(
    "retains only the immutable %s correlation projection",
    async (scenarioId, fields) => {
      const packet = await parsedResponsePacket(scenarioId);
      const projection = packet.runtime_evidence_projection;

      expect(projection.observations).toHaveLength(4);
      expect(Object.isFrozen(projection)).toBe(true);
      expect(Object.isFrozen(projection.observations)).toBe(true);
      expect(Object.isFrozen(projection.observations[0])).toBe(true);
      expect(Object.isFrozen(projection.observations[0]?.decisive_values)).toBe(true);
      expect(projection.observations.map(({ scope_role }) => scope_role)).toEqual([
        "affected",
        "protected",
        "affected",
        "protected",
      ]);
      expect(projection.observations[0]?.decisive_values).toEqual([]);
      expect(projection.observations[0]?.declared_reference).toMatchObject({
        state: "reference_mismatch",
        approved_state_sha256: DIGEST,
      });
      expect(
        projection.observations[0]?.declared_reference?.match_statuses.filter(
          ({ matches_approved }) => !matches_approved,
        ).length,
      ).toBe(scenarioId === "tos-config-rollout-drift-v1" ? 3 : 2);
      expect(projection.observations[2]?.declared_reference).toBeNull();
      expect(projection.observations[2]?.decisive_values.map(({ field }) => field)).toEqual(fields);
      const serialized = JSON.stringify(projection);
      expect(serialized).not.toContain("reference.scenario_id");
      expect(serialized).not.toContain("reference.incident_class");
      expect(serialized).not.toContain("declared_reference.state");
      expect(serialized).not.toContain("normalized_arguments");
      expect(serialized).not.toContain("provider_payload");
    },
  );

  it.each([
    ["unknown job", { job_id: "job-outside-deterministic-scope" }],
    ["invalid trace", { trace_id: "not-a-trace" }],
    ["out-of-window time", { observed_at: "2026-09-04T11:59:59.000Z" }],
  ])("rejects a projection with a tampered %s", async (_label, mutation) => {
    const raw = rawResponsePacket("tos-resource-resolution-drift-v1");
    const projection = raw.runtime_evidence_projection as Readonly<Record<string, unknown>>;
    const observations = projection.observations as readonly Readonly<Record<string, unknown>>[];
    const tamperedProjection = {
      ...projection,
      observations: [{ ...observations[0], ...mutation }, ...observations.slice(1)],
    };
    const referenceEvidence = raw.reference_evidence as Readonly<Record<string, unknown>>;
    const tampered = {
      ...raw,
      runtime_evidence_projection: tamperedProjection,
      reference_evidence: { ...referenceEvidence, runtime_projection: tamperedProjection },
    };

    await expect(
      parseReferenceResponsePacket(
        tampered,
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it.each([
    ["one signal", ["metric.worker-cohort"]],
    ["the wrong complementary pair", ["metric.worker-cohort", "trace.by-id"]],
  ] as const)("rejects resolved evidence with %s", async (_label, queryKeys) => {
    await expect(
      parseReferenceResponsePacket(
        rawResponsePacket("tos-resource-resolution-drift-v1", "resolved", queryKeys),
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it.each([
    [
      "a missing metric match flag",
      (attributes: Readonly<Record<string, unknown>>) =>
        Object.fromEntries(
          Object.entries(attributes).filter(
            ([key]) => key !== "declared_reference.cache_key_matches_approved",
          ),
        ),
    ],
    [
      "detail on the wrong signal",
      (attributes: Readonly<Record<string, unknown>>) => ({
        ...attributes,
        "runtime.effective_resource_sha256": DIGEST_B,
      }),
    ],
    [
      "a mismatched approved-state binding",
      (attributes: Readonly<Record<string, unknown>>) => ({
        ...attributes,
        "declared_reference.approved_state_sha256": DIGEST_B,
      }),
    ],
  ] as const)("rejects %s", async (_label, mutateAttributes) => {
    const raw = rawResponsePacket("tos-resource-resolution-drift-v1");
    const projection = raw.runtime_evidence_projection as Readonly<Record<string, unknown>>;
    const observations = projection.observations as readonly Readonly<Record<string, unknown>>[];
    const metric = observations[0] ?? {};
    const attributes = metric.attributes as Readonly<Record<string, unknown>>;
    const tampered = replaceRuntimeObservations(raw, [
      { ...metric, attributes: mutateAttributes(attributes) },
      ...observations.slice(1),
    ]);

    await expect(
      parseReferenceResponsePacket(
        tampered,
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it.each([
    ["metric resource digest", 0, "a".repeat(64)],
    ["log resource sentinel", 2, "none"],
  ] as const)("rejects a %s", async (_label, observationIndex, resourceSha256) => {
    const raw = rawResponsePacket("tos-resource-resolution-drift-v1");
    const projection = raw.runtime_evidence_projection as Readonly<Record<string, unknown>>;
    const observations = projection.observations as readonly Readonly<Record<string, unknown>>[];
    const selected = observations[observationIndex] ?? {};
    const tampered = replaceRuntimeObservations(raw, [
      ...observations.slice(0, observationIndex),
      { ...selected, resource_sha256: resourceSha256 },
      ...observations.slice(observationIndex + 1),
    ]);

    await expect(
      parseReferenceResponsePacket(
        tampered,
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it("rejects an exact detail that contradicts its metric match flag", async () => {
    const raw = rawResponsePacket("tos-resource-resolution-drift-v1");
    const projection = raw.runtime_evidence_projection as Readonly<Record<string, unknown>>;
    const observations = projection.observations as readonly Readonly<Record<string, unknown>>[];
    const tampered = replaceRuntimeObservations(
      raw,
      observations.map((observation) => {
        if (observation.signal !== "log" || observation.job_id !== "job-affected-001") {
          return observation;
        }
        return {
          ...observation,
          resource_sha256: "a".repeat(64),
          attributes: {
            ...(observation.attributes as Readonly<Record<string, unknown>>),
            "runtime.effective_resource_sha256": DIGEST,
          },
        };
      }),
    );

    await expect(
      parseReferenceResponsePacket(
        tampered,
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it("rejects tampered decisive evidence instead of rendering it", async () => {
    const raw = rawResponsePacket("tos-resource-resolution-drift-v1");
    const projection = raw.runtime_evidence_projection as Readonly<Record<string, unknown>>;
    const observations = projection.observations as readonly Readonly<Record<string, unknown>>[];
    const first = observations[0] ?? {};
    const attributes = first.attributes as Readonly<Record<string, unknown>>;
    const tamperedProjection = {
      ...projection,
      observations: [
        {
          ...first,
          attributes: { ...attributes, "runtime.effective_resource_sha256": "forged" },
        },
        ...observations.slice(1),
      ],
    };
    const referenceEvidence = raw.reference_evidence as Readonly<Record<string, unknown>>;

    await expect(
      parseReferenceResponsePacket(
        {
          ...raw,
          runtime_evidence_projection: tamperedProjection,
          reference_evidence: { ...referenceEvidence, runtime_projection: tamperedProjection },
        },
        "tos-resource-resolution-drift-v1",
        REQUEST_ID,
        async () => DIGEST,
      ),
    ).rejects.toThrow("reference-response-invalid");
  });

  it("posts only a fresh opaque request identifier and parses the bound response", async () => {
    const requestIds = [REQUEST_ID, "123e4567-e89b-12d3-a456-426614174001"];
    const bodies: unknown[] = [];
    const createRequestId = vi.fn(() => requestIds.shift() ?? "unexpected");
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe(
        "https://colortrace.example/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs",
      );
      expect(init).toMatchObject({
        credentials: "same-origin",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        method: "POST",
        redirect: "error",
      });
      bodies.push(JSON.parse(String(init?.body)) as unknown);
      return Response.json(rawResponsePacket("tos-resource-resolution-drift-v1"));
    });
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example/workspace",
      createRequestId,
      fetch: fetchMock,
      sha256: async () => DIGEST,
    });

    const first = await adapter.runScenario("tos-resource-resolution-drift-v1");
    const second = await adapter.runScenario("tos-resource-resolution-drift-v1");

    expect(first.status).toBe("resolved");
    expect(second.status).toBe("resolved");
    expect(createRequestId).toHaveBeenCalledTimes(2);
    expect(bodies).toEqual([
      { schema: "reference-scenario-run-request/v1", request_id: REQUEST_ID },
      {
        schema: "reference-scenario-run-request/v1",
        request_id: "123e4567-e89b-12d3-a456-426614174001",
      },
    ]);
    expect(JSON.stringify(bodies)).not.toContain("resource-resolution-drift");
  });

  it("posts the exact recovery decision bindings and verifies the approved response", async () => {
    const packet = await parsedResponsePacket("tos-resource-resolution-drift-v1");
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      expect(String(input)).toBe(
        `https://colortrace.example/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs/${REQUEST_ID}/decision`,
      );
      expect(init).toMatchObject({
        credentials: "same-origin",
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        method: "POST",
        redirect: "error",
      });
      expect(JSON.parse(String(init?.body))).toEqual({
        schema: "reference-recovery-decision-request/v1",
        request_id: REQUEST_ID,
        decision: "approved",
        approval_phrase: REFERENCE_APPROVAL_PHRASE,
        approval_nonce: APPROVAL_NONCE,
        packet_id: packet.packet_id,
        packet_sha256: packet.derivation_sha256,
        expected_state_sha256: packet.expected_state_assessment.expected_state_sha256,
        reconciliation_id: packet.diagnosis_reconciliation.reconciliation_id,
        action_intent_id: packet.action_intent?.action_intent_id,
        action_intent_sha256: packet.action_intent?.derivation_sha256,
      });
      return Response.json(rawRecoveryDecision(packet, "approved"), {
        headers: {
          "X-ColorTrace-Execution-Target": "colortrace-simulator",
          "X-ColorTrace-Production-State-Changed": "false",
        },
      });
    });
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example/workspace",
      createApprovalNonce: () => APPROVAL_NONCE,
      fetch: fetchMock,
      sha256: async () => DIGEST,
    });

    const decision = await adapter.decideRecovery(packet, "approved");

    expect(decision).toMatchObject({
      outcome: "applied",
      protected_state_unchanged: true,
      scope: {
        affected_job_count: 1,
        protected_job_count: 1,
        establishes_full_population_scope: false,
      },
      execution_boundary: {
        identity_verified: false,
        identity_assurance: "unverified-public-demo-gesture",
        production_access_used: false,
        production_state_changed: false,
      },
      verification: {
        verifier: "deterministic-simulator-state",
        establishes_pixel_output: false,
        establishes_full_population_scope: false,
        production_evidence: false,
      },
    });
  });

  it("rejects a recovery response with malformed verification proof", async () => {
    const packet = await parsedResponsePacket("tos-resource-resolution-drift-v1");
    const raw = rawRecoveryDecision(packet, "approved");
    const malformedVerification = {
      ...(raw.verification as Readonly<Record<string, unknown>>),
      establishes_pixel_output: true,
    };
    const malformed = {
      ...raw,
      verification: malformedVerification,
      receipt: {
        ...(raw.receipt as Readonly<Record<string, unknown>>),
        verification: malformedVerification,
      },
    };
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      createApprovalNonce: () => APPROVAL_NONCE,
      fetch: async () =>
        Response.json(malformed, {
          headers: {
            "X-ColorTrace-Execution-Target": "colortrace-simulator",
            "X-ColorTrace-Production-State-Changed": "false",
          },
        }),
      sha256: async () => DIGEST,
    });

    await expect(adapter.decideRecovery(packet, "approved")).rejects.toMatchObject({
      code: "reference-recovery-response-invalid",
    });
  });

  it("strictly accepts a recorded benchmark report", async () => {
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () => Response.json(recordedBenchmarkSuite()),
      sha256: async () => DIGEST,
    });

    const suite = await adapter.benchmarkSuite();

    expect(suite.result_state).toBe("recorded");
    expect(suite.result).toMatchObject({
      passed: true,
      evidence: {
        source: "recorded-worker-receipts",
        observation_count: 720,
      },
      metrics: {
        false_authorized_actions: 0,
        recorded_model_advantage_basis_points: 3334,
      },
    });
  });

  it("rejects a recorded benchmark with a malformed evidence claim", async () => {
    const suite = recordedBenchmarkSuite();
    const malformed = {
      ...suite,
      result: {
        ...suite.result,
        evidence: { ...suite.result?.evidence, observation_count: 719 },
      },
    };
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () => Response.json(malformed),
      sha256: async () => DIGEST,
    });

    await expect(adapter.benchmarkSuite()).rejects.toMatchObject({
      code: "reference-response-invalid",
    });
  });

  it.each([
    [
      "scenario binding",
      {
        ...rawResponsePacket("tos-resource-resolution-drift-v1"),
        scenario_id: "tos-config-rollout-drift-v1",
      },
    ],
    [
      "packet digest",
      {
        ...rawResponsePacket("tos-resource-resolution-drift-v1"),
        derivation_sha256: DIGEST_B,
      },
    ],
    [
      "resolved status",
      {
        ...rawResponsePacket("tos-resource-resolution-drift-v1"),
        status: "unresolved",
      },
    ],
    [
      "operational incident binding",
      {
        ...rawResponsePacket("tos-resource-resolution-drift-v1", "unresolved"),
        operational_evidence_assessment: {
          ...(rawResponsePacket("tos-resource-resolution-drift-v1", "unresolved")
            .operational_evidence_assessment as Readonly<Record<string, unknown>>),
          incident_id: "reference-incident-wrong",
        },
      },
    ],
  ])("rejects a malformed %s", async (_label, responsePacket) => {
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      createRequestId: () => REQUEST_ID,
      fetch: async () => Response.json(responsePacket),
      sha256: async () => DIGEST,
    });

    await expect(adapter.runScenario("tos-resource-resolution-drift-v1")).rejects.toMatchObject({
      code: "reference-response-invalid",
    });
  });

  it("loads strict same-origin contracts and verifies open-film PNG bindings", async () => {
    const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1]);
    const fetched: string[] = [];
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      fetched.push(url);
      expect(init).toMatchObject({
        credentials: "same-origin",
        method: "GET",
        redirect: "error",
      });
      if (url.endsWith("/v1/demo/scenarios")) {
        return Response.json(scenarioList());
      }
      if (url.endsWith("/v1/benchmarks/reference-suite")) {
        return Response.json(benchmarkSuite());
      }
      if (url.endsWith("/visuals/expected")) {
        return new Response(png, {
          headers: {
            "Content-Type": "image/png",
            "X-ColorTrace-Pixel-Evidence": "true",
            "X-ColorTrace-Representation": "open-film-preview-png/v1",
            "X-ColorTrace-Scenario-SHA256": DIGEST,
            "X-Content-SHA256": DIGEST,
          },
        });
      }
      const scenarioId = REFERENCE_SCENARIO_IDS.find((candidate) => url.endsWith(candidate));
      if (scenarioId === undefined) return new Response(null, { status: 404 });
      return Response.json({ ...scenarioDetail(scenarioId), scenario: {} });
    });
    const revokeObjectUrl = vi.fn();
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example/workspace",
      fetch: fetchMock,
      createObjectUrl: () => "blob:verified-reference",
      revokeObjectUrl,
      sha256: async () => DIGEST,
    });

    const catalog = await adapter.listScenarios();
    const detail = await adapter.getScenario("tos-resource-resolution-drift-v1");
    const benchmark = await adapter.benchmarkSuite();
    const descriptor = catalog.items[0]?.visuals.find((item) => item.kind === "expected");
    if (descriptor === undefined) throw new Error("missing visual fixture");
    const loaded = await adapter.loadVisual(descriptor, DIGEST);
    adapter.releaseVisual(loaded);

    expect(detail.evidence_requirements["missing_conflicting_or_cross-run_evidence"]).toBe(
      "unresolved",
    );
    expect(benchmark.result_state).toBe("not-reported");
    expect(loaded).toMatchObject({
      content_sha256: DIGEST,
      height: 506,
      pixel_evidence: true,
      representation: "open-film-preview-png/v1",
      scenario_sha256: DIGEST,
      src: "blob:verified-reference",
      width: 960,
    });
    expect(revokeObjectUrl).toHaveBeenCalledWith("blob:verified-reference");
    expect(fetched).toContain("https://colortrace.example/v1/demo/scenarios");
  });

  it("rejects a pixel preview whose scenario binding does not match", async () => {
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), {
          headers: {
            "Content-Type": "image/png",
            "X-ColorTrace-Pixel-Evidence": "true",
            "X-ColorTrace-Representation": "open-film-preview-png/v1",
            "X-ColorTrace-Scenario-SHA256": `sha256:${"b".repeat(64)}`,
            "X-Content-SHA256": DIGEST,
          },
        }),
      sha256: async () => DIGEST,
    });
    const descriptor = summary("tos-resource-resolution-drift-v1").visuals[0];
    if (descriptor === undefined) throw new Error("missing visual fixture");

    await expect(adapter.loadVisual(descriptor, DIGEST)).rejects.toMatchObject({
      code: "reference-visual-response-invalid",
    });
  });

  it("rejects a pixel preview whose response digest conflicts with its descriptor", async () => {
    const responseDigest = `sha256:${"b".repeat(64)}`;
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), {
          headers: {
            "Content-Type": "image/png",
            "X-ColorTrace-Pixel-Evidence": "true",
            "X-ColorTrace-Representation": "open-film-preview-png/v1",
            "X-ColorTrace-Scenario-SHA256": DIGEST,
            "X-Content-SHA256": responseDigest,
          },
        }),
      sha256: async () => responseDigest,
    });
    const descriptor = summary("tos-resource-resolution-drift-v1").visuals[0];
    if (descriptor === undefined) throw new Error("missing visual fixture");

    await expect(adapter.loadVisual(descriptor, DIGEST)).rejects.toMatchObject({
      code: "reference-visual-response-invalid",
    });
  });

  it("rejects a pixel preview whose bytes conflict with the declared digest", async () => {
    const actualDigest = `sha256:${"b".repeat(64)}`;
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), {
          headers: {
            "Content-Type": "image/png",
            "X-ColorTrace-Pixel-Evidence": "true",
            "X-ColorTrace-Representation": "open-film-preview-png/v1",
            "X-ColorTrace-Scenario-SHA256": DIGEST,
            "X-Content-SHA256": DIGEST,
          },
        }),
      sha256: async () => actualDigest,
    });
    const descriptor = summary("tos-resource-resolution-drift-v1").visuals[0];
    if (descriptor === undefined) throw new Error("missing visual fixture");

    await expect(adapter.loadVisual(descriptor, DIGEST)).rejects.toMatchObject({
      code: "reference-visual-digest-conflict",
    });
  });

  it("rejects bytes without a PNG signature", async () => {
    const adapter = createReferenceDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(new TextEncoder().encode("not a png"), {
          headers: {
            "Content-Type": "image/png",
            "X-ColorTrace-Pixel-Evidence": "true",
            "X-ColorTrace-Representation": "open-film-preview-png/v1",
            "X-ColorTrace-Scenario-SHA256": DIGEST,
            "X-Content-SHA256": DIGEST,
          },
        }),
      sha256: async () => DIGEST,
    });
    const descriptor = summary("tos-resource-resolution-drift-v1").visuals[0];
    if (descriptor === undefined) throw new Error("missing visual fixture");

    await expect(adapter.loadVisual(descriptor, DIGEST)).rejects.toMatchObject({
      code: "reference-visual-response-invalid",
    });
  });
});
