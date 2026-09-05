import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, type Page, test } from "@playwright/test";

import {
  REFERENCE_SCENARIO_IDS,
  type ReferenceAuthority,
  type ReferenceBenchmarkSuite,
  type ReferenceImpactBenchmark,
  type ReferenceIncidentClass,
  type ReferenceRecoveryKind,
  type ReferenceScenarioDetail,
  type ReferenceScenarioId,
  type ReferenceScenarioList,
  type ReferenceScenarioSummary,
  type ReferenceVisualKind,
  type ReferenceVisualRepresentation,
  type ReferenceVisualSourceRelation,
} from "../src/reference-demo-api.ts";

const DIGEST = `sha256:${"a".repeat(64)}`;
const DIGEST_B = `sha256:${"b".repeat(64)}`;
const DIGEST_C = `sha256:${"c".repeat(64)}`;
const REQUEST_ID = "123e4567-e89b-12d3-a456-426614174000";
const APPROVAL_NONCE = "123e4567-e89b-12d3-a456-426614174099";
const RUN_INCIDENT_ID = `reference-incident-${"a".repeat(24)}`;
const RUN_ID = `reference-run-${"a".repeat(24)}`;
const PREVIEW_ROOT = fileURLToPath(
  new URL("../../api/src/colortrace_api/reference_previews/", import.meta.url),
);
const RECORDED_BENCHMARK_PATH = fileURLToPath(
  new URL(
    "../../api/src/colortrace_api/reference_results/reference-impact-benchmark.json",
    import.meta.url,
  ),
);
const VISUAL_KINDS = ["expected", "observed", "recovered", "diff"] as const;

type PreviewManifest = {
  readonly scenarios: Readonly<
    Record<
      ReferenceScenarioId,
      {
        readonly served_artifact_id: string;
        readonly visuals: Readonly<
          Record<
            ReferenceVisualKind,
            {
              readonly filename: string;
              readonly height: 506;
              readonly representation: ReferenceVisualRepresentation;
              readonly sha256: string;
              readonly source_artifact_ids: readonly string[];
              readonly source_canonical_pixel_sha256: readonly string[];
              readonly source_output_sha256: readonly string[];
              readonly source_receipt_sha256: readonly string[];
              readonly source_relation: ReferenceVisualSourceRelation;
              readonly width: 960;
            }
          >
        >;
      }
    >
  >;
};

const previewManifest = JSON.parse(
  await readFile(path.join(PREVIEW_ROOT, "manifest.json"), "utf8"),
) as PreviewManifest;
const recordedBenchmarkResult = JSON.parse(
  await readFile(RECORDED_BENCHMARK_PATH, "utf8"),
) as ReferenceImpactBenchmark;

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

const SCENARIOS = {
  "tos-resource-resolution-drift-v1": {
    facts: ["runtime.effective_resource_sha256", "runtime.frame_pipeline_sha256"],
    incidentClass: "resource-resolution-drift/v1",
    recoveryKind: "reconcile-resource",
    symptom: "Frames completed, but a worker resolved a different LUT than the approved reference.",
    title: "A successful render resolved the wrong look resource",
  },
  "tos-config-rollout-drift-v1": {
    facts: [
      "runtime.effective_config_sha256",
      "runtime.config_generation",
      "runtime.frame_pipeline_sha256",
    ],
    incidentClass: "configuration-rollout-drift/v1",
    recoveryKind: "pin-rollout",
    symptom:
      "Frames completed under an older configuration generation while the LUT stayed current.",
    title: "A stale color configuration remained active",
  },
  "tos-stale-derivative-cache-v1": {
    facts: [
      "runtime.frame_pipeline_sha256",
      "derivative.parent_sha256",
      "cache.generation",
      "cache.key",
    ],
    incidentClass: "stale-derivative-cache/v1",
    recoveryKind: "invalidate-cache",
    symptom:
      "The frame pipeline matched the reference, but cached derivatives came from older parents.",
    title: "Correct frames served stale review derivatives",
  },
} as const satisfies Readonly<
  Record<
    ReferenceScenarioId,
    {
      readonly facts: readonly string[];
      readonly incidentClass: ReferenceIncidentClass;
      readonly recoveryKind: ReferenceRecoveryKind;
      readonly symptom: string;
      readonly title: string;
    }
  >
>;

const SCENARIO_SHA256 = {
  "tos-resource-resolution-drift-v1": `sha256:${"1".repeat(64)}`,
  "tos-config-rollout-drift-v1": `sha256:${"2".repeat(64)}`,
  "tos-stale-derivative-cache-v1": `sha256:${"3".repeat(64)}`,
} as const satisfies Readonly<Record<ReferenceScenarioId, string>>;

function summary(scenarioId: ReferenceScenarioId): ReferenceScenarioSummary {
  const metadata = SCENARIOS[scenarioId];
  const preview = previewManifest.scenarios[scenarioId];
  return {
    scenario_id: scenarioId,
    scenario_sha256: SCENARIO_SHA256[scenarioId],
    title: metadata.title,
    symptom: metadata.symptom,
    incident_class: metadata.incidentClass,
    recovery_kind: metadata.recoveryKind,
    scope: {
      artifact_count: 240,
      affected_artifact_count: 72,
      protected_artifact_count: 168,
    },
    visuals: VISUAL_KINDS.map((kind) => {
      const visual = preview.visuals[kind];
      return {
        kind,
        href: `/v1/demo/scenarios/${scenarioId}/visuals/${kind}`,
        content_sha256: visual.sha256,
        representation: visual.representation,
        pixel_evidence: true,
        width: visual.width,
        height: visual.height,
        served_artifact_id: preview.served_artifact_id,
        source_artifact_ids: visual.source_artifact_ids,
        source_relation: visual.source_relation,
        source_receipt_sha256: visual.source_receipt_sha256,
        source_output_sha256: visual.source_output_sha256,
        source_canonical_pixel_sha256: visual.source_canonical_pixel_sha256,
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
  const metadata = SCENARIOS[scenarioId];
  return {
    schema: "reference-scenario-detail/v1",
    summary: summary(scenarioId),
    evidence_requirements: {
      minimum_complementary_signal_classes: 2,
      runtime_fact_source: "structured-grafana-observations",
      required_fact_fields: metadata.facts,
      decision_authority: "deterministic-validators",
      "missing_conflicting_or_cross-run_evidence": "unresolved",
    },
    recovery_boundary: {
      intent: metadata.recoveryKind,
      requires_human_approval: true,
      execution_target: "colortrace-simulator",
      catalog_executes_actions: false,
    },
    provenance: PROVENANCE,
    authority: AUTHORITY,
    detail_sha256: DIGEST,
  };
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Readonly<Record<string, unknown>>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new Error("unsupported fixture value");
}

function digest(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function benchmarkSuite(): ReferenceBenchmarkSuite {
  const body: Omit<ReferenceBenchmarkSuite, "suite_sha256"> = {
    schema: "reference-benchmark-suite/v1",
    suite_id: "tears-of-steel-reference-suite-v1",
    definition_state: "sealed",
    result_state: "not-reported",
    scenarios: REFERENCE_SCENARIO_IDS.map((scenarioId) => ({
      scenario_id: scenarioId,
      scenario_sha256: SCENARIO_SHA256[scenarioId],
      incident_class: SCENARIOS[scenarioId].incidentClass,
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
  };
  return { ...body, suite_sha256: digest(canonicalJson(body)) };
}

function recordedBenchmarkSuite(): ReferenceBenchmarkSuite {
  const suite = benchmarkSuite();
  const body: Omit<ReferenceBenchmarkSuite, "suite_sha256"> = {
    schema: suite.schema,
    suite_id: suite.suite_id,
    definition_state: suite.definition_state,
    result_state: "recorded",
    scenarios: suite.scenarios,
    acceptance_requirements: suite.acceptance_requirements,
    measurement_boundary: {
      ...suite.measurement_boundary,
      catalog_claims_observed_savings: true,
    },
    result: recordedBenchmarkResult,
    provenance: suite.provenance,
    authority: suite.authority,
  };
  return { ...body, suite_sha256: digest(canonicalJson(body)) };
}

function runtimeObservation(
  queryKey: "metric.worker-cohort" | "log.config-cohort",
  role: "affected" | "protected",
): Readonly<Record<string, unknown>> {
  const affected = role === "affected";
  const metric = queryKey === "metric.worker-cohort";
  const evidenceId = metric ? DIGEST_B : DIGEST_C;
  const attributes = metric
    ? {
        "declared_reference.state": affected ? "reference_mismatch" : "reference_match",
        "declared_reference.approved_state_sha256": DIGEST,
        "declared_reference.effective_resource_matches_approved": String(!affected),
        "declared_reference.effective_config_matches_approved": "true",
        "declared_reference.config_generation_matches_approved": "true",
        "declared_reference.frame_pipeline_matches_approved": String(!affected),
        "declared_reference.derivative_parent_matches_approved": "true",
        "declared_reference.derivative_generation_matches_approved": "true",
        "declared_reference.cache_key_matches_approved": "true",
        "reference.evidence_scope": "representative",
        "reference.affected_representative_count": "1",
        "reference.protected_representative_count": "1",
        "reference.population_affected_artifact_count": "72",
        "reference.population_protected_artifact_count": "168",
      }
    : {
        "runtime.effective_resource_sha256": affected ? DIGEST_B : DIGEST,
        "runtime.effective_config_sha256": DIGEST,
        "runtime.config_generation": "7",
        "runtime.frame_pipeline_sha256": affected ? DIGEST_B : DIGEST,
        "cache.key": "cache:03_2a:00003:g7",
      };
  return {
    schema: "normalized-runtime-observation/v1",
    request_id: "evidence-request-001",
    incident_id: RUN_INCIDENT_ID,
    event_id: `event-${metric ? 0 : 1}-${role}`,
    signal: metric ? "metric" : "log",
    fixture_id: "tears-of-steel-linear-exr-240-v1",
    run_id: RUN_ID,
    job_id: affected ? "job-affected-001" : "job-safe-001",
    worker_id: `worker-${role}`,
    trace_id: affected ? "1".repeat(32) : "2".repeat(32),
    artifact_id: affected ? "frame:03_2a:00000" : "frame:04_5f:00108",
    config_sha256: "a".repeat(64),
    resource_sha256: metric ? "none" : (affected ? DIGEST_B : DIGEST).slice("sha256:".length),
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
      tool: metric ? "query_prometheus" : "query_loki_logs",
      normalized_arguments: { query: queryKey, provider_payload: "not retained" },
    },
    fact_id: `runtime-fact:${(metric ? (affected ? "d" : "e") : affected ? "f" : "9").repeat(64)}`,
    fact_sha256: `sha256:${(metric ? (affected ? "d" : "e") : affected ? "f" : "9").repeat(64)}`,
  };
}

function rawReferenceRun(): Readonly<Record<string, unknown>> {
  const expectedAssessmentId = `expected-assessment:${"a".repeat(64)}`;
  const operationalAssessmentId = `operational-assessment:${"b".repeat(64)}`;
  const reconciliationId = `diagnosis-reconciliation:${"c".repeat(64)}`;
  const evidenceFactIds = ["9", "d", "e", "f"].map((value) => `runtime-fact:${value.repeat(64)}`);
  const actionIntent = {
    schema: "simulator-action-intent/v1",
    reconciliation_id: reconciliationId,
    incident_class: "resource-resolution-drift/v1",
    command: "reconcile-resource",
    target: "simulator",
    requires_human_approval: true,
    authorizes_execution: false,
    affected_job_ids: ["job-affected-001"],
    evidence_fact_ids: evidenceFactIds,
    parameters: {
      changed_fields: ["effective_resource_sha256"],
      expected: { effective_resource_sha256: DIGEST },
      observed: { effective_resource_sha256: DIGEST_B },
    },
    action_intent_id: `action-intent:${"e".repeat(64)}`,
    derivation_sha256: `sha256:${"e".repeat(64)}`,
  };
  const queryKeys = ["metric.worker-cohort", "log.config-cohort"] as const;
  const evidenceIds = [DIGEST, DIGEST_B, DIGEST_C];
  const projection = {
    schema: "runtime-evidence-projection/v1",
    request_id: "evidence-request-001",
    incident_id: RUN_INCIDENT_ID,
    query_keys: queryKeys,
    evidence_ids: evidenceIds.slice(1),
    observations: queryKeys.flatMap((queryKey) => [
      runtimeObservation(queryKey, "affected"),
      runtimeObservation(queryKey, "protected"),
    ]),
    projection_sha256: DIGEST,
  };
  const classAssessments = [
    "resource-resolution-drift/v1",
    "configuration-rollout-drift/v1",
    "stale-derivative-cache/v1",
  ].map((incidentClass, index) => {
    const supported = index === 0;
    const hex = ["1", "2", "3"][index] ?? "1";
    return {
      schema: "incident-class-assessment/v1",
      status: supported ? "supported" : "rejected",
      incident_class: incidentClass,
      expected_state_assessment_id: expectedAssessmentId,
      operational_evidence_assessment_id: operationalAssessmentId,
      scope: { affected_job_ids: ["job-affected-001"], safe_job_ids: ["job-safe-001"] },
      evidence_fact_ids: evidenceFactIds,
      cause: supported ? { changed_fields: ["effective_resource_sha256"] } : {},
      reason_codes: [supported ? "incident-class-supported" : "incident-class-not-supported"],
      assessment_id: `class-assessment:${hex.repeat(64)}`,
      derivation_sha256: `sha256:${hex.repeat(64)}`,
    };
  });
  return {
    schema: "response-packet/v3",
    packet_id: `response-packet:${"a".repeat(64)}`,
    version: 3,
    status: "resolved",
    incident_id: RUN_INCIDENT_ID,
    scenario_id: "tos-resource-resolution-drift-v1",
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
      scenario_id: "tos-resource-resolution-drift-v1",
      fixture_id: "tears-of-steel-linear-exr-240-v1",
      run_id: RUN_ID,
      source: "grafana-mcp",
      structured_only: true,
      query_keys: ["alert.rule", ...queryKeys],
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
      scenario_id: "tos-resource-resolution-drift-v1",
      fixture_id: "tears-of-steel-linear-exr-240-v1",
      run_id: RUN_ID,
      evidence_window: {
        start: "2026-09-04T12:00:00.000Z",
        end: "2026-09-04T12:05:00.000Z",
      },
      approved: {
        resource_sha256: DIGEST,
        config_sha256: DIGEST,
        config_generation: 7,
        frame_pipeline_sha256: DIGEST,
        derivative_parent_sha256: DIGEST,
        derivative_generation: 7,
        cache_key: "cache:03_2a:00003:g7",
      },
      scope: { affected_job_ids: ["job-affected-001"], safe_job_ids: ["job-safe-001"] },
      reason_codes: ["expected-state-supported"],
      assessment_id: expectedAssessmentId,
      derivation_sha256: DIGEST,
    },
    operational_evidence_assessment: {
      schema: "operational-evidence-assessment/v1",
      status: "supported",
      expected_state_assessment_id: expectedAssessmentId,
      request_id: "evidence-request-001",
      incident_id: RUN_INCIDENT_ID,
      fixture_id: "tears-of-steel-linear-exr-240-v1",
      run_id: RUN_ID,
      job_facts: { "job-affected-001": { signals: ["log", "metric"] } },
      fact_ids: evidenceFactIds,
      evidence_ids: evidenceIds.slice(1),
      reason_codes: ["operational-evidence-supported"],
      assessment_id: operationalAssessmentId,
      derivation_sha256: DIGEST_B,
    },
    incident_class_assessments: classAssessments,
    diagnosis_reconciliation: {
      schema: "diagnosis-reconciliation/v1",
      reconciliation_id: reconciliationId,
      status: "supported",
      incident_class: "resource-resolution-drift/v1",
      expected_state_assessment_id: expectedAssessmentId,
      operational_evidence_assessment_id: operationalAssessmentId,
      class_assessment_ids: classAssessments.map((item) => item.assessment_id),
      scope: { affected_job_ids: ["job-affected-001"], safe_job_ids: ["job-safe-001"] },
      evidence_fact_ids: evidenceFactIds,
      reason_codes: ["diagnosis-supported"],
      action_intent: actionIntent,
      derivation_sha256: DIGEST_C,
    },
    selection_trace: ["alert.rule", ...queryKeys].map((queryKey, index) => ({
      sequence: index,
      selected_by: index === 0 ? "policy" : "model",
      query_key: queryKey,
      evidence_id: evidenceIds[index],
      disposition: index === 2 ? "resolved" : "continue",
      reason_codes: [index === 2 ? "sufficient-evidence" : "evidence-collected"],
      operational_assessment_id: operationalAssessmentId,
      reconciliation_id: reconciliationId,
    })),
    model_selection: {
      schema: "model-selection/v3",
      trust: "untrusted-model-output",
      hypotheses: [
        {
          ordinal: 1,
          incident_class: "resource-resolution-drift/v1",
          evidence_ids: evidenceIds.slice(1),
        },
      ],
      query_keys: ["alert.rule", ...queryKeys],
      stop_reason: "sufficient-evidence",
      output_sha256: DIGEST_B,
    },
    model_invocation: {
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
    },
    agent_trace: {
      schema: "agent-trace/v2",
      trace_id: "1".repeat(32),
      spans: [
        ["grafana", "ok", "alert.rule", 12, 1, null, null, null],
        ["gemini", "ok", null, 38, 3, null, 720, 96],
        ["grafana", "ok", "metric.worker-cohort", 18, 1, null, null, null],
        ["validator", "unresolved", "metric.worker-cohort", 2, 0, null, null, null],
        [
          "reconciliation",
          "unresolved",
          "metric.worker-cohort",
          1,
          0,
          "incomplete-evidence",
          null,
          null,
        ],
        ["grafana", "ok", "log.config-cohort", 18, 1, null, null, null],
        ["validator", "ok", "log.config-cohort", 2, 0, null, null, null],
        ["reconciliation", "ok", "log.config-cohort", 1, 0, null, null, null],
      ].map(
        (
          [
            stage,
            status,
            query_key,
            duration_ms,
            attempts,
            error_code,
            input_tokens,
            output_tokens,
          ],
          sequence,
        ) => ({
          sequence,
          stage,
          status,
          duration_ms,
          query_key,
          input_tokens,
          output_tokens,
          attempts,
          attempts_complete: true,
          unobserved_model_calls: 0,
          error_code,
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
    no_action_reason: null,
    finalized_at: "2026-09-04T12:05:00.000Z",
    derivation_sha256: DIGEST,
  };
}

function rawRecoveryDecision(requestId: string): Readonly<Record<string, unknown>> {
  const before = { generation: 1, state_sha256: DIGEST_B, protected_state_sha256: DIGEST_C };
  const after = { generation: 2, state_sha256: DIGEST, protected_state_sha256: DIGEST_C };
  const actionIntentId = `action-intent:${"e".repeat(64)}`;
  const reconciliationId = `diagnosis-reconciliation:${"c".repeat(64)}`;
  const approval = {
    schema: "reference-human-approval/v3",
    decision: "approved",
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
    action_intent_id: actionIntentId,
    action_intent_sha256: `sha256:${"e".repeat(64)}`,
    reconciliation_id: reconciliationId,
    scenario_id: "tos-resource-resolution-drift-v1",
    incident_class: "resource-resolution-drift/v1",
    command: "reconcile-resource",
    affected_job_ids: ["job-affected-001"],
    state_generation: 1,
    state_sha256: DIGEST_B,
    protected_state_sha256: DIGEST_C,
    approval_id: `reference-approval:${"a".repeat(64)}`,
    approval_sha256: DIGEST,
  };
  const verification = {
    schema: "reference-recovery-verification/v1",
    verifier: "deterministic-simulator-state",
    result: "verified",
    scenario_id: "tos-resource-resolution-drift-v1",
    incident_class: "resource-resolution-drift/v1",
    action_intent_id: actionIntentId,
    action_intent_sha256: `sha256:${"e".repeat(64)}`,
    reconciliation_id: reconciliationId,
    before,
    after,
    affected_job_ids: ["job-affected-001"],
    affected_expected_field_checks: [
      {
        field: "effective_resource_sha256",
        expected_value: DIGEST,
        matched_job_ids: ["job-affected-001"],
      },
    ],
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
  };
  const receipt = {
    schema: "reference-recovery-receipt/v3",
    approval_id: approval.approval_id,
    approval_sha256: approval.approval_sha256,
    action_intent_id: actionIntentId,
    action_intent_sha256: `sha256:${"e".repeat(64)}`,
    reconciliation_id: reconciliationId,
    scenario_id: "tos-resource-resolution-drift-v1",
    incident_class: "resource-resolution-drift/v1",
    command: "reconcile-resource",
    before,
    after,
    affected_job_ids: ["job-affected-001"],
    protected_job_ids: ["job-safe-001"],
    mutations: [
      {
        job_id: "job-affected-001",
        before_job_state_sha256: DIGEST_B,
        after_job_state_sha256: DIGEST_C,
        changed_components: ["frame", "derivative"],
      },
    ],
    protected_state_unchanged: true,
    action_intent_requires_human_approval: true,
    action_intent_authorizes_execution: false,
    verification,
    result: "applied",
    receipt_id: `reference-recovery:${"a".repeat(64)}`,
    receipt_sha256: DIGEST,
  };
  return {
    schema: "reference-recovery-decision/v1",
    scenario_id: "tos-resource-resolution-drift-v1",
    request_id: requestId,
    run_id: RUN_ID,
    packet_id: `response-packet:${"a".repeat(64)}`,
    packet_sha256: DIGEST,
    decision: "approved",
    outcome: "applied",
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
      simulator_state_changed: true,
      production_access_used: false,
      production_state_changed: false,
      production_claim: "none",
    },
    decision_sha256: DIGEST,
  };
}

function isScenarioId(value: string): value is ReferenceScenarioId {
  return REFERENCE_SCENARIO_IDS.some((scenarioId) => scenarioId === value);
}

function isVisualKind(value: string): value is ReferenceVisualKind {
  return VISUAL_KINDS.some((kind) => kind === value);
}

async function installReferenceApi(
  page: Page,
  mutations: string[],
  benchmark: ReferenceBenchmarkSuite = benchmarkSuite(),
) {
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() !== "GET") {
      mutations.push(`${request.method()} ${url.pathname}`);
      await route.fulfill({ json: { code: "unexpected-mutation" }, status: 503 });
      return;
    }
    if (url.pathname === "/v1/demo/scenarios") {
      await route.fulfill({ json: scenarioList() });
      return;
    }
    if (url.pathname === "/v1/benchmarks/reference-suite") {
      await route.fulfill({ json: benchmark });
      return;
    }
    const visualMatch = url.pathname.match(/^\/v1\/demo\/scenarios\/([^/]+)\/visuals\/([^/]+)$/u);
    if (visualMatch !== null) {
      const scenarioId = visualMatch[1] ?? "";
      const kind = visualMatch[2] ?? "";
      if (isScenarioId(scenarioId) && isVisualKind(kind)) {
        const descriptor = previewManifest.scenarios[scenarioId].visuals[kind];
        await route.fulfill({
          body: await readFile(path.join(PREVIEW_ROOT, descriptor.filename)),
          contentType: "image/png",
          headers: {
            "X-ColorTrace-Pixel-Evidence": "true",
            "X-ColorTrace-Representation": descriptor.representation,
            "X-ColorTrace-Scenario-SHA256": SCENARIO_SHA256[scenarioId],
            "X-Content-SHA256": descriptor.sha256,
          },
        });
        return;
      }
    }
    const detailMatch = url.pathname.match(/^\/v1\/demo\/scenarios\/([^/]+)$/u);
    if (detailMatch !== null) {
      const scenarioId = detailMatch[1] ?? "";
      if (isScenarioId(scenarioId)) {
        await route.fulfill({ json: scenarioDetail(scenarioId) });
        return;
      }
    }
    await route.fulfill({ json: { code: "not-found" }, status: 404 });
  });
}

async function installReferenceV3Flow(page: Page, requests: unknown[]) {
  await installReferenceApi(page, []);
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "GET" && url.pathname === "/v1/benchmarks/reference-suite") {
      await route.fulfill({ json: { ...benchmarkSuite(), suite_sha256: DIGEST } });
      return;
    }
    if (
      request.method() === "POST" &&
      url.pathname === "/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs"
    ) {
      requests.push(request.postDataJSON());
      await route.fulfill({ json: rawReferenceRun() });
      return;
    }
    if (
      request.method() === "POST" &&
      url.pathname ===
        `/v1/demo/scenarios/tos-resource-resolution-drift-v1/runs/${REQUEST_ID}/decision`
    ) {
      const body = request.postDataJSON() as Readonly<Record<string, unknown>>;
      requests.push(body);
      await route.fulfill({
        headers: {
          "X-ColorTrace-Execution-Target": "colortrace-simulator",
          "X-ColorTrace-Production-State-Changed": "false",
        },
        json: rawRecoveryDecision(String(body.request_id)),
      });
      return;
    }
    await route.fallback();
  });
}

async function installDeterministicReferenceCrypto(page: Page) {
  await page.addInitScript(
    ({ approvalNonce, requestId }) => {
      const nativeDigest = globalThis.crypto.subtle.digest.bind(globalThis.crypto.subtle);
      let identifierIndex = 0;
      Object.defineProperty(globalThis.crypto, "randomUUID", {
        configurable: true,
        value: () => (identifierIndex++ === 0 ? requestId : approvalNonce),
      });
      Object.defineProperty(globalThis.crypto.subtle, "digest", {
        configurable: true,
        value: async (algorithm: AlgorithmIdentifier, data: BufferSource) => {
          const bytes = ArrayBuffer.isView(data)
            ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
            : new Uint8Array(data);
          const pngSignature = [137, 80, 78, 71, 13, 10, 26, 10];
          if (pngSignature.every((byte, index) => bytes[index] === byte)) {
            return nativeDigest(algorithm, data);
          }
          return new Uint8Array(32).fill(0xaa).buffer;
        },
      });
    },
    { approvalNonce: APPROVAL_NONCE, requestId: REQUEST_ID },
  );
}

test("loads verified reference pixels and switches evidence contracts without mutating", async ({
  page,
}) => {
  const mutations: string[] = [];
  await installReferenceApi(page, mutations);

  await page.goto("/");

  const workspace = page.getByRole("region", {
    name: "Three ways a successful render can still be wrong",
  });
  await expect(workspace).toBeVisible();
  await expect(
    workspace.getByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    }),
  ).toBeVisible();
  await expect(workspace.getByAltText(/Expected state open-film pixel preview/iu)).toHaveJSProperty(
    "naturalWidth",
    960,
  );
  await expect(
    workspace.getByAltText(/Observed failure open-film pixel preview/iu),
  ).toHaveJSProperty("naturalWidth", 960);
  await expect(workspace.getByText("PNG hash verified · pixel evidence")).toHaveCount(3);
  await expect(
    workspace.getByRole("heading", {
      name: "Gemini may select → Grafana can return → validators decide → human may authorize",
    }),
  ).toBeVisible();
  await expect(
    workspace.getByRole("heading", { name: "Sealed benchmark; results not reported" }),
  ).toBeVisible();

  await workspace.getByText("Inspect the bounded query and evidence contract").click();
  await expect(workspace.getByText("runtime.effective_resource_sha256")).toBeVisible();

  await workspace.getByRole("button", { name: /Configuration rollout.*72 affected/iu }).click();
  await expect(
    workspace.getByRole("heading", { name: "A stale color configuration remained active" }),
  ).toBeVisible();
  await expect(workspace.getByText("Effective config digest + generation")).toBeVisible();
  await expect(workspace.getByText("PNG hash verified · pixel evidence")).toHaveCount(3);
  await workspace.getByText("Inspect the bounded query and evidence contract").click();
  await expect(workspace.getByText("runtime.config_generation")).toBeVisible();
  await expect(workspace.getByRole("button", { name: "Run live investigation" })).toBeEnabled();
  expect(mutations).toEqual([]);
});

test("renders the recorded reference impact v3 benchmark without comparison claims", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const mutations: string[] = [];
  await installReferenceApi(page, mutations, recordedBenchmarkSuite());

  await page.goto("/");

  const benchmark = page.getByRole("region", { name: "Product gates passed" });
  await expect(benchmark).toBeVisible();
  await expect(benchmark.locator('[data-result-state="passed"]')).toHaveText(
    "Impact target passed",
  );
  await expect(
    benchmark.getByText("Full impact benchmark · passed", { exact: true }),
  ).toBeVisible();

  const metricValues = benchmark
    .getByRole("region", { name: "Recorded benchmark metrics" })
    .locator("strong");
  await expect(metricValues).toHaveCount(4);
  for (const [index, expected] of ["100%", "0", "70%", "41.67%"].entries()) {
    await expect(metricValues.nth(index)).toBeVisible();
    await expect(metricValues.nth(index)).toHaveText(expected);
  }

  const scenarioRows = benchmark.locator("tbody tr");
  await expect(scenarioRows).toHaveCount(3);
  for (let index = 0; index < 3; index += 1) {
    await expect(scenarioRows.nth(index).locator('td[data-check="true"]')).toHaveCount(2);
  }
  await expect(benchmark).not.toContainText(
    /model boundary|model-call receipts|selector delta|fixed order|model comparison|model advantage/iu,
  );
  expect(mutations).toEqual([]);

  if (process.env.COLORTRACE_CAPTURE_SHOT_SAFE_SCREENSHOT === "1") {
    await page.screenshot({
      animations: "disabled",
      fullPage: true,
      path: "../../.cache/playwright/reference-v3-recorded-benchmark.png",
    });
  }
});

test("completes the reference v3 Detect, Explain, Approve, Verify path", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const requests: unknown[] = [];
  await installDeterministicReferenceCrypto(page);
  await installReferenceV3Flow(page, requests);

  await page.goto("/");

  const workspace = page.getByRole("region", {
    name: "Three ways a successful render can still be wrong",
  });
  await expect(
    workspace.getByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    }),
  ).toBeVisible();
  await expect(workspace.getByText("PNG hash verified · pixel evidence")).toHaveCount(3);

  await workspace.getByRole("button", { name: "Run live investigation" }).click();

  await expect(workspace.getByText("Response packet v3")).toBeVisible();
  await expect(workspace.getByRole("heading", { name: "Investigation resolved" })).toBeVisible();
  await expect(
    workspace
      .getByRole("region", { name: "Returned investigation conclusion" })
      .getByText(
        /Grafana MCP supplied 4 bound structured facts.*Gemini only selected read-only queries/iu,
      ),
  ).toBeVisible();
  await expect(workspace.getByText("Gemini selected queries")).toBeVisible();
  await expect(workspace.getByRole("heading", { name: "Correlated Grafana facts" })).toBeVisible();
  await expect(workspace.getByRole("heading", { name: "reconcile-resource" })).toBeVisible();
  await expect(
    workspace.getByText(/validators decided.*human approval still required/iu),
  ).toBeVisible();

  await workspace.getByRole("button", { name: "Approve simulator action" }).click();

  await expect(
    workspace.getByRole("heading", { name: "Representative simulator recovery applied" }),
  ).toBeVisible();
  await expect(
    workspace.getByText("Fresh simulator state verified", { exact: true }),
  ).toBeVisible();
  await expect(
    workspace
      .locator(".reference-live__authority")
      .filter({ hasText: /human demo gesture recorded.*fresh simulator state verified/iu }),
  ).toBeVisible();
  await expect(
    workspace.getByText(/Production untouched: no production access was used/iu),
  ).toBeVisible();

  expect(requests).toHaveLength(2);
  expect(requests[0]).toEqual({
    schema: "reference-scenario-run-request/v1",
    request_id: REQUEST_ID,
  });
  expect(requests[1]).toMatchObject({
    schema: "reference-recovery-decision-request/v1",
    request_id: REQUEST_ID,
    decision: "approved",
    approval_nonce: APPROVAL_NONCE,
    packet_id: `response-packet:${"a".repeat(64)}`,
    packet_sha256: DIGEST,
  });

  if (process.env.COLORTRACE_CAPTURE_SHOT_SAFE_SCREENSHOT === "1") {
    await page.screenshot({
      animations: "disabled",
      fullPage: true,
      path: "../../.cache/playwright/reference-v3-verified.png",
    });
  }
});
