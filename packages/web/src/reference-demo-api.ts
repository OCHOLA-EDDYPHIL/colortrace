import {
  createReferenceScenarioRunRequest,
  parseReferenceResponsePacket,
  type ReferencePacketSha256,
  type ReferenceResponsePacket,
  type ReferenceScenarioRunRequest,
} from "./reference-run-contract.ts";
import {
  createReferenceRecoveryDecisionRequest,
  parseReferenceRecoveryDecision,
  type ReferenceRecoveryChoice,
  type ReferenceRecoveryDecision,
  type ReferenceRecoveryDecisionRequest,
} from "./reference-recovery-contract.ts";

export const REFERENCE_SCENARIO_IDS = [
  "tos-resource-resolution-drift-v1",
  "tos-config-rollout-drift-v1",
  "tos-stale-derivative-cache-v1",
] as const;

export type ReferenceScenarioId = (typeof REFERENCE_SCENARIO_IDS)[number];
export type ReferenceIncidentClass =
  | "resource-resolution-drift/v1"
  | "configuration-rollout-drift/v1"
  | "stale-derivative-cache/v1";
export type ReferenceRecoveryKind = "reconcile-resource" | "pin-rollout" | "invalidate-cache";
export type ReferenceVisualKind = "expected" | "observed" | "recovered" | "diff";
export type ReferenceVisualRepresentation =
  | "open-film-preview-png/v1"
  | "open-film-difference-png/v1";
export type ReferenceVisualSourceRelation =
  | "current"
  | "stale-parent"
  | "amplified-absolute-display-difference-8x";

export type ReferenceVisualDescriptor = {
  readonly kind: ReferenceVisualKind;
  readonly href: string;
  readonly content_sha256: string;
  readonly representation: ReferenceVisualRepresentation;
  readonly pixel_evidence: true;
  readonly width: 960;
  readonly height: 506;
  readonly served_artifact_id: string;
  readonly source_artifact_ids: readonly string[];
  readonly source_relation: ReferenceVisualSourceRelation;
  readonly source_receipt_sha256: readonly string[];
  readonly source_output_sha256: readonly string[];
  readonly source_canonical_pixel_sha256: readonly string[];
};

export type ReferenceScopeSummary = {
  readonly artifact_count: number;
  readonly affected_artifact_count: number;
  readonly protected_artifact_count: number;
};

export type ReferenceScenarioSummary = {
  readonly scenario_id: ReferenceScenarioId;
  readonly scenario_sha256: string;
  readonly title: string;
  readonly symptom: string;
  readonly incident_class: ReferenceIncidentClass;
  readonly recovery_kind: ReferenceRecoveryKind;
  readonly scope: ReferenceScopeSummary;
  readonly visuals: readonly ReferenceVisualDescriptor[];
};

export type ReferenceAuthority = {
  readonly schema: "reference-authority-boundary/v1";
  readonly catalog_facts: "sealed-reference-contracts";
  readonly incident_facts: "deterministic-validators";
  readonly model_role: "advisory";
  readonly evidence_access: "grafana-mcp-read-only";
  readonly action_approval: "human-only";
  readonly action_execution_target: "colortrace-simulator";
};

export type ReferenceProvenance = {
  readonly attribution: string;
  readonly license: {
    readonly spdx: string;
    readonly url: string;
  };
};

export type ReferenceScenarioList = {
  readonly schema: "reference-scenario-list/v1";
  readonly collection_id: string;
  readonly items: readonly ReferenceScenarioSummary[];
  readonly provenance: ReferenceProvenance;
  readonly authority: ReferenceAuthority;
  readonly catalog_sha256: string;
};

export type ReferenceScenarioDetail = {
  readonly schema: "reference-scenario-detail/v1";
  readonly summary: ReferenceScenarioSummary;
  readonly evidence_requirements: {
    readonly minimum_complementary_signal_classes: number;
    readonly runtime_fact_source: "structured-grafana-observations";
    readonly required_fact_fields: readonly string[];
    readonly decision_authority: "deterministic-validators";
    readonly "missing_conflicting_or_cross-run_evidence": "unresolved";
  };
  readonly recovery_boundary: {
    readonly intent: ReferenceRecoveryKind;
    readonly requires_human_approval: true;
    readonly execution_target: "colortrace-simulator";
    readonly catalog_executes_actions: false;
  };
  readonly provenance: ReferenceProvenance;
  readonly authority: ReferenceAuthority;
  readonly detail_sha256: string;
};

export type ReferenceBenchmarkSuite = {
  readonly schema: "reference-benchmark-suite/v1";
  readonly suite_id: string;
  readonly definition_state: "sealed";
  readonly result_state: "not-reported" | "recorded";
  readonly scenarios: readonly {
    readonly scenario_id: ReferenceScenarioId;
    readonly scenario_sha256: string;
    readonly incident_class: ReferenceIncidentClass;
    readonly rerender_all_artifact_count: number;
    readonly targeted_artifact_count: number;
    readonly protected_artifact_count: number;
    readonly scope_reduction_basis_points: number;
  }[];
  readonly acceptance_requirements: {
    readonly output_equivalence: "required";
    readonly protected_output_integrity: "required";
    readonly maximum_false_authorized_actions: number;
    readonly minimum_resolvable_holdout_accuracy_basis_points: number;
    readonly minimum_median_compute_avoided_basis_points: number;
    readonly minimum_median_bytes_avoided_basis_points: number;
  };
  readonly measurement_boundary: {
    readonly scope_reduction_is_measured_result: false;
    readonly reported_results_require_recorded_evaluator_output: true;
    readonly catalog_claims_observed_savings: boolean;
    readonly live_run_scope: "representative-evidence-only";
  };
  readonly result: ReferenceImpactBenchmark | null;
  readonly provenance: ReferenceProvenance;
  readonly authority: ReferenceAuthority & {
    readonly benchmark_result_authority: "recorded-evaluator-output";
  };
  readonly suite_sha256: string;
};

export type ReferenceImpactBenchmark = {
  readonly schema: "reference-impact-benchmark/v1";
  readonly reference_collection_id: string;
  readonly reference_manifest_sha256: string;
  readonly campaign_report_sha256: string;
  readonly evidence: {
    readonly source: "recorded-worker-receipts";
    readonly evidence_set_id: string;
    readonly recorded_worker_evidence: true;
    readonly observation_count: 720;
  };
  readonly thresholds: {
    readonly minimum_classification_accuracy_basis_points: 9500;
    readonly minimum_median_compute_avoided_basis_points: 4000;
    readonly minimum_median_application_bytes_avoided_basis_points: 4000;
    readonly maximum_false_authorized_actions: 0;
  };
  readonly metrics: {
    readonly classification_accuracy_basis_points: number;
    readonly false_authorized_actions: number;
    readonly adaptive_advantage_basis_points: number;
    readonly recorded_model_advantage_basis_points: number;
    readonly median_compute_avoided_basis_points: number;
    readonly median_application_bytes_avoided_basis_points: number;
  };
  readonly timing: {
    readonly informational_only: true;
    readonly excluded_from_acceptance: true;
    readonly baseline_cpu_nanoseconds: number;
    readonly baseline_wall_nanoseconds: number;
    readonly selective_cpu_nanoseconds: number;
    readonly selective_wall_nanoseconds: number;
  };
  readonly scenario_results: readonly ReferenceImpactScenarioResult[];
  readonly checks: ReferenceImpactChecks;
  readonly passed: boolean;
  readonly report_sha256: string;
};

export type ReferenceImpactScenarioResult = {
  readonly scenario_id: ReferenceScenarioId;
  readonly incident_class: ReferenceIncidentClass;
  readonly artifact_count: number;
  readonly affected_artifact_count: number;
  readonly protected_artifact_count: number;
  readonly baseline: ReferenceImpactWork;
  readonly selective: ReferenceImpactWork;
  readonly compute_avoided_basis_points: number;
  readonly application_bytes_avoided_basis_points: number;
  readonly output_equivalence: boolean;
  readonly protected_output_integrity: boolean;
};

export type ReferenceImpactWork = {
  readonly pixel_work: number;
  readonly application_bytes: number;
};

export type ReferenceImpactChecks = {
  readonly campaign_acceptance_passed: boolean;
  readonly output_equivalence: boolean;
  readonly protected_output_integrity: boolean;
  readonly zero_false_authorized_actions: boolean;
  readonly classification_at_least_95_percent: boolean;
  readonly same_selection_budgets: boolean;
  readonly measurable_adaptive_advantage: boolean;
  readonly median_compute_avoided_at_least_40_percent: boolean;
  readonly median_application_bytes_avoided_at_least_40_percent: boolean;
};

export type ReferenceDemoAdapter = {
  readonly listScenarios: (signal?: AbortSignal) => Promise<ReferenceScenarioList>;
  readonly getScenario: (
    scenarioId: ReferenceScenarioId,
    signal?: AbortSignal,
  ) => Promise<ReferenceScenarioDetail>;
  readonly benchmarkSuite: (signal?: AbortSignal) => Promise<ReferenceBenchmarkSuite>;
  readonly runScenario: (
    scenarioId: ReferenceScenarioId,
    signal?: AbortSignal,
  ) => Promise<ReferenceResponsePacket>;
  readonly decideRecovery: (
    packet: ReferenceResponsePacket,
    decision: ReferenceRecoveryChoice,
    signal?: AbortSignal,
  ) => Promise<ReferenceRecoveryDecision>;
  readonly loadVisual: (
    descriptor: ReferenceVisualDescriptor,
    expectedScenarioSha256: string,
    signal?: AbortSignal,
  ) => Promise<VerifiedReferenceVisual>;
  readonly releaseVisual: (visual: VerifiedReferenceVisual) => void;
};

export type ReferenceDemoAdapterOptions = {
  readonly baseUrl: string;
  readonly fetch?: typeof fetch;
  readonly createObjectUrl?: (blob: Blob) => string;
  readonly revokeObjectUrl?: (url: string) => void;
  readonly createRequestId?: () => string;
  readonly createApprovalNonce?: () => string;
  readonly sha256?: (value: ArrayBuffer) => Promise<string>;
};

export type VerifiedReferenceVisual = {
  readonly kind: ReferenceVisualKind;
  readonly content_sha256: string;
  readonly scenario_sha256: string;
  readonly representation: ReferenceVisualRepresentation;
  readonly pixel_evidence: true;
  readonly width: 960;
  readonly height: 506;
  readonly served_artifact_id: string;
  readonly source_relation: ReferenceVisualSourceRelation;
  readonly src: string;
};

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const REFERENCE_SCENARIO_ID_SET = new Set<string>(REFERENCE_SCENARIO_IDS);
const INCIDENT_CLASSES = new Set<ReferenceIncidentClass>([
  "resource-resolution-drift/v1",
  "configuration-rollout-drift/v1",
  "stale-derivative-cache/v1",
]);
const RECOVERY_KINDS = new Set<ReferenceRecoveryKind>([
  "reconcile-resource",
  "pin-rollout",
  "invalidate-cache",
]);
const VISUAL_KINDS = new Set<ReferenceVisualKind>(["expected", "observed", "recovered", "diff"]);
const VISUAL_SOURCE_RELATIONS = new Set<ReferenceVisualSourceRelation>([
  "current",
  "stale-parent",
  "amplified-absolute-display-difference-8x",
]);
const VISUAL_DESCRIPTOR_KEYS = new Set([
  "kind",
  "href",
  "content_sha256",
  "representation",
  "pixel_evidence",
  "width",
  "height",
  "served_artifact_id",
  "source_artifact_ids",
  "source_relation",
  "source_receipt_sha256",
  "source_output_sha256",
  "source_canonical_pixel_sha256",
]);
const BENCHMARK_SUITE_KEYS = new Set([
  "schema",
  "suite_id",
  "definition_state",
  "result_state",
  "scenarios",
  "acceptance_requirements",
  "measurement_boundary",
  "result",
  "provenance",
  "authority",
  "suite_sha256",
]);
const BENCHMARK_SCENARIO_KEYS = new Set([
  "scenario_id",
  "scenario_sha256",
  "incident_class",
  "rerender_all_artifact_count",
  "targeted_artifact_count",
  "protected_artifact_count",
  "scope_reduction_basis_points",
]);
const BENCHMARK_REQUIREMENT_KEYS = new Set([
  "output_equivalence",
  "protected_output_integrity",
  "maximum_false_authorized_actions",
  "minimum_resolvable_holdout_accuracy_basis_points",
  "minimum_median_compute_avoided_basis_points",
  "minimum_median_bytes_avoided_basis_points",
]);
const BENCHMARK_MEASUREMENT_KEYS = new Set([
  "scope_reduction_is_measured_result",
  "reported_results_require_recorded_evaluator_output",
  "catalog_claims_observed_savings",
  "live_run_scope",
]);
const BENCHMARK_AUTHORITY_KEYS = new Set([
  "schema",
  "catalog_facts",
  "incident_facts",
  "model_role",
  "evidence_access",
  "action_approval",
  "action_execution_target",
  "benchmark_result_authority",
]);
const IMPACT_BENCHMARK_KEYS = new Set([
  "schema",
  "reference_collection_id",
  "reference_manifest_sha256",
  "campaign_report_sha256",
  "evidence",
  "thresholds",
  "metrics",
  "timing",
  "scenario_results",
  "checks",
  "passed",
  "report_sha256",
]);
const IMPACT_EVIDENCE_KEYS = new Set([
  "source",
  "evidence_set_id",
  "recorded_worker_evidence",
  "observation_count",
]);
const IMPACT_THRESHOLD_KEYS = new Set([
  "minimum_classification_accuracy_basis_points",
  "minimum_median_compute_avoided_basis_points",
  "minimum_median_application_bytes_avoided_basis_points",
  "maximum_false_authorized_actions",
]);
const IMPACT_METRIC_KEYS = new Set([
  "classification_accuracy_basis_points",
  "false_authorized_actions",
  "adaptive_advantage_basis_points",
  "recorded_model_advantage_basis_points",
  "median_compute_avoided_basis_points",
  "median_application_bytes_avoided_basis_points",
]);
const IMPACT_TIMING_KEYS = new Set([
  "informational_only",
  "excluded_from_acceptance",
  "baseline_cpu_nanoseconds",
  "baseline_wall_nanoseconds",
  "selective_cpu_nanoseconds",
  "selective_wall_nanoseconds",
]);
const IMPACT_SCENARIO_KEYS = new Set([
  "scenario_id",
  "incident_class",
  "artifact_count",
  "affected_artifact_count",
  "protected_artifact_count",
  "baseline",
  "selective",
  "compute_avoided_basis_points",
  "application_bytes_avoided_basis_points",
  "output_equivalence",
  "protected_output_integrity",
]);
const IMPACT_WORK_KEYS = new Set(["pixel_work", "application_bytes"]);
const IMPACT_CHECK_KEYS = new Set([
  "campaign_acceptance_passed",
  "output_equivalence",
  "protected_output_integrity",
  "zero_false_authorized_actions",
  "classification_at_least_95_percent",
  "same_selection_budgets",
  "measurable_adaptive_advantage",
  "median_compute_avoided_at_least_40_percent",
  "median_application_bytes_avoided_at_least_40_percent",
]);
const MAX_VISUAL_BYTES = 2 * 1024 * 1024;

export class ReferenceDemoApiError extends Error {
  readonly code: string;
  readonly status: number | null;

  constructor(status: number | null, code: string, options?: ErrorOptions) {
    super(code, options);
    this.name = "ReferenceDemoApiError";
    this.status = status;
    this.code = code;
  }
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Readonly<Record<string, unknown>>, keys: ReadonlySet<string>): void {
  const actual = Object.keys(value);
  if (actual.length !== keys.size || actual.some((key) => !keys.has(key))) {
    throw invalidResponse();
  }
}

function stringField(value: Readonly<Record<string, unknown>>, key: string): string {
  const field = value[key];
  if (typeof field !== "string" || field.length === 0) throw invalidResponse();
  return field;
}

function integerField(value: Readonly<Record<string, unknown>>, key: string): number {
  const field = value[key];
  if (!Number.isSafeInteger(field) || (field as number) < 0) throw invalidResponse();
  return field as number;
}

function boundedIntegerField(
  value: Readonly<Record<string, unknown>>,
  key: string,
  minimum: number,
  maximum: number,
): number {
  const field = integerField(value, key);
  if (field < minimum || field > maximum) throw invalidResponse();
  return field;
}

function booleanField(value: Readonly<Record<string, unknown>>, key: string): boolean {
  const field = value[key];
  if (typeof field !== "boolean") throw invalidResponse();
  return field;
}

function recordField(
  value: Readonly<Record<string, unknown>>,
  key: string,
): Readonly<Record<string, unknown>> {
  const field = value[key];
  if (!isRecord(field)) throw invalidResponse();
  return field;
}

function arrayField(value: Readonly<Record<string, unknown>>, key: string): readonly unknown[] {
  const field = value[key];
  if (!Array.isArray(field)) throw invalidResponse();
  return field;
}

function stringArrayField(
  value: Readonly<Record<string, unknown>>,
  key: string,
  pattern: RegExp,
  expectedLength: number,
): readonly string[] {
  const fields = arrayField(value, key);
  if (
    fields.length !== expectedLength ||
    fields.some((field) => typeof field !== "string" || !pattern.test(field))
  ) {
    throw invalidResponse();
  }
  return fields as readonly string[];
}

function invalidResponse(): ReferenceDemoApiError {
  return new ReferenceDemoApiError(null, "reference-response-invalid");
}

function parseScenarioId(value: string): ReferenceScenarioId {
  if (!REFERENCE_SCENARIO_ID_SET.has(value)) throw invalidResponse();
  return value as ReferenceScenarioId;
}

function parseIncidentClass(value: string): ReferenceIncidentClass {
  if (!INCIDENT_CLASSES.has(value as ReferenceIncidentClass)) throw invalidResponse();
  return value as ReferenceIncidentClass;
}

function parseRecoveryKind(value: string): ReferenceRecoveryKind {
  if (!RECOVERY_KINDS.has(value as ReferenceRecoveryKind)) throw invalidResponse();
  return value as ReferenceRecoveryKind;
}

function parseAuthority(value: unknown): ReferenceAuthority {
  if (!isRecord(value)) throw invalidResponse();
  if (
    value.schema !== "reference-authority-boundary/v1" ||
    value.catalog_facts !== "sealed-reference-contracts" ||
    value.incident_facts !== "deterministic-validators" ||
    value.model_role !== "advisory" ||
    value.evidence_access !== "grafana-mcp-read-only" ||
    value.action_approval !== "human-only" ||
    value.action_execution_target !== "colortrace-simulator"
  ) {
    throw invalidResponse();
  }
  return value as ReferenceAuthority;
}

function parseProvenance(value: unknown): ReferenceProvenance {
  if (!isRecord(value)) throw invalidResponse();
  const license = recordField(value, "license");
  const spdx = stringField(license, "spdx");
  const url = stringField(license, "url");
  if (!URL.canParse(url)) throw invalidResponse();
  return {
    attribution: stringField(value, "attribution"),
    license: { spdx, url },
  };
}

function parseScope(value: unknown): ReferenceScopeSummary {
  if (!isRecord(value)) throw invalidResponse();
  const artifactCount = integerField(value, "artifact_count");
  const affectedArtifactCount = integerField(value, "affected_artifact_count");
  const protectedArtifactCount = integerField(value, "protected_artifact_count");
  if (
    artifactCount === 0 ||
    affectedArtifactCount === 0 ||
    protectedArtifactCount === 0 ||
    affectedArtifactCount + protectedArtifactCount !== artifactCount
  ) {
    throw invalidResponse();
  }
  return {
    artifact_count: artifactCount,
    affected_artifact_count: affectedArtifactCount,
    protected_artifact_count: protectedArtifactCount,
  };
}

function parseVisual(value: unknown, scenarioId: ReferenceScenarioId): ReferenceVisualDescriptor {
  if (
    !isRecord(value) ||
    Object.keys(value).length !== VISUAL_DESCRIPTOR_KEYS.size ||
    Object.keys(value).some((key) => !VISUAL_DESCRIPTOR_KEYS.has(key))
  ) {
    throw invalidResponse();
  }
  const kindValue = stringField(value, "kind");
  if (!VISUAL_KINDS.has(kindValue as ReferenceVisualKind)) throw invalidResponse();
  const kind = kindValue as ReferenceVisualKind;
  const href = stringField(value, "href");
  const contentSha256 = stringField(value, "content_sha256");
  const representation =
    kind === "diff" ? "open-film-difference-png/v1" : "open-film-preview-png/v1";
  const sourceRelation = stringField(value, "source_relation");
  if (!VISUAL_SOURCE_RELATIONS.has(sourceRelation as ReferenceVisualSourceRelation)) {
    throw invalidResponse();
  }
  const sourceCount = kind === "diff" ? 2 : 1;
  const servedArtifactId = stringField(value, "served_artifact_id");
  const sourceArtifactIds = stringArrayField(value, "source_artifact_ids", IDENTIFIER, sourceCount);
  const sourceReceiptSha256 = stringArrayField(value, "source_receipt_sha256", DIGEST, sourceCount);
  const sourceOutputSha256 = stringArrayField(value, "source_output_sha256", DIGEST, sourceCount);
  const sourceCanonicalPixelSha256 = stringArrayField(
    value,
    "source_canonical_pixel_sha256",
    DIGEST,
    sourceCount,
  );
  const expectedRelation =
    kind === "diff"
      ? "amplified-absolute-display-difference-8x"
      : scenarioId === "tos-stale-derivative-cache-v1" && kind === "observed"
        ? "stale-parent"
        : "current";
  const expectedHref = `/v1/demo/scenarios/${encodeURIComponent(scenarioId)}/visuals/${kind}`;
  if (
    href !== expectedHref ||
    !DIGEST.test(contentSha256) ||
    value.representation !== representation ||
    value.pixel_evidence !== true ||
    value.width !== 960 ||
    value.height !== 506 ||
    sourceRelation !== expectedRelation ||
    !IDENTIFIER.test(servedArtifactId) ||
    (sourceRelation === "current" && sourceArtifactIds[0] !== servedArtifactId) ||
    (sourceRelation === "stale-parent" && sourceArtifactIds[0] === servedArtifactId) ||
    (sourceRelation === "amplified-absolute-display-difference-8x" &&
      sourceArtifactIds[0] !== servedArtifactId)
  ) {
    throw invalidResponse();
  }
  return {
    kind,
    href,
    content_sha256: contentSha256,
    representation,
    pixel_evidence: true,
    width: 960,
    height: 506,
    served_artifact_id: servedArtifactId,
    source_artifact_ids: sourceArtifactIds,
    source_relation: sourceRelation as ReferenceVisualSourceRelation,
    source_receipt_sha256: sourceReceiptSha256,
    source_output_sha256: sourceOutputSha256,
    source_canonical_pixel_sha256: sourceCanonicalPixelSha256,
  };
}

function parseScenarioSummary(value: unknown): ReferenceScenarioSummary {
  if (!isRecord(value)) throw invalidResponse();
  const scenarioId = parseScenarioId(stringField(value, "scenario_id"));
  const scenarioSha256 = stringField(value, "scenario_sha256");
  if (!DIGEST.test(scenarioSha256)) throw invalidResponse();
  const visuals = arrayField(value, "visuals").map((visual) => parseVisual(visual, scenarioId));
  if (visuals.length !== VISUAL_KINDS.size || new Set(visuals.map(({ kind }) => kind)).size !== 4) {
    throw invalidResponse();
  }
  return {
    scenario_id: scenarioId,
    scenario_sha256: scenarioSha256,
    title: stringField(value, "title"),
    symptom: stringField(value, "symptom"),
    incident_class: parseIncidentClass(stringField(value, "incident_class")),
    recovery_kind: parseRecoveryKind(stringField(value, "recovery_kind")),
    scope: parseScope(value.scope),
    visuals,
  };
}

function parseScenarioList(value: unknown): ReferenceScenarioList {
  if (!isRecord(value) || value.schema !== "reference-scenario-list/v1") {
    throw invalidResponse();
  }
  const catalogSha256 = stringField(value, "catalog_sha256");
  if (!DIGEST.test(catalogSha256)) throw invalidResponse();
  const items = arrayField(value, "items").map(parseScenarioSummary);
  if (
    items.length !== REFERENCE_SCENARIO_IDS.length ||
    new Set(items.map(({ scenario_id }) => scenario_id)).size !== REFERENCE_SCENARIO_IDS.length ||
    REFERENCE_SCENARIO_IDS.some(
      (scenarioId) => !items.some((item) => item.scenario_id === scenarioId),
    )
  ) {
    throw invalidResponse();
  }
  return {
    schema: "reference-scenario-list/v1",
    collection_id: stringField(value, "collection_id"),
    items,
    provenance: parseProvenance(value.provenance),
    authority: parseAuthority(value.authority),
    catalog_sha256: catalogSha256,
  };
}

function parseScenarioDetail(
  value: unknown,
  expectedScenarioId: ReferenceScenarioId,
): ReferenceScenarioDetail {
  if (!isRecord(value) || value.schema !== "reference-scenario-detail/v1") {
    throw invalidResponse();
  }
  const summary = parseScenarioSummary(value.summary);
  if (summary.scenario_id !== expectedScenarioId) throw invalidResponse();
  const evidence = recordField(value, "evidence_requirements");
  const requiredFactFields = arrayField(evidence, "required_fact_fields").map((field) => {
    if (typeof field !== "string" || !IDENTIFIER.test(field)) throw invalidResponse();
    return field;
  });
  const minimumSignalClasses = integerField(evidence, "minimum_complementary_signal_classes");
  if (
    minimumSignalClasses < 2 ||
    requiredFactFields.length < 2 ||
    new Set(requiredFactFields).size !== requiredFactFields.length ||
    evidence.runtime_fact_source !== "structured-grafana-observations" ||
    evidence.decision_authority !== "deterministic-validators" ||
    evidence["missing_conflicting_or_cross-run_evidence"] !== "unresolved"
  ) {
    throw invalidResponse();
  }
  const recovery = recordField(value, "recovery_boundary");
  const recoveryIntent = parseRecoveryKind(stringField(recovery, "intent"));
  if (
    recoveryIntent !== summary.recovery_kind ||
    recovery.requires_human_approval !== true ||
    recovery.execution_target !== "colortrace-simulator" ||
    recovery.catalog_executes_actions !== false
  ) {
    throw invalidResponse();
  }
  const detailSha256 = stringField(value, "detail_sha256");
  if (!DIGEST.test(detailSha256)) throw invalidResponse();
  return {
    schema: "reference-scenario-detail/v1",
    summary,
    evidence_requirements: {
      minimum_complementary_signal_classes: minimumSignalClasses,
      runtime_fact_source: "structured-grafana-observations",
      required_fact_fields: requiredFactFields,
      decision_authority: "deterministic-validators",
      "missing_conflicting_or_cross-run_evidence": "unresolved",
    },
    recovery_boundary: {
      intent: recoveryIntent,
      requires_human_approval: true,
      execution_target: "colortrace-simulator",
      catalog_executes_actions: false,
    },
    provenance: parseProvenance(value.provenance),
    authority: parseAuthority(value.authority),
    detail_sha256: detailSha256,
  };
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw invalidResponse();
}

function utf8(value: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(value);
  return encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  ) as ArrayBuffer;
}

async function verifyJsonDigest(
  value: Readonly<Record<string, unknown>>,
  digestKey: string,
  sha256: ReferencePacketSha256,
): Promise<string> {
  const declared = stringField(value, digestKey);
  if (!DIGEST.test(declared)) throw invalidResponse();
  const body = Object.fromEntries(Object.entries(value).filter(([key]) => key !== digestKey));
  const actual = await sha256(utf8(canonicalJson(body)));
  if (!DIGEST.test(actual) || actual !== declared) throw invalidResponse();
  return declared;
}

function signedBasisPoints(value: Readonly<Record<string, unknown>>, key: string): number {
  const field = value[key];
  if (!Number.isSafeInteger(field) || (field as number) < -10_000 || (field as number) > 10_000) {
    throw invalidResponse();
  }
  return field as number;
}

function signedScenarioBasisPoints(value: Readonly<Record<string, unknown>>, key: string): number {
  const field = value[key];
  if (!Number.isSafeInteger(field) || (field as number) > 10_000) throw invalidResponse();
  return field as number;
}

function expectedIncidentClass(scenarioId: ReferenceScenarioId): ReferenceIncidentClass {
  switch (scenarioId) {
    case "tos-resource-resolution-drift-v1":
      return "resource-resolution-drift/v1";
    case "tos-config-rollout-drift-v1":
      return "configuration-rollout-drift/v1";
    case "tos-stale-derivative-cache-v1":
      return "stale-derivative-cache/v1";
  }
}

function avoidedBasisPoints(actual: number, baseline: number): number {
  if (baseline <= 0) throw invalidResponse();
  const numerator = BigInt(baseline - actual) * 10_000n;
  const denominator = BigInt(baseline);
  let quotient = numerator / denominator;
  if (numerator < 0n && numerator % denominator !== 0n) quotient -= 1n;
  if (quotient < BigInt(Number.MIN_SAFE_INTEGER) || quotient > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw invalidResponse();
  }
  return Number(quotient);
}

function median(values: readonly number[]): number {
  if (values.length === 0) throw invalidResponse();
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.floor(ordered.length / 2)] as number;
}

function parseImpactWork(value: unknown): ReferenceImpactWork {
  const source = isRecord(value) ? value : null;
  if (source === null) throw invalidResponse();
  exactKeys(source, IMPACT_WORK_KEYS);
  return {
    pixel_work: integerField(source, "pixel_work"),
    application_bytes: integerField(source, "application_bytes"),
  };
}

async function parseImpactBenchmark(
  value: unknown,
  scenarios: ReferenceBenchmarkSuite["scenarios"],
  requirements: ReferenceBenchmarkSuite["acceptance_requirements"],
  sha256: ReferencePacketSha256,
): Promise<ReferenceImpactBenchmark> {
  if (!isRecord(value)) throw invalidResponse();
  exactKeys(value, IMPACT_BENCHMARK_KEYS);
  if (
    value.schema !== "reference-impact-benchmark/v1" ||
    stringField(value, "reference_collection_id") !== "tears-of-steel-linear-exr-240-v1"
  ) {
    throw invalidResponse();
  }
  const referenceManifestSha256 = stringField(value, "reference_manifest_sha256");
  const campaignReportSha256 = stringField(value, "campaign_report_sha256");
  if (!DIGEST.test(referenceManifestSha256) || !DIGEST.test(campaignReportSha256)) {
    throw invalidResponse();
  }

  const evidence = recordField(value, "evidence");
  exactKeys(evidence, IMPACT_EVIDENCE_KEYS);
  const evidenceSetId = stringField(evidence, "evidence_set_id");
  if (
    evidence.source !== "recorded-worker-receipts" ||
    evidence.recorded_worker_evidence !== true ||
    evidence.observation_count !== 720 ||
    !DIGEST.test(evidenceSetId)
  ) {
    throw invalidResponse();
  }

  const thresholds = recordField(value, "thresholds");
  exactKeys(thresholds, IMPACT_THRESHOLD_KEYS);
  if (
    thresholds.minimum_classification_accuracy_basis_points !== 9500 ||
    thresholds.minimum_median_compute_avoided_basis_points !== 4000 ||
    thresholds.minimum_median_application_bytes_avoided_basis_points !== 4000 ||
    thresholds.maximum_false_authorized_actions !== 0 ||
    thresholds.minimum_classification_accuracy_basis_points !==
      requirements.minimum_resolvable_holdout_accuracy_basis_points ||
    thresholds.minimum_median_compute_avoided_basis_points !==
      requirements.minimum_median_compute_avoided_basis_points ||
    thresholds.minimum_median_application_bytes_avoided_basis_points !==
      requirements.minimum_median_bytes_avoided_basis_points ||
    thresholds.maximum_false_authorized_actions !== requirements.maximum_false_authorized_actions
  ) {
    throw invalidResponse();
  }

  const metricsSource = recordField(value, "metrics");
  exactKeys(metricsSource, IMPACT_METRIC_KEYS);
  const metrics: ReferenceImpactBenchmark["metrics"] = {
    classification_accuracy_basis_points: boundedIntegerField(
      metricsSource,
      "classification_accuracy_basis_points",
      0,
      10_000,
    ),
    false_authorized_actions: integerField(metricsSource, "false_authorized_actions"),
    adaptive_advantage_basis_points: signedBasisPoints(
      metricsSource,
      "adaptive_advantage_basis_points",
    ),
    recorded_model_advantage_basis_points: signedBasisPoints(
      metricsSource,
      "recorded_model_advantage_basis_points",
    ),
    median_compute_avoided_basis_points: boundedIntegerField(
      metricsSource,
      "median_compute_avoided_basis_points",
      0,
      10_000,
    ),
    median_application_bytes_avoided_basis_points: boundedIntegerField(
      metricsSource,
      "median_application_bytes_avoided_basis_points",
      0,
      10_000,
    ),
  };
  if (metrics.recorded_model_advantage_basis_points !== metrics.adaptive_advantage_basis_points) {
    throw invalidResponse();
  }

  const timingSource = recordField(value, "timing");
  exactKeys(timingSource, IMPACT_TIMING_KEYS);
  if (timingSource.informational_only !== true || timingSource.excluded_from_acceptance !== true) {
    throw invalidResponse();
  }
  const timing: ReferenceImpactBenchmark["timing"] = {
    informational_only: true,
    excluded_from_acceptance: true,
    baseline_cpu_nanoseconds: integerField(timingSource, "baseline_cpu_nanoseconds"),
    baseline_wall_nanoseconds: integerField(timingSource, "baseline_wall_nanoseconds"),
    selective_cpu_nanoseconds: integerField(timingSource, "selective_cpu_nanoseconds"),
    selective_wall_nanoseconds: integerField(timingSource, "selective_wall_nanoseconds"),
  };

  const scenarioResults = arrayField(value, "scenario_results").map(
    (item): ReferenceImpactScenarioResult => {
      if (!isRecord(item)) throw invalidResponse();
      exactKeys(item, IMPACT_SCENARIO_KEYS);
      const scenarioId = parseScenarioId(stringField(item, "scenario_id"));
      const definition = scenarios.find((scenario) => scenario.scenario_id === scenarioId);
      const incidentClass = parseIncidentClass(stringField(item, "incident_class"));
      const artifactCount = integerField(item, "artifact_count");
      const affectedCount = integerField(item, "affected_artifact_count");
      const protectedCount = integerField(item, "protected_artifact_count");
      const baseline = parseImpactWork(item.baseline);
      const selective = parseImpactWork(item.selective);
      const computeAvoided = signedScenarioBasisPoints(item, "compute_avoided_basis_points");
      const bytesAvoided = signedScenarioBasisPoints(
        item,
        "application_bytes_avoided_basis_points",
      );
      if (
        definition === undefined ||
        incidentClass !== expectedIncidentClass(scenarioId) ||
        definition.incident_class !== incidentClass ||
        artifactCount !== definition.rerender_all_artifact_count ||
        affectedCount !== definition.targeted_artifact_count ||
        protectedCount !== definition.protected_artifact_count ||
        affectedCount + protectedCount !== artifactCount ||
        computeAvoided !== avoidedBasisPoints(selective.pixel_work, baseline.pixel_work) ||
        bytesAvoided !== avoidedBasisPoints(selective.application_bytes, baseline.application_bytes)
      ) {
        throw invalidResponse();
      }
      return {
        scenario_id: scenarioId,
        incident_class: incidentClass,
        artifact_count: artifactCount,
        affected_artifact_count: affectedCount,
        protected_artifact_count: protectedCount,
        baseline,
        selective,
        compute_avoided_basis_points: computeAvoided,
        application_bytes_avoided_basis_points: bytesAvoided,
        output_equivalence: booleanField(item, "output_equivalence"),
        protected_output_integrity: booleanField(item, "protected_output_integrity"),
      };
    },
  );
  if (
    scenarioResults.length !== REFERENCE_SCENARIO_IDS.length ||
    new Set(scenarioResults.map(({ scenario_id }) => scenario_id)).size !==
      REFERENCE_SCENARIO_IDS.length ||
    evidence.observation_count !==
      scenarioResults.reduce((sum, item) => sum + item.artifact_count, 0)
  ) {
    throw invalidResponse();
  }

  const checksSource = recordField(value, "checks");
  exactKeys(checksSource, IMPACT_CHECK_KEYS);
  const checks: ReferenceImpactChecks = {
    campaign_acceptance_passed: booleanField(checksSource, "campaign_acceptance_passed"),
    output_equivalence: booleanField(checksSource, "output_equivalence"),
    protected_output_integrity: booleanField(checksSource, "protected_output_integrity"),
    zero_false_authorized_actions: booleanField(checksSource, "zero_false_authorized_actions"),
    classification_at_least_95_percent: booleanField(
      checksSource,
      "classification_at_least_95_percent",
    ),
    same_selection_budgets: booleanField(checksSource, "same_selection_budgets"),
    measurable_adaptive_advantage: booleanField(checksSource, "measurable_adaptive_advantage"),
    median_compute_avoided_at_least_40_percent: booleanField(
      checksSource,
      "median_compute_avoided_at_least_40_percent",
    ),
    median_application_bytes_avoided_at_least_40_percent: booleanField(
      checksSource,
      "median_application_bytes_avoided_at_least_40_percent",
    ),
  };
  const passed = booleanField(value, "passed");
  if (
    checks.output_equivalence !== scenarioResults.every((item) => item.output_equivalence) ||
    checks.protected_output_integrity !==
      scenarioResults.every((item) => item.protected_output_integrity) ||
    checks.zero_false_authorized_actions !==
      (metrics.false_authorized_actions === requirements.maximum_false_authorized_actions) ||
    checks.classification_at_least_95_percent !==
      metrics.classification_accuracy_basis_points >=
        requirements.minimum_resolvable_holdout_accuracy_basis_points ||
    checks.measurable_adaptive_advantage !== metrics.recorded_model_advantage_basis_points >= 1 ||
    metrics.median_compute_avoided_basis_points !==
      median(scenarioResults.map((item) => item.compute_avoided_basis_points)) ||
    metrics.median_application_bytes_avoided_basis_points !==
      median(scenarioResults.map((item) => item.application_bytes_avoided_basis_points)) ||
    checks.median_compute_avoided_at_least_40_percent !==
      metrics.median_compute_avoided_basis_points >=
        requirements.minimum_median_compute_avoided_basis_points ||
    checks.median_application_bytes_avoided_at_least_40_percent !==
      metrics.median_application_bytes_avoided_basis_points >=
        requirements.minimum_median_bytes_avoided_basis_points ||
    passed !== Object.values(checks).every(Boolean)
  ) {
    throw invalidResponse();
  }

  const reportSha256 = await verifyJsonDigest(value, "report_sha256", sha256);
  return {
    schema: "reference-impact-benchmark/v1",
    reference_collection_id: "tears-of-steel-linear-exr-240-v1",
    reference_manifest_sha256: referenceManifestSha256,
    campaign_report_sha256: campaignReportSha256,
    evidence: {
      source: "recorded-worker-receipts",
      evidence_set_id: evidenceSetId,
      recorded_worker_evidence: true,
      observation_count: 720,
    },
    thresholds: {
      minimum_classification_accuracy_basis_points: 9500,
      minimum_median_compute_avoided_basis_points: 4000,
      minimum_median_application_bytes_avoided_basis_points: 4000,
      maximum_false_authorized_actions: 0,
    },
    metrics,
    timing,
    scenario_results: scenarioResults,
    checks,
    passed,
    report_sha256: reportSha256,
  };
}

async function parseBenchmarkSuite(
  value: unknown,
  sha256: ReferencePacketSha256,
): Promise<ReferenceBenchmarkSuite> {
  if (!isRecord(value)) throw invalidResponse();
  exactKeys(value, BENCHMARK_SUITE_KEYS);
  const resultState = value.result_state;
  if (
    value.schema !== "reference-benchmark-suite/v1" ||
    value.definition_state !== "sealed" ||
    (resultState !== "not-reported" && resultState !== "recorded")
  ) {
    throw invalidResponse();
  }
  const scenarios = arrayField(value, "scenarios").map((item) => {
    if (!isRecord(item)) throw invalidResponse();
    exactKeys(item, BENCHMARK_SCENARIO_KEYS);
    const scenarioId = parseScenarioId(stringField(item, "scenario_id"));
    const scenarioSha256 = stringField(item, "scenario_sha256");
    const rerenderAll = integerField(item, "rerender_all_artifact_count");
    const targeted = integerField(item, "targeted_artifact_count");
    const protectedCount = integerField(item, "protected_artifact_count");
    const scopeReduction = integerField(item, "scope_reduction_basis_points");
    const incidentClass = parseIncidentClass(stringField(item, "incident_class"));
    if (
      !DIGEST.test(scenarioSha256) ||
      incidentClass !== expectedIncidentClass(scenarioId) ||
      rerenderAll === 0 ||
      targeted === 0 ||
      protectedCount === 0 ||
      targeted + protectedCount !== rerenderAll ||
      scopeReduction > 10_000 ||
      scopeReduction !== Math.floor((protectedCount * 10_000) / rerenderAll)
    ) {
      throw invalidResponse();
    }
    return {
      scenario_id: scenarioId,
      scenario_sha256: scenarioSha256,
      incident_class: incidentClass,
      rerender_all_artifact_count: rerenderAll,
      targeted_artifact_count: targeted,
      protected_artifact_count: protectedCount,
      scope_reduction_basis_points: scopeReduction,
    };
  });
  if (
    scenarios.length !== REFERENCE_SCENARIO_IDS.length ||
    new Set(scenarios.map(({ scenario_id }) => scenario_id)).size !== REFERENCE_SCENARIO_IDS.length
  ) {
    throw invalidResponse();
  }
  const requirementsSource = recordField(value, "acceptance_requirements");
  exactKeys(requirementsSource, BENCHMARK_REQUIREMENT_KEYS);
  const requirements: ReferenceBenchmarkSuite["acceptance_requirements"] = {
    output_equivalence: "required",
    protected_output_integrity: "required",
    maximum_false_authorized_actions: integerField(
      requirementsSource,
      "maximum_false_authorized_actions",
    ),
    minimum_resolvable_holdout_accuracy_basis_points: boundedIntegerField(
      requirementsSource,
      "minimum_resolvable_holdout_accuracy_basis_points",
      0,
      10_000,
    ),
    minimum_median_compute_avoided_basis_points: boundedIntegerField(
      requirementsSource,
      "minimum_median_compute_avoided_basis_points",
      0,
      10_000,
    ),
    minimum_median_bytes_avoided_basis_points: boundedIntegerField(
      requirementsSource,
      "minimum_median_bytes_avoided_basis_points",
      0,
      10_000,
    ),
  };
  const measurement = recordField(value, "measurement_boundary");
  exactKeys(measurement, BENCHMARK_MEASUREMENT_KEYS);
  const claimsObservedSavings = booleanField(measurement, "catalog_claims_observed_savings");
  if (
    requirementsSource.output_equivalence !== "required" ||
    requirementsSource.protected_output_integrity !== "required" ||
    requirements.maximum_false_authorized_actions !== 0 ||
    requirements.minimum_resolvable_holdout_accuracy_basis_points !== 9500 ||
    requirements.minimum_median_compute_avoided_basis_points !== 4000 ||
    requirements.minimum_median_bytes_avoided_basis_points !== 4000 ||
    measurement.scope_reduction_is_measured_result !== false ||
    measurement.reported_results_require_recorded_evaluator_output !== true ||
    measurement.live_run_scope !== "representative-evidence-only" ||
    claimsObservedSavings !== (resultState === "recorded") ||
    (resultState === "not-reported" && value.result !== null) ||
    (resultState === "recorded" && value.result === null)
  ) {
    throw invalidResponse();
  }
  const provenance = recordField(value, "provenance");
  const parsedProvenance = parseProvenance(provenance);
  const authority = recordField(value, "authority");
  exactKeys(authority, BENCHMARK_AUTHORITY_KEYS);
  const parsedAuthority = parseAuthority(authority);
  if (authority.benchmark_result_authority !== "recorded-evaluator-output") {
    throw invalidResponse();
  }
  const result =
    resultState === "recorded"
      ? await parseImpactBenchmark(value.result, scenarios, requirements, sha256)
      : null;
  const suiteSha256 = await verifyJsonDigest(value, "suite_sha256", sha256);
  return {
    schema: "reference-benchmark-suite/v1",
    suite_id: stringField(value, "suite_id"),
    definition_state: "sealed",
    result_state: resultState,
    scenarios,
    acceptance_requirements: requirements,
    measurement_boundary: {
      scope_reduction_is_measured_result: false,
      reported_results_require_recorded_evaluator_output: true,
      catalog_claims_observed_savings: claimsObservedSavings,
      live_run_scope: "representative-evidence-only",
    },
    result,
    provenance: parsedProvenance,
    authority: {
      ...parsedAuthority,
      benchmark_result_authority: "recorded-evaluator-output",
    },
    suite_sha256: suiteSha256,
  };
}

export function createReferenceDemoAdapter({
  baseUrl,
  fetch: fetchImplementation = fetch,
  createObjectUrl = (blob) => URL.createObjectURL(blob),
  revokeObjectUrl = (url) => URL.revokeObjectURL(url),
  createRequestId = () => crypto.randomUUID(),
  createApprovalNonce = () => crypto.randomUUID(),
  sha256 = defaultSha256,
}: ReferenceDemoAdapterOptions): ReferenceDemoAdapter {
  const origin = new URL(baseUrl).origin;
  const usedApprovalNonces = new Set<string>();

  function endpoint(path: string): URL {
    return new URL(path, `${origin}/`);
  }

  async function jsonRequest(path: string, signal?: AbortSignal): Promise<unknown> {
    let response: Response;
    try {
      response = await fetchImplementation(endpoint(path), {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
        method: "GET",
        redirect: "error",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (error) {
      throw new ReferenceDemoApiError(null, "reference-network-failure", { cause: error });
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    let body: unknown;
    try {
      body = contentType === "application/json" ? await response.json() : null;
    } catch (error) {
      throw new ReferenceDemoApiError(response.status, "reference-response-invalid", {
        cause: error,
      });
    }
    if (!response.ok) {
      throw new ReferenceDemoApiError(response.status, "reference-request-failed");
    }
    if (contentType !== "application/json") throw invalidResponse();
    return body;
  }

  async function verifiedVisual(
    descriptor: ReferenceVisualDescriptor,
    expectedScenarioSha256: string,
    signal?: AbortSignal,
  ): Promise<VerifiedReferenceVisual> {
    if (!DIGEST.test(expectedScenarioSha256)) throw invalidResponse();
    let response: Response;
    try {
      response = await fetchImplementation(endpoint(descriptor.href), {
        credentials: "same-origin",
        headers: { Accept: "image/png" },
        method: "GET",
        redirect: "error",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (error) {
      throw new ReferenceDemoApiError(null, "reference-network-failure", { cause: error });
    }
    if (!response.ok) {
      throw new ReferenceDemoApiError(response.status, "reference-visual-unavailable");
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    const declaredSha256 = response.headers.get("x-content-sha256");
    const scenarioSha256 = response.headers.get("x-colortrace-scenario-sha256");
    if (
      contentType !== "image/png" ||
      declaredSha256 === null ||
      !DIGEST.test(declaredSha256) ||
      declaredSha256 !== descriptor.content_sha256 ||
      scenarioSha256 !== expectedScenarioSha256 ||
      response.headers.get("x-colortrace-representation") !== descriptor.representation ||
      response.headers.get("x-colortrace-pixel-evidence") !== "true"
    ) {
      await response.body?.cancel();
      throw new ReferenceDemoApiError(response.status, "reference-visual-response-invalid");
    }
    const content = await response.arrayBuffer();
    const signature = new Uint8Array(content.slice(0, 8));
    if (
      content.byteLength < 8 ||
      content.byteLength > MAX_VISUAL_BYTES ||
      ![137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => signature[index] === byte)
    ) {
      throw new ReferenceDemoApiError(response.status, "reference-visual-response-invalid");
    }
    const actualSha256 = await sha256(content);
    if (actualSha256 !== declaredSha256 || actualSha256 !== descriptor.content_sha256) {
      throw new ReferenceDemoApiError(response.status, "reference-visual-digest-conflict");
    }
    return {
      kind: descriptor.kind,
      content_sha256: actualSha256,
      scenario_sha256: scenarioSha256,
      representation: descriptor.representation,
      pixel_evidence: true,
      width: descriptor.width,
      height: descriptor.height,
      served_artifact_id: descriptor.served_artifact_id,
      source_relation: descriptor.source_relation,
      src: createObjectUrl(new Blob([content], { type: "image/png" })),
    };
  }

  async function runScenario(
    scenarioId: ReferenceScenarioId,
    signal?: AbortSignal,
  ): Promise<ReferenceResponsePacket> {
    let request: ReferenceScenarioRunRequest;
    try {
      request = createReferenceScenarioRunRequest(createRequestId());
    } catch (error) {
      throw new ReferenceDemoApiError(null, "reference-request-id-invalid", { cause: error });
    }
    let response: Response;
    try {
      response = await fetchImplementation(
        endpoint(`/v1/demo/scenarios/${encodeURIComponent(scenarioId)}/runs`),
        {
          body: JSON.stringify(request),
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
          redirect: "error",
          ...(signal === undefined ? {} : { signal }),
        },
      );
    } catch (error) {
      throw new ReferenceDemoApiError(null, "reference-network-failure", { cause: error });
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    let body: unknown;
    try {
      body = contentType === "application/json" ? await response.json() : null;
    } catch (error) {
      throw new ReferenceDemoApiError(response.status, "reference-response-invalid", {
        cause: error,
      });
    }
    if (!response.ok) {
      throw new ReferenceDemoApiError(response.status, "reference-run-request-failed");
    }
    if (contentType !== "application/json") throw invalidResponse();
    try {
      return await parseReferenceResponsePacket(body, scenarioId, request.request_id, sha256);
    } catch (error) {
      throw new ReferenceDemoApiError(response.status, "reference-response-invalid", {
        cause: error,
      });
    }
  }

  async function decideRecovery(
    packet: ReferenceResponsePacket,
    decision: ReferenceRecoveryChoice,
    signal?: AbortSignal,
  ): Promise<ReferenceRecoveryDecision> {
    let request: ReferenceRecoveryDecisionRequest;
    try {
      const approvalNonce = createApprovalNonce();
      if (usedApprovalNonces.has(approvalNonce)) throw new Error("approval-nonce-reused");
      request = createReferenceRecoveryDecisionRequest(packet, decision, approvalNonce);
      usedApprovalNonces.add(approvalNonce);
    } catch (error) {
      throw new ReferenceDemoApiError(null, "reference-approval-nonce-invalid", {
        cause: error,
      });
    }
    let response: Response;
    try {
      response = await fetchImplementation(
        endpoint(
          `/v1/demo/scenarios/${encodeURIComponent(packet.scenario_id)}/runs/${encodeURIComponent(packet.request_id)}/decision`,
        ),
        {
          body: JSON.stringify(request),
          credentials: "same-origin",
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
          },
          method: "POST",
          redirect: "error",
          ...(signal === undefined ? {} : { signal }),
        },
      );
    } catch (error) {
      throw new ReferenceDemoApiError(null, "reference-network-failure", { cause: error });
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    let body: unknown;
    try {
      body = contentType === "application/json" ? await response.json() : null;
    } catch (error) {
      throw new ReferenceDemoApiError(response.status, "reference-response-invalid", {
        cause: error,
      });
    }
    if (!response.ok) {
      throw new ReferenceDemoApiError(response.status, "reference-recovery-decision-failed");
    }
    if (
      contentType !== "application/json" ||
      response.headers.get("x-colortrace-execution-target") !== "colortrace-simulator" ||
      response.headers.get("x-colortrace-production-state-changed") !== "false"
    ) {
      throw new ReferenceDemoApiError(response.status, "reference-recovery-response-invalid");
    }
    try {
      return await parseReferenceRecoveryDecision(
        body,
        packet,
        decision,
        request.approval_nonce,
        sha256,
      );
    } catch (error) {
      throw new ReferenceDemoApiError(response.status, "reference-recovery-response-invalid", {
        cause: error,
      });
    }
  }

  return {
    listScenarios: async (signal) =>
      parseScenarioList(await jsonRequest("/v1/demo/scenarios", signal)),
    getScenario: async (scenarioId, signal) =>
      parseScenarioDetail(
        await jsonRequest(`/v1/demo/scenarios/${encodeURIComponent(scenarioId)}`, signal),
        scenarioId,
      ),
    benchmarkSuite: async (signal) =>
      parseBenchmarkSuite(await jsonRequest("/v1/benchmarks/reference-suite", signal), sha256),
    runScenario,
    decideRecovery,
    loadVisual: verifiedVisual,
    releaseVisual: (visual) => revokeObjectUrl(visual.src),
  };
}

async function defaultSha256(value: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return (
    "sha256:" +
    Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")
  );
}
