export const REFERENCE_QUERY_KEYS = [
  "alert.rule",
  "log.correlated-events",
  "metric.correlated-observations",
  "trace.by-id",
  "metric.worker-cohort",
  "log.config-cohort",
] as const;

export const REFERENCE_INCIDENT_CLASSES = [
  "resource-resolution-drift/v1",
  "configuration-rollout-drift/v1",
  "stale-derivative-cache/v1",
] as const;

export type ReferenceRunScenarioId =
  | "tos-resource-resolution-drift-v1"
  | "tos-config-rollout-drift-v1"
  | "tos-stale-derivative-cache-v1";
export type ReferenceRunIncidentClass = (typeof REFERENCE_INCIDENT_CLASSES)[number];
export type ReferenceQueryKey = (typeof REFERENCE_QUERY_KEYS)[number];
export type ReferenceRunStatus = "resolved" | "unresolved";
export type ReferenceAssessmentStatus = "supported" | "rejected" | "insufficient" | "conflicting";
export type ReferenceSignalClass = "log" | "metric" | "trace";

export type ReferenceDecisiveField =
  | "runtime.effective_resource_sha256"
  | "runtime.effective_config_sha256"
  | "runtime.config_generation"
  | "runtime.frame_pipeline_sha256"
  | "derivative.parent_sha256"
  | "cache.generation"
  | "cache.key";

export type ReferenceDecisiveValue = {
  readonly field: ReferenceDecisiveField;
  readonly value: string;
};

export type ReferenceRuntimeObservation = {
  readonly fact_id: string;
  readonly signal: ReferenceSignalClass;
  readonly scope_role: "affected" | "protected";
  readonly job_id: string;
  readonly trace_id: string;
  readonly observed_at: string;
  readonly query_key: ReferenceQueryKey;
  readonly evidence_id: string;
  readonly decisive_values: readonly ReferenceDecisiveValue[];
};

export type ReferenceRuntimeEvidenceProjection = {
  readonly request_id: string;
  readonly incident_id: string;
  readonly query_keys: readonly ReferenceQueryKey[];
  readonly evidence_ids: readonly string[];
  readonly observations: readonly ReferenceRuntimeObservation[];
  readonly projection_sha256: string;
};

export type ReferenceScenarioRunRequest = {
  readonly schema: "reference-scenario-run-request/v1";
  readonly request_id: string;
};

export type ReferenceRunScope = {
  readonly affected_job_ids: readonly string[];
  readonly safe_job_ids: readonly string[];
};

export type ReferenceSelectionTraceEntry = {
  readonly sequence: number;
  readonly selected_by: "policy" | "model";
  readonly query_key: ReferenceQueryKey;
  readonly evidence_id: string | null;
  readonly disposition: "continue" | "resolved" | "unresolved";
  readonly reason_codes: readonly string[];
  readonly operational_assessment_id: string | null;
  readonly reconciliation_id: string | null;
};

export type ReferenceModelSelection = {
  readonly trust: "untrusted-model-output";
  readonly query_keys: readonly ReferenceQueryKey[];
  readonly stop_reason:
    | "sufficient-evidence"
    | "incomplete-evidence"
    | "conflicting-evidence"
    | "invalid-evidence"
    | "evidence-unavailable"
    | "evidence-budget-exhausted";
  readonly output_sha256: string;
};

export type ReferenceModelInvocation = {
  readonly provider: "vertex-ai";
  readonly model: "gemini-3.5-flash";
  readonly prompt_version: "evidence-selection/v3";
  readonly input_tokens: number | null;
  readonly output_tokens: number | null;
  readonly model_calls: number;
  readonly unobserved_model_calls: number;
  readonly status: "accepted" | "failed" | "invalid";
};

export type ReferenceAgentSpan = {
  readonly sequence: number;
  readonly stage: "grafana" | "gemini" | "validator" | "reconciliation";
  readonly status: "ok" | "error" | "unresolved";
  readonly duration_ms: number;
  readonly query_key: ReferenceQueryKey | null;
  readonly input_tokens: number | null;
  readonly output_tokens: number | null;
  readonly attempts: number;
  readonly attempts_complete: boolean;
  readonly unobserved_model_calls: number;
  readonly error_code: string | null;
};

export type ReferenceActionIntent = {
  readonly action_intent_id: string;
  readonly reconciliation_id: string;
  readonly incident_class: ReferenceRunIncidentClass;
  readonly command: "reconcile-resource" | "pin-rollout" | "invalidate-cache";
  readonly target: "simulator";
  readonly requires_human_approval: true;
  readonly authorizes_execution: false;
  readonly affected_job_ids: readonly string[];
  readonly evidence_fact_ids: readonly string[];
  readonly parameters: Readonly<Record<string, unknown>>;
  readonly derivation_sha256: string;
};

export type ReferenceDiagnosisReconciliation = {
  readonly reconciliation_id: string;
  readonly status: ReferenceAssessmentStatus;
  readonly incident_class: ReferenceRunIncidentClass | null;
  readonly scope: ReferenceRunScope;
  readonly reason_codes: readonly string[];
};

export type ReferenceResponsePacket = {
  readonly schema: "response-packet/v3";
  readonly request_id: string;
  readonly packet_id: string;
  readonly version: 3;
  readonly status: ReferenceRunStatus;
  readonly incident_id: string;
  readonly scenario_id: ReferenceRunScenarioId;
  readonly fixture_id: string;
  readonly run_id: string;
  readonly evidence_ids: readonly string[];
  readonly reference_evidence: {
    readonly evidence_bundle_id: string;
    readonly source: "grafana-mcp";
    readonly structured_only: true;
    readonly query_keys: readonly ReferenceQueryKey[];
    readonly evidence_ids: readonly string[];
    readonly signal_classes: readonly ReferenceSignalClass[];
  };
  readonly runtime_evidence_projection: ReferenceRuntimeEvidenceProjection;
  readonly expected_state_assessment: {
    readonly assessment_id: string;
    readonly expected_state_sha256: string;
    readonly status: ReferenceAssessmentStatus;
  };
  readonly operational_evidence_assessment: {
    readonly assessment_id: string;
    readonly status: ReferenceAssessmentStatus;
  };
  readonly diagnosis_reconciliation: ReferenceDiagnosisReconciliation;
  readonly selection_trace: readonly ReferenceSelectionTraceEntry[];
  readonly model_selection: ReferenceModelSelection | null;
  readonly model_invocation: ReferenceModelInvocation | null;
  readonly agent_trace: {
    readonly trace_id: string;
    readonly spans: readonly ReferenceAgentSpan[];
  };
  readonly authority_policy: readonly [
    "gemini-query-selection-only",
    "grafana-read-only-evidence",
    "deterministic-validators-authoritative",
    "human-approval-required-for-action",
  ];
  readonly action_intent: ReferenceActionIntent | null;
  readonly no_action_reason: string | null;
  readonly finalized_at: string;
  readonly derivation_sha256: string;
};

export type ReferencePacketSha256 = (value: ArrayBuffer) => Promise<string>;

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const REQUEST_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const REASON_CODE = /^[a-z][a-z0-9-]{1,79}$/u;
const RUNTIME_FACT_ID = /^runtime-fact:[0-9a-f]{64}$/u;
const TRACE_ID = /^[0-9a-f]{32}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const BARE_DIGEST = /^[0-9a-f]{64}$/u;
const ATTRIBUTE_DIGEST = /^(?:sha256:)?[0-9a-f]{64}$/u;
const POSITIVE_INTEGER_TEXT = /^[1-9][0-9]{0,15}$/u;
const QUERY_KEY_SET = new Set<string>(REFERENCE_QUERY_KEYS);
const INCIDENT_CLASS_SET = new Set<string>(REFERENCE_INCIDENT_CLASSES);
const ASSESSMENT_STATUSES = new Set<ReferenceAssessmentStatus>([
  "supported",
  "rejected",
  "insufficient",
  "conflicting",
]);
const STOP_REASONS = new Set<ReferenceModelSelection["stop_reason"]>([
  "sufficient-evidence",
  "incomplete-evidence",
  "conflicting-evidence",
  "invalid-evidence",
  "evidence-unavailable",
  "evidence-budget-exhausted",
]);
const ACTION_COMMANDS: Readonly<
  Record<ReferenceRunIncidentClass, ReferenceActionIntent["command"]>
> = {
  "resource-resolution-drift/v1": "reconcile-resource",
  "configuration-rollout-drift/v1": "pin-rollout",
  "stale-derivative-cache/v1": "invalidate-cache",
};
const ACTION_CHANGED_FIELDS: Readonly<Record<ReferenceRunIncidentClass, readonly string[]>> = {
  "resource-resolution-drift/v1": ["effective_resource_sha256"],
  "configuration-rollout-drift/v1": ["config_generation", "effective_config_sha256"],
  "stale-derivative-cache/v1": ["derivative_generation", "derivative_parent_sha256"],
};

const PACKET_KEYS = new Set([
  "schema",
  "packet_id",
  "version",
  "status",
  "incident_id",
  "scenario_id",
  "fixture_id",
  "run_id",
  "policy_binding",
  "fixed_window",
  "evidence_ids",
  "reference_evidence",
  "runtime_evidence_projection",
  "expected_state_assessment",
  "operational_evidence_assessment",
  "incident_class_assessments",
  "diagnosis_reconciliation",
  "selection_trace",
  "model_selection",
  "model_invocation",
  "agent_trace",
  "authority_policy",
  "action_intent",
  "no_action_reason",
  "finalized_at",
  "derivation_sha256",
]);
const SELECTION_TRACE_KEYS = new Set([
  "sequence",
  "selected_by",
  "query_key",
  "evidence_id",
  "disposition",
  "reason_codes",
  "operational_assessment_id",
  "reconciliation_id",
]);
const MODEL_INVOCATION_KEYS = new Set([
  "schema",
  "provider",
  "model",
  "prompt_version",
  "request_sha256",
  "output_sha256",
  "input_tokens",
  "output_tokens",
  "model_calls",
  "unobserved_model_calls",
  "status",
]);
const AGENT_SPAN_KEYS = new Set([
  "sequence",
  "stage",
  "status",
  "duration_ms",
  "query_key",
  "input_tokens",
  "output_tokens",
  "attempts",
  "attempts_complete",
  "unobserved_model_calls",
  "error_code",
]);
const ACTION_INTENT_KEYS = new Set([
  "schema",
  "reconciliation_id",
  "incident_class",
  "command",
  "target",
  "requires_human_approval",
  "authorizes_execution",
  "affected_job_ids",
  "evidence_fact_ids",
  "parameters",
  "action_intent_id",
  "derivation_sha256",
]);
const RECONCILIATION_KEYS = new Set([
  "schema",
  "reconciliation_id",
  "status",
  "incident_class",
  "expected_state_assessment_id",
  "operational_evidence_assessment_id",
  "class_assessment_ids",
  "scope",
  "evidence_fact_ids",
  "reason_codes",
  "action_intent",
  "derivation_sha256",
]);
const EXPECTED_ASSESSMENT_KEYS = new Set([
  "schema",
  "status",
  "expected_state_id",
  "expected_state_sha256",
  "scenario_id",
  "fixture_id",
  "run_id",
  "evidence_window",
  "approved",
  "scope",
  "reason_codes",
  "assessment_id",
  "derivation_sha256",
]);
const OPERATIONAL_ASSESSMENT_KEYS = new Set([
  "schema",
  "status",
  "expected_state_assessment_id",
  "request_id",
  "incident_id",
  "fixture_id",
  "run_id",
  "job_facts",
  "fact_ids",
  "evidence_ids",
  "reason_codes",
  "assessment_id",
  "derivation_sha256",
]);
const CLASS_ASSESSMENT_KEYS = new Set([
  "schema",
  "status",
  "incident_class",
  "expected_state_assessment_id",
  "operational_evidence_assessment_id",
  "scope",
  "evidence_fact_ids",
  "cause",
  "reason_codes",
  "assessment_id",
  "derivation_sha256",
]);
const REFERENCE_EVIDENCE_KEYS = new Set([
  "schema",
  "evidence_bundle_id",
  "request_id",
  "incident_id",
  "scenario_id",
  "fixture_id",
  "run_id",
  "source",
  "structured_only",
  "query_keys",
  "evidence_ids",
  "expected_state_sha256",
  "runtime_projection",
  "derivation_sha256",
]);
const RUNTIME_PROJECTION_KEYS = new Set([
  "schema",
  "request_id",
  "incident_id",
  "query_keys",
  "evidence_ids",
  "observations",
  "projection_sha256",
]);
const RUNTIME_OBSERVATION_KEYS = new Set([
  "schema",
  "request_id",
  "incident_id",
  "event_id",
  "signal",
  "fixture_id",
  "run_id",
  "job_id",
  "worker_id",
  "trace_id",
  "artifact_id",
  "config_sha256",
  "resource_sha256",
  "transform_id",
  "observed_at",
  "emitted_at",
  "retrieved_at",
  "attributes",
  "provenance",
  "fact_id",
  "fact_sha256",
]);
const RUNTIME_PROVENANCE_KEYS = new Set([
  "query_key",
  "evidence_id",
  "event_sha256",
  "content_sha256",
  "catalog_version",
  "catalog_sha256",
  "tool",
  "normalized_arguments",
]);
const MODEL_SELECTION_KEYS = new Set([
  "schema",
  "trust",
  "hypotheses",
  "query_keys",
  "stop_reason",
  "output_sha256",
]);

const QUERY_SIGNAL: Readonly<
  Record<Exclude<ReferenceQueryKey, "alert.rule">, ReferenceSignalClass>
> = {
  "log.correlated-events": "log",
  "metric.correlated-observations": "metric",
  "trace.by-id": "trace",
  "metric.worker-cohort": "metric",
  "log.config-cohort": "log",
};
const QUERY_TOOL: Readonly<Record<Exclude<ReferenceQueryKey, "alert.rule">, string>> = {
  "log.correlated-events": "query_loki_logs",
  "metric.correlated-observations": "query_prometheus",
  "trace.by-id": "tempo_get-trace",
  "metric.worker-cohort": "query_prometheus",
  "log.config-cohort": "query_loki_logs",
};
const SCENARIO_DECISIVE_FIELDS: Readonly<
  Record<
    ReferenceRunScenarioId,
    readonly {
      readonly field: ReferenceDecisiveField;
      readonly pattern: RegExp;
    }[]
  >
> = {
  "tos-resource-resolution-drift-v1": [
    { field: "runtime.effective_resource_sha256", pattern: ATTRIBUTE_DIGEST },
    { field: "runtime.frame_pipeline_sha256", pattern: ATTRIBUTE_DIGEST },
  ],
  "tos-config-rollout-drift-v1": [
    { field: "runtime.effective_config_sha256", pattern: ATTRIBUTE_DIGEST },
    { field: "runtime.config_generation", pattern: POSITIVE_INTEGER_TEXT },
    { field: "runtime.frame_pipeline_sha256", pattern: ATTRIBUTE_DIGEST },
  ],
  "tos-stale-derivative-cache-v1": [
    { field: "runtime.frame_pipeline_sha256", pattern: ATTRIBUTE_DIGEST },
    { field: "derivative.parent_sha256", pattern: ATTRIBUTE_DIGEST },
    { field: "cache.generation", pattern: POSITIVE_INTEGER_TEXT },
    { field: "cache.key", pattern: IDENTIFIER },
  ],
};

function invalidPacket(): Error {
  return new Error("reference-response-invalid");
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) throw invalidPacket();
  return value;
}

function exactKeys(value: Readonly<Record<string, unknown>>, keys: ReadonlySet<string>): void {
  const actual = Object.keys(value);
  if (actual.length !== keys.size || actual.some((key) => !keys.has(key))) throw invalidPacket();
}

function stringValue(value: unknown, pattern: RegExp = IDENTIFIER): string {
  if (typeof value !== "string" || !pattern.test(value)) throw invalidPacket();
  return value;
}

function integerValue(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw invalidPacket();
  }
  return value as number;
}

function nullableInteger(value: unknown): number | null {
  return value === null ? null : integerValue(value, 0, Number.MAX_SAFE_INTEGER);
}

function booleanValue(value: unknown): boolean {
  if (typeof value !== "boolean") throw invalidPacket();
  return value;
}

function stringArray(
  value: unknown,
  pattern: RegExp,
  minimum: number,
  maximum: number,
): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    value.some((item) => typeof item !== "string" || !pattern.test(item)) ||
    new Set(value).size !== value.length
  ) {
    throw invalidPacket();
  }
  return value as readonly string[];
}

function queryKey(value: unknown): ReferenceQueryKey {
  const key = stringValue(value);
  if (!QUERY_KEY_SET.has(key)) throw invalidPacket();
  return key as ReferenceQueryKey;
}

function incidentClass(value: unknown): ReferenceRunIncidentClass {
  const name = stringValue(value);
  if (!INCIDENT_CLASS_SET.has(name)) throw invalidPacket();
  return name as ReferenceRunIncidentClass;
}

function assessmentStatus(value: unknown): ReferenceAssessmentStatus {
  if (!ASSESSMENT_STATUSES.has(value as ReferenceAssessmentStatus)) throw invalidPacket();
  return value as ReferenceAssessmentStatus;
}

function prefixedDigest(value: unknown, prefix: string): string {
  const identifier = stringValue(value);
  if (!new RegExp(`^${prefix}:[0-9a-f]{64}$`, "u").test(identifier)) throw invalidPacket();
  return identifier;
}

function assertIdentityDigest(identifier: string, digest: string, prefix: string): void {
  if (identifier !== `${prefix}:${digest.slice("sha256:".length)}`) throw invalidPacket();
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function parseTimestamp(value: unknown): string {
  const timestamp = stringValue(value, TIMESTAMP);
  if (Number.isNaN(Date.parse(timestamp))) throw invalidPacket();
  return timestamp;
}

function parseScope(value: unknown): ReferenceRunScope {
  const source = record(value);
  exactKeys(source, new Set(["affected_job_ids", "safe_job_ids"]));
  const affected = stringArray(source.affected_job_ids, IDENTIFIER, 0, 512);
  const safe = stringArray(source.safe_job_ids, IDENTIFIER, 0, 512);
  if (affected.some((item) => safe.includes(item))) throw invalidPacket();
  return { affected_job_ids: affected, safe_job_ids: safe };
}

function parseSelectionTrace(
  value: unknown,
  evidenceIds: readonly string[],
): readonly ReferenceSelectionTraceEntry[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 4) throw invalidPacket();
  const entries = value.map((item, sequence): ReferenceSelectionTraceEntry => {
    const source = record(item);
    exactKeys(source, SELECTION_TRACE_KEYS);
    const selectedBy = source.selected_by;
    const disposition = source.disposition;
    if (
      (selectedBy !== "policy" && selectedBy !== "model") ||
      (disposition !== "continue" && disposition !== "resolved" && disposition !== "unresolved")
    ) {
      throw invalidPacket();
    }
    const evidenceId = source.evidence_id === null ? null : stringValue(source.evidence_id, DIGEST);
    const operationalAssessmentId =
      source.operational_assessment_id === null
        ? null
        : prefixedDigest(source.operational_assessment_id, "operational-assessment");
    const reconciliationId =
      source.reconciliation_id === null
        ? null
        : prefixedDigest(source.reconciliation_id, "diagnosis-reconciliation");
    if (
      source.sequence !== sequence ||
      (evidenceId !== null && !evidenceIds.includes(evidenceId))
    ) {
      throw invalidPacket();
    }
    return {
      sequence,
      selected_by: selectedBy,
      query_key: queryKey(source.query_key),
      evidence_id: evidenceId,
      disposition,
      reason_codes: stringArray(source.reason_codes, REASON_CODE, 0, 16),
      operational_assessment_id: operationalAssessmentId,
      reconciliation_id: reconciliationId,
    };
  });
  if (
    entries[0]?.selected_by !== "policy" ||
    entries[0].query_key !== "alert.rule" ||
    entries.slice(1).some(({ selected_by }) => selected_by !== "model") ||
    new Set(entries.map(({ query_key }) => query_key)).size !== entries.length ||
    entries.at(-1)?.disposition === "continue"
  ) {
    throw invalidPacket();
  }
  return entries;
}

function parseModelSelection(
  value: unknown,
  traceKeys: readonly ReferenceQueryKey[],
  evidenceIds: readonly string[],
): ReferenceModelSelection | null {
  if (value === null) return null;
  const source = record(value);
  exactKeys(source, MODEL_SELECTION_KEYS);
  if (source.schema !== "model-selection/v3" || source.trust !== "untrusted-model-output") {
    throw invalidPacket();
  }
  const keys = stringArray(source.query_keys, IDENTIFIER, 2, 4).map(queryKey);
  const stopReason = source.stop_reason as ReferenceModelSelection["stop_reason"];
  const outputSha256 = stringValue(source.output_sha256, DIGEST);
  if (!sameStrings(keys, traceKeys) || !STOP_REASONS.has(stopReason)) throw invalidPacket();
  if (!Array.isArray(source.hypotheses) || source.hypotheses.length > 3) throw invalidPacket();
  source.hypotheses.forEach((item, index) => {
    const hypothesis = record(item);
    exactKeys(hypothesis, new Set(["ordinal", "incident_class", "evidence_ids"]));
    if (
      hypothesis.ordinal !== index + 1 ||
      !INCIDENT_CLASS_SET.has(hypothesis.incident_class as string) ||
      stringArray(hypothesis.evidence_ids, DIGEST, 1, 4).some(
        (evidenceId) => !evidenceIds.includes(evidenceId),
      )
    ) {
      throw invalidPacket();
    }
  });
  return {
    trust: "untrusted-model-output",
    query_keys: keys,
    stop_reason: stopReason,
    output_sha256: outputSha256,
  };
}

function parseModelInvocation(value: unknown): ReferenceModelInvocation | null {
  if (value === null) return null;
  const source = record(value);
  exactKeys(source, MODEL_INVOCATION_KEYS);
  const status = source.status;
  if (
    source.schema !== "model-tool-invocation/v3" ||
    source.provider !== "vertex-ai" ||
    source.model !== "gemini-3.5-flash" ||
    source.prompt_version !== "evidence-selection/v3" ||
    (status !== "accepted" && status !== "failed" && status !== "invalid")
  ) {
    throw invalidPacket();
  }
  stringValue(source.request_sha256, DIGEST);
  const outputSha256 =
    source.output_sha256 === null ? null : stringValue(source.output_sha256, DIGEST);
  const inputTokens = nullableInteger(source.input_tokens);
  const outputTokens = nullableInteger(source.output_tokens);
  const modelCalls = integerValue(source.model_calls, 1, 4);
  const unobservedModelCalls = integerValue(source.unobserved_model_calls, 0, 4);
  const usageIsUnknown = inputTokens === null && outputTokens === null;
  const usageIsObserved = inputTokens !== null && outputTokens !== null;
  if (
    unobservedModelCalls > modelCalls ||
    (unobservedModelCalls > 0 && !usageIsUnknown) ||
    (status === "failed" && (outputSha256 !== null || (!usageIsUnknown && !usageIsObserved))) ||
    (status !== "failed" &&
      (outputSha256 === null || !usageIsObserved || unobservedModelCalls !== 0))
  ) {
    throw invalidPacket();
  }
  return {
    provider: "vertex-ai",
    model: "gemini-3.5-flash",
    prompt_version: "evidence-selection/v3",
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    model_calls: modelCalls,
    unobserved_model_calls: unobservedModelCalls,
    status,
  };
}

function parseAgentTrace(
  value: unknown,
  invocation: ReferenceModelInvocation | null,
): ReferenceResponsePacket["agent_trace"] {
  const source = record(value);
  exactKeys(source, new Set(["schema", "trace_id", "spans"]));
  if (source.schema !== "agent-trace/v2") throw invalidPacket();
  const traceId = stringValue(source.trace_id, TRACE_ID);
  if (!Array.isArray(source.spans) || source.spans.length < 1 || source.spans.length > 16) {
    throw invalidPacket();
  }
  const spans = source.spans.map((item, sequence): ReferenceAgentSpan => {
    const span = record(item);
    exactKeys(span, AGENT_SPAN_KEYS);
    const stage = span.stage;
    const status = span.status;
    if (
      span.sequence !== sequence ||
      (stage !== "grafana" &&
        stage !== "gemini" &&
        stage !== "validator" &&
        stage !== "reconciliation") ||
      (status !== "ok" && status !== "error" && status !== "unresolved")
    ) {
      throw invalidPacket();
    }
    const errorCode = span.error_code === null ? null : stringValue(span.error_code, REASON_CODE);
    const inputTokens = nullableInteger(span.input_tokens);
    const outputTokens = nullableInteger(span.output_tokens);
    const attempts = integerValue(span.attempts, 0, 8);
    const unobservedModelCalls = integerValue(span.unobserved_model_calls, 0, 4);
    if (
      (stage !== "gemini" && unobservedModelCalls !== 0) ||
      unobservedModelCalls > attempts ||
      (unobservedModelCalls > 0 && (inputTokens !== null || outputTokens !== null))
    ) {
      throw invalidPacket();
    }
    return {
      sequence,
      stage,
      status,
      duration_ms: integerValue(span.duration_ms, 0, 120_000),
      query_key: span.query_key === null ? null : queryKey(span.query_key),
      input_tokens: inputTokens,
      output_tokens: outputTokens,
      attempts,
      attempts_complete: booleanValue(span.attempts_complete),
      unobserved_model_calls: unobservedModelCalls,
      error_code: errorCode,
    };
  });
  const modelSpans = spans.filter(({ stage }) => stage === "gemini");
  if (invocation === null ? modelSpans.length !== 0 : modelSpans.length !== 1)
    throw invalidPacket();
  const modelSpan = modelSpans[0];
  if (
    invocation !== null &&
    (modelSpan?.input_tokens !== invocation.input_tokens ||
      modelSpan.output_tokens !== invocation.output_tokens ||
      modelSpan.attempts !== invocation.model_calls ||
      modelSpan.unobserved_model_calls !== invocation.unobserved_model_calls)
  ) {
    throw invalidPacket();
  }
  return { trace_id: traceId, spans };
}

function parseActionIntent(value: unknown): ReferenceActionIntent {
  const source = record(value);
  exactKeys(source, ACTION_INTENT_KEYS);
  const incident = incidentClass(source.incident_class);
  const command = source.command as ReferenceActionIntent["command"];
  const derivationSha256 = stringValue(source.derivation_sha256, DIGEST);
  const actionIntentId = prefixedDigest(source.action_intent_id, "action-intent");
  const reconciliationId = prefixedDigest(source.reconciliation_id, "diagnosis-reconciliation");
  const affectedJobIds = stringArray(source.affected_job_ids, IDENTIFIER, 1, 512);
  const evidenceFactIds = stringArray(source.evidence_fact_ids, RUNTIME_FACT_ID, 1, 2048);
  const parameters = record(source.parameters);
  exactKeys(
    parameters,
    new Set(
      incident === "stale-derivative-cache/v1"
        ? ["changed_fields", "expected", "observed", "cache_key"]
        : ["changed_fields", "expected", "observed"],
    ),
  );
  const changedFields = stringArray(parameters.changed_fields, IDENTIFIER, 1, 4);
  const expected = record(parameters.expected);
  const observed = record(parameters.observed);
  const expectedFields = ACTION_CHANGED_FIELDS[incident];
  if (
    source.schema !== "simulator-action-intent/v1" ||
    command !== ACTION_COMMANDS[incident] ||
    source.target !== "simulator" ||
    source.requires_human_approval !== true ||
    source.authorizes_execution !== false ||
    !sameStrings(changedFields, expectedFields) ||
    !sameStrings(Object.keys(expected).sort(), [...expectedFields].sort()) ||
    !sameStrings(Object.keys(observed).sort(), [...expectedFields].sort()) ||
    (incident === "stale-derivative-cache/v1" &&
      !IDENTIFIER.test(parameters.cache_key as string)) ||
    (incident !== "stale-derivative-cache/v1" && "cache_key" in parameters)
  ) {
    throw invalidPacket();
  }
  for (const field of expectedFields) {
    const expectsInteger = field.endsWith("generation");
    if (expectsInteger) {
      integerValue(expected[field], 0, Number.MAX_SAFE_INTEGER);
      integerValue(observed[field], 0, Number.MAX_SAFE_INTEGER);
    } else {
      stringValue(expected[field], DIGEST);
      stringValue(observed[field], DIGEST);
    }
    if (expected[field] === observed[field]) throw invalidPacket();
  }
  assertIdentityDigest(actionIntentId, derivationSha256, "action-intent");
  return {
    action_intent_id: actionIntentId,
    reconciliation_id: reconciliationId,
    incident_class: incident,
    command,
    target: "simulator",
    requires_human_approval: true,
    authorizes_execution: false,
    affected_job_ids: affectedJobIds,
    evidence_fact_ids: evidenceFactIds,
    parameters,
    derivation_sha256: derivationSha256,
  };
}

function parseProjection(
  value: unknown,
  incidentId: string,
  packetEvidenceIds: readonly string[],
  scenarioId: ReferenceRunScenarioId,
  fixtureId: string,
  runId: string,
  scope: ReferenceRunScope,
  windowStart: string,
  windowEnd: string,
): {
  readonly source: Readonly<Record<string, unknown>>;
  readonly requestId: string;
  readonly signalClasses: readonly ReferenceSignalClass[];
  readonly projection: ReferenceRuntimeEvidenceProjection;
} {
  const source = record(value);
  exactKeys(source, RUNTIME_PROJECTION_KEYS);
  if (source.schema !== "runtime-evidence-projection/v1" || source.incident_id !== incidentId) {
    throw invalidPacket();
  }
  const requestId = stringValue(source.request_id);
  const queryKeys = stringArray(source.query_keys, IDENTIFIER, 0, 3).map(queryKey);
  const evidenceIds = stringArray(source.evidence_ids, DIGEST, 0, 8);
  if (evidenceIds.some((evidenceId) => !packetEvidenceIds.includes(evidenceId))) {
    throw invalidPacket();
  }
  const projectionSha256 = stringValue(source.projection_sha256, DIGEST);
  if (!Array.isArray(source.observations) || source.observations.length > 2048) {
    throw invalidPacket();
  }
  const observedFactIds: string[] = [];
  const observedQueryKeys: ReferenceQueryKey[] = [];
  const observedEvidenceIds: string[] = [];
  const signalClasses: ReferenceSignalClass[] = [];
  const observations: ReferenceRuntimeObservation[] = [];
  const scopedJobIds = new Set([...scope.affected_job_ids, ...scope.safe_job_ids]);
  for (const item of source.observations) {
    const observation = record(item);
    exactKeys(observation, RUNTIME_OBSERVATION_KEYS);
    if (
      observation.schema !== "normalized-runtime-observation/v1" ||
      observation.request_id !== requestId ||
      observation.incident_id !== incidentId ||
      observation.fixture_id !== fixtureId ||
      observation.run_id !== runId
    ) {
      throw invalidPacket();
    }
    const signal = observation.signal;
    if (signal !== "log" && signal !== "metric" && signal !== "trace") throw invalidPacket();
    const factId = stringValue(observation.fact_id, RUNTIME_FACT_ID);
    const factSha256 = stringValue(observation.fact_sha256, DIGEST);
    if (factId !== `runtime-fact:${factSha256.slice("sha256:".length)}`) throw invalidPacket();

    stringValue(observation.event_id);
    stringValue(observation.worker_id);
    const jobId = stringValue(observation.job_id);
    if (!scopedJobIds.has(jobId)) throw invalidPacket();
    const scopeRole = scope.affected_job_ids.includes(jobId) ? "affected" : "protected";
    const traceId = stringValue(observation.trace_id, TRACE_ID);
    if (observation.artifact_id !== null) stringValue(observation.artifact_id);
    if (observation.config_sha256 !== null) stringValue(observation.config_sha256, BARE_DIGEST);
    stringValue(observation.resource_sha256, BARE_DIGEST);
    if (observation.transform_id !== null) stringValue(observation.transform_id);
    const observedAt = parseTimestamp(observation.observed_at);
    const emittedAt = parseTimestamp(observation.emitted_at);
    const retrievedAt = parseTimestamp(observation.retrieved_at);
    if (
      Date.parse(observedAt) < Date.parse(windowStart) ||
      Date.parse(observedAt) > Date.parse(windowEnd) ||
      Date.parse(emittedAt) < Date.parse(observedAt) ||
      Date.parse(retrievedAt) < Date.parse(emittedAt)
    ) {
      throw invalidPacket();
    }

    const attributes = record(observation.attributes);
    const decisiveValues = Object.freeze(
      SCENARIO_DECISIVE_FIELDS[scenarioId].map(({ field, pattern }) => {
        const decisiveValue = stringValue(attributes[field], pattern);
        if (
          pattern === POSITIVE_INTEGER_TEXT &&
          !Number.isSafeInteger(Number.parseInt(decisiveValue, 10))
        ) {
          throw invalidPacket();
        }
        return Object.freeze({ field, value: decisiveValue });
      }),
    );
    const provenance = record(observation.provenance);
    exactKeys(provenance, RUNTIME_PROVENANCE_KEYS);
    const evidenceId = stringValue(provenance.evidence_id, DIGEST);
    const provenanceQueryKey = queryKey(provenance.query_key);
    if (
      provenanceQueryKey === "alert.rule" ||
      !queryKeys.includes(provenanceQueryKey) ||
      !evidenceIds.includes(evidenceId) ||
      QUERY_SIGNAL[provenanceQueryKey] !== signal ||
      provenance.event_sha256 !== evidenceId ||
      provenance.catalog_version !== "grafana-evidence-query-catalog/v2" ||
      provenance.tool !== QUERY_TOOL[provenanceQueryKey] ||
      !isRecord(provenance.normalized_arguments)
    ) {
      throw invalidPacket();
    }
    stringValue(provenance.content_sha256, DIGEST);
    stringValue(provenance.catalog_sha256, DIGEST);
    observedFactIds.push(factId);
    if (!observedQueryKeys.includes(provenanceQueryKey)) observedQueryKeys.push(provenanceQueryKey);
    if (!observedEvidenceIds.includes(evidenceId)) observedEvidenceIds.push(evidenceId);
    if (!signalClasses.includes(signal)) signalClasses.push(signal);
    observations.push(
      Object.freeze({
        fact_id: factId,
        signal,
        scope_role: scopeRole,
        job_id: jobId,
        trace_id: traceId,
        observed_at: observedAt,
        query_key: provenanceQueryKey,
        evidence_id: evidenceId,
        decisive_values: decisiveValues,
      }),
    );
  }
  if (
    new Set(observedFactIds).size !== observedFactIds.length ||
    !sameStrings(queryKeys, observedQueryKeys) ||
    !sameStrings(evidenceIds, observedEvidenceIds)
  ) {
    throw invalidPacket();
  }
  return {
    source,
    requestId,
    signalClasses: Object.freeze(signalClasses),
    projection: Object.freeze({
      request_id: requestId,
      incident_id: incidentId,
      query_keys: Object.freeze(queryKeys),
      evidence_ids: Object.freeze(evidenceIds),
      observations: Object.freeze(observations),
      projection_sha256: projectionSha256,
    }),
  };
}

function parseReferenceEvidence(
  value: unknown,
  packet: {
    readonly incidentId: string;
    readonly scenarioId: ReferenceRunScenarioId;
    readonly fixtureId: string;
    readonly runId: string;
    readonly evidenceIds: readonly string[];
    readonly expectedStateSha256: string;
    readonly traceKeys: readonly ReferenceQueryKey[];
    readonly projection: ReturnType<typeof parseProjection>;
  },
): ReferenceResponsePacket["reference_evidence"] {
  const source = record(value);
  exactKeys(source, REFERENCE_EVIDENCE_KEYS);
  const evidenceBundleId = prefixedDigest(source.evidence_bundle_id, "reference-evidence");
  const derivationSha256 = stringValue(source.derivation_sha256, DIGEST);
  const queryKeys = stringArray(source.query_keys, IDENTIFIER, 1, 4).map(queryKey);
  const evidenceIds = stringArray(source.evidence_ids, DIGEST, 0, 8);
  if (
    source.schema !== "reference-evidence/v3" ||
    source.incident_id !== packet.incidentId ||
    source.scenario_id !== packet.scenarioId ||
    source.fixture_id !== packet.fixtureId ||
    source.run_id !== packet.runId ||
    source.request_id !== packet.projection.requestId ||
    source.source !== "grafana-mcp" ||
    source.structured_only !== true ||
    source.expected_state_sha256 !== packet.expectedStateSha256 ||
    !sameStrings(queryKeys, packet.traceKeys) ||
    !sameStrings(evidenceIds, packet.evidenceIds) ||
    canonicalJson(source.runtime_projection) !== canonicalJson(packet.projection.source)
  ) {
    throw invalidPacket();
  }
  assertIdentityDigest(evidenceBundleId, derivationSha256, "reference-evidence");
  return {
    evidence_bundle_id: evidenceBundleId,
    source: "grafana-mcp",
    structured_only: true,
    query_keys: queryKeys,
    evidence_ids: evidenceIds,
    signal_classes: packet.projection.signalClasses,
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
  throw invalidPacket();
}

function utf8(value: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(value);
  return encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  ) as ArrayBuffer;
}

function withoutKeys(
  value: Readonly<Record<string, unknown>>,
  keys: ReadonlySet<string>,
): Readonly<Record<string, unknown>> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.has(key)));
}

async function verifyDerived(
  value: Readonly<Record<string, unknown>>,
  digestKey: string,
  excludedKeys: ReadonlySet<string>,
  sha256: ReferencePacketSha256,
): Promise<void> {
  const declared = stringValue(value[digestKey], DIGEST);
  const actual = await sha256(utf8(canonicalJson(withoutKeys(value, excludedKeys))));
  if (!DIGEST.test(actual) || actual !== declared) throw invalidPacket();
}

function parseRunRequest(value: unknown): ReferenceScenarioRunRequest {
  const source = record(value);
  exactKeys(source, new Set(["schema", "request_id"]));
  if (source.schema !== "reference-scenario-run-request/v1") throw invalidPacket();
  return {
    schema: "reference-scenario-run-request/v1",
    request_id: stringValue(source.request_id, REQUEST_IDENTIFIER),
  };
}

export function createReferenceScenarioRunRequest(requestId: string): ReferenceScenarioRunRequest {
  return parseRunRequest({ schema: "reference-scenario-run-request/v1", request_id: requestId });
}

export async function parseReferenceResponsePacket(
  value: unknown,
  expectedScenarioId: ReferenceRunScenarioId,
  requestId: string,
  sha256: ReferencePacketSha256,
): Promise<ReferenceResponsePacket> {
  const source = record(value);
  exactKeys(source, PACKET_KEYS);
  const status = source.status;
  if (
    source.schema !== "response-packet/v3" ||
    source.version !== 3 ||
    (status !== "resolved" && status !== "unresolved") ||
    source.scenario_id !== expectedScenarioId
  ) {
    throw invalidPacket();
  }
  const packetId = prefixedDigest(source.packet_id, "response-packet");
  const derivationSha256 = stringValue(source.derivation_sha256, DIGEST);
  assertIdentityDigest(packetId, derivationSha256, "response-packet");
  const incidentId = stringValue(source.incident_id);
  const fixtureId = stringValue(source.fixture_id);
  const runId = stringValue(source.run_id);
  if (fixtureId !== "tears-of-steel-linear-exr-240-v1") throw invalidPacket();

  const policy = record(source.policy_binding);
  exactKeys(policy, new Set(["version", "sha256"]));
  if (policy.version !== "reference-investigation/v1") throw invalidPacket();
  stringValue(policy.sha256, DIGEST);

  const window = record(source.fixed_window);
  exactKeys(window, new Set(["start", "end"]));
  const windowStart = parseTimestamp(window.start);
  const windowEnd = parseTimestamp(window.end);
  if (Date.parse(windowStart) >= Date.parse(windowEnd)) throw invalidPacket();

  const evidenceIds = stringArray(source.evidence_ids, DIGEST, 0, 8);
  const expected = record(source.expected_state_assessment);
  exactKeys(expected, EXPECTED_ASSESSMENT_KEYS);
  const expectedAssessmentId = prefixedDigest(expected.assessment_id, "expected-assessment");
  const expectedDerivation = stringValue(expected.derivation_sha256, DIGEST);
  assertIdentityDigest(expectedAssessmentId, expectedDerivation, "expected-assessment");
  const expectedStateSha256 = stringValue(expected.expected_state_sha256, DIGEST);
  const expectedStateId = prefixedDigest(expected.expected_state_id, "expected-state");
  assertIdentityDigest(expectedStateId, expectedStateSha256, "expected-state");
  const expectedScope = parseScope(expected.scope);
  if (
    expected.schema !== "expected-state-assessment/v1" ||
    expected.status !== "supported" ||
    expected.scenario_id !== expectedScenarioId ||
    expected.fixture_id !== fixtureId ||
    expected.run_id !== runId ||
    canonicalJson(expected.evidence_window) !== canonicalJson(source.fixed_window) ||
    !isRecord(expected.approved)
  ) {
    throw invalidPacket();
  }
  stringArray(expected.reason_codes, REASON_CODE, 1, 16);

  const operational = record(source.operational_evidence_assessment);
  exactKeys(operational, OPERATIONAL_ASSESSMENT_KEYS);
  const operationalAssessmentId = prefixedDigest(
    operational.assessment_id,
    "operational-assessment",
  );
  const operationalDerivation = stringValue(operational.derivation_sha256, DIGEST);
  assertIdentityDigest(operationalAssessmentId, operationalDerivation, "operational-assessment");
  const operationalStatus = assessmentStatus(operational.status);
  const operationalRequestId =
    operational.request_id === null ? null : stringValue(operational.request_id);
  const operationalIncidentId =
    operational.incident_id === null ? null : stringValue(operational.incident_id);
  if (
    operational.schema !== "operational-evidence-assessment/v1" ||
    operational.expected_state_assessment_id !== expectedAssessmentId ||
    (operationalIncidentId !== null && operationalIncidentId !== incidentId) ||
    (status === "resolved" &&
      (operationalRequestId === null ||
        operationalIncidentId === null ||
        operationalStatus !== "supported")) ||
    operational.fixture_id !== fixtureId ||
    operational.run_id !== runId ||
    !isRecord(operational.job_facts) ||
    stringArray(operational.evidence_ids, DIGEST, 0, 8).some(
      (evidenceId) => !evidenceIds.includes(evidenceId),
    )
  ) {
    throw invalidPacket();
  }
  stringArray(operational.fact_ids, RUNTIME_FACT_ID, 0, 2048);
  stringArray(operational.reason_codes, REASON_CODE, 1, 16);

  if (
    !Array.isArray(source.incident_class_assessments) ||
    source.incident_class_assessments.length !== 3
  ) {
    throw invalidPacket();
  }
  const classAssessments = source.incident_class_assessments.map((item, index) => {
    const assessment = record(item);
    exactKeys(assessment, CLASS_ASSESSMENT_KEYS);
    const className = incidentClass(assessment.incident_class);
    const classStatus = assessmentStatus(assessment.status);
    const assessmentId = prefixedDigest(assessment.assessment_id, "class-assessment");
    const assessmentDerivation = stringValue(assessment.derivation_sha256, DIGEST);
    assertIdentityDigest(assessmentId, assessmentDerivation, "class-assessment");
    const cause = record(assessment.cause);
    if (
      assessment.schema !== "incident-class-assessment/v1" ||
      className !== REFERENCE_INCIDENT_CLASSES[index] ||
      assessment.expected_state_assessment_id !== expectedAssessmentId ||
      assessment.operational_evidence_assessment_id !== operationalAssessmentId ||
      (classStatus === "supported") !== Object.keys(cause).length > 0
    ) {
      throw invalidPacket();
    }
    parseScope(assessment.scope);
    stringArray(assessment.evidence_fact_ids, RUNTIME_FACT_ID, 0, 2048);
    stringArray(assessment.reason_codes, REASON_CODE, 1, 16);
    return { assessmentId, className, classStatus };
  });

  const reconciliation = record(source.diagnosis_reconciliation);
  exactKeys(reconciliation, RECONCILIATION_KEYS);
  if (reconciliation.schema !== "diagnosis-reconciliation/v1") throw invalidPacket();
  const reconciliationId = prefixedDigest(
    reconciliation.reconciliation_id,
    "diagnosis-reconciliation",
  );
  const reconciliationStatus = assessmentStatus(reconciliation.status);
  const reconciliationClass =
    reconciliation.incident_class === null ? null : incidentClass(reconciliation.incident_class);
  const reconciliationScope = parseScope(reconciliation.scope);
  const reconciliationFactIds = stringArray(
    reconciliation.evidence_fact_ids,
    RUNTIME_FACT_ID,
    0,
    2048,
  );
  const reconciliationReasons = stringArray(reconciliation.reason_codes, REASON_CODE, 1, 16);
  stringValue(reconciliation.derivation_sha256, DIGEST);
  const nestedAction =
    reconciliation.action_intent === null ? null : parseActionIntent(reconciliation.action_intent);
  if (
    reconciliation.expected_state_assessment_id !== expectedAssessmentId ||
    reconciliation.operational_evidence_assessment_id !== operationalAssessmentId ||
    !sameStrings(
      stringArray(reconciliation.class_assessment_ids, /^class-assessment:[0-9a-f]{64}$/u, 3, 3),
      classAssessments.map(({ assessmentId }) => assessmentId),
    ) ||
    (reconciliationStatus === "supported") !==
      (reconciliationClass !== null && nestedAction !== null) ||
    (nestedAction !== null &&
      (nestedAction.reconciliation_id !== reconciliationId ||
        nestedAction.incident_class !== reconciliationClass ||
        !sameStrings(nestedAction.affected_job_ids, reconciliationScope.affected_job_ids) ||
        !sameStrings(nestedAction.evidence_fact_ids, reconciliationFactIds)))
  ) {
    throw invalidPacket();
  }

  const trace = parseSelectionTrace(source.selection_trace, evidenceIds);
  const traceKeys = trace.map(({ query_key }) => query_key);
  if (
    trace.at(-1)?.operational_assessment_id !== operationalAssessmentId ||
    trace.at(-1)?.reconciliation_id !== reconciliationId
  ) {
    throw invalidPacket();
  }
  const modelSelection = parseModelSelection(source.model_selection, traceKeys, evidenceIds);
  const modelInvocation = parseModelInvocation(source.model_invocation);
  if (
    (modelSelection === null && modelInvocation?.status === "accepted") ||
    (modelSelection !== null &&
      (modelInvocation === null ||
        modelInvocation.status !== "accepted" ||
        modelSelection.output_sha256 !== record(source.model_invocation).output_sha256))
  ) {
    throw invalidPacket();
  }
  const agentTrace = parseAgentTrace(source.agent_trace, modelInvocation);

  const projection = parseProjection(
    source.runtime_evidence_projection,
    incidentId,
    evidenceIds,
    expectedScenarioId,
    fixtureId,
    runId,
    expectedScope,
    windowStart,
    windowEnd,
  );
  if (operationalRequestId !== null && operationalRequestId !== projection.requestId) {
    throw invalidPacket();
  }
  const referenceEvidence = parseReferenceEvidence(source.reference_evidence, {
    incidentId,
    scenarioId: expectedScenarioId,
    fixtureId,
    runId,
    evidenceIds,
    expectedStateSha256,
    traceKeys,
    projection,
  });

  const authority = source.authority_policy;
  if (
    !Array.isArray(authority) ||
    !sameStrings(authority as string[], [
      "gemini-query-selection-only",
      "grafana-read-only-evidence",
      "deterministic-validators-authoritative",
      "human-approval-required-for-action",
    ])
  ) {
    throw invalidPacket();
  }
  const actionIntent =
    source.action_intent === null ? null : parseActionIntent(source.action_intent);
  const noActionReason =
    source.no_action_reason === null ? null : stringValue(source.no_action_reason, REASON_CODE);
  if (
    (status === "resolved" &&
      (reconciliationStatus !== "supported" ||
        reconciliationClass === null ||
        reconciliationClass !== expectedIncidentClass(expectedScenarioId) ||
        actionIntent === null ||
        canonicalJson(source.action_intent) !== canonicalJson(reconciliation.action_intent) ||
        noActionReason !== null ||
        modelSelection?.stop_reason !== "sufficient-evidence" ||
        modelInvocation?.status !== "accepted" ||
        trace.at(-1)?.disposition !== "resolved" ||
        referenceEvidence.signal_classes.length < 2)) ||
    (status === "unresolved" &&
      (actionIntent !== null ||
        noActionReason === null ||
        trace.at(-1)?.disposition !== "unresolved"))
  ) {
    throw invalidPacket();
  }
  if (
    actionIntent !== null &&
    (!sameStrings(actionIntent.affected_job_ids, reconciliationScope.affected_job_ids) ||
      actionIntent.reconciliation_id !== reconciliationId)
  ) {
    throw invalidPacket();
  }
  if (
    reconciliationClass !== null &&
    !classAssessments.some(
      (assessment) =>
        assessment.className === reconciliationClass && assessment.classStatus === "supported",
    )
  ) {
    throw invalidPacket();
  }
  if (
    reconciliationStatus === "supported" &&
    (!sameStrings(reconciliationScope.affected_job_ids, expectedScope.affected_job_ids) ||
      !sameStrings(reconciliationScope.safe_job_ids, expectedScope.safe_job_ids))
  ) {
    throw invalidPacket();
  }

  const finalizedAt = parseTimestamp(source.finalized_at);
  const request = createReferenceScenarioRunRequest(requestId);
  const bindingSha256 = await sha256(utf8(`${expectedScenarioId}\0${request.request_id}`));
  if (!DIGEST.test(bindingSha256)) throw invalidPacket();
  const bindingHex = bindingSha256.slice("sha256:".length);
  if (
    incidentId !== `reference-incident-${bindingHex.slice(0, 24)}` ||
    runId !== `reference-run-${bindingHex.slice(24, 48)}`
  ) {
    throw invalidPacket();
  }
  await verifyDerived(
    source,
    "derivation_sha256",
    new Set(["packet_id", "derivation_sha256"]),
    sha256,
  );

  return {
    schema: "response-packet/v3",
    request_id: request.request_id,
    packet_id: packetId,
    version: 3,
    status,
    incident_id: incidentId,
    scenario_id: expectedScenarioId,
    fixture_id: fixtureId,
    run_id: runId,
    evidence_ids: evidenceIds,
    reference_evidence: referenceEvidence,
    runtime_evidence_projection: projection.projection,
    expected_state_assessment: {
      assessment_id: expectedAssessmentId,
      expected_state_sha256: expectedStateSha256,
      status: "supported",
    },
    operational_evidence_assessment: {
      assessment_id: operationalAssessmentId,
      status: operationalStatus,
    },
    diagnosis_reconciliation: {
      reconciliation_id: reconciliationId,
      status: reconciliationStatus,
      incident_class: reconciliationClass,
      scope: reconciliationScope,
      reason_codes: reconciliationReasons,
    },
    selection_trace: trace,
    model_selection: modelSelection,
    model_invocation: modelInvocation,
    agent_trace: agentTrace,
    authority_policy: [
      "gemini-query-selection-only",
      "grafana-read-only-evidence",
      "deterministic-validators-authoritative",
      "human-approval-required-for-action",
    ],
    action_intent: actionIntent,
    no_action_reason: noActionReason,
    finalized_at: finalizedAt,
    derivation_sha256: derivationSha256,
  };
}

function expectedIncidentClass(scenarioId: ReferenceRunScenarioId): ReferenceRunIncidentClass {
  switch (scenarioId) {
    case "tos-resource-resolution-drift-v1":
      return "resource-resolution-drift/v1";
    case "tos-config-rollout-drift-v1":
      return "configuration-rollout-drift/v1";
    case "tos-stale-derivative-cache-v1":
      return "stale-derivative-cache/v1";
  }
}
