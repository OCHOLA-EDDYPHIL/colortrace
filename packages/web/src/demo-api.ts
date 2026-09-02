export const CANONICAL_DEMO_SCENARIO = "ct-shadowed-lut-v1:canonical";
export const DEMO_APPROVAL_PHRASE = "APPROVE_COLORTRACE_SIMULATOR_ACTION";
export const DEMO_REJECTION_REASONS = [
  "unsafe-scope",
  "insufficient-evidence",
  "incorrect-command",
  "unresolved-risk",
] as const;

export type DemoRejectionReason = (typeof DEMO_REJECTION_REASONS)[number];

export type DemoPhase =
  | "preparing"
  | "awaiting-approval"
  | "executing"
  | "awaiting-closure"
  | "closing"
  | "closed"
  | "unresolved"
  | "expired";

export type DemoVisualKind = "expected" | "observed" | "recovered" | "diff";
export type DemoPreviewVisualKind = Exclude<DemoVisualKind, "recovered">;

export type DemoVisualDescriptor = {
  readonly href: string;
  readonly sha256: string;
  readonly media_type: "image/png";
  readonly label: "illustrative-authored-fixture";
};

export type DemoComparison = {
  readonly renders: readonly {
    readonly job_id: string;
    readonly worker_id: string;
    readonly status: "succeeded";
    readonly nominal_config_sha256: string;
    readonly resolved_lut_sha256: string;
  }[];
  readonly nominal_config_match: true;
  readonly resolved_lut_match: false;
};

export type DemoScenarioPreview = {
  readonly schema: "colortrace-demo-scenario-preview/v1";
  readonly scenario_id: string;
  readonly source_commit: string;
  readonly build_sha256: string;
  readonly comparison: DemoComparison;
  readonly visual_comparison: Readonly<Record<DemoPreviewVisualKind, DemoVisualDescriptor>>;
};

export type DemoInvestigationProofV1 = {
  readonly schema: "colortrace-demo-investigation-proof/v1";
  readonly packet_id: string;
  readonly packet_sha256: string;
  readonly status: "resolved" | "unresolved";
  readonly model_invocations: readonly {
    readonly invocation_id: string;
    readonly turn_kind: "evidence-selection" | "response-drafting";
    readonly model: string;
    readonly framework: string;
    readonly result_class: "accepted" | "budget-rejected" | "failed" | "invalid";
    readonly inventory_sha256: string | null;
    readonly output_sha256: string | null;
    readonly trace_id: string;
  }[];
  readonly evidence: readonly {
    readonly evidence_id: string;
    readonly query_key: string;
    readonly tool: string;
    readonly inventory_sha256: string;
    readonly content_sha256: string;
    readonly freshness: "current" | "stale" | "unresolved";
  }[];
  readonly validators: readonly {
    readonly result_id: string;
    readonly validator: string;
    readonly validator_version: string;
    readonly status: "resolved" | "unresolved";
    readonly derivation_sha256: string;
  }[];
  readonly scope: {
    readonly state: "resolved" | "unresolved";
    readonly affected_count: number;
    readonly safe_count: number;
    readonly unknown_count: number;
  };
  readonly budget_use: {
    readonly elapsed_ms: number;
    readonly model_turns: number;
    readonly input_tokens: number;
    readonly output_tokens: number;
    readonly mcp_attempts: number;
    readonly validator_calls: number;
  };
  readonly plan: {
    readonly status: "pending" | "approved" | "rejected" | "stale";
    readonly version: number;
    readonly plan_sha256: string;
    readonly target_sha256: string;
  };
};

export type DemoPlanTarget = {
  readonly schema: "simulator-target/v1";
  readonly namespace: "colortrace-simulator";
  readonly kind: "color-resource" | "frame" | "derivative";
  readonly id: string;
};

export type DemoPlanCommand =
  | {
      readonly schema: "simulator-quarantine-command/v1";
      readonly command_id: string;
      readonly namespace: "colortrace-simulator";
      readonly target: DemoPlanTarget;
      readonly expected_resource_sha256: string;
      readonly mode: "quarantine-and-install-approved-replacement";
    }
  | {
      readonly schema: "simulator-targeted-rerender-command/v1";
      readonly command_id: string;
      readonly namespace: "colortrace-simulator";
      readonly target: DemoPlanTarget;
      readonly job_id: string;
      readonly source_id: string;
      readonly transform_id: "look/main/v1" | "identity/v1";
      readonly source_manifest_sha256: string;
      readonly source_png_sha256: string;
      readonly expected_config_sha256: string;
      readonly expected_output_sha256: string;
      readonly expected_display_sha256: string;
      readonly lineage_parent_artifact_id: string;
    }
  | {
      readonly schema: "simulator-targeted-rerender-command/v1";
      readonly command_id: string;
      readonly namespace: "colortrace-simulator";
      readonly target: DemoPlanTarget;
      readonly job_id: string;
      readonly source_id: string;
      readonly transform_id: "look/main/v1" | "identity/v1";
      readonly source_manifest_sha256: string;
      readonly source_png_sha256: string;
      readonly expected_config_sha256: string;
      readonly expected_derivative_sha256: string;
      readonly expected_derivative_display_sha256: string;
      readonly lineage_parent_artifact_id: string;
    };

export type DemoActionEnvelope = {
  readonly schema: "simulator-action-envelope/v1";
  readonly fixture_id: string;
  readonly fixture_manifest_sha256: string;
  readonly fixture_generation: number;
  readonly source_batch_id: string;
  readonly source_batch_sha256: string;
  readonly runtime_manifest_sha256: string;
  readonly runtime_generation: number;
  readonly expected_publication_pointer_sha256: string;
  readonly expected_publication_generation: number;
  readonly expected_resource_sha256: string;
  readonly replacement_resource_logical_path: "luts/show_look.cube";
  readonly replacement_resource_sha256: string;
  readonly declared_resource_manifest_sha256: string;
  readonly ocio_version: "2.5.2";
  readonly preservation_manifest_sha256: string;
  readonly safe_complement_sha256: string;
  readonly lineage_manifest_sha256: string;
  readonly lineage_generation: number;
};

export type DemoInvestigationProofV2 = {
  readonly schema: "colortrace-demo-investigation-proof/v2";
  readonly packet_id: string;
  readonly packet_sha256: string;
  readonly status: "resolved";
  readonly adjudication: {
    readonly model_role: "evidence-selection-and-advisory-drafting";
    readonly model_authority: "advisory-only";
    readonly validator_role: "deterministic-claim-adjudication";
    readonly decision_mode: "deterministic-validation";
  };
  readonly model_invocations: DemoInvestigationProofV1["model_invocations"];
  readonly comparison: DemoComparison;
  readonly claims: readonly {
    readonly claim_id: string;
    readonly claim_type: string;
    readonly subject: {
      readonly kind: string;
      readonly value: string;
    };
    readonly state: "confirmed" | "rejected";
    readonly reason_codes: readonly string[];
    readonly evidence_ids: readonly string[];
    readonly source_validator_result_id: string;
  }[];
  readonly evidence: readonly {
    readonly evidence_id: string;
    readonly query_key: string;
    readonly tool: string;
    readonly inventory_sha256: string;
    readonly content_sha256: string;
    readonly freshness: "current";
    readonly display_excerpt: string;
    readonly display_excerpt_truncated: boolean;
  }[];
  readonly validators: DemoInvestigationProofV1["validators"];
  readonly scope: DemoInvestigationProofV1["scope"] & { readonly state: "resolved" };
  readonly budget_use: DemoInvestigationProofV1["budget_use"];
  readonly plan: DemoInvestigationProofV1["plan"] & {
    readonly exclusions_sha256: string;
    readonly commands_sha256: string;
    readonly targets: readonly DemoPlanTarget[];
    readonly protected_exclusions: readonly DemoPlanTarget[];
    readonly shared_action_bindings: DemoActionEnvelope;
    readonly command_summaries: readonly DemoPlanCommand[];
  };
};

export type DemoInvestigationProofV3 = Omit<
  DemoInvestigationProofV2,
  "schema" | "model_invocations" | "evidence"
> & {
  readonly schema: "colortrace-demo-investigation-proof/v3";
  readonly model_invocations: readonly {
    readonly invocation_id: string;
    readonly turn_kind: "evidence-selection" | "response-drafting";
    readonly attempt: number;
    readonly model: string;
    readonly location: string;
    readonly framework: string;
    readonly framework_version: string;
    readonly client_version: string;
    readonly prompt_version: string;
    readonly policy_version: string;
    readonly inventory_sha256: string | null;
    readonly normalized_input_sha256: string;
    readonly input_evidence_ids: readonly string[];
    readonly output_sha256: string | null;
    readonly latency_ms: number;
    readonly usage: {
      readonly input_tokens: number | null;
      readonly output_tokens: number | null;
      readonly model_calls: number;
      readonly unobserved_model_calls: number;
    };
    readonly result_class: "accepted" | "budget-rejected" | "failed" | "invalid";
    readonly error_code: string | null;
    readonly trace_id: string;
    readonly derivation_sha256: string;
  }[];
  readonly evidence: readonly {
    readonly evidence_id: string;
    readonly query_key: string;
    readonly tool: string;
    readonly inventory_sha256: string;
    readonly content_sha256: string;
    readonly freshness: "current";
    readonly display_excerpt: string;
    readonly display_excerpt_truncated: boolean;
    readonly source: {
      readonly kind: "grafana-mcp";
      readonly server: string;
      readonly server_version: string;
      readonly server_commit: string;
      readonly binary_sha256: string;
      readonly mcp_sdk_version: string;
      readonly mcp_protocol_version: string;
      readonly tool: string;
      readonly tool_input_schema_sha256: string;
      readonly tool_annotations_sha256: string;
      readonly inventory_version: string;
    };
    readonly timing: {
      readonly source_time: string | null;
      readonly event_time: string | null;
      readonly retrieved_at: string;
    };
  }[];
  readonly model_advisory: {
    readonly trust: "untrusted-model-output";
    readonly summary: string;
    readonly evidence_ids: readonly string[];
    readonly output_sha256: string;
  };
  readonly finalized_at: string;
};

export type DemoInvestigationProof =
  | DemoInvestigationProofV1
  | DemoInvestigationProofV2
  | DemoInvestigationProofV3;

export type DemoExecutionProof = {
  readonly schema: "colortrace-demo-execution-proof/v1";
  readonly action: {
    readonly action_id: string;
    readonly status: "succeeded";
    readonly outcome_id: string;
    readonly outcome_sha256: string;
    readonly publication_generation_before: number;
    readonly publication_generation_after: number;
    readonly affected_count: number;
    readonly safe_count: number;
    readonly safe_complement_before_sha256: string;
    readonly safe_complement_after_sha256: string;
    readonly safe_complement_proof_sha256: string;
    readonly publication_receipt_sha256: string;
  };
  readonly recovery: {
    readonly status: "recovery_verified" | "recovery_failed" | "recovery_unresolved";
    readonly workflow_id: string;
    readonly workflow_version: number;
    readonly packet_id: string;
    readonly packet_sha256: string;
    readonly evidence_count: number;
    readonly evidence_request_sha256: string;
    readonly checks: readonly {
      readonly check: string;
      readonly status: "passed" | "failed" | "unresolved";
      readonly result_sha256: string;
    }[];
  };
};

export type DemoBuildProvenance = Readonly<Record<string, unknown>> & {
  readonly schema: "colortrace-demo-build-provenance/v1";
  readonly source_commit: string;
};

export type DemoApproval = {
  readonly phrase: string;
  readonly incident_version: number;
  readonly plan_version: number;
  readonly plan_sha256: string;
  readonly target_sha256: string;
};

export type DemoRecovery = {
  readonly outcome_id: string;
  readonly outcome_sha256: string;
  readonly workflow_id: string;
  readonly workflow_version: number;
  readonly packet_id: string;
  readonly packet_sha256: string;
  readonly closure_id: string | null;
  readonly closure_sha256: string | null;
};

type DemoRunBase = {
  readonly run_id: string;
  readonly incident_id: string;
  readonly scenario_id: string;
  readonly source_commit: string;
  readonly build_sha256: string;
  readonly phase: DemoPhase;
  readonly version: number;
  readonly lease_expires_at: string | null;
  readonly poll: {
    readonly href: string;
    readonly after_milliseconds: number;
  };
  readonly approval: DemoApproval | null;
  readonly recovery: DemoRecovery | null;
  readonly visual_comparison: Readonly<Partial<Record<DemoVisualKind, DemoVisualDescriptor>>>;
  readonly investigation?: DemoInvestigationProof;
  readonly execution?: DemoExecutionProof;
  readonly terminal: boolean;
  readonly terminal_reason: string | null;
  readonly receipt_href: string | null;
  readonly reset: boolean;
  readonly approval_nonce?: string;
};

export type DemoTimelineKind =
  | "run-created"
  | "investigation-completed"
  | "approval-submitted"
  | "plan-rejected"
  | "run-unresolved"
  | "run-expired"
  | "recovery-verified"
  | "closure-submitted"
  | "recovery-closed";

export type DemoTimelineItem = {
  readonly run_version: number;
  readonly kind: DemoTimelineKind;
  readonly phase: DemoPhase;
  readonly recorded_at: string;
};

export type DemoRunV1 = DemoRunBase & {
  readonly schema: "colortrace-demo-run/v1";
};

export type DemoRunV2 = DemoRunBase & {
  readonly schema: "colortrace-demo-run/v2";
  readonly timeline: readonly DemoTimelineItem[];
};

export type DemoRun = DemoRunV1 | DemoRunV2;

export type DemoReceipt = {
  readonly schema: "colortrace-demo-receipt/v1";
  readonly run_id: string;
  readonly incident_id: string;
  readonly scenario_id: string;
  readonly source_commit: string;
  readonly build_sha256: string;
  readonly provenance: DemoBuildProvenance;
  readonly phase: "closed" | "unresolved" | "expired";
  readonly run_version: number;
  readonly created_at: string;
  readonly terminal_at: string;
  readonly reason_code: string;
  readonly bindings: {
    readonly incident_version: number | null;
    readonly plan_version: number | null;
    readonly plan_sha256: string | null;
    readonly target_sha256: string | null;
    readonly outcome_id: string | null;
    readonly outcome_sha256: string | null;
    readonly workflow_id: string | null;
    readonly workflow_version: number | null;
    readonly packet_id: string | null;
    readonly packet_sha256: string | null;
    readonly closure_id: string | null;
    readonly closure_sha256: string | null;
  };
  readonly visuals: readonly {
    readonly kind: DemoVisualKind;
    readonly sha256: string;
  }[];
  readonly proofs: readonly {
    readonly stage: "investigation" | "execution";
    readonly sha256: string;
  }[];
  readonly receipt_id: string;
  readonly receipt_sha256: string;
};

export type DemoReset = {
  readonly schema: "colortrace-demo-reset/v1";
  readonly run_id: string;
  readonly phase: "closed" | "unresolved" | "expired";
  readonly version: number;
  readonly reset: true;
  readonly receipt_href: string;
  readonly restoration: {
    readonly schema: "simulator-authored-scenario-reset/v1";
    readonly operation_id: string;
    readonly fixture_id: string;
    readonly source_batch_sha256: string;
    readonly previous_pointer_sha256: string;
    readonly active_pointer_sha256: string;
    readonly generation: 1;
  };
};

export type DemoStartRequest = {
  readonly approval_nonce: string;
  readonly idempotency_key: string;
};

export type VerifiedDemoVisual = {
  readonly kind: DemoVisualKind;
  readonly sha256: string;
  readonly src: string;
};

export type DemoApprovalRequest = {
  readonly schema: "colortrace-demo-approval-request/v1";
  readonly approval_nonce: string;
  readonly approval_phrase: string;
  readonly expected_run_version: number;
  readonly expected_incident_version: number;
  readonly expected_plan_version: number;
  readonly expected_plan_sha256: string;
  readonly expected_target_sha256: string;
  readonly idempotency_key: string;
};

export type DemoRejectionRequest = {
  readonly schema: "colortrace-demo-rejection-request/v1";
  readonly approval_nonce: string;
  readonly expected_run_version: number;
  readonly expected_incident_version: number;
  readonly expected_plan_version: number;
  readonly expected_plan_sha256: string;
  readonly expected_target_sha256: string;
  readonly reason_code: DemoRejectionReason;
  readonly idempotency_key: string;
};

export type DemoClosureRequest = {
  readonly schema: "colortrace-demo-closure-request/v1";
  readonly expected_run_version: number;
  readonly expected_incident_version: number;
  readonly expected_workflow_version: number;
  readonly expected_packet_id: string;
  readonly expected_packet_sha256: string;
  readonly expected_outcome_id: string;
  readonly expected_outcome_sha256: string;
  readonly reason: string;
  readonly idempotency_key: string;
};

export type DemoAdapter = {
  readonly preview: (signal?: AbortSignal) => Promise<DemoScenarioPreview>;
  readonly previewVisual: (
    kind: DemoPreviewVisualKind,
    expectedSha256?: string,
    signal?: AbortSignal,
  ) => Promise<VerifiedDemoVisual>;
  readonly start: (request: DemoStartRequest, signal?: AbortSignal) => Promise<DemoRun>;
  readonly get: (runId: string, signal?: AbortSignal) => Promise<DemoRun>;
  readonly approve: (runId: string, request: DemoApprovalRequest) => Promise<DemoRun>;
  readonly reject: (runId: string, request: DemoRejectionRequest) => Promise<DemoRun>;
  readonly close: (runId: string, request: DemoClosureRequest) => Promise<DemoRun>;
  readonly reset: (
    runId: string,
    expectedVersion: number,
    idempotencyKey: string,
  ) => Promise<DemoReset>;
  readonly receipt: (runId: string, signal?: AbortSignal) => Promise<DemoReceipt>;
  readonly visual: (
    runId: string,
    kind: DemoVisualKind,
    expectedSha256?: string,
    signal?: AbortSignal,
  ) => Promise<VerifiedDemoVisual>;
  readonly releaseVisual: (visual: VerifiedDemoVisual) => void;
};

export type DemoAdapterOptions = {
  readonly baseUrl: string;
  readonly fetch?: typeof fetch;
  readonly createObjectUrl?: (blob: Blob) => string;
  readonly revokeObjectUrl?: (url: string) => void;
  readonly sha256?: (value: ArrayBuffer) => Promise<string>;
};

const RUN_ID = /^demo-run-[0-9a-f]{32}$/u;
const INCIDENT_ID = /^incident-demo-[0-9a-f]{32}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const HEX_DIGEST = /^[0-9a-f]{64}$/u;
const COMMIT = /^[0-9a-f]{40}$/u;
const NONCE = /^[A-Za-z0-9_-]{32,256}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TRACE_ID = /^[0-9a-f]{32}$/u;
const REASON_CODE = /^[a-z][a-z0-9-]{1,63}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PHASES = new Set<DemoPhase>([
  "preparing",
  "awaiting-approval",
  "executing",
  "awaiting-closure",
  "closing",
  "closed",
  "unresolved",
  "expired",
]);
const TERMINAL_PHASES = new Set<DemoPhase>(["closed", "unresolved", "expired"]);
const VISUAL_KINDS = new Set<DemoVisualKind>(["expected", "observed", "recovered", "diff"]);
const PREVIEW_VISUAL_KINDS = new Set<DemoPreviewVisualKind>(["expected", "observed", "diff"]);
const REJECTION_REASONS = new Set<DemoRejectionReason>(DEMO_REJECTION_REASONS);
const INVESTIGATION_TOOLS = {
  "alert.rule": "alerting_manage_rules",
  "log.correlated-events": "query_loki_logs",
  "metric.correlated-observations": "query_prometheus",
  "trace.by-id": "tempo_get-trace",
} as const;
const MCP_SOURCE_IDENTITY = {
  kind: "grafana-mcp",
  server: "mcp-grafana",
  server_version: "1.1.0",
  server_commit: "007e8d82154899a28e19e8dfe9c2bb4452c5211a",
  binary_sha256: "a3dacdcace8d8082dd7cb245e41be54e8da4a9375969cb39c85c420a30ea0809",
  mcp_sdk_version: "1.29.0",
  mcp_protocol_version: "2025-06-18",
} as const;
const CANONICAL_V3_CLAIMS = {
  "causal-resource": {
    state: "confirmed",
    reasonCode: "causal-resource-confirmed",
  },
  "nominal-config": {
    state: "rejected",
    reasonCode: "nominal-config-authoritatively-rejected",
  },
  "worker-alone": {
    state: "rejected",
    reasonCode: "worker-alone-authoritatively-rejected",
  },
  distractor: {
    state: "rejected",
    reasonCode: "distractor-authoritatively-rejected",
  },
} as const;
const RECOVERY_CHECKS = [
  "active-publication",
  "approved-resource-state",
  "declared-reference-recovery",
  "exact-typed-lineage",
  "approved-recovery-scope",
  "safe-complement-preservation",
  "post-action-telemetry-correlation",
] as const;
const MAX_VISUAL_BYTES = 8 * 1024 * 1024;

function compareUnicodeCodePoints(left: string, right: string): number {
  const leftCodePoints = Array.from(left, (character) => character.codePointAt(0) as number);
  const rightCodePoints = Array.from(right, (character) => character.codePointAt(0) as number);
  const sharedLength = Math.min(leftCodePoints.length, rightCodePoints.length);
  for (let index = 0; index < sharedLength; index += 1) {
    const difference = (leftCodePoints[index] as number) - (rightCodePoints[index] as number);
    if (difference !== 0) return difference;
  }
  return leftCodePoints.length - rightCodePoints.length;
}

function requireUnicodeScalarString(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new TypeError("canonical JSON strings must contain Unicode scalar values");
      }
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      throw new TypeError("canonical JSON strings must contain Unicode scalar values");
    }
  }
  return value;
}

function canonicalJsonText(value: unknown): string {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(requireUnicodeScalarString(value));
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("canonical JSON numbers must be safe integers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJsonText(item)).join(",")}]`;
  }
  if (isRecord(value)) {
    const entries = Object.keys(value)
      .sort(compareUnicodeCodePoints)
      .map(
        (key) =>
          `${JSON.stringify(requireUnicodeScalarString(key))}:${canonicalJsonText(value[key])}`,
      );
    return `{${entries.join(",")}}`;
  }
  throw new TypeError("value is not canonical JSON");
}

export function canonicalJsonBytes(value: unknown): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(canonicalJsonText(value));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function recordWithKeys(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!isRecord(value) || !hasExactKeys(value, keys)) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return value;
}

function stringField(value: Record<string, unknown>, key: string): string {
  const selected = value[key];
  if (typeof selected !== "string") throw new DemoApiError(null, "demo-response-invalid");
  return selected;
}

function nullableStringField(value: Record<string, unknown>, key: string): string | null {
  const selected = value[key];
  if (selected !== null && typeof selected !== "string") {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return selected;
}

function integerField(value: Record<string, unknown>, key: string): number {
  const selected = value[key];
  if (!Number.isSafeInteger(selected) || (selected as number) < 1) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return selected as number;
}

function boundedIntegerField(value: Record<string, unknown>, key: string, maximum: number): number {
  const selected = value[key];
  if (
    !Number.isSafeInteger(selected) ||
    (selected as number) < 0 ||
    (selected as number) > maximum
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return selected as number;
}

function nullableIntegerField(value: Record<string, unknown>, key: string): number | null {
  if (value[key] === null) return null;
  return integerField(value, key);
}

function nullableBoundedIntegerField(
  value: Record<string, unknown>,
  key: string,
  maximum: number,
): number | null {
  if (value[key] === null) return null;
  return boundedIntegerField(value, key, maximum);
}

function booleanField(value: Record<string, unknown>, key: string): boolean {
  const selected = value[key];
  if (typeof selected !== "boolean") throw new DemoApiError(null, "demo-response-invalid");
  return selected;
}

function requirePattern(value: string, pattern: RegExp): string {
  if (!pattern.test(value)) throw new DemoApiError(null, "demo-response-invalid");
  return value;
}

function boundedPlainText(value: unknown): string {
  if (typeof value !== "string") throw new DemoApiError(null, "demo-response-invalid");
  const characters = Array.from(value);
  if (
    characters.length < 1 ||
    characters.length > 1_024 ||
    new TextEncoder().encode(value).length > 4_096
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const forbidden = /[\p{Cc}\p{Cf}\p{Cs}\p{Co}]/u;
  if (
    characters.some(
      (character) => character !== "\n" && character !== "\t" && forbidden.test(character),
    )
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return value;
}

function digestField(value: Record<string, unknown>, key: string): string {
  return requirePattern(stringField(value, key), DIGEST);
}

function nullableDigestField(value: Record<string, unknown>, key: string): string | null {
  const selected = nullableStringField(value, key);
  return selected === null ? null : requirePattern(selected, DIGEST);
}

function timestampValue(value: unknown): string {
  if (typeof value !== "string" || !TIMESTAMP.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return value;
}

function nullableTimestampField(value: Record<string, unknown>, key: string): string | null {
  const selected = value[key];
  return selected === null ? null : timestampValue(selected);
}

function parseComparison(value: unknown): DemoComparison {
  const comparison = recordWithKeys(value, [
    "renders",
    "nominal_config_match",
    "resolved_lut_match",
  ]);
  if (
    !Array.isArray(comparison.renders) ||
    comparison.renders.length !== 2 ||
    comparison.nominal_config_match !== true ||
    comparison.resolved_lut_match !== false
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const renders = comparison.renders.map((value) => {
    const render = recordWithKeys(value, [
      "job_id",
      "worker_id",
      "status",
      "nominal_config_sha256",
      "resolved_lut_sha256",
    ]);
    if (render.status !== "succeeded") {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      job_id: requirePattern(stringField(render, "job_id"), IDENTIFIER),
      worker_id: requirePattern(stringField(render, "worker_id"), IDENTIFIER),
      status: "succeeded" as const,
      nominal_config_sha256: digestField(render, "nominal_config_sha256"),
      resolved_lut_sha256: digestField(render, "resolved_lut_sha256"),
    };
  });
  if (
    renders[0]?.job_id === renders[1]?.job_id ||
    renders[0]?.worker_id === renders[1]?.worker_id ||
    renders[0]?.nominal_config_sha256 !== renders[1]?.nominal_config_sha256 ||
    renders[0]?.resolved_lut_sha256 === renders[1]?.resolved_lut_sha256
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return {
    renders,
    nominal_config_match: true,
    resolved_lut_match: false,
  };
}

function parseApproval(value: unknown): DemoApproval | null {
  if (value === null) return null;
  const selected = recordWithKeys(value, [
    "phrase",
    "incident_version",
    "plan_version",
    "plan_sha256",
    "target_sha256",
  ]);
  const phrase = stringField(selected, "phrase");
  if (phrase !== DEMO_APPROVAL_PHRASE) throw new DemoApiError(null, "demo-response-invalid");
  return {
    phrase,
    incident_version: integerField(selected, "incident_version"),
    plan_version: integerField(selected, "plan_version"),
    plan_sha256: digestField(selected, "plan_sha256"),
    target_sha256: digestField(selected, "target_sha256"),
  };
}

function parseRecovery(value: unknown): DemoRecovery | null {
  if (value === null) return null;
  const selected = recordWithKeys(value, [
    "outcome_id",
    "outcome_sha256",
    "workflow_id",
    "workflow_version",
    "packet_id",
    "packet_sha256",
    "closure_id",
    "closure_sha256",
  ]);
  const closureId = nullableStringField(selected, "closure_id");
  return {
    outcome_id: requirePattern(stringField(selected, "outcome_id"), IDENTIFIER),
    outcome_sha256: digestField(selected, "outcome_sha256"),
    workflow_id: requirePattern(stringField(selected, "workflow_id"), IDENTIFIER),
    workflow_version: integerField(selected, "workflow_version"),
    packet_id: requirePattern(stringField(selected, "packet_id"), IDENTIFIER),
    packet_sha256: digestField(selected, "packet_sha256"),
    closure_id: closureId === null ? null : requirePattern(closureId, IDENTIFIER),
    closure_sha256: nullableDigestField(selected, "closure_sha256"),
  };
}

function parseInvestigationV1(value: unknown): DemoInvestigationProofV1 {
  const proof = recordWithKeys(value, [
    "schema",
    "packet_id",
    "packet_sha256",
    "status",
    "model_invocations",
    "evidence",
    "validators",
    "scope",
    "budget_use",
    "plan",
  ]);
  if (
    proof.schema !== "colortrace-demo-investigation-proof/v1" ||
    (proof.status !== "resolved" && proof.status !== "unresolved") ||
    !Array.isArray(proof.model_invocations) ||
    proof.model_invocations.length > 6 ||
    !Array.isArray(proof.evidence) ||
    proof.evidence.length < 1 ||
    proof.evidence.length > 8 ||
    !Array.isArray(proof.validators) ||
    proof.validators.length < 1 ||
    proof.validators.length > 16
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const modelInvocations = proof.model_invocations.map((value) => {
    const invocation = recordWithKeys(value, [
      "invocation_id",
      "turn_kind",
      "model",
      "framework",
      "result_class",
      "inventory_sha256",
      "output_sha256",
      "trace_id",
    ]);
    const turnKind = invocation.turn_kind;
    const resultClass = invocation.result_class;
    if (
      (turnKind !== "evidence-selection" && turnKind !== "response-drafting") ||
      (resultClass !== "accepted" &&
        resultClass !== "budget-rejected" &&
        resultClass !== "failed" &&
        resultClass !== "invalid")
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      invocation_id: requirePattern(stringField(invocation, "invocation_id"), IDENTIFIER),
      turn_kind: turnKind as "evidence-selection" | "response-drafting",
      model: requirePattern(stringField(invocation, "model"), IDENTIFIER),
      framework: requirePattern(stringField(invocation, "framework"), IDENTIFIER),
      result_class: resultClass as "accepted" | "budget-rejected" | "failed" | "invalid",
      inventory_sha256: nullableDigestField(invocation, "inventory_sha256"),
      output_sha256: nullableDigestField(invocation, "output_sha256"),
      trace_id: requirePattern(stringField(invocation, "trace_id"), TRACE_ID),
    };
  });
  const queryKeys = new Set<string>();
  const evidence = proof.evidence.map((value) => {
    const item = recordWithKeys(value, [
      "evidence_id",
      "query_key",
      "tool",
      "inventory_sha256",
      "content_sha256",
      "freshness",
    ]);
    const queryKey = requirePattern(stringField(item, "query_key"), IDENTIFIER);
    if (
      queryKeys.has(queryKey) ||
      (item.freshness !== "current" &&
        item.freshness !== "stale" &&
        item.freshness !== "unresolved")
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    queryKeys.add(queryKey);
    return {
      evidence_id: digestField(item, "evidence_id"),
      query_key: queryKey,
      tool: requirePattern(stringField(item, "tool"), IDENTIFIER),
      inventory_sha256: digestField(item, "inventory_sha256"),
      content_sha256: digestField(item, "content_sha256"),
      freshness: item.freshness as "current" | "stale" | "unresolved",
    };
  });
  const validators = proof.validators.map((value) => {
    const validator = recordWithKeys(value, [
      "result_id",
      "validator",
      "validator_version",
      "status",
      "derivation_sha256",
    ]);
    if (validator.status !== "resolved" && validator.status !== "unresolved") {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      result_id: requirePattern(stringField(validator, "result_id"), IDENTIFIER),
      validator: requirePattern(stringField(validator, "validator"), IDENTIFIER),
      validator_version: requirePattern(stringField(validator, "validator_version"), IDENTIFIER),
      status: validator.status as "resolved" | "unresolved",
      derivation_sha256: digestField(validator, "derivation_sha256"),
    };
  });
  const scope = recordWithKeys(proof.scope, [
    "state",
    "affected_count",
    "safe_count",
    "unknown_count",
  ]);
  if (scope.state !== "resolved" && scope.state !== "unresolved") {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const budget = recordWithKeys(proof.budget_use, [
    "elapsed_ms",
    "model_turns",
    "input_tokens",
    "output_tokens",
    "mcp_attempts",
    "validator_calls",
  ]);
  const plan = recordWithKeys(proof.plan, ["status", "version", "plan_sha256", "target_sha256"]);
  if (
    plan.status !== "pending" &&
    plan.status !== "approved" &&
    plan.status !== "rejected" &&
    plan.status !== "stale"
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return {
    schema: "colortrace-demo-investigation-proof/v1",
    packet_id: requirePattern(stringField(proof, "packet_id"), IDENTIFIER),
    packet_sha256: digestField(proof, "packet_sha256"),
    status: proof.status,
    model_invocations: modelInvocations,
    evidence,
    validators,
    scope: {
      state: scope.state,
      affected_count: boundedIntegerField(scope, "affected_count", 256),
      safe_count: boundedIntegerField(scope, "safe_count", 256),
      unknown_count: boundedIntegerField(scope, "unknown_count", 256),
    },
    budget_use: {
      elapsed_ms: boundedIntegerField(budget, "elapsed_ms", 10_000_000),
      model_turns: boundedIntegerField(budget, "model_turns", 10_000_000),
      input_tokens: boundedIntegerField(budget, "input_tokens", 10_000_000),
      output_tokens: boundedIntegerField(budget, "output_tokens", 10_000_000),
      mcp_attempts: boundedIntegerField(budget, "mcp_attempts", 10_000_000),
      validator_calls: boundedIntegerField(budget, "validator_calls", 10_000_000),
    },
    plan: {
      status: plan.status,
      version: integerField(plan, "version"),
      plan_sha256: digestField(plan, "plan_sha256"),
      target_sha256: digestField(plan, "target_sha256"),
    },
  };
}

function parseInvestigationV2(value: unknown): DemoInvestigationProofV2 {
  const proof = recordWithKeys(value, [
    "schema",
    "packet_id",
    "packet_sha256",
    "status",
    "adjudication",
    "model_invocations",
    "comparison",
    "claims",
    "evidence",
    "validators",
    "scope",
    "budget_use",
    "plan",
  ]);
  if (
    proof.schema !== "colortrace-demo-investigation-proof/v2" ||
    proof.status !== "resolved" ||
    !Array.isArray(proof.model_invocations) ||
    proof.model_invocations.length > 6 ||
    !Array.isArray(proof.claims) ||
    proof.claims.length < 1 ||
    proof.claims.length > 16 ||
    !Array.isArray(proof.evidence) ||
    proof.evidence.length < 1 ||
    proof.evidence.length > 8 ||
    !Array.isArray(proof.validators) ||
    proof.validators.length < 1 ||
    proof.validators.length > 16
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const adjudication = recordWithKeys(proof.adjudication, [
    "model_role",
    "model_authority",
    "validator_role",
    "decision_mode",
  ]);
  if (
    adjudication.model_role !== "evidence-selection-and-advisory-drafting" ||
    adjudication.model_authority !== "advisory-only" ||
    adjudication.validator_role !== "deterministic-claim-adjudication" ||
    adjudication.decision_mode !== "deterministic-validation"
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const modelInvocations = proof.model_invocations.map((value) => {
    const invocation = recordWithKeys(value, [
      "invocation_id",
      "turn_kind",
      "model",
      "framework",
      "result_class",
      "inventory_sha256",
      "output_sha256",
      "trace_id",
    ]);
    const turnKind = invocation.turn_kind;
    const resultClass = invocation.result_class;
    if (
      (turnKind !== "evidence-selection" && turnKind !== "response-drafting") ||
      (resultClass !== "accepted" &&
        resultClass !== "budget-rejected" &&
        resultClass !== "failed" &&
        resultClass !== "invalid")
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      invocation_id: requirePattern(stringField(invocation, "invocation_id"), IDENTIFIER),
      turn_kind: turnKind,
      model: requirePattern(stringField(invocation, "model"), IDENTIFIER),
      framework: requirePattern(stringField(invocation, "framework"), IDENTIFIER),
      result_class: resultClass,
      inventory_sha256: nullableDigestField(invocation, "inventory_sha256"),
      output_sha256: nullableDigestField(invocation, "output_sha256"),
      trace_id: requirePattern(stringField(invocation, "trace_id"), TRACE_ID),
    } as DemoInvestigationProofV2["model_invocations"][number];
  });

  const comparison = parseComparison(proof.comparison);
  const renders = comparison.renders;

  const claimIds = new Set<string>();
  const claims = proof.claims.map((value) => {
    const claim = recordWithKeys(value, [
      "claim_id",
      "claim_type",
      "subject",
      "state",
      "reason_codes",
      "evidence_ids",
      "source_validator_result_id",
    ]);
    const claimId = requirePattern(stringField(claim, "claim_id"), IDENTIFIER);
    const claimType = requirePattern(stringField(claim, "claim_type"), REASON_CODE);
    const subject = recordWithKeys(claim.subject, ["kind", "value"]);
    if (
      claimIds.has(claimId) ||
      (claim.state !== "confirmed" && claim.state !== "rejected") ||
      !Array.isArray(claim.reason_codes) ||
      claim.reason_codes.length < 1 ||
      claim.reason_codes.length > 16 ||
      !Array.isArray(claim.evidence_ids) ||
      claim.evidence_ids.length < 1 ||
      claim.evidence_ids.length > 64
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    const reasonCodes = claim.reason_codes.map((reason) =>
      requirePattern(typeof reason === "string" ? reason : "", REASON_CODE),
    );
    const evidenceIds = claim.evidence_ids.map((identifier) =>
      requirePattern(typeof identifier === "string" ? identifier : "", IDENTIFIER),
    );
    if (
      new Set(reasonCodes).size !== reasonCodes.length ||
      new Set(evidenceIds).size !== evidenceIds.length
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    claimIds.add(claimId);
    return {
      claim_id: claimId,
      claim_type: claimType,
      subject: {
        kind: requirePattern(stringField(subject, "kind"), REASON_CODE),
        value: requirePattern(stringField(subject, "value"), IDENTIFIER),
      },
      state: claim.state,
      reason_codes: reasonCodes,
      evidence_ids: evidenceIds,
      source_validator_result_id: requirePattern(
        stringField(claim, "source_validator_result_id"),
        IDENTIFIER,
      ),
    } as DemoInvestigationProofV2["claims"][number];
  });
  if (new Set(claims.map((claim) => claim.state)).size !== 2) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const evidenceIds = new Set<string>();
  const queryKeys = new Set<string>();
  const evidence = proof.evidence.map((value) => {
    const item = recordWithKeys(value, [
      "evidence_id",
      "query_key",
      "tool",
      "inventory_sha256",
      "content_sha256",
      "freshness",
      "display_excerpt",
      "display_excerpt_truncated",
    ]);
    const evidenceId = requirePattern(stringField(item, "evidence_id"), IDENTIFIER);
    const queryKey = requirePattern(stringField(item, "query_key"), IDENTIFIER);
    const excerpt = boundedPlainText(item.display_excerpt);
    if (evidenceIds.has(evidenceId) || queryKeys.has(queryKey) || item.freshness !== "current") {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    evidenceIds.add(evidenceId);
    queryKeys.add(queryKey);
    return {
      evidence_id: evidenceId,
      query_key: queryKey,
      tool: requirePattern(stringField(item, "tool"), IDENTIFIER),
      inventory_sha256: digestField(item, "inventory_sha256"),
      content_sha256: digestField(item, "content_sha256"),
      freshness: "current" as const,
      display_excerpt: excerpt,
      display_excerpt_truncated: booleanField(item, "display_excerpt_truncated"),
    };
  });

  const validatorIds = new Set<string>();
  const validators = proof.validators.map((value) => {
    const validator = recordWithKeys(value, [
      "result_id",
      "validator",
      "validator_version",
      "status",
      "derivation_sha256",
    ]);
    const resultId = requirePattern(stringField(validator, "result_id"), IDENTIFIER);
    const derivationSha256 = digestField(validator, "derivation_sha256");
    if (
      validatorIds.has(resultId) ||
      validator.status !== "resolved" ||
      resultId !== `validation-result:${derivationSha256.slice("sha256:".length)}`
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    validatorIds.add(resultId);
    return {
      result_id: resultId,
      validator: requirePattern(stringField(validator, "validator"), IDENTIFIER),
      validator_version: requirePattern(stringField(validator, "validator_version"), IDENTIFIER),
      status: "resolved" as const,
      derivation_sha256: derivationSha256,
    };
  });
  if (claims.some((claim) => !validatorIds.has(claim.source_validator_result_id))) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const scope = recordWithKeys(proof.scope, [
    "state",
    "affected_count",
    "safe_count",
    "unknown_count",
  ]);
  if (scope.state !== "resolved") throw new DemoApiError(null, "demo-response-invalid");
  const budget = recordWithKeys(proof.budget_use, [
    "elapsed_ms",
    "model_turns",
    "input_tokens",
    "output_tokens",
    "mcp_attempts",
    "validator_calls",
  ]);
  const plan = recordWithKeys(proof.plan, [
    "status",
    "version",
    "plan_sha256",
    "target_sha256",
    "exclusions_sha256",
    "commands_sha256",
    "targets",
    "protected_exclusions",
    "shared_action_bindings",
    "command_summaries",
  ]);
  if (
    (plan.status !== "pending" &&
      plan.status !== "approved" &&
      plan.status !== "rejected" &&
      plan.status !== "stale") ||
    !Array.isArray(plan.targets) ||
    plan.targets.length < 1 ||
    plan.targets.length > 8 ||
    !Array.isArray(plan.protected_exclusions) ||
    plan.protected_exclusions.length > 8 ||
    !Array.isArray(plan.command_summaries) ||
    plan.command_summaries.length !== 5
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const parseTarget = (value: unknown): DemoPlanTarget => {
    const target = recordWithKeys(value, ["schema", "namespace", "kind", "id"]);
    if (
      target.schema !== "simulator-target/v1" ||
      target.namespace !== "colortrace-simulator" ||
      (target.kind !== "color-resource" && target.kind !== "frame" && target.kind !== "derivative")
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      schema: "simulator-target/v1",
      namespace: "colortrace-simulator",
      kind: target.kind,
      id: requirePattern(stringField(target, "id"), IDENTIFIER),
    };
  };
  const targetKey = (target: DemoPlanTarget): string => `${target.kind}:${target.id}`;
  const targets = plan.targets.map(parseTarget);
  const protectedExclusions = plan.protected_exclusions.map(parseTarget);
  const targetKeys = new Set(targets.map(targetKey));
  const protectedKeys = new Set(protectedExclusions.map(targetKey));
  if (
    targets.length !== 5 ||
    protectedExclusions.length !== 3 ||
    targets.filter((target) => target.kind === "color-resource").length !== 1 ||
    targets.filter((target) => target.kind === "frame").length !== 3 ||
    targets.filter((target) => target.kind === "derivative").length !== 1 ||
    protectedExclusions.some((target) => target.kind !== "frame") ||
    targetKeys.size !== targets.length ||
    protectedKeys.size !== protectedExclusions.length ||
    protectedExclusions.some((target) => targetKeys.has(targetKey(target)))
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const commandIds = new Set<string>();
  const commandSummaries = plan.command_summaries.map((value) => {
    if (!isRecord(value)) throw new DemoApiError(null, "demo-response-invalid");
    const schema = value.schema;
    if (schema === "simulator-quarantine-command/v1") {
      const command = recordWithKeys(value, [
        "schema",
        "command_id",
        "namespace",
        "target",
        "expected_resource_sha256",
        "mode",
      ]);
      const target = parseTarget(command.target);
      const commandId = requirePattern(stringField(command, "command_id"), IDENTIFIER);
      if (
        commandIds.has(commandId) ||
        command.namespace !== "colortrace-simulator" ||
        command.mode !== "quarantine-and-install-approved-replacement" ||
        target.kind !== "color-resource" ||
        !targetKeys.has(targetKey(target))
      ) {
        throw new DemoApiError(null, "demo-response-invalid");
      }
      commandIds.add(commandId);
      return {
        schema: "simulator-quarantine-command/v1" as const,
        command_id: commandId,
        namespace: "colortrace-simulator" as const,
        target,
        expected_resource_sha256: digestField(command, "expected_resource_sha256"),
        mode: "quarantine-and-install-approved-replacement" as const,
      };
    }
    if (schema === "simulator-targeted-rerender-command/v1") {
      const preliminaryTarget = parseTarget(value.target);
      const sharedKeys = [
        "schema",
        "command_id",
        "namespace",
        "target",
        "job_id",
        "transform_id",
        "source_id",
        "source_manifest_sha256",
        "source_png_sha256",
        "expected_config_sha256",
        "lineage_parent_artifact_id",
      ];
      const command = recordWithKeys(
        value,
        preliminaryTarget.kind === "frame"
          ? [...sharedKeys, "expected_output_sha256", "expected_display_sha256"]
          : preliminaryTarget.kind === "derivative"
            ? [...sharedKeys, "expected_derivative_sha256", "expected_derivative_display_sha256"]
            : [],
      );
      const target = parseTarget(command.target);
      const commandId = requirePattern(stringField(command, "command_id"), IDENTIFIER);
      const transformId = stringField(command, "transform_id");
      if (
        commandIds.has(commandId) ||
        command.namespace !== "colortrace-simulator" ||
        (transformId !== "look/main/v1" && transformId !== "identity/v1") ||
        target.kind === "color-resource" ||
        !targetKeys.has(targetKey(target))
      ) {
        throw new DemoApiError(null, "demo-response-invalid");
      }
      commandIds.add(commandId);
      const shared = {
        schema: "simulator-targeted-rerender-command/v1" as const,
        command_id: commandId,
        namespace: "colortrace-simulator" as const,
        target,
        job_id: requirePattern(stringField(command, "job_id"), IDENTIFIER),
        source_id: requirePattern(stringField(command, "source_id"), IDENTIFIER),
        transform_id: transformId as "look/main/v1" | "identity/v1",
        source_manifest_sha256: digestField(command, "source_manifest_sha256"),
        source_png_sha256: digestField(command, "source_png_sha256"),
        expected_config_sha256: digestField(command, "expected_config_sha256"),
        lineage_parent_artifact_id: requirePattern(
          stringField(command, "lineage_parent_artifact_id"),
          IDENTIFIER,
        ),
      };
      return target.kind === "frame"
        ? {
            ...shared,
            expected_output_sha256: digestField(command, "expected_output_sha256"),
            expected_display_sha256: digestField(command, "expected_display_sha256"),
          }
        : {
            ...shared,
            expected_derivative_sha256: digestField(command, "expected_derivative_sha256"),
            expected_derivative_display_sha256: digestField(
              command,
              "expected_derivative_display_sha256",
            ),
          };
    }
    throw new DemoApiError(null, "demo-response-invalid");
  });
  if (
    commandSummaries.filter((command) => command.schema === "simulator-quarantine-command/v1")
      .length !== 1
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const bindings = recordWithKeys(plan.shared_action_bindings, [
    "schema",
    "fixture_id",
    "fixture_manifest_sha256",
    "fixture_generation",
    "source_batch_id",
    "source_batch_sha256",
    "runtime_manifest_sha256",
    "runtime_generation",
    "expected_publication_pointer_sha256",
    "expected_publication_generation",
    "expected_resource_sha256",
    "replacement_resource_logical_path",
    "replacement_resource_sha256",
    "declared_resource_manifest_sha256",
    "ocio_version",
    "preservation_manifest_sha256",
    "safe_complement_sha256",
    "lineage_manifest_sha256",
    "lineage_generation",
  ]);
  if (
    bindings.schema !== "simulator-action-envelope/v1" ||
    bindings.replacement_resource_logical_path !== "luts/show_look.cube" ||
    bindings.ocio_version !== "2.5.2"
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const sharedActionBindings: DemoActionEnvelope = {
    schema: "simulator-action-envelope/v1",
    fixture_id: requirePattern(stringField(bindings, "fixture_id"), IDENTIFIER),
    fixture_manifest_sha256: digestField(bindings, "fixture_manifest_sha256"),
    fixture_generation: integerField(bindings, "fixture_generation"),
    source_batch_id: requirePattern(stringField(bindings, "source_batch_id"), IDENTIFIER),
    source_batch_sha256: digestField(bindings, "source_batch_sha256"),
    runtime_manifest_sha256: digestField(bindings, "runtime_manifest_sha256"),
    runtime_generation: integerField(bindings, "runtime_generation"),
    expected_publication_pointer_sha256: digestField(
      bindings,
      "expected_publication_pointer_sha256",
    ),
    expected_publication_generation: integerField(bindings, "expected_publication_generation"),
    expected_resource_sha256: digestField(bindings, "expected_resource_sha256"),
    replacement_resource_logical_path: "luts/show_look.cube",
    replacement_resource_sha256: digestField(bindings, "replacement_resource_sha256"),
    declared_resource_manifest_sha256: digestField(bindings, "declared_resource_manifest_sha256"),
    ocio_version: "2.5.2",
    preservation_manifest_sha256: digestField(bindings, "preservation_manifest_sha256"),
    safe_complement_sha256: digestField(bindings, "safe_complement_sha256"),
    lineage_manifest_sha256: digestField(bindings, "lineage_manifest_sha256"),
    lineage_generation: integerField(bindings, "lineage_generation"),
  };
  const expectedResource = sharedActionBindings.expected_resource_sha256;
  const replacementResource = sharedActionBindings.replacement_resource_sha256;
  const commandTargetKeys = new Set(commandSummaries.map((command) => targetKey(command.target)));
  const generations = new Set([
    sharedActionBindings.fixture_generation,
    sharedActionBindings.runtime_generation,
    sharedActionBindings.expected_publication_generation,
    sharedActionBindings.lineage_generation,
  ]);
  if (
    expectedResource === replacementResource ||
    generations.size !== 1 ||
    targets.find((target) => target.kind === "color-resource")?.id !== expectedResource ||
    commandTargetKeys.size !== targetKeys.size ||
    [...commandTargetKeys].some((key) => !targetKeys.has(key)) ||
    commandSummaries.some((command) =>
      command.schema === "simulator-quarantine-command/v1"
        ? command.expected_resource_sha256 !== expectedResource
        : command.expected_config_sha256 !== renders[0]?.nominal_config_sha256,
    )
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const packetId = requirePattern(stringField(proof, "packet_id"), IDENTIFIER);
  const packetSha256 = digestField(proof, "packet_sha256");
  if (packetId !== `response-packet:${packetSha256.slice("sha256:".length)}`) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  return {
    schema: "colortrace-demo-investigation-proof/v2",
    packet_id: packetId,
    packet_sha256: packetSha256,
    status: "resolved",
    adjudication: {
      model_role: "evidence-selection-and-advisory-drafting",
      model_authority: "advisory-only",
      validator_role: "deterministic-claim-adjudication",
      decision_mode: "deterministic-validation",
    },
    model_invocations: modelInvocations,
    comparison: {
      renders,
      nominal_config_match: true,
      resolved_lut_match: false,
    },
    claims,
    evidence,
    validators,
    scope: {
      state: "resolved",
      affected_count: boundedIntegerField(scope, "affected_count", 256),
      safe_count: boundedIntegerField(scope, "safe_count", 256),
      unknown_count: boundedIntegerField(scope, "unknown_count", 256),
    },
    budget_use: {
      elapsed_ms: boundedIntegerField(budget, "elapsed_ms", 10_000_000),
      model_turns: boundedIntegerField(budget, "model_turns", 10_000_000),
      input_tokens: boundedIntegerField(budget, "input_tokens", 10_000_000),
      output_tokens: boundedIntegerField(budget, "output_tokens", 10_000_000),
      mcp_attempts: boundedIntegerField(budget, "mcp_attempts", 10_000_000),
      validator_calls: boundedIntegerField(budget, "validator_calls", 10_000_000),
    },
    plan: {
      status: plan.status,
      version: integerField(plan, "version"),
      plan_sha256: digestField(plan, "plan_sha256"),
      target_sha256: digestField(plan, "target_sha256"),
      exclusions_sha256: digestField(plan, "exclusions_sha256"),
      commands_sha256: digestField(plan, "commands_sha256"),
      targets,
      protected_exclusions: protectedExclusions,
      shared_action_bindings: sharedActionBindings,
      command_summaries: commandSummaries,
    },
  };
}

function parseInvestigationV3(value: unknown): DemoInvestigationProofV3 {
  const proof = recordWithKeys(value, [
    "schema",
    "packet_id",
    "packet_sha256",
    "status",
    "adjudication",
    "model_invocations",
    "comparison",
    "claims",
    "evidence",
    "validators",
    "scope",
    "budget_use",
    "plan",
    "model_advisory",
    "finalized_at",
  ]);
  if (
    proof.schema !== "colortrace-demo-investigation-proof/v3" ||
    !Array.isArray(proof.model_invocations) ||
    proof.model_invocations.length < 2 ||
    proof.model_invocations.length > 6 ||
    !Array.isArray(proof.evidence)
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const invocationIds = new Set<string>();
  const invocationAttempts = new Set<string>();
  const modelInvocations = proof.model_invocations.map((value) => {
    const invocation = recordWithKeys(value, [
      "invocation_id",
      "turn_kind",
      "attempt",
      "model",
      "location",
      "framework",
      "framework_version",
      "client_version",
      "prompt_version",
      "policy_version",
      "inventory_sha256",
      "normalized_input_sha256",
      "input_evidence_ids",
      "output_sha256",
      "latency_ms",
      "usage",
      "result_class",
      "error_code",
      "trace_id",
      "derivation_sha256",
    ]);
    const turnKind = invocation.turn_kind;
    const resultClass = invocation.result_class;
    if (
      (turnKind !== "evidence-selection" && turnKind !== "response-drafting") ||
      (resultClass !== "accepted" &&
        resultClass !== "budget-rejected" &&
        resultClass !== "failed" &&
        resultClass !== "invalid") ||
      !Array.isArray(invocation.input_evidence_ids) ||
      invocation.input_evidence_ids.length > 256
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    const inputEvidenceIds = invocation.input_evidence_ids.map((identifier) =>
      requirePattern(typeof identifier === "string" ? identifier : "", IDENTIFIER),
    );
    if (new Set(inputEvidenceIds).size !== inputEvidenceIds.length) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    const usage = recordWithKeys(invocation.usage, [
      "input_tokens",
      "output_tokens",
      "model_calls",
      "unobserved_model_calls",
    ]);
    const errorCode = nullableStringField(invocation, "error_code");
    const invocationId = requirePattern(stringField(invocation, "invocation_id"), IDENTIFIER);
    const derivationSha256 = digestField(invocation, "derivation_sha256");
    const attempt = integerField(invocation, "attempt");
    const attemptKey = `${turnKind}:${attempt}`;
    const promptVersion = stringField(invocation, "prompt_version");
    const modelCalls = boundedIntegerField(usage, "model_calls", 6);
    const unobservedModelCalls = boundedIntegerField(usage, "unobserved_model_calls", 6);
    const inputTokens = nullableBoundedIntegerField(usage, "input_tokens", 10_000_000);
    const outputTokens = nullableBoundedIntegerField(usage, "output_tokens", 10_000_000);
    if (
      invocationIds.has(invocationId) ||
      invocationAttempts.has(attemptKey) ||
      invocationId !== `model-invocation:${derivationSha256.slice("sha256:".length)}` ||
      attempt > 6 ||
      invocation.model !== "gemini-3.5-flash" ||
      invocation.location !== "global" ||
      invocation.framework !== "google-adk" ||
      invocation.framework_version !== "2.6.3" ||
      invocation.client_version !== "2.17.0" ||
      promptVersion !==
        (turnKind === "evidence-selection" ? "evidence-selection/v1" : "response-drafting/v1") ||
      invocation.policy_version !== "bounded-investigation/v1" ||
      (resultClass === "accepted" && errorCode !== null) ||
      (errorCode !== null && !/^[a-z][a-z0-9_]{1,63}$/u.test(errorCode)) ||
      modelCalls < 1 ||
      unobservedModelCalls > modelCalls ||
      (resultClass === "accepted" &&
        (invocation.output_sha256 === null ||
          inputTokens === null ||
          outputTokens === null ||
          unobservedModelCalls !== 0))
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    invocationIds.add(invocationId);
    invocationAttempts.add(attemptKey);
    return {
      invocation_id: invocationId,
      turn_kind: turnKind,
      attempt,
      model: "gemini-3.5-flash",
      location: "global",
      framework: "google-adk",
      framework_version: "2.6.3",
      client_version: "2.17.0",
      prompt_version: promptVersion,
      policy_version: "bounded-investigation/v1",
      inventory_sha256: nullableDigestField(invocation, "inventory_sha256"),
      normalized_input_sha256: digestField(invocation, "normalized_input_sha256"),
      input_evidence_ids: inputEvidenceIds,
      output_sha256: nullableDigestField(invocation, "output_sha256"),
      latency_ms: boundedIntegerField(invocation, "latency_ms", 120_000),
      usage: {
        input_tokens: inputTokens,
        output_tokens: outputTokens,
        model_calls: modelCalls,
        unobserved_model_calls: unobservedModelCalls,
      },
      result_class: resultClass,
      error_code: errorCode,
      trace_id: requirePattern(stringField(invocation, "trace_id"), TRACE_ID),
      derivation_sha256: derivationSha256,
    } as DemoInvestigationProofV3["model_invocations"][number];
  });

  const evidence = proof.evidence.map((value) => {
    const item = recordWithKeys(value, [
      "evidence_id",
      "query_key",
      "tool",
      "inventory_sha256",
      "content_sha256",
      "freshness",
      "display_excerpt",
      "display_excerpt_truncated",
      "source",
      "timing",
    ]);
    const source = recordWithKeys(item.source, [
      "kind",
      "server",
      "server_version",
      "server_commit",
      "binary_sha256",
      "mcp_sdk_version",
      "mcp_protocol_version",
      "tool",
      "tool_input_schema_sha256",
      "tool_annotations_sha256",
      "inventory_version",
    ]);
    const timing = recordWithKeys(item.timing, ["source_time", "event_time", "retrieved_at"]);
    const queryKey = requirePattern(stringField(item, "query_key"), IDENTIFIER);
    const tool = requirePattern(stringField(item, "tool"), IDENTIFIER);
    const inventorySha256 = digestField(item, "inventory_sha256");
    if (
      item.freshness !== "current" ||
      Object.entries(MCP_SOURCE_IDENTITY).some(([key, expected]) => source[key] !== expected) ||
      !Object.hasOwn(INVESTIGATION_TOOLS, queryKey) ||
      INVESTIGATION_TOOLS[queryKey as keyof typeof INVESTIGATION_TOOLS] !== tool ||
      source.tool !== tool ||
      source.inventory_version !== inventorySha256
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      evidence_id: digestField(item, "evidence_id"),
      query_key: queryKey,
      tool,
      inventory_sha256: inventorySha256,
      content_sha256: digestField(item, "content_sha256"),
      freshness: "current" as const,
      display_excerpt: boundedPlainText(item.display_excerpt),
      display_excerpt_truncated: booleanField(item, "display_excerpt_truncated"),
      source: {
        ...MCP_SOURCE_IDENTITY,
        tool,
        tool_input_schema_sha256: requirePattern(
          stringField(source, "tool_input_schema_sha256"),
          HEX_DIGEST,
        ),
        tool_annotations_sha256: requirePattern(
          stringField(source, "tool_annotations_sha256"),
          HEX_DIGEST,
        ),
        inventory_version: requirePattern(stringField(source, "inventory_version"), DIGEST),
      },
      timing: {
        source_time: nullableTimestampField(timing, "source_time"),
        event_time: nullableTimestampField(timing, "event_time"),
        retrieved_at: timestampValue(timing.retrieved_at),
      },
    };
  });

  const base = parseInvestigationV2({
    schema: "colortrace-demo-investigation-proof/v2",
    packet_id: proof.packet_id,
    packet_sha256: proof.packet_sha256,
    status: proof.status,
    adjudication: proof.adjudication,
    model_invocations: modelInvocations.map((invocation) => ({
      invocation_id: invocation.invocation_id,
      turn_kind: invocation.turn_kind,
      model: invocation.model,
      framework: invocation.framework,
      result_class: invocation.result_class,
      inventory_sha256: invocation.inventory_sha256,
      output_sha256: invocation.output_sha256,
      trace_id: invocation.trace_id,
    })),
    comparison: proof.comparison,
    claims: proof.claims,
    evidence: evidence.map((item) => ({
      evidence_id: item.evidence_id,
      query_key: item.query_key,
      tool: item.tool,
      inventory_sha256: item.inventory_sha256,
      content_sha256: item.content_sha256,
      freshness: item.freshness,
      display_excerpt: item.display_excerpt,
      display_excerpt_truncated: item.display_excerpt_truncated,
    })),
    validators: proof.validators,
    scope: proof.scope,
    budget_use: proof.budget_use,
    plan: proof.plan,
  });

  const canonicalClaimEntries = Object.entries(CANONICAL_V3_CLAIMS);
  const canonicalValidatorIds = new Set<string>();
  if (base.claims.length !== canonicalClaimEntries.length) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  for (const [claimType, requirement] of canonicalClaimEntries) {
    const matching = base.claims.filter((claim) => claim.claim_type === claimType);
    const claim = matching[0];
    if (
      matching.length !== 1 ||
      claim === undefined ||
      claim.state !== requirement.state ||
      claim.reason_codes.length !== 1 ||
      claim.reason_codes[0] !== requirement.reasonCode
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    canonicalValidatorIds.add(claim.source_validator_result_id);
  }
  if (canonicalValidatorIds.size !== 1) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  const evidenceIds = new Set(evidence.map((item) => item.evidence_id));
  const acceptedInvocations = modelInvocations.filter(
    (invocation) => invocation.result_class === "accepted",
  );
  const acceptedTurns = new Set(acceptedInvocations.map((invocation) => invocation.turn_kind));
  if (
    modelInvocations.some((invocation) =>
      invocation.input_evidence_ids.some((evidenceId) => !evidenceIds.has(evidenceId)),
    ) ||
    acceptedInvocations.length !== 2 ||
    acceptedTurns.size !== 2 ||
    modelInvocations.reduce((sum, invocation) => sum + invocation.usage.model_calls, 0) !==
      base.budget_use.model_turns ||
    modelInvocations.reduce((sum, invocation) => sum + (invocation.usage.input_tokens ?? 0), 0) !==
      base.budget_use.input_tokens ||
    modelInvocations.reduce((sum, invocation) => sum + (invocation.usage.output_tokens ?? 0), 0) !==
      base.budget_use.output_tokens
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const advisory = recordWithKeys(proof.model_advisory, [
    "trust",
    "summary",
    "evidence_ids",
    "output_sha256",
  ]);
  if (advisory.trust !== "untrusted-model-output" || !Array.isArray(advisory.evidence_ids)) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const advisoryEvidenceIds = advisory.evidence_ids.map((identifier) =>
    requirePattern(typeof identifier === "string" ? identifier : "", DIGEST),
  );
  const advisoryOutputSha256 = digestField(advisory, "output_sha256");
  const acceptedDrafts = modelInvocations.filter(
    (invocation) =>
      invocation.turn_kind === "response-drafting" && invocation.result_class === "accepted",
  );
  if (
    advisoryEvidenceIds.length < 1 ||
    advisoryEvidenceIds.length > 32 ||
    new Set(advisoryEvidenceIds).size !== advisoryEvidenceIds.length ||
    advisoryEvidenceIds.some((evidenceId) => !evidenceIds.has(evidenceId)) ||
    !acceptedDrafts.some((invocation) => invocation.output_sha256 === advisoryOutputSha256)
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const finalizedAt = timestampValue(proof.finalized_at);
  if (evidence.some((item) => Date.parse(item.timing.retrieved_at) > Date.parse(finalizedAt))) {
    throw new DemoApiError(null, "demo-response-invalid");
  }

  return {
    ...base,
    schema: "colortrace-demo-investigation-proof/v3",
    model_invocations: modelInvocations,
    evidence,
    model_advisory: {
      trust: "untrusted-model-output",
      summary: boundedPlainText(advisory.summary),
      evidence_ids: advisoryEvidenceIds,
      output_sha256: advisoryOutputSha256,
    },
    finalized_at: finalizedAt,
  };
}

function parseInvestigation(value: unknown): DemoInvestigationProof {
  if (isRecord(value) && value.schema === "colortrace-demo-investigation-proof/v3") {
    return parseInvestigationV3(value);
  }
  if (isRecord(value) && value.schema === "colortrace-demo-investigation-proof/v2") {
    return parseInvestigationV2(value);
  }
  return parseInvestigationV1(value);
}

function parseExecution(value: unknown): DemoExecutionProof {
  const proof = recordWithKeys(value, ["schema", "action", "recovery"]);
  if (proof.schema !== "colortrace-demo-execution-proof/v1") {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const action = recordWithKeys(proof.action, [
    "action_id",
    "status",
    "outcome_id",
    "outcome_sha256",
    "publication_generation_before",
    "publication_generation_after",
    "affected_count",
    "safe_count",
    "safe_complement_before_sha256",
    "safe_complement_after_sha256",
    "safe_complement_proof_sha256",
    "publication_receipt_sha256",
  ]);
  const recovery = recordWithKeys(proof.recovery, [
    "status",
    "workflow_id",
    "workflow_version",
    "packet_id",
    "packet_sha256",
    "evidence_count",
    "evidence_request_sha256",
    "checks",
  ]);
  if (
    action.status !== "succeeded" ||
    (recovery.status !== "recovery_verified" &&
      recovery.status !== "recovery_failed" &&
      recovery.status !== "recovery_unresolved") ||
    !Array.isArray(recovery.checks) ||
    recovery.checks.length < 1 ||
    recovery.checks.length > 7
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const checks = recovery.checks.map((value) => {
    const check = recordWithKeys(value, ["check", "status", "result_sha256"]);
    if (check.status !== "passed" && check.status !== "failed" && check.status !== "unresolved") {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      check: requirePattern(stringField(check, "check"), IDENTIFIER),
      status: check.status as "passed" | "failed" | "unresolved",
      result_sha256: digestField(check, "result_sha256"),
    };
  });
  const selected: DemoExecutionProof = {
    schema: "colortrace-demo-execution-proof/v1",
    action: {
      action_id: requirePattern(stringField(action, "action_id"), IDENTIFIER),
      status: "succeeded",
      outcome_id: requirePattern(stringField(action, "outcome_id"), IDENTIFIER),
      outcome_sha256: digestField(action, "outcome_sha256"),
      publication_generation_before: integerField(action, "publication_generation_before"),
      publication_generation_after: integerField(action, "publication_generation_after"),
      affected_count: boundedIntegerField(action, "affected_count", 256),
      safe_count: boundedIntegerField(action, "safe_count", 256),
      safe_complement_before_sha256: digestField(action, "safe_complement_before_sha256"),
      safe_complement_after_sha256: digestField(action, "safe_complement_after_sha256"),
      safe_complement_proof_sha256: digestField(action, "safe_complement_proof_sha256"),
      publication_receipt_sha256: digestField(action, "publication_receipt_sha256"),
    },
    recovery: {
      status: recovery.status,
      workflow_id: requirePattern(stringField(recovery, "workflow_id"), IDENTIFIER),
      workflow_version: integerField(recovery, "workflow_version"),
      packet_id: requirePattern(stringField(recovery, "packet_id"), IDENTIFIER),
      packet_sha256: digestField(recovery, "packet_sha256"),
      evidence_count: boundedIntegerField(recovery, "evidence_count", 256),
      evidence_request_sha256: digestField(recovery, "evidence_request_sha256"),
      checks,
    },
  };
  if (
    selected.action.publication_generation_after !==
      selected.action.publication_generation_before + 1 ||
    selected.action.affected_count !== 4 ||
    selected.action.safe_count !== 3 ||
    selected.action.safe_complement_before_sha256 !==
      selected.action.safe_complement_after_sha256 ||
    selected.recovery.status !== "recovery_verified" ||
    selected.recovery.evidence_count !== 21 ||
    checks.length !== RECOVERY_CHECKS.length ||
    checks.some(
      (check, index) => check.check !== RECOVERY_CHECKS[index] || check.status !== "passed",
    )
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return selected;
}

function parsePreviewVisualComparison(
  value: unknown,
): Readonly<Record<DemoPreviewVisualKind, DemoVisualDescriptor>> {
  const comparison = recordWithKeys(value, ["expected", "observed", "diff"]);
  const selected = {} as Record<DemoPreviewVisualKind, DemoVisualDescriptor>;
  for (const kind of PREVIEW_VISUAL_KINDS) {
    const descriptor = recordWithKeys(comparison[kind], ["href", "sha256", "media_type", "label"]);
    if (
      descriptor.media_type !== "image/png" ||
      descriptor.label !== "illustrative-authored-fixture" ||
      stringField(descriptor, "href") !== `/v1/demo/visuals/${kind}`
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    selected[kind] = {
      href: `/v1/demo/visuals/${kind}`,
      sha256: digestField(descriptor, "sha256"),
      media_type: "image/png",
      label: "illustrative-authored-fixture",
    };
  }
  return selected;
}

function parsePreview(value: unknown): DemoScenarioPreview {
  const preview = recordWithKeys(value, [
    "schema",
    "scenario_id",
    "source_commit",
    "build_sha256",
    "comparison",
    "visual_comparison",
  ]);
  if (
    preview.schema !== "colortrace-demo-scenario-preview/v1" ||
    stringField(preview, "scenario_id") !== CANONICAL_DEMO_SCENARIO
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return {
    schema: "colortrace-demo-scenario-preview/v1",
    scenario_id: CANONICAL_DEMO_SCENARIO,
    source_commit: requirePattern(stringField(preview, "source_commit"), COMMIT),
    build_sha256: digestField(preview, "build_sha256"),
    comparison: parseComparison(preview.comparison),
    visual_comparison: parsePreviewVisualComparison(preview.visual_comparison),
  };
}

function parseVisualComparison(
  value: unknown,
  runId: string,
): Readonly<Partial<Record<DemoVisualKind, DemoVisualDescriptor>>> {
  if (!isRecord(value)) throw new DemoApiError(null, "demo-response-invalid");
  const selected: Partial<Record<DemoVisualKind, DemoVisualDescriptor>> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (!VISUAL_KINDS.has(key as DemoVisualKind)) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    const descriptor = recordWithKeys(raw, ["href", "sha256", "media_type", "label"]);
    if (
      descriptor.media_type !== "image/png" ||
      descriptor.label !== "illustrative-authored-fixture" ||
      stringField(descriptor, "href") !== `/v1/demo/runs/${runId}/visuals/${key}`
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    selected[key as DemoVisualKind] = {
      href: stringField(descriptor, "href"),
      sha256: digestField(descriptor, "sha256"),
      media_type: "image/png",
      label: "illustrative-authored-fixture",
    };
  }
  return selected;
}

const TIMELINE_KIND_PHASE: Readonly<Record<DemoTimelineKind, DemoPhase>> = {
  "run-created": "preparing",
  "investigation-completed": "awaiting-approval",
  "approval-submitted": "executing",
  "plan-rejected": "unresolved",
  "run-unresolved": "unresolved",
  "run-expired": "expired",
  "recovery-verified": "awaiting-closure",
  "closure-submitted": "closing",
  "recovery-closed": "closed",
};

function parseTimeline(value: unknown, runVersion: number, phase: DemoPhase): DemoTimelineItem[] {
  if (!Array.isArray(value) || value.length !== runVersion) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const timeline = value.map((raw, index) => {
    const item = recordWithKeys(raw, ["run_version", "kind", "phase", "recorded_at"]);
    const kind = stringField(item, "kind") as DemoTimelineKind;
    const itemPhase = stringField(item, "phase") as DemoPhase;
    if (
      !Object.hasOwn(TIMELINE_KIND_PHASE, kind) ||
      !PHASES.has(itemPhase) ||
      TIMELINE_KIND_PHASE[kind] !== itemPhase ||
      integerField(item, "run_version") !== index + 1
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      run_version: index + 1,
      kind,
      phase: itemPhase,
      recorded_at: timestampValue(item.recorded_at),
    };
  });
  if (timeline[0]?.kind !== "run-created" || timeline.at(-1)?.phase !== phase) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  for (let index = 1; index < timeline.length; index += 1) {
    const previous = timeline[index - 1] as DemoTimelineItem;
    const current = timeline[index] as DemoTimelineItem;
    const validTransition =
      (current.kind === "investigation-completed" && previous.phase === "preparing") ||
      (current.kind === "approval-submitted" && previous.phase === "awaiting-approval") ||
      (current.kind === "plan-rejected" && previous.phase === "awaiting-approval") ||
      (current.kind === "recovery-verified" && previous.phase === "executing") ||
      (current.kind === "closure-submitted" && previous.phase === "awaiting-closure") ||
      (current.kind === "recovery-closed" && previous.phase === "closing") ||
      ((current.kind === "run-unresolved" || current.kind === "run-expired") &&
        !TERMINAL_PHASES.has(previous.phase));
    if (!validTransition || Date.parse(current.recorded_at) < Date.parse(previous.recorded_at)) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
  }
  return timeline;
}

function parseRun(value: unknown, expectedStartNonce?: string): DemoRun {
  const requiredKeys = [
    "schema",
    "run_id",
    "incident_id",
    "scenario_id",
    "source_commit",
    "build_sha256",
    "phase",
    "version",
    "lease_expires_at",
    "poll",
    "approval",
    "recovery",
    "visual_comparison",
    "terminal",
    "terminal_reason",
    "receipt_href",
    "reset",
  ];
  const schema = isRecord(value) ? value.schema : undefined;
  const optionalKeys = new Set(["approval_nonce", "investigation", "execution"]);
  if (schema === "colortrace-demo-run/v2") requiredKeys.push("timeline");
  if (
    !isRecord(value) ||
    (schema !== "colortrace-demo-run/v1" && schema !== "colortrace-demo-run/v2") ||
    !requiredKeys.every((key) => Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !requiredKeys.includes(key) && !optionalKeys.has(key))
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const phaseValue = value.phase;
  if (typeof phaseValue !== "string" || !PHASES.has(phaseValue as DemoPhase)) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const phase = phaseValue as DemoPhase;
  const runVersion = integerField(value, "version");
  const terminal = booleanField(value, "terminal");
  if (terminal !== TERMINAL_PHASES.has(phase)) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const lease = nullableStringField(value, "lease_expires_at");
  if (
    (terminal && lease !== null) ||
    (!terminal && (lease === null || !Number.isFinite(Date.parse(lease))))
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const poll = recordWithKeys(value.poll, ["href", "after_milliseconds"]);
  const pollHref = stringField(poll, "href");
  const pollAfter = integerField(poll, "after_milliseconds");
  if (!pollHref.startsWith("/v1/demo/runs/") || pollAfter !== 1_000) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const nonce = value.approval_nonce;
  if (
    (nonce !== undefined &&
      (typeof nonce !== "string" ||
        !NONCE.test(nonce) ||
        expectedStartNonce === undefined ||
        nonce !== expectedStartNonce ||
        phase !== "awaiting-approval")) ||
    (expectedStartNonce !== undefined && phase === "awaiting-approval" && nonce === undefined)
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const runId = requirePattern(stringField(value, "run_id"), RUN_ID);
  if (
    stringField(value, "scenario_id") !== CANONICAL_DEMO_SCENARIO ||
    pollHref !== `/v1/demo/runs/${runId}`
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const terminalReason = nullableStringField(value, "terminal_reason");
  const receiptHref = nullableStringField(value, "receipt_href");
  const reset = booleanField(value, "reset");
  if (
    (terminal &&
      (terminalReason === null ||
        !REASON_CODE.test(terminalReason) ||
        receiptHref !== `/v1/demo/runs/${runId}/receipt`)) ||
    (!terminal && (terminalReason !== null || receiptHref !== null || reset))
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const approval = parseApproval(value.approval);
  const recovery = parseRecovery(value.recovery);
  const investigation =
    value.investigation === undefined ? undefined : parseInvestigation(value.investigation);
  const execution = value.execution === undefined ? undefined : parseExecution(value.execution);
  const investigationRequired = new Set<DemoPhase>([
    "awaiting-approval",
    "executing",
    "awaiting-closure",
    "closing",
    "closed",
  ]).has(phase);
  const executionRequired = new Set<DemoPhase>(["awaiting-closure", "closing", "closed"]).has(
    phase,
  );
  if (
    (approval === null) !== (investigation === undefined) ||
    (recovery === null) !== (execution === undefined) ||
    (investigationRequired && investigation === undefined) ||
    (executionRequired && execution === undefined)
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  if (
    expectedStartNonce !== undefined &&
    (schema !== "colortrace-demo-run/v2" ||
      phase !== "awaiting-approval" ||
      investigation?.schema !== "colortrace-demo-investigation-proof/v3")
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  if (
    approval !== null &&
    investigation !== undefined &&
    (investigation.plan.version !== approval.plan_version ||
      investigation.plan.plan_sha256 !== approval.plan_sha256 ||
      investigation.plan.target_sha256 !== approval.target_sha256)
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  if (
    approval !== null &&
    investigation !== undefined &&
    investigation.schema !== "colortrace-demo-investigation-proof/v1"
  ) {
    const inventoryDigests = new Set(investigation.evidence.map((item) => item.inventory_sha256));
    const accepted = investigation.model_invocations.filter(
      (item) => item.result_class === "accepted",
    );
    const acceptedTurns = new Set(accepted.map((item) => item.turn_kind));
    const queryTools = new Map(investigation.evidence.map((item) => [item.query_key, item.tool]));
    if (
      investigation.status !== "resolved" ||
      investigation.scope.state !== "resolved" ||
      investigation.scope.affected_count !== 4 ||
      investigation.scope.safe_count !== 3 ||
      investigation.scope.unknown_count !== 0 ||
      investigation.plan.status !== "pending" ||
      queryTools.size !== Object.keys(INVESTIGATION_TOOLS).length ||
      Object.entries(INVESTIGATION_TOOLS).some(([key, tool]) => queryTools.get(key) !== tool) ||
      investigation.evidence.some((item) => item.freshness !== "current") ||
      inventoryDigests.size !== 1 ||
      accepted.length < 2 ||
      acceptedTurns.size !== 2 ||
      !acceptedTurns.has("evidence-selection") ||
      !acceptedTurns.has("response-drafting") ||
      accepted.some(
        (item) => item.inventory_sha256 === null || !inventoryDigests.has(item.inventory_sha256),
      ) ||
      investigation.validators.some((item) => item.status !== "resolved")
    ) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
  }
  if (
    recovery !== null &&
    execution !== undefined &&
    (execution.action.outcome_id !== recovery.outcome_id ||
      execution.action.outcome_sha256 !== recovery.outcome_sha256 ||
      execution.recovery.workflow_id !== recovery.workflow_id ||
      execution.recovery.workflow_version !== recovery.workflow_version ||
      execution.recovery.packet_id !== recovery.packet_id ||
      execution.recovery.packet_sha256 !== recovery.packet_sha256)
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const visualComparison = parseVisualComparison(value.visual_comparison, runId);
  const expectedVisualKinds = new Set<DemoVisualKind>();
  if (investigation !== undefined) {
    expectedVisualKinds.add("expected");
    expectedVisualKinds.add("observed");
    expectedVisualKinds.add("diff");
  }
  if (execution !== undefined) expectedVisualKinds.add("recovered");
  const visualKinds = Object.keys(visualComparison) as DemoVisualKind[];
  if (
    visualKinds.length !== expectedVisualKinds.size ||
    visualKinds.some((kind) => !expectedVisualKinds.has(kind))
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  if (
    schema === "colortrace-demo-run/v2" &&
    investigation !== undefined &&
    investigation.schema !== "colortrace-demo-investigation-proof/v3"
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const timeline =
    schema === "colortrace-demo-run/v2"
      ? parseTimeline(value.timeline, runVersion, phase)
      : undefined;
  if (timeline !== undefined && terminal) {
    const lastKind = timeline.at(-1)?.kind;
    const expectedTerminalKind =
      phase === "closed"
        ? "recovery-closed"
        : phase === "expired"
          ? "run-expired"
          : terminalReason?.startsWith("plan-rejected-")
            ? "plan-rejected"
            : "run-unresolved";
    if (lastKind !== expectedTerminalKind) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
  }
  const parsed = {
    schema,
    run_id: runId,
    incident_id: requirePattern(stringField(value, "incident_id"), INCIDENT_ID),
    scenario_id: CANONICAL_DEMO_SCENARIO,
    source_commit: requirePattern(stringField(value, "source_commit"), COMMIT),
    build_sha256: digestField(value, "build_sha256"),
    phase,
    version: runVersion,
    lease_expires_at: lease,
    poll: { href: pollHref, after_milliseconds: pollAfter },
    approval,
    recovery,
    visual_comparison: visualComparison,
    terminal,
    terminal_reason: terminalReason,
    receipt_href: receiptHref,
    reset,
    ...(nonce === undefined ? {} : { approval_nonce: nonce }),
    ...(investigation === undefined ? {} : { investigation }),
    ...(execution === undefined ? {} : { execution }),
    ...(timeline === undefined ? {} : { timeline }),
  };
  return parsed as DemoRun;
}

const RECEIPT_BINDING_DIGESTS = [
  "plan_sha256",
  "target_sha256",
  "outcome_sha256",
  "packet_sha256",
  "closure_sha256",
] as const;
const RECEIPT_BINDING_IDENTIFIERS = [
  "outcome_id",
  "workflow_id",
  "packet_id",
  "closure_id",
] as const;

function parseReceipt(value: unknown): DemoReceipt {
  const receipt = recordWithKeys(value, [
    "schema",
    "run_id",
    "incident_id",
    "scenario_id",
    "source_commit",
    "build_sha256",
    "provenance",
    "phase",
    "run_version",
    "created_at",
    "terminal_at",
    "reason_code",
    "bindings",
    "proofs",
    "visuals",
    "receipt_id",
    "receipt_sha256",
  ]);
  if (receipt.schema !== "colortrace-demo-receipt/v1") {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const phase = stringField(receipt, "phase");
  if (phase !== "closed" && phase !== "unresolved" && phase !== "expired") {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  if (!Array.isArray(receipt.visuals) || !Array.isArray(receipt.proofs)) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const bindings = recordWithKeys(receipt.bindings, [
    "incident_version",
    "plan_version",
    "plan_sha256",
    "target_sha256",
    "outcome_id",
    "outcome_sha256",
    "workflow_id",
    "workflow_version",
    "packet_id",
    "packet_sha256",
    "closure_id",
    "closure_sha256",
  ]);
  const parsedBindings = {
    incident_version: nullableIntegerField(bindings, "incident_version"),
    plan_version: nullableIntegerField(bindings, "plan_version"),
    plan_sha256: nullableDigestField(bindings, "plan_sha256"),
    target_sha256: nullableDigestField(bindings, "target_sha256"),
    outcome_id: nullableStringField(bindings, "outcome_id"),
    outcome_sha256: nullableDigestField(bindings, "outcome_sha256"),
    workflow_id: nullableStringField(bindings, "workflow_id"),
    workflow_version: nullableIntegerField(bindings, "workflow_version"),
    packet_id: nullableStringField(bindings, "packet_id"),
    packet_sha256: nullableDigestField(bindings, "packet_sha256"),
    closure_id: nullableStringField(bindings, "closure_id"),
    closure_sha256: nullableDigestField(bindings, "closure_sha256"),
  };
  for (const key of RECEIPT_BINDING_DIGESTS) {
    const selected = parsedBindings[key];
    if (selected !== null && !DIGEST.test(selected)) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
  }
  for (const key of RECEIPT_BINDING_IDENTIFIERS) {
    const selected = parsedBindings[key];
    if (selected !== null && !IDENTIFIER.test(selected)) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
  }
  const visuals = receipt.visuals.map((value) => {
    const visual = recordWithKeys(value, ["kind", "sha256"]);
    const kind = stringField(visual, "kind");
    if (!VISUAL_KINDS.has(kind as DemoVisualKind)) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return { kind: kind as DemoVisualKind, sha256: digestField(visual, "sha256") };
  });
  if (new Set(visuals.map((visual) => visual.kind)).size !== visuals.length) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const proofs = receipt.proofs.map((value) => {
    const proof = recordWithKeys(value, ["stage", "sha256"]);
    if (proof.stage !== "investigation" && proof.stage !== "execution") {
      throw new DemoApiError(null, "demo-response-invalid");
    }
    return {
      stage: proof.stage as "investigation" | "execution",
      sha256: digestField(proof, "sha256"),
    };
  });
  if (new Set(proofs.map((proof) => proof.stage)).size !== proofs.length) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const sourceCommit = requirePattern(stringField(receipt, "source_commit"), COMMIT);
  if (
    !isRecord(receipt.provenance) ||
    receipt.provenance.schema !== "colortrace-demo-build-provenance/v1" ||
    receipt.provenance.source_commit !== sourceCommit
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const provenance = receipt.provenance as DemoBuildProvenance;
  const scenarioId = stringField(receipt, "scenario_id");
  const createdAt = stringField(receipt, "created_at");
  const terminalAt = stringField(receipt, "terminal_at");
  if (
    scenarioId !== CANONICAL_DEMO_SCENARIO ||
    !TIMESTAMP.test(createdAt) ||
    !TIMESTAMP.test(terminalAt) ||
    !Number.isFinite(Date.parse(createdAt)) ||
    !Number.isFinite(Date.parse(terminalAt)) ||
    Date.parse(terminalAt) < Date.parse(createdAt)
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const receiptSha256 = digestField(receipt, "receipt_sha256");
  const receiptId = requirePattern(stringField(receipt, "receipt_id"), IDENTIFIER);
  if (receiptId !== `demo-receipt:${receiptSha256.slice("sha256:".length)}`) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return {
    schema: "colortrace-demo-receipt/v1",
    run_id: requirePattern(stringField(receipt, "run_id"), RUN_ID),
    incident_id: requirePattern(stringField(receipt, "incident_id"), INCIDENT_ID),
    scenario_id: scenarioId,
    source_commit: sourceCommit,
    build_sha256: digestField(receipt, "build_sha256"),
    provenance,
    phase,
    run_version: integerField(receipt, "run_version"),
    created_at: createdAt,
    terminal_at: terminalAt,
    reason_code: requirePattern(stringField(receipt, "reason_code"), REASON_CODE),
    bindings: parsedBindings,
    visuals,
    proofs,
    receipt_id: receiptId,
    receipt_sha256: receiptSha256,
  };
}

function parseReset(value: unknown, runId: string): DemoReset {
  const reset = recordWithKeys(value, [
    "schema",
    "run_id",
    "phase",
    "version",
    "reset",
    "receipt_href",
    "restoration",
  ]);
  if (reset.schema !== "colortrace-demo-reset/v1") {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  const phase = stringField(reset, "phase");
  const receiptHref = stringField(reset, "receipt_href");
  const restoration = recordWithKeys(reset.restoration, [
    "schema",
    "operation_id",
    "fixture_id",
    "source_batch_sha256",
    "previous_pointer_sha256",
    "active_pointer_sha256",
    "generation",
  ]);
  if (
    (phase !== "closed" && phase !== "unresolved" && phase !== "expired") ||
    stringField(reset, "run_id") !== runId ||
    booleanField(reset, "reset") !== true ||
    receiptHref !== `/v1/demo/runs/${runId}/receipt` ||
    restoration.schema !== "simulator-authored-scenario-reset/v1" ||
    restoration.generation !== 1
  ) {
    throw new DemoApiError(null, "demo-response-invalid");
  }
  return {
    schema: "colortrace-demo-reset/v1",
    run_id: runId,
    phase,
    version: integerField(reset, "version"),
    reset: true,
    receipt_href: receiptHref,
    restoration: {
      schema: "simulator-authored-scenario-reset/v1",
      operation_id: requirePattern(stringField(restoration, "operation_id"), IDENTIFIER),
      fixture_id: requirePattern(stringField(restoration, "fixture_id"), IDENTIFIER),
      source_batch_sha256: digestField(restoration, "source_batch_sha256"),
      previous_pointer_sha256: digestField(restoration, "previous_pointer_sha256"),
      active_pointer_sha256: digestField(restoration, "active_pointer_sha256"),
      generation: 1,
    },
  };
}

function errorCode(value: unknown): string {
  if (isRecord(value) && typeof value.code === "string" && REASON_CODE.test(value.code)) {
    return value.code;
  }
  return "demo-request-failed";
}

export class DemoApiError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly runId: string | null;

  constructor(
    status: number | null,
    code: string,
    options?: ErrorOptions & { readonly runId?: string },
  ) {
    super(`Demo API request failed: ${code}`, options);
    this.name = "DemoApiError";
    this.status = status;
    this.code = code;
    this.runId = options?.runId !== undefined && RUN_ID.test(options.runId) ? options.runId : null;
  }
}

async function defaultSha256(value: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return `sha256:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

type Sha256Implementation = (value: ArrayBuffer) => Promise<string>;

async function canonicalDocumentSha256(
  value: unknown,
  sha256: Sha256Implementation,
): Promise<string> {
  return sha256(canonicalJsonBytes(value).buffer);
}

async function verifyRunCommandDigest(run: DemoRun, sha256: Sha256Implementation): Promise<void> {
  const investigation = run.investigation;
  if (
    investigation === undefined ||
    investigation.schema === "colortrace-demo-investigation-proof/v1"
  ) {
    return;
  }
  const commands = investigation.plan.command_summaries.map((summary) => ({
    ...summary,
    action_envelope: investigation.plan.shared_action_bindings,
  }));
  try {
    if ((await canonicalDocumentSha256(commands, sha256)) !== investigation.plan.commands_sha256) {
      throw new DemoApiError(null, "demo-response-invalid");
    }
  } catch (error) {
    if (error instanceof DemoApiError) throw error;
    throw new DemoApiError(null, "demo-response-invalid", { cause: error });
  }
}

function receiptBody(receipt: DemoReceipt): Omit<DemoReceipt, "receipt_id" | "receipt_sha256"> {
  const { receipt_id: _receiptId, receipt_sha256: _receiptSha256, ...body } = receipt;
  return body;
}

async function receiptEnvelopeMatches(
  receipt: DemoReceipt,
  sha256: Sha256Implementation,
): Promise<boolean> {
  const provenanceSha256 = await canonicalDocumentSha256(receipt.provenance, sha256);
  if (provenanceSha256 !== receipt.build_sha256) return false;
  const bodySha256 = await canonicalDocumentSha256(receiptBody(receipt), sha256);
  return (
    bodySha256 === receipt.receipt_sha256 &&
    receipt.receipt_id === `demo-receipt:${bodySha256.slice("sha256:".length)}`
  );
}

export async function verifyDemoReceiptIntegrity(
  receipt: DemoReceipt,
  run: DemoRun,
): Promise<boolean> {
  try {
    if (!(await receiptEnvelopeMatches(receipt, defaultSha256))) return false;
    const expectedProofs = new Map<"investigation" | "execution", string>();
    if (run.investigation !== undefined) {
      expectedProofs.set(
        "investigation",
        await canonicalDocumentSha256(run.investigation, defaultSha256),
      );
    }
    if (run.execution !== undefined) {
      expectedProofs.set("execution", await canonicalDocumentSha256(run.execution, defaultSha256));
    }
    return (
      receipt.proofs.length === expectedProofs.size &&
      receipt.proofs.every((proof) => expectedProofs.get(proof.stage) === proof.sha256)
    );
  } catch {
    return false;
  }
}

export function createDemoAdapter({
  baseUrl,
  fetch: fetchImplementation = fetch,
  createObjectUrl = (blob) => URL.createObjectURL(blob),
  revokeObjectUrl = (url) => URL.revokeObjectURL(url),
  sha256 = defaultSha256,
}: DemoAdapterOptions): DemoAdapter {
  const origin = new URL(baseUrl).origin;

  function endpoint(path: string): URL {
    return new URL(path, `${origin}/`);
  }

  async function jsonRequest(
    path: string,
    options: { readonly body?: unknown; readonly signal?: AbortSignal } = {},
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await fetchImplementation(endpoint(path), {
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          ...(options.body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        method: options.body === undefined ? "GET" : "POST",
        redirect: "error",
        ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (error) {
      throw new DemoApiError(null, "demo-network-failure", { cause: error });
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    let body: unknown;
    try {
      body = contentType === "application/json" ? await response.json() : null;
    } catch (error) {
      throw new DemoApiError(response.status, "demo-response-invalid", { cause: error });
    }
    if (!response.ok) {
      const runId = isRecord(body) && typeof body.run_id === "string" ? body.run_id : undefined;
      throw new DemoApiError(response.status, errorCode(body), {
        ...(runId === undefined ? {} : { runId }),
      });
    }
    if (contentType !== "application/json") {
      throw new DemoApiError(response.status, "demo-response-invalid");
    }
    return body;
  }

  function runPath(runId: string, suffix = ""): string {
    if (!RUN_ID.test(runId)) throw new DemoApiError(null, "demo-run-id-invalid");
    return `/v1/demo/runs/${encodeURIComponent(runId)}${suffix}`;
  }

  async function checkedRun(value: unknown, expectedStartNonce?: string): Promise<DemoRun> {
    const parsed = parseRun(value, expectedStartNonce);
    await verifyRunCommandDigest(parsed, sha256);
    return parsed;
  }

  async function boundRun(value: unknown, runId: string): Promise<DemoRun> {
    const parsed = await checkedRun(value);
    if (parsed.run_id !== runId) throw new DemoApiError(null, "demo-response-invalid");
    return parsed;
  }

  async function verifiedVisual(
    path: string,
    kind: DemoVisualKind,
    expectedSha256?: string,
    signal?: AbortSignal,
  ): Promise<VerifiedDemoVisual> {
    let response: Response;
    try {
      response = await fetchImplementation(endpoint(path), {
        credentials: "same-origin",
        headers: { Accept: "image/png" },
        method: "GET",
        redirect: "error",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (error) {
      throw new DemoApiError(null, "demo-network-failure", { cause: error });
    }
    if (!response.ok) {
      throw new DemoApiError(response.status, "demo-visual-unavailable");
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    const declared = response.headers.get("x-content-sha256");
    if (contentType !== "image/png" || declared === null || !DIGEST.test(declared)) {
      await response.body?.cancel();
      throw new DemoApiError(response.status, "demo-visual-response-invalid");
    }
    const content = await response.arrayBuffer();
    const signature = new Uint8Array(content.slice(0, 8));
    if (
      content.byteLength < 8 ||
      content.byteLength > MAX_VISUAL_BYTES ||
      ![137, 80, 78, 71, 13, 10, 26, 10].every((byte, index) => signature[index] === byte)
    ) {
      throw new DemoApiError(response.status, "demo-visual-response-invalid");
    }
    const actual = await sha256(content);
    if (actual !== declared || (expectedSha256 !== undefined && actual !== expectedSha256)) {
      throw new DemoApiError(response.status, "demo-visual-digest-conflict");
    }
    const src = createObjectUrl(new Blob([content], { type: "image/png" }));
    return { kind, sha256: actual, src };
  }

  return {
    preview: async (signal) => parsePreview(await jsonRequest("/v1/demo", { signal })),
    previewVisual: async (kind, expectedSha256, signal) => {
      if (!PREVIEW_VISUAL_KINDS.has(kind)) {
        throw new DemoApiError(null, "demo-visual-kind-invalid");
      }
      return verifiedVisual(`/v1/demo/visuals/${kind}`, kind, expectedSha256, signal);
    },
    start: async (request, signal) => {
      if (!NONCE.test(request.approval_nonce) || !IDEMPOTENCY_KEY.test(request.idempotency_key)) {
        throw new DemoApiError(null, "demo-request-invalid");
      }
      const parsed = await checkedRun(
        await jsonRequest("/v1/demo/runs", {
          body: {
            schema: "colortrace-demo-run-request/v2",
            scenario_id: CANONICAL_DEMO_SCENARIO,
            approval_nonce: request.approval_nonce,
            idempotency_key: request.idempotency_key,
          },
          signal,
        }),
        request.approval_nonce,
      );
      return parsed;
    },
    get: async (runId, signal) => boundRun(await jsonRequest(runPath(runId), { signal }), runId),
    approve: async (runId, request) =>
      boundRun(await jsonRequest(runPath(runId, "/approve"), { body: request }), runId),
    reject: async (runId, request) => {
      if (
        request.schema !== "colortrace-demo-rejection-request/v1" ||
        !NONCE.test(request.approval_nonce) ||
        !Number.isSafeInteger(request.expected_run_version) ||
        request.expected_run_version < 1 ||
        !Number.isSafeInteger(request.expected_incident_version) ||
        request.expected_incident_version < 1 ||
        !Number.isSafeInteger(request.expected_plan_version) ||
        request.expected_plan_version < 1 ||
        !DIGEST.test(request.expected_plan_sha256) ||
        !DIGEST.test(request.expected_target_sha256) ||
        !REJECTION_REASONS.has(request.reason_code) ||
        !IDEMPOTENCY_KEY.test(request.idempotency_key)
      ) {
        throw new DemoApiError(null, "demo-request-invalid");
      }
      return boundRun(await jsonRequest(runPath(runId, "/reject"), { body: request }), runId);
    },
    close: async (runId, request) =>
      boundRun(await jsonRequest(runPath(runId, "/close"), { body: request }), runId),
    reset: async (runId, expectedVersion, idempotencyKey) =>
      parseReset(
        await jsonRequest(runPath(runId, "/reset"), {
          body: {
            schema: "colortrace-demo-reset-request/v1",
            expected_run_version: expectedVersion,
            idempotency_key: idempotencyKey,
          },
        }),
        runId,
      ),
    receipt: async (runId, signal) => {
      const parsed = parseReceipt(await jsonRequest(runPath(runId, "/receipt"), { signal }));
      let validEnvelope = false;
      try {
        validEnvelope = await receiptEnvelopeMatches(parsed, sha256);
      } catch {
        validEnvelope = false;
      }
      if (parsed.run_id !== runId || !validEnvelope) {
        throw new DemoApiError(null, "demo-response-invalid");
      }
      return parsed;
    },
    visual: async (runId, kind, expectedSha256, signal) => {
      if (!VISUAL_KINDS.has(kind)) throw new DemoApiError(null, "demo-visual-kind-invalid");
      return verifiedVisual(runPath(runId, `/visuals/${kind}`), kind, expectedSha256, signal);
    },
    releaseVisual: (visual) => revokeObjectUrl(visual.src),
  };
}
