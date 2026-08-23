export const CANONICAL_DEMO_SCENARIO = "ct-shadowed-lut-v1:canonical";
export const DEMO_APPROVAL_PHRASE = "APPROVE_COLORTRACE_SIMULATOR_ACTION";

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

export type DemoVisualDescriptor = {
  readonly href: string;
  readonly sha256: string;
  readonly media_type: "image/png";
  readonly label: "illustrative-authored-fixture";
};

export type DemoInvestigationProof = {
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

export type DemoRun = {
  readonly schema: "colortrace-demo-run/v1";
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
  readonly start: (request: DemoStartRequest, signal?: AbortSignal) => Promise<DemoRun>;
  readonly get: (runId: string, signal?: AbortSignal) => Promise<DemoRun>;
  readonly approve: (runId: string, request: DemoApprovalRequest) => Promise<DemoRun>;
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
const INVESTIGATION_TOOLS = {
  "alert.rule": "alerting_manage_rules",
  "log.correlated-events": "query_loki_logs",
  "metric.correlated-observations": "query_prometheus",
  "trace.by-id": "tempo_get-trace",
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

function booleanField(value: Record<string, unknown>, key: string): boolean {
  const selected = value[key];
  if (typeof selected !== "boolean") throw new DemoApiError(null, "demo-response-invalid");
  return selected;
}

function requirePattern(value: string, pattern: RegExp): string {
  if (!pattern.test(value)) throw new DemoApiError(null, "demo-response-invalid");
  return value;
}

function digestField(value: Record<string, unknown>, key: string): string {
  return requirePattern(stringField(value, key), DIGEST);
}

function nullableDigestField(value: Record<string, unknown>, key: string): string | null {
  const selected = nullableStringField(value, key);
  return selected === null ? null : requirePattern(selected, DIGEST);
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

function parseInvestigation(value: unknown): DemoInvestigationProof {
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
  const optionalKeys = new Set(["approval_nonce", "investigation", "execution"]);
  if (
    !isRecord(value) ||
    value.schema !== "colortrace-demo-run/v1" ||
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
  if (approval !== null && investigation !== undefined) {
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
      investigation.plan.version !== approval.plan_version ||
      investigation.plan.plan_sha256 !== approval.plan_sha256 ||
      investigation.plan.target_sha256 !== approval.target_sha256 ||
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
  return {
    schema: "colortrace-demo-run/v1",
    run_id: runId,
    incident_id: requirePattern(stringField(value, "incident_id"), INCIDENT_ID),
    scenario_id: CANONICAL_DEMO_SCENARIO,
    source_commit: requirePattern(stringField(value, "source_commit"), COMMIT),
    build_sha256: digestField(value, "build_sha256"),
    phase,
    version: integerField(value, "version"),
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
  };
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

  function boundRun(value: unknown, runId: string): DemoRun {
    const parsed = parseRun(value);
    if (parsed.run_id !== runId) throw new DemoApiError(null, "demo-response-invalid");
    return parsed;
  }

  return {
    start: async (request, signal) => {
      if (!NONCE.test(request.approval_nonce) || !IDEMPOTENCY_KEY.test(request.idempotency_key)) {
        throw new DemoApiError(null, "demo-request-invalid");
      }
      const parsed = parseRun(
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
      let response: Response;
      try {
        response = await fetchImplementation(endpoint(runPath(runId, `/visuals/${kind}`)), {
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
    },
    releaseVisual: (visual) => revokeObjectUrl(visual.src),
  };
}
