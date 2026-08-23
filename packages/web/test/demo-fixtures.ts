import { createHash } from "node:crypto";

import {
  canonicalJsonBytes,
  type DemoBuildProvenance,
  type DemoExecutionProof,
  type DemoInvestigationProof,
  type DemoReceipt,
  type DemoReset,
  type DemoRun,
  type DemoVisualKind,
} from "../src/demo-api.ts";

export const RUN_ID = "demo-run-11111111111111111111111111111111";
export const NONCE = "n".repeat(32);
export const PLAN_DIGEST = `sha256:${"1".repeat(64)}`;
export const TARGET_DIGEST = `sha256:${"2".repeat(64)}`;
export const OUTCOME_DIGEST = `sha256:${"3".repeat(64)}`;
export const PACKET_DIGEST = `sha256:${"4".repeat(64)}`;
export const CLOSURE_DIGEST = `sha256:${"5".repeat(64)}`;
export const SAFE_PROOF_DIGEST = `sha256:${"8".repeat(64)}`;

function documentSha256(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJsonBytes(value)).digest("hex")}`;
}

export function buildProvenance(): DemoBuildProvenance {
  return {
    schema: "colortrace-demo-build-provenance/v1",
    source_commit: "a".repeat(40),
    source_tree: "b".repeat(40),
    runtime_image: `ghcr.io/example/colortrace@sha256:${"c".repeat(64)}`,
    public_url: "https://colortrace.example",
    staging_generation: "candidate-1",
  };
}

export const BUILD_DIGEST = documentSha256(buildProvenance());

export function sealDemoReceipt(
  body: Omit<DemoReceipt, "receipt_id" | "receipt_sha256">,
): DemoReceipt {
  const receiptSha256 = documentSha256(body);
  return {
    ...body,
    receipt_id: `demo-receipt:${receiptSha256.slice("sha256:".length)}`,
    receipt_sha256: receiptSha256,
  };
}

export const RECOVERY_CHECKS = [
  "active-publication",
  "approved-resource-state",
  "declared-reference-recovery",
  "exact-typed-lineage",
  "approved-recovery-scope",
  "safe-complement-preservation",
  "post-action-telemetry-correlation",
] as const;

export const VISUAL_DIGESTS: Readonly<Record<DemoVisualKind, string>> = Object.fromEntries(
  (["expected", "observed", "diff", "recovered"] as const).map((kind) => [
    kind,
    `sha256:${kind.charCodeAt(0).toString(16).padStart(2, "0").repeat(32)}`,
  ]),
) as Readonly<Record<DemoVisualKind, string>>;

export function investigationProof(): DemoInvestigationProof {
  const queryTools = [
    ["alert.rule", "alerting_manage_rules"],
    ["log.correlated-events", "query_loki_logs"],
    ["metric.correlated-observations", "query_prometheus"],
    ["trace.by-id", "tempo_get-trace"],
  ] as const;
  return {
    schema: "colortrace-demo-investigation-proof/v1",
    packet_id: `response-packet:${"6".repeat(64)}`,
    packet_sha256: `sha256:${"6".repeat(64)}`,
    status: "resolved",
    model_invocations: [
      {
        invocation_id: `model-invocation:${"8".repeat(64)}`,
        turn_kind: "evidence-selection",
        model: "gemini-3.5-flash",
        framework: "google-adk",
        result_class: "accepted",
        inventory_sha256: `sha256:${"7".repeat(64)}`,
        output_sha256: `sha256:${"8".repeat(64)}`,
        trace_id: "8".repeat(32),
      },
      {
        invocation_id: `model-invocation:${"9".repeat(64)}`,
        turn_kind: "response-drafting",
        model: "gemini-3.5-flash",
        framework: "google-adk",
        result_class: "accepted",
        inventory_sha256: `sha256:${"7".repeat(64)}`,
        output_sha256: `sha256:${"9".repeat(64)}`,
        trace_id: "9".repeat(32),
      },
    ],
    evidence: queryTools.map(([queryKey, tool], index) => ({
      evidence_id: `sha256:${(index + 10).toString(16).repeat(64)}`,
      query_key: queryKey,
      tool,
      inventory_sha256: `sha256:${"7".repeat(64)}`,
      content_sha256: `sha256:${(index + 10).toString(16).repeat(64)}`,
      freshness: "current",
    })),
    validators: [
      {
        result_id: `validator-result:${"e".repeat(64)}`,
        validator: "colortrace-validator",
        validator_version: "1.0.0",
        status: "resolved",
        derivation_sha256: `sha256:${"e".repeat(64)}`,
      },
    ],
    scope: { state: "resolved", affected_count: 4, safe_count: 3, unknown_count: 0 },
    budget_use: {
      elapsed_ms: 1,
      model_turns: 2,
      input_tokens: 100,
      output_tokens: 20,
      mcp_attempts: 4,
      validator_calls: 6,
    },
    plan: {
      status: "pending",
      version: 3,
      plan_sha256: PLAN_DIGEST,
      target_sha256: TARGET_DIGEST,
    },
  };
}

export function executionProof(): DemoExecutionProof {
  return {
    schema: "colortrace-demo-execution-proof/v1",
    action: {
      action_id: `simulator-action:${"a".repeat(64)}`,
      status: "succeeded",
      outcome_id: `simulator-action-outcome:${"3".repeat(64)}`,
      outcome_sha256: OUTCOME_DIGEST,
      publication_generation_before: 1,
      publication_generation_after: 2,
      affected_count: 4,
      safe_count: 3,
      safe_complement_before_sha256: `sha256:${"b".repeat(64)}`,
      safe_complement_after_sha256: `sha256:${"b".repeat(64)}`,
      safe_complement_proof_sha256: SAFE_PROOF_DIGEST,
      publication_receipt_sha256: `sha256:${"d".repeat(64)}`,
    },
    recovery: {
      status: "recovery_verified",
      workflow_id: `recovery-workflow:${"4".repeat(64)}`,
      workflow_version: 2,
      packet_id: `recovery-packet:${"4".repeat(64)}`,
      packet_sha256: PACKET_DIGEST,
      evidence_count: 21,
      evidence_request_sha256: `sha256:${"e".repeat(64)}`,
      checks: RECOVERY_CHECKS.map((check, index) => ({
        check,
        status: "passed",
        result_sha256: `sha256:${(index + 1).toString(16).padStart(64, "0")}`,
      })),
    },
  };
}

export function demoRun(
  phase: DemoRun["phase"] = "awaiting-approval",
  overrides: Partial<DemoRun> = {},
  visualDigests: Readonly<Record<DemoVisualKind, string>> = VISUAL_DIGESTS,
): DemoRun {
  const terminal = phase === "closed" || phase === "unresolved" || phase === "expired";
  const recovered = phase === "awaiting-closure" || phase === "closing" || phase === "closed";
  const visualKinds: DemoVisualKind[] = ["expected", "observed", "diff"];
  if (recovered) visualKinds.push("recovered");
  return {
    schema: "colortrace-demo-run/v1",
    run_id: RUN_ID,
    incident_id: "incident-demo-11111111111111111111111111111111",
    scenario_id: "ct-shadowed-lut-v1:canonical",
    source_commit: "a".repeat(40),
    build_sha256: BUILD_DIGEST,
    phase,
    version: phase === "awaiting-approval" ? 2 : phase === "awaiting-closure" ? 4 : 6,
    lease_expires_at: terminal ? null : "2099-08-23T12:15:00.000Z",
    poll: { href: `/v1/demo/runs/${RUN_ID}`, after_milliseconds: 1_000 },
    approval: {
      phrase: "APPROVE_COLORTRACE_SIMULATOR_ACTION",
      incident_version: 7,
      plan_version: 3,
      plan_sha256: PLAN_DIGEST,
      target_sha256: TARGET_DIGEST,
    },
    recovery: recovered
      ? {
          outcome_id: `simulator-action-outcome:${"3".repeat(64)}`,
          outcome_sha256: OUTCOME_DIGEST,
          workflow_id: `recovery-workflow:${"4".repeat(64)}`,
          workflow_version: 2,
          packet_id: `recovery-packet:${"4".repeat(64)}`,
          packet_sha256: PACKET_DIGEST,
          closure_id: phase === "closed" ? `recovery-closure:${"5".repeat(64)}` : null,
          closure_sha256: phase === "closed" ? CLOSURE_DIGEST : null,
        }
      : null,
    visual_comparison: Object.fromEntries(
      visualKinds.map((kind) => [
        kind,
        {
          href: `/v1/demo/runs/${RUN_ID}/visuals/${kind}`,
          sha256: visualDigests[kind],
          media_type: "image/png",
          label: "illustrative-authored-fixture",
        },
      ]),
    ),
    investigation: investigationProof(),
    ...(recovered ? { execution: executionProof() } : {}),
    terminal,
    terminal_reason: terminal ? (phase === "closed" ? "recovery-closed" : "lease-expired") : null,
    receipt_href: terminal ? `/v1/demo/runs/${RUN_ID}/receipt` : null,
    reset: false,
    ...(phase === "awaiting-approval" ? { approval_nonce: NONCE } : {}),
    ...overrides,
  };
}

export function demoReceipt(
  visualDigests: Readonly<Record<DemoVisualKind, string>> = VISUAL_DIGESTS,
): DemoReceipt {
  const body: Omit<DemoReceipt, "receipt_id" | "receipt_sha256"> = {
    schema: "colortrace-demo-receipt/v1",
    run_id: RUN_ID,
    incident_id: "incident-demo-11111111111111111111111111111111",
    scenario_id: "ct-shadowed-lut-v1:canonical",
    source_commit: "a".repeat(40),
    build_sha256: BUILD_DIGEST,
    provenance: buildProvenance(),
    phase: "closed",
    run_version: 6,
    created_at: "2026-08-23T12:00:00.000Z",
    terminal_at: "2026-08-23T12:03:00.000Z",
    reason_code: "recovery-closed",
    bindings: {
      incident_version: 7,
      plan_version: 3,
      plan_sha256: PLAN_DIGEST,
      target_sha256: TARGET_DIGEST,
      outcome_id: `simulator-action-outcome:${"3".repeat(64)}`,
      outcome_sha256: OUTCOME_DIGEST,
      workflow_id: `recovery-workflow:${"4".repeat(64)}`,
      workflow_version: 2,
      packet_id: `recovery-packet:${"4".repeat(64)}`,
      packet_sha256: PACKET_DIGEST,
      closure_id: `recovery-closure:${"5".repeat(64)}`,
      closure_sha256: CLOSURE_DIGEST,
    },
    proofs: [
      { stage: "execution", sha256: documentSha256(executionProof()) },
      { stage: "investigation", sha256: documentSha256(investigationProof()) },
    ],
    visuals: (["diff", "expected", "observed", "recovered"] as const).map((kind) => ({
      kind,
      sha256: visualDigests[kind],
    })),
  };
  return sealDemoReceipt(body);
}

export function demoReset(): DemoReset {
  return {
    schema: "colortrace-demo-reset/v1",
    run_id: RUN_ID,
    phase: "closed",
    version: 6,
    reset: true,
    receipt_href: `/v1/demo/runs/${RUN_ID}/receipt`,
    restoration: {
      schema: "simulator-authored-scenario-reset/v1",
      operation_id: `demo-reset:${"a".repeat(64)}`,
      fixture_id: "ct-shadowed-lut-v1:canonical",
      source_batch_sha256: `sha256:${"b".repeat(64)}`,
      previous_pointer_sha256: `sha256:${"c".repeat(64)}`,
      active_pointer_sha256: `sha256:${"d".repeat(64)}`,
      generation: 1,
    },
  };
}
