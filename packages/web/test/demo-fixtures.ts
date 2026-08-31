import { createHash } from "node:crypto";

import {
  canonicalJsonBytes,
  type DemoActionEnvelope,
  type DemoBuildProvenance,
  type DemoExecutionProof,
  type DemoInvestigationProofV1,
  type DemoInvestigationProofV2,
  type DemoInvestigationProofV3,
  type DemoPlanCommand,
  type DemoPreviewVisualKind,
  type DemoReceipt,
  type DemoRejectionReason,
  type DemoReset,
  type DemoRun,
  type DemoRunV1,
  type DemoScenarioPreview,
  type DemoTimelineItem,
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

export function investigationProofV1(): DemoInvestigationProofV1 {
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
        result_id: `validation-result:${"e".repeat(64)}`,
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

function target(kind: "color-resource" | "frame" | "derivative", id: string) {
  return {
    schema: "simulator-target/v1" as const,
    namespace: "colortrace-simulator" as const,
    kind,
    id,
  };
}

export function investigationProofV2(): DemoInvestigationProofV2 {
  const legacy = investigationProofV1();
  const validators = legacy.validators.map((validator) => ({
    ...validator,
    result_id: `validation-result:${validator.derivation_sha256.slice("sha256:".length)}`,
  }));
  const sourceValidatorResultId = validators[0]?.result_id;
  if (sourceValidatorResultId === undefined) throw new Error("missing fixture validator");
  const expectedResource = `sha256:${"a".repeat(64)}`;
  const replacementResource = `sha256:${"b".repeat(64)}`;
  const targets = [
    target("color-resource", expectedResource),
    target("frame", "frame-b-01"),
    target("frame", "frame-b-02"),
    target("frame", "frame-b-03"),
    target("derivative", "artifact-b-02-derivative"),
  ];
  const protectedExclusions = [
    target("frame", "frame-a-01"),
    target("frame", "frame-a-02"),
    target("frame", "frame-b-04"),
  ];
  const sourceManifest = `sha256:${"c".repeat(64)}`;
  const sourcePng = `sha256:${"d".repeat(64)}`;
  const expectedConfig = `sha256:${"e".repeat(64)}`;
  const frameCommand = (frame: (typeof targets)[number], index: number) => ({
    schema: "simulator-targeted-rerender-command/v1" as const,
    command_id: `rerender-frame-${index}`,
    namespace: "colortrace-simulator" as const,
    target: frame,
    job_id: `job-b-0${index}`,
    transform_id: "look/main/v1" as const,
    source_id: `source-b-0${index}`,
    source_manifest_sha256: sourceManifest,
    source_png_sha256: sourcePng,
    expected_config_sha256: expectedConfig,
    expected_output_sha256: `sha256:${String(index).repeat(64)}`,
    expected_display_sha256: `sha256:${String(index + 3).repeat(64)}`,
    lineage_parent_artifact_id: `source-b-0${index}`,
  });
  const evidence = legacy.evidence.map((item, index) => ({
    evidence_id: item.evidence_id,
    query_key: item.query_key,
    tool: item.tool,
    inventory_sha256: item.inventory_sha256,
    content_sha256: item.content_sha256,
    freshness: "current" as const,
    display_excerpt:
      index === 0
        ? "Alert firing for the bound render comparison."
        : index === 1
          ? "Worker A and worker B completed with the same nominal configuration."
          : index === 2
            ? "Resolved LUT digests differ across the compared successful renders."
            : "<provider-data>Trace joins the render and resolved resource records.</provider-data>",
    display_excerpt_truncated: index === 3,
  }));
  const sharedActionBindings: DemoActionEnvelope = {
    schema: "simulator-action-envelope/v1",
    fixture_id: "ct-shadowed-lut-v1:canonical",
    fixture_manifest_sha256: `sha256:${"1".repeat(64)}`,
    fixture_generation: 1,
    source_batch_id: "source-batch-1",
    source_batch_sha256: `sha256:${"2".repeat(64)}`,
    runtime_manifest_sha256: `sha256:${"3".repeat(64)}`,
    runtime_generation: 1,
    expected_publication_pointer_sha256: `sha256:${"4".repeat(64)}`,
    expected_publication_generation: 1,
    expected_resource_sha256: expectedResource,
    replacement_resource_logical_path: "luts/show_look.cube",
    replacement_resource_sha256: replacementResource,
    declared_resource_manifest_sha256: `sha256:${"5".repeat(64)}`,
    ocio_version: "2.5.2",
    preservation_manifest_sha256: `sha256:${"8".repeat(64)}`,
    safe_complement_sha256: `sha256:${"9".repeat(64)}`,
    lineage_manifest_sha256: `sha256:${"0".repeat(64)}`,
    lineage_generation: 1,
  };
  const commandSummaries: readonly DemoPlanCommand[] = [
    {
      schema: "simulator-quarantine-command/v1",
      command_id: "quarantine-resource-1",
      namespace: "colortrace-simulator",
      target: targets[0] as (typeof targets)[number],
      expected_resource_sha256: expectedResource,
      mode: "quarantine-and-install-approved-replacement",
    },
    frameCommand(targets[1] as (typeof targets)[number], 1),
    frameCommand(targets[2] as (typeof targets)[number], 2),
    frameCommand(targets[3] as (typeof targets)[number], 3),
    {
      schema: "simulator-targeted-rerender-command/v1",
      command_id: "rerender-derivative-1",
      namespace: "colortrace-simulator",
      target: targets[4] as (typeof targets)[number],
      job_id: "job-b-02",
      transform_id: "look/main/v1",
      source_id: "source-b-02",
      source_manifest_sha256: sourceManifest,
      source_png_sha256: sourcePng,
      expected_config_sha256: expectedConfig,
      expected_derivative_sha256: `sha256:${"6".repeat(64)}`,
      expected_derivative_display_sha256: `sha256:${"7".repeat(64)}`,
      lineage_parent_artifact_id: "artifact-b-02",
    },
  ];
  const commandsSha256 = documentSha256(
    commandSummaries.map((summary) => ({
      ...summary,
      action_envelope: sharedActionBindings,
    })),
  );
  return {
    schema: "colortrace-demo-investigation-proof/v2",
    packet_id: legacy.packet_id,
    packet_sha256: legacy.packet_sha256,
    status: "resolved",
    adjudication: {
      model_role: "evidence-selection-and-advisory-drafting",
      model_authority: "advisory-only",
      validator_role: "deterministic-claim-adjudication",
      decision_mode: "deterministic-validation",
    },
    model_invocations: legacy.model_invocations,
    comparison: {
      renders: [
        {
          job_id: "job-a-02",
          worker_id: "worker-a",
          status: "succeeded",
          nominal_config_sha256: expectedConfig,
          resolved_lut_sha256: replacementResource,
        },
        {
          job_id: "job-b-02",
          worker_id: "worker-b",
          status: "succeeded",
          nominal_config_sha256: expectedConfig,
          resolved_lut_sha256: expectedResource,
        },
      ],
      nominal_config_match: true,
      resolved_lut_match: false,
    },
    claims: [
      {
        claim_id: `claim:${"1".repeat(64)}`,
        claim_type: "causal-resource",
        subject: { kind: "resource-sha256", value: expectedResource },
        state: "confirmed",
        reason_codes: ["causal-resource-confirmed"],
        evidence_ids: evidence.map((item) => item.evidence_id),
        source_validator_result_id: sourceValidatorResultId,
      },
      {
        claim_id: `claim:${"2".repeat(64)}`,
        claim_type: "nominal-config",
        subject: { kind: "config-sha256", value: expectedConfig },
        state: "rejected",
        reason_codes: ["nominal-config-authoritatively-rejected"],
        evidence_ids: evidence.slice(0, 2).map((item) => item.evidence_id),
        source_validator_result_id: sourceValidatorResultId,
      },
      {
        claim_id: `claim:${"3".repeat(64)}`,
        claim_type: "worker-alone",
        subject: { kind: "worker-id", value: "worker-b" },
        state: "rejected",
        reason_codes: ["worker-alone-authoritatively-rejected"],
        evidence_ids: evidence.slice(1, 3).map((item) => item.evidence_id),
        source_validator_result_id: sourceValidatorResultId,
      },
    ],
    evidence,
    validators,
    scope: legacy.scope as DemoInvestigationProofV2["scope"],
    budget_use: legacy.budget_use,
    plan: {
      ...legacy.plan,
      exclusions_sha256: `sha256:${"f".repeat(64)}`,
      commands_sha256: commandsSha256,
      targets,
      protected_exclusions: protectedExclusions,
      shared_action_bindings: sharedActionBindings,
      command_summaries: commandSummaries,
    },
  };
}

export function investigationProof(): DemoInvestigationProofV3 {
  const v2 = investigationProofV2();
  const retrievedAt = "2026-08-23T12:00:01.000Z";
  const modelInvocations = v2.model_invocations.map((invocation, index) => {
    const derivationSha256 = `sha256:${String(index + 3).repeat(64)}`;
    return {
      invocation_id: `model-invocation:${derivationSha256.slice("sha256:".length)}`,
      turn_kind: invocation.turn_kind,
      attempt: 1,
      model: invocation.model,
      location: "global",
      framework: invocation.framework,
      framework_version: "2.6.3",
      client_version: "2.17.0",
      prompt_version:
        invocation.turn_kind === "evidence-selection"
          ? "evidence-selection/v1"
          : "response-drafting/v1",
      policy_version: "bounded-investigation/v1",
      inventory_sha256: invocation.inventory_sha256,
      normalized_input_sha256: `sha256:${String(index + 1).repeat(64)}`,
      input_evidence_ids:
        invocation.turn_kind === "response-drafting"
          ? v2.evidence.map((item) => item.evidence_id)
          : [],
      output_sha256: invocation.output_sha256,
      latency_ms: 120 + index,
      usage: {
        input_tokens: index === 0 ? 60 : 40,
        output_tokens: index === 0 ? 0 : 20,
        model_calls: 1,
        unobserved_model_calls: 0,
      },
      result_class: invocation.result_class,
      error_code: null,
      trace_id: invocation.trace_id,
      derivation_sha256: derivationSha256,
    };
  });
  return {
    ...v2,
    schema: "colortrace-demo-investigation-proof/v3",
    claims: [
      ...v2.claims,
      {
        claim_id: `claim:${"4".repeat(64)}`,
        claim_type: "distractor",
        subject: { kind: "event-id", value: "distractor-01" },
        state: "rejected",
        reason_codes: ["distractor-authoritatively-rejected"],
        evidence_ids: v2.evidence.slice(0, 2).map((item) => item.evidence_id),
        source_validator_result_id: v2.validators[0]?.result_id as string,
      },
    ],
    model_invocations: modelInvocations,
    evidence: v2.evidence.map((item, index) => ({
      ...item,
      source: {
        kind: "grafana-mcp",
        server: "mcp-grafana",
        server_version: "1.1.0",
        server_commit: "007e8d82154899a28e19e8dfe9c2bb4452c5211a",
        binary_sha256: "5f6b1492ff35f92506e17310b3ea8b689c3f04c1fe0f6d4cc0a1f6e50bd52d93",
        mcp_sdk_version: "1.29.0",
        mcp_protocol_version: "2025-06-18",
        tool: item.tool,
        tool_input_schema_sha256: String(index + 4).repeat(64),
        tool_annotations_sha256: (index + 8).toString(16).repeat(64),
        inventory_version: item.inventory_sha256,
      },
      timing: {
        source_time: index === 0 ? null : "2026-08-23T12:00:00.000Z",
        event_time: "2026-08-23T12:00:00.000Z",
        retrieved_at: retrievedAt,
      },
    })),
    model_advisory: {
      trust: "untrusted-model-output",
      summary:
        "The compared renders share one declared configuration, while their resolved LUT content differs.",
      evidence_ids: v2.evidence.map((item) => item.evidence_id),
      output_sha256: modelInvocations[1]?.output_sha256 as string,
    },
    finalized_at: "2026-08-23T12:00:02.000Z",
  };
}

export function scenarioPreview(): DemoScenarioPreview {
  const comparison = investigationProofV2().comparison;
  return {
    schema: "colortrace-demo-scenario-preview/v1",
    scenario_id: "ct-shadowed-lut-v1:canonical",
    source_commit: "a".repeat(40),
    build_sha256: BUILD_DIGEST,
    comparison,
    visual_comparison: Object.fromEntries(
      (["expected", "observed", "diff"] as const).map((kind) => [
        kind,
        {
          href: `/v1/demo/visuals/${kind}`,
          sha256: VISUAL_DIGESTS[kind],
          media_type: "image/png",
          label: "illustrative-authored-fixture",
        },
      ]),
    ) as Readonly<
      Record<DemoPreviewVisualKind, DemoScenarioPreview["visual_comparison"][DemoPreviewVisualKind]>
    >,
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

function timelineForPhase(phase: DemoRun["phase"]): readonly DemoTimelineItem[] {
  const timeline: DemoTimelineItem[] = [
    {
      run_version: 1,
      kind: "run-created",
      phase: "preparing",
      recorded_at: "2026-08-23T12:00:00.000Z",
    },
  ];
  if (phase === "preparing") return timeline;
  timeline.push({
    run_version: 2,
    kind: "investigation-completed",
    phase: "awaiting-approval",
    recorded_at: "2026-08-23T12:00:02.000Z",
  });
  if (phase === "awaiting-approval") return timeline;
  if (phase === "unresolved") {
    timeline.push({
      run_version: 3,
      kind: "plan-rejected",
      phase: "unresolved",
      recorded_at: "2026-08-23T12:01:00.000Z",
    });
    return timeline;
  }
  timeline.push({
    run_version: 3,
    kind: "approval-submitted",
    phase: "executing",
    recorded_at: "2026-08-23T12:01:00.000Z",
  });
  if (phase === "executing") return timeline;
  timeline.push({
    run_version: 4,
    kind: "recovery-verified",
    phase: "awaiting-closure",
    recorded_at: "2026-08-23T12:02:00.000Z",
  });
  if (phase === "awaiting-closure") return timeline;
  if (phase === "expired") {
    timeline.push({
      run_version: 5,
      kind: "run-expired",
      phase: "expired",
      recorded_at: "2026-08-23T12:15:00.000Z",
    });
    return timeline;
  }
  timeline.push({
    run_version: 5,
    kind: "closure-submitted",
    phase: "closing",
    recorded_at: "2026-08-23T12:02:30.000Z",
  });
  if (phase === "closing") return timeline;
  timeline.push({
    run_version: 6,
    kind: "recovery-closed",
    phase: "closed",
    recorded_at: "2026-08-23T12:03:00.000Z",
  });
  return timeline;
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
  const timeline = timelineForPhase(phase);
  const schema = overrides.schema ?? "colortrace-demo-run/v2";
  const selectedVersion =
    phase === "preparing"
      ? 1
      : phase === "awaiting-approval"
        ? 2
        : phase === "executing"
          ? 3
          : phase === "awaiting-closure"
            ? 4
            : phase === "closing"
              ? 5
              : timeline.length;
  const result = {
    schema,
    run_id: RUN_ID,
    incident_id: "incident-demo-11111111111111111111111111111111",
    scenario_id: "ct-shadowed-lut-v1:canonical",
    source_commit: "a".repeat(40),
    build_sha256: BUILD_DIGEST,
    phase,
    version: selectedVersion,
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
    ...(schema === "colortrace-demo-run/v2" ? { timeline } : {}),
    terminal,
    terminal_reason: terminal ? (phase === "closed" ? "recovery-closed" : "lease-expired") : null,
    receipt_href: terminal ? `/v1/demo/runs/${RUN_ID}/receipt` : null,
    reset: false,
    ...(phase === "awaiting-approval" ? { approval_nonce: NONCE } : {}),
    ...overrides,
  };
  return result as DemoRun;
}

export function demoRunV1(
  phase: DemoRunV1["phase"] = "awaiting-approval",
  overrides: Partial<DemoRunV1> = {},
): DemoRunV1 {
  const run = demoRun(phase, { ...overrides, schema: "colortrace-demo-run/v1" });
  const { timeline: _timeline, ...legacy } = run as DemoRun & {
    readonly timeline?: readonly DemoTimelineItem[];
  };
  return legacy as DemoRunV1;
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

export function demoRejectedRun(reason: DemoRejectionReason = "unsafe-scope"): DemoRun {
  return demoRun("unresolved", {
    version: 3,
    terminal_reason: `plan-rejected-${reason}`,
  });
}

export function demoRejectedReceipt(
  reason: DemoRejectionReason = "unsafe-scope",
  visualDigests: Readonly<Record<DemoVisualKind, string>> = VISUAL_DIGESTS,
): DemoReceipt {
  return sealDemoReceipt({
    schema: "colortrace-demo-receipt/v1",
    run_id: RUN_ID,
    incident_id: "incident-demo-11111111111111111111111111111111",
    scenario_id: "ct-shadowed-lut-v1:canonical",
    source_commit: "a".repeat(40),
    build_sha256: BUILD_DIGEST,
    provenance: buildProvenance(),
    phase: "unresolved",
    run_version: 3,
    created_at: "2026-08-23T12:00:00.000Z",
    terminal_at: "2026-08-23T12:02:00.000Z",
    reason_code: `plan-rejected-${reason}`,
    bindings: {
      incident_version: 7,
      plan_version: 3,
      plan_sha256: PLAN_DIGEST,
      target_sha256: TARGET_DIGEST,
      outcome_id: null,
      outcome_sha256: null,
      workflow_id: null,
      workflow_version: null,
      packet_id: null,
      packet_sha256: null,
      closure_id: null,
      closure_sha256: null,
    },
    proofs: [{ stage: "investigation", sha256: documentSha256(investigationProof()) }],
    visuals: (["diff", "expected", "observed"] as const).map((kind) => ({
      kind,
      sha256: visualDigests[kind],
    })),
  });
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
