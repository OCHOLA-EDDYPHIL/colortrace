import { createHash } from "node:crypto";

import { describe, expect, it, vi } from "vitest";

import {
  CANONICAL_DEMO_SCENARIO,
  canonicalJsonBytes,
  createDemoAdapter,
  DemoApiError,
  type DemoReceipt,
  type DemoRun,
  verifyDemoReceiptIntegrity,
} from "../src/demo-api.ts";
import {
  BUILD_DIGEST,
  demoReceipt,
  demoRejectedRun,
  demoReset,
  demoRun,
  demoRunV1,
  executionProof,
  investigationProof,
  investigationProofV1,
  investigationProofV2,
  NONCE,
  RUN_ID,
  scenarioPreview,
  sealDemoReceipt,
  VISUAL_DIGESTS,
} from "./demo-fixtures.ts";

const DIGEST = VISUAL_DIGESTS.expected;

function runResponse(overrides: Partial<DemoRun> = {}): DemoRun {
  return demoRun("awaiting-approval", overrides);
}

function digest(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJsonBytes(value)).digest("hex")}`;
}

function receiptBody(receipt: DemoReceipt): Omit<DemoReceipt, "receipt_id" | "receipt_sha256"> {
  return Object.fromEntries(
    Object.entries(receipt).filter(([key]) => key !== "receipt_id" && key !== "receipt_sha256"),
  ) as Omit<DemoReceipt, "receipt_id" | "receipt_sha256">;
}

describe("demo API adapter", () => {
  it("matches Python canonical JSON and finalized document digest vectors", () => {
    const canonicalVector = {
      z: "line\n\t\0é😀",
      a: [1, true, null],
      nested: { β: "雪" },
    };
    const codePointOrderVector = { "\ue000": "bmp", "😀": "astral" };

    expect(digest(canonicalVector)).toBe(
      "sha256:0247d3f9635dc09a8f2fa7b7a8046685d186c87a8b9b48ed6e18a15a1edd5264",
    );
    expect(digest(codePointOrderVector)).toBe(
      "sha256:4874d36535a1b5dfdad7f2b3af83f87debd2f0795ae7d2d09447e17223c42dd0",
    );
    expect(digest(investigationProofV1())).toBe(
      "sha256:84f71a42568b86c26c56c3eb0f1f9fd64adfdef38e09acf4d9a7b709d30e093d",
    );
    expect(digest(executionProof())).toBe(
      "sha256:2f3cbaad549894daf44046ea9d107a5cad8f80ecbc0b104670c030a019946446",
    );
    expect(BUILD_DIGEST).toBe(
      "sha256:a5ff48f8c5356c7c6dc51fb9b3578fcc63e786cde2a3db789b2d11daf9e660bd",
    );
    expect(demoReceipt().receipt_sha256).toBe(
      "sha256:62f764fbcd42cde727edce70a4dec92d304e167a38b9e651b2ab8999a6486187",
    );
  });

  it("starts only the canonical scenario with same-origin JSON", async () => {
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify(runResponse()), {
          headers: { "Content-Type": "application/json" },
          status: 201,
        }),
    );
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example/app",
      fetch: fetchMock,
    });

    const run = await adapter.start({ approval_nonce: NONCE, idempotency_key: "demo-start-1" });

    expect(run.run_id).toBe(RUN_ID);
    const [input, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(input)).toBe("https://colortrace.example/v1/demo/runs");
    expect(init).toMatchObject({ credentials: "same-origin", method: "POST", redirect: "error" });
    expect(JSON.parse(String(init?.body))).toEqual({
      schema: "colortrace-demo-run-request/v2",
      scenario_id: CANONICAL_DEMO_SCENARIO,
      approval_nonce: NONCE,
      idempotency_key: "demo-start-1",
    });
  });

  it("loads and verifies the authored comparison without starting a run", async () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1]);
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      const url = String(input);
      expect(init?.method).toBe("GET");
      if (url === "https://colortrace.example/v1/demo") {
        return new Response(JSON.stringify(scenarioPreview()), {
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(bytes, {
        headers: {
          "Content-Type": "image/png",
          "X-Content-SHA256": VISUAL_DIGESTS.expected,
        },
      });
    });
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example/workspace",
      fetch: fetchMock,
      createObjectUrl: () => "blob:preview",
      sha256: async () => VISUAL_DIGESTS.expected,
    });

    const preview = await adapter.preview();
    const visual = await adapter.previewVisual(
      "expected",
      preview.visual_comparison.expected.sha256,
    );

    expect(preview.comparison.renders).toHaveLength(2);
    expect(visual).toEqual({
      kind: "expected",
      sha256: VISUAL_DIGESTS.expected,
      src: "blob:preview",
    });
    expect(fetchMock.mock.calls.map(([input]) => String(input))).toEqual([
      "https://colortrace.example/v1/demo",
      "https://colortrace.example/v1/demo/visuals/expected",
    ]);
    expect(fetchMock.mock.calls.every(([, init]) => init?.method === "GET")).toBe(true);
  });

  it("rejects a preview with extra fields or noncanonical visual links", async () => {
    const preview = scenarioPreview();
    const responses = [
      { ...preview, run_id: RUN_ID },
      {
        ...preview,
        visual_comparison: {
          ...preview.visual_comparison,
          diff: { ...preview.visual_comparison.diff, href: "/v1/demo/visuals/expected" },
        },
      },
    ];
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(responses.shift()), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(adapter.preview()).rejects.toMatchObject({ code: "demo-response-invalid" });
    await expect(adapter.preview()).rejects.toMatchObject({ code: "demo-response-invalid" });
  });

  it("rejects a start response that does not return the client nonce", async () => {
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(runResponse({ approval_nonce: "m".repeat(32) })), {
          headers: { "Content-Type": "application/json" },
          status: 201,
        }),
    });

    await expect(
      adapter.start({ approval_nonce: NONCE, idempotency_key: "demo-start-1" }),
    ).rejects.toMatchObject({ code: "demo-response-invalid" });
  });

  it("reads stored v1 proofs but requires the v3 review projection from a new run", async () => {
    const legacy = demoRunV1("awaiting-approval", {
      approval_nonce: undefined,
      investigation: investigationProofV1(),
    });
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: vi.fn(
        async () =>
          new Response(JSON.stringify(legacy), {
            headers: { "Content-Type": "application/json" },
          }),
      ),
    });

    await expect(adapter.get(RUN_ID)).resolves.toMatchObject({
      investigation: { schema: "colortrace-demo-investigation-proof/v1" },
    });
    await expect(
      adapter.start({ approval_nonce: NONCE, idempotency_key: "demo-start-legacy" }),
    ).rejects.toMatchObject({ code: "demo-response-invalid" });
  });

  it("reads a stored terminal v1 run without applying v2 review invariants", async () => {
    const investigation = investigationProofV1();
    const legacy = demoRunV1("closed", {
      investigation: {
        ...investigation,
        plan: { ...investigation.plan, status: "approved" },
      },
    });
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(legacy), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(adapter.get(RUN_ID)).resolves.toMatchObject({
      phase: "closed",
      terminal: true,
      investigation: {
        schema: "colortrace-demo-investigation-proof/v1",
        plan: { status: "approved" },
      },
    });
  });

  it("continues to read a stored v2 investigation inside a legacy run", async () => {
    const storedInvestigation = investigationProofV2();
    const legacy = demoRunV1("awaiting-approval", {
      approval_nonce: undefined,
      investigation: {
        ...storedInvestigation,
        claims: storedInvestigation.claims.slice(0, 2),
      },
    });
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(legacy), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(adapter.get(RUN_ID)).resolves.toMatchObject({
      schema: "colortrace-demo-run/v1",
      investigation: {
        schema: "colortrace-demo-investigation-proof/v2",
        claims: [{ claim_type: "causal-resource" }, { claim_type: "nominal-config" }],
      },
    });
  });

  it("rejects a stored v1 run whose approval and investigation bindings diverge", async () => {
    const investigation = investigationProofV1();
    const legacy = demoRunV1("awaiting-approval", {
      approval_nonce: undefined,
      investigation: {
        ...investigation,
        plan: { ...investigation.plan, target_sha256: `sha256:${"f".repeat(64)}` },
      },
    });
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(legacy), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(adapter.get(RUN_ID)).rejects.toMatchObject({ code: "demo-response-invalid" });
  });

  it("rejects malformed or unsafe v3 review projections", async () => {
    const response = runResponse();
    const investigation = investigationProof();
    const malformed = [
      {
        ...investigation,
        comparison: {
          ...investigation.comparison,
          renders: investigation.comparison.renders.map((render) => ({
            ...render,
            resolved_lut_sha256: investigation.comparison.renders[0]?.resolved_lut_sha256,
          })),
        },
      },
      {
        ...investigation,
        evidence: investigation.evidence.map((item, index) =>
          index === 0 ? { ...item, display_excerpt: "unsafe\u0000text" } : item,
        ),
      },
      {
        ...investigation,
        plan: {
          ...investigation.plan,
          command_summaries: investigation.plan.command_summaries.slice(0, 4),
        },
      },
      {
        ...investigation,
        claims: investigation.claims.map((claim, index) =>
          index === 0
            ? {
                ...claim,
                source_validator_result_id: `validation-result:${"f".repeat(64)}`,
              }
            : claim,
        ),
      },
      { ...investigation, packet_id: `response-packet:${"f".repeat(64)}` },
      {
        ...investigation,
        validators: investigation.validators.map((validator) => ({
          ...validator,
          result_id: `validator-result:${validator.derivation_sha256.slice("sha256:".length)}`,
        })),
        claims: investigation.claims.map((claim) => ({
          ...claim,
          source_validator_result_id: `validator-result:${investigation.validators[0]?.derivation_sha256.slice("sha256:".length)}`,
        })),
      },
      {
        ...investigation,
        plan: { ...investigation.plan, commands_sha256: `sha256:${"f".repeat(64)}` },
      },
    ];
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify({ ...response, investigation: malformed.shift() }), {
          headers: { "Content-Type": "application/json" },
        }),
    );
    const adapter = createDemoAdapter({ baseUrl: "https://colortrace.example", fetch: fetchMock });

    for (const idempotencyKey of [
      "bad-comparison",
      "bad-evidence",
      "bad-plan",
      "bad-validator-reference",
      "bad-packet-relation",
      "bad-validator-relation",
      "bad-command-digest",
    ]) {
      await expect(
        adapter.start({ approval_nonce: NONCE, idempotency_key: idempotencyKey }),
      ).rejects.toMatchObject({ code: "demo-response-invalid" });
    }
  });

  it("rejects altered MCP provenance, advisory trust, model usage, and evidence timing", async () => {
    const response = runResponse();
    const investigation = investigationProof();
    const malformed = [
      {
        ...investigation,
        evidence: investigation.evidence.map((item, index) =>
          index === 0 ? { ...item, source: { ...item.source, server: "lookalike-grafana" } } : item,
        ),
      },
      {
        ...investigation,
        evidence: investigation.evidence.map((item, index) =>
          index === 0
            ? {
                ...item,
                timing: { ...item.timing, retrieved_at: "2026-08-23T12:00:01Z" },
              }
            : item,
        ),
      },
      {
        ...investigation,
        model_advisory: { ...investigation.model_advisory, trust: "authoritative" },
      },
      {
        ...investigation,
        model_invocations: investigation.model_invocations.map((item, index) =>
          index === 0 ? { ...item, usage: { ...item.usage, unobserved_model_calls: 1 } } : item,
        ),
      },
    ];
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify({ ...response, investigation: malformed.shift() }), {
          headers: { "Content-Type": "application/json" },
          status: 201,
        }),
    });

    for (const idempotencyKey of ["bad-source", "bad-time", "bad-trust", "bad-usage"]) {
      await expect(
        adapter.start({ approval_nonce: NONCE, idempotency_key: idempotencyKey }),
      ).rejects.toMatchObject({ code: "demo-response-invalid" });
    }
  });

  it("rejects a fresh v3 proof with flipped, missing, or misreasoned canonical claims", async () => {
    const response = runResponse();
    const investigation = investigationProof();
    const malformed = [
      {
        ...investigation,
        claims: investigation.claims.map((claim) =>
          claim.claim_type === "nominal-config" ? { ...claim, state: "confirmed" } : claim,
        ),
      },
      {
        ...investigation,
        claims: investigation.claims.filter((claim) => claim.claim_type !== "distractor"),
      },
      {
        ...investigation,
        claims: investigation.claims.map((claim) =>
          claim.claim_type === "worker-alone"
            ? { ...claim, reason_codes: ["insufficient-evidence"] }
            : claim,
        ),
      },
    ];
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify({ ...response, investigation: malformed.shift() }), {
          headers: { "Content-Type": "application/json" },
          status: 201,
        }),
    });

    for (const idempotencyKey of ["flipped-claim", "missing-claim", "wrong-claim-reason"]) {
      await expect(
        adapter.start({ approval_nonce: NONCE, idempotency_key: idempotencyKey }),
      ).rejects.toMatchObject({ code: "demo-response-invalid" });
    }
  });

  it("requires a contiguous, causal server timeline on run v2", async () => {
    const response = runResponse();
    if (response.schema !== "colortrace-demo-run/v2") throw new Error("missing timeline fixture");
    const malformed = [
      response.timeline.slice(1),
      response.timeline.map((item, index) => (index === 1 ? { ...item, run_version: 3 } : item)),
      response.timeline.map((item, index) =>
        index === 1 ? { ...item, kind: "approval-submitted" } : item,
      ),
      response.timeline.map((item, index) =>
        index === 1 ? { ...item, recorded_at: "2026-08-23T11:59:59.000Z" } : item,
      ),
      response.timeline.map((item, index) => (index === 0 ? { ...item, synthetic: true } : item)),
    ];
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify({ ...response, timeline: malformed.shift() }), {
          headers: { "Content-Type": "application/json" },
          status: 201,
        }),
    });

    for (const idempotencyKey of ["gap", "version", "causal", "clock", "extra"]) {
      await expect(
        adapter.start({ approval_nonce: NONCE, idempotency_key: idempotencyKey }),
      ).rejects.toMatchObject({ code: "demo-response-invalid" });
    }
  });

  it("posts an exact bound rejection and accepts its terminal run", async () => {
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify(demoRejectedRun("unsafe-scope")), {
          headers: { "Content-Type": "application/json" },
        }),
    );
    const adapter = createDemoAdapter({ baseUrl: "https://colortrace.example", fetch: fetchMock });
    const request = {
      schema: "colortrace-demo-rejection-request/v1" as const,
      approval_nonce: NONCE,
      expected_run_version: 2,
      expected_incident_version: 7,
      expected_plan_version: 3,
      expected_plan_sha256: `sha256:${"1".repeat(64)}`,
      expected_target_sha256: `sha256:${"2".repeat(64)}`,
      reason_code: "unsafe-scope" as const,
      idempotency_key: "demo-reject-1",
    };

    await expect(adapter.reject(RUN_ID, request)).resolves.toMatchObject({
      phase: "unresolved",
      terminal: true,
      terminal_reason: "plan-rejected-unsafe-scope",
    });
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
      `https://colortrace.example/v1/demo/runs/${RUN_ID}/reject`,
    );
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual(request);
  });

  it("rejects an investigation proof that violates the canonical facade bindings", async () => {
    const response = runResponse();
    const investigation = response.investigation as NonNullable<DemoRun["investigation"]>;
    const malformed = {
      ...response,
      investigation: {
        ...investigation,
        scope: { ...investigation.scope, affected_count: 3 },
      },
    };
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(malformed), {
          headers: { "Content-Type": "application/json" },
          status: 201,
        }),
    });

    await expect(
      adapter.start({ approval_nonce: NONCE, idempotency_key: "demo-start-1" }),
    ).rejects.toMatchObject({ code: "demo-response-invalid" });
  });

  it.each(["stale", "unresolved"] as const)(
    "rejects a resolved investigation whose evidence is %s",
    async (freshness) => {
      const response = runResponse();
      const investigation = response.investigation as NonNullable<DemoRun["investigation"]>;
      const malformed = {
        ...response,
        investigation: {
          ...investigation,
          evidence: investigation.evidence.map((item, index) =>
            index === 0 ? { ...item, freshness } : item,
          ),
        },
      };
      const adapter = createDemoAdapter({
        baseUrl: "https://colortrace.example",
        fetch: async () =>
          new Response(JSON.stringify(malformed), {
            headers: { "Content-Type": "application/json" },
            status: 201,
          }),
      });

      await expect(
        adapter.start({ approval_nonce: NONCE, idempotency_key: "demo-start-1" }),
      ).rejects.toMatchObject({ code: "demo-response-invalid" });
    },
  );

  it("rejects an execution proof with an incomplete recovery check set", async () => {
    const response = demoRun("awaiting-closure");
    const execution = response.execution as NonNullable<DemoRun["execution"]>;
    const malformed = {
      ...response,
      execution: {
        ...execution,
        recovery: { ...execution.recovery, checks: execution.recovery.checks.slice(0, 6) },
      },
    };
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(malformed), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(
      adapter.approve(RUN_ID, {
        schema: "colortrace-demo-approval-request/v1",
        approval_nonce: NONCE,
        approval_phrase: "APPROVE_COLORTRACE_SIMULATOR_ACTION",
        expected_run_version: 2,
        expected_incident_version: 7,
        expected_plan_version: 3,
        expected_plan_sha256: `sha256:${"1".repeat(64)}`,
        expected_target_sha256: `sha256:${"2".repeat(64)}`,
        idempotency_key: "demo-approve-1",
      }),
    ).rejects.toMatchObject({ code: "demo-response-invalid" });
  });

  it("hashes the exact PNG bytes before exposing an object URL", async () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3]);
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        new Response(bytes, {
          headers: { "Content-Type": "image/png", "X-Content-SHA256": DIGEST },
        }),
    );
    const createObjectUrl = vi.fn(() => "blob:verified-image");
    const revokeObjectUrl = vi.fn();
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: fetchMock,
      createObjectUrl,
      revokeObjectUrl,
      sha256: async () => DIGEST,
    });

    const visual = await adapter.visual(RUN_ID, "expected", DIGEST);
    adapter.releaseVisual(visual);

    expect(visual).toEqual({ kind: "expected", sha256: DIGEST, src: "blob:verified-image" });
    expect(createObjectUrl).toHaveBeenCalledOnce();
    expect(revokeObjectUrl).toHaveBeenCalledWith("blob:verified-image");
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(
      `https://colortrace.example/v1/demo/runs/${RUN_ID}/visuals/expected`,
    );
  });

  it("withholds a visual when the response digest and bytes disagree", async () => {
    const bytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
    const createObjectUrl = vi.fn(() => "blob:must-not-exist");
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(bytes, {
          headers: { "Content-Type": "image/png", "X-Content-SHA256": DIGEST },
        }),
      createObjectUrl,
      sha256: async () => `sha256:${"f".repeat(64)}`,
    });

    await expect(adapter.visual(RUN_ID, "observed")).rejects.toMatchObject({
      code: "demo-visual-digest-conflict",
    });
    expect(createObjectUrl).not.toHaveBeenCalled();
  });

  it("rejects a cross-run response and preserves an active-run identity", async () => {
    const otherRun = "demo-run-22222222222222222222222222222222";
    const responses = [
      new Response(JSON.stringify(runResponse({ run_id: otherRun, approval_nonce: undefined })), {
        headers: { "Content-Type": "application/json" },
      }),
      new Response(JSON.stringify({ code: "demo-active-run-exists", run_id: RUN_ID }), {
        headers: { "Content-Type": "application/json" },
        status: 409,
      }),
    ];
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: vi.fn(async () => responses.shift() as Response),
    });

    await expect(adapter.get(RUN_ID)).rejects.toMatchObject({ code: "demo-response-invalid" });
    const error = await adapter
      .start({ approval_nonce: NONCE, idempotency_key: "demo-start-2" })
      .catch((reason: unknown) => reason);
    expect(error).toBeInstanceOf(DemoApiError);
    expect(error).toMatchObject({ code: "demo-active-run-exists", runId: RUN_ID, status: 409 });
  });

  it("accepts the facade reset acknowledgement instead of treating it as a run", async () => {
    const fetchMock = vi.fn<typeof fetch>(
      async () =>
        new Response(JSON.stringify(demoReset()), {
          headers: { "Content-Type": "application/json" },
        }),
    );
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: fetchMock,
    });

    await expect(adapter.reset(RUN_ID, 6, "demo-reset-1")).resolves.toMatchObject({
      schema: "colortrace-demo-reset/v1",
      run_id: RUN_ID,
      reset: true,
      restoration: { schema: "simulator-authored-scenario-reset/v1", generation: 1 },
    });
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      schema: "colortrace-demo-reset-request/v1",
      expected_run_version: 6,
      idempotency_key: "demo-reset-1",
    });
  });

  it("parses receipt proof bindings and build provenance", async () => {
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(demoReceipt()), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    const receipt = await adapter.receipt(RUN_ID);

    expect(receipt.proofs.map((proof) => proof.stage)).toEqual(["execution", "investigation"]);
    expect(receipt.provenance).toMatchObject({
      schema: "colortrace-demo-build-provenance/v1",
      source_commit: "a".repeat(40),
    });
    await expect(verifyDemoReceiptIntegrity(receipt, demoRun("closed"))).resolves.toBe(true);
  });

  it("rejects a one-bit proof mismatch even when the receipt envelope is resealed", async () => {
    const receipt = demoReceipt();
    const proofMismatch = sealDemoReceipt({
      ...receiptBody(receipt),
      proofs: receipt.proofs.map((proof) =>
        proof.stage === "execution"
          ? {
              ...proof,
              sha256: `${proof.sha256.slice(0, -1)}${proof.sha256.endsWith("0") ? "1" : "0"}`,
            }
          : proof,
      ),
    });

    await expect(verifyDemoReceiptIntegrity(proofMismatch, demoRun("closed"))).resolves.toBe(false);
  });

  it("rejects a provenance/build mismatch even when the receipt body is resealed", async () => {
    const receipt = demoReceipt();
    const mismatch = sealDemoReceipt({
      ...receiptBody(receipt),
      provenance: { ...receipt.provenance, staging_generation: "candidate-2" },
    });
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(mismatch), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(adapter.receipt(RUN_ID)).rejects.toMatchObject({
      code: "demo-response-invalid",
    });
  });

  it("rejects a one-bit receipt-body mismatch", async () => {
    const receipt = demoReceipt();
    const mismatch = {
      ...receipt,
      reason_code: receipt.reason_code.endsWith("d") ? "recovery-closee" : "recovery-closed",
    };
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(mismatch), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(adapter.receipt(RUN_ID)).rejects.toMatchObject({
      code: "demo-response-invalid",
    });
  });

  it("rejects malformed reset restoration and receipt proof records", async () => {
    const malformedReset = {
      ...demoReset(),
      restoration: { ...demoReset().restoration, generation: 2 },
    };
    const malformedReceipt = {
      ...demoReceipt(),
      proofs: [{ stage: "investigation" }],
    };
    const responses = [malformedReset, malformedReceipt];
    const adapter = createDemoAdapter({
      baseUrl: "https://colortrace.example",
      fetch: async () =>
        new Response(JSON.stringify(responses.shift()), {
          headers: { "Content-Type": "application/json" },
        }),
    });

    await expect(adapter.reset(RUN_ID, 6, "demo-reset-1")).rejects.toMatchObject({
      code: "demo-response-invalid",
    });
    await expect(adapter.receipt(RUN_ID)).rejects.toMatchObject({
      code: "demo-response-invalid",
    });
  });
});
