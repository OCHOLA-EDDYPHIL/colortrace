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
  demoReset,
  demoRun,
  executionProof,
  investigationProof,
  NONCE,
  RUN_ID,
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
    expect(digest(investigationProof())).toBe(
      "sha256:ab19b7e0decc3376174e730fb16594897341f47b4d00ea3741aaa64d39f160fc",
    );
    expect(digest(executionProof())).toBe(
      "sha256:2f3cbaad549894daf44046ea9d107a5cad8f80ecbc0b104670c030a019946446",
    );
    expect(BUILD_DIGEST).toBe(
      "sha256:a5ff48f8c5356c7c6dc51fb9b3578fcc63e786cde2a3db789b2d11daf9e660bd",
    );
    expect(demoReceipt().receipt_sha256).toBe(
      "sha256:66b90d1224562b615e887852b428946427672b89f89b1dee13daf8d1c2e19896",
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
