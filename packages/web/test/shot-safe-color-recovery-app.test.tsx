import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type DemoAdapter,
  DemoApiError,
  type DemoReceipt,
  type DemoVisualKind,
} from "../src/demo-api.ts";
import { ShotSafeColorRecoveryApp } from "../src/shot-safe-color-recovery-app.tsx";
import {
  demoReceipt,
  demoRejectedReceipt,
  demoRejectedRun,
  demoReset,
  demoRun,
  NONCE,
  OUTCOME_DIGEST,
  PACKET_DIGEST,
  PLAN_DIGEST,
  RUN_ID,
  sealDemoReceipt,
  TARGET_DIGEST,
  VISUAL_DIGESTS,
} from "./demo-fixtures.ts";

function memoryStorage(initial: Readonly<Record<string, string>> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: vi.fn((key: string) => values.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => values.set(key, value)),
    removeItem: vi.fn((key: string) => values.delete(key)),
  };
}

function adapterFixture() {
  const adapter: DemoAdapter = {
    start: vi.fn(async (request) =>
      demoRun("awaiting-approval", { approval_nonce: request.approval_nonce }),
    ),
    get: vi.fn(async () => demoRun("awaiting-approval", { approval_nonce: undefined })),
    approve: vi.fn(async () => demoRun("awaiting-closure")),
    reject: vi.fn(async (_runId, request) => demoRejectedRun(request.reason_code)),
    close: vi.fn(async () => demoRun("closed")),
    reset: vi.fn(async () => demoReset()),
    receipt: vi.fn(async () => demoReceipt()),
    visual: vi.fn(async (_runId: string, kind: DemoVisualKind) => ({
      kind,
      sha256: VISUAL_DIGESTS[kind],
      src: `data:image/png;base64,${kind}`,
    })),
    releaseVisual: vi.fn(),
  };
  return adapter;
}

async function decodeRenderedImages(): Promise<void> {
  await act(async () => {
    for (const image of document.querySelectorAll("img")) fireEvent.load(image);
    await Promise.resolve();
  });
}

beforeEach(() => {
  vi.spyOn(crypto, "randomUUID").mockReturnValue(
    "nnnnnnnn-nnnn-nnnn-nnnn-nnnnnnnnnnnn" as `${string}-${string}-${string}-${string}-${string}`,
  );
  Object.defineProperty(HTMLImageElement.prototype, "decode", {
    configurable: true,
    value: vi.fn(async () => undefined),
  });
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("shot-safe color recovery", () => {
  it("guides an exact approval through recovered output, closure, receipt, and reset", async () => {
    const adapter = adapterFixture();
    const storage = memoryStorage();
    vi.mocked(adapter.start).mockImplementation(async (request) => {
      expect(storage.values.get("colortrace.demo.approval-nonce")).toBe(request.approval_nonce);
      expect(storage.values.get("colortrace.demo.start-idempotency-key")).toBe(
        request.idempotency_key,
      );
      return demoRun("awaiting-approval", { approval_nonce: request.approval_nonce });
    });
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={storage} />);

    expect(screen.getByRole("heading", { name: /successful render can still be/u })).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(await screen.findByRole("heading", { name: "Expected versus observed" })).toBeVisible();
    expect(await screen.findByAltText("Declared expected output")).toBeVisible();
    expect(await screen.findByAltText(/Observed output with a visible color shift/u)).toBeVisible();
    await decodeRenderedImages();
    expect(
      screen.getByRole("heading", { name: "Same configuration, different resolved LUT" }),
    ).toBeVisible();
    expect(screen.getByText("Root cause confirmed")).toBeVisible();
    expect(screen.getByText("Declared configuration ruled out")).toBeVisible();
    expect(screen.getByText("Worker-only explanation rejected")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Recover only the affected work" })).toBeVisible();
    expect(screen.getByText("artifact-b-02-derivative", { exact: true })).toBeVisible();
    expect(screen.getByText("Rerender the affected derivative")).toBeVisible();

    const approveButton = screen.getByRole("button", { name: "Approve recovery action" });
    expect(approveButton).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Retype review nonce"), { target: { value: NONCE } });
    fireEvent.change(screen.getByLabelText("Type approval phrase"), {
      target: { value: "APPROVE_COLORTRACE_SIMULATOR_ACTION" },
    });
    fireEvent.click(
      screen.getByLabelText(
        /I approve only the displayed targets and keep the exclusions protected/u,
      ),
    );
    expect(approveButton).toBeEnabled();
    fireEvent.click(approveButton);

    expect(await screen.findByRole("heading", { name: "Recovered output" })).toBeVisible();
    expect(await screen.findByAltText("Recovered output")).toBeVisible();
    await decodeRenderedImages();
    expect(screen.getAllByText("Protected outputs verified.").length).toBeGreaterThan(0);
    expect(storage.values.has("colortrace.demo.approval-nonce")).toBe(false);
    fireEvent.click(screen.getByText("Technical proof and provenance", { exact: true }));
    expect(screen.getAllByText("query_loki_logs", { exact: true }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/gemini-3\.5-flash/u).length).toBeGreaterThan(0);
    expect(screen.getByText("post-action-telemetry-correlation", { exact: true })).toBeVisible();
    fireEvent.click(screen.getByLabelText(/I verified the recovered image/u));
    fireEvent.click(screen.getByRole("button", { name: "Verify and close recovery" }));

    expect(
      await screen.findByRole("heading", { name: "Recovery closed with a verified receipt" }),
    ).toBeVisible();
    expect(await screen.findByText("Recorded and verified")).toBeVisible();
    expect(storage.values.get("colortrace.demo.run-id")).toBe(RUN_ID);
    fireEvent.click(screen.getByRole("button", { name: "Reset for another run" }));

    expect(
      await screen.findByRole("heading", { name: /successful render can still be/u }),
    ).toBeVisible();
    expect(screen.getByText(/reset to authored generation 1/u)).toBeVisible();
    expect(adapter.approve).toHaveBeenCalledWith(
      RUN_ID,
      expect.objectContaining({
        approval_nonce: NONCE,
        approval_phrase: "APPROVE_COLORTRACE_SIMULATOR_ACTION",
        expected_run_version: 2,
        expected_incident_version: 7,
        expected_plan_version: 3,
        expected_plan_sha256: PLAN_DIGEST,
        expected_target_sha256: TARGET_DIGEST,
      }),
    );
    expect(adapter.close).toHaveBeenCalledWith(
      RUN_ID,
      expect.objectContaining({
        expected_run_version: 4,
        expected_packet_sha256: PACKET_DIGEST,
        expected_outcome_sha256: OUTCOME_DIGEST,
      }),
    );
    expect(adapter.reset).toHaveBeenCalledWith(RUN_ID, 6, expect.stringMatching(/^demo-reset-/u));
    expect(adapter.start).toHaveBeenCalledWith({
      approval_nonce: NONCE,
      idempotency_key: expect.stringMatching(/^demo-start-/u),
    });
  }, 15_000);

  it("does not let an older poll response reverse an accepted recovery", async () => {
    const adapter = adapterFixture();
    let resolvePoll: ((run: ReturnType<typeof demoRun>) => void) | undefined;
    vi.mocked(adapter.start).mockResolvedValue(
      demoRun("awaiting-approval", {
        poll: { href: `/v1/demo/runs/${RUN_ID}`, after_milliseconds: 250 },
      }),
    );
    vi.mocked(adapter.get).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolvePoll = resolve;
        }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    expect(await screen.findByRole("heading", { name: "Expected versus observed" })).toBeVisible();
    expect(await screen.findByAltText("Declared expected output")).toBeVisible();
    expect(await screen.findByAltText(/Observed output with a visible color shift/u)).toBeVisible();
    expect(await screen.findByAltText(/Illustrative pixel difference/u)).toBeVisible();
    await decodeRenderedImages();
    fireEvent.change(screen.getByLabelText("Retype review nonce"), { target: { value: NONCE } });
    fireEvent.change(screen.getByLabelText("Type approval phrase"), {
      target: { value: "APPROVE_COLORTRACE_SIMULATOR_ACTION" },
    });
    fireEvent.click(
      screen.getByLabelText(
        /I approve only the displayed targets and keep the exclusions protected/u,
      ),
    );
    await waitFor(() => expect(adapter.get).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Approve recovery action" }));
    expect(await screen.findByRole("heading", { name: "Recovered output" })).toBeVisible();

    await act(async () => {
      resolvePoll?.(demoRun("awaiting-approval"));
      await Promise.resolve();
    });

    expect(screen.getByRole("heading", { name: "Recovered output" })).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Approve recovery action" }),
    ).not.toBeInTheDocument();
  });

  it("restores only session-scoped state and fails closed without the nonce", async () => {
    const adapter = adapterFixture();
    const storage = memoryStorage({ "colortrace.demo.run-id": RUN_ID });
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={storage} />);

    expect(
      await screen.findByRole("heading", { name: "Review cannot continue in this browser" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Approve recovery action" }),
    ).not.toBeInTheDocument();
    expect(adapter.get).toHaveBeenCalledWith(RUN_ID, expect.any(AbortSignal));
  });

  it("replays the exact persisted start after an ambiguous response and reload", async () => {
    const storage = memoryStorage();
    const firstAdapter = adapterFixture();
    vi.mocked(firstAdapter.start).mockRejectedValue(new DemoApiError(null, "demo-network-failure"));
    const firstRender = render(
      <ShotSafeColorRecoveryApp adapter={firstAdapter} storage={storage} />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/service is unavailable/u);
    const persisted = {
      approval_nonce: storage.values.get("colortrace.demo.approval-nonce") as string,
      idempotency_key: storage.values.get("colortrace.demo.start-idempotency-key") as string,
    };
    expect(persisted.approval_nonce).toBe(NONCE);
    firstRender.unmount();

    const resumedAdapter = adapterFixture();
    render(<ShotSafeColorRecoveryApp adapter={resumedAdapter} storage={storage} />);

    expect(await screen.findByRole("heading", { name: "Expected versus observed" })).toBeVisible();
    expect(resumedAdapter.start).toHaveBeenCalledWith(persisted, expect.any(AbortSignal));
    expect(storage.values.get("colortrace.demo.run-id")).toBe(RUN_ID);
    expect(storage.values.has("colortrace.demo.start-idempotency-key")).toBe(false);
  });

  it("keeps the terminal run and replays the persisted reset after reload", async () => {
    const storage = memoryStorage({ "colortrace.demo.run-id": RUN_ID });
    const firstAdapter = adapterFixture();
    vi.mocked(firstAdapter.get).mockResolvedValue(demoRun("closed"));
    vi.mocked(firstAdapter.reset).mockRejectedValue(new DemoApiError(null, "demo-reset-uncertain"));
    const firstRender = render(
      <ShotSafeColorRecoveryApp adapter={firstAdapter} storage={storage} />,
    );

    expect(
      await screen.findByRole("heading", { name: "Recovery closed with a verified receipt" }),
    ).toBeVisible();
    expect(storage.values.get("colortrace.demo.run-id")).toBe(RUN_ID);
    const resetButton = await screen.findByRole("button", { name: "Reset for another run" });
    await waitFor(() => expect(resetButton).toBeEnabled());
    fireEvent.click(resetButton);
    expect(await screen.findByRole("alert")).toHaveTextContent(/result is uncertain/u);
    const resetIdempotencyKey = storage.values.get(
      "colortrace.demo.reset-idempotency-key",
    ) as string;
    expect(resetIdempotencyKey).toMatch(/^demo-reset-/u);
    expect(storage.values.get("colortrace.demo.run-id")).toBe(RUN_ID);
    firstRender.unmount();

    const resumedAdapter = adapterFixture();
    vi.mocked(resumedAdapter.get).mockResolvedValue(demoRun("closed"));
    render(<ShotSafeColorRecoveryApp adapter={resumedAdapter} storage={storage} />);

    expect(await screen.findByText(/reset to authored generation 1/u)).toBeVisible();
    expect(resumedAdapter.reset).toHaveBeenCalledWith(RUN_ID, 6, resetIdempotencyKey);
    expect(storage.values.size).toBe(0);
  });

  it("surfaces a resumed reset replay failure in the terminal action area", async () => {
    const resetIdempotencyKey = "demo-reset-persisted";
    const storage = memoryStorage({
      "colortrace.demo.run-id": RUN_ID,
      "colortrace.demo.reset-idempotency-key": resetIdempotencyKey,
    });
    const adapter = adapterFixture();
    vi.mocked(adapter.get).mockResolvedValue(demoRun("closed"));
    vi.mocked(adapter.reset).mockRejectedValue(new DemoApiError(null, "demo-network-failure"));

    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={storage} />);

    const terminal = await screen.findByRole("region", {
      name: "Recovery closed with a verified receipt",
    });
    expect(await within(terminal).findByRole("alert")).toHaveTextContent(/result is uncertain/u);
    expect(adapter.reset).toHaveBeenCalledWith(RUN_ID, 6, resetIdempotencyKey);
    expect(storage.values.get("colortrace.demo.run-id")).toBe(RUN_ID);
  });

  it("keeps reset disabled when a cryptographically valid receipt misbinds a proof", async () => {
    const receipt = demoReceipt();
    const body = Object.fromEntries(
      Object.entries(receipt).filter(([key]) => key !== "receipt_id" && key !== "receipt_sha256"),
    ) as Omit<DemoReceipt, "receipt_id" | "receipt_sha256">;
    const proofMismatch = sealDemoReceipt({
      ...body,
      proofs: body.proofs.map((proof) =>
        proof.stage === "execution" ? { ...proof, sha256: `sha256:${"0".repeat(64)}` } : proof,
      ),
    });
    const adapter = adapterFixture();
    vi.mocked(adapter.get).mockResolvedValue(demoRun("closed"));
    vi.mocked(adapter.receipt).mockResolvedValue(proofMismatch);

    render(
      <ShotSafeColorRecoveryApp
        adapter={adapter}
        storage={memoryStorage({ "colortrace.demo.run-id": RUN_ID })}
      />,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be verified/u);
    expect(screen.getByRole("button", { name: "Reset for another run" })).toBeDisabled();
    expect(adapter.reset).not.toHaveBeenCalled();
  });

  it("withholds approval when any visual cannot be verified", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.visual).mockImplementation(async (_runId, kind) => {
      if (kind === "diff") throw new DemoApiError(409, "demo-visual-digest-conflict");
      return { kind, sha256: VISUAL_DIGESTS[kind], src: `data:image/png;base64,${kind}` };
    });
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be verified/u);
    expect(screen.getByRole("button", { name: "Approve recovery action" })).toBeDisabled();
    expect(adapter.approve).not.toHaveBeenCalled();
  });

  it("rejects a bound plan without verified visuals, verifies the receipt, and permits reset", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.visual).mockRejectedValue(
      new DemoApiError(409, "demo-visual-digest-conflict"),
    );
    vi.mocked(adapter.receipt).mockResolvedValue(demoRejectedReceipt("unsafe-scope"));
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/could not be verified/u);
    fireEvent.change(screen.getByLabelText("Retype review nonce"), { target: { value: NONCE } });
    fireEvent.change(screen.getByLabelText("Rejection reason"), {
      target: { value: "unsafe-scope" },
    });

    const reject = screen.getByRole("button", { name: "Reject plan" });
    expect(screen.getByRole("button", { name: "Approve recovery action" })).toBeDisabled();
    expect(reject).toBeEnabled();
    fireEvent.click(reject);

    expect(
      await screen.findByRole("heading", { name: "Plan rejected with a verified receipt" }),
    ).toBeVisible();
    expect(await screen.findByText("plan-rejected-unsafe-scope")).toBeVisible();
    expect(adapter.reject).toHaveBeenCalledWith(
      RUN_ID,
      expect.objectContaining({
        schema: "colortrace-demo-rejection-request/v1",
        approval_nonce: NONCE,
        expected_run_version: 2,
        expected_incident_version: 7,
        expected_plan_version: 3,
        expected_plan_sha256: PLAN_DIGEST,
        expected_target_sha256: TARGET_DIGEST,
        reason_code: "unsafe-scope",
        idempotency_key: expect.stringMatching(/^demo-reject-/u),
      }),
    );
    expect(adapter.approve).not.toHaveBeenCalled();
    expect(adapter.close).not.toHaveBeenCalled();

    const reset = await screen.findByRole("button", { name: "Reset for another run" });
    await waitFor(() => expect(reset).toBeEnabled());
    fireEvent.click(reset);
    expect(
      await screen.findByRole("heading", { name: /successful render can still be/u }),
    ).toBeVisible();
  });

  it("reuses the exact rejection idempotency key after an ambiguous response", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.reject)
      .mockRejectedValueOnce(new DemoApiError(null, "demo-network-failure"))
      .mockResolvedValueOnce(demoRejectedRun("unresolved-risk"));
    vi.mocked(adapter.receipt).mockResolvedValue(demoRejectedReceipt("unresolved-risk"));
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    await screen.findByRole("heading", { name: "Decide the exact plan" });
    const submit = async () => {
      fireEvent.change(screen.getByLabelText("Retype review nonce"), {
        target: { value: NONCE },
      });
      fireEvent.change(screen.getByLabelText("Rejection reason"), {
        target: { value: "unresolved-risk" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Reject plan" }));
    };
    await submit();
    expect(await screen.findByRole("heading", { name: "Decision paused" })).toBeVisible();
    const firstRequest = vi.mocked(adapter.reject).mock.calls[0]?.[1];

    fireEvent.click(screen.getByRole("button", { name: "Recheck run state" }));
    await screen.findByRole("heading", { name: "Decide the exact plan" });
    await submit();
    await screen.findByRole("heading", { name: "Plan rejected with a verified receipt" });

    expect(adapter.reject).toHaveBeenCalledTimes(2);
    expect(vi.mocked(adapter.reject).mock.calls[1]?.[1]).toEqual(firstRequest);
  });

  it("withholds approval when the current comparison cannot be decoded", async () => {
    const adapter = adapterFixture();
    vi.mocked(HTMLImageElement.prototype.decode).mockImplementation(function (
      this: HTMLImageElement,
    ) {
      return this.alt.includes("pixel difference")
        ? Promise.reject(new DOMException("decode failed"))
        : Promise.resolve();
    });
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    await screen.findByAltText(
      "Illustrative pixel difference between expected and observed output",
    );
    await decodeRenderedImages();

    expect(await screen.findByRole("alert")).toHaveTextContent(/difference image.*decoded/u);
    expect(screen.getByRole("button", { name: "Approve recovery action" })).toBeDisabled();
    expect(adapter.approve).not.toHaveBeenCalled();
  });

  it("withholds closure when the recovered visual cannot be decoded", async () => {
    const adapter = adapterFixture();
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    await screen.findByAltText(
      "Illustrative pixel difference between expected and observed output",
    );
    await decodeRenderedImages();
    fireEvent.change(screen.getByLabelText("Retype review nonce"), { target: { value: NONCE } });
    fireEvent.change(screen.getByLabelText("Type approval phrase"), {
      target: { value: "APPROVE_COLORTRACE_SIMULATOR_ACTION" },
    });
    fireEvent.click(
      screen.getByLabelText(
        /I approve only the displayed targets and keep the exclusions protected/u,
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "Approve recovery action" }));

    const recovered = await screen.findByAltText("Recovered output");
    vi.mocked(HTMLImageElement.prototype.decode).mockRejectedValueOnce(
      new DOMException("decode failed"),
    );
    await act(async () => {
      fireEvent.load(recovered);
      await Promise.resolve();
    });

    expect(await screen.findByRole("alert")).toHaveTextContent(/recovered image.*decoded/u);
    fireEvent.click(screen.getByLabelText(/I verified the recovered image/u));
    expect(screen.getByRole("button", { name: "Verify and close recovery" })).toBeDisabled();
    expect(adapter.close).not.toHaveBeenCalled();
  });

  it("releases a stale visual and requires the replacement descriptor to decode", async () => {
    const changedDigest = `sha256:${"9".repeat(64)}`;
    const changedDigests = { ...VISUAL_DIGESTS, expected: changedDigest };
    const adapter = adapterFixture();
    vi.mocked(adapter.get).mockResolvedValue(
      demoRun("awaiting-approval", { approval_nonce: undefined }, changedDigests),
    );
    vi.mocked(adapter.visual).mockImplementation(async (_runId, kind, expectedSha256) => ({
      kind,
      sha256: expectedSha256 ?? VISUAL_DIGESTS[kind],
      src: `blob:${kind}:${expectedSha256 ?? VISUAL_DIGESTS[kind]}`,
    }));
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    const originalExpected = await screen.findByAltText("Declared expected output");
    await screen.findByAltText(
      "Illustrative pixel difference between expected and observed output",
    );
    await decodeRenderedImages();
    fireEvent.change(screen.getByLabelText("Retype review nonce"), { target: { value: NONCE } });
    fireEvent.change(screen.getByLabelText("Type approval phrase"), {
      target: { value: "APPROVE_COLORTRACE_SIMULATOR_ACTION" },
    });
    fireEvent.click(
      screen.getByLabelText(
        /I approve only the displayed targets and keep the exclusions protected/u,
      ),
    );
    const approve = screen.getByRole("button", { name: "Approve recovery action" });
    expect(approve).toBeEnabled();

    await waitFor(() => expect(adapter.get).toHaveBeenCalled(), { timeout: 2_000 });
    await waitFor(() =>
      expect(adapter.visual).toHaveBeenCalledWith(
        RUN_ID,
        "expected",
        changedDigest,
        expect.any(AbortSignal),
      ),
    );
    expect(adapter.releaseVisual).toHaveBeenCalledWith({
      kind: "expected",
      sha256: VISUAL_DIGESTS.expected,
      src: `blob:expected:${VISUAL_DIGESTS.expected}`,
    });
    expect(approve).toBeDisabled();

    await act(async () => {
      fireEvent.load(originalExpected);
      await Promise.resolve();
    });
    expect(approve).toBeDisabled();

    const replacement = screen.getByAltText("Declared expected output");
    await act(async () => {
      fireEvent.load(replacement);
      await Promise.resolve();
    });
    expect(approve).toBeEnabled();
  });

  it("reconciles an awaiting approval into lease expiry and removes stale controls", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.get).mockResolvedValue(demoRun("expired"));
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    expect(await screen.findByRole("heading", { name: "Decide the exact plan" })).toBeVisible();

    expect(
      await screen.findByRole(
        "heading",
        { name: "Run stopped without closure" },
        { timeout: 2_000 },
      ),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "Approve recovery action" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Verify and close recovery" })).toBeNull();
  });

  it("reconciles an awaiting closure into lease expiry and removes stale closure", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.start).mockResolvedValue(demoRun("awaiting-closure"));
    vi.mocked(adapter.get).mockResolvedValue(demoRun("expired"));
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    expect(await screen.findByRole("heading", { name: "Recovered image verified" })).toBeVisible();

    expect(
      await screen.findByRole(
        "heading",
        { name: "Run stopped without closure" },
        { timeout: 2_000 },
      ),
    ).toBeVisible();
    expect(screen.queryByRole("button", { name: "Verify and close recovery" })).toBeNull();
  });

  it("shows a transient reconciliation error and retries until authoritative state succeeds", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.start).mockResolvedValue(demoRun("executing"));
    vi.mocked(adapter.get)
      .mockRejectedValueOnce(new DemoApiError(null, "demo-network-failure"))
      .mockResolvedValue(demoRun("awaiting-closure"));
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    expect(await screen.findByRole("heading", { name: "Applying recovery" })).toBeVisible();
    expect(await screen.findByRole("alert", {}, { timeout: 2_000 })).toHaveTextContent(
      /service is unavailable/u,
    );
    expect(screen.getByRole("button", { name: "Recheck run state" })).toBeVisible();

    expect(
      await screen.findByRole("heading", { name: "Recovered image verified" }, { timeout: 2_000 }),
    ).toBeVisible();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(adapter.get).toHaveBeenCalledTimes(2);
  });

  it("recovers an active-run conflict but stays fail-closed without its nonce", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.start).mockRejectedValue(
      new DemoApiError(409, "demo-active-run-exists", { runId: RUN_ID }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(
      await screen.findByRole("heading", { name: "Review cannot continue in this browser" }),
    ).toBeVisible();
    expect(adapter.get).toHaveBeenCalledWith(RUN_ID, undefined);
    expect(
      screen.queryByRole("button", { name: "Approve recovery action" }),
    ).not.toBeInTheDocument();
  });

  it("recovers a reset-required conflict to the terminal run", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.start).mockRejectedValue(
      new DemoApiError(409, "demo-reset-required", { runId: RUN_ID }),
    );
    vi.mocked(adapter.get).mockResolvedValue(demoRun("closed"));
    const storage = memoryStorage();
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={storage} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(
      await screen.findByRole("heading", { name: "Recovery closed with a verified receipt" }),
    ).toBeVisible();
    expect(storage.values.get("colortrace.demo.run-id")).toBe(RUN_ID);
    expect(storage.values.has("colortrace.demo.approval-nonce")).toBe(false);
    const resetButton = await screen.findByRole("button", { name: "Reset for another run" });
    await waitFor(() => expect(resetButton).toBeEnabled());
  });
});
