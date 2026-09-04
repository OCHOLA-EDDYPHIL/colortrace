import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type DemoAdapter,
  DemoApiError,
  type DemoReceipt,
  type DemoVisualKind,
} from "../src/demo-api.ts";
import type {
  ReferenceDemoAdapter,
  ReferenceScenarioList,
  ReferenceVisualKind,
} from "../src/reference-demo-api.ts";
import { ShotSafeColorRecoveryApp } from "../src/shot-safe-color-recovery-app.tsx";
import {
  demoReceipt,
  demoRejectedReceipt,
  demoRejectedRun,
  demoReset,
  demoRun,
  executionProof,
  investigationProof,
  investigationProofV1,
  investigationProofV2,
  investigationProofV3,
  NONCE,
  OUTCOME_DIGEST,
  PACKET_DIGEST,
  PLAN_DIGEST,
  RUN_ID,
  scenarioPreview,
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
    preview: vi.fn(async () => scenarioPreview()),
    previewVisual: vi.fn(async (kind: DemoVisualKind) => ({
      kind,
      sha256: VISUAL_DIGESTS[kind],
      src: `data:image/png;base64,preview-${kind}`,
    })),
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

const REFERENCE_DIGEST = `sha256:${"a".repeat(64)}`;

function referenceAdapterFixture(): ReferenceDemoAdapter {
  const scenarioId = "tos-resource-resolution-drift-v1" as const;
  const visual = (kind: ReferenceVisualKind) => ({
    kind,
    href: `/v1/demo/scenarios/${scenarioId}/visuals/${kind}`,
    content_sha256: REFERENCE_DIGEST,
    representation:
      kind === "diff"
        ? ("open-film-difference-png/v1" as const)
        : ("open-film-preview-png/v1" as const),
    pixel_evidence: true as const,
    width: 960 as const,
    height: 506 as const,
    served_artifact_id: "frame:03_2a:00000",
    source_artifact_ids: ["frame:03_2a:00000"],
    source_relation:
      kind === "diff"
        ? ("amplified-absolute-display-difference-8x" as const)
        : ("current" as const),
    source_receipt_sha256: [REFERENCE_DIGEST],
    source_output_sha256: [REFERENCE_DIGEST],
    source_canonical_pixel_sha256: [REFERENCE_DIGEST],
  });
  const catalog: ReferenceScenarioList = {
    schema: "reference-scenario-list/v1",
    collection_id: "tears-of-steel-linear-exr-240-v1",
    items: [
      {
        scenario_id: scenarioId,
        scenario_sha256: REFERENCE_DIGEST,
        title: "A successful render resolved the wrong look resource",
        symptom: "Frames completed, but a worker resolved a different LUT.",
        incident_class: "resource-resolution-drift/v1",
        recovery_kind: "reconcile-resource",
        scope: {
          artifact_count: 240,
          affected_artifact_count: 72,
          protected_artifact_count: 168,
        },
        visuals: [visual("expected"), visual("observed"), visual("recovered"), visual("diff")],
      },
    ],
    provenance: {
      attribution: "Tears of Steel © Blender Foundation | mango.blender.org",
      license: { spdx: "CC-BY-3.0", url: "https://creativecommons.org/licenses/by/3.0/" },
    },
    authority: {
      schema: "reference-authority-boundary/v1",
      catalog_facts: "sealed-reference-contracts",
      incident_facts: "deterministic-validators",
      model_role: "advisory",
      evidence_access: "grafana-mcp-read-only",
      action_approval: "human-only",
      action_execution_target: "colortrace-simulator",
    },
    catalog_sha256: REFERENCE_DIGEST,
  };
  const pending = () => new Promise<never>(() => undefined);
  return {
    listScenarios: vi.fn(async () => catalog),
    getScenario: vi.fn(pending),
    benchmarkSuite: vi.fn(pending),
    runScenario: vi.fn(pending),
    decideRecovery: vi.fn(pending),
    loadVisual: vi.fn(async (descriptor, scenarioSha256) => ({
      kind: descriptor.kind,
      content_sha256: descriptor.content_sha256,
      scenario_sha256: scenarioSha256,
      representation: descriptor.representation,
      pixel_evidence: true as const,
      width: 960 as const,
      height: 506 as const,
      served_artifact_id: descriptor.served_artifact_id,
      source_relation: descriptor.source_relation,
      src: `blob:reference-${descriptor.kind}`,
    })),
    releaseVisual: vi.fn(),
  };
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
  it("presents verified open-film pixels and action in the first fold before compatibility", async () => {
    const referenceAdapter = referenceAdapterFixture();
    render(
      <ShotSafeColorRecoveryApp
        adapter={adapterFixture()}
        referenceAdapter={referenceAdapter}
        storage={memoryStorage()}
      />,
    );

    const firstFold = document.querySelector('[data-first-fold="comparison-and-action"]');
    if (!(firstFold instanceof HTMLElement)) throw new Error("missing first fold");
    const primaryExpected = await within(firstFold).findByAltText(
      /Expected state open-film pixel preview/iu,
    );
    const primaryObserved = within(firstFold).getByAltText(
      /Observed failure open-film pixel preview/iu,
    );
    const primaryProof = screen.getByRole("heading", {
      name: "Three ways a successful render can still be wrong",
    });
    const secondaryWorkflow = screen.getByRole("heading", {
      name: "Canonical approval and recovery loop",
    });

    expect(document.querySelectorAll("h1")).toHaveLength(1);
    const primaryAction = screen.getByRole("link", { name: "Explore the open-film proof" });
    const compatibilityAction = screen.getByRole("button", {
      name: "Investigate the color fault",
    });
    const syntheticExpected = await screen.findByAltText(
      "Expected cinematic soundstage portrait with a cool teal color grade",
    );
    expect(screen.getByText("Primary proof · open-film reference suite")).toBeVisible();
    expect(screen.getByText("Secondary · synthetic compatibility preview")).toBeVisible();
    expect(firstFold).toContainElement(primaryExpected);
    expect(firstFold).toContainElement(primaryObserved);
    expect(firstFold).not.toContainElement(syntheticExpected);
    expect(firstFold).not.toContainElement(compatibilityAction);
    expect(primaryAction).toHaveAttribute("href", "#reference-suite-title");
    expect(primaryAction).toHaveClass("shot-button--primary");
    expect(compatibilityAction).toHaveClass("shot-button--secondary");
    expect(
      primaryAction.compareDocumentPosition(compatibilityAction) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0);
    expect(
      primaryProof.compareDocumentPosition(secondaryWorkflow) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).not.toBe(0);
    expect(screen.getByText("Secondary compatibility workflow")).toBeVisible();
    expect(referenceAdapter.loadVisual).toHaveBeenCalledTimes(2);
  });

  it("shows the verified cinematic preview before any run mutation", async () => {
    const adapter = adapterFixture();
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    const expected = await screen.findByAltText(
      "Expected cinematic soundstage portrait with a cool teal color grade",
    );
    const observed = screen.getByAltText(
      "Observed version of the same cinematic portrait with a warmer orange color grade",
    );
    const difference = screen.getByAltText(
      "Red heat-map view of the color difference across the cinematic frame",
    );
    const firstFold = document.querySelector('[data-first-fold="comparison-and-action"]');
    const callToAction = screen.getByRole("button", { name: "Investigate the color fault" });

    expect(firstFold).not.toBeNull();
    expect(firstFold).toContainElement(expected);
    expect(firstFold).toContainElement(observed);
    expect(firstFold).toContainElement(difference);
    expect(firstFold).toContainElement(callToAction);
    expect(
      screen.getByRole("heading", { name: "Both renders succeeded—why do they look different?" }),
    ).toBeVisible();
    expect(screen.getByText(/ColorTrace helps VFX pipeline technical directors/iu)).toBeVisible();
    expect(
      screen.getByText("Build-time fixture · hash verified · no live investigation yet"),
    ).toBeVisible();
    expect(adapter.preview).toHaveBeenCalledOnce();
    expect(adapter.previewVisual).toHaveBeenCalledTimes(3);
    expect(adapter.start).not.toHaveBeenCalled();
    expect(adapter.approve).not.toHaveBeenCalled();
    expect(adapter.reject).not.toHaveBeenCalled();
    expect(adapter.close).not.toHaveBeenCalled();
    expect(adapter.reset).not.toHaveBeenCalled();
  });

  it("describes the real external work while a live investigation is pending", async () => {
    const adapter = adapterFixture();
    let resolveStart: ((run: ReturnType<typeof demoRun>) => void) | undefined;
    vi.mocked(adapter.start).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveStart = resolve;
        }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    const start = screen.getByRole("button", { name: "Investigate the color fault" });
    fireEvent.click(start);

    expect(
      await screen.findByText(/waiting for Grafana evidence and the bounded Gemini advisory/iu),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Preparing recovery…" })).toBeDisabled();

    await act(async () => {
      resolveStart?.(demoRun("awaiting-approval"));
      await Promise.resolve();
    });
    expect(await screen.findByRole("heading", { name: "Expected versus observed" })).toBeVisible();
  });

  it("describes saved-run reconciliation without claiming a new live investigation", async () => {
    const adapter = adapterFixture();
    const storage = memoryStorage({ "colortrace.demo.run-id": RUN_ID });
    let resolveGet: ((run: ReturnType<typeof demoRun>) => void) | undefined;
    vi.mocked(adapter.get).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveGet = resolve;
        }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={storage} />);

    expect(
      await screen.findByText("Loading the saved run and reconciling it with the service."),
    ).toBeVisible();
    expect(screen.queryByText(/Live investigation running/iu)).not.toBeInTheDocument();

    await act(async () => {
      resolveGet?.(demoRun("awaiting-approval"));
      await Promise.resolve();
    });
    expect(await screen.findByRole("heading", { name: "Expected versus observed" })).toBeVisible();
  });

  it("never lets decoded preview blobs satisfy the run-bound approval gate", async () => {
    const adapter = adapterFixture();
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    await screen.findByAltText(
      "Expected cinematic soundstage portrait with a cool teal color grade",
    );
    await decodeRenderedImages();
    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    await screen.findByRole("heading", { name: "Decide the exact plan" });
    fireEvent.change(screen.getByLabelText("Retype review nonce"), { target: { value: NONCE } });
    fireEvent.change(screen.getByLabelText("Type approval phrase"), {
      target: { value: "APPROVE_COLORTRACE_SIMULATOR_ACTION" },
    });
    fireEvent.click(
      screen.getByLabelText(
        /I approve only the displayed targets and keep the exclusions protected/u,
      ),
    );

    expect(screen.getByRole("button", { name: "Approve recovery action" })).toBeDisabled();
    expect(adapter.approve).not.toHaveBeenCalled();
  });

  it("shows the adaptive path and keeps complete evidence inspectable", async () => {
    const adapter = adapterFixture();
    const hostileInvestigation = investigationProof();
    vi.mocked(adapter.start).mockImplementation(async (request) =>
      demoRun("awaiting-approval", {
        approval_nonce: request.approval_nonce,
        investigation: {
          ...hostileInvestigation,
          evidence: hostileInvestigation.evidence.map((item, index) =>
            index === 0
              ? { ...item, display_excerpt: '<script data-hostile="evidence">alert(1)</script>' }
              : item,
          ),
          model_advisory: {
            ...hostileInvestigation.model_advisory,
            summary: '<img data-hostile="advisory" src=x onerror=alert(1)>',
          },
        },
      }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));
    const evidenceRegion = await screen.findByRole("region", {
      name: "Gemini selected evidence; validators decided",
    });

    const facts = screen.getByLabelText("Investigation facts");
    expect(facts).toHaveTextContent(/Renders\s*2 succeeded/u);
    expect(facts).toHaveTextContent(/Declared configuration\s*Same/u);
    expect(facts).toHaveTextContent(/Resolved LUT\s*Different/u);
    expect(facts).toHaveTextContent(/Affected\s*4 outputs/u);
    expect(facts).toHaveTextContent(/Protected\s*3 outputs/u);
    const impact = screen.getByLabelText("Synthetic fixture impact comparison");
    expect(impact).toHaveTextContent(/3 affected source frames targeted/u);
    expect(impact).toHaveTextContent(/3 verified-safe source frames excluded/u);
    expect(impact).toHaveTextContent(
      /3 fewer source-frame rerenders than rerendering all 6 observed source frames/u,
    );
    expect(impact).toHaveTextContent(/Synthetic fixture comparison—not a production benchmark/u);
    expect(impact).toHaveTextContent(/Time, compute, and cost savings were not measured/u);
    expect(within(evidenceRegion).getByText("2 bounded Grafana reads")).toBeVisible();
    expect(within(evidenceRegion).getByText("3 current evidence views")).toBeVisible();
    expect(within(evidenceRegion).getByText("Sufficient evidence")).toBeVisible();
    expect(within(evidenceRegion).getByText("Approve or reject the exact plan")).toBeVisible();
    expect(within(evidenceRegion).getByText("Gemini selected")).toBeVisible();
    expect(within(evidenceRegion).getByText("Grafana returned")).toBeVisible();
    expect(within(evidenceRegion).getByText("Validators decided")).toBeVisible();
    expect(within(evidenceRegion).getByText("Human authorizes")).toBeVisible();
    const adaptivePath = within(evidenceRegion).getByRole("list", {
      name: "Adaptive evidence path",
    });
    expect(within(adaptivePath).getByText(/Policy baseline: Alert baseline/u)).toBeVisible();
    expect(within(adaptivePath).getByText(/Gemini selected: Exact logs/u)).toBeVisible();
    expect(within(adaptivePath).getByText(/Gemini selected: Worker cohort/u)).toBeVisible();
    expect(within(adaptivePath).getByText(/Validators resolved/u)).toBeVisible();
    const hypotheses = within(evidenceRegion).getByRole("list", { name: "Bounded hypotheses" });
    expect(within(hypotheses).getByText(/1\. Color resource drift/u)).toBeVisible();
    expect(within(hypotheses).getByText(/2\. Worker-only failure/u)).toBeVisible();
    expect(within(hypotheses).getAllByRole("link").length).toBeGreaterThan(1);
    const decisiveSignal = evidenceRegion.querySelector(".shot-evidence-highlight");
    expect(decisiveSignal).not.toBeNull();
    expect(
      within(decisiveSignal as HTMLElement).getByText(
        "Worker A and worker B completed with the same nominal configuration.",
      ),
    ).toBeVisible();
    expect(within(evidenceRegion).getByText("Untrusted")).toBeVisible();
    expect(
      within(evidenceRegion).getByText("Deterministic code—not model prose—", { exact: false }),
    ).toBeVisible();
    const disclosure = within(evidenceRegion).getByText("Inspect all 3 Grafana evidence views");
    fireEvent.click(disclosure);
    const evidenceGrid = evidenceRegion.querySelector(
      '[data-proof-section="live-grafana-evidence"]',
    );
    expect(evidenceGrid).not.toBeNull();
    expect(evidenceGrid?.querySelectorAll("article")).toHaveLength(3);
    for (const name of ["Alert baseline", "Exact logs", "Worker cohort"]) {
      expect(within(evidenceGrid as HTMLElement).getByRole("heading", { name })).toBeVisible();
    }
    expect(within(evidenceGrid as HTMLElement).getAllByText("Grafana MCP")).toHaveLength(3);
    expect(within(evidenceGrid as HTMLElement).getAllByText("12:00:01 UTC")).toHaveLength(3);
    expect(screen.getByText("Deterministic validator · decision authority")).toBeVisible();
    expect(
      within(evidenceGrid as HTMLElement).getByText(
        '<script data-hostile="evidence">alert(1)</script>',
      ),
    ).toBeVisible();
    expect(screen.getByText('<img data-hostile="advisory" src=x onerror=alert(1)>')).toBeVisible();
    expect(document.querySelector("[data-hostile]")).toBeNull();

    const plan = screen.getByRole("region", { name: "Recover only the affected work" });
    const counts = plan.querySelector(".shot-counts");
    expect(counts).toHaveTextContent(/Affected\s*4\s*Protected\s*3\s*Unknown\s*0/u);
    expect(plan).toHaveTextContent(/3 of 7 outputs protected \(43%\)/u);
    expect(plan).toHaveTextContent(
      /5 bounded commands: 1 LUT replacement, 3 frame rerenders, and 1 derivative rerender/u,
    );
    expect(screen.getByText("Inspect 5 bounded commands")).toBeVisible();
    const activity = screen.getByRole("region", { name: "What actually happened" });
    const activityDisclosure = within(activity).getByText("Inspect 2 recorded events");
    expect(activityDisclosure).toBeVisible();
    expect(within(activity).getByText("Run created")).not.toBeVisible();
    expect(within(activity).getByText("Investigation completed")).not.toBeVisible();
    fireEvent.click(activityDisclosure);
    expect(within(activity).getByText("Run created")).toBeVisible();
    expect(within(activity).getByText("Investigation completed")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Decide the exact plan" })).toBeVisible();
    expect(screen.getByText("Technical proof and provenance")).toBeVisible();
  });

  it("keeps stored v3 evidence presentation reviewable without an adaptive trace", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.start).mockImplementation(async (request) =>
      demoRun("awaiting-approval", {
        approval_nonce: request.approval_nonce,
        investigation: investigationProofV3(),
      }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(
      await screen.findByRole("region", {
        name: "Gemini gathered evidence; validators decided",
      }),
    ).toBeVisible();
    expect(screen.queryByRole("list", { name: "Adaptive evidence path" })).not.toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Bounded hypotheses" })).not.toBeInTheDocument();
  });

  it("keeps legacy investigation proof reviewable without inventing an agent summary", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.start).mockImplementation(async (request) =>
      demoRun("awaiting-approval", {
        approval_nonce: request.approval_nonce,
        investigation: investigationProofV1(),
      }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(await screen.findByRole("heading", { name: "Investigation proof v1" })).toBeVisible();
    expect(screen.queryByLabelText("Investigation facts")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "Gemini gathered evidence; validators decided" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Synthetic fixture impact comparison")).not.toBeInTheDocument();
  });

  it("withholds the fixture comparison when protected and affected scope overlap", async () => {
    const adapter = adapterFixture();
    const investigation = investigationProofV2();
    const affectedFrame = investigation.plan.targets.find((target) => target.kind === "frame");
    if (affectedFrame === undefined) throw new Error("missing affected frame fixture");
    vi.mocked(adapter.start).mockImplementation(async (request) =>
      demoRun("awaiting-approval", {
        approval_nonce: request.approval_nonce,
        investigation: {
          ...investigation,
          plan: {
            ...investigation.plan,
            protected_exclusions: [
              affectedFrame,
              ...investigation.plan.protected_exclusions.slice(1),
            ],
          },
        },
      }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(await screen.findByLabelText("Investigation facts")).toBeVisible();
    expect(screen.queryByLabelText("Synthetic fixture impact comparison")).not.toBeInTheDocument();
  });

  it("keeps the concise facts and bounded commands available for v2 proof", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.start).mockImplementation(async (request) =>
      demoRun("awaiting-approval", {
        approval_nonce: request.approval_nonce,
        investigation: investigationProofV2(),
      }),
    );
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    const facts = await screen.findByLabelText("Investigation facts");
    expect(facts).toHaveTextContent(/Affected\s*4 outputs/u);
    expect(facts).toHaveTextContent(/Protected\s*3 outputs/u);
    expect(screen.getByLabelText("Synthetic fixture impact comparison")).toHaveTextContent(
      /3 fewer source-frame rerenders than rerendering all 6 observed source frames/u,
    );
    expect(
      screen.queryByRole("region", { name: "Gemini gathered evidence; validators decided" }),
    ).not.toBeInTheDocument();
    const disclosure = screen.getByText("Inspect 5 bounded commands");
    const firstCommand = document.querySelector(".shot-plan-review .shot-command");
    expect(firstCommand).not.toBeNull();
    expect(firstCommand).not.toBeVisible();
    fireEvent.click(disclosure);
    expect(firstCommand).toBeVisible();
  });

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

    expect(
      screen.getByRole("heading", { name: /both renders succeeded.*look different/iu }),
    ).toBeVisible();
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
    expect(screen.getByText("Unrelated event ruled out")).toBeVisible();
    expect(screen.getByRole("heading", { name: "Recover only the affected work" })).toBeVisible();
    expect(screen.getByText("artifact-b-02-derivative", { exact: true })).toBeVisible();
    expect(screen.getByText("Rerender the affected derivative")).not.toBeVisible();
    fireEvent.click(screen.getByText("Inspect 5 bounded commands"));
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
    const outcome = screen.getByLabelText("Recovery outcome");
    expect(outcome).toHaveTextContent(/Recovered\s*4 outputs/u);
    expect(outcome).toHaveTextContent(/Protected\s*3 unchanged/u);
    expect(outcome).toHaveTextContent(/Checks\s*7\/7 passed/u);
    expect(outcome).toHaveTextContent(/Next\s*Ready for human closure/u);
    expect(
      screen.getByText(
        "Recovered all 4 affected outputs; all 3 protected outputs remained unchanged.",
      ),
    ).toBeVisible();
    expect(screen.getByLabelText("Synthetic fixture impact comparison")).toHaveTextContent(
      /This plan calls for 3 fewer source-frame rerenders/u,
    );
    expect(storage.values.has("colortrace.demo.approval-nonce")).toBe(false);
    fireEvent.click(screen.getByText("Technical proof and provenance", { exact: true }));
    expect(screen.getAllByText("query_loki_logs", { exact: true }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/gemini-3\.5-flash/u).length).toBeGreaterThan(0);
    expect(screen.getByText("post-action-telemetry-correlation", { exact: true })).toBeVisible();
    fireEvent.click(screen.getByLabelText(/I verified the recovered image/u));
    fireEvent.click(screen.getByRole("button", { name: "Verify and close recovery" }));

    expect(
      await screen.findByRole(
        "heading",
        { name: "Recovery closed with a verified receipt" },
        { timeout: 3_000 },
      ),
    ).toBeVisible();
    expect(await screen.findByText("Recorded and verified")).toBeVisible();
    expect(storage.values.get("colortrace.demo.run-id")).toBe(RUN_ID);
    fireEvent.click(screen.getByRole("button", { name: "Reset for another run" }));

    expect(
      await screen.findByRole("heading", { name: /both renders succeeded.*look different/iu }),
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

  it("does not present an incomplete recovery proof as successful", async () => {
    const adapter = adapterFixture();
    const execution = executionProof();
    const incomplete = demoRun("awaiting-closure", {
      execution: {
        ...execution,
        recovery: {
          ...execution.recovery,
          status: "recovery_failed",
          checks: execution.recovery.checks.map((check, index) =>
            index === 0 ? { ...check, status: "failed" as const } : check,
          ),
        },
      },
    });
    vi.mocked(adapter.start).mockResolvedValue(incomplete);
    vi.mocked(adapter.get).mockResolvedValue(incomplete);
    render(<ShotSafeColorRecoveryApp adapter={adapter} storage={memoryStorage()} />);

    fireEvent.click(screen.getByRole("button", { name: "Investigate the color fault" }));

    expect(await screen.findByRole("heading", { name: "Recovered output" })).toBeVisible();
    const outcome = screen.getByLabelText("Recovery outcome");
    expect(outcome).toHaveTextContent(/Affected scope\s*4 outputs/u);
    expect(outcome).toHaveTextContent(/6\/7 passed/u);
    expect(outcome).toHaveTextContent(/Next\s*Verification incomplete/u);
    const incompleteMessage = screen.getByText(
      "Recovery verification is incomplete, so this result is not presented as successful.",
    );
    expect(incompleteMessage).toBeVisible();
    expect(incompleteMessage).toHaveAttribute("role", "alert");
    const banner = screen.getByRole("banner");
    expect(within(banner).getByText("Verification incomplete")).toBeVisible();
    expect(within(banner).queryByText("Recovery verified")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: "Recovered image verified" }),
    ).not.toBeInTheDocument();
  });

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

  it("labels a terminal receipt as verifying until its integrity check succeeds", async () => {
    const adapter = adapterFixture();
    let resolveReceipt: ((receipt: DemoReceipt) => void) | undefined;
    vi.mocked(adapter.get).mockResolvedValue(demoRun("closed"));
    vi.mocked(adapter.receipt).mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveReceipt = resolve;
        }),
    );

    render(
      <ShotSafeColorRecoveryApp
        adapter={adapter}
        storage={memoryStorage({ "colortrace.demo.run-id": RUN_ID })}
      />,
    );

    const verifying = await screen.findByRole("region", {
      name: "Recovery closed; verifying receipt",
    });
    expect(within(verifying).getByText(/verification is still in progress/iu)).toBeVisible();
    expect(within(verifying).queryByText(/verified receipt/iu)).not.toBeInTheDocument();

    await act(async () => {
      resolveReceipt?.(demoReceipt());
      await Promise.resolve();
    });
    expect(
      await screen.findByRole("heading", { name: "Recovery closed with a verified receipt" }),
    ).toBeVisible();
    expect(screen.getByText("Recorded and verified")).toBeVisible();
  });

  it("reports receipt verification as unavailable when a terminal receipt fails", async () => {
    const adapter = adapterFixture();
    vi.mocked(adapter.get).mockResolvedValue(demoRun("closed"));
    vi.mocked(adapter.receipt).mockRejectedValue(new DemoApiError(null, "demo-response-invalid"));

    render(
      <ShotSafeColorRecoveryApp
        adapter={adapter}
        storage={memoryStorage({ "colortrace.demo.run-id": RUN_ID })}
      />,
    );

    const unavailable = await screen.findByRole("region", {
      name: "Recovery closed; receipt verification unavailable",
    });
    expect(within(unavailable).getByText(/receipt could not be verified/iu)).toBeVisible();
    expect(within(unavailable).queryByText(/verified receipt/iu)).not.toBeInTheDocument();
    expect(
      within(unavailable).getByRole("button", { name: "Reset for another run" }),
    ).toBeDisabled();
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
      await screen.findByRole("heading", { name: /both renders succeeded.*look different/iu }),
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
