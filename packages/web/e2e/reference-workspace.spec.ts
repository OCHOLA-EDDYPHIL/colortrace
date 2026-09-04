import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, type Page, test } from "@playwright/test";

import {
  REFERENCE_SCENARIO_IDS,
  type ReferenceAuthority,
  type ReferenceBenchmarkSuite,
  type ReferenceIncidentClass,
  type ReferenceRecoveryKind,
  type ReferenceScenarioDetail,
  type ReferenceScenarioId,
  type ReferenceScenarioList,
  type ReferenceScenarioSummary,
  type ReferenceVisualKind,
  type ReferenceVisualRepresentation,
  type ReferenceVisualSourceRelation,
} from "../src/reference-demo-api.ts";

const DIGEST = `sha256:${"a".repeat(64)}`;
const PREVIEW_ROOT = fileURLToPath(
  new URL("../../api/src/colortrace_api/reference_previews/", import.meta.url),
);
const VISUAL_KINDS = ["expected", "observed", "recovered", "diff"] as const;

type PreviewManifest = {
  readonly scenarios: Readonly<
    Record<
      ReferenceScenarioId,
      {
        readonly served_artifact_id: string;
        readonly visuals: Readonly<
          Record<
            ReferenceVisualKind,
            {
              readonly filename: string;
              readonly height: 506;
              readonly representation: ReferenceVisualRepresentation;
              readonly sha256: string;
              readonly source_artifact_ids: readonly string[];
              readonly source_canonical_pixel_sha256: readonly string[];
              readonly source_output_sha256: readonly string[];
              readonly source_receipt_sha256: readonly string[];
              readonly source_relation: ReferenceVisualSourceRelation;
              readonly width: 960;
            }
          >
        >;
      }
    >
  >;
};

const previewManifest = JSON.parse(
  await readFile(path.join(PREVIEW_ROOT, "manifest.json"), "utf8"),
) as PreviewManifest;

const AUTHORITY: ReferenceAuthority = {
  schema: "reference-authority-boundary/v1",
  catalog_facts: "sealed-reference-contracts",
  incident_facts: "deterministic-validators",
  model_role: "advisory",
  evidence_access: "grafana-mcp-read-only",
  action_approval: "human-only",
  action_execution_target: "colortrace-simulator",
};

const PROVENANCE = {
  attribution: "Tears of Steel © Blender Foundation | mango.blender.org",
  license: { spdx: "CC-BY-3.0", url: "https://creativecommons.org/licenses/by/3.0/" },
} as const;

const SCENARIOS = {
  "tos-resource-resolution-drift-v1": {
    facts: ["runtime.effective_resource_sha256", "runtime.frame_pipeline_sha256"],
    incidentClass: "resource-resolution-drift/v1",
    recoveryKind: "reconcile-resource",
    symptom: "Frames completed, but a worker resolved a different LUT than the approved reference.",
    title: "A successful render resolved the wrong look resource",
  },
  "tos-config-rollout-drift-v1": {
    facts: [
      "runtime.effective_config_sha256",
      "runtime.config_generation",
      "runtime.frame_pipeline_sha256",
    ],
    incidentClass: "configuration-rollout-drift/v1",
    recoveryKind: "pin-rollout",
    symptom:
      "Frames completed under an older configuration generation while the LUT stayed current.",
    title: "A stale color configuration remained active",
  },
  "tos-stale-derivative-cache-v1": {
    facts: [
      "runtime.frame_pipeline_sha256",
      "derivative.parent_sha256",
      "cache.generation",
      "cache.key",
    ],
    incidentClass: "stale-derivative-cache/v1",
    recoveryKind: "invalidate-cache",
    symptom:
      "The frame pipeline matched the reference, but cached derivatives came from older parents.",
    title: "Correct frames served stale review derivatives",
  },
} as const satisfies Readonly<
  Record<
    ReferenceScenarioId,
    {
      readonly facts: readonly string[];
      readonly incidentClass: ReferenceIncidentClass;
      readonly recoveryKind: ReferenceRecoveryKind;
      readonly symptom: string;
      readonly title: string;
    }
  >
>;

const SCENARIO_SHA256 = {
  "tos-resource-resolution-drift-v1": `sha256:${"1".repeat(64)}`,
  "tos-config-rollout-drift-v1": `sha256:${"2".repeat(64)}`,
  "tos-stale-derivative-cache-v1": `sha256:${"3".repeat(64)}`,
} as const satisfies Readonly<Record<ReferenceScenarioId, string>>;

function summary(scenarioId: ReferenceScenarioId): ReferenceScenarioSummary {
  const metadata = SCENARIOS[scenarioId];
  const preview = previewManifest.scenarios[scenarioId];
  return {
    scenario_id: scenarioId,
    scenario_sha256: SCENARIO_SHA256[scenarioId],
    title: metadata.title,
    symptom: metadata.symptom,
    incident_class: metadata.incidentClass,
    recovery_kind: metadata.recoveryKind,
    scope: {
      artifact_count: 240,
      affected_artifact_count: 72,
      protected_artifact_count: 168,
    },
    visuals: VISUAL_KINDS.map((kind) => {
      const visual = preview.visuals[kind];
      return {
        kind,
        href: `/v1/demo/scenarios/${scenarioId}/visuals/${kind}`,
        content_sha256: visual.sha256,
        representation: visual.representation,
        pixel_evidence: true,
        width: visual.width,
        height: visual.height,
        served_artifact_id: preview.served_artifact_id,
        source_artifact_ids: visual.source_artifact_ids,
        source_relation: visual.source_relation,
        source_receipt_sha256: visual.source_receipt_sha256,
        source_output_sha256: visual.source_output_sha256,
        source_canonical_pixel_sha256: visual.source_canonical_pixel_sha256,
      };
    }),
  };
}

function scenarioList(): ReferenceScenarioList {
  return {
    schema: "reference-scenario-list/v1",
    collection_id: "tears-of-steel-linear-exr-240-v1",
    items: REFERENCE_SCENARIO_IDS.map(summary),
    provenance: PROVENANCE,
    authority: AUTHORITY,
    catalog_sha256: DIGEST,
  };
}

function scenarioDetail(scenarioId: ReferenceScenarioId): ReferenceScenarioDetail {
  const metadata = SCENARIOS[scenarioId];
  return {
    schema: "reference-scenario-detail/v1",
    summary: summary(scenarioId),
    evidence_requirements: {
      minimum_complementary_signal_classes: 2,
      runtime_fact_source: "structured-grafana-observations",
      required_fact_fields: metadata.facts,
      decision_authority: "deterministic-validators",
      "missing_conflicting_or_cross-run_evidence": "unresolved",
    },
    recovery_boundary: {
      intent: metadata.recoveryKind,
      requires_human_approval: true,
      execution_target: "colortrace-simulator",
      catalog_executes_actions: false,
    },
    provenance: PROVENANCE,
    authority: AUTHORITY,
    detail_sha256: DIGEST,
  };
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Readonly<Record<string, unknown>>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  throw new Error("unsupported fixture value");
}

function digest(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function benchmarkSuite(): ReferenceBenchmarkSuite {
  const body: Omit<ReferenceBenchmarkSuite, "suite_sha256"> = {
    schema: "reference-benchmark-suite/v1",
    suite_id: "tears-of-steel-reference-suite-v1",
    definition_state: "sealed",
    result_state: "not-reported",
    scenarios: REFERENCE_SCENARIO_IDS.map((scenarioId) => ({
      scenario_id: scenarioId,
      scenario_sha256: SCENARIO_SHA256[scenarioId],
      incident_class: SCENARIOS[scenarioId].incidentClass,
      rerender_all_artifact_count: 240,
      targeted_artifact_count: 72,
      protected_artifact_count: 168,
      scope_reduction_basis_points: 7000,
    })),
    acceptance_requirements: {
      output_equivalence: "required",
      protected_output_integrity: "required",
      maximum_false_authorized_actions: 0,
      minimum_resolvable_holdout_accuracy_basis_points: 9500,
      minimum_median_compute_avoided_basis_points: 4000,
      minimum_median_bytes_avoided_basis_points: 4000,
    },
    measurement_boundary: {
      scope_reduction_is_measured_result: false,
      reported_results_require_recorded_evaluator_output: true,
      catalog_claims_observed_savings: false,
      live_run_scope: "representative-evidence-only",
    },
    result: null,
    provenance: PROVENANCE,
    authority: {
      ...AUTHORITY,
      benchmark_result_authority: "recorded-evaluator-output",
    },
  };
  return { ...body, suite_sha256: digest(canonicalJson(body)) };
}

function isScenarioId(value: string): value is ReferenceScenarioId {
  return REFERENCE_SCENARIO_IDS.some((scenarioId) => scenarioId === value);
}

function isVisualKind(value: string): value is ReferenceVisualKind {
  return VISUAL_KINDS.some((kind) => kind === value);
}

async function installReferenceApi(page: Page, mutations: string[]) {
  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() !== "GET") {
      mutations.push(`${request.method()} ${url.pathname}`);
      await route.fulfill({ json: { code: "unexpected-mutation" }, status: 503 });
      return;
    }
    if (url.pathname === "/v1/demo/scenarios") {
      await route.fulfill({ json: scenarioList() });
      return;
    }
    if (url.pathname === "/v1/benchmarks/reference-suite") {
      await route.fulfill({ json: benchmarkSuite() });
      return;
    }
    const visualMatch = url.pathname.match(/^\/v1\/demo\/scenarios\/([^/]+)\/visuals\/([^/]+)$/u);
    if (visualMatch !== null) {
      const scenarioId = visualMatch[1] ?? "";
      const kind = visualMatch[2] ?? "";
      if (isScenarioId(scenarioId) && isVisualKind(kind)) {
        const descriptor = previewManifest.scenarios[scenarioId].visuals[kind];
        await route.fulfill({
          body: await readFile(path.join(PREVIEW_ROOT, descriptor.filename)),
          contentType: "image/png",
          headers: {
            "X-ColorTrace-Pixel-Evidence": "true",
            "X-ColorTrace-Representation": descriptor.representation,
            "X-ColorTrace-Scenario-SHA256": SCENARIO_SHA256[scenarioId],
            "X-Content-SHA256": descriptor.sha256,
          },
        });
        return;
      }
    }
    const detailMatch = url.pathname.match(/^\/v1\/demo\/scenarios\/([^/]+)$/u);
    if (detailMatch !== null) {
      const scenarioId = detailMatch[1] ?? "";
      if (isScenarioId(scenarioId)) {
        await route.fulfill({ json: scenarioDetail(scenarioId) });
        return;
      }
    }
    await route.fulfill({ json: { code: "not-found" }, status: 404 });
  });
}

test("loads verified reference pixels and switches evidence contracts without mutating", async ({
  page,
}) => {
  const mutations: string[] = [];
  await installReferenceApi(page, mutations);

  await page.goto("/");

  const workspace = page.getByRole("region", {
    name: "Three ways a successful render can still be wrong",
  });
  await expect(workspace).toBeVisible();
  await expect(
    workspace.getByRole("heading", {
      name: "A successful render resolved the wrong look resource",
    }),
  ).toBeVisible();
  await expect(workspace.getByAltText(/Expected state open-film pixel preview/iu)).toHaveJSProperty(
    "naturalWidth",
    960,
  );
  await expect(
    workspace.getByAltText(/Observed failure open-film pixel preview/iu),
  ).toHaveJSProperty("naturalWidth", 960);
  await expect(workspace.getByText("PNG hash verified · pixel evidence")).toHaveCount(3);
  await expect(
    workspace.getByRole("heading", {
      name: "Gemini may select → Grafana can return → validators decide → human may authorize",
    }),
  ).toBeVisible();
  await expect(
    workspace.getByRole("heading", { name: "Sealed benchmark; results not reported" }),
  ).toBeVisible();

  await workspace.getByText("Inspect the bounded query and evidence contract").click();
  await expect(workspace.getByText("runtime.effective_resource_sha256")).toBeVisible();

  await workspace.getByRole("button", { name: /Configuration rollout.*72 affected/iu }).click();
  await expect(
    workspace.getByRole("heading", { name: "A stale color configuration remained active" }),
  ).toBeVisible();
  await expect(workspace.getByText("Effective config digest + generation")).toBeVisible();
  await expect(workspace.getByText("PNG hash verified · pixel evidence")).toHaveCount(3);
  await workspace.getByText("Inspect the bounded query and evidence contract").click();
  await expect(workspace.getByText("runtime.config_generation")).toBeVisible();
  await expect(workspace.getByRole("button", { name: "Run live investigation" })).toBeEnabled();
  expect(mutations).toEqual([]);
});
