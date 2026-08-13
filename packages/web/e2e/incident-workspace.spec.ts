import AxeBuilder from "@axe-core/playwright";
import { projectIncidentReplay } from "@colortrace/workspace-model";
import { canonicalReplayFixture } from "@colortrace/workspace-model/test-fixtures";
import { expect, type Page, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { installPreparedApi } from "./api-fixtures.ts";

const DESKTOP_VIEWPORT = { width: 1440, height: 900 } as const;
const MOBILE_VIEWPORT = { width: 390, height: 844 } as const;
const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] as const;
const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const evidenceRoot = path.join(packageRoot, "evidence", "issue-21");
const EVIDENCE_SCREENSHOTS = {
  desktop: {
    path: "packages/web/evidence/issue-21/evidence-scope-1440x900.png",
    sha256: "ebfd353c8471a59cbe208123a6b8c612c2f6e7d97a206bc5e70c4a8d6bbe447f",
  },
  mobile: {
    path: "packages/web/evidence/issue-21/evidence-scope-390x844.png",
    sha256: "8d611ecd7243df429befcbfce6125b0c12ff2e8edad76de4cf9f021542b5b60c",
  },
} as const;

async function captureEvidenceScreenshot(
  page: Page,
  screenshot: (typeof EVIDENCE_SCREENSHOTS)[keyof typeof EVIDENCE_SCREENSHOTS],
) {
  if (process.env.COLORTRACE_CAPTURE_EVIDENCE !== "1") return;
  await mkdir(evidenceRoot, { recursive: true });
  const scopeTop = await page.locator(".scope-panel").evaluate((element) => {
    return element.getBoundingClientRect().top + window.scrollY;
  });
  await page.evaluate(
    (top) => window.scrollTo({ behavior: "instant", top: Math.max(0, top - 16) }),
    scopeTop,
  );
  const image = await page.screenshot({
    animations: "disabled",
    path: path.join(packageRoot, path.relative("packages/web", screenshot.path)),
  });
  expect(createHash("sha256").update(image).digest("hex")).toBe(screenshot.sha256);
}

test("renders the canonical evidence and exact supported scope at 1440x900", async ({
  page,
}, testInfo) => {
  await page.setViewportSize(DESKTOP_VIEWPORT);
  const { data } = await installPreparedApi(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();
  await expect(page.getByText("Pipeline operator", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Investigation timeline" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Affected scope" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Evidence details" })).toBeVisible();

  for (const category of [
    "Source observation",
    "Model reasoning",
    "Deterministic result",
    "Workflow event",
    "Human event",
  ]) {
    await expect(page.getByRole("list", { name: "Timeline record categories" })).toContainText(
      category,
    );
  }

  const workspace = projectIncidentReplay({
    ...canonicalReplayFixture,
    human_events: data.source.human_events,
  });
  await expect(page.locator(".timeline-entry")).toHaveCount(workspace.timeline.length);
  await expect(page.locator(".timeline-entry", { hasText: "incident.admitted" })).toContainText(
    "Pipeline operator (operator@example.test)",
  );
  await expect(page.getByText("incident-canonical", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("claim-causal-resource", { exact: true }).first()).toBeVisible();
  await expect(
    page.locator('[data-evidence-item="validator-artifact"]', {
      hasText: "validator-evidence:frame-b-01",
    }),
  ).toHaveCount(1);
  await expect(page.locator('[data-scope-node="causal"]')).toHaveCount(1);
  await expect(page.locator('[data-scope-node="affected"][data-kind="frame"]')).toHaveCount(3);
  await expect(page.locator('[data-scope-node="affected"][data-kind="derivative"]')).toHaveCount(1);
  await expect(page.locator('[data-scope-node="safe"]')).toHaveCount(3);
  await expect(page.locator('[data-scope-node="unknown"]')).toHaveCount(0);
  await expect(page.locator("[data-scope-edge]")).toHaveCount(4);
  await expect(page.locator('[data-scope-count="causal-resource"] dd')).toHaveText("1");
  await expect(page.locator('[data-scope-count="affected-frames"] dd')).toHaveText("3");
  await expect(page.locator('[data-scope-count="affected-derivatives"] dd')).toHaveText("1");
  await expect(page.locator('[data-scope-count="verified-safe"] dd')).toHaveText("3");
  await expect(page.locator('[data-scope-count="unknown-scope"] dd')).toHaveText("0");
  await expect(
    page.getByRole("heading", { name: "Safe work on the implicated worker" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Reference-comparison limitation" }),
  ).toBeVisible();

  const edgeCitationAudit = await page.locator("[data-scope-edge]").evaluateAll((edges) =>
    edges.map((edge) => {
      const citations = Array.from(edge.querySelectorAll<HTMLElement>(".evidence-citation"));
      const links = citations.filter(
        (citation): citation is HTMLAnchorElement => citation instanceof HTMLAnchorElement,
      );
      return {
        citations: citations.length,
        linked: links.length,
        uniqueTargets: links.filter((link) => {
          const id = link.getAttribute("href")?.slice(1);
          if (id === undefined || id.length === 0) return false;
          return (
            Array.from(document.querySelectorAll<HTMLElement>("[id]")).filter(
              (candidate) => candidate.id === id,
            ).length === 1
          );
        }).length,
      };
    }),
  );
  expect(edgeCitationAudit).toHaveLength(4);
  for (const edge of edgeCitationAudit) {
    expect(edge.citations).toBeGreaterThan(0);
    expect(edge.linked).toBe(edge.citations);
    expect(edge.uniqueTargets).toBe(edge.citations);
  }

  const citationGeometry = await page.locator(".citation-list > li").evaluateAll((items) =>
    items.map((item) => {
      const citation = item.querySelector<HTMLElement>(".evidence-citation");
      const code = citation?.querySelector<HTMLElement>("code");
      if (citation === null || citation === undefined || code === null || code === undefined) {
        return null;
      }
      const itemBox = item.getBoundingClientRect();
      const citationBox = citation.getBoundingClientRect();
      const codeBox = code.getBoundingClientRect();
      return {
        citationWidth: citationBox.width,
        codeWidth: codeBox.width,
        itemWidth: itemBox.width,
      };
    }),
  );
  expect(citationGeometry.length).toBeGreaterThan(0);
  for (const geometry of citationGeometry) {
    expect(geometry).not.toBeNull();
    if (geometry === null) continue;
    expect(Math.abs(geometry.citationWidth - geometry.itemWidth)).toBeLessThanOrEqual(1);
    expect(geometry.codeWidth).toBeGreaterThanOrEqual(192);
  }

  const claimTimes = page.locator(".claim-card time");
  await expect(claimTimes).toHaveCount(workspace.claims.length);
  for (let index = 0; index < workspace.claims.length; index += 1) {
    await expect(claimTimes.nth(index)).toHaveAttribute(
      "datetime",
      canonicalReplayFixture.packet.finalized_at,
    );
  }

  await testInfo.attach("prepared-investigation-1440x900", {
    body: await page.screenshot(),
    contentType: "image/png",
  });
  await captureEvidenceScreenshot(page, EVIDENCE_SCREENSHOTS.desktop);
});

test("keeps the investigation legible without page-level horizontal overflow on a small viewport", async ({
  page,
}, testInfo) => {
  await page.setViewportSize(MOBILE_VIEWPORT);
  await installPreparedApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();

  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.clientWidth);

  const inboxBox = await page.getByRole("navigation", { name: "Incident inbox" }).boundingBox();
  const mainBox = await page.locator("main").boundingBox();
  expect(inboxBox).not.toBeNull();
  expect(mainBox).not.toBeNull();
  if (inboxBox !== null && mainBox !== null) {
    expect(mainBox.y).toBeGreaterThanOrEqual(inboxBox.y + inboxBox.height - 1);
  }

  await expect(page.getByRole("heading", { name: "Investigation timeline" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Affected scope" })).toBeVisible();
  await testInfo.attach("prepared-investigation-small-viewport", {
    body: await page.screenshot(),
    contentType: "image/png",
  });
  await captureEvidenceScreenshot(page, EVIDENCE_SCREENSHOTS.mobile);
});

test("supports keyboard skip navigation into the incident details", async ({ page }) => {
  await installPreparedApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press("Tab");
  const skipLink = page.getByRole("link", { name: "Skip to incident details" });
  await expect(skipLink).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("main")).toBeFocused();

  const fallbackDetails = page.locator(".scope-list-fallback");
  const fallback = fallbackDetails.getByText("Open scope list fallback");
  await fallback.focus();
  await page.keyboard.press("Enter");
  await expect(fallbackDetails).toHaveAttribute("open", "");

  const firstCitation = page.locator("[data-scope-edge] a.evidence-citation").first();
  await firstCitation.focus();
  await expect(firstCitation).toBeFocused();
  const target = await firstCitation.getAttribute("href");
  await page.keyboard.press("Enter");
  await expect(page.locator(target ?? "#missing-evidence-target")).toBeVisible();
});

test("passes automated WCAG A and AA checks for the prepared workspace", async ({
  page,
}, testInfo) => {
  await page.setViewportSize(DESKTOP_VIEWPORT);
  await installPreparedApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Investigation timeline" })).toBeVisible();

  const results = await new AxeBuilder({ page }).withTags([...WCAG_TAGS]).analyze();
  await testInfo.attach("axe-wcag-results", {
    body: Buffer.from(JSON.stringify(results, null, 2)),
    contentType: "application/json",
  });
  expect(
    results.violations,
    results.violations.map((violation) => `${violation.id}: ${violation.help}`).join("\n"),
  ).toEqual([]);
  const unresolvedContrast = results.incomplete.filter(
    (result) =>
      result.id === "color-contrast" &&
      (result.impact === "serious" ||
        result.impact === "critical" ||
        result.nodes.some((node) => node.impact === "serious" || node.impact === "critical")),
  );
  expect(
    unresolvedContrast,
    unresolvedContrast
      .map((result) => `${result.id}: ${result.help} (${result.nodes.length} nodes)`)
      .join("\n"),
  ).toEqual([]);
  if (process.env.COLORTRACE_CAPTURE_EVIDENCE === "1") {
    await mkdir(evidenceRoot, { recursive: true });
    await writeFile(
      path.join(evidenceRoot, "accessibility-summary.json"),
      `${JSON.stringify(
        {
          schema: "colortrace-accessibility-evidence/v1",
          issue: 21,
          generated_at: new Date().toISOString(),
          source_test: "packages/web/e2e/incident-workspace.spec.ts",
          engine: results.testEngine,
          viewport: DESKTOP_VIEWPORT,
          tags: WCAG_TAGS,
          violations: results.violations.length,
          incomplete: results.incomplete.length,
          serious_or_critical_color_contrast_incomplete: unresolvedContrast.length,
          passes: results.passes.length,
          screenshots: Object.values(EVIDENCE_SCREENSHOTS),
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
  }
});

test("uses a same-origin in-memory OIDC token provider without browser token storage", async ({
  baseURL,
  page,
}) => {
  if (baseURL === undefined) throw new Error("Playwright base URL is required");
  const { captured, data, oidcToken } = await installPreparedApi(page);
  if (oidcToken === null) throw new Error("Prepared API did not install an OIDC provider");
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();

  const expectedPaths = new Set([
    "/v1/session",
    "/v1/incidents",
    `/v1/incidents/${data.incident.incident_id}/workspace`,
  ]);
  const seenPaths = new Set(captured.map((request) => new URL(request.url).pathname));
  expect(seenPaths).toEqual(expectedPaths);
  for (const request of captured) {
    expect(new URL(request.url).origin).toBe(new URL(baseURL).origin);
    expect(request.method).toBe("GET");
    if (new URL(request.url).pathname === "/v1/session") {
      expect(request.headers.authorization).toBe(`Bearer ${oidcToken}`);
    } else {
      expect(request.headers.authorization).toBeUndefined();
    }
  }

  expect(
    await page.evaluate(() => ({
      hostProviderPresent: Object.hasOwn(
        globalThis,
        Symbol.for("colortrace.host.oidc-token-provider/v1"),
      ),
      localStorage: Object.keys(window.localStorage),
      sessionStorage: Object.keys(window.sessionStorage),
    })),
  ).toEqual({ hostProviderPresent: false, localStorage: [], sessionStorage: [] });
});

test("falls back to public read-only workspace when no host token provider is installed", async ({
  page,
}) => {
  const { captured } = await installPreparedApi(page, { oidcToken: null });
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Unauthenticated read-only session" }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();
  const sessionRequest = captured.find(
    (request) => new URL(request.url).pathname === "/v1/session",
  );
  expect(sessionRequest?.headers.authorization).toBeUndefined();
});

test("fails closed when a ready view packet does not match the replay packet", async ({ page }) => {
  await installPreparedApi(page, { viewPacket: "mismatched" });
  await page.goto("/");

  await expect(
    page.getByRole("heading", { name: "Incident replay could not be verified" }),
  ).toBeVisible();
  await expect(page.getByText(/packet did not match the verified replay/i)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Investigation timeline" })).toHaveCount(0);
});

test("withholds a relationship when its cited validator artifact is missing", async ({ page }) => {
  const removedEvidenceId = "validator-evidence:frame-b-01";
  await installPreparedApi(page, { removedValidatorEvidenceId: removedEvidenceId });
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Referenced evidence is missing" })).toBeVisible();
  await expect(
    page.getByRole("alert", { name: "Unsupported relationships withheld" }),
  ).toContainText(removedEvidenceId);
  await expect(page.locator("[data-scope-edge]")).toHaveCount(3);
  await expect(page.locator("[data-scope-edge] .evidence-citation--unlinked")).toHaveCount(0);
});

test("keeps provider payloads inert in a real browser", async ({ page }) => {
  const payload = '<img src=x onerror="globalThis.compromised=true"><script>alert(1)</script>';
  await installPreparedApi(page, { providerExcerpt: payload });
  await page.goto("/");
  await expect(page.locator("textarea.evidence-preview").first()).toHaveValue(payload);
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  expect(
    await page
      .locator("script")
      .evaluateAll((scripts) => scripts.some((script) => script.textContent?.includes("alert(1)"))),
  ).toBe(false);
  expect(await page.evaluate(() => Reflect.get(globalThis, "compromised"))).toBeUndefined();
});
