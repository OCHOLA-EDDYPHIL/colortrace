import AxeBuilder from "@axe-core/playwright";
import { projectIncidentReplay } from "@colortrace/workspace-model";
import { canonicalReplayFixture } from "@colortrace/workspace-model/test-fixtures";
import { expect, test } from "@playwright/test";

import { installPreparedApi } from "./api-fixtures.ts";

const DESKTOP_VIEWPORT = { width: 1440, height: 900 } as const;
const MOBILE_VIEWPORT = { width: 390, height: 844 } as const;

test("renders the prepared incident overview and timeline at 1440x900", async ({
  page,
}, testInfo) => {
  await page.setViewportSize(DESKTOP_VIEWPORT);
  const { data } = await installPreparedApi(page);
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();
  await expect(page.getByText("Pipeline operator", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Investigation timeline" })).toBeVisible();

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
  await testInfo.attach("prepared-investigation-small-viewport", {
    body: await page.screenshot(),
    contentType: "image/png",
  });
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
});

test("passes automated WCAG A and AA checks for the prepared workspace", async ({
  page,
}, testInfo) => {
  await page.setViewportSize(DESKTOP_VIEWPORT);
  await installPreparedApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Investigation timeline" })).toBeVisible();

  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
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

test("keeps provider payloads inert in a real browser", async ({ page }) => {
  const payload = '<img src=x onerror="globalThis.compromised=true"><script>alert(1)</script>';
  await installPreparedApi(page, { providerExcerpt: payload });
  await page.goto("/");
  await expect(page.getByText(payload, { exact: true }).first()).toBeVisible();
  await expect(page.locator('img[src="x"]')).toHaveCount(0);
  expect(
    await page
      .locator("script")
      .evaluateAll((scripts) => scripts.some((script) => script.textContent?.includes("alert(1)"))),
  ).toBe(false);
  expect(await page.evaluate(() => Reflect.get(globalThis, "compromised"))).toBeUndefined();
});
