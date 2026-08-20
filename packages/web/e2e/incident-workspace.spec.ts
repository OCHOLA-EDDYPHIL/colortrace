import AxeBuilder from "@axe-core/playwright";
import { projectIncidentReplay } from "@colortrace/workspace-model";
import { canonicalReplayFixture } from "@colortrace/workspace-model/test-fixtures";
import { expect, type Page, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { installPreparedApi } from "./api-fixtures.ts";

const DESKTOP_VIEWPORT = { width: 1440, height: 900 } as const;
const MOBILE_VIEWPORT = { width: 390, height: 844 } as const;
const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"] as const;
const packageRoot = fileURLToPath(new URL("..", import.meta.url));
const evidenceRoot = path.join(packageRoot, "evidence", "issue-21");
const issue22EvidenceRoot = path.join(packageRoot, "evidence", "issue-22");
const issue24EvidenceRoot = path.join(packageRoot, "evidence", "issue-24");
const uxEvidenceRoot = path.join(packageRoot, "evidence", "ux-accessibility");
const ISSUE_22_EVIDENCE_SCREENSHOTS = [
  {
    filename: "response-plan-review-1440x900.png",
    path: "packages/web/evidence/issue-22/response-plan-review-1440x900.png",
  },
  {
    filename: "response-plan-review-390x844.png",
    path: "packages/web/evidence/issue-22/response-plan-review-390x844.png",
  },
  {
    filename: "response-plan-actions-1440x900.png",
    path: "packages/web/evidence/issue-22/response-plan-actions-1440x900.png",
  },
  {
    filename: "response-plan-actions-390x844.png",
    path: "packages/web/evidence/issue-22/response-plan-actions-390x844.png",
  },
] as const;
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

async function captureIssue22Evidence(page: Page, name: string) {
  if (process.env.COLORTRACE_CAPTURE_ISSUE_22_EVIDENCE !== "1") return;
  await mkdir(issue22EvidenceRoot, { recursive: true });
  const planTop = await page.locator(".plan-panel").evaluate((element) => {
    return element.getBoundingClientRect().top + window.scrollY;
  });
  await page.evaluate(
    (top) => window.scrollTo({ behavior: "instant", top: Math.max(0, top - 16) }),
    planTop,
  );
  await page.screenshot({
    animations: "disabled",
    path: path.join(issue22EvidenceRoot, name),
  });
}

async function captureIssue22ActionEvidence(page: Page, name: string) {
  if (process.env.COLORTRACE_CAPTURE_ISSUE_22_EVIDENCE !== "1") return;
  await mkdir(issue22EvidenceRoot, { recursive: true });
  const controlsTop = await page.locator(".plan-controls").evaluate((element) => {
    return element.getBoundingClientRect().top + window.scrollY;
  });
  const viewport = page.viewportSize();
  const contextOffset = viewport !== null && viewport.width <= 760 ? 120 : 360;
  await page.evaluate(
    ({ offset, top }) => window.scrollTo({ behavior: "instant", top: Math.max(0, top - offset) }),
    { offset: contextOffset, top: controlsTop },
  );
  await page.screenshot({
    animations: "disabled",
    path: path.join(issue22EvidenceRoot, name),
  });
}

async function captureIssue24Evidence(page: Page, name: string) {
  if (process.env.COLORTRACE_CAPTURE_ISSUE_24_EVIDENCE !== "1") return;
  await mkdir(issue24EvidenceRoot, { recursive: true });
  const recoveryTop = await page.locator(".recovery-panel").evaluate((element) => {
    return element.getBoundingClientRect().top + window.scrollY;
  });
  await page.evaluate(
    (top) => window.scrollTo({ behavior: "instant", top: Math.max(0, top - 16) }),
    recoveryTop,
  );
  await page.screenshot({
    animations: "disabled",
    path: path.join(issue24EvidenceRoot, name),
  });
}

test("reports bound fixture impact without turning the counterfactual into a benchmark", async ({
  page,
}) => {
  await page.setViewportSize(DESKTOP_VIEWPORT);
  await installPreparedApi(page, { recoveryState: "recovery_verified" });
  await page.goto("/");

  const report = page.getByRole("region", { name: "Incident-level impact" });
  await expect(report).toBeVisible();
  await expect(report).toContainText("Not a production benchmark");
  const observed = report.locator(".impact-report__observed");
  const hypothetical = report.locator(".impact-report__hypothetical");
  await expect(observed).toContainText("Observed records");
  await expect(observed).toContainText("Affected frames3");
  await expect(observed).toContainText("Verified-safe frames3");
  await expect(observed).toContainText("Provider costNot recorded");
  await expect(observed).toContainText("Compute timeNot recorded");
  await expect(hypothetical).toContainText("Hypothetical comparison");
  await expect(hypothetical).toContainText("Rerenders avoided under assumption3");
  await expect(hypothetical).toContainText("not an observed cost, time saving");

  await report.getByText("Calculation policy, bindings, and limitations").click();
  await expect(report.getByText("fixture-observed-impact/v1")).toBeVisible();
  await expect(report.getByText(/recovery-packet:/u)).toBeVisible();
  await expect(report).not.toContainText("ROI");
  await expect(report).not.toContainText("industry-wide");
});

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

test("labels synthetic provenance and resets the workspace using read-only requests", async ({
  page,
}) => {
  const securityConsoleErrors: string[] = [];
  const pageErrors: string[] = [];
  page.on("console", (message) => {
    if (
      message.type() === "error" &&
      /Content Security Policy|@vitejs\/plugin-react|Refused to execute/iu.test(message.text())
    ) {
      securityConsoleErrors.push(message.text());
    }
  });
  page.on("pageerror", (error) => pageErrors.push(error.message));
  const { captured } = await installPreparedApi(page);

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();
  await expect(page.getByLabel("Data provenance")).toContainText("Synthetic simulator data");
  await page.getByRole("button", { name: "Reset workspace view" }).click();
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();

  const listRequests = captured.filter(
    (request) => new URL(request.url).pathname === "/v1/incidents",
  );
  expect(listRequests.length).toBeGreaterThanOrEqual(2);
  expect(captured.every((request) => request.method === "GET")).toBe(true);
  expect(securityConsoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
});

test("keeps slow, empty, and failed list states actionable", async ({ baseURL, browser }) => {
  if (baseURL === undefined) throw new Error("Playwright base URL is required");
  const delayedPage = await browser.newPage({ baseURL, viewport: DESKTOP_VIEWPORT });
  await installPreparedApi(delayedPage, { incidentListMode: "delayed" });
  await delayedPage.goto("/", { waitUntil: "domcontentloaded" });
  await expect(delayedPage.getByRole("heading", { name: "Loading incident" })).toBeVisible();
  await expect(delayedPage.getByRole("button", { name: "Reset workspace view" })).toBeEnabled();
  await expect(delayedPage.getByRole("heading", { name: "Incident overview" })).toBeVisible();
  await delayedPage.close();

  const emptyPage = await browser.newPage({ baseURL, viewport: DESKTOP_VIEWPORT });
  await installPreparedApi(emptyPage, { incidentListMode: "empty" });
  await emptyPage.goto("/");
  await expect(emptyPage.getByRole("heading", { name: "No incidents" })).toBeVisible();
  await expect(emptyPage.getByRole("button", { name: "Reset workspace view" })).toBeEnabled();
  await emptyPage.close();

  const errorPage = await browser.newPage({ baseURL, viewport: DESKTOP_VIEWPORT });
  await installPreparedApi(errorPage, { incidentListMode: "error" });
  await errorPage.goto("/");
  await expect(errorPage.getByRole("heading", { name: "Incident data unavailable" })).toBeVisible();
  await expect(errorPage.getByRole("button", { name: "Try again" })).toBeEnabled();
  await expect(errorPage.getByRole("button", { name: "Reset workspace view" })).toBeEnabled();
  await errorPage.close();
});

test("captures the current UX and accessibility evidence set", async ({ page }) => {
  test.skip(process.env.COLORTRACE_CAPTURE_UX_EVIDENCE !== "1");
  await mkdir(uxEvidenceRoot, { recursive: true });
  const { captured } = await installPreparedApi(page);

  await page.setViewportSize(DESKTOP_VIEWPORT);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();
  const axeResults = await new AxeBuilder({ page }).withTags([...WCAG_TAGS]).analyze();
  expect(axeResults.violations).toEqual([]);
  const contrastIncomplete = axeResults.incomplete.filter(
    (result) =>
      result.id === "color-contrast" &&
      (result.impact === "serious" ||
        result.impact === "critical" ||
        result.nodes.some((node) => node.impact === "serious" || node.impact === "critical")),
  );
  expect(contrastIncomplete).toEqual([]);

  await page.evaluate(() => window.scrollTo({ behavior: "instant", top: 0 }));
  const desktopImage = await page.screenshot({
    animations: "disabled",
    path: path.join(uxEvidenceRoot, "workspace-1440x900.png"),
  });
  const scopeTop = await page.locator(".scope-panel").evaluate((element) => {
    return element.getBoundingClientRect().top + window.scrollY;
  });
  await page.evaluate(
    (top) => window.scrollTo({ behavior: "instant", top: Math.max(0, top - 16) }),
    scopeTop,
  );
  const comparisonImage = await page.screenshot({
    animations: "disabled",
    path: path.join(uxEvidenceRoot, "evidence-comparison-1440x900.png"),
  });

  await page.setViewportSize(MOBILE_VIEWPORT);
  await page.evaluate(() => window.scrollTo({ behavior: "instant", top: 0 }));
  const mobileImage = await page.screenshot({
    animations: "disabled",
    path: path.join(uxEvidenceRoot, "workspace-390x844.png"),
  });
  await page.getByRole("button", { name: "Reset workspace view" }).click();
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();

  const requestMethods = [...new Set(captured.map((request) => request.method))].sort();
  expect(requestMethods).toEqual(["GET"]);
  await writeFile(
    path.join(uxEvidenceRoot, "acceptance-evidence.json"),
    `${JSON.stringify(
      {
        schema: "colortrace-ux-accessibility-evidence/v1",
        generated_at: new Date().toISOString(),
        source_test: "packages/web/e2e/incident-workspace.spec.ts",
        engine: axeResults.testEngine,
        wcag_tags: WCAG_TAGS,
        violations: axeResults.violations.length,
        serious_or_critical_color_contrast_incomplete: contrastIncomplete.length,
        reset: {
          control: "Reset workspace view",
          behavior: "Reload the generated fixture view and select its first incident.",
          request_methods: requestMethods,
          simulator_action_requests: captured.filter((request) =>
            new URL(request.url).pathname.includes("simulator-actions"),
          ).length,
        },
        screenshots: [
          {
            path: "packages/web/evidence/ux-accessibility/workspace-1440x900.png",
            sha256: createHash("sha256").update(desktopImage).digest("hex"),
          },
          {
            path: "packages/web/evidence/ux-accessibility/workspace-390x844.png",
            sha256: createHash("sha256").update(mobileImage).digest("hex"),
          },
          {
            path: "packages/web/evidence/ux-accessibility/evidence-comparison-1440x900.png",
            sha256: createHash("sha256").update(comparisonImage).digest("hex"),
          },
        ],
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
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
  await captureIssue22Evidence(page, "response-plan-review-390x844.png");
  await captureIssue22ActionEvidence(page, "response-plan-actions-390x844.png");
});

test("reflows without page-level overflow at a 200 percent zoom-equivalent viewport", async ({
  page,
}) => {
  await page.setViewportSize({ height: 450, width: 720 });
  await installPreparedApi(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Incident overview" })).toBeVisible();
  await expect(page.getByLabel("Data provenance")).toBeVisible();
  await expect(page.getByRole("button", { name: "Reset workspace view" })).toBeVisible();
  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.clientWidth);
});

test("requires exact confirmation and sends immutable bindings before approval", async ({
  page,
}) => {
  await page.setViewportSize(DESKTOP_VIEWPORT);
  const { captured, data, oidcToken } = await installPreparedApi(page);
  await page.goto("/");

  const planHeading = page.getByRole("heading", { name: "Response plan review" });
  await expect(planHeading).toBeVisible();
  await planHeading.scrollIntoViewIfNeeded();
  await captureIssue22Evidence(page, "response-plan-review-1440x900.png");
  await expect(page.getByText(data.responsePlan.plan.plan_sha256, { exact: true })).toBeVisible();
  const planPanel = page.locator(".plan-panel");
  await expect(
    planPanel.getByRole("heading", { name: "Shared simulator action envelope" }),
  ).toBeVisible();
  await expect(planPanel.getByText("Preservation manifest", { exact: true })).toBeVisible();
  await expect(planPanel.getByText("Safe complement", { exact: true })).toBeVisible();
  await expect(planPanel.getByText("Source PNG", { exact: true })).toHaveCount(2);
  await expect(planPanel.getByText("Expected derivative display", { exact: true })).toBeVisible();
  await captureIssue22ActionEvidence(page, "response-plan-actions-1440x900.png");

  await page.getByRole("button", { name: "Approve exact plan" }).click();
  expect(captured.some((request) => request.url.endsWith("/approve"))).toBe(false);
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText(data.responsePlan.plan.plan_sha256);
  await expect(dialog).toContainText("3 targets");
  await expect(dialog).toContainText("3 typed commands");
  const confirm = page.getByRole("button", { name: "Confirm approve" });
  const cancel = page.getByRole("button", { name: "Cancel" });
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(cancel).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Approve exact plan" })).toBeFocused();
  expect(captured.some((request) => request.url.endsWith("/approve"))).toBe(false);
  await page.getByRole("button", { name: "Approve exact plan" }).click();
  await page.getByRole("button", { name: "Confirm approve" }).click();

  await expect(page.locator('.status-badge[data-status="approved"]')).toBeVisible();
  const approval = captured.find((request) => request.url.endsWith("/approve"));
  expect(approval).toBeDefined();
  expect(approval?.headers.authorization).toBe(`Bearer ${oidcToken}`);
  expect(approval?.body).toEqual({
    expected_incident_version: data.responsePlan.plan.incident_version,
    expected_plan_version: data.responsePlan.plan.version,
    expected_plan_sha256: data.responsePlan.plan.plan_sha256,
    idempotency_key: expect.stringMatching(/^plan-approve-/),
  });
  await expect(page.getByRole("button", { name: "Approve exact plan" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Reject plan" })).toBeDisabled();
});

test("distinguishes unresolved blockers and unknown targets before acknowledgement", async ({
  page,
}) => {
  await installPreparedApi(page, { responsePlanUncertainty: true });
  await page.goto("/");

  const uncertainty = page.getByRole("region", { name: "Approval uncertainty" });
  await expect(uncertainty.getByText("validator-blocker", { exact: true })).toHaveCount(2);
  await expect(uncertainty.getByText("operator-review-note", { exact: true })).toBeVisible();
  await expect(uncertainty.getByText("frame-unknown-0009", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("checkbox", {
      name: "Acknowledge all listed unresolved items for this version",
    }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Approve exact plan" }).click();
  const dialog = page.getByRole("alertdialog");
  await expect(dialog).toContainText("validator-blocker");
  await expect(dialog).toContainText("frame-unknown-0009");
});

test("makes an approved-plan edit immutable and visibly returns it to pending review", async ({
  page,
}) => {
  const { captured, data } = await installPreparedApi(page, { responsePlanState: "approved" });
  await page.goto("/");
  await expect(page.locator('.status-badge[data-status="approved"]')).toBeVisible();

  const replacement = `sha256:${"4".repeat(64)}`;
  await page.getByRole("textbox", { name: "Approved replacement SHA-256" }).fill(replacement);
  await page.getByRole("button", { name: "Create revised version" }).click();
  await expect(page.getByRole("alertdialog")).toContainText(/invalidates any approval/i);
  await expect(page.getByRole("alertdialog")).toContainText(replacement);
  await page.getByRole("button", { name: "Confirm revise" }).click();

  await expect(page.locator('.status-badge[data-status="pending"]')).toBeVisible();
  await expect(page.locator(".plan-identity").getByText("2", { exact: true })).toBeVisible();
  const edit = captured.find((request) => request.method === "PUT");
  expect(edit?.body).toEqual({
    expected_incident_version: data.responsePlan.plan.incident_version,
    expected_plan_version: data.responsePlan.plan.version,
    expected_plan_sha256: data.responsePlan.plan.plan_sha256,
    response_packet_id: data.responsePlan.plan.response_packet_id,
    response_packet_sha256: data.responsePlan.plan.response_packet_sha256,
    deterministic_scope_sha256: data.responsePlan.plan.deterministic_scope_sha256,
    targets: data.responsePlan.plan.targets,
    exclusions: data.responsePlan.plan.exclusions,
    commands: data.responsePlan.plan.commands.map((command) => ({
      ...command,
      action_envelope: {
        ...command.action_envelope,
        replacement_resource_sha256: replacement,
      },
    })),
    unresolved_acknowledged: data.responsePlan.plan.unresolved_acknowledged,
    idempotency_key: expect.stringMatching(/^plan-edit-/),
  });
});

test("retries an ambiguous approval with one retained idempotency key", async ({ page }) => {
  const { captured } = await installPreparedApi(page, { approvalMode: "ambiguous-once" });
  await page.goto("/");

  await page.getByRole("button", { name: "Approve exact plan" }).click();
  await page.getByRole("button", { name: "Confirm approve" }).click();
  await expect(page.getByRole("alert")).toContainText(/mutation did not complete/i);
  await page.getByRole("button", { name: "Retry exact action" }).click();

  await expect(page.locator('.plan-panel .status-badge[data-status="approved"]')).toBeVisible();
  const approvals = captured.filter((request) => request.url.endsWith("/approve"));
  expect(approvals).toHaveLength(2);
  const firstApproval = approvals[0];
  const secondApproval = approvals[1];
  if (firstApproval === undefined || secondApproval === undefined) {
    throw new Error("Expected two captured approval requests");
  }
  expect((secondApproval.body as { idempotency_key: string }).idempotency_key).toBe(
    (firstApproval.body as { idempotency_key: string }).idempotency_key,
  );
});

test("reconciles an accepted approval without replaying it after refresh failure", async ({
  page,
}) => {
  const { captured } = await installPreparedApi(page, { approvalMode: "refresh-fails-once" });
  await page.goto("/");

  await page.getByRole("button", { name: "Approve exact plan" }).click();
  await page.getByRole("button", { name: "Confirm approve" }).click();
  await expect(page.getByRole("alert")).toContainText(/mutation was accepted/i);
  await expect(page.getByRole("button", { name: "Retry exact action" })).toHaveCount(0);
  await page.getByRole("button", { name: "Reconcile plan state" }).click();

  await expect(page.locator('.plan-panel .status-badge[data-status="approved"]')).toBeVisible();
  expect(captured.filter((request) => request.url.endsWith("/approve"))).toHaveLength(1);
});

test("keeps stale approval authority visibly disabled", async ({ page }) => {
  await installPreparedApi(page, { responsePlanState: "stale" });
  await page.goto("/");
  await expect(page.getByText(/stale and cannot be decided or dispatched/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve exact plan" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Create revised version" })).toBeDisabled();
});

test("keeps expired approval authority visibly disabled", async ({ page }) => {
  await installPreparedApi(page, { sessionStatus: "expired" });
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Operator session expired or invalid" }),
  ).toBeVisible();
  await expect(page.getByText(/controls remain disabled/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve exact plan" })).toBeDisabled();
});

test("renders exact post-action recovery authority and records explicit human closure", async ({
  page,
}) => {
  await page.setViewportSize(DESKTOP_VIEWPORT);
  const { captured, data, oidcToken } = await installPreparedApi(page, {
    recoveryState: "recovery_verified",
  });
  const recovery = data.recovery;
  if (recovery === null || recovery.packet === null) {
    throw new Error("Prepared recovery must include its verified packet");
  }
  await page.goto("/");

  const panel = page.locator(".recovery-panel");
  await expect(
    panel.getByRole("heading", { name: "Recovery verification and closure" }),
  ).toBeVisible();
  await expect(panel.getByText(/command success alone does not establish recovery/i)).toBeVisible();
  await expect(panel.locator(".recovery-check-list > li")).toHaveCount(7);
  await expect(
    panel.getByText(recovery.snapshot.action_outcome.outcome_sha256).first(),
  ).toBeVisible();
  await expect(
    panel
      .locator(".recovery-safe-work")
      .getByText(recovery.snapshot.action_outcome.safe_complement_before_sha256 ?? "missing"),
  ).toHaveCount(3);
  await panel.getByText("Open cited evidence and artifact records").click();
  await expect(panel.locator(".recovery-record")).toHaveCount(22);
  await captureIssue24Evidence(page, "recovery-verified-1440x900.png");

  const reason = "Reviewed exact post-action evidence and safe-work preservation.";
  await panel.getByRole("textbox", { name: "Closure reason" }).fill(reason);
  const trigger = panel.getByRole("button", { name: "Close verified recovery" });
  await trigger.click();
  const dialog = page.getByRole("alertdialog", { name: "Close this exact verified recovery?" });
  await expect(dialog).toContainText(recovery.packet.packet_sha256);
  await expect(dialog).toContainText(recovery.packet.outcome_sha256);
  const confirm = dialog.getByRole("button", { name: "Confirm closure" });
  const cancel = dialog.getByRole("button", { name: "Cancel" });
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  await expect(cancel).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(confirm).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(dialog).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await trigger.click();
  await page.getByRole("button", { name: "Confirm closure" }).click();

  await expect(panel.getByText(/one immutable human closure record/i)).toBeVisible();
  await expect(panel.getByText(reason)).toBeVisible();
  const closureRequest = captured.find((request) => request.url.endsWith("/recovery/close"));
  expect(closureRequest?.headers.authorization).toBe(`Bearer ${oidcToken}`);
  expect(closureRequest?.body).toEqual({
    schema: "recovery-closure-request/v1",
    expected_incident_version: recovery.current_incident_version,
    expected_workflow_version: recovery.workflow_version,
    expected_packet_id: recovery.packet.packet_id,
    expected_packet_sha256: recovery.packet.packet_sha256,
    expected_outcome_id: recovery.packet.outcome_id,
    expected_outcome_sha256: recovery.packet.outcome_sha256,
    reason,
    idempotency_key: expect.stringMatching(/^recovery-close-/),
  });
});

test("keeps unresolved recovery fail-closed and legible on a small viewport", async ({
  page,
}, testInfo) => {
  await page.setViewportSize(MOBILE_VIEWPORT);
  await installPreparedApi(page, { recoveryState: "recovery_unresolved" });
  await page.goto("/");

  const panel = page.locator(".recovery-panel");
  await expect(
    panel.locator('.status-badge[data-status="recovery_unresolved"]').first(),
  ).toBeVisible();
  await expect(panel.getByRole("textbox", { name: "Closure reason" })).toBeDisabled();
  await expect(panel.getByRole("button", { name: "Close verified recovery" })).toBeDisabled();
  await panel.getByText("Open cited evidence and artifact records").click();
  await expect(panel.getByText("Late evidence")).toBeVisible();
  await panel.scrollIntoViewIfNeeded();
  const layout = await page.evaluate(() => ({
    clientWidth: document.documentElement.clientWidth,
    scrollWidth: document.documentElement.scrollWidth,
  }));
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.clientWidth);

  const results = await new AxeBuilder({ page }).withTags([...WCAG_TAGS]).analyze();
  await testInfo.attach("recovery-axe-wcag-results", {
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
  await captureIssue24Evidence(page, "recovery-unresolved-390x844.png");
  if (process.env.COLORTRACE_CAPTURE_ISSUE_24_EVIDENCE === "1") {
    const screenshotPath = path.join(issue24EvidenceRoot, "recovery-unresolved-390x844.png");
    await writeFile(
      path.join(issue24EvidenceRoot, "accessibility-summary.json"),
      `${JSON.stringify(
        {
          schema: "colortrace-accessibility-evidence/v1",
          issue: 24,
          generated_at: new Date().toISOString(),
          source_test: "packages/web/e2e/incident-workspace.spec.ts",
          engine: results.testEngine,
          viewport: MOBILE_VIEWPORT,
          tags: WCAG_TAGS,
          violations: results.violations.length,
          incomplete: results.incomplete.length,
          serious_or_critical_color_contrast_incomplete: unresolvedContrast.length,
          passes: results.passes.length,
          screenshots: [
            {
              path: "packages/web/evidence/issue-24/recovery-unresolved-390x844.png",
              sha256: createHash("sha256")
                .update(await readFile(screenshotPath))
                .digest("hex"),
            },
          ],
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
  }
});

test("retries an ambiguous closure with one retained exact idempotency key", async ({ page }) => {
  const { captured } = await installPreparedApi(page, {
    closureMode: "ambiguous-once",
    recoveryState: "recovery_verified",
  });
  await page.goto("/");

  const panel = page.locator(".recovery-panel");
  await panel.getByRole("textbox", { name: "Closure reason" }).fill("Reviewed exact recovery.");
  await panel.getByRole("button", { name: "Close verified recovery" }).click();
  await page.getByRole("button", { name: "Confirm closure" }).click();
  await expect(panel.getByRole("alert")).toContainText(/closure response was ambiguous/i);
  await panel.getByRole("button", { name: "Retry exact closure" }).click();

  await expect(panel.getByText(/one immutable human closure record/i)).toBeVisible();
  const closures = captured.filter((request) => request.url.endsWith("/recovery/close"));
  expect(closures).toHaveLength(2);
  const first = closures[0]?.body as { idempotency_key: string } | undefined;
  const second = closures[1]?.body as { idempotency_key: string } | undefined;
  expect(first).toBeDefined();
  expect(second?.idempotency_key).toBe(first?.idempotency_key);
});

test("renders rejected plans as decided and exposes no dispatch control", async ({ page }) => {
  await installPreparedApi(page, { responsePlanState: "rejected" });
  await page.goto("/");

  await expect(page.locator('.plan-panel .status-badge[data-status="rejected"]')).toBeVisible();
  await expect(page.getByText(/rejected by/i)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve exact plan" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Reject plan" })).toBeDisabled();
  await expect(page.getByRole("button", { name: /dispatch/i })).toHaveCount(0);
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
  if (process.env.COLORTRACE_CAPTURE_ISSUE_22_EVIDENCE === "1") {
    await mkdir(issue22EvidenceRoot, { recursive: true });
    const screenshots = await Promise.all(
      ISSUE_22_EVIDENCE_SCREENSHOTS.map(async (screenshot) => ({
        path: screenshot.path,
        sha256: createHash("sha256")
          .update(await readFile(path.join(issue22EvidenceRoot, screenshot.filename)))
          .digest("hex"),
      })),
    );
    await writeFile(
      path.join(issue22EvidenceRoot, "accessibility-summary.json"),
      `${JSON.stringify(
        {
          schema: "colortrace-accessibility-evidence/v1",
          issue: 22,
          generated_at: new Date().toISOString(),
          source_test: "packages/web/e2e/incident-workspace.spec.ts",
          engine: results.testEngine,
          viewport: DESKTOP_VIEWPORT,
          tags: WCAG_TAGS,
          violations: results.violations.length,
          incomplete: results.incomplete.length,
          serious_or_critical_color_contrast_incomplete: unresolvedContrast.length,
          passes: results.passes.length,
          screenshots,
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
    `/v1/incidents/${data.incident.incident_id}/response-plan`,
    `/v1/incidents/${data.incident.incident_id}/recovery`,
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
  await expect(page.getByRole("heading", { name: "Response plan review" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve exact plan" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Create revised version" })).toBeDisabled();
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
  await installPreparedApi(page, { providerExcerpt: payload, responsePlanCommandId: payload });
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
