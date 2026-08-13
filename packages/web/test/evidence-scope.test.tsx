import { projectIncidentReplay, type WorkspaceEvidence } from "@colortrace/workspace-model";
import {
  canonicalReplayFixture,
  cloneReplayFixture,
  unresolvedReplayFixture,
} from "@colortrace/workspace-model/test-fixtures";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import {
  inboxItemFromWorkspace,
  IncidentWorkspaceShell,
} from "../src/incident-workspace-shell.tsx";
import { ScopeView } from "../src/scope-view.tsx";

type Mutable<T> = T extends readonly (infer Item)[]
  ? Mutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
    : T;

const viewer = {
  kind: "authenticated",
  displayName: "Pipeline operator",
  principalKind: "human",
  roles: ["response-plan.editor", "response-plan.approver"],
} as const;

const responsePlan = {
  actionError: null,
  busy: false,
  capabilities: { canApprove: false, canEdit: false, session: "read-only" },
  onApprove: () => undefined,
  onEdit: () => undefined,
  onReject: () => undefined,
  state: { kind: "absent" },
} as const;

function renderCompleted(replay: Parameters<typeof projectIncidentReplay>[0]) {
  const workspace = projectIncidentReplay(replay);
  const incident = inboxItemFromWorkspace(workspace);
  const rendered = render(
    <IncidentWorkspaceShell
      incidents={[incident]}
      responsePlan={responsePlan}
      selectedIncidentId={incident.id}
      state={{ kind: "workspace", workspace }}
      viewer={viewer}
    />,
  );
  return { ...rendered, workspace };
}

function previewCount(evidence: readonly WorkspaceEvidence[]): number {
  return evidence.filter((item) => item.kind === "provider" || item.kind === "validator-artifact")
    .length;
}

afterEach(cleanup);

describe("evidence and affected scope", () => {
  it("renders the literal canonical scope counts without inventing graph edges", () => {
    const { container, workspace } = renderCompleted(canonicalReplayFixture);

    expect(screen.getAllByText("incident-canonical").length).toBeGreaterThan(0);
    expect(screen.getAllByText("claim-causal-resource").length).toBeGreaterThan(0);
    expect(screen.getAllByText("validator-evidence:frame-b-01").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Affected scope" })).toBeVisible();
    expect(screen.getByRole("heading", { name: "Evidence details" })).toBeVisible();
    expect(container.querySelectorAll('[data-scope-node="causal"]')).toHaveLength(1);
    expect(
      container.querySelectorAll('[data-scope-node="affected"][data-kind="frame"]'),
    ).toHaveLength(3);
    expect(
      container.querySelectorAll('[data-scope-node="affected"][data-kind="derivative"]'),
    ).toHaveLength(1);
    expect(container.querySelectorAll('[data-scope-node="safe"]')).toHaveLength(3);
    expect(container.querySelectorAll('[data-scope-node="unknown"]')).toHaveLength(0);
    expect(container.querySelectorAll("[data-scope-node]")).toHaveLength(8);
    expect(container.querySelectorAll("[data-scope-edge]")).toHaveLength(4);
    expect(container.querySelector('[data-scope-count="causal-resource"] dd')).toHaveTextContent(
      "1",
    );
    expect(container.querySelector('[data-scope-count="affected-frames"] dd')).toHaveTextContent(
      "3",
    );
    expect(
      container.querySelector('[data-scope-count="affected-derivatives"] dd'),
    ).toHaveTextContent("1");
    expect(container.querySelector('[data-scope-count="verified-safe"] dd')).toHaveTextContent("3");
    expect(container.querySelector('[data-scope-count="unknown-scope"] dd')).toHaveTextContent("0");
    expect(workspace.scope.edges).toHaveLength(4);
    expect(container.querySelectorAll("[data-evidence-item]")).toHaveLength(
      workspace.evidence.items.length,
    );
    expect(screen.getAllByRole("textbox")).toHaveLength(previewCount(workspace.evidence.items));
  });

  it("shows policy and evidence links for every displayed decisive relationship", () => {
    const { container, workspace } = renderCompleted(canonicalReplayFixture);
    const edgeElements = Array.from(container.querySelectorAll<HTMLElement>("[data-scope-edge]"));

    expect(edgeElements).toHaveLength(workspace.scope.edges.length);
    for (const element of edgeElements) {
      expect(within(element).getByText("Derivation policy")).toBeVisible();
      const citations = Array.from(element.querySelectorAll<HTMLElement>(".evidence-citation"));
      const links = within(element).getAllByRole("link");
      expect(citations.length).toBeGreaterThan(0);
      expect(links).toHaveLength(citations.length);
      for (const link of links) {
        const targetId = link.getAttribute("href")?.slice(1);
        expect(targetId).toBeTruthy();
        expect(
          Array.from(document.querySelectorAll<HTMLElement>("[id]")).filter(
            (candidate) => candidate.id === targetId,
          ),
        ).toHaveLength(1);
      }
    }

    const firstLink = within(edgeElements[0] as HTMLElement).getAllByRole("link")[0];
    expect(firstLink).toBeDefined();
    firstLink?.focus();
    expect(firstLink).toHaveFocus();
    const targetId = firstLink?.getAttribute("href")?.slice(1);
    expect(targetId).toBeTruthy();
    expect(document.getElementById(targetId ?? "missing")).not.toBeNull();
  });

  it("makes safe work on the implicated worker prominent without grouping causality by worker", () => {
    const { workspace } = renderCompleted(canonicalReplayFixture);
    const expected = workspace.scope.nodes.filter(
      (node) => node.kind === "frame" && node.safe_on_implicated_worker,
    );

    const callout = screen.getByRole("complementary", {
      name: "Safe work on the implicated worker",
    });
    expect(expected.length).toBeGreaterThan(0);
    for (const node of expected) {
      if (node.kind !== "frame") continue;
      expect(within(callout).getByText(node.job_id)).toBeVisible();
      expect(within(callout).getByText(node.id)).toBeVisible();
    }
    expect(screen.getByText(/worker identifiers are metadata/i)).toBeVisible();
  });

  it("distinguishes scope sets and exposes the reference-comparison boundary", () => {
    const { workspace } = renderCompleted(canonicalReplayFixture);
    const referenceLimit = workspace.limitations.find(
      (limitation) => limitation.code === "reference-policy-technical-only",
    );

    for (const heading of [
      "Causal resource",
      "Affected frames",
      "Affected derivatives",
      "Verified safe work",
      "Unknown scope",
    ]) {
      expect(screen.getByRole("heading", { name: heading })).toBeVisible();
    }
    expect(screen.getByRole("heading", { name: "Reference-comparison limitation" })).toBeVisible();
    expect(referenceLimit).toBeDefined();
    expect(screen.getAllByText(referenceLimit?.detail ?? "missing").length).toBeGreaterThan(0);
  });

  it("provides a keyboard-operable list fallback and bounded artifact previews", () => {
    const { workspace } = renderCompleted(canonicalReplayFixture);
    const summary = screen.getByText("Open scope list fallback");
    summary.focus();
    expect(summary).toHaveFocus();
    fireEvent.click(summary);

    const details = summary.closest("details");
    expect(details).toHaveAttribute("open");
    expect(
      screen.getByRole("table", { name: "Authoritative projected scope nodes" }),
    ).toBeVisible();
    expect(screen.getByRole("table", { name: "Decisive scope relationships" })).toBeVisible();

    const artifact = workspace.evidence.items.find((item) => item.kind === "validator-artifact");
    expect(artifact?.kind).toBe("validator-artifact");
    if (artifact?.kind !== "validator-artifact") return;
    const preview = screen.getByRole("textbox", {
      name: `Bounded artifact metadata preview for ${artifact.evidence_id}`,
    });
    preview.focus();
    expect(preview).toHaveFocus();
    expect((preview as HTMLTextAreaElement).value).toContain(artifact.content_sha256);
    expect(screen.getAllByText(/raw artifact bytes are not included/i).length).toBeGreaterThan(0);
  });

  it("keeps missing evidence and unknown scope explicit", () => {
    const { container, workspace } = renderCompleted(unresolvedReplayFixture);

    expect(screen.getByRole("heading", { name: "Referenced evidence is missing" })).toBeVisible();
    for (const reference of workspace.evidence.missing_references) {
      expect(screen.getAllByText(reference).length).toBeGreaterThan(0);
    }
    expect(container.querySelectorAll("[data-scope-node]")).toHaveLength(
      workspace.scope.nodes.length,
    );
    expect(container.querySelectorAll("[data-scope-edge]")).toHaveLength(0);
    expect(
      screen.getByText("No evidence-supported causal or lineage edge is recorded."),
    ).toBeVisible();
    expect(screen.getByRole("heading", { name: "Unknown scope" })).toBeVisible();
  });

  it("withholds the exact edge whose validator artifact was removed", () => {
    const replay = cloneReplayFixture() as Mutable<typeof canonicalReplayFixture>;
    const removedEvidenceId = "validator-evidence:frame-b-01";
    const validator = replay.validator_results[0];
    expect(validator).toBeDefined();
    if (validator === undefined) return;
    validator.evidence = validator.evidence.filter(
      (artifact) => artifact.evidence_id !== removedEvidenceId,
    );

    const { container, workspace } = renderCompleted(replay);

    expect(workspace.evidence.missing_references).toContain(removedEvidenceId);
    expect(workspace.scope.edges).toHaveLength(4);
    expect(container.querySelectorAll("[data-scope-edge]")).toHaveLength(3);
    expect(container.querySelector("[data-scope-edge] .evidence-citation--unlinked")).toBeNull();
    const alert = screen.getByRole("alert", { name: "Unsupported relationships withheld" });
    expect(alert).toHaveTextContent(`causal-scope:${"7".repeat(64)}:frame-b-01`);
    expect(alert).toHaveTextContent(removedEvidenceId);
    expect(alert).toHaveTextContent("is missing");
  });

  it.each(["stale", "unresolved"] as const)(
    "withholds an edge whose uniquely resolved citation is %s",
    (availability) => {
      const workspace = projectIncidentReplay(canonicalReplayFixture);
      const targetEvidenceId = "validator-evidence:frame-b-01";
      const evidence: WorkspaceEvidence[] = workspace.evidence.items.map((item) =>
        item.kind === "validator-artifact" && item.evidence_id === targetEvidenceId
          ? { ...item, availability }
          : item,
      );

      const { container } = render(
        <ScopeView
          evidence={evidence}
          limitations={workspace.limitations}
          scope={workspace.scope}
        />,
      );

      expect(container.querySelectorAll("[data-scope-edge]")).toHaveLength(3);
      const alert = screen.getByRole("alert", { name: "Unsupported relationships withheld" });
      expect(alert).toHaveTextContent(`validator-artifact:${targetEvidenceId} is ${availability}`);
    },
  );

  it("withholds an edge whose expected citation identity is ambiguous", () => {
    const workspace = projectIncidentReplay(canonicalReplayFixture);
    const targetEvidenceId = "validator-evidence:frame-b-01";
    const artifact = workspace.evidence.items.find(
      (item) => item.kind === "validator-artifact" && item.evidence_id === targetEvidenceId,
    );
    expect(artifact).toBeDefined();
    if (artifact === undefined) return;
    const duplicate: WorkspaceEvidence = {
      ...artifact,
      workspace_id: `${artifact.workspace_id}:duplicate`,
    };

    const { container } = render(
      <ScopeView
        evidence={[...workspace.evidence.items, duplicate]}
        limitations={workspace.limitations}
        scope={workspace.scope}
      />,
    );

    expect(container.querySelectorAll("[data-scope-edge]")).toHaveLength(3);
    const alert = screen.getByRole("alert", { name: "Unsupported relationships withheld" });
    expect(alert).toHaveTextContent(
      `validator-artifact:${targetEvidenceId} resolves to more than one evidence record`,
    );
  });

  it("withholds an edge when only evidence of the wrong kind has the cited identity", () => {
    const workspace = projectIncidentReplay(canonicalReplayFixture);
    const targetEvidenceId = "validator-evidence:frame-b-01";
    const provider = workspace.evidence.items.find((item) => item.kind === "provider");
    expect(provider).toBeDefined();
    if (provider === undefined) return;
    const wrongKind: WorkspaceEvidence = {
      ...provider,
      evidence_id: targetEvidenceId,
      workspace_id: `provider:${targetEvidenceId}`,
    };
    const evidence = workspace.evidence.items
      .filter(
        (item) => !(item.kind === "validator-artifact" && item.evidence_id === targetEvidenceId),
      )
      .concat(wrongKind);

    const { container } = render(
      <ScopeView evidence={evidence} limitations={workspace.limitations} scope={workspace.scope} />,
    );

    expect(container.querySelectorAll("[data-scope-edge]")).toHaveLength(3);
    const alert = screen.getByRole("alert", { name: "Unsupported relationships withheld" });
    expect(alert).toHaveTextContent(
      `validator-artifact:${targetEvidenceId} expects validator-artifact evidence but only provider evidence is present`,
    );
  });

  it("renders injection-shaped evidence only as inert text in linked previews", () => {
    const payload = '<svg onload="globalThis.compromised=true"><script>alert(1)</script>';
    const replay = cloneReplayFixture() as Mutable<typeof canonicalReplayFixture>;
    const provider = replay.evidence[0];
    expect(provider).toBeDefined();
    if (provider !== undefined) provider.display_excerpt = payload;

    const { container } = renderCompleted(replay);
    const preview = screen.getByRole("textbox", {
      name: `Bounded text preview for ${provider?.evidence_id}`,
    });
    expect(preview).toHaveValue(payload);
    expect(container.querySelector("svg")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(Reflect.get(globalThis, "compromised")).not.toBe(true);
  });
});
