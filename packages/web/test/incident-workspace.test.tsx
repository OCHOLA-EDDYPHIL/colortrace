import { projectIncidentReplay, type WorkspaceIncidentSummary } from "@colortrace/workspace-model";
import {
  canonicalReplayFixture,
  cloneReplayFixture,
  unresolvedReplayFixture,
} from "@colortrace/workspace-model/test-fixtures";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  inboxItemFromWorkspace,
  IncidentWorkspaceShell,
} from "../src/incident-workspace-shell.tsx";
import { InvestigationTimeline } from "../src/investigation-timeline.tsx";
import type { IncidentWorkspaceViewState } from "../src/view-state.ts";

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

function pendingIncident(
  status: "queued" | "running",
  overrides: Partial<WorkspaceIncidentSummary> = {},
): WorkspaceIncidentSummary {
  return {
    id: `incident-${status}`,
    alert_id: `alert-${status}`,
    status,
    created_at: "2026-08-13T12:00:00.000Z",
    updated_at: "2026-08-13T12:01:00.000Z",
    delayed: false,
    missing: [],
    ...overrides,
  };
}

function renderWorkspace(
  state: IncidentWorkspaceViewState,
  incidents: readonly WorkspaceIncidentSummary[] = [],
  options: {
    readonly onReset?: () => void;
    readonly onRetry?: () => void;
    readonly onSelectIncident?: (id: string) => void;
  } = {},
) {
  return render(
    <IncidentWorkspaceShell
      incidents={incidents}
      selectedIncidentId={incidents[0]?.id ?? null}
      responsePlan={responsePlan}
      state={state}
      viewer={viewer}
      {...options}
    />,
  );
}

afterEach(cleanup);

describe("IncidentWorkspaceShell adverse and lifecycle states", () => {
  it("identifies synthetic provenance and offers a deterministic view reset", () => {
    const reset = vi.fn();
    renderWorkspace({ kind: "empty", message: "No incident records were returned." }, [], {
      onReset: reset,
    });

    expect(screen.getByLabelText("Data provenance")).toHaveTextContent("Synthetic simulator data");
    expect(screen.getByLabelText("Data provenance")).toHaveTextContent("simulator-only actions");
    const button = screen.getByRole("button", { name: "Reset workspace view" });
    fireEvent.click(button);
    expect(reset).toHaveBeenCalledOnce();
  });

  it("announces loading without moving keyboard focus", () => {
    renderWorkspace({ kind: "loading", message: "Loading the incident list." });

    expect(screen.getByRole("status")).toHaveTextContent("Loading incident");
    expect(screen.getByText("Loading incident").closest("div[aria-busy='true']")).not.toBeNull();
    const skipLink = screen.getByRole("link", { name: "Skip to incident details" });
    skipLink.focus();
    expect(skipLink).toHaveFocus();
  });

  it("renders an explicit empty inbox and workspace", () => {
    renderWorkspace({ kind: "empty", message: "No incident records were returned." });

    expect(screen.getByRole("navigation", { name: "Incident inbox" })).toHaveTextContent(
      "No incidents are available.",
    );
    expect(screen.getByRole("status")).toHaveTextContent("No incident records were returned.");
  });

  it("renders a fetch failure with a keyboard-operable retry", () => {
    const retry = vi.fn();
    renderWorkspace({ kind: "fetch-error", message: "The incident service did not respond." }, [], {
      onRetry: retry,
    });

    expect(screen.getByRole("alert")).toHaveTextContent("Incident data unavailable");
    const button = screen.getByRole("button", { name: "Try again" });
    button.focus();
    expect(button).toHaveFocus();
    fireEvent.click(button);
    expect(retry).toHaveBeenCalledOnce();
  });

  it("explains queued work and what has not started", () => {
    const incident = pendingIncident("queued", { missing: ["Worker start record"] });
    renderWorkspace({ kind: "queued", incident }, [incident]);

    expect(screen.getByRole("heading", { name: "Investigation queued" })).toBeVisible();
    expect(screen.getByText(/worker has not started this investigation/i)).toBeVisible();
    expect(screen.getByText("Worker start record")).toBeVisible();
    expect(screen.getAllByText("Queued").length).toBeGreaterThan(0);
  });

  it("explains delayed running work and its missing records", () => {
    const incident = pendingIncident("running", {
      delayed: true,
      missing: ["Deterministic validator result", "Final response packet"],
    });
    renderWorkspace({ kind: "running", incident }, [incident]);

    expect(screen.getByRole("heading", { name: "Investigation in progress" })).toBeVisible();
    expect(screen.getByText(/investigation is delayed/i)).toBeVisible();
    expect(screen.getByText("Deterministic validator result")).toBeVisible();
    expect(screen.getByText("Final response packet")).toBeVisible();
  });

  it("withholds details when replay integrity fails", () => {
    const incident = pendingIncident("running");
    renderWorkspace(
      {
        kind: "integrity-error",
        incident,
        message: "Scope identities do not match the persisted validator result.",
      },
      [incident],
    );

    expect(screen.getByRole("alert")).toHaveTextContent("Incident replay could not be verified");
    expect(screen.getByText(/workspace is withheld/i)).toBeVisible();
    expect(screen.queryByRole("heading", { name: "Investigation timeline" })).toBeNull();
  });
});

describe("completed incident overview and timeline", () => {
  it("renders a resolved projection with accessible claims, timestamps, and category labels", () => {
    const workspace = projectIncidentReplay(canonicalReplayFixture);
    const incident = inboxItemFromWorkspace(workspace);
    renderWorkspace({ kind: "workspace", workspace }, [incident]);

    expect(screen.getByRole("heading", { name: "Incident overview" })).toBeVisible();
    expect(screen.getByText(/persisted investigation packet is complete/i)).toBeVisible();
    expect(screen.getByRole("heading", { name: "Investigation timeline" })).toBeVisible();
    expect(screen.getAllByText("Resolved").length).toBeGreaterThan(0);
    expect(document.querySelectorAll("time[datetime]").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Packet finalized").length).toBe(workspace.claims.length);
    for (const time of document.querySelectorAll(".claim-card time")) {
      expect(time).toHaveAttribute("datetime", canonicalReplayFixture.packet.finalized_at);
    }

    const categoryList = screen.getByRole("list", { name: "Timeline record categories" });
    for (const label of [
      "Source observation",
      "Model reasoning",
      "Deterministic result",
      "Workflow event",
      "Human event",
    ]) {
      expect(within(categoryList).getByText(label)).toBeVisible();
    }
    expect(screen.getAllByRole("list", { name: "Citations" }).length).toBeGreaterThan(0);
  });

  it("shows an explicit unavailable fallback when packet finalization time is absent", () => {
    const replay = cloneReplayFixture() as Mutable<typeof canonicalReplayFixture>;
    replay.packet.finalized_at = "not-a-timestamp";
    const workspace = projectIncidentReplay(replay);
    const incident = inboxItemFromWorkspace(workspace);
    renderWorkspace({ kind: "workspace", workspace }, [incident]);

    expect(screen.getAllByText("Packet finalized").length).toBe(workspace.claims.length);
    expect(document.querySelectorAll(".claim-card time")).toHaveLength(0);
    expect(document.querySelectorAll(".claim-card .timestamp--unavailable")).toHaveLength(
      workspace.claims.length,
    );
  });

  it("keeps an unresolved projection explicit and names missing evidence", () => {
    const workspace = projectIncidentReplay(unresolvedReplayFixture);
    const incident = inboxItemFromWorkspace(workspace);
    renderWorkspace({ kind: "workspace", workspace }, [incident]);

    expect(screen.getByText(/investigation is unresolved/i)).toBeVisible();
    expect(screen.getByRole("heading", { name: "Investigation conditions" })).toBeVisible();
    expect(screen.getByText(/missing evidence/i)).toBeVisible();
    expect(screen.getAllByText("Unresolved").length).toBeGreaterThan(0);
  });

  it("fails closed when the shared projection reports invalid scope parity", () => {
    const replay = cloneReplayFixture() as Mutable<typeof canonicalReplayFixture>;
    const affected = replay.packet.scope.affected[0];
    expect(affected).toBeDefined();
    if (affected !== undefined) affected.id = "frame-not-in-validator-result";
    const workspace = projectIncidentReplay(replay);
    const incident = inboxItemFromWorkspace(workspace);
    renderWorkspace({ kind: "workspace", workspace }, [incident]);

    expect(workspace.overview.state).toBe("invalid");
    expect(screen.getByRole("alert")).toHaveTextContent("Incident replay could not be verified");
    expect(screen.queryByRole("heading", { name: "Investigation timeline" })).toBeNull();
  });

  it("labels an empty timeline without inventing records", () => {
    render(<InvestigationTimeline entries={[]} evidence={[]} />);

    expect(screen.getByRole("heading", { name: "Investigation timeline" })).toBeVisible();
    expect(screen.getByText("No timeline records are available.")).toBeVisible();
    expect(screen.queryByRole("article")).toBeNull();
  });

  it("keeps injection-shaped provider text inert", () => {
    const payload = '<img src=x onerror="globalThis.compromised=true"><script>alert(1)</script>';
    const replay = cloneReplayFixture() as Mutable<typeof canonicalReplayFixture>;
    const evidence = replay.evidence[0];
    expect(evidence).toBeDefined();
    if (evidence !== undefined) {
      evidence.display_excerpt = payload;
    }
    const workspace = projectIncidentReplay(replay);
    const incident = inboxItemFromWorkspace(workspace);
    const { container } = renderWorkspace({ kind: "workspace", workspace }, [incident]);

    expect(screen.getAllByText(payload).length).toBeGreaterThan(0);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(Reflect.get(globalThis, "compromised")).not.toBe(true);
  });

  it("keeps inbox selection in normal keyboard order", () => {
    const resolvedWorkspace = projectIncidentReplay(canonicalReplayFixture);
    const unresolvedWorkspace = projectIncidentReplay(unresolvedReplayFixture);
    const incidents = [
      inboxItemFromWorkspace(resolvedWorkspace),
      inboxItemFromWorkspace(unresolvedWorkspace),
    ];
    const select = vi.fn();
    renderWorkspace({ kind: "workspace", workspace: resolvedWorkspace }, incidents, {
      onSelectIncident: select,
    });

    const inbox = screen.getByRole("navigation", { name: "Incident inbox" });
    const links = within(inbox).getAllByRole("link");
    expect(links).toHaveLength(2);
    links[1]?.focus();
    expect(links[1]).toHaveFocus();
    if (links[1] !== undefined) fireEvent.click(links[1]);
    expect(select).toHaveBeenCalledWith(unresolvedWorkspace.incident.id);
  });
});
