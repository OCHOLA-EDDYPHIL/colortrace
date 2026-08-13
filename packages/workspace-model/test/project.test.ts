import { describe, expect, expectTypeOf, it } from "vitest";

import type { IncidentReplay as GeneratedIncidentReplay } from "../../api-client/src/generated/types.gen.ts";
import { sha256Hex } from "../src/canonical-sha256.ts";
import { canonicalJsonSha256, projectIncidentReplay } from "../src/index.ts";
import type {
  IncidentReplayProjectionInput,
  ProjectionHumanAuditEvent,
  WorkspaceIncidentSummary,
} from "../src/types.ts";
import { canonicalReplayFixture, cloneReplayFixture, unresolvedReplayFixture } from "./fixtures.ts";

type Mutable<T> = T extends readonly (infer Item)[]
  ? Mutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
    : T;

function mutableReplay(
  replay: IncidentReplayProjectionInput = canonicalReplayFixture,
): Mutable<IncidentReplayProjectionInput> {
  return cloneReplayFixture(replay) as Mutable<IncidentReplayProjectionInput>;
}

function humanAuditEvents(): Mutable<ProjectionHumanAuditEvent>[] {
  const firstTraceEvent = canonicalReplayFixture.trace_events[0];
  const secondTraceEvent = canonicalReplayFixture.trace_events[1];
  if (firstTraceEvent === undefined || secondTraceEvent === undefined) {
    throw new Error("Canonical replay must contain two trace events");
  }
  const build = (
    body: Mutable<Omit<ProjectionHumanAuditEvent, "event_id" | "event_sha256">>,
  ): Mutable<ProjectionHumanAuditEvent> => {
    const eventSha256 = `sha256:${canonicalJsonSha256(body)}`;
    return {
      ...body,
      event_id: `human-audit-event:${eventSha256.slice("sha256:".length)}`,
      event_sha256: eventSha256,
    };
  };
  const first = build({
    schema: "incident-human-audit-event/v1",
    incident_id: canonicalReplayFixture.incident.incident_id,
    sequence: 1,
    event_type: "incident.admitted",
    actor: {
      subject: "operator:alpha",
      display_name: "Alpha Operator",
      issuer: "https://identity.example.test/tenant",
      audience: "colortrace-api",
      principal_kind: "human",
    },
    predecessor_event_sha256: null,
    occurred_at: "2026-08-13T12:00:10.000Z",
    citations: [{ namespace: "trace-event", id: firstTraceEvent.event_id }],
  });
  const second = build({
    schema: "incident-human-audit-event/v1",
    incident_id: canonicalReplayFixture.incident.incident_id,
    sequence: 2,
    event_type: "incident.admitted",
    actor: {
      subject: "operator:beta",
      display_name: "Beta Operator",
      issuer: "https://identity.example.test/tenant",
      audience: "colortrace-api",
      principal_kind: "human",
    },
    predecessor_event_sha256: first.event_sha256,
    occurred_at: "2026-08-13T12:00:10.000Z",
    citations: [{ namespace: "trace-event", id: secondTraceEvent.event_id }],
  });
  return [first, second];
}

describe("canonicalJsonSha256", () => {
  it.each([
    ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
    [
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ],
  ])("matches the standard SHA-256 vector for %j", (value, expected) => {
    expect(sha256Hex(new TextEncoder().encode(value))).toBe(expected);
  });

  it("matches Python canonical UTF-8 for non-ASCII and control content", () => {
    expect(
      canonicalJsonSha256({
        z: "line\n\t\u0000é😀",
        a: [1, true, null],
        nested: { β: "雪" },
      }),
    ).toBe("0247d3f9635dc09a8f2fa7b7a8046685d186c87a8b9b48ed6e18a15a1edd5264");
  });
});

describe("projectIncidentReplay", () => {
  it("projects canonical evidence, exact scope, limitations, and authority", () => {
    const workspace = projectIncidentReplay(canonicalReplayFixture);

    expect(workspace.overview).toMatchObject({
      state: "resolved",
      claim_counts: { confirmed: 1, inferred: 0, rejected: 0, unresolved: 0 },
      scope_counts: { affected: 4, safe: 3, unknown: 0 },
      candidate_plan: { state: "available", non_executable: true },
      next_authority: "human-plan-review",
    });
    expect(workspace.scope.parity).toEqual({ status: "verified", reason_codes: [] });
    expect(workspace.scope.nodes).toHaveLength(8);
    expect(workspace.scope.edges).toHaveLength(4);
    expect(workspace.scope.edges.every((edge) => edge.citations.length > 0)).toBe(true);
    expect(
      workspace.scope.nodes.find((node) => node.kind === "frame" && node.id === "frame-b-04"),
    ).toMatchObject({ classification: "safe", safe_on_implicated_worker: true });
    expect(new Set(workspace.evidence.items.map((item) => item.kind))).toEqual(
      new Set(["provider", "validator-artifact", "deterministic-derivation"]),
    );
    expect(workspace.evidence.missing_references).toEqual([]);
    expect(new Set(workspace.timeline.map((item) => item.category))).toEqual(
      new Set(["source-observation", "model-reasoning", "deterministic-result", "workflow-event"]),
    );
    expect(workspace.claims[0]).toMatchObject({
      timestamp: canonicalReplayFixture.packet.finalized_at,
      time_basis: "finalized-at",
    });
    expect(workspace.limitations.map((item) => item.code)).toContain(
      "reference-policy-technical-only",
    );
    expect(workspace.limitations).toContainEqual(
      expect.objectContaining({ code: "human-event-history-unavailable" }),
    );
    expect(workspace.limitations).toContainEqual(
      expect.objectContaining({
        code: "record-time-unavailable",
        detail: expect.stringContaining(
          "Model invocations and deterministic results carry no occurrence timestamp",
        ),
      }),
    );
    expect(workspace.adverse_states).toContainEqual(
      expect.objectContaining({ code: "time-basis-incomplete", severity: "warning" }),
    );
    expect(workspace.adverse_states.some((item) => item.severity === "blocking")).toBe(false);
    expect(Object.isFrozen(workspace)).toBe(true);
    expect(Object.isFrozen(workspace.scope.nodes)).toBe(true);
    expect(Object.isFrozen(workspace.scope.nodes[0])).toBe(true);
  });

  it("projects authenticated audit records as deterministically ordered human events", () => {
    const replay = mutableReplay();
    const auditEvents = humanAuditEvents();
    replay.human_events = auditEvents;

    const workspace = projectIncidentReplay(replay);
    const humanEvents = workspace.timeline.filter((item) => item.category === "human-event");

    expect(humanEvents.map((item) => item.record_id)).toEqual(
      auditEvents.map((event) => event.event_id).sort(),
    );
    expect(humanEvents.find((item) => item.record_id === auditEvents[0]?.event_id)).toMatchObject({
      status: "informational",
      timestamp: "2026-08-13T12:00:10.000Z",
      time_basis: "occurred-at",
      label: "incident.admitted",
      detail: "Alpha Operator (operator:alpha)",
      citations: [
        { namespace: "human-audit-event", id: auditEvents[0]?.event_sha256 },
        { namespace: "trace-event", id: canonicalReplayFixture.trace_events[0]?.event_id },
      ],
    });
    expect(workspace.limitations.map((item) => item.code)).not.toContain(
      "human-event-history-unavailable",
    );
  });

  it("rejects a syntactically plausible human event whose canonical digest is false", () => {
    const replay = mutableReplay();
    replay.human_events = humanAuditEvents();
    const first = replay.human_events[0];
    if (first !== undefined) {
      first.actor.display_name = "Digest-tampered operator";
    }

    const workspace = projectIncidentReplay(replay);

    expect(workspace.overview.state).toBe("invalid");
    expect(workspace.scope.nodes).toEqual([]);
    expect(workspace.adverse_states).toContainEqual(
      expect.objectContaining({ code: "identity-mismatch", severity: "blocking" }),
    );
  });

  it.each(["event", "actor", "citation"] as const)(
    "rejects an extra %s key even when the event is otherwise bound",
    (target) => {
      const replay = mutableReplay();
      replay.human_events = humanAuditEvents();
      const first = replay.human_events[0];
      expect(first).toBeDefined();
      if (first === undefined) return;
      if (target === "event") {
        (first as unknown as Record<string, unknown>).unexpected = true;
      } else if (target === "actor") {
        (first.actor as unknown as Record<string, unknown>).unexpected = true;
      } else {
        const firstCitation = first.citations[0];
        expect(firstCitation).toBeDefined();
        if (firstCitation !== undefined) {
          (firstCitation as unknown as Record<string, unknown>).unexpected = true;
        }
      }

      const workspace = projectIncidentReplay(replay);

      expect(workspace.overview.state).toBe("invalid");
      expect(workspace.scope.nodes).toEqual([]);
    },
  );

  it("fails closed for cross-incident or tampered human audit chains", () => {
    const crossIncident = mutableReplay();
    crossIncident.human_events = humanAuditEvents();
    const first = crossIncident.human_events[0];
    if (first !== undefined) first.incident_id = "incident-other";

    const crossIncidentWorkspace = projectIncidentReplay(crossIncident);
    expect(crossIncidentWorkspace.overview.state).toBe("invalid");
    expect(crossIncidentWorkspace.scope.nodes).toEqual([]);
    expect(crossIncidentWorkspace.adverse_states).toContainEqual(
      expect.objectContaining({ code: "identity-mismatch", severity: "blocking" }),
    );

    const tamperedChain = mutableReplay();
    tamperedChain.human_events = humanAuditEvents();
    const second = tamperedChain.human_events[1];
    if (second !== undefined) second.predecessor_event_sha256 = null;

    const tamperedWorkspace = projectIncidentReplay(tamperedChain);
    expect(tamperedWorkspace.overview.state).toBe("invalid");
    expect(tamperedWorkspace.scope.nodes).toEqual([]);
  });

  it("does not present an invalid packet finalization time as a claim occurrence", () => {
    const replay = mutableReplay();
    replay.packet.finalized_at = "not-a-timestamp";

    const workspace = projectIncidentReplay(replay);

    expect(workspace.claims[0]).toMatchObject({ timestamp: null, time_basis: "unavailable" });
    expect(workspace.adverse_states).toContainEqual(
      expect.objectContaining({ code: "time-basis-incomplete", severity: "warning" }),
    );
  });

  it("keeps unresolved and missing evidence explicit without promoting scope", () => {
    const workspace = projectIncidentReplay(unresolvedReplayFixture);

    expect(workspace.overview.state).toBe("unresolved");
    expect(workspace.overview.candidate_plan).toEqual({
      state: "blocked",
      id: null,
      non_executable: true,
    });
    expect(workspace.scope).toMatchObject({
      state: "unresolved",
      parity: { status: "not-verifiable" },
    });
    expect(workspace.scope.nodes).toEqual([
      expect.objectContaining({
        kind: "frame",
        id: "frame-unknown",
        classification: "unknown",
      }),
    ]);
    expect(workspace.scope.edges).toEqual([]);
    expect(workspace.evidence.missing_references).toEqual(["missing:evidence"]);
    expect(workspace.adverse_states.map((item) => item.code)).toEqual(
      expect.arrayContaining([
        "missing-evidence",
        "provider-evidence-error",
        "unresolved-investigation",
      ]),
    );
    expect(workspace.limitations.map((item) => item.code)).toContain("scope-parity-not-verifiable");
  });

  it("namespaces evidence identities and blocks ambiguous cross-namespace citations", () => {
    const replay = mutableReplay();
    const provider = replay.evidence[0];
    expect(provider).toBeDefined();
    const oldId = provider?.evidence_id ?? "";
    const collisionId = "validator-evidence:frame-b-01";
    if (provider !== undefined) provider.evidence_id = collisionId;
    replay.packet.evidence_ids = replay.packet.evidence_ids.map((id) =>
      id === oldId ? collisionId : id,
    );
    replay.invocations = replay.invocations.map((item) => ({
      ...item,
      input_evidence_ids: item.input_evidence_ids.map((id) => (id === oldId ? collisionId : id)),
    }));
    replay.packet.invocation_records = replay.packet.invocation_records.map((item) => ({
      ...item,
      input_evidence_ids: item.input_evidence_ids.map((id) => (id === oldId ? collisionId : id)),
    }));

    const workspace = projectIncidentReplay(replay);
    const colliding = workspace.evidence.items.filter((item) => item.evidence_id === collisionId);

    expect(colliding.map((item) => item.workspace_id)).toEqual([
      `provider:${collisionId}`,
      `${"validator-artifact"}:${canonicalReplayFixture.validator_results[0]?.result_id}:${collisionId}`,
    ]);
    expect(workspace.overview.state).toBe("invalid");
    expect(workspace.scope.nodes).toEqual([]);
    expect(workspace.adverse_states).toContainEqual(
      expect.objectContaining({ code: "evidence-namespace-collision", severity: "blocking" }),
    );
  });

  it("fails closed when packet and validator scope identities differ", () => {
    const replay = mutableReplay();
    const firstAffected = replay.packet.scope.affected[0];
    expect(firstAffected).toBeDefined();
    if (firstAffected !== undefined) firstAffected.id = "frame-not-validated";

    const workspace = projectIncidentReplay(replay);

    expect(workspace.overview.state).toBe("invalid");
    expect(workspace.overview.scope_counts).toEqual({ affected: 0, safe: 0, unknown: 0 });
    expect(workspace.scope.parity).toMatchObject({ status: "failed" });
    expect(workspace.scope.parity.reason_codes).toContain("scope-affected-identity-mismatch");
    expect(workspace.scope.nodes).toEqual([]);
    expect(workspace.scope.edges).toEqual([]);
    expect(workspace.adverse_states).toContainEqual(
      expect.objectContaining({ code: "scope-parity-failed", severity: "blocking" }),
    );
  });

  it("is deterministic across semantically equivalent input ordering", () => {
    const replay = mutableReplay();
    replay.evidence.reverse();
    replay.validator_results[0]?.scope.frames.reverse();
    replay.validator_results[0]?.evidence.reverse();
    replay.packet.scope.affected.reverse();
    replay.packet.scope.safe.reverse();
    replay.trace_events.reverse();
    replay.invocations.reverse();
    replay.packet.invocation_records.reverse();
    replay.human_events = humanAuditEvents().reverse();

    const canonicalWithHumanEvents = mutableReplay();
    canonicalWithHumanEvents.human_events = humanAuditEvents();

    expect(projectIncidentReplay(replay)).toEqual(projectIncidentReplay(canonicalWithHumanEvents));
  });

  it("keeps injection-shaped provider text inert and bounded to display text", () => {
    const replay = mutableReplay();
    const injection = '<img src=x onerror="globalThis.compromised=true"><script>alert(1)</script>';
    const evidence = replay.evidence[0];
    expect(evidence).toBeDefined();
    if (evidence !== undefined) {
      evidence.display_excerpt = injection;
      evidence.content = { instruction: injection, event_type: "human.approved" };
    }
    const traceEvent = replay.trace_events[0];
    if (traceEvent !== undefined) traceEvent.event_type = "human.approved";

    const workspace = projectIncidentReplay(replay);
    const projected = workspace.evidence.items.find(
      (item) => item.kind === "provider" && item.evidence_id === evidence?.evidence_id,
    );

    expect(projected).toMatchObject({ kind: "provider", display_excerpt: injection });
    expect(
      workspace.timeline.find((item) => item.record_id === evidence?.evidence_id)?.detail,
    ).toBe(injection);
    expect(workspace.timeline.some((item) => item.category === "human-event")).toBe(false);
    expect(
      workspace.timeline.find((item) => item.record_id === traceEvent?.event_id)?.category,
    ).toBe("workflow-event");
    expect(workspace.scope.nodes).toHaveLength(8);
  });

  it("accepts the generated replay contract structurally and exports partial incident state", () => {
    expectTypeOf<GeneratedIncidentReplay>().toMatchTypeOf<IncidentReplayProjectionInput>();
    expectTypeOf<WorkspaceIncidentSummary>().toEqualTypeOf<{
      readonly id: string;
      readonly alert_id: string;
      readonly status: "queued" | "resolved" | "running" | "unresolved";
      readonly created_at: string;
      readonly updated_at: string;
      readonly delayed: boolean;
      readonly missing: readonly string[];
    }>();
  });
});
