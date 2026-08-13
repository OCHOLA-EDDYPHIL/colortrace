import type {
  IncidentRecord,
  IncidentReplay,
  IncidentSummary,
  IncidentWorkspaceSource,
  HumanAuditEvent,
  TaskRecord,
} from "@colortrace/api-client";
import { canonicalJsonSha256 } from "@colortrace/workspace-model";
import { cloneReplayFixture } from "@colortrace/workspace-model/test-fixtures";
import type { Page } from "@playwright/test";

type Mutable<T> = T extends readonly (infer Item)[]
  ? Mutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
    : T;

export type CapturedApiRequest = {
  readonly headers: Readonly<Record<string, string>>;
  readonly method: string;
  readonly url: string;
};

export type PreparedApi = {
  readonly incident: IncidentSummary;
  readonly replay: IncidentReplay;
  readonly source: IncidentWorkspaceSource;
};

function preparedApi(providerExcerpt?: string, removedValidatorEvidenceId?: string): PreparedApi {
  const replay = cloneReplayFixture() as Mutable<ReturnType<typeof cloneReplayFixture>>;
  if (providerExcerpt !== undefined) {
    if (replay.evidence.length === 0) throw new Error("Canonical replay has no provider evidence");
    for (const evidence of replay.evidence) evidence.display_excerpt = providerExcerpt;
  }
  if (removedValidatorEvidenceId !== undefined) {
    const validator = replay.validator_results[0];
    if (validator === undefined) throw new Error("Canonical replay has no validator result");
    validator.evidence = validator.evidence.filter(
      (artifact) => artifact.evidence_id !== removedValidatorEvidenceId,
    );
  }

  const incident: IncidentSummary = {
    schema: "incident-summary/v1",
    incident_id: replay.incident.incident_id,
    alert_id: replay.incident.alert_id,
    status: replay.incident.status,
    version: replay.incident.version,
    trace_id: replay.incident.trace_id,
    packet_id: replay.incident.packet_id,
    created_at: replay.incident.created_at,
    updated_at: replay.incident.updated_at,
    delayed: false,
    missing: [],
  };
  const typedReplay = replay as unknown as IncidentReplay;
  const firstTraceEvent = replay.trace_events[0];
  if (firstTraceEvent === undefined) throw new Error("Canonical replay has no trace events");
  const humanEventBody: Omit<HumanAuditEvent, "event_id" | "event_sha256"> = {
    schema: "incident-human-audit-event/v1",
    incident_id: replay.incident.incident_id,
    sequence: 1,
    event_type: "incident.admitted",
    actor: {
      subject: "operator@example.test",
      display_name: "Pipeline operator",
      issuer: "https://identity.example.test/tenant",
      audience: "colortrace-api",
      principal_kind: "human",
    },
    predecessor_event_sha256: null,
    occurred_at: "2026-08-13T12:00:00.000Z",
    citations: [{ namespace: "trace-event", id: firstTraceEvent.event_id }],
  };
  const humanEventDigest = canonicalJsonSha256(humanEventBody);
  const humanEvent: HumanAuditEvent = {
    ...humanEventBody,
    event_id: `human-audit-event:${humanEventDigest}`,
    event_sha256: `sha256:${humanEventDigest}`,
  };
  const source: IncidentWorkspaceSource = {
    schema: "incident-workspace-source/v1",
    view: {
      schema: "incident-view/v1",
      incident: replay.incident as IncidentRecord,
      task: replay.task as TaskRecord,
      packet: typedReplay.packet,
    },
    replay_state: "ready",
    human_events: [humanEvent],
    replay: typedReplay,
  };
  return { incident, replay: typedReplay, source };
}

export async function installPreparedApi(
  page: Page,
  options: {
    readonly providerExcerpt?: string;
    readonly removedValidatorEvidenceId?: string;
    readonly viewPacket?: "exact" | "mismatched" | "missing";
    readonly oidcToken?: string | null;
  } = {},
): Promise<{
  readonly captured: CapturedApiRequest[];
  readonly data: PreparedApi;
  readonly oidcToken: string | null;
}> {
  const data = preparedApi(options.providerExcerpt, options.removedValidatorEvidenceId);
  const oidcToken =
    options.oidcToken === undefined
      ? `acceptance-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
      : options.oidcToken;
  if (oidcToken !== null) {
    await page.addInitScript(
      ({ contract, token }) => {
        Object.defineProperty(globalThis, Symbol.for(contract), {
          configurable: true,
          enumerable: false,
          value: () => token,
          writable: false,
        });
      },
      { contract: "colortrace.host.oidc-token-provider/v1", token: oidcToken },
    );
  }
  const viewPacket =
    options.viewPacket === "missing"
      ? null
      : options.viewPacket === "mismatched"
        ? { ...data.replay.packet, packet_id: "response-packet:mismatched" }
        : data.replay.packet;
  const source: IncidentWorkspaceSource = {
    ...data.source,
    view: { ...data.source.view, packet: viewPacket },
  };
  const captured: CapturedApiRequest[] = [];

  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    captured.push({
      headers: await request.allHeaders(),
      method: request.method(),
      url: request.url(),
    });

    if (request.method() !== "GET") {
      await route.fulfill({ json: { code: "method-not-allowed" }, status: 405 });
      return;
    }
    if (url.pathname === "/v1/session") {
      if (oidcToken === null || request.headers().authorization !== `Bearer ${oidcToken}`) {
        await route.fulfill({ json: { code: "authentication-required" }, status: 401 });
        return;
      }
      await route.fulfill({
        json: {
          schema: "operator-session/v1",
          subject: "operator@example.test",
          display_name: "Pipeline operator",
          roles: ["operator"],
          issuer: "https://identity.example.test/tenant",
          audience: "colortrace-api",
          principal_kind: "human",
        },
      });
      return;
    }
    if (url.pathname === "/v1/incidents") {
      await route.fulfill({
        json: {
          schema: "incident-list/v1",
          items: [data.incident],
          next_cursor: null,
        },
      });
      return;
    }
    if (url.pathname === `/v1/incidents/${data.incident.incident_id}/workspace`) {
      await route.fulfill({ json: source });
      return;
    }
    await route.fulfill({ json: { code: "resource-unavailable" }, status: 404 });
  });

  return { captured, data, oidcToken };
}
