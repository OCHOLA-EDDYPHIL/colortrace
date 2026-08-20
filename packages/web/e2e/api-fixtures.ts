import type {
  IncidentRecord,
  IncidentReplay,
  IncidentSummary,
  IncidentWorkspaceSource,
  HumanAuditEvent,
  RecoveryReview,
  ResponsePlanReview,
  TaskRecord,
} from "@colortrace/api-client";
import { canonicalJsonSha256 } from "@colortrace/workspace-model";
import { cloneReplayFixture } from "@colortrace/workspace-model/test-fixtures";
import { recoveryReviewFixture } from "@colortrace/workspace-model/recovery-test-fixture";
import type { Page } from "@playwright/test";

import { responsePlanReviewFixture } from "../test/response-plan-fixture.ts";

type Mutable<T> = T extends readonly (infer Item)[]
  ? Mutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
    : T;

export type CapturedApiRequest = {
  readonly body: unknown | null;
  readonly headers: Readonly<Record<string, string>>;
  readonly method: string;
  readonly url: string;
};

export type PreparedApi = {
  readonly incident: IncidentSummary;
  readonly replay: IncidentReplay;
  readonly recovery: RecoveryReview | null;
  readonly responsePlan: ResponsePlanReview;
  readonly source: IncidentWorkspaceSource;
};

function preparedApi(
  providerExcerpt?: string,
  removedValidatorEvidenceId?: string,
  recovery: RecoveryReview | null = null,
): PreparedApi {
  const replay = cloneReplayFixture() as Mutable<ReturnType<typeof cloneReplayFixture>>;
  if (recovery !== null) {
    const incidentId = recovery.snapshot.incident_id;
    replay.incident.incident_id = incidentId;
    replay.task.incident_id = incidentId;
    replay.alert.incident_id = incidentId;
    replay.packet.incident_id = incidentId;
    for (const evidence of replay.evidence) evidence.incident_id = incidentId;
    for (const result of replay.validator_results) result.incident_id = incidentId;
    for (const invocation of replay.invocations) invocation.incident_id = incidentId;
    for (const event of replay.trace_events) event.incident_id = incidentId;
  }
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
  return {
    incident,
    replay: typedReplay,
    recovery,
    responsePlan: responsePlanReviewFixture({ incidentId: incident.incident_id }),
    source,
  };
}

export async function installPreparedApi(
  page: Page,
  options: {
    readonly providerExcerpt?: string;
    readonly removedValidatorEvidenceId?: string;
    readonly approvalMode?: "ambiguous-once" | "normal" | "refresh-fails-once";
    readonly closureMode?: "ambiguous-once" | "normal";
    readonly incidentListMode?: "delayed" | "empty" | "error" | "normal";
    readonly recoveryState?:
      | "closed"
      | "recovery_failed"
      | "recovery_unresolved"
      | "recovery_verified";
    readonly responsePlanCommandId?: string;
    readonly responsePlanState?: ResponsePlanReview["state"];
    readonly responsePlanUncertainty?: boolean;
    readonly sessionStatus?: "active" | "expired";
    readonly viewPacket?: "exact" | "mismatched" | "missing";
    readonly oidcToken?: string | null;
  } = {},
): Promise<{
  readonly captured: CapturedApiRequest[];
  readonly data: PreparedApi;
  readonly oidcToken: string | null;
}> {
  const initialRecovery =
    options.recoveryState === undefined
      ? null
      : (recoveryReviewFixture(options.recoveryState) as unknown as RecoveryReview);
  const data = preparedApi(
    options.providerExcerpt,
    options.removedValidatorEvidenceId,
    initialRecovery,
  );
  let responsePlan = responsePlanReviewFixture({
    commandId: options.responsePlanCommandId,
    incidentId: data.incident.incident_id,
    state: options.responsePlanState,
    ...(options.responsePlanState === "stale" ? { currentIncidentVersion: 8 } : {}),
    ...(options.responsePlanUncertainty === true
      ? {
          blockingUnresolvedItemIds: ["validator-blocker"],
          unknownTargetIds: ["frame-unknown-0009"],
          unresolvedItemIds: ["validator-blocker", "operator-review-note"],
        }
      : {}),
  });
  let recovery = initialRecovery;
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
  let approvalAttempts = 0;
  let closureAttempts = 0;
  let failNextPlanRead = false;

  await page.route("**/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    captured.push({
      body: request.postData() === null ? null : request.postDataJSON(),
      headers: await request.allHeaders(),
      method: request.method(),
      url: request.url(),
    });

    if (url.pathname === "/v1/session") {
      if (
        oidcToken === null ||
        options.sessionStatus === "expired" ||
        request.headers().authorization !== `Bearer ${oidcToken}`
      ) {
        await route.fulfill({ json: { code: "authentication-required" }, status: 401 });
        return;
      }
      await route.fulfill({
        json: {
          schema: "operator-session/v1",
          subject: "operator@example.test",
          display_name: "Pipeline operator",
          roles: ["operator", "response-plan.editor", "response-plan.approver", "recovery.closer"],
          issuer: "https://identity.example.test/tenant",
          audience: "colortrace-api",
          principal_kind: "human",
        },
      });
      return;
    }
    if (url.pathname === "/v1/incidents") {
      if (options.incidentListMode === "delayed") {
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      if (options.incidentListMode === "error") {
        await route.fulfill({ json: { code: "temporary-list-failure" }, status: 503 });
        return;
      }
      await route.fulfill({
        json: {
          schema: "incident-list/v1",
          items: options.incidentListMode === "empty" ? [] : [data.incident],
          next_cursor: null,
        },
      });
      return;
    }
    if (url.pathname === `/v1/incidents/${data.incident.incident_id}/workspace`) {
      await route.fulfill({ json: source });
      return;
    }
    if (url.pathname === `/v1/incidents/${data.incident.incident_id}/response-plan`) {
      if (request.method() === "GET") {
        if (failNextPlanRead) {
          failNextPlanRead = false;
          await route.fulfill({ json: { code: "temporary-read-failure" }, status: 503 });
          return;
        }
        await route.fulfill({ json: responsePlan });
        return;
      }
      if (oidcToken === null || request.headers().authorization !== `Bearer ${oidcToken}`) {
        await route.fulfill({ json: { code: "authentication-required" }, status: 401 });
        return;
      }
      if (request.method() === "PUT") {
        const body = request.postDataJSON() as {
          commands: ResponsePlanReview["plan"]["commands"];
          unresolved_acknowledged: boolean;
        };
        const editedPlan = {
          ...responsePlan.plan,
          commands: body.commands,
          version: responsePlan.plan.version + 1,
          previous_plan_sha256: responsePlan.plan.plan_sha256,
          unresolved_acknowledged: body.unresolved_acknowledged,
          plan_sha256: `sha256:${"b".repeat(64)}`,
          created_at: "2026-08-13T18:10:00.000Z",
        };
        responsePlan = {
          ...responsePlan,
          state: "pending",
          plan: editedPlan,
          decision: null,
        };
        await route.fulfill({ json: editedPlan });
        return;
      }
    }
    if (
      url.pathname === `/v1/incidents/${data.incident.incident_id}/response-plan/approve` &&
      request.method() === "POST"
    ) {
      if (oidcToken === null || request.headers().authorization !== `Bearer ${oidcToken}`) {
        await route.fulfill({ json: { code: "authentication-required" }, status: 401 });
        return;
      }
      approvalAttempts += 1;
      responsePlan = responsePlanReviewFixture({
        incidentId: data.incident.incident_id,
        state: "approved",
      });
      if (options.approvalMode === "ambiguous-once" && approvalAttempts === 1) {
        await route.abort("connectionreset");
        return;
      }
      if (options.approvalMode === "refresh-fails-once") failNextPlanRead = true;
      await route.fulfill({ json: responsePlan.decision });
      return;
    }
    if (
      url.pathname === `/v1/incidents/${data.incident.incident_id}/response-plan/reject` &&
      request.method() === "POST"
    ) {
      if (oidcToken === null || request.headers().authorization !== `Bearer ${oidcToken}`) {
        await route.fulfill({ json: { code: "authentication-required" }, status: 401 });
        return;
      }
      responsePlan = responsePlanReviewFixture({
        incidentId: data.incident.incident_id,
        state: "rejected",
      });
      await route.fulfill({ json: responsePlan.decision });
      return;
    }
    if (url.pathname === `/v1/incidents/${data.incident.incident_id}/recovery`) {
      if (request.method() !== "GET") {
        await route.fulfill({ json: { code: "method-not-allowed" }, status: 405 });
        return;
      }
      if (recovery === null) {
        await route.fulfill({ json: { code: "recovery-not-found" }, status: 404 });
        return;
      }
      await route.fulfill({ json: recovery });
      return;
    }
    if (
      url.pathname === `/v1/incidents/${data.incident.incident_id}/recovery/close` &&
      request.method() === "POST"
    ) {
      if (oidcToken === null || request.headers().authorization !== `Bearer ${oidcToken}`) {
        await route.fulfill({ json: { code: "authentication-required" }, status: 401 });
        return;
      }
      if (recovery === null || recovery.packet === null) {
        await route.fulfill({ json: { code: "recovery-not-found" }, status: 404 });
        return;
      }
      closureAttempts += 1;
      const body = request.postDataJSON() as { idempotency_key: string; reason: string };
      recovery = recoveryReviewFixture("closed", {
        closureIdempotencyKey: body.idempotency_key,
        closureReason: body.reason,
      }) as unknown as RecoveryReview;
      if (options.closureMode === "ambiguous-once" && closureAttempts === 1) {
        await route.abort("connectionreset");
        return;
      }
      await route.fulfill({ json: recovery.closure });
      return;
    }
    if (request.method() !== "GET") {
      await route.fulfill({ json: { code: "method-not-allowed" }, status: 405 });
      return;
    }
    await route.fulfill({ json: { code: "resource-unavailable" }, status: 404 });
  });

  return { captured, data, oidcToken };
}
