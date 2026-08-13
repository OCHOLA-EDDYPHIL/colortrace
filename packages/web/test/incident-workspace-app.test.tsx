import type {
  IncidentRecord,
  IncidentReplay,
  IncidentSummary,
  IncidentWorkspaceSource,
  TaskRecord,
} from "@colortrace/api-client";
import { cloneReplayFixture } from "@colortrace/workspace-model/test-fixtures";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createIncidentReadAdapter, IncidentApiError } from "../src/api-adapter.ts";
import {
  captureHostOidcTokenProvider,
  HOST_OIDC_TOKEN_PROVIDER_CONTRACT,
} from "../src/host-auth.ts";
import { IncidentWorkspaceApp, projectWorkspaceSource } from "../src/incident-workspace-app.tsx";
import { responsePlanReviewFixture } from "./response-plan-fixture.ts";

type Mutable<T> = T extends readonly (infer Item)[]
  ? Mutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
    : T;

type Deferred<T> = {
  readonly promise: Promise<T>;
  readonly resolve: (value: T) => void;
};

function deferred<T>(): Deferred<T> {
  let resolve: ((value: T) => void) | undefined;
  const promise = new Promise<T>((next) => {
    resolve = next;
  });
  return {
    promise,
    resolve: (value) => {
      if (resolve === undefined) throw new Error("Deferred promise was not initialized");
      resolve(value);
    },
  };
}

function summary(
  incidentId: string,
  status: IncidentSummary["status"] = "resolved",
  overrides: Partial<IncidentSummary> = {},
): IncidentSummary {
  return {
    schema: "incident-summary/v1",
    incident_id: incidentId,
    alert_id: `alert-${incidentId}`,
    status,
    version: 3,
    trace_id: "1".repeat(32),
    packet_id: status === "queued" || status === "running" ? null : `packet-${incidentId}`,
    created_at: "2026-08-13T12:00:00.000Z",
    updated_at: "2026-08-13T12:01:00.000Z",
    delayed: false,
    missing: [],
    ...overrides,
  };
}

function incidentRecord(item: IncidentSummary): IncidentRecord {
  return {
    schema: "incident-record/v1",
    incident_id: item.incident_id,
    alert_id: item.alert_id,
    status: item.status,
    version: item.version,
    alert_sha256: `sha256:${"a".repeat(64)}`,
    trace_id: item.trace_id,
    packet_id: item.packet_id,
    created_at: item.created_at,
    updated_at: item.updated_at,
  };
}

function taskRecord(item: IncidentSummary): TaskRecord {
  return {
    schema: "incident-task/v1",
    task_id: `task-${item.incident_id}`,
    incident_id: item.incident_id,
    expected_incident_version: 1,
    alert_sha256: `sha256:${"a".repeat(64)}`,
    trace_id: item.trace_id,
    status: item.status === "queued" || item.status === "running" ? item.status : "complete",
    packet_id: item.packet_id,
    created_at: item.created_at,
    updated_at: item.updated_at,
  };
}

function pendingSource(item: IncidentSummary): IncidentWorkspaceSource {
  return {
    schema: "incident-workspace-source/v1",
    view: {
      schema: "incident-view/v1",
      incident: incidentRecord(item),
      task: taskRecord(item),
      packet: null,
    },
    replay_state: "pending",
    human_events: [],
    replay: null,
  };
}

function replayFor(item: IncidentSummary): IncidentReplay {
  const replay = cloneReplayFixture() as Mutable<ReturnType<typeof cloneReplayFixture>>;
  const packetId = item.packet_id ?? `packet-${item.incident_id}`;
  replay.incident.incident_id = item.incident_id;
  replay.incident.alert_id = item.alert_id;
  replay.incident.status = item.status === "unresolved" ? "unresolved" : "resolved";
  replay.incident.packet_id = packetId;
  replay.incident.created_at = item.created_at;
  replay.incident.updated_at = item.updated_at;
  replay.task.incident_id = item.incident_id;
  replay.task.packet_id = packetId;
  replay.alert.incident_id = item.incident_id;
  replay.alert.alert_id = item.alert_id;
  replay.packet.incident_id = item.incident_id;
  replay.packet.packet_id = packetId;
  for (const evidence of replay.evidence) evidence.incident_id = item.incident_id;
  for (const result of replay.validator_results) result.incident_id = item.incident_id;
  for (const invocation of replay.invocations) invocation.incident_id = item.incident_id;
  for (const event of replay.trace_events) event.incident_id = item.incident_id;
  return replay as unknown as IncidentReplay;
}

function readySource(item: IncidentSummary): IncidentWorkspaceSource {
  const replay = replayFor(item);
  return {
    schema: "incident-workspace-source/v1",
    view: {
      schema: "incident-view/v1",
      incident: incidentRecord(item),
      task: taskRecord(item),
      packet: replay.packet,
    },
    replay_state: "ready",
    human_events: [],
    replay,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

function sessionResponse(): Response {
  return jsonResponse({
    schema: "operator-session/v1",
    subject: "operator-1",
    display_name: "Pipeline operator",
    roles: ["operator"],
    issuer: "https://identity.example.test/tenant",
    audience: "colortrace-api",
    principal_kind: "human",
  });
}

function planSessionResponse(): Response {
  return jsonResponse({
    schema: "operator-session/v1",
    subject: "operator-1",
    display_name: "Pipeline operator",
    roles: ["operator", "response-plan.editor", "response-plan.approver"],
    issuer: "https://identity.example.test/tenant",
    audience: "colortrace-api",
    principal_kind: "human",
  });
}

function incidentListResponse(items: readonly IncidentSummary[]): Response {
  return jsonResponse({ schema: "incident-list/v1", items, next_cursor: null });
}

function routedFetch(route: (request: Request) => Promise<Response> | Response): {
  readonly fetch: typeof fetch;
  readonly requests: Request[];
} {
  const requests: Request[] = [];
  const fetchImplementation: typeof fetch = async (input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    requests.push(request);
    return route(request);
  };
  return { fetch: fetchImplementation, requests };
}

function routePath(request: Request): string {
  return new URL(request.url).pathname;
}

function absentResponsePlan(request: Request): Response | null {
  return routePath(request).endsWith("/response-plan")
    ? jsonResponse({ code: "plan-not-found" }, 404)
    : null;
}

afterEach(cleanup);

describe("incident read adapter", () => {
  it("captures and removes only the configurable host OIDC provider contract", async () => {
    const host = {};
    const key = Symbol.for(HOST_OIDC_TOKEN_PROVIDER_CONTRACT);
    const provider = vi.fn(() => "ephemeral-host-token");
    Object.defineProperty(host, key, {
      configurable: true,
      enumerable: false,
      value: provider,
      writable: false,
    });

    const captured = captureHostOidcTokenProvider(host);

    expect(Object.getOwnPropertyDescriptor(host, key)).toBeUndefined();
    expect(captured?.()).toBe("ephemeral-host-token");
    expect(provider).toHaveBeenCalledOnce();
  });

  it("fails closed for an undeletable host provider", () => {
    const host = {};
    Object.defineProperty(host, Symbol.for(HOST_OIDC_TOKEN_PROVIDER_CONTRACT), {
      configurable: false,
      value: () => "must-not-be-captured",
    });
    expect(captureHostOidcTokenProvider(host)).toBeUndefined();
  });

  it("keeps an injected bearer token in memory and sends it only to the session read", async () => {
    const item = summary("incident-authenticated");
    const { fetch, requests } = routedFetch((request) => {
      if (routePath(request) === "/v1/session") return sessionResponse();
      if (routePath(request) === "/v1/incidents") return incidentListResponse([item]);
      return jsonResponse(readySource(item));
    });
    const tokenProvider = vi.fn(() => "ephemeral-test-token");
    const adapter = createIncidentReadAdapter({
      baseUrl: "https://web.test",
      fetch,
      tokenProvider,
    });

    await adapter.getSession();
    await adapter.listIncidents();
    await adapter.getWorkspace(item.incident_id);

    expect(tokenProvider).toHaveBeenCalledOnce();
    expect(requests).toHaveLength(3);
    expect(requests[0]?.headers.get("Authorization")).toBe("Bearer ephemeral-test-token");
    expect(requests[1]?.headers.has("Authorization")).toBe(false);
    expect(requests[2]?.headers.has("Authorization")).toBe(false);
    expect(requests.every((request) => request.method === "GET")).toBe(true);
  });

  it("preserves typed API status and error codes", async () => {
    const { fetch } = routedFetch(() => jsonResponse({ code: "operator-token-invalid" }, 401));
    const adapter = createIncidentReadAdapter({ baseUrl: "https://web.test", fetch });

    const request = adapter.getSession();
    await expect(request).rejects.toBeInstanceOf(IncidentApiError);
    await expect(request).rejects.toMatchObject({
      code: "operator-token-invalid",
      status: 401,
    });
  });

  it("binds authenticated plan mutations to exact immutable preconditions", async () => {
    const review = responsePlanReviewFixture();
    const { fetch, requests } = routedFetch((request) => {
      if (request.method === "PUT") return jsonResponse(review.plan);
      return jsonResponse(
        review.decision ?? {
          schema: "response-plan-decision/v1",
          outcome: "approved",
        },
      );
    });
    const adapter = createIncidentReadAdapter({
      baseUrl: "https://web.test",
      fetch,
      tokenProvider: () => "ephemeral-plan-token",
    });

    await adapter.approveResponsePlan(review.plan.incident_id, review.plan, "approve-key");
    const replacement = `sha256:${"4".repeat(64)}`;
    const revision = {
      commands: review.plan.commands.map((command) => ({
        ...command,
        action_envelope: {
          ...command.action_envelope,
          replacement_resource_sha256: replacement,
        },
      })),
      unresolved_acknowledged: true,
    };
    await adapter.editResponsePlan(review.plan.incident_id, review.plan, revision, "edit-key");
    await adapter.rejectResponsePlan(
      review.plan.incident_id,
      review.plan,
      "unsafe-scope",
      "reject-key",
    );

    expect(requests.map((request) => request.method)).toEqual(["POST", "PUT", "POST"]);
    expect(
      requests.every(
        (request) => request.headers.get("Authorization") === "Bearer ephemeral-plan-token",
      ),
    ).toBe(true);
    expect(await requests[0]?.clone().json()).toEqual({
      expected_incident_version: review.plan.incident_version,
      expected_plan_version: review.plan.version,
      expected_plan_sha256: review.plan.plan_sha256,
      idempotency_key: "approve-key",
    });
    expect(await requests[1]?.clone().json()).toEqual({
      expected_incident_version: review.plan.incident_version,
      expected_plan_version: review.plan.version,
      expected_plan_sha256: review.plan.plan_sha256,
      response_packet_id: review.plan.response_packet_id,
      response_packet_sha256: review.plan.response_packet_sha256,
      deterministic_scope_sha256: review.plan.deterministic_scope_sha256,
      targets: review.plan.targets,
      exclusions: review.plan.exclusions,
      commands: revision.commands,
      unresolved_acknowledged: revision.unresolved_acknowledged,
      idempotency_key: "edit-key",
    });
    expect(await requests[2]?.clone().json()).toEqual({
      expected_incident_version: review.plan.incident_version,
      expected_plan_version: review.plan.version,
      expected_plan_sha256: review.plan.plan_sha256,
      reason_code: "unsafe-scope",
      idempotency_key: "reject-key",
    });
  });
});

describe("IncidentWorkspaceApp", () => {
  it("fails closed when a ready view packet is absent or differs from its replay", () => {
    const item = summary("incident-packet-binding");
    const source = readySource(item);
    const missing: IncidentWorkspaceSource = {
      ...source,
      view: { ...source.view, packet: null },
    };
    expect(projectWorkspaceSource(missing, item)).toMatchObject({ kind: "integrity-error" });

    const packet = source.view.packet;
    expect(packet).not.toBeNull();
    const mismatched: IncidentWorkspaceSource = {
      ...source,
      view: {
        ...source.view,
        packet: packet === null ? null : { ...packet, packet_id: "packet-other" },
      },
    };
    expect(projectWorkspaceSource(mismatched, item)).toMatchObject({ kind: "integrity-error" });
  });

  it("renders the authenticated prepared flow from API replay data", async () => {
    const item = summary("incident-prepared");
    const { fetch } = routedFetch((request) => {
      if (routePath(request) === "/v1/session") return sessionResponse();
      if (routePath(request) === "/v1/incidents") return incidentListResponse([item]);
      const absent = absentResponsePlan(request);
      if (absent !== null) return absent;
      return jsonResponse(readySource(item));
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({ baseUrl: "https://web.test", fetch })}
      />,
    );

    expect(await screen.findByText("Pipeline operator")).toBeVisible();
    expect(await screen.findByRole("heading", { name: "Incident overview" })).toBeVisible();
    expect(screen.getAllByText(item.incident_id).length).toBeGreaterThan(0);
  });

  it("retries an ambiguous approval with the retained logical-action idempotency key", async () => {
    const review = responsePlanReviewFixture({ incidentId: "incident-ambiguous-approval" });
    const item = summary(review.plan.incident_id);
    let currentReview = review;
    let approvalAttempts = 0;
    const { fetch, requests } = routedFetch((request) => {
      const path = routePath(request);
      if (path === "/v1/session") return planSessionResponse();
      if (path === "/v1/incidents") return incidentListResponse([item]);
      if (path.endsWith("/workspace")) return jsonResponse(readySource(item));
      if (path.endsWith("/response-plan") && request.method === "GET") {
        return jsonResponse(currentReview);
      }
      if (path.endsWith("/response-plan/approve") && request.method === "POST") {
        approvalAttempts += 1;
        if (approvalAttempts === 1) throw new TypeError("connection reset after request");
        currentReview = responsePlanReviewFixture({
          incidentId: item.incident_id,
          state: "approved",
        });
        return jsonResponse(currentReview.decision);
      }
      return jsonResponse({ code: "unexpected" }, 500);
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({
          baseUrl: "https://web.test",
          fetch,
          tokenProvider: () => "ephemeral-plan-token",
        })}
      />,
    );

    const approve = await screen.findByRole("button", { name: "Approve exact plan" });
    fireEvent.click(approve);
    fireEvent.click(screen.getByRole("button", { name: "Confirm approve" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/mutation did not complete/i);

    fireEvent.click(screen.getByRole("button", { name: "Retry exact action" }));
    expect(await screen.findByText(/Approved by/i)).toBeVisible();

    const approvalRequests = requests.filter((request) =>
      routePath(request).endsWith("/response-plan/approve"),
    );
    expect(approvalRequests).toHaveLength(2);
    const first = (await approvalRequests[0]?.clone().json()) as { idempotency_key: string };
    const second = (await approvalRequests[1]?.clone().json()) as { idempotency_key: string };
    expect(second.idempotency_key).toBe(first.idempotency_key);
  });

  it("reports post-commit refresh failure separately and reconciles without replay", async () => {
    const review = responsePlanReviewFixture({ incidentId: "incident-reconcile-approval" });
    const item = summary(review.plan.incident_id);
    let currentReview = review;
    let failNextPlanRead = false;
    const { fetch, requests } = routedFetch((request) => {
      const path = routePath(request);
      if (path === "/v1/session") return planSessionResponse();
      if (path === "/v1/incidents") return incidentListResponse([item]);
      if (path.endsWith("/workspace")) return jsonResponse(readySource(item));
      if (path.endsWith("/response-plan") && request.method === "GET") {
        if (failNextPlanRead) {
          failNextPlanRead = false;
          return jsonResponse({ code: "temporary-read-failure" }, 503);
        }
        return jsonResponse(currentReview);
      }
      if (path.endsWith("/response-plan/approve") && request.method === "POST") {
        currentReview = responsePlanReviewFixture({
          incidentId: item.incident_id,
          state: "approved",
        });
        failNextPlanRead = true;
        return jsonResponse(currentReview.decision);
      }
      return jsonResponse({ code: "unexpected" }, 500);
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({
          baseUrl: "https://web.test",
          fetch,
          tokenProvider: () => "ephemeral-plan-token",
        })}
      />,
    );

    fireEvent.click(await screen.findByRole("button", { name: "Approve exact plan" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm approve" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/mutation was accepted/i);
    expect(screen.queryByRole("button", { name: "Retry exact action" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Reconcile plan state" }));
    expect(await screen.findByText(/Approved by/i)).toBeVisible();
    expect(
      requests.filter((request) => routePath(request).endsWith("/response-plan/approve")),
    ).toHaveLength(1);
  });

  it("cannot project an old incident mutation completion into a newly selected plan", async () => {
    const first = summary("incident-mutation-slow");
    const second = summary("incident-mutation-fast");
    const firstReview = responsePlanReviewFixture({
      commandId: "quarantine-first-incident",
      incidentId: first.incident_id,
    });
    const secondReview = responsePlanReviewFixture({
      commandId: "quarantine-second-incident",
      incidentId: second.incident_id,
    });
    const approvalResponse = deferred<Response>();
    const { fetch, requests } = routedFetch((request) => {
      const path = routePath(request);
      if (path === "/v1/session") return planSessionResponse();
      if (path === "/v1/incidents") return incidentListResponse([first, second]);
      if (path.endsWith("/workspace")) {
        return jsonResponse(readySource(path.includes(second.incident_id) ? second : first));
      }
      if (path.endsWith("/response-plan") && request.method === "GET") {
        return jsonResponse(path.includes(second.incident_id) ? secondReview : firstReview);
      }
      if (path.endsWith("/response-plan/approve") && request.method === "POST") {
        return approvalResponse.promise;
      }
      return jsonResponse({ code: "unexpected" }, 500);
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({
          baseUrl: "https://web.test",
          fetch,
          tokenProvider: () => "ephemeral-plan-token",
        })}
      />,
    );

    expect(await screen.findByText("quarantine-first-incident")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Approve exact plan" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm approve" }));
    const inbox = screen.getByRole("navigation", { name: "Incident inbox" });
    fireEvent.click(within(inbox).getByRole("link", { name: new RegExp(second.incident_id) }));
    expect(await screen.findByText("quarantine-second-incident")).toBeVisible();

    const approvedFirst = responsePlanReviewFixture({
      incidentId: first.incident_id,
      state: "approved",
    });
    await act(async () => {
      approvalResponse.resolve(jsonResponse(approvedFirst.decision));
      await approvalResponse.promise;
    });

    expect(screen.getByText("quarantine-second-incident")).toBeVisible();
    expect(screen.queryByText(/Approved by/i)).toBeNull();
    expect(
      requests.filter(
        (request) =>
          routePath(request) === `/v1/incidents/${first.incident_id}/response-plan` &&
          request.method === "GET",
      ),
    ).toHaveLength(1);
  });

  it("keeps pending replay, delayed, and missing records explicit", async () => {
    const item = summary("incident-running", "running", {
      delayed: true,
      missing: ["Deterministic validator result", "Final response packet"],
    });
    const { fetch } = routedFetch((request) => {
      if (routePath(request) === "/v1/session") return sessionResponse();
      if (routePath(request) === "/v1/incidents") return incidentListResponse([item]);
      const absent = absentResponsePlan(request);
      if (absent !== null) return absent;
      return jsonResponse(pendingSource(item));
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({ baseUrl: "https://web.test", fetch })}
      />,
    );

    expect(await screen.findByRole("heading", { name: "Investigation in progress" })).toBeVisible();
    expect(screen.getByText(/investigation is delayed/i)).toBeVisible();
    expect(screen.getByText("Deterministic validator result")).toBeVisible();
    expect(screen.getByText("Final response packet")).toBeVisible();
  });

  it("shows a 401 session explicitly while retaining public incident reads", async () => {
    const item = summary("incident-public");
    const { fetch, requests } = routedFetch((request) => {
      if (routePath(request) === "/v1/session") {
        return jsonResponse({ code: "operator-token-required" }, 401);
      }
      if (routePath(request) === "/v1/incidents") return incidentListResponse([item]);
      const absent = absentResponsePlan(request);
      if (absent !== null) return absent;
      return jsonResponse(readySource(item));
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({ baseUrl: "https://web.test", fetch })}
      />,
    );

    expect(
      await screen.findByRole("heading", { name: "Unauthenticated read-only session" }),
    ).toBeVisible();
    expect(await screen.findByRole("heading", { name: "Incident overview" })).toBeVisible();
    expect(requests.find((request) => routePath(request).endsWith("/workspace"))).toBeDefined();
  });

  it("fails closed on a typed workspace integrity response", async () => {
    const item = summary("incident-integrity");
    const { fetch } = routedFetch((request) => {
      if (routePath(request) === "/v1/session") return sessionResponse();
      if (routePath(request) === "/v1/incidents") return incidentListResponse([item]);
      return jsonResponse({ code: "replay-integrity-failed" }, 409);
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({ baseUrl: "https://web.test", fetch })}
      />,
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Incident replay could not be verified");
    expect(alert).toHaveTextContent("replay-integrity-failed");
    expect(screen.queryByRole("heading", { name: "Investigation timeline" })).toBeNull();
  });

  it("loads a selected incident through the read adapter", async () => {
    const first = summary("incident-first");
    const second = summary("incident/second");
    const { fetch, requests } = routedFetch((request) => {
      const path = routePath(request);
      if (path === "/v1/session") return sessionResponse();
      if (path === "/v1/incidents") return incidentListResponse([first, second]);
      const absent = absentResponsePlan(request);
      if (absent !== null) return absent;
      return jsonResponse(readySource(path.includes("second") ? second : first));
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({ baseUrl: "https://web.test", fetch })}
      />,
    );
    await screen.findByRole("heading", { name: "Incident overview" });

    const inbox = screen.getByRole("navigation", { name: "Incident inbox" });
    fireEvent.click(within(inbox).getByRole("link", { name: new RegExp(second.incident_id) }));

    expect(screen.getByRole("main")).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent("Loading incident");

    await waitFor(() => {
      expect(within(screen.getByRole("main")).getByText(second.incident_id)).toBeVisible();
    });
    expect(
      requests.some((request) => request.url.endsWith("/v1/incidents/incident%2Fsecond/workspace")),
    ).toBe(true);
  });

  it("moves focus to the announced loading state when retrying", async () => {
    let listAttempts = 0;
    const retryList = deferred<Response>();
    const { fetch } = routedFetch((request) => {
      if (routePath(request) === "/v1/session") return sessionResponse();
      if (routePath(request) === "/v1/incidents") {
        listAttempts += 1;
        if (listAttempts === 1) return jsonResponse({ code: "service-unavailable" }, 503);
        return retryList.promise;
      }
      return jsonResponse({ code: "unexpected" }, 500);
    });
    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({ baseUrl: "https://web.test", fetch })}
      />,
    );
    const retry = await screen.findByRole("button", { name: "Try again" });

    fireEvent.click(retry);

    expect(screen.getByRole("main")).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent("Loading incident");
    await act(async () => {
      retryList.resolve(incidentListResponse([]));
      await retryList.promise;
    });
    expect(await screen.findByRole("status")).toHaveTextContent("No incident records");
  });

  it("aborts and ignores a stale workspace response after selection changes", async () => {
    const first = summary("incident-slow");
    const second = summary("incident-fast");
    const slowResponse = deferred<Response>();
    const { fetch, requests } = routedFetch((request) => {
      const path = routePath(request);
      if (path === "/v1/session") return sessionResponse();
      if (path === "/v1/incidents") return incidentListResponse([first, second]);
      const absent = absentResponsePlan(request);
      if (absent !== null) return absent;
      if (path.includes(first.incident_id)) return slowResponse.promise;
      return jsonResponse(readySource(second));
    });

    render(
      <IncidentWorkspaceApp
        adapter={createIncidentReadAdapter({ baseUrl: "https://web.test", fetch })}
      />,
    );

    const inbox = await screen.findByRole("navigation", { name: "Incident inbox" });
    await waitFor(() => {
      expect(requests.some((request) => routePath(request).includes(first.incident_id))).toBe(true);
    });
    fireEvent.click(within(inbox).getByRole("link", { name: new RegExp(second.incident_id) }));

    await waitFor(() => {
      expect(within(screen.getByRole("main")).getByText(second.incident_id)).toBeVisible();
    });
    const slowRequest = requests.find((request) => routePath(request).includes(first.incident_id));
    expect(slowRequest?.signal.aborted).toBe(true);

    await act(async () => {
      slowResponse.resolve(jsonResponse(readySource(first)));
      await slowResponse.promise;
    });
    expect(within(screen.getByRole("main")).getByText(second.incident_id)).toBeVisible();
    expect(within(screen.getByRole("main")).queryByText(first.incident_id)).toBeNull();
  });
});
