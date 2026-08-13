import { describe, expect, it } from "vitest";

import {
  type AlertIntake,
  createClient,
  createIncident,
  getIncident,
  replayIncident,
} from "../src/index";

const alert: AlertIntake = {
  schema: "alert-intake/v1",
  incident_id: "incident-001",
  alert_id: "alert-001",
  alert_started_at: "2026-08-13T12:00:00.000Z",
  retrieved_at: "2026-08-13T12:01:00.000Z",
  measured_clock_skew_seconds: 1,
  binding: {
    prometheus_datasource_uid: "prometheus-main",
    loki_datasource_uid: "loki-main",
    tempo_datasource_uid: "tempo-main",
    alert_rule_uid: "ct-alert-main",
  },
  correlation_keys: {
    fixture_id: "ct-shadowed-lut-v1",
    run_id: "run-001",
    job_id: "job-b-02",
    worker_id: "worker-b",
    artifact_id: "output-job-b-02",
    trace_id: "11111111111111111111111111111111",
    config_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
    transform_id: "look/main/v1",
  },
  predecessor_event_sha256: null,
};

describe("generated incident client", () => {
  it("sends the exact typed alert body to the admission boundary", async () => {
    const requests: Request[] = [];
    const generatedClient = createClient({
      baseUrl: "https://example.invalid",
      fetch: async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        requests.push(request);
        return new Response(
          JSON.stringify({
            schema: "incident-accepted/v1",
            incident_id: "incident-001",
            task_id: `task:${"a".repeat(64)}`,
            status: "queued",
            version: 1,
            trace_id: alert.correlation_keys.trace_id,
            duplicate: false,
          }),
          { headers: { "Content-Type": "application/json" }, status: 202 },
        );
      },
    });

    const response = await createIncident(
      { alertIntake: alert },
      { client: generatedClient, throwOnError: true },
    );

    expect(response.status).toBe("queued");
    expect(requests).toHaveLength(1);
    expect(requests[0]?.method).toBe("POST");
    expect(requests[0]?.url).toBe("https://example.invalid/v1/incidents");
    await expect(requests[0]?.json()).resolves.toEqual(alert);
  });

  it("encodes incident identity for current-state and replay reads", async () => {
    const requests: Request[] = [];
    const generatedClient = createClient({
      baseUrl: "https://example.invalid",
      fetch: async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        requests.push(request);
        return new Response(JSON.stringify({ code: "incident-not-found" }), {
          headers: { "Content-Type": "application/json" },
          status: 404,
        });
      },
    });

    await expect(
      getIncident({ incidentId: "incident/001" }, { client: generatedClient, throwOnError: true }),
    ).rejects.toEqual({ code: "incident-not-found" });
    await expect(
      replayIncident(
        { incidentId: "incident/001" },
        { client: generatedClient, throwOnError: true },
      ),
    ).rejects.toEqual({ code: "incident-not-found" });

    expect(requests.map((request) => request.url)).toEqual([
      "https://example.invalid/v1/incidents/incident%2F001",
      "https://example.invalid/v1/incidents/incident%2F001/replay",
    ]);
  });
});
