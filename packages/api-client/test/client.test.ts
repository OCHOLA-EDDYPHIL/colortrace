import { describe, expect, expectTypeOf, it } from "vitest";

import {
  admitRecoveryVerification,
  type AdmitSimulatorActionRequest,
  admitSimulatorAction,
  type AlertIntake,
  type CandidatePlan,
  createClient,
  createIncident,
  type DeterministicResult,
  type EvidenceEnvelope,
  executeRecoveryVerificationTask,
  getIncident,
  type IncidentReplay,
  type ModelInvocation,
  replayIncident,
  type RecoveryVerificationAdmission,
  type RecoveryVerificationAdmissionRequest,
  type RecoveryVerificationTask,
  type RecoveryVerificationTaskResult,
  type ResponsePacket,
  type SimulatorActionAdmission,
  type TraceEvent,
  type UnresolvedItem,
  type ValidatorResult,
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
  it("keeps persisted provenance fields concrete", () => {
    expectTypeOf<
      ResponsePacket["deterministic_results"][number]
    >().toEqualTypeOf<DeterministicResult>();
    expectTypeOf<ResponsePacket["invocation_records"][number]>().toEqualTypeOf<ModelInvocation>();
    expectTypeOf<ResponsePacket["unresolved_items"][number]>().toEqualTypeOf<UnresolvedItem>();
    expectTypeOf<Exclude<ResponsePacket["candidate_plan"], null>>().toEqualTypeOf<CandidatePlan>();
    expectTypeOf<IncidentReplay["evidence"][number]>().toEqualTypeOf<EvidenceEnvelope>();
    expectTypeOf<IncidentReplay["validator_results"][number]>().toEqualTypeOf<ValidatorResult>();
    expectTypeOf<IncidentReplay["invocations"][number]>().toEqualTypeOf<ModelInvocation>();
    expectTypeOf<IncidentReplay["trace_events"][number]>().toEqualTypeOf<TraceEvent>();
  });

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

  it("admits only the opaque typed simulator dispatch identity", async () => {
    const requests: Request[] = [];
    const body: AdmitSimulatorActionRequest = {
      schema: "simulator-action-admission-request/v1",
      task_key: `dispatch-task:${"1".repeat(64)}`,
      operation_id: `dispatch-operation:${"2".repeat(64)}`,
      payload_sha256: `sha256:${"3".repeat(64)}`,
    };
    const admission: SimulatorActionAdmission = {
      ...body,
      schema: "simulator-action-admission/v1",
      admission_id: `simulator-admission:${"4".repeat(64)}`,
      action_id: `simulator-action:${"5".repeat(64)}`,
      dispatch_bundle_sha256: `sha256:${"6".repeat(64)}`,
      incident_id: "incident-001",
      incident_version: 3,
      plan_id: `response-plan:${"7".repeat(64)}`,
      plan_version: 2,
      plan_sha256: `sha256:${"8".repeat(64)}`,
      approval_id: `plan-decision:${"9".repeat(64)}`,
      approval_sha256: `sha256:${"a".repeat(64)}`,
      authorization_id: `dispatch-authorization:${"b".repeat(64)}`,
      authorization_sha256: `sha256:${"c".repeat(64)}`,
      consumption_id: `dispatch-consumption:${"d".repeat(64)}`,
      consumption_sha256: `sha256:${"e".repeat(64)}`,
      executor_actor: {
        issuer: "https://identity.example.test",
        subject: "simulator@example.test",
        audience: "colortrace-api",
        kind: "service",
      },
      admitted_at: "2026-08-13T21:00:00Z",
      admission_sha256: `sha256:${"f".repeat(64)}`,
    };
    const generatedClient = createClient({
      baseUrl: "https://example.invalid",
      fetch: async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        requests.push(request);
        return new Response(JSON.stringify(admission), {
          headers: { "Content-Type": "application/json" },
          status: 202,
        });
      },
    });

    const response = await admitSimulatorAction(
      { incidentId: "incident/001", admitSimulatorActionRequest: body },
      { client: generatedClient, throwOnError: true },
    );

    expect(response).toEqual(admission);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.method).toBe("POST");
    expect(requests[0]?.url).toBe(
      "https://example.invalid/internal/v1/incidents/incident%2F001/simulator-actions",
    );
    await expect(requests[0]?.json()).resolves.toEqual(body);
  });

  it("keeps verification admission separate from private task execution", async () => {
    const requests: Request[] = [];
    const taskKey = `recovery-verification-task:${"1".repeat(64)}`;
    const admissionRequest: RecoveryVerificationAdmissionRequest = {
      schema: "recovery-verification-admission-request/v1",
      expected_incident_version: 4,
      expected_outcome_sha256: `sha256:${"2".repeat(64)}`,
      idempotency_key: "test-test-test",
    };
    const admission: RecoveryVerificationAdmission = {
      ...admissionRequest,
      schema: "recovery-verification-admission/v1",
      task_key: taskKey,
      incident_id: "incident/001",
      payload_sha256: `sha256:${"3".repeat(64)}`,
      duplicate: false,
      state: "queued",
    };
    const task: RecoveryVerificationTask = {
      schema: "recovery-verification-task/v1",
      task_key: admission.task_key,
      incident_id: admission.incident_id,
      expected_incident_version: admission.expected_incident_version,
      expected_outcome_sha256: admission.expected_outcome_sha256,
      payload_sha256: admission.payload_sha256,
      idempotency_key: admission.idempotency_key,
    };
    const result: RecoveryVerificationTaskResult = {
      schema: "recovery-verification-task-result/v1",
      result_id: `recovery-verification-task-result:${"4".repeat(64)}`,
      result_sha256: `sha256:${"4".repeat(64)}`,
      task_key: task.task_key,
      payload_sha256: task.payload_sha256,
      incident_id: task.incident_id,
      expected_incident_version: task.expected_incident_version,
      expected_outcome_sha256: task.expected_outcome_sha256,
      status: "unresolved",
      packet_id: null,
      packet_sha256: null,
      reason_code: "recovery-verification-worker-failed",
    };
    const generatedClient = createClient({
      baseUrl: "https://example.invalid",
      fetch: async (input, init) => {
        const request = input instanceof Request ? input : new Request(input, init);
        requests.push(request);
        const response = request.url.includes("/private/") ? result : admission;
        return new Response(JSON.stringify(response), {
          headers: { "Content-Type": "application/json" },
          status: request.url.includes("/private/") ? 200 : 202,
        });
      },
    });

    await expect(
      admitRecoveryVerification(
        {
          incidentId: "incident/001",
          recoveryVerificationAdmissionRequest: admissionRequest,
        },
        { client: generatedClient, throwOnError: true },
      ),
    ).resolves.toEqual(admission);
    await expect(
      executeRecoveryVerificationTask(
        { taskKey, recoveryVerificationTask: task },
        { client: generatedClient, throwOnError: true },
      ),
    ).resolves.toEqual(result);

    expect(requests.map((request) => request.url)).toEqual([
      "https://example.invalid/internal/v1/incidents/incident%2F001/recovery/verifications",
      `https://example.invalid/private/v1/recovery-verification-tasks/${encodeURIComponent(taskKey)}`,
    ]);
    await expect(requests[0]?.json()).resolves.toEqual(admissionRequest);
    await expect(requests[1]?.json()).resolves.toEqual(task);
  });
});
