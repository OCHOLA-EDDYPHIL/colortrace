import type {
  IncidentReplayProjectionInput,
  ProjectionEvidenceEnvelope,
  ProjectionModelInvocation,
  ProjectionTraceEvent,
} from "../src/types.ts";

const digest = (character: string): string => `sha256:${character.repeat(64)}`;
const rawDigest = (character: string): string => character.repeat(64);

const incidentId = "incident-canonical";
const traceId = "1".repeat(32);
const resultId = `validation-result:${rawDigest("a")}`;
const deterministicEvidenceId = `deterministic-result:${rawDigest("b")}`;

function providerEvidence(
  evidenceId: string,
  queryKey: string,
  eventTime: string,
  excerpt: string,
  overrides: Partial<ProjectionEvidenceEnvelope> = {},
): ProjectionEvidenceEnvelope {
  return {
    schema: "evidence-envelope/v1",
    evidence_id: evidenceId,
    incident_id: incidentId,
    request_id: `request-${queryKey}`,
    source: { kind: "grafana-mcp", tool: `tool-${queryKey}` },
    observation: { kind: "grafana-mcp-query", query_key: queryKey },
    timing: {
      source_time: null,
      event_time: eventTime,
      retrieved_at: "2026-08-13T12:00:20.000Z",
      freshness: "current",
    },
    content_sha256: digest("c"),
    content: { value: excerpt },
    display_excerpt: excerpt,
    correlation_keys: { trace_id: traceId },
    collection: { outcome: "collected", attempts: 1, retries: 0, error: null },
    trust: "untrusted-provider-data",
    producer_version: "mcp-grafana/1.1.0",
    predecessor_event_sha256: null,
    event_sha256: digest("d"),
    ...overrides,
  };
}

function invocation(id: string, inputEvidenceIds: readonly string[]): ProjectionModelInvocation {
  return {
    invocation_id: id,
    incident_id: incidentId,
    turn_kind: id.endsWith("1") ? "evidence-selection" : "response-drafting",
    input_evidence_ids: inputEvidenceIds,
    latency_ms: 120,
    result_class: "accepted",
    error_code: null,
    output_sha256: digest("e"),
    trace_id: traceId,
    derivation_sha256: digest("f"),
  };
}

function traceEvent(
  sequence: number,
  eventType: string,
  occurredAt: string,
  status?: string,
): ProjectionTraceEvent {
  const eventSha256 = digest(String(sequence));
  return {
    event_id: `event:${eventSha256.slice("sha256:".length)}`,
    incident_id: incidentId,
    sequence,
    event_type: eventType,
    trace_id: traceId,
    payload: status === undefined ? {} : { status },
    occurred_at: occurredAt,
    event_sha256: eventSha256,
  };
}

const providerIds = [digest("1"), digest("2"), digest("3"), digest("4")] as const;
const frameEvidenceIds = [
  "validator-evidence:frame-b-01",
  "validator-evidence:frame-b-02",
  "validator-evidence:frame-b-03",
  "validator-evidence:frame-a-01",
  "validator-evidence:frame-a-02",
  "validator-evidence:frame-b-04",
] as const;
const derivativeEvidenceId = "validator-evidence:artifact-b-02-derivative";
const validatorEvidenceIds = [...frameEvidenceIds, derivativeEvidenceId] as const;

const affected = [
  { kind: "frame" as const, id: "frame-b-01" },
  { kind: "frame" as const, id: "frame-b-02" },
  { kind: "frame" as const, id: "frame-b-03" },
  { kind: "derivative" as const, id: "artifact-b-02-derivative" },
];
const safe = [
  { kind: "frame" as const, id: "frame-a-01" },
  { kind: "frame" as const, id: "frame-a-02" },
  { kind: "frame" as const, id: "frame-b-04" },
];

const modelInvocations = [
  invocation("invocation-1", providerIds),
  invocation("invocation-2", [...providerIds, ...validatorEvidenceIds]),
];

export const canonicalReplayFixture = {
  schema: "incident-replay/v1",
  incident: {
    incident_id: incidentId,
    alert_id: "alert-canonical",
    status: "resolved",
    version: 3,
    alert_sha256: digest("0"),
    trace_id: traceId,
    packet_id: `response-packet:${rawDigest("9")}`,
    created_at: "2026-08-13T12:00:00.000Z",
    updated_at: "2026-08-13T12:00:40.000Z",
  },
  task: {
    task_id: `task:${rawDigest("8")}`,
    incident_id: incidentId,
    expected_incident_version: 1,
    alert_sha256: digest("0"),
    trace_id: traceId,
    status: "complete",
    packet_id: `response-packet:${rawDigest("9")}`,
    created_at: "2026-08-13T12:00:00.000Z",
    updated_at: "2026-08-13T12:00:40.000Z",
  },
  alert: {
    incident_id: incidentId,
    alert_id: "alert-canonical",
    alert_started_at: "2026-08-13T11:59:50.000Z",
    retrieved_at: "2026-08-13T12:00:00.000Z",
    correlation_keys: { trace_id: traceId, worker_id: "worker-b" },
  },
  evidence: [
    providerEvidence(
      providerIds[2],
      "metric.correlated-observations",
      "2026-08-13T11:59:58.000Z",
      "metric evidence",
    ),
    providerEvidence(providerIds[0], "alert.rule", "2026-08-13T11:59:50.000Z", "alert evidence"),
    providerEvidence(providerIds[3], "trace.by-id", "2026-08-13T11:59:59.000Z", "trace evidence"),
    providerEvidence(
      providerIds[1],
      "log.correlated-events",
      "2026-08-13T11:59:56.000Z",
      "log evidence",
    ),
  ],
  validator_results: [
    {
      result_id: resultId,
      incident_id: incidentId,
      status: "resolved",
      validator: { name: "colortrace-validator", version: "1.0.0" },
      policies: {
        comparison: "declared-reference-comparison/v1",
        scope: "single-causal-resource-scope/v1",
        lineage: "exact-typed-lineage/v1",
        claim: "deterministic-claim/v1",
      },
      scope: {
        state: "resolved",
        policy: "single-causal-resource-scope/v1",
        causal_resource_sha256: rawDigest("7"),
        frames: [
          {
            job_id: "job-b-02",
            frame_id: "frame-b-02",
            output_id: "output-b-02",
            worker_id: "worker-b",
            state: "affected",
            reason_codes: ["causal-resource-confirmed"],
            evidence_ids: [frameEvidenceIds[1]],
          },
          {
            job_id: "job-a-02",
            frame_id: "frame-a-02",
            output_id: "output-a-02",
            worker_id: "worker-a",
            state: "safe",
            reason_codes: ["comparison-match-safe"],
            evidence_ids: [frameEvidenceIds[4]],
          },
          {
            job_id: "job-b-04",
            frame_id: "frame-b-04",
            output_id: "output-b-04",
            worker_id: "worker-b",
            state: "safe",
            reason_codes: ["comparison-match-safe"],
            evidence_ids: [frameEvidenceIds[5]],
          },
          {
            job_id: "job-b-01",
            frame_id: "frame-b-01",
            output_id: "output-b-01",
            worker_id: "worker-b",
            state: "affected",
            reason_codes: ["causal-resource-confirmed"],
            evidence_ids: [frameEvidenceIds[0]],
          },
          {
            job_id: "job-a-01",
            frame_id: "frame-a-01",
            output_id: "output-a-01",
            worker_id: "worker-a",
            state: "safe",
            reason_codes: ["comparison-match-safe"],
            evidence_ids: [frameEvidenceIds[3]],
          },
          {
            job_id: "job-b-03",
            frame_id: "frame-b-03",
            output_id: "output-b-03",
            worker_id: "worker-b",
            state: "affected",
            reason_codes: ["causal-resource-confirmed"],
            evidence_ids: [frameEvidenceIds[2]],
          },
        ],
        derivatives: [
          {
            artifact_id: "artifact-b-02-derivative",
            parent_artifact_id: "output-b-02",
            state: "affected",
            lineage_policy: "exact-typed-lineage/v1",
            reason_codes: ["derivative-inherits-parent-scope"],
            evidence_ids: [derivativeEvidenceId],
          },
        ],
        reason_codes: [],
      },
      claims: [
        {
          claim_id: "claim-causal-resource",
          deterministic_result_evidence_id: deterministicEvidenceId,
          derivation_sha256: rawDigest("b"),
          evidence_ids: [frameEvidenceIds[0], frameEvidenceIds[1], frameEvidenceIds[2]],
        },
      ],
      evidence: validatorEvidenceIds.map((evidenceId, index) => ({
        evidence_id: evidenceId,
        kind: index === validatorEvidenceIds.length - 1 ? "lineage" : "scope-frame",
        path: `artifacts/${index}.json`,
        sha256: rawDigest(String((index + 1) % 10)),
      })),
      reason_codes: [],
      derivation_sha256: rawDigest("a"),
    },
  ],
  invocations: modelInvocations,
  packet: {
    packet_id: `response-packet:${rawDigest("9")}`,
    incident_id: incidentId,
    version: 1,
    status: "resolved",
    fixed_window: {
      start: "2026-08-13T11:54:50.000Z",
      end: "2026-08-13T12:00:00.000Z",
      frozen_at: "2026-08-13T12:00:00.000Z",
    },
    evidence_ids: [...providerIds, ...validatorEvidenceIds, deterministicEvidenceId],
    deterministic_results: [
      {
        result_id: resultId,
        validator: "colortrace-validator",
        validator_version: "1.0.0",
        status: "resolved",
        policy_versions: {
          comparison: "declared-reference-comparison/v1",
          scope: "single-causal-resource-scope/v1",
        },
        derivation_sha256: rawDigest("a"),
        evidence_ids: validatorEvidenceIds,
      },
    ],
    claims: [
      {
        claim_id: "claim-causal-resource",
        claim_type: "causal-resource",
        subject: { kind: "resource-sha256", value: rawDigest("7") },
        state: "confirmed",
        policy: "deterministic-claim/v1",
        deterministic_result_evidence_id: deterministicEvidenceId,
        source_validator_result_id: resultId,
        derivation_sha256: rawDigest("b"),
        contradiction_links: [],
        evidence_ids: [frameEvidenceIds[0], frameEvidenceIds[1], frameEvidenceIds[2]],
        reason_codes: ["causal-resource-confirmed"],
      },
    ],
    scope: {
      state: "resolved",
      policy: "single-causal-resource-scope/v1",
      affected,
      safe,
      unknown: [],
      reason_codes: [],
    },
    invocation_records: modelInvocations,
    unresolved_items: [],
    candidate_plan: {
      plan_id: `candidate-plan:${rawDigest("6")}`,
      non_executable: true,
      targets: affected,
      claim_ids: ["claim-causal-resource"],
    },
    no_action_reason: null,
    finalized_at: "2026-08-13T12:00:38.000Z",
    derivation_sha256: digest("9"),
  },
  trace_events: [
    traceEvent(1, "api.intake.accepted", "2026-08-13T12:00:00.000Z"),
    traceEvent(2, "task.queued", "2026-08-13T12:00:01.000Z"),
    traceEvent(3, "worker.started", "2026-08-13T12:00:02.000Z"),
    traceEvent(4, "packet.persisted", "2026-08-13T12:00:39.000Z", "resolved"),
    traceEvent(5, "incident.completed", "2026-08-13T12:00:40.000Z", "resolved"),
  ],
  derivation_sha256: digest("5"),
} satisfies IncidentReplayProjectionInput;

const unresolvedIncidentId = "incident-unresolved";
const unresolvedTraceId = "2".repeat(32);
const unresolvedEvidenceId = digest("a");
const unresolvedInvocation: ProjectionModelInvocation = {
  invocation_id: "invocation-unresolved",
  incident_id: unresolvedIncidentId,
  turn_kind: "evidence-selection",
  input_evidence_ids: [unresolvedEvidenceId],
  latency_ms: 20000,
  result_class: "failed",
  error_code: "trace-missing",
  output_sha256: null,
  trace_id: unresolvedTraceId,
  derivation_sha256: digest("b"),
};

export const unresolvedReplayFixture = {
  schema: "incident-replay/v1",
  incident: {
    incident_id: unresolvedIncidentId,
    alert_id: "alert-unresolved",
    status: "unresolved",
    version: 3,
    alert_sha256: digest("c"),
    trace_id: unresolvedTraceId,
    packet_id: `response-packet:${rawDigest("d")}`,
    created_at: "2026-08-13T13:00:00.000Z",
    updated_at: "2026-08-13T13:00:30.000Z",
  },
  task: {
    task_id: `task:${rawDigest("e")}`,
    incident_id: unresolvedIncidentId,
    expected_incident_version: 1,
    alert_sha256: digest("c"),
    trace_id: unresolvedTraceId,
    status: "complete",
    packet_id: `response-packet:${rawDigest("d")}`,
    created_at: "2026-08-13T13:00:00.000Z",
    updated_at: "2026-08-13T13:00:30.000Z",
  },
  alert: {
    incident_id: unresolvedIncidentId,
    alert_id: "alert-unresolved",
    alert_started_at: "2026-08-13T12:59:50.000Z",
    retrieved_at: "2026-08-13T13:00:00.000Z",
    correlation_keys: { trace_id: unresolvedTraceId },
  },
  evidence: [
    providerEvidence(
      unresolvedEvidenceId,
      "trace.by-id",
      "2026-08-13T12:59:59.000Z",
      "trace unavailable",
      {
        incident_id: unresolvedIncidentId,
        correlation_keys: { trace_id: unresolvedTraceId },
        timing: {
          source_time: null,
          event_time: "2026-08-13T12:59:59.000Z",
          retrieved_at: "2026-08-13T13:00:20.000Z",
          freshness: "unresolved",
        },
        collection: {
          outcome: "error",
          attempts: 1,
          retries: 0,
          error: { code: "trace-missing", retryable: false },
        },
      },
    ),
  ],
  validator_results: [],
  invocations: [unresolvedInvocation],
  packet: {
    packet_id: `response-packet:${rawDigest("d")}`,
    incident_id: unresolvedIncidentId,
    version: 1,
    status: "unresolved",
    fixed_window: {
      start: "2026-08-13T12:54:50.000Z",
      end: "2026-08-13T13:00:00.000Z",
      frozen_at: "2026-08-13T13:00:00.000Z",
    },
    evidence_ids: [unresolvedEvidenceId, "missing:evidence"],
    deterministic_results: [],
    claims: [
      {
        claim_id: "claim-investigation-incomplete",
        claim_type: "investigation-completeness",
        subject: { kind: "incident-id", value: unresolvedIncidentId },
        state: "unresolved",
        policy: "investigation-completeness/v1",
        deterministic_result_evidence_id: null,
        source_validator_result_id: null,
        derivation_sha256: rawDigest("f"),
        contradiction_links: [],
        evidence_ids: [unresolvedEvidenceId],
        reason_codes: ["evidence-unavailable"],
      },
    ],
    scope: {
      state: "unresolved",
      policy: "single-causal-resource-scope/v1",
      affected: [],
      safe: [],
      unknown: [{ kind: "frame", id: "frame-unknown" }],
      reason_codes: ["evidence-unavailable"],
    },
    invocation_records: [unresolvedInvocation],
    unresolved_items: [
      {
        code: "evidence-unavailable",
        stage: "evidence",
        evidence_ids: [unresolvedEvidenceId, "missing:evidence"],
      },
    ],
    candidate_plan: null,
    no_action_reason: "evidence-unavailable",
    finalized_at: "2026-08-13T13:00:28.000Z",
    derivation_sha256: digest("d"),
  },
  trace_events: [
    {
      ...traceEvent(1, "api.intake.accepted", "2026-08-13T13:00:00.000Z"),
      incident_id: unresolvedIncidentId,
      trace_id: unresolvedTraceId,
    },
    {
      ...traceEvent(2, "task.queued", "2026-08-13T13:00:01.000Z"),
      incident_id: unresolvedIncidentId,
      trace_id: unresolvedTraceId,
    },
    {
      ...traceEvent(3, "worker.started", "2026-08-13T13:00:02.000Z"),
      incident_id: unresolvedIncidentId,
      trace_id: unresolvedTraceId,
    },
    {
      ...traceEvent(4, "packet.persisted", "2026-08-13T13:00:29.000Z", "unresolved"),
      incident_id: unresolvedIncidentId,
      trace_id: unresolvedTraceId,
    },
    {
      ...traceEvent(5, "incident.completed", "2026-08-13T13:00:30.000Z", "unresolved"),
      incident_id: unresolvedIncidentId,
      trace_id: unresolvedTraceId,
    },
  ],
  derivation_sha256: digest("1"),
} satisfies IncidentReplayProjectionInput;

export function cloneReplayFixture(
  replay: IncidentReplayProjectionInput = canonicalReplayFixture,
): IncidentReplayProjectionInput {
  return JSON.parse(JSON.stringify(replay)) as IncidentReplayProjectionInput;
}
