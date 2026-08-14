import { canonicalJsonSha256 } from "../src/canonical-sha256.ts";
import { RECOVERY_CHECKS } from "../src/recovery.ts";
import type {
  RecoveryAuditEvent,
  RecoveryActionOutcome,
  RecoveryCheckResult,
  RecoveryClosureResult,
  RecoveryEvidenceRecord,
  RecoveryPacket,
  RecoveryReviewProjectionInput,
  RecoveryTarget,
  RecoveryVerificationArtifact,
  RecoveryVerificationSnapshot,
} from "../src/recovery-types.ts";

export type RecoveryFixtureState =
  | "closed"
  | "recovery_failed"
  | "recovery_unresolved"
  | "recovery_verified";

export type RecoveryFixtureOptions = {
  readonly closureIdempotencyKey?: string;
  readonly closureReason?: string;
};

const INCIDENT_ID = "incident-recovery-24";
const WORKFLOW_ID = "recovery-workflow-24";
const ACTION_ID = `simulator-action:${"a".repeat(64)}`;
const PUBLICATION_POINTER_SHA256 = digest(2);
const SAFE_COMPLEMENT_SHA256 = digest(3);
const SAFE_PROOF_SHA256 = digest(4);

function digest(value: number): `sha256:${string}` {
  return `sha256:${(value % 16).toString(16).repeat(64)}`;
}

function target(kind: RecoveryTarget["kind"], id: string): RecoveryTarget {
  return {
    schema: "simulator-target/v1",
    namespace: "colortrace-simulator",
    kind,
    id,
  };
}

const RESOURCE = target("color-resource", "show-look-resource");
const FRAMES = [
  target("frame", "frame-a-01"),
  target("frame", "frame-a-02"),
  target("frame", "frame-a-03"),
];
const REFERENCES = [
  target("frame", "reference-a-01"),
  target("frame", "reference-a-02"),
  target("frame", "reference-a-03"),
];
const DERIVATIVE = target("derivative", "derivative-a-01");
const SAFE_FRAME = target("frame", "frame-b-04");

function artifact(
  artifactId: string,
  role: RecoveryVerificationArtifact["role"],
  value: number,
  artifactTarget: RecoveryTarget | null,
): RecoveryVerificationArtifact {
  return {
    schema: "recovery-verification-artifact/v1",
    artifact_id: artifactId,
    role,
    target: artifactTarget,
    sha256: digest(value),
    size: value * 101,
    publication_pointer_sha256: PUBLICATION_POINTER_SHA256,
  };
}

const ARTIFACTS: readonly RecoveryVerificationArtifact[] = [
  artifact("artifact-active-resource", "active-resource", 5, RESOURCE),
  artifact("artifact-affected-1", "affected-output", 6, FRAMES[0] ?? null),
  artifact("artifact-affected-2", "affected-output", 7, FRAMES[1] ?? null),
  artifact("artifact-affected-3", "affected-output", 8, FRAMES[2] ?? null),
  artifact("artifact-reference-1", "declared-reference", 9, REFERENCES[0] ?? null),
  artifact("artifact-reference-2", "declared-reference", 10, REFERENCES[1] ?? null),
  artifact("artifact-reference-3", "declared-reference", 11, REFERENCES[2] ?? null),
  artifact("artifact-derivative", "derivative-output", 12, DERIVATIVE),
  artifact("artifact-derivative-parent", "derivative-parent", 13, FRAMES[0] ?? null),
  artifact("artifact-fixture-manifest", "fixture-manifest", 14, null),
  artifact("artifact-lineage-manifest", "lineage-manifest", 15, null),
  artifact("artifact-preservation-manifest", "preservation-manifest", 16, null),
  artifact("artifact-runtime-manifest", "runtime-manifest", 17, null),
  artifact("artifact-safe-complement", "safe-complement", 18, SAFE_FRAME),
  artifact("artifact-safe-proof", "safe-complement-proof", 19, SAFE_FRAME),
];

function sealSnapshot(
  body: Omit<RecoveryVerificationSnapshot, "snapshot_id" | "snapshot_sha256">,
): RecoveryVerificationSnapshot {
  const snapshotSha256 = `sha256:${canonicalJsonSha256(body)}`;
  return {
    ...body,
    snapshot_id: `recovery-snapshot:${snapshotSha256.slice("sha256:".length)}`,
    snapshot_sha256: snapshotSha256,
  };
}

function buildSnapshot(): RecoveryVerificationSnapshot {
  const actionOutcomeBody = {
    schema: "simulator-action-outcome/v1",
    action_id: ACTION_ID,
    status: "succeeded",
    reason_codes: [],
    incident_id: INCIDENT_ID,
    incident_version: 5,
    plan_id: "response-plan-24",
    plan_version: 3,
    plan_sha256: digest(5),
    action_started_at: "2026-08-14T12:00:00.000Z",
    publication_promoted_at: "2026-08-14T12:00:50.000Z",
    completed_at: "2026-08-14T12:01:00.000Z",
    active_publication_pointer_sha256: PUBLICATION_POINTER_SHA256,
    active_runtime_manifest_sha256: digest(6),
    preservation_manifest_sha256: digest(7),
    safe_complement_before_sha256: SAFE_COMPLEMENT_SHA256,
    safe_complement_after_sha256: SAFE_COMPLEMENT_SHA256,
    safe_complement_proof_sha256: SAFE_PROOF_SHA256,
    targets: [...FRAMES, DERIVATIVE],
    exclusions: [SAFE_FRAME],
    command_outcomes: [
      {
        schema: "simulator-command-result/v1",
        command_id: "command-quarantine-resource",
        result_kind: "quarantine",
        target: RESOURCE,
        trace_id: "1".repeat(32),
        before: { state: "active" },
        after: { state: "quarantined" },
      },
      ...FRAMES.map((frame, index) => ({
        schema: "simulator-command-result/v1" as const,
        command_id: `command-rerender-${index + 1}`,
        result_kind: "frame" as const,
        target: frame,
        trace_id: `${index + 2}`.repeat(32),
        before: { generation: 1 },
        after: { generation: 2 },
      })),
    ],
    new_trace_ids: ["1".repeat(32), "2".repeat(32), "3".repeat(32), "4".repeat(32)],
  } as const satisfies Omit<RecoveryActionOutcome, "outcome_id" | "outcome_sha256">;
  const outcomeSha256 = `sha256:${canonicalJsonSha256(actionOutcomeBody)}`;
  const actionOutcome: RecoveryActionOutcome = {
    ...actionOutcomeBody,
    outcome_id: `simulator-action-outcome:${outcomeSha256.slice("sha256:".length)}`,
    outcome_sha256: outcomeSha256,
  };
  return sealSnapshot({
    schema: "recovery-verification-snapshot/v1",
    incident_id: INCIDENT_ID,
    incident_version: 5,
    created_at: "2026-08-14T12:01:45.000Z",
    action_outcome: actionOutcome,
    active_publication: {
      schema: "recovery-active-publication/v1",
      publication_id: "publication-generation-2",
      observed_at: "2026-08-14T12:01:30.000Z",
      generation: 2,
      pointer_sha256: PUBLICATION_POINTER_SHA256,
      runtime_manifest_sha256: digest(6),
      fixture_manifest_sha256: digest(8),
      lineage_manifest_sha256: digest(9),
      declared_resource_manifest_sha256: digest(10),
      preservation_manifest_sha256: digest(7),
      safe_complement_sha256: SAFE_COMPLEMENT_SHA256,
      safe_complement_proof_sha256: SAFE_PROOF_SHA256,
      candidate_seal_sha256: digest(11),
      candidate_tree_sha256: digest(12),
    },
    verification_artifacts: [...ARTIFACTS],
  });
}

function evidenceId(index: number): string {
  return `recovery-evidence:${digest(index + 1).slice("sha256:".length)}`;
}

function evidenceRecords(
  state: RecoveryFixtureState,
  snapshot: RecoveryVerificationSnapshot,
): RecoveryEvidenceRecord[] {
  const outcome = snapshot.action_outcome;
  return RECOVERY_CHECKS.map((check, index) => ({
    schema: "recovery-evidence-record/v1",
    evidence_id: evidenceId(index),
    evidence_sha256: digest(index + 1),
    signal: index === 0 ? "metric" : index === 1 ? "log" : "trace",
    event_id: `recovery-event-${index + 1}`,
    subject_kind: index === 6 ? "safe" : "command",
    subject_id: check,
    trace_id: index < 2 ? null : `${index + 1}`.repeat(32),
    observed_at: `2026-08-14T12:02:${String(index).padStart(2, "0")}.000Z`,
    emitted_at: `2026-08-14T12:02:${String(index + 10).padStart(2, "0")}.000Z`,
    retrieved_at: `2026-08-14T12:02:${String(index + 20).padStart(2, "0")}.000Z`,
    freshness: state === "recovery_unresolved" && index === 6 ? "late" : "post-action",
    correlation: {
      incident_id: INCIDENT_ID,
      action_id: ACTION_ID,
      outcome_id: outcome.outcome_id,
      outcome_sha256: outcome.outcome_sha256,
      target: ARTIFACTS[index]?.target ?? null,
    },
    source_label: `Recovery ${check}`,
    display_excerpt: `Sanitized post-action ${check} observation.`,
  }));
}

function sealCheck(
  body: Omit<RecoveryCheckResult, "result_id" | "result_sha256">,
): RecoveryCheckResult {
  const resultSha256 = `sha256:${canonicalJsonSha256(body)}`;
  return {
    ...body,
    result_id: `recovery-check-result:${resultSha256.slice("sha256:".length)}`,
    result_sha256: resultSha256,
  };
}

function checkResults(state: RecoveryFixtureState): RecoveryCheckResult[] {
  return RECOVERY_CHECKS.map((check, index) => {
    const adverse = index === 6 && (state === "recovery_failed" || state === "recovery_unresolved");
    const resultState = adverse
      ? state === "recovery_failed"
        ? "failed"
        : "unresolved"
      : "passed";
    return sealCheck({
      schema: "recovery-check-result/v1",
      check,
      policy: `${check}/v1`,
      state: resultState,
      normalized_inputs_sha256: digest(index + 2),
      evidence_ids: [evidenceId(index)],
      artifact_ids: [ARTIFACTS[index]?.artifact_id ?? "artifact-missing"],
      reason_codes: adverse
        ? [state === "recovery_failed" ? "telemetry-correlation-failed" : "evidence-late"]
        : [],
    });
  });
}

function sealPacket(body: Omit<RecoveryPacket, "packet_id" | "packet_sha256">): RecoveryPacket {
  const packetSha256 = `sha256:${canonicalJsonSha256(body)}`;
  return {
    ...body,
    packet_id: `recovery-packet:${packetSha256.slice("sha256:".length)}`,
    packet_sha256: packetSha256,
  };
}

function buildPacket(
  state: RecoveryFixtureState,
  snapshot: RecoveryVerificationSnapshot,
  records: readonly RecoveryEvidenceRecord[],
): RecoveryPacket {
  const status = state === "closed" ? "recovery_verified" : state;
  const results = checkResults(state === "closed" ? "recovery_verified" : state);
  return sealPacket({
    schema: "recovery-packet/v1",
    incident_id: INCIDENT_ID,
    incident_version: 5,
    workflow_id: WORKFLOW_ID,
    workflow_version: 3,
    attempt_id: "recovery-attempt-1",
    attempt_number: 1,
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    outcome_id: snapshot.action_outcome.outcome_id,
    outcome_sha256: snapshot.action_outcome.outcome_sha256,
    action_id: snapshot.action_outcome.action_id,
    action_started_at: snapshot.action_outcome.action_started_at,
    evaluation_started_at: "2026-08-14T12:02:00.000Z",
    evaluation_completed_at: "2026-08-14T12:03:00.000Z",
    evidence_request_id: "evidence-request-24",
    evidence_request_sha256: digest(13),
    evidence_ids: records.map((record) => record.evidence_id),
    check_results: results,
    status,
    failure_items: results
      .filter((result) => result.state === "failed")
      .map((result) => ({ check: result.check, reason_codes: [...result.reason_codes] })),
    unresolved_items: results
      .filter((result) => result.state === "unresolved")
      .map((result) => ({ check: result.check, reason_codes: [...result.reason_codes] })),
    eligible_for_closure: status === "recovery_verified",
    supersedes_packet_id: null,
    supersedes_packet_sha256: null,
  });
}

function sealAuditEvent(
  body: Omit<RecoveryAuditEvent, "event_id" | "event_sha256">,
): RecoveryAuditEvent {
  const eventSha256 = `sha256:${canonicalJsonSha256(body)}`;
  return {
    ...body,
    event_id: `recovery-audit-event:${eventSha256.slice("sha256:".length)}`,
    event_sha256: eventSha256,
  };
}

function serviceActor(): RecoveryAuditEvent["actor"] {
  return {
    issuer: "https://identity.example.test/workload",
    subject: "recovery-verifier-service",
    audience: "colortrace-api",
    display_name: "Recovery verifier",
    kind: "service",
    authorized_role: "recovery.verifier",
  };
}

function humanActor(): RecoveryAuditEvent["actor"] {
  return {
    issuer: "https://identity.example.test/tenant",
    subject: "operator-24",
    audience: "colortrace-api",
    display_name: "Pipeline operator",
    kind: "human",
    authorized_role: "recovery.closer",
  };
}

function auditEvent(
  snapshot: RecoveryVerificationSnapshot,
  packet: RecoveryPacket,
  sequence: number,
  eventType: RecoveryAuditEvent["event_type"],
  predecessorEventSha256: string | null,
  closureIdempotencyKey = "close-recovery-24",
  closureReason = "Verified recovery reviewed against post-action evidence.",
): RecoveryAuditEvent {
  const hasPacket = eventType === "verification.completed" || eventType === "recovery.closed";
  const actor = eventType === "recovery.closed" ? humanActor() : serviceActor();
  return sealAuditEvent({
    schema: "recovery-audit-event/v1",
    incident_id: INCIDENT_ID,
    workflow_id: WORKFLOW_ID,
    sequence,
    event_type: eventType,
    actor,
    snapshot_id: snapshot.snapshot_id,
    snapshot_sha256: snapshot.snapshot_sha256,
    outcome_id: snapshot.action_outcome.outcome_id,
    outcome_sha256: snapshot.action_outcome.outcome_sha256,
    packet_id: hasPacket ? packet.packet_id : null,
    packet_sha256: hasPacket ? packet.packet_sha256 : null,
    idempotency_key:
      eventType === "recovery.closed" ? closureIdempotencyKey : `verify-recovery-${sequence}`,
    predecessor_event_sha256: predecessorEventSha256,
    occurred_at: `2026-08-14T12:0${sequence + 2}:00.000Z`,
    details:
      eventType === "recovery.closed"
        ? { reason: closureReason, workflow_version_before: 3, workflow_version_after: 4 }
        : { authoritative_state: eventType },
  });
}

function sealClosure(
  body: Omit<RecoveryClosureResult, "closure_id" | "closure_sha256">,
): RecoveryClosureResult {
  const closureSha256 = `sha256:${canonicalJsonSha256(body)}`;
  return {
    ...body,
    closure_id: `recovery-closure:${closureSha256.slice("sha256:".length)}`,
    closure_sha256: closureSha256,
  };
}

export function recoveryReviewFixture(
  state: RecoveryFixtureState = "recovery_verified",
  options: RecoveryFixtureOptions = {},
): RecoveryReviewProjectionInput {
  const closureIdempotencyKey = options.closureIdempotencyKey ?? "close-recovery-24";
  const closureReason =
    options.closureReason ?? "Verified recovery reviewed against post-action evidence.";
  const snapshot = buildSnapshot();
  const records = evidenceRecords(state, snapshot);
  const packet = buildPacket(state, snapshot, records);
  const requested = auditEvent(snapshot, packet, 1, "verification.requested", null);
  const completed = auditEvent(
    snapshot,
    packet,
    2,
    "verification.completed",
    requested.event_sha256,
  );
  if (state !== "closed") {
    return {
      schema: "recovery-review/v1",
      state,
      current_incident_version: 5,
      workflow_version: 3,
      snapshot,
      evidence_records: records,
      packet,
      closure: null,
      audit_events: [requested, completed],
    };
  }

  const closed = auditEvent(
    snapshot,
    packet,
    3,
    "recovery.closed",
    completed.event_sha256,
    closureIdempotencyKey,
    closureReason,
  );
  const closure = sealClosure({
    schema: "recovery-closure-result/v1",
    incident_id: INCIDENT_ID,
    workflow_id: WORKFLOW_ID,
    workflow_version_before: 3,
    workflow_version_after: 4,
    packet_id: packet.packet_id,
    packet_sha256: packet.packet_sha256,
    outcome_id: packet.outcome_id,
    outcome_sha256: packet.outcome_sha256,
    actor: {
      issuer: "https://identity.example.test/tenant",
      subject: "operator-24",
      audience: "colortrace-api",
      display_name: "Pipeline operator",
      kind: "human",
    },
    authorized_role: "recovery.closer",
    reason: closureReason,
    closed_at: "2026-08-14T12:05:00.000Z",
    idempotency_key: closureIdempotencyKey,
    audit_event_id: closed.event_id,
    audit_event_sha256: closed.event_sha256,
  });
  return {
    schema: "recovery-review/v1",
    state: "closed",
    current_incident_version: 5,
    workflow_version: 4,
    snapshot,
    evidence_records: records,
    packet,
    closure,
    audit_events: [requested, completed, closed],
  };
}

export function cloneRecoveryReview(
  review: RecoveryReviewProjectionInput = recoveryReviewFixture(),
): RecoveryReviewProjectionInput {
  return JSON.parse(JSON.stringify(review)) as RecoveryReviewProjectionInput;
}
