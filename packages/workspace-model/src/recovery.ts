import { canonicalJsonSha256 } from "./canonical-sha256.ts";
import type {
  RecoveryAuditEvent,
  RecoveryCheckName,
  RecoveryCheckResult,
  RecoveryClosureResult,
  RecoveryEvidenceRecord,
  RecoveryPacket,
  RecoveryProjectionProblem,
  RecoveryReviewProjectionInput,
  RecoveryTarget,
  RecoveryVerificationArtifact,
  RecoveryVerificationSnapshot,
  RecoveryWorkspace,
} from "./recovery-types.ts";

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const RECOVERY_EVIDENCE_ID = /^recovery-evidence:[0-9a-f]{64}$/u;
const REASON_CODE = /^[a-z][a-z0-9-]{1,63}$/u;
const TRACE_ID = /^(?!0{32}$)[0-9a-f]{32}$/u;

export const RECOVERY_CHECKS = [
  "active-publication",
  "approved-resource-state",
  "declared-reference-recovery",
  "exact-typed-lineage",
  "approved-recovery-scope",
  "safe-complement-preservation",
  "post-action-telemetry-correlation",
] as const satisfies readonly RecoveryCheckName[];

const ARTIFACT_ROLE_COUNTS = {
  "active-resource": 1,
  "affected-output": 3,
  "declared-reference": 3,
  "derivative-output": 1,
  "derivative-parent": 1,
  "fixture-manifest": 1,
  "lineage-manifest": 1,
  "preservation-manifest": 1,
  "runtime-manifest": 1,
  "safe-complement": 1,
  "safe-complement-proof": 1,
} as const satisfies Readonly<Record<RecoveryVerificationArtifact["role"], number>>;

const REVIEW_KEYS = [
  "schema",
  "state",
  "current_incident_version",
  "workflow_version",
  "snapshot",
  "evidence_records",
  "packet",
  "closure",
  "audit_events",
] as const;
const SNAPSHOT_KEYS = [
  "schema",
  "snapshot_id",
  "snapshot_sha256",
  "incident_id",
  "incident_version",
  "created_at",
  "action_outcome",
  "active_publication",
  "verification_artifacts",
] as const;
const PUBLICATION_KEYS = [
  "schema",
  "publication_id",
  "observed_at",
  "generation",
  "pointer_sha256",
  "runtime_manifest_sha256",
  "fixture_manifest_sha256",
  "lineage_manifest_sha256",
  "declared_resource_manifest_sha256",
  "preservation_manifest_sha256",
  "safe_complement_sha256",
  "safe_complement_proof_sha256",
  "candidate_seal_sha256",
  "candidate_tree_sha256",
] as const;
const ARTIFACT_KEYS = [
  "schema",
  "artifact_id",
  "role",
  "target",
  "sha256",
  "size",
  "publication_pointer_sha256",
] as const;
const TARGET_KEYS = ["schema", "namespace", "kind", "id"] as const;
const EVIDENCE_KEYS = [
  "schema",
  "evidence_id",
  "evidence_sha256",
  "signal",
  "event_id",
  "subject_kind",
  "subject_id",
  "trace_id",
  "observed_at",
  "emitted_at",
  "retrieved_at",
  "freshness",
  "correlation",
  "source_label",
  "display_excerpt",
] as const;
const CORRELATION_KEYS = [
  "incident_id",
  "action_id",
  "outcome_id",
  "outcome_sha256",
  "target",
] as const;
const CHECK_KEYS = [
  "schema",
  "result_id",
  "result_sha256",
  "check",
  "policy",
  "state",
  "normalized_inputs_sha256",
  "evidence_ids",
  "artifact_ids",
  "reason_codes",
] as const;
const PACKET_KEYS = [
  "schema",
  "packet_id",
  "packet_sha256",
  "incident_id",
  "incident_version",
  "workflow_id",
  "workflow_version",
  "attempt_id",
  "attempt_number",
  "snapshot_id",
  "snapshot_sha256",
  "outcome_id",
  "outcome_sha256",
  "action_id",
  "action_started_at",
  "evaluation_started_at",
  "evaluation_completed_at",
  "evidence_request_id",
  "evidence_request_sha256",
  "evidence_ids",
  "check_results",
  "status",
  "failure_items",
  "unresolved_items",
  "eligible_for_closure",
  "supersedes_packet_id",
  "supersedes_packet_sha256",
] as const;
const PACKET_ITEM_KEYS = ["check", "reason_codes"] as const;
const CLOSURE_KEYS = [
  "schema",
  "closure_id",
  "closure_sha256",
  "incident_id",
  "workflow_id",
  "workflow_version_before",
  "workflow_version_after",
  "packet_id",
  "packet_sha256",
  "outcome_id",
  "outcome_sha256",
  "actor",
  "authorized_role",
  "reason",
  "closed_at",
  "idempotency_key",
  "audit_event_id",
  "audit_event_sha256",
] as const;
const CLOSURE_ACTOR_KEYS = ["issuer", "subject", "audience", "display_name", "kind"] as const;
const AUDIT_KEYS = [
  "schema",
  "event_id",
  "event_sha256",
  "incident_id",
  "workflow_id",
  "sequence",
  "event_type",
  "actor",
  "snapshot_id",
  "snapshot_sha256",
  "outcome_id",
  "outcome_sha256",
  "packet_id",
  "packet_sha256",
  "idempotency_key",
  "predecessor_event_sha256",
  "occurred_at",
  "details",
] as const;
const AUDIT_ACTOR_KEYS = [
  "issuer",
  "subject",
  "audience",
  "display_name",
  "kind",
  "authorized_role",
] as const;

function compareText(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function exactKeys(value: object, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort(compareText);
  const expected = [...keys].sort(compareText);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function unique(values: readonly string[]): boolean {
  return new Set(values).size === values.length;
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareText);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  const leftSorted = sortedUnique(left);
  const rightSorted = sortedUnique(right);
  return (
    leftSorted.length === rightSorted.length &&
    leftSorted.every((value, index) => value === rightSorted[index])
  );
}

function validTimestamp(value: string): boolean {
  return value.endsWith("Z") && value.length <= 64 && Number.isFinite(Date.parse(value));
}

function timestamp(value: string): number {
  return Date.parse(value);
}

function positive(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 1;
}

function validTarget(target: RecoveryTarget): boolean {
  return (
    exactKeys(target, TARGET_KEYS) &&
    target.schema === "simulator-target/v1" &&
    target.namespace === "colortrace-simulator" &&
    ["color-resource", "derivative", "frame"].includes(target.kind) &&
    IDENTIFIER.test(target.id)
  );
}

function withoutFields(
  value: object,
  fields: readonly string[],
): Readonly<Record<string, unknown>> {
  const excluded = new Set(fields);
  return Object.fromEntries(Object.entries(value).filter(([key]) => !excluded.has(key)));
}

function validDocumentDigest(
  value: object,
  id: string,
  digest: string,
  prefix: string,
  excluded: readonly string[],
): boolean {
  if (!DIGEST.test(digest)) return false;
  try {
    const expected = `sha256:${canonicalJsonSha256(withoutFields(value, excluded))}`;
    return digest === expected && id === `${prefix}${expected.slice("sha256:".length)}`;
  } catch {
    return false;
  }
}

function cloneJson<T>(value: T): T {
  if (Array.isArray(value)) return value.map((child) => cloneJson(child)) as T;
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, cloneJson(child)]),
    ) as T;
  }
  return value;
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function invalid(problems: Set<RecoveryProjectionProblem>): RecoveryWorkspace {
  const selected = [...problems].sort(compareText);
  return deepFreeze({
    schema: "recovery-workspace/v1",
    integrity: "invalid",
    problems: selected.length === 0 ? ["schema-binding"] : selected,
    review: null,
  });
}

function validateSnapshot(
  snapshot: RecoveryVerificationSnapshot,
  incidentId: string,
  currentIncidentVersion: number,
  problems: Set<RecoveryProjectionProblem>,
): void {
  const outcome = snapshot.action_outcome;
  const publication = snapshot.active_publication;
  if (
    !exactKeys(snapshot, SNAPSHOT_KEYS) ||
    snapshot.schema !== "recovery-verification-snapshot/v1" ||
    !validTimestamp(snapshot.created_at) ||
    !positive(snapshot.incident_version)
  ) {
    problems.add("schema-binding");
  }
  if (
    snapshot.incident_id !== incidentId ||
    snapshot.incident_version !== currentIncidentVersion ||
    outcome.incident_id !== incidentId ||
    outcome.incident_version !== currentIncidentVersion
  ) {
    problems.add("identity-binding");
  }
  if (
    !validDocumentDigest(
      snapshot,
      snapshot.snapshot_id,
      snapshot.snapshot_sha256,
      "recovery-snapshot:",
      ["snapshot_id", "snapshot_sha256"],
    )
  ) {
    problems.add("digest-binding");
  }
  if (
    !validDocumentDigest(
      outcome,
      outcome.outcome_id,
      outcome.outcome_sha256,
      "simulator-action-outcome:",
      ["outcome_id", "outcome_sha256"],
    )
  ) {
    problems.add("digest-binding");
  }
  if (
    outcome.schema !== "simulator-action-outcome/v1" ||
    outcome.status !== "succeeded" ||
    outcome.reason_codes.length !== 0 ||
    !IDENTIFIER.test(outcome.outcome_id) ||
    !IDENTIFIER.test(outcome.action_id) ||
    !DIGEST.test(outcome.outcome_sha256) ||
    !DIGEST.test(outcome.plan_sha256) ||
    !positive(outcome.plan_version) ||
    !validTimestamp(outcome.action_started_at) ||
    !validTimestamp(outcome.completed_at) ||
    outcome.publication_promoted_at === null ||
    !validTimestamp(outcome.publication_promoted_at) ||
    timestamp(outcome.action_started_at) > timestamp(outcome.completed_at)
  ) {
    problems.add("schema-binding");
  }
  if (
    !exactKeys(publication, PUBLICATION_KEYS) ||
    publication.schema !== "recovery-active-publication/v1" ||
    !positive(publication.generation) ||
    !validTimestamp(publication.observed_at) ||
    Object.entries(publication).some(
      ([key, value]) =>
        key.endsWith("_sha256") && (typeof value !== "string" || !DIGEST.test(value)),
    )
  ) {
    problems.add("schema-binding");
  }
  if (
    outcome.active_publication_pointer_sha256 !== publication.pointer_sha256 ||
    outcome.active_runtime_manifest_sha256 !== publication.runtime_manifest_sha256 ||
    outcome.preservation_manifest_sha256 !== publication.preservation_manifest_sha256 ||
    outcome.safe_complement_after_sha256 !== publication.safe_complement_sha256 ||
    outcome.safe_complement_proof_sha256 !== publication.safe_complement_proof_sha256 ||
    timestamp(publication.observed_at) < timestamp(outcome.completed_at)
  ) {
    problems.add("publication-binding");
  }
  if (
    outcome.safe_complement_before_sha256 === null ||
    outcome.safe_complement_after_sha256 === null ||
    outcome.safe_complement_proof_sha256 === null ||
    !DIGEST.test(outcome.safe_complement_before_sha256) ||
    !DIGEST.test(outcome.safe_complement_after_sha256) ||
    !DIGEST.test(outcome.safe_complement_proof_sha256) ||
    outcome.targets.some((target) => !validTarget(target)) ||
    outcome.exclusions.some((target) => !validTarget(target)) ||
    !unique(outcome.new_trace_ids) ||
    outcome.new_trace_ids.some((traceId) => !TRACE_ID.test(traceId))
  ) {
    problems.add("schema-binding");
  }

  const artifacts = snapshot.verification_artifacts;
  const artifactIds = artifacts.map((artifact) => artifact.artifact_id);
  const counts = new Map<RecoveryVerificationArtifact["role"], number>();
  for (const artifact of artifacts) {
    counts.set(artifact.role, (counts.get(artifact.role) ?? 0) + 1);
    if (
      !exactKeys(artifact, ARTIFACT_KEYS) ||
      artifact.schema !== "recovery-verification-artifact/v1" ||
      !IDENTIFIER.test(artifact.artifact_id) ||
      !DIGEST.test(artifact.sha256) ||
      !Number.isSafeInteger(artifact.size) ||
      artifact.size < 0 ||
      artifact.publication_pointer_sha256 !== publication.pointer_sha256 ||
      (artifact.target !== null && !validTarget(artifact.target))
    ) {
      problems.add("schema-binding");
    }
  }
  if (
    artifacts.length !== 15 ||
    !unique(artifactIds) ||
    Object.entries(ARTIFACT_ROLE_COUNTS).some(
      ([role, expected]) => counts.get(role as RecoveryVerificationArtifact["role"]) !== expected,
    )
  ) {
    problems.add("citation-binding");
  }
}

function validateEvidence(
  records: readonly RecoveryEvidenceRecord[],
  snapshot: RecoveryVerificationSnapshot,
  problems: Set<RecoveryProjectionProblem>,
): void {
  const outcome = snapshot.action_outcome;
  const ids = records.map((record) => record.evidence_id);
  if (!unique(ids)) problems.add("citation-binding");
  for (const record of records) {
    if (
      !exactKeys(record, EVIDENCE_KEYS) ||
      !exactKeys(record.correlation, CORRELATION_KEYS) ||
      record.schema !== "recovery-evidence-record/v1" ||
      !RECOVERY_EVIDENCE_ID.test(record.evidence_id) ||
      !DIGEST.test(record.evidence_sha256) ||
      !IDENTIFIER.test(record.event_id) ||
      !IDENTIFIER.test(record.subject_id) ||
      !["log", "metric", "trace"].includes(record.signal) ||
      !["command", "safe"].includes(record.subject_kind) ||
      !["ambiguous", "late", "post-action", "pre-action"].includes(record.freshness) ||
      !validTimestamp(record.observed_at) ||
      !validTimestamp(record.emitted_at) ||
      !validTimestamp(record.retrieved_at) ||
      record.display_excerpt.length > 4096 ||
      record.source_label.length === 0 ||
      record.source_label.length > 128 ||
      (record.trace_id !== null && !TRACE_ID.test(record.trace_id)) ||
      (record.correlation.target !== null && !validTarget(record.correlation.target))
    ) {
      problems.add("schema-binding");
    }
    if (
      record.correlation.incident_id !== snapshot.incident_id ||
      record.correlation.action_id !== outcome.action_id ||
      record.correlation.outcome_id !== outcome.outcome_id ||
      record.correlation.outcome_sha256 !== outcome.outcome_sha256
    ) {
      problems.add("identity-binding");
    }
    const observed = timestamp(record.observed_at);
    const emitted = timestamp(record.emitted_at);
    const retrieved = timestamp(record.retrieved_at);
    const started = timestamp(outcome.action_started_at);
    if (
      observed > emitted ||
      emitted > retrieved ||
      (record.freshness === "post-action" && observed <= started) ||
      (record.freshness === "pre-action" && observed > started)
    ) {
      problems.add("evidence-time-binding");
    }
  }
}

function validateCheckResult(
  result: RecoveryCheckResult,
  expectedCheck: RecoveryCheckName,
  evidenceIds: Set<string>,
  artifactIds: Set<string>,
  problems: Set<RecoveryProjectionProblem>,
): void {
  if (
    !exactKeys(result, CHECK_KEYS) ||
    result.schema !== "recovery-check-result/v1" ||
    result.check !== expectedCheck ||
    result.policy !== `${expectedCheck}/v1` ||
    !DIGEST.test(result.normalized_inputs_sha256) ||
    !unique(result.evidence_ids) ||
    !unique(result.artifact_ids) ||
    !unique(result.reason_codes) ||
    result.reason_codes.some((reason) => !REASON_CODE.test(reason))
  ) {
    problems.add("schema-binding");
  }
  if (
    !validDocumentDigest(result, result.result_id, result.result_sha256, "recovery-check-result:", [
      "result_id",
      "result_sha256",
    ])
  ) {
    problems.add("digest-binding");
  }
  if (
    result.evidence_ids.some((id) => !evidenceIds.has(id)) ||
    result.artifact_ids.some((id) => !artifactIds.has(id))
  ) {
    problems.add("citation-binding");
  }
}

function validatePacket(
  packet: RecoveryPacket,
  snapshot: RecoveryVerificationSnapshot,
  records: readonly RecoveryEvidenceRecord[],
  workflowVersion: number,
  problems: Set<RecoveryProjectionProblem>,
): void {
  const outcome = snapshot.action_outcome;
  if (
    !exactKeys(packet, PACKET_KEYS) ||
    packet.schema !== "recovery-packet/v1" ||
    !positive(packet.workflow_version) ||
    !positive(packet.attempt_number) ||
    !validTimestamp(packet.action_started_at) ||
    !validTimestamp(packet.evaluation_started_at) ||
    !validTimestamp(packet.evaluation_completed_at) ||
    timestamp(packet.evaluation_started_at) > timestamp(packet.evaluation_completed_at)
  ) {
    problems.add("schema-binding");
  }
  if (
    packet.incident_id !== snapshot.incident_id ||
    packet.incident_version !== snapshot.incident_version ||
    packet.snapshot_id !== snapshot.snapshot_id ||
    packet.snapshot_sha256 !== snapshot.snapshot_sha256 ||
    packet.outcome_id !== outcome.outcome_id ||
    packet.outcome_sha256 !== outcome.outcome_sha256 ||
    packet.action_id !== outcome.action_id ||
    packet.action_started_at !== outcome.action_started_at
  ) {
    problems.add("packet-binding");
  }
  if (
    !validDocumentDigest(packet, packet.packet_id, packet.packet_sha256, "recovery-packet:", [
      "packet_id",
      "packet_sha256",
    ])
  ) {
    problems.add("digest-binding");
  }
  const evidenceIds = new Set(records.map((record) => record.evidence_id));
  const artifactIds = new Set(
    snapshot.verification_artifacts.map((artifact) => artifact.artifact_id),
  );
  packet.check_results.forEach((result, index) => {
    const expected = RECOVERY_CHECKS[index];
    if (expected === undefined) problems.add("status-binding");
    else validateCheckResult(result, expected, evidenceIds, artifactIds, problems);
  });
  const allCheckEvidence = sortedUnique(
    packet.check_results.flatMap((result) => [...result.evidence_ids]),
  );
  if (
    packet.check_results.length !== RECOVERY_CHECKS.length ||
    !sameStrings(packet.evidence_ids, allCheckEvidence) ||
    !sameStrings(
      packet.evidence_ids,
      records.map((record) => record.evidence_id),
    ) ||
    packet.workflow_version > workflowVersion
  ) {
    problems.add("citation-binding");
  }
  const states = packet.check_results.map((result) => result.state);
  const expectedStatus = states.includes("failed")
    ? "recovery_failed"
    : states.includes("unresolved")
      ? "recovery_unresolved"
      : "recovery_verified";
  const expectedFailures = packet.check_results
    .filter((result) => result.state === "failed")
    .map((result) => ({ check: result.check, reason_codes: [...result.reason_codes] }));
  const expectedUnresolved = packet.check_results
    .filter((result) => result.state === "unresolved")
    .map((result) => ({ check: result.check, reason_codes: [...result.reason_codes] }));
  const itemsMatch = (
    actual: readonly {
      readonly check: RecoveryCheckName;
      readonly reason_codes: readonly string[];
    }[],
    expected: readonly {
      readonly check: RecoveryCheckName;
      readonly reason_codes: readonly string[];
    }[],
  ) =>
    actual.length === expected.length &&
    actual.every(
      (item, index) =>
        exactKeys(item, PACKET_ITEM_KEYS) &&
        item.check === expected[index]?.check &&
        sameStrings(item.reason_codes, expected[index]?.reason_codes ?? []),
    );
  if (
    packet.status !== expectedStatus ||
    packet.eligible_for_closure !== (expectedStatus === "recovery_verified") ||
    !itemsMatch(packet.failure_items, expectedFailures) ||
    !itemsMatch(packet.unresolved_items, expectedUnresolved) ||
    (packet.supersedes_packet_id === null) !== (packet.supersedes_packet_sha256 === null) ||
    (packet.supersedes_packet_id !== null && !IDENTIFIER.test(packet.supersedes_packet_id)) ||
    (packet.supersedes_packet_sha256 !== null && !DIGEST.test(packet.supersedes_packet_sha256))
  ) {
    problems.add("status-binding");
  }
  if (
    packet.status === "recovery_verified" &&
    (records.some((record) => {
      const observed = timestamp(record.observed_at);
      const emitted = timestamp(record.emitted_at);
      const retrieved = timestamp(record.retrieved_at);
      const actionStarted = timestamp(packet.action_started_at);
      const evaluationStarted = timestamp(packet.evaluation_started_at);
      const evaluationCompleted = timestamp(packet.evaluation_completed_at);
      return (
        record.freshness !== "post-action" ||
        observed <= actionStarted ||
        emitted <= actionStarted ||
        retrieved < evaluationStarted ||
        retrieved > evaluationCompleted ||
        evaluationCompleted - retrieved > 60_000
      );
    }) ||
      outcome.safe_complement_before_sha256 !== outcome.safe_complement_after_sha256)
  ) {
    problems.add("status-binding");
  }
}

function validateClosure(
  closure: RecoveryClosureResult,
  packet: RecoveryPacket,
  workflowId: string,
  workflowVersion: number,
  problems: Set<RecoveryProjectionProblem>,
): void {
  if (
    !exactKeys(closure, CLOSURE_KEYS) ||
    !exactKeys(closure.actor, CLOSURE_ACTOR_KEYS) ||
    closure.schema !== "recovery-closure-result/v1" ||
    closure.actor.kind !== "human" ||
    closure.authorized_role !== "recovery.closer" ||
    closure.reason.trim() !== closure.reason ||
    closure.reason.length === 0 ||
    closure.reason.length > 512 ||
    !validTimestamp(closure.closed_at) ||
    !IDEMPOTENCY_KEY.test(closure.idempotency_key)
  ) {
    problems.add("schema-binding");
  }
  if (
    closure.incident_id !== packet.incident_id ||
    closure.workflow_id !== workflowId ||
    closure.workflow_version_before !== packet.workflow_version ||
    closure.workflow_version_after !== closure.workflow_version_before + 1 ||
    closure.workflow_version_after !== workflowVersion ||
    closure.packet_id !== packet.packet_id ||
    closure.packet_sha256 !== packet.packet_sha256 ||
    closure.outcome_id !== packet.outcome_id ||
    closure.outcome_sha256 !== packet.outcome_sha256
  ) {
    problems.add("closure-binding");
  }
  if (
    !validDocumentDigest(closure, closure.closure_id, closure.closure_sha256, "recovery-closure:", [
      "closure_id",
      "closure_sha256",
    ])
  ) {
    problems.add("digest-binding");
  }
}

function validateAudit(
  events: readonly RecoveryAuditEvent[],
  snapshot: RecoveryVerificationSnapshot,
  packet: RecoveryPacket | null,
  closure: RecoveryClosureResult | null,
  problems: Set<RecoveryProjectionProblem>,
): string | null {
  if (events.length === 0) {
    problems.add("audit-binding");
    return null;
  }
  const workflowId = events[0]?.workflow_id ?? null;
  let predecessor: string | null = null;
  for (const [index, event] of events.entries()) {
    const verificationEvent = [
      "verification.claimed",
      "verification.completed",
      "verification.reclaimed",
      "verification.requested",
    ].includes(event.event_type);
    const closureEvent = event.event_type === "recovery.closed";
    if (
      !exactKeys(event, AUDIT_KEYS) ||
      !exactKeys(event.actor, AUDIT_ACTOR_KEYS) ||
      event.schema !== "recovery-audit-event/v1" ||
      (!verificationEvent && !closureEvent) ||
      (verificationEvent &&
        (event.actor.kind !== "service" || event.actor.authorized_role !== "recovery.verifier")) ||
      (closureEvent &&
        (event.actor.kind !== "human" || event.actor.authorized_role !== "recovery.closer")) ||
      event.sequence !== index + 1 ||
      event.workflow_id !== workflowId ||
      event.predecessor_event_sha256 !== predecessor ||
      event.incident_id !== snapshot.incident_id ||
      event.snapshot_id !== snapshot.snapshot_id ||
      event.snapshot_sha256 !== snapshot.snapshot_sha256 ||
      event.outcome_id !== snapshot.action_outcome.outcome_id ||
      event.outcome_sha256 !== snapshot.action_outcome.outcome_sha256 ||
      !validTimestamp(event.occurred_at) ||
      !IDEMPOTENCY_KEY.test(event.idempotency_key) ||
      (event.packet_id === null) !== (event.packet_sha256 === null)
    ) {
      problems.add("audit-binding");
    }
    if (
      !validDocumentDigest(event, event.event_id, event.event_sha256, "recovery-audit-event:", [
        "event_id",
        "event_sha256",
      ])
    ) {
      problems.add("digest-binding");
    }
    predecessor = event.event_sha256;
  }
  const last = events.at(-1);
  if (closure !== null) {
    if (
      last?.event_type !== "recovery.closed" ||
      last.event_id !== closure.audit_event_id ||
      last.event_sha256 !== closure.audit_event_sha256 ||
      last.packet_id !== closure.packet_id ||
      last.packet_sha256 !== closure.packet_sha256 ||
      last.actor.kind !== "human" ||
      last.actor.authorized_role !== "recovery.closer" ||
      last.actor.issuer !== closure.actor.issuer ||
      last.actor.subject !== closure.actor.subject ||
      last.actor.audience !== closure.actor.audience ||
      last.actor.display_name !== closure.actor.display_name ||
      last.idempotency_key !== closure.idempotency_key ||
      last.occurred_at !== closure.closed_at ||
      last.details.reason !== closure.reason ||
      last.details.workflow_version_before !== closure.workflow_version_before ||
      last.details.workflow_version_after !== closure.workflow_version_after
    ) {
      problems.add("audit-binding");
    }
  } else if (packet !== null) {
    const completion = [...events]
      .reverse()
      .find((event) => event.event_type === "verification.completed");
    if (
      completion?.packet_id !== packet.packet_id ||
      completion.packet_sha256 !== packet.packet_sha256
    ) {
      problems.add("audit-binding");
    }
  }
  return workflowId;
}

export function projectRecoveryReview(
  input: RecoveryReviewProjectionInput,
  incidentId: string,
): RecoveryWorkspace {
  const problems = new Set<RecoveryProjectionProblem>();
  if (
    !exactKeys(input, REVIEW_KEYS) ||
    input.schema !== "recovery-review/v1" ||
    !IDENTIFIER.test(incidentId) ||
    !positive(input.current_incident_version) ||
    !positive(input.workflow_version)
  ) {
    problems.add("schema-binding");
  }

  validateSnapshot(input.snapshot, incidentId, input.current_incident_version, problems);
  validateEvidence(input.evidence_records, input.snapshot, problems);
  if (input.packet !== null) {
    validatePacket(
      input.packet,
      input.snapshot,
      input.evidence_records,
      input.workflow_version,
      problems,
    );
  }
  const workflowId = validateAudit(
    input.audit_events,
    input.snapshot,
    input.packet,
    input.closure,
    problems,
  );

  if (input.packet === null) {
    if (
      !["verification_pending", "verification_running"].includes(input.state) ||
      input.closure !== null ||
      input.evidence_records.length > 0
    ) {
      problems.add("status-binding");
    }
  } else if (input.state === "closed") {
    if (
      input.packet.status !== "recovery_verified" ||
      !input.packet.eligible_for_closure ||
      input.closure === null ||
      workflowId === null
    ) {
      problems.add("status-binding");
    } else {
      validateClosure(input.closure, input.packet, workflowId, input.workflow_version, problems);
    }
  } else if (
    input.closure !== null ||
    input.state !== input.packet.status ||
    input.packet.workflow_version !== input.workflow_version ||
    (workflowId !== null && input.packet.workflow_id !== workflowId)
  ) {
    problems.add("status-binding");
  }

  if (problems.size > 0) return invalid(problems);

  const selected = cloneJson(input);
  const review: RecoveryReviewProjectionInput = {
    ...selected,
    evidence_records: [...selected.evidence_records].sort((left, right) =>
      compareText(left.evidence_id, right.evidence_id),
    ),
    audit_events: [...selected.audit_events].sort((left, right) => left.sequence - right.sequence),
    snapshot: {
      ...selected.snapshot,
      verification_artifacts: [...selected.snapshot.verification_artifacts].sort((left, right) =>
        compareText(left.artifact_id, right.artifact_id),
      ),
    },
  };
  return deepFreeze({
    schema: "recovery-workspace/v1",
    integrity: "verified",
    problems: [],
    review,
  });
}
