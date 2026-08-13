import type {
  ClaimState,
  EvidenceAvailability,
  IncidentReplayProjectionInput,
  InvestigationWorkspace,
  ProjectionModelInvocation,
  ProjectionScopeState,
  ProjectionValidatorResult,
  WorkspaceAdverseState,
  WorkspaceAdverseStateCode,
  WorkspaceCitation,
  WorkspaceCitationNamespace,
  WorkspaceClaim,
  WorkspaceDerivativeScopeNode,
  WorkspaceDeterministicDerivationEvidence,
  WorkspaceEvidence,
  WorkspaceFrameScopeNode,
  WorkspaceLimitation,
  WorkspaceProviderEvidence,
  WorkspaceScopeEdge,
  WorkspaceScopeGraph,
  WorkspaceScopeNode,
  WorkspaceScopeParity,
  WorkspaceState,
  WorkspaceTimelineCategory,
  WorkspaceTimelineEntry,
  WorkspaceTimelineStatus,
  WorkspaceValidatorArtifactEvidence,
} from "./types.ts";
import { canonicalJsonSha256 } from "./canonical-sha256.ts";

const categoryRank: Readonly<Record<WorkspaceTimelineCategory, number>> = {
  "source-observation": 0,
  "model-reasoning": 1,
  "deterministic-result": 2,
  "workflow-event": 3,
  "human-event": 4,
};

const evidenceKindRank: Readonly<Record<WorkspaceEvidence["kind"], number>> = {
  provider: 0,
  "validator-artifact": 1,
  "deterministic-derivation": 2,
};

const scopeClassificationRank: Readonly<Record<WorkspaceScopeNode["classification"], number>> = {
  causal: 0,
  affected: 1,
  safe: 2,
  unknown: 3,
};

const scopeKindRank: Readonly<Record<WorkspaceScopeNode["kind"], number>> = {
  resource: 0,
  frame: 1,
  derivative: 2,
};

function compareText(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].sort(compareText);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  const normalizedLeft = sortedUnique(left);
  const normalizedRight = sortedUnique(right);
  return (
    normalizedLeft.length === normalizedRight.length &&
    normalizedLeft.every((value, index) => value === normalizedRight[index])
  );
}

function hasExactKeys(value: object, expected: readonly string[]): boolean {
  return sameStrings(Object.keys(value), expected);
}

function citation(namespace: WorkspaceCitationNamespace, id: string): WorkspaceCitation {
  return { namespace, id };
}

function sortCitations(values: Iterable<WorkspaceCitation>): WorkspaceCitation[] {
  const unique = new Map<string, WorkspaceCitation>();
  for (const value of values) unique.set(`${value.namespace}\u0000${value.id}`, value);
  return [...unique.values()].sort(
    (left, right) => compareText(left.namespace, right.namespace) || compareText(left.id, right.id),
  );
}

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function evidenceAvailability(
  collection: "collected" | "error",
  freshness: "current" | "stale" | "unresolved",
): EvidenceAvailability {
  if (collection === "error") return "error";
  if (freshness === "stale") return "stale";
  if (freshness === "unresolved") return "unresolved";
  return "available";
}

function timelineStatusForInvocation(
  resultClass: ProjectionModelInvocation["result_class"],
): WorkspaceTimelineStatus {
  if (resultClass === "accepted") return "succeeded";
  if (resultClass === "budget-rejected") return "unresolved";
  return "failed";
}

function timelineStatusForTrace(
  eventType: string,
  payload: Readonly<Record<string, unknown>>,
): WorkspaceTimelineStatus {
  if (payload.status === "unresolved") return "unresolved";
  if (eventType === "incident.completed" || eventType === "packet.persisted") return "succeeded";
  return "informational";
}

function validTimestamp(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function compareTimeline(left: WorkspaceTimelineEntry, right: WorkspaceTimelineEntry): number {
  const leftTime = left.timestamp === null ? Number.POSITIVE_INFINITY : Date.parse(left.timestamp);
  const rightTime =
    right.timestamp === null ? Number.POSITIVE_INFINITY : Date.parse(right.timestamp);
  const normalizedLeft = Number.isFinite(leftTime) ? leftTime : Number.POSITIVE_INFINITY;
  const normalizedRight = Number.isFinite(rightTime) ? rightTime : Number.POSITIVE_INFINITY;
  return (
    normalizedLeft - normalizedRight ||
    categoryRank[left.category] - categoryRank[right.category] ||
    compareText(left.id, right.id)
  );
}

function compareEvidence(left: WorkspaceEvidence, right: WorkspaceEvidence): number {
  return (
    evidenceKindRank[left.kind] - evidenceKindRank[right.kind] ||
    compareText(left.evidence_id, right.evidence_id) ||
    compareText(left.workspace_id, right.workspace_id)
  );
}

function compareScopeNode(left: WorkspaceScopeNode, right: WorkspaceScopeNode): number {
  return (
    scopeClassificationRank[left.classification] - scopeClassificationRank[right.classification] ||
    scopeKindRank[left.kind] - scopeKindRank[right.kind] ||
    compareText(left.id, right.id)
  );
}

function identityProblems(input: IncidentReplayProjectionInput): string[] {
  const incidentId = input.incident.incident_id;
  const traceId = input.incident.trace_id;
  const problems: string[] = [];
  if (
    input.task.incident_id !== incidentId ||
    input.alert.incident_id !== incidentId ||
    input.packet.incident_id !== incidentId
  ) {
    problems.push("incident-id-binding");
  }
  if (
    input.incident.alert_id !== input.alert.alert_id ||
    input.incident.alert_sha256 !== input.task.alert_sha256
  ) {
    problems.push("alert-binding");
  }
  if (
    input.incident.packet_id !== input.packet.packet_id ||
    input.task.packet_id !== input.packet.packet_id
  ) {
    problems.push("packet-binding");
  }
  if (input.task.trace_id !== traceId || input.alert.correlation_keys.trace_id !== traceId) {
    problems.push("trace-binding");
  }
  if (input.evidence.some((item) => item.incident_id !== incidentId)) {
    problems.push("evidence-incident-binding");
  }
  if (input.validator_results.some((item) => item.incident_id !== incidentId)) {
    problems.push("validator-incident-binding");
  }
  if (
    input.invocations.some((item) => item.incident_id !== incidentId || item.trace_id !== traceId)
  ) {
    problems.push("invocation-binding");
  }
  if (
    input.trace_events.some((item) => item.incident_id !== incidentId || item.trace_id !== traceId)
  ) {
    problems.push("trace-event-binding");
  }
  const humanEvents = [...(input.human_events ?? [])].sort(
    (left, right) => left.sequence - right.sequence,
  );
  const traceEventIds = new Set(input.trace_events.map((event) => event.event_id));
  let humanPredecessor: string | null = null;
  for (const [index, event] of humanEvents.entries()) {
    const digestSuffix = event.event_sha256.match(/^sha256:([0-9a-f]{64})$/u)?.[1];
    const body = {
      schema: event.schema,
      incident_id: event.incident_id,
      sequence: event.sequence,
      event_type: event.event_type,
      actor: event.actor,
      predecessor_event_sha256: event.predecessor_event_sha256,
      occurred_at: event.occurred_at,
      citations: event.citations,
    };
    let expectedDigest: string | null = null;
    try {
      expectedDigest = `sha256:${canonicalJsonSha256(body)}`;
    } catch {
      expectedDigest = null;
    }
    if (
      !hasExactKeys(event, [
        "schema",
        "event_id",
        "incident_id",
        "sequence",
        "event_type",
        "actor",
        "predecessor_event_sha256",
        "occurred_at",
        "citations",
        "event_sha256",
      ]) ||
      !hasExactKeys(event.actor, [
        "subject",
        "display_name",
        "issuer",
        "audience",
        "principal_kind",
      ]) ||
      event.schema !== "incident-human-audit-event/v1" ||
      event.incident_id !== incidentId ||
      event.sequence !== index + 1 ||
      event.event_type !== "incident.admitted" ||
      event.predecessor_event_sha256 !== humanPredecessor ||
      digestSuffix === undefined ||
      event.event_sha256 !== expectedDigest ||
      event.event_id !== `human-audit-event:${digestSuffix}` ||
      event.actor.principal_kind !== "human" ||
      event.actor.subject.length === 0 ||
      event.actor.display_name.length === 0 ||
      event.actor.issuer.length === 0 ||
      event.actor.audience.length === 0 ||
      event.citations.some(
        (value) =>
          !hasExactKeys(value, ["namespace", "id"]) ||
          value.namespace !== "trace-event" ||
          !traceEventIds.has(value.id),
      )
    ) {
      problems.push("human-audit-event-binding");
      break;
    }
    humanPredecessor = event.event_sha256;
  }
  if (
    input.invocations.length !== input.packet.invocation_records.length ||
    input.invocations.some(
      (item, index) => item.invocation_id !== input.packet.invocation_records[index]?.invocation_id,
    )
  ) {
    problems.push("packet-invocation-binding");
  }
  return sortedUnique(problems);
}

type EvidenceDraft = WorkspaceEvidence & { readonly supporting_ids?: readonly string[] };

function buildEvidenceDrafts(input: IncidentReplayProjectionInput): EvidenceDraft[] {
  const items: EvidenceDraft[] = [];
  for (const envelope of input.evidence) {
    let timestamp = envelope.timing.retrieved_at;
    let timeBasis: WorkspaceProviderEvidence["time_basis"] = "retrieved-at";
    if (envelope.timing.event_time !== null) {
      timestamp = envelope.timing.event_time;
      timeBasis = "event-time";
    } else if (envelope.timing.source_time !== null) {
      timestamp = envelope.timing.source_time;
      timeBasis = "source-time";
    }
    const provider: WorkspaceProviderEvidence = {
      kind: "provider",
      workspace_id: `provider:${envelope.evidence_id}`,
      evidence_id: envelope.evidence_id,
      availability: evidenceAvailability(envelope.collection.outcome, envelope.timing.freshness),
      incident_id: envelope.incident_id,
      source_kind: envelope.source.kind,
      tool: envelope.source.tool ?? null,
      observation_kind: envelope.observation.kind,
      query_key: envelope.observation.query_key ?? null,
      content_sha256: envelope.content_sha256,
      display_excerpt: envelope.display_excerpt,
      timestamp,
      time_basis: timeBasis,
      error_code: envelope.collection.error?.code ?? null,
      citations: [citation("provider-evidence", envelope.evidence_id)],
    };
    items.push(provider);
  }
  for (const result of input.validator_results) {
    for (const artifact of result.evidence) {
      const projected: WorkspaceValidatorArtifactEvidence = {
        kind: "validator-artifact",
        workspace_id: `validator-artifact:${result.result_id}:${artifact.evidence_id}`,
        evidence_id: artifact.evidence_id,
        availability: "available",
        validator_result_id: result.result_id,
        artifact_kind: artifact.kind,
        path: artifact.path,
        content_sha256: artifact.sha256,
        citations: [citation("validator-artifact", artifact.evidence_id)],
      };
      items.push(projected);
    }
  }
  for (const result of input.packet.deterministic_results) {
    const projected: EvidenceDraft = {
      kind: "deterministic-derivation",
      workspace_id: `deterministic-derivation:${result.result_id}`,
      evidence_id: result.result_id,
      availability: result.status === "resolved" ? "available" : "unresolved",
      validator_result_id: result.result_id,
      claim_id: null,
      policy_versions: { ...result.policy_versions },
      derivation_sha256: result.derivation_sha256,
      citations: [],
      supporting_ids: result.evidence_ids,
    };
    items.push(projected);
  }
  for (const claim of input.packet.claims) {
    if (claim.deterministic_result_evidence_id === null) continue;
    const projected: EvidenceDraft = {
      kind: "deterministic-derivation",
      workspace_id: `deterministic-derivation:${claim.deterministic_result_evidence_id}`,
      evidence_id: claim.deterministic_result_evidence_id,
      availability:
        claim.state === "confirmed" || claim.state === "rejected" ? "available" : "unresolved",
      validator_result_id: claim.source_validator_result_id,
      claim_id: claim.claim_id,
      policy_versions: { claim: claim.policy },
      derivation_sha256: claim.derivation_sha256,
      citations: [],
      supporting_ids: claim.evidence_ids,
    };
    items.push(projected);
  }
  return items;
}

function evidenceNamespaces(
  drafts: readonly EvidenceDraft[],
): Map<string, Set<WorkspaceCitationNamespace>> {
  const namespaces = new Map<string, Set<WorkspaceCitationNamespace>>();
  for (const item of drafts) {
    const namespace: WorkspaceCitationNamespace =
      item.kind === "provider"
        ? "provider-evidence"
        : item.kind === "validator-artifact"
          ? "validator-artifact"
          : "deterministic-derivation";
    const existing = namespaces.get(item.evidence_id) ?? new Set<WorkspaceCitationNamespace>();
    existing.add(namespace);
    namespaces.set(item.evidence_id, existing);
  }
  return namespaces;
}

function citationsForIds(
  identifiers: Iterable<string>,
  namespaces: ReadonlyMap<string, ReadonlySet<WorkspaceCitationNamespace>>,
): WorkspaceCitation[] {
  const values: WorkspaceCitation[] = [];
  for (const identifier of identifiers) {
    const matches = namespaces.get(identifier);
    if (matches === undefined || matches.size === 0) {
      values.push(citation("provider-evidence", identifier));
      continue;
    }
    for (const namespace of matches) values.push(citation(namespace, identifier));
  }
  return sortCitations(values);
}

function finalizeEvidence(
  drafts: readonly EvidenceDraft[],
  namespaces: ReadonlyMap<string, ReadonlySet<WorkspaceCitationNamespace>>,
): WorkspaceEvidence[] {
  return drafts
    .map((draft): WorkspaceEvidence => {
      if (draft.kind !== "deterministic-derivation") return draft;
      const supportingIds = draft.supporting_ids ?? [];
      const value: WorkspaceDeterministicDerivationEvidence = {
        kind: draft.kind,
        workspace_id: draft.workspace_id,
        evidence_id: draft.evidence_id,
        availability: draft.availability,
        validator_result_id: draft.validator_result_id,
        claim_id: draft.claim_id,
        policy_versions: draft.policy_versions,
        derivation_sha256: draft.derivation_sha256,
        citations: citationsForIds(supportingIds, namespaces),
      };
      return value;
    })
    .sort(compareEvidence);
}

function referencedEvidenceIds(input: IncidentReplayProjectionInput): string[] {
  const identifiers: string[] = [...input.packet.evidence_ids];
  for (const result of input.packet.deterministic_results) identifiers.push(...result.evidence_ids);
  for (const claim of input.packet.claims) {
    identifiers.push(...claim.evidence_ids);
    if (claim.deterministic_result_evidence_id !== null) {
      identifiers.push(claim.deterministic_result_evidence_id);
    }
  }
  for (const invocation of input.invocations) identifiers.push(...invocation.input_evidence_ids);
  for (const unresolved of input.packet.unresolved_items) {
    identifiers.push(...unresolved.evidence_ids);
  }
  for (const result of input.validator_results) {
    for (const frame of result.scope.frames) identifiers.push(...frame.evidence_ids);
    for (const derivative of result.scope.derivatives) identifiers.push(...derivative.evidence_ids);
    for (const claim of result.claims) {
      identifiers.push(...claim.evidence_ids, claim.deterministic_result_evidence_id);
    }
  }
  return sortedUnique(identifiers);
}

type NormalizedValidatorScope = {
  readonly frames: ReadonlyMap<string, WorkspaceFrameScopeNode>;
  readonly derivatives: ReadonlyMap<string, WorkspaceDerivativeScopeNode>;
  readonly causalResource: string | null;
  readonly reasons: readonly string[];
};

function packetScopeSets(input: IncidentReplayProjectionInput): {
  readonly sets: Readonly<Record<ProjectionScopeState, readonly string[]>>;
  readonly reasons: readonly string[];
} {
  const reasons: string[] = [];
  const ownership = new Map<string, ProjectionScopeState>();
  const result: Record<ProjectionScopeState, string[]> = {
    affected: [],
    safe: [],
    unknown: [],
  };
  for (const state of ["affected", "safe", "unknown"] as const) {
    for (const item of input.packet.scope[state]) {
      const key = `${item.kind}:${item.id}`;
      if (ownership.has(key)) reasons.push("packet-scope-identity-duplicate");
      ownership.set(key, state);
      result[state].push(key);
    }
    result[state] = sortedUnique(result[state]);
  }
  return { sets: result, reasons: sortedUnique(reasons) };
}

function normalizeValidatorScope(
  results: readonly ProjectionValidatorResult[],
  namespaces: ReadonlyMap<string, ReadonlySet<WorkspaceCitationNamespace>>,
): NormalizedValidatorScope {
  const frames = new Map<string, WorkspaceFrameScopeNode>();
  const derivatives = new Map<string, WorkspaceDerivativeScopeNode>();
  const reasons: string[] = [];
  let causalResource: string | null = null;
  for (const result of results) {
    if (result.scope.causal_resource_sha256 !== null) {
      if (causalResource !== null && causalResource !== result.scope.causal_resource_sha256) {
        reasons.push("validator-causal-resource-conflict");
      }
      causalResource = result.scope.causal_resource_sha256;
    }
    for (const frame of result.scope.frames) {
      if (frame.frame_id === null) {
        reasons.push("validator-frame-identity-missing");
        continue;
      }
      const key = `frame:${frame.frame_id}`;
      const node: WorkspaceFrameScopeNode = {
        key,
        kind: "frame",
        id: frame.frame_id,
        classification: frame.state,
        job_id: frame.job_id,
        output_id: frame.output_id,
        worker_id: frame.worker_id,
        safe_on_implicated_worker: false,
        reason_codes: sortedUnique(frame.reason_codes),
        citations: citationsForIds(frame.evidence_ids, namespaces),
      };
      const previous = frames.get(key);
      if (previous !== undefined) {
        reasons.push("validator-frame-identity-duplicate");
        if (
          previous.classification !== node.classification ||
          previous.job_id !== node.job_id ||
          previous.output_id !== node.output_id ||
          previous.worker_id !== node.worker_id
        ) {
          reasons.push("validator-frame-identity-conflict");
        }
      } else {
        frames.set(key, node);
      }
      if (frame.state === "affected" && frame.evidence_ids.length === 0) {
        reasons.push("validator-scope-citation-missing");
      }
    }
    for (const derivative of result.scope.derivatives) {
      const key = `derivative:${derivative.artifact_id}`;
      const node: WorkspaceDerivativeScopeNode = {
        key,
        kind: "derivative",
        id: derivative.artifact_id,
        classification: derivative.state,
        parent_artifact_id: derivative.parent_artifact_id,
        reason_codes: sortedUnique(derivative.reason_codes),
        citations: citationsForIds(derivative.evidence_ids, namespaces),
      };
      const previous = derivatives.get(key);
      if (previous !== undefined) {
        reasons.push("validator-derivative-identity-duplicate");
        if (
          previous.classification !== node.classification ||
          previous.parent_artifact_id !== node.parent_artifact_id
        ) {
          reasons.push("validator-derivative-identity-conflict");
        }
      } else {
        derivatives.set(key, node);
      }
      if (
        derivative.state === "affected" &&
        (derivative.parent_artifact_id === null || derivative.evidence_ids.length === 0)
      ) {
        reasons.push("validator-lineage-binding-missing");
      }
    }
  }
  const implicatedWorkers = new Set(
    [...frames.values()]
      .filter((node) => node.classification === "affected" && node.worker_id !== null)
      .map((node) => node.worker_id),
  );
  for (const [key, frame] of frames) {
    if (
      frame.classification === "safe" &&
      frame.worker_id !== null &&
      implicatedWorkers.has(frame.worker_id)
    ) {
      frames.set(key, { ...frame, safe_on_implicated_worker: true });
    }
  }
  if (
    [...frames.values(), ...derivatives.values()].some(
      (node) => node.classification === "affected",
    ) &&
    causalResource === null
  ) {
    reasons.push("validator-causal-resource-missing");
  }
  const outputIds = new Set(
    [...frames.values()]
      .map((frame) => frame.output_id)
      .filter((outputId): outputId is string => outputId !== null),
  );
  if (
    [...derivatives.values()].some(
      (derivative) =>
        derivative.classification === "affected" &&
        (derivative.parent_artifact_id === null || !outputIds.has(derivative.parent_artifact_id)),
    )
  ) {
    reasons.push("validator-lineage-parent-missing");
  }
  return { frames, derivatives, causalResource, reasons: sortedUnique(reasons) };
}

function scopeParity(
  input: IncidentReplayProjectionInput,
  normalized: NormalizedValidatorScope,
): WorkspaceScopeParity {
  const packet = packetScopeSets(input);
  const reasons = [...packet.reasons, ...normalized.reasons];
  const packetResultIds = input.packet.deterministic_results.map((item) => item.result_id);
  const validatorResultIds = input.validator_results.map((item) => item.result_id);
  if (packetResultIds.length === 0 && validatorResultIds.length === 0) {
    if (
      input.packet.status === "unresolved" &&
      packet.sets.affected.length === 0 &&
      packet.sets.safe.length === 0
    ) {
      return {
        status: "not-verifiable",
        reason_codes: sortedUnique([...reasons, "validator-scope-unavailable"]),
      };
    }
    reasons.push("validator-result-missing");
  } else if (!sameStrings(packetResultIds, validatorResultIds)) {
    reasons.push("validator-result-identity-mismatch");
  }
  const validatorSets: Record<ProjectionScopeState, string[]> = {
    affected: [],
    safe: [],
    unknown: [],
  };
  for (const node of [...normalized.frames.values(), ...normalized.derivatives.values()]) {
    validatorSets[node.classification].push(node.key);
  }
  for (const state of ["affected", "safe", "unknown"] as const) {
    if (!sameStrings(packet.sets[state], validatorSets[state])) {
      reasons.push(`scope-${state}-identity-mismatch`);
    }
  }
  for (const result of input.validator_results) {
    const packetResult = input.packet.deterministic_results.find(
      (candidate) => candidate.result_id === result.result_id,
    );
    if (
      packetResult === undefined ||
      packetResult.status !== result.status ||
      packetResult.derivation_sha256 !== result.derivation_sha256
    ) {
      reasons.push("validator-result-binding-mismatch");
    }
    if (
      result.scope.policy !== input.packet.scope.policy ||
      result.policies.scope !== input.packet.scope.policy
    ) {
      reasons.push("scope-policy-mismatch");
    }
  }
  if (input.validator_results.some((result) => result.scope.state !== input.packet.scope.state)) {
    reasons.push("scope-state-mismatch");
  }
  return {
    status: reasons.length === 0 ? "verified" : "failed",
    reason_codes: sortedUnique(reasons),
  };
}

function invalidScope(policy: string, parity: WorkspaceScopeParity): WorkspaceScopeGraph {
  return { state: "invalid", policy, parity, nodes: [], edges: [] };
}

function unresolvedPacketNodes(input: IncidentReplayProjectionInput): WorkspaceScopeNode[] {
  return input.packet.scope.unknown
    .map((item): WorkspaceScopeNode => {
      if (item.kind === "frame") {
        return {
          key: `frame:${item.id}`,
          kind: "frame",
          id: item.id,
          classification: "unknown",
          job_id: item.id,
          output_id: null,
          worker_id: null,
          safe_on_implicated_worker: false,
          reason_codes: sortedUnique(input.packet.scope.reason_codes),
          citations: [],
        };
      }
      return {
        key: `derivative:${item.id}`,
        kind: "derivative",
        id: item.id,
        classification: "unknown",
        parent_artifact_id: null,
        reason_codes: sortedUnique(input.packet.scope.reason_codes),
        citations: [],
      };
    })
    .sort(compareScopeNode);
}

function buildScope(
  input: IncidentReplayProjectionInput,
  normalized: NormalizedValidatorScope,
  parity: WorkspaceScopeParity,
  forceInvalid: boolean,
): WorkspaceScopeGraph {
  if (forceInvalid || parity.status === "failed")
    return invalidScope(input.packet.scope.policy, parity);
  if (parity.status === "not-verifiable") {
    return {
      state: "unresolved",
      policy: input.packet.scope.policy,
      parity,
      nodes: unresolvedPacketNodes(input),
      edges: [],
    };
  }
  const nodes: WorkspaceScopeNode[] = [
    ...normalized.frames.values(),
    ...normalized.derivatives.values(),
  ];
  const resourceKey =
    normalized.causalResource === null ? null : `resource:${normalized.causalResource}`;
  if (normalized.causalResource !== null) {
    nodes.push({
      key: resourceKey as string,
      kind: "resource",
      id: normalized.causalResource,
      classification: "causal",
      reason_codes: ["causal-resource-confirmed"],
      citations: sortCitations(
        [...normalized.frames.values()]
          .filter((node) => node.classification === "affected")
          .flatMap((node) => node.citations),
      ),
    });
  }
  const edges: WorkspaceScopeEdge[] = [];
  if (resourceKey !== null) {
    for (const frame of normalized.frames.values()) {
      if (frame.classification !== "affected") continue;
      edges.push({
        id: `causal-scope:${normalized.causalResource}:${frame.id}`,
        kind: "causal-scope",
        from: resourceKey,
        to: frame.key,
        policy: input.packet.scope.policy,
        citations: frame.citations,
      });
    }
  }
  const outputToFrame = new Map<string, string>();
  for (const frame of normalized.frames.values()) {
    if (frame.output_id !== null) outputToFrame.set(frame.output_id, frame.key);
  }
  for (const derivative of normalized.derivatives.values()) {
    if (derivative.parent_artifact_id === null) continue;
    const parent = outputToFrame.get(derivative.parent_artifact_id);
    if (parent === undefined) continue;
    edges.push({
      id: `lineage:${derivative.parent_artifact_id}:${derivative.id}`,
      kind: "lineage",
      from: parent,
      to: derivative.key,
      policy: "exact-typed-lineage/v1",
      citations: derivative.citations,
    });
  }
  return {
    state: input.packet.scope.state === "resolved" ? "resolved" : "unresolved",
    policy: input.packet.scope.policy,
    parity,
    nodes: nodes.sort(compareScopeNode),
    edges: edges.sort(
      (left, right) => compareText(left.kind, right.kind) || compareText(left.id, right.id),
    ),
  };
}

function buildClaims(
  input: IncidentReplayProjectionInput,
  namespaces: ReadonlyMap<string, ReadonlySet<WorkspaceCitationNamespace>>,
): WorkspaceClaim[] {
  const finalizedAt = validTimestamp(input.packet.finalized_at) ? input.packet.finalized_at : null;
  return input.packet.claims
    .map((claim): WorkspaceClaim => {
      const citations = citationsForIds(
        claim.deterministic_result_evidence_id === null
          ? claim.evidence_ids
          : [...claim.evidence_ids, claim.deterministic_result_evidence_id],
        namespaces,
      );
      if (claim.source_validator_result_id !== null) {
        citations.push(citation("deterministic-derivation", claim.source_validator_result_id));
      }
      return {
        id: claim.claim_id,
        type: claim.claim_type,
        subject_kind: claim.subject.kind,
        subject_value: claim.subject.value,
        state: claim.state,
        policy: claim.policy,
        reason_codes: sortedUnique(claim.reason_codes),
        timestamp: finalizedAt,
        time_basis: finalizedAt === null ? "unavailable" : "finalized-at",
        citations: sortCitations(citations),
      };
    })
    .sort((left, right) => compareText(left.state, right.state) || compareText(left.id, right.id));
}

function buildTimeline(
  input: IncidentReplayProjectionInput,
  namespaces: ReadonlyMap<string, ReadonlySet<WorkspaceCitationNamespace>>,
): WorkspaceTimelineEntry[] {
  const timeline: WorkspaceTimelineEntry[] = [];
  for (const envelope of input.evidence) {
    let timestamp = envelope.timing.retrieved_at;
    let timeBasis: WorkspaceTimelineEntry["time_basis"] = "retrieved-at";
    if (envelope.timing.event_time !== null) {
      timestamp = envelope.timing.event_time;
      timeBasis = "event-time";
    } else if (envelope.timing.source_time !== null) {
      timestamp = envelope.timing.source_time;
      timeBasis = "source-time";
    }
    timeline.push({
      id: `timeline:provider:${envelope.evidence_id}`,
      record_id: envelope.evidence_id,
      category: "source-observation",
      status:
        envelope.collection.outcome === "error"
          ? "failed"
          : envelope.timing.freshness === "current"
            ? "succeeded"
            : "unresolved",
      timestamp: validTimestamp(timestamp) ? timestamp : null,
      time_basis: validTimestamp(timestamp) ? timeBasis : "unavailable",
      label: envelope.observation.query_key ?? envelope.observation.kind,
      detail: envelope.display_excerpt,
      citations: [citation("provider-evidence", envelope.evidence_id)],
    });
  }
  for (const invocation of input.invocations) {
    timeline.push({
      id: `timeline:model:${invocation.invocation_id}`,
      record_id: invocation.invocation_id,
      category: "model-reasoning",
      status: timelineStatusForInvocation(invocation.result_class),
      timestamp: null,
      time_basis: "unavailable",
      label: invocation.turn_kind,
      detail: invocation.error_code,
      citations: citationsForIds(invocation.input_evidence_ids, namespaces),
    });
  }
  for (const result of input.packet.deterministic_results) {
    timeline.push({
      id: `timeline:deterministic:${result.result_id}`,
      record_id: result.result_id,
      category: "deterministic-result",
      status: result.status === "resolved" ? "succeeded" : "unresolved",
      timestamp: null,
      time_basis: "unavailable",
      label: `${result.validator}/${result.validator_version}`,
      detail: null,
      citations: citationsForIds(result.evidence_ids, namespaces),
    });
  }
  for (const event of input.trace_events) {
    timeline.push({
      id: `timeline:trace:${event.event_id}`,
      record_id: event.event_id,
      category: "workflow-event",
      status: timelineStatusForTrace(event.event_type, event.payload),
      timestamp: validTimestamp(event.occurred_at) ? event.occurred_at : null,
      time_basis: validTimestamp(event.occurred_at) ? "occurred-at" : "unavailable",
      label: event.event_type,
      detail: typeof event.payload.status === "string" ? event.payload.status : null,
      citations: [citation("trace-event", event.event_id)],
    });
  }
  for (const event of input.human_events ?? []) {
    timeline.push({
      id: `timeline:human:${event.event_id}`,
      record_id: event.event_id,
      category: "human-event",
      status: "informational",
      timestamp: validTimestamp(event.occurred_at) ? event.occurred_at : null,
      time_basis: validTimestamp(event.occurred_at) ? "occurred-at" : "unavailable",
      label: event.event_type,
      detail: `${event.actor.display_name} (${event.actor.subject})`,
      citations: sortCitations([
        ...event.citations.map((value) => ({ ...value })),
        citation("human-audit-event", event.event_sha256),
      ]),
    });
  }
  return timeline.sort(compareTimeline);
}

function evidenceCounts(
  evidence: readonly WorkspaceEvidence[],
): Record<EvidenceAvailability, number> {
  const counts: Record<EvidenceAvailability, number> = {
    available: 0,
    error: 0,
    stale: 0,
    unresolved: 0,
  };
  for (const item of evidence) counts[item.availability] += 1;
  return counts;
}

function claimCounts(claims: readonly WorkspaceClaim[]): Record<ClaimState, number> {
  const counts: Record<ClaimState, number> = {
    confirmed: 0,
    inferred: 0,
    rejected: 0,
    unresolved: 0,
  };
  for (const claim of claims) counts[claim.state] += 1;
  return counts;
}

function scopeCounts(scope: WorkspaceScopeGraph): Record<ProjectionScopeState, number> {
  const counts: Record<ProjectionScopeState, number> = { affected: 0, safe: 0, unknown: 0 };
  for (const node of scope.nodes) {
    if (node.classification !== "causal") counts[node.classification] += 1;
  }
  return counts;
}

function namespaceCollisions(
  namespaces: ReadonlyMap<string, ReadonlySet<WorkspaceCitationNamespace>>,
): string[] {
  return [...namespaces]
    .filter(([, values]) => values.size > 1)
    .map(([identifier]) => identifier)
    .sort(compareText);
}

function adverseState(
  code: WorkspaceAdverseStateCode,
  severity: WorkspaceAdverseState["severity"],
  detail: string,
  relatedIds: readonly string[],
): WorkspaceAdverseState {
  return { code, severity, detail, related_ids: sortedUnique(relatedIds) };
}

function buildAdverseStates(
  input: IncidentReplayProjectionInput,
  identity: readonly string[],
  parity: WorkspaceScopeParity,
  evidence: readonly WorkspaceEvidence[],
  missing: readonly string[],
  collisions: readonly string[],
  timeline: readonly WorkspaceTimelineEntry[],
): WorkspaceAdverseState[] {
  const values: WorkspaceAdverseState[] = [];
  if (identity.length > 0) {
    values.push(
      adverseState(
        "identity-mismatch",
        "blocking",
        "Persisted replay identities do not bind to one incident.",
        identity,
      ),
    );
  }
  if (collisions.length > 0) {
    values.push(
      adverseState(
        "evidence-namespace-collision",
        "blocking",
        "An evidence identifier resolves to more than one evidence namespace.",
        collisions,
      ),
    );
  }
  if (parity.status === "failed") {
    values.push(
      adverseState(
        "scope-parity-failed",
        "blocking",
        "Packet and validator scope identities do not match.",
        parity.reason_codes,
      ),
    );
  }
  if (missing.length > 0) {
    values.push(
      adverseState(
        "missing-evidence",
        "blocking",
        "One or more cited evidence records are unavailable.",
        missing,
      ),
    );
  }
  const failed = evidence
    .filter((item) => item.kind === "provider" && item.availability === "error")
    .map((item) => item.evidence_id);
  if (failed.length > 0) {
    values.push(
      adverseState(
        "provider-evidence-error",
        "blocking",
        "Provider evidence collection failed.",
        failed,
      ),
    );
  }
  const stale = evidence
    .filter((item) => item.kind === "provider" && item.availability === "stale")
    .map((item) => item.evidence_id);
  if (stale.length > 0) {
    values.push(adverseState("stale-evidence", "blocking", "Provider evidence is stale.", stale));
  }
  if (timeline.some((entry) => entry.time_basis === "unavailable")) {
    values.push(
      adverseState(
        "time-basis-incomplete",
        "warning",
        "One or more timeline records do not have a usable timestamp.",
        timeline
          .filter((entry) => entry.time_basis === "unavailable")
          .map((entry) => entry.record_id),
      ),
    );
  }
  if (input.packet.status === "unresolved") {
    values.push(
      adverseState(
        "unresolved-investigation",
        "blocking",
        "The investigation remains unresolved and cannot supply an executable plan.",
        [
          ...input.packet.scope.reason_codes,
          ...input.packet.unresolved_items.map((item) => item.code),
        ],
      ),
    );
  }
  return values.sort(
    (left, right) =>
      compareText(left.severity, right.severity) || compareText(left.code, right.code),
  );
}

function buildLimitations(
  input: IncidentReplayProjectionInput,
  parity: WorkspaceScopeParity,
): WorkspaceLimitation[] {
  const values: WorkspaceLimitation[] = [
    {
      code: "display-preview-non-authoritative",
      detail:
        "Display excerpts are bounded previews; cited digests identify authoritative records.",
      related_ids: input.evidence.map((item) => item.evidence_id).sort(compareText),
    },
    {
      code: "model-output-not-evidence",
      detail: "Model invocation output is provenance and cannot establish a claim or scope.",
      related_ids: input.invocations.map((item) => item.invocation_id).sort(compareText),
    },
    {
      code: "reference-policy-technical-only",
      detail: "Reference comparison evaluates declared technical state, not creative correctness.",
      related_ids: input.validator_results.map((item) => item.result_id).sort(compareText),
    },
    {
      code: "record-time-unavailable",
      detail:
        "Claims use packet finalization only as record time, not occurrence time. Model invocations and deterministic results carry no occurrence timestamp and are shown as unavailable.",
      related_ids: sortedUnique([
        ...input.packet.claims.map((item) => item.claim_id),
        ...input.invocations.map((item) => item.invocation_id),
        ...input.packet.deterministic_results.map((item) => item.result_id),
      ]),
    },
  ];
  if ((input.human_events ?? []).length === 0) {
    values.push({
      code: "human-event-history-unavailable",
      detail: "This replay contract contains no authenticated human-event history.",
      related_ids: [],
    });
  }
  if (parity.status === "not-verifiable") {
    values.push({
      code: "scope-parity-not-verifiable",
      detail: "No validator scope is available; only explicitly unknown packet scope is shown.",
      related_ids: parity.reason_codes,
    });
  }
  return values.sort((left, right) => compareText(left.code, right.code));
}

function workspaceState(
  input: IncidentReplayProjectionInput,
  identity: readonly string[],
  parity: WorkspaceScopeParity,
  collisions: readonly string[],
  missing: readonly string[],
  evidence: readonly WorkspaceEvidence[],
): WorkspaceState {
  if (identity.length > 0 || parity.status === "failed" || collisions.length > 0) return "invalid";
  if (
    input.packet.status === "unresolved" ||
    parity.status === "not-verifiable" ||
    missing.length > 0 ||
    evidence.some((item) => item.availability !== "available")
  ) {
    return "unresolved";
  }
  return "resolved";
}

export function projectIncidentReplay(
  input: IncidentReplayProjectionInput,
): InvestigationWorkspace {
  const identity = identityProblems(input);
  const drafts = buildEvidenceDrafts(input);
  const namespaces = evidenceNamespaces(drafts);
  const evidence = finalizeEvidence(drafts, namespaces);
  const knownEvidenceIds = new Set(evidence.map((item) => item.evidence_id));
  const missing = referencedEvidenceIds(input).filter(
    (identifier) => !knownEvidenceIds.has(identifier),
  );
  const collisions = namespaceCollisions(namespaces);
  const normalizedScope = normalizeValidatorScope(input.validator_results, namespaces);
  const parity = scopeParity(input, normalizedScope);
  const state = workspaceState(input, identity, parity, collisions, missing, evidence);
  const scope = buildScope(
    input,
    normalizedScope,
    parity,
    state === "invalid" && parity.status !== "failed",
  );
  const claims = buildClaims(input, namespaces);
  const timeline = buildTimeline(input, namespaces);
  const adverseStates = buildAdverseStates(
    input,
    identity,
    parity,
    evidence,
    missing,
    collisions,
    timeline,
  );
  const planState =
    state === "resolved" && input.packet.candidate_plan !== null
      ? "available"
      : input.packet.status === "unresolved"
        ? "blocked"
        : "not-applicable";
  const workspace: InvestigationWorkspace = {
    schema: "investigation-workspace/v1",
    incident: {
      id: input.incident.incident_id,
      alert_id: input.incident.alert_id,
      status: input.incident.status,
      version: input.incident.version,
      trace_id: input.incident.trace_id,
      packet_id: input.packet.packet_id,
      created_at: input.incident.created_at,
      updated_at: input.incident.updated_at,
      finalized_at: input.packet.finalized_at,
    },
    overview: {
      state,
      claim_counts: claimCounts(claims),
      scope_counts: scopeCounts(scope),
      evidence_counts: evidenceCounts(evidence),
      candidate_plan: {
        state: planState,
        id: planState === "available" ? (input.packet.candidate_plan?.plan_id ?? null) : null,
        non_executable: true,
      },
      next_authority:
        planState === "available"
          ? "human-plan-review"
          : state === "resolved"
            ? "none"
            : "investigation-required",
    },
    claims,
    timeline,
    evidence: { items: evidence, missing_references: missing },
    scope,
    limitations: buildLimitations(input, parity),
    adverse_states: adverseStates,
  };
  return deepFreeze(workspace);
}
