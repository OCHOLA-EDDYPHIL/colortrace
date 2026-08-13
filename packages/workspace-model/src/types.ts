export type ClaimState = "confirmed" | "inferred" | "rejected" | "unresolved";

export type ProjectionScopeState = "affected" | "safe" | "unknown";

export type IncidentReplayProjectionInput = {
  readonly schema: "incident-replay/v1";
  readonly incident: {
    readonly incident_id: string;
    readonly alert_id: string;
    readonly status: "resolved" | "unresolved";
    readonly version: number;
    readonly alert_sha256: string;
    readonly trace_id: string;
    readonly packet_id: string;
    readonly created_at: string;
    readonly updated_at: string;
  };
  readonly task: {
    readonly task_id: string;
    readonly incident_id: string;
    readonly expected_incident_version: number;
    readonly alert_sha256: string;
    readonly trace_id: string;
    readonly status: "complete";
    readonly packet_id: string;
    readonly created_at: string;
    readonly updated_at: string;
  };
  readonly alert: {
    readonly incident_id: string;
    readonly alert_id: string;
    readonly alert_started_at: string;
    readonly retrieved_at: string;
    readonly correlation_keys: {
      readonly trace_id: string;
      readonly worker_id?: string;
    };
  };
  readonly evidence: readonly ProjectionEvidenceEnvelope[];
  readonly validator_results: readonly ProjectionValidatorResult[];
  readonly invocations: readonly ProjectionModelInvocation[];
  readonly packet: ProjectionResponsePacket;
  readonly trace_events: readonly ProjectionTraceEvent[];
  readonly human_events?: readonly ProjectionHumanAuditEvent[];
  readonly derivation_sha256: string;
};

export type ProjectionEvidenceEnvelope = {
  readonly schema: "evidence-envelope/v1";
  readonly evidence_id: string;
  readonly incident_id: string;
  readonly request_id: string;
  readonly source: {
    readonly kind: string;
    readonly tool?: string;
  };
  readonly observation: {
    readonly kind: string;
    readonly query_key?: string;
  };
  readonly timing: {
    readonly source_time: string | null;
    readonly event_time: string | null;
    readonly retrieved_at: string;
    readonly freshness: "current" | "stale" | "unresolved";
  };
  readonly content_sha256: string;
  readonly content: unknown;
  readonly display_excerpt: string;
  readonly correlation_keys: Readonly<Record<string, string>>;
  readonly collection: {
    readonly outcome: "collected" | "error";
    readonly attempts: number;
    readonly retries: number;
    readonly error: {
      readonly code: string;
      readonly retryable: false;
    } | null;
  };
  readonly trust: "untrusted-provider-data" | "deterministic-result";
  readonly producer_version: string;
  readonly predecessor_event_sha256: string | null;
  readonly event_sha256: string;
};

export type ProjectionModelInvocation = {
  readonly invocation_id: string;
  readonly incident_id: string;
  readonly turn_kind: string;
  readonly input_evidence_ids: readonly string[];
  readonly latency_ms: number;
  readonly result_class: "accepted" | "budget-rejected" | "failed" | "invalid";
  readonly error_code: string | null;
  readonly output_sha256: string | null;
  readonly trace_id: string;
  readonly derivation_sha256: string;
};

export type ProjectionDeterministicResult = {
  readonly result_id: string;
  readonly validator: string;
  readonly validator_version: string;
  readonly status: "resolved" | "unresolved";
  readonly policy_versions: Readonly<Record<string, string>>;
  readonly derivation_sha256: string;
  readonly evidence_ids: readonly string[];
};

export type ProjectionClaim = {
  readonly claim_id: string;
  readonly claim_type: string;
  readonly subject: {
    readonly kind: string;
    readonly value: string | null;
  };
  readonly state: ClaimState;
  readonly policy: string;
  readonly deterministic_result_evidence_id: string | null;
  readonly source_validator_result_id: string | null;
  readonly derivation_sha256: string;
  readonly contradiction_links: readonly string[];
  readonly evidence_ids: readonly string[];
  readonly reason_codes: readonly string[];
};

export type ProjectionScopeItem = {
  readonly kind: "derivative" | "frame";
  readonly id: string;
};

export type ProjectionResponsePacket = {
  readonly packet_id: string;
  readonly incident_id: string;
  readonly version: number;
  readonly status: "resolved" | "unresolved";
  readonly fixed_window: {
    readonly start: string;
    readonly end: string;
    readonly frozen_at: string;
  };
  readonly evidence_ids: readonly string[];
  readonly deterministic_results: readonly ProjectionDeterministicResult[];
  readonly claims: readonly ProjectionClaim[];
  readonly scope: {
    readonly state: "resolved" | "unresolved";
    readonly policy: string;
    readonly affected: readonly ProjectionScopeItem[];
    readonly safe: readonly ProjectionScopeItem[];
    readonly unknown: readonly ProjectionScopeItem[];
    readonly reason_codes: readonly string[];
  };
  readonly invocation_records: readonly ProjectionModelInvocation[];
  readonly unresolved_items: readonly {
    readonly code: string;
    readonly stage: string;
    readonly evidence_ids: readonly string[];
  }[];
  readonly candidate_plan: {
    readonly plan_id: string;
    readonly non_executable: true;
    readonly targets: readonly ProjectionScopeItem[];
    readonly claim_ids: readonly string[];
  } | null;
  readonly no_action_reason: string | null;
  readonly finalized_at: string;
  readonly derivation_sha256: string;
};

export type ProjectionValidatorScopeFrame = {
  readonly job_id: string;
  readonly frame_id: string | null;
  readonly output_id: string | null;
  readonly worker_id: string | null;
  readonly state: ProjectionScopeState;
  readonly reason_codes: readonly string[];
  readonly evidence_ids: readonly string[];
};

export type ProjectionValidatorScopeDerivative = {
  readonly artifact_id: string;
  readonly parent_artifact_id: string | null;
  readonly state: ProjectionScopeState;
  readonly lineage_policy: string;
  readonly reason_codes: readonly string[];
  readonly evidence_ids: readonly string[];
};

export type ProjectionValidatorResult = {
  readonly result_id: string;
  readonly incident_id: string;
  readonly status: "resolved" | "unresolved";
  readonly validator: {
    readonly name: string;
    readonly version: string;
  };
  readonly policies: {
    readonly comparison: string;
    readonly scope: string;
    readonly lineage: string;
    readonly claim: string;
  };
  readonly scope: {
    readonly state: "resolved" | "unresolved";
    readonly policy: string;
    readonly causal_resource_sha256: string | null;
    readonly frames: readonly ProjectionValidatorScopeFrame[];
    readonly derivatives: readonly ProjectionValidatorScopeDerivative[];
    readonly reason_codes: readonly string[];
  };
  readonly claims: readonly {
    readonly claim_id: string;
    readonly deterministic_result_evidence_id: string;
    readonly derivation_sha256: string;
    readonly evidence_ids: readonly string[];
  }[];
  readonly evidence: readonly {
    readonly evidence_id: string;
    readonly kind: string;
    readonly path: string;
    readonly sha256: string;
  }[];
  readonly reason_codes: readonly string[];
  readonly derivation_sha256: string;
};

export type ProjectionTraceEvent = {
  readonly event_id: string;
  readonly incident_id: string;
  readonly sequence: number;
  readonly event_type: string;
  readonly trace_id: string;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly occurred_at: string;
  readonly event_sha256: string;
};

export type ProjectionHumanAuditEvent = {
  readonly schema: "incident-human-audit-event/v1";
  readonly event_id: string;
  readonly incident_id: string;
  readonly sequence: number;
  readonly event_type: string;
  readonly actor: {
    readonly subject: string;
    readonly display_name: string;
    readonly issuer: string;
    readonly audience: string;
    readonly principal_kind: "human";
  };
  readonly predecessor_event_sha256: string | null;
  readonly occurred_at: string;
  readonly event_sha256: string;
  readonly citations: readonly {
    readonly namespace: "trace-event";
    readonly id: string;
  }[];
};

export type WorkspaceState = "invalid" | "resolved" | "unresolved";

export type WorkspaceTimeBasis =
  | "event-time"
  | "finalized-at"
  | "occurred-at"
  | "retrieved-at"
  | "source-time"
  | "unavailable";

export type WorkspaceTimelineCategory =
  | "deterministic-result"
  | "human-event"
  | "model-reasoning"
  | "source-observation"
  | "workflow-event";

export type WorkspaceTimelineStatus = "failed" | "informational" | "succeeded" | "unresolved";

export type WorkspaceCitationNamespace =
  | "claim"
  | "deterministic-derivation"
  | "human-audit-event"
  | "model-invocation"
  | "provider-evidence"
  | "trace-event"
  | "validator-artifact";

export type WorkspaceCitation = {
  readonly namespace: WorkspaceCitationNamespace;
  readonly id: string;
};

export type WorkspaceTimelineEntry = {
  readonly id: string;
  readonly record_id: string;
  readonly category: WorkspaceTimelineCategory;
  readonly status: WorkspaceTimelineStatus;
  readonly timestamp: string | null;
  readonly time_basis: WorkspaceTimeBasis;
  readonly label: string;
  readonly detail: string | null;
  readonly citations: readonly WorkspaceCitation[];
};

export type EvidenceAvailability = "available" | "error" | "stale" | "unresolved";

type WorkspaceEvidenceBase = {
  readonly workspace_id: string;
  readonly evidence_id: string;
  readonly availability: EvidenceAvailability;
  readonly citations: readonly WorkspaceCitation[];
};

export type WorkspaceProviderEvidence = WorkspaceEvidenceBase & {
  readonly kind: "provider";
  readonly incident_id: string;
  readonly source_kind: string;
  readonly tool: string | null;
  readonly observation_kind: string;
  readonly query_key: string | null;
  readonly content_sha256: string;
  readonly display_excerpt: string;
  readonly timestamp: string;
  readonly time_basis: Exclude<WorkspaceTimeBasis, "finalized-at" | "occurred-at" | "unavailable">;
  readonly error_code: string | null;
};

export type WorkspaceValidatorArtifactEvidence = WorkspaceEvidenceBase & {
  readonly kind: "validator-artifact";
  readonly validator_result_id: string;
  readonly artifact_kind: string;
  readonly path: string;
  readonly content_sha256: string;
};

export type WorkspaceDeterministicDerivationEvidence = WorkspaceEvidenceBase & {
  readonly kind: "deterministic-derivation";
  readonly validator_result_id: string | null;
  readonly claim_id: string | null;
  readonly policy_versions: Readonly<Record<string, string>>;
  readonly derivation_sha256: string;
};

export type WorkspaceEvidence =
  | WorkspaceDeterministicDerivationEvidence
  | WorkspaceProviderEvidence
  | WorkspaceValidatorArtifactEvidence;

export type WorkspaceEvidenceCollection = {
  readonly items: readonly WorkspaceEvidence[];
  readonly missing_references: readonly string[];
};

export type WorkspaceScopeClassification = "affected" | "causal" | "safe" | "unknown";

type WorkspaceScopeNodeBase = {
  readonly key: string;
  readonly id: string;
  readonly classification: WorkspaceScopeClassification;
  readonly reason_codes: readonly string[];
  readonly citations: readonly WorkspaceCitation[];
};

export type WorkspaceResourceScopeNode = WorkspaceScopeNodeBase & {
  readonly kind: "resource";
  readonly classification: "causal";
};

export type WorkspaceFrameScopeNode = WorkspaceScopeNodeBase & {
  readonly kind: "frame";
  readonly classification: ProjectionScopeState;
  readonly job_id: string;
  readonly output_id: string | null;
  readonly worker_id: string | null;
  readonly safe_on_implicated_worker: boolean;
};

export type WorkspaceDerivativeScopeNode = WorkspaceScopeNodeBase & {
  readonly kind: "derivative";
  readonly classification: ProjectionScopeState;
  readonly parent_artifact_id: string | null;
};

export type WorkspaceScopeNode =
  | WorkspaceDerivativeScopeNode
  | WorkspaceFrameScopeNode
  | WorkspaceResourceScopeNode;

export type WorkspaceScopeEdge = {
  readonly id: string;
  readonly kind: "causal-scope" | "lineage";
  readonly from: string;
  readonly to: string;
  readonly policy: string;
  readonly citations: readonly WorkspaceCitation[];
};

export type WorkspaceScopeParity = {
  readonly status: "failed" | "not-verifiable" | "verified";
  readonly reason_codes: readonly string[];
};

export type WorkspaceScopeGraph = {
  readonly state: WorkspaceState;
  readonly policy: string;
  readonly parity: WorkspaceScopeParity;
  readonly nodes: readonly WorkspaceScopeNode[];
  readonly edges: readonly WorkspaceScopeEdge[];
};

export type WorkspaceClaim = {
  readonly id: string;
  readonly type: string;
  readonly subject_kind: string;
  readonly subject_value: string | null;
  readonly state: ClaimState;
  readonly policy: string;
  readonly reason_codes: readonly string[];
  readonly timestamp: string | null;
  readonly time_basis: "finalized-at" | "unavailable";
  readonly citations: readonly WorkspaceCitation[];
};

export type WorkspaceIncident = {
  readonly id: string;
  readonly alert_id: string;
  readonly status: "resolved" | "unresolved";
  readonly version: number;
  readonly trace_id: string;
  readonly packet_id: string;
  readonly created_at: string;
  readonly updated_at: string;
  readonly finalized_at: string;
};

export type WorkspaceIncidentSummary = {
  readonly id: string;
  readonly alert_id: string;
  readonly status: "queued" | "resolved" | "running" | "unresolved";
  readonly created_at: string;
  readonly updated_at: string;
  readonly delayed: boolean;
  readonly missing: readonly string[];
};

export type WorkspaceOverview = {
  readonly state: WorkspaceState;
  readonly claim_counts: Readonly<Record<ClaimState, number>>;
  readonly scope_counts: Readonly<Record<ProjectionScopeState, number>>;
  readonly evidence_counts: Readonly<Record<EvidenceAvailability, number>>;
  readonly candidate_plan: {
    readonly state: "available" | "blocked" | "not-applicable";
    readonly id: string | null;
    readonly non_executable: true;
  };
  readonly next_authority: "human-plan-review" | "investigation-required" | "none";
};

export type WorkspaceLimitationCode =
  | "display-preview-non-authoritative"
  | "human-event-history-unavailable"
  | "model-output-not-evidence"
  | "record-time-unavailable"
  | "reference-policy-technical-only"
  | "scope-parity-not-verifiable";

export type WorkspaceLimitation = {
  readonly code: WorkspaceLimitationCode;
  readonly detail: string;
  readonly related_ids: readonly string[];
};

export type WorkspaceAdverseStateCode =
  | "evidence-namespace-collision"
  | "identity-mismatch"
  | "missing-evidence"
  | "provider-evidence-error"
  | "scope-parity-failed"
  | "stale-evidence"
  | "time-basis-incomplete"
  | "unresolved-investigation";

export type WorkspaceAdverseState = {
  readonly code: WorkspaceAdverseStateCode;
  readonly severity: "blocking" | "warning";
  readonly detail: string;
  readonly related_ids: readonly string[];
};

export type InvestigationWorkspace = {
  readonly schema: "investigation-workspace/v1";
  readonly incident: WorkspaceIncident;
  readonly overview: WorkspaceOverview;
  readonly claims: readonly WorkspaceClaim[];
  readonly timeline: readonly WorkspaceTimelineEntry[];
  readonly evidence: WorkspaceEvidenceCollection;
  readonly scope: WorkspaceScopeGraph;
  readonly limitations: readonly WorkspaceLimitation[];
  readonly adverse_states: readonly WorkspaceAdverseState[];
};
