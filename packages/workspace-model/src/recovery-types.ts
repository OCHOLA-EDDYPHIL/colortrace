export type RecoveryWorkflowState =
  | "verification_pending"
  | "verification_running"
  | "recovery_verified"
  | "recovery_failed"
  | "recovery_unresolved"
  | "closed";

export type RecoveryCheckName =
  | "active-publication"
  | "approved-resource-state"
  | "declared-reference-recovery"
  | "exact-typed-lineage"
  | "approved-recovery-scope"
  | "safe-complement-preservation"
  | "post-action-telemetry-correlation";

export type RecoveryTarget = {
  readonly schema: "simulator-target/v1";
  readonly namespace: "colortrace-simulator";
  readonly kind: "color-resource" | "derivative" | "frame";
  readonly id: string;
};

export type RecoveryCheckResult = {
  readonly schema: "recovery-check-result/v1";
  readonly result_id: string;
  readonly result_sha256: string;
  readonly check: RecoveryCheckName;
  readonly policy: `${RecoveryCheckName}/v1`;
  readonly state: "failed" | "passed" | "unresolved";
  readonly normalized_inputs_sha256: string;
  readonly evidence_ids: readonly string[];
  readonly artifact_ids: readonly string[];
  readonly reason_codes: readonly string[];
};

export type RecoveryPacketItem = {
  readonly check: RecoveryCheckName;
  readonly reason_codes: readonly string[];
};

export type RecoveryPacket = {
  readonly schema: "recovery-packet/v1";
  readonly packet_id: string;
  readonly packet_sha256: string;
  readonly incident_id: string;
  readonly incident_version: number;
  readonly workflow_id: string;
  readonly workflow_version: number;
  readonly attempt_id: string;
  readonly attempt_number: number;
  readonly snapshot_id: string;
  readonly snapshot_sha256: string;
  readonly outcome_id: string;
  readonly outcome_sha256: string;
  readonly action_id: string;
  readonly action_started_at: string;
  readonly evaluation_started_at: string;
  readonly evaluation_completed_at: string;
  readonly evidence_request_id: string;
  readonly evidence_request_sha256: string;
  readonly evidence_ids: readonly string[];
  readonly check_results: readonly RecoveryCheckResult[];
  readonly status: "recovery_failed" | "recovery_unresolved" | "recovery_verified";
  readonly failure_items: readonly RecoveryPacketItem[];
  readonly unresolved_items: readonly RecoveryPacketItem[];
  readonly eligible_for_closure: boolean;
  readonly supersedes_packet_id: string | null;
  readonly supersedes_packet_sha256: string | null;
};

export type RecoveryActionOutcome = {
  readonly schema: "simulator-action-outcome/v1";
  readonly outcome_id: string;
  readonly outcome_sha256: string;
  readonly action_id: string;
  readonly status: "failed" | "succeeded";
  readonly reason_codes: readonly string[];
  readonly incident_id: string;
  readonly incident_version: number;
  readonly plan_id: string;
  readonly plan_version: number;
  readonly plan_sha256: string;
  readonly action_started_at: string;
  readonly publication_promoted_at: string | null;
  readonly completed_at: string;
  readonly active_publication_pointer_sha256: string | null;
  readonly active_runtime_manifest_sha256: string | null;
  readonly preservation_manifest_sha256: string | null;
  readonly safe_complement_before_sha256: string | null;
  readonly safe_complement_after_sha256: string | null;
  readonly safe_complement_proof_sha256: string | null;
  readonly targets: readonly RecoveryTarget[];
  readonly exclusions: readonly RecoveryTarget[];
  readonly command_outcomes: readonly {
    readonly schema: "simulator-command-result/v1";
    readonly command_id: string;
    readonly result_kind: "derivative" | "frame" | "quarantine";
    readonly target: RecoveryTarget;
    readonly trace_id: string;
    readonly before: Readonly<Record<string, unknown>>;
    readonly after: Readonly<Record<string, unknown>>;
  }[];
  readonly new_trace_ids: readonly string[];
  readonly [key: string]: unknown;
};

export type RecoveryActivePublication = {
  readonly schema: "recovery-active-publication/v1";
  readonly publication_id: string;
  readonly observed_at: string;
  readonly generation: number;
  readonly pointer_sha256: string;
  readonly runtime_manifest_sha256: string;
  readonly fixture_manifest_sha256: string;
  readonly lineage_manifest_sha256: string;
  readonly declared_resource_manifest_sha256: string;
  readonly preservation_manifest_sha256: string;
  readonly safe_complement_sha256: string;
  readonly safe_complement_proof_sha256: string;
  readonly candidate_seal_sha256: string;
  readonly candidate_tree_sha256: string;
};

export type RecoveryVerificationArtifact = {
  readonly schema: "recovery-verification-artifact/v1";
  readonly artifact_id: string;
  readonly role:
    | "active-resource"
    | "affected-output"
    | "declared-reference"
    | "derivative-output"
    | "derivative-parent"
    | "fixture-manifest"
    | "lineage-manifest"
    | "preservation-manifest"
    | "runtime-manifest"
    | "safe-complement"
    | "safe-complement-proof";
  readonly target: RecoveryTarget | null;
  readonly sha256: string;
  readonly size: number;
  readonly publication_pointer_sha256: string;
};

export type RecoveryVerificationSnapshot = {
  readonly schema: "recovery-verification-snapshot/v1";
  readonly snapshot_id: string;
  readonly snapshot_sha256: string;
  readonly incident_id: string;
  readonly incident_version: number;
  readonly created_at: string;
  readonly action_outcome: RecoveryActionOutcome;
  readonly active_publication: RecoveryActivePublication;
  readonly verification_artifacts: readonly RecoveryVerificationArtifact[];
};

export type RecoveryEvidenceRecord = {
  readonly schema: "recovery-evidence-record/v1";
  readonly evidence_id: string;
  readonly evidence_sha256: string;
  readonly signal: "log" | "metric" | "trace";
  readonly event_id: string;
  readonly subject_kind: "command" | "safe";
  readonly subject_id: string;
  readonly trace_id: string | null;
  readonly observed_at: string;
  readonly emitted_at: string;
  readonly retrieved_at: string;
  readonly freshness: "ambiguous" | "late" | "post-action" | "pre-action";
  readonly correlation: {
    readonly incident_id: string;
    readonly action_id: string;
    readonly outcome_id: string;
    readonly outcome_sha256: string;
    readonly target: RecoveryTarget | null;
  };
  readonly source_label: string;
  readonly display_excerpt: string;
};

export type RecoveryAuditEvent = {
  readonly schema: "recovery-audit-event/v1";
  readonly event_id: string;
  readonly event_sha256: string;
  readonly incident_id: string;
  readonly workflow_id: string;
  readonly sequence: number;
  readonly event_type:
    | "recovery.closed"
    | "verification.claimed"
    | "verification.completed"
    | "verification.reclaimed"
    | "verification.requested";
  readonly actor: {
    readonly issuer: string;
    readonly subject: string;
    readonly audience: string;
    readonly display_name: string;
    readonly kind: "human" | "service";
    readonly authorized_role: "recovery.closer" | "recovery.verifier";
  };
  readonly snapshot_id: string;
  readonly snapshot_sha256: string;
  readonly outcome_id: string;
  readonly outcome_sha256: string;
  readonly packet_id: string | null;
  readonly packet_sha256: string | null;
  readonly idempotency_key: string;
  readonly predecessor_event_sha256: string | null;
  readonly occurred_at: string;
  readonly details: Readonly<Record<string, unknown>>;
};

export type RecoveryClosureResult = {
  readonly schema: "recovery-closure-result/v1";
  readonly closure_id: string;
  readonly closure_sha256: string;
  readonly incident_id: string;
  readonly workflow_id: string;
  readonly workflow_version_before: number;
  readonly workflow_version_after: number;
  readonly packet_id: string;
  readonly packet_sha256: string;
  readonly outcome_id: string;
  readonly outcome_sha256: string;
  readonly actor: {
    readonly issuer: string;
    readonly subject: string;
    readonly audience: string;
    readonly display_name: string;
    readonly kind: "human";
  };
  readonly authorized_role: "recovery.closer";
  readonly reason: string;
  readonly closed_at: string;
  readonly idempotency_key: string;
  readonly audit_event_id: string;
  readonly audit_event_sha256: string;
};

export type RecoveryReviewProjectionInput = {
  readonly schema: "recovery-review/v1";
  readonly state: RecoveryWorkflowState;
  readonly current_incident_version: number;
  readonly workflow_version: number;
  readonly snapshot: RecoveryVerificationSnapshot;
  readonly evidence_records: readonly RecoveryEvidenceRecord[];
  readonly packet: RecoveryPacket | null;
  readonly closure: RecoveryClosureResult | null;
  readonly audit_events: readonly RecoveryAuditEvent[];
};

export type RecoveryProjectionProblem =
  | "audit-binding"
  | "citation-binding"
  | "closure-binding"
  | "digest-binding"
  | "evidence-time-binding"
  | "identity-binding"
  | "packet-binding"
  | "publication-binding"
  | "schema-binding"
  | "status-binding";

export type RecoveryWorkspace =
  | {
      readonly schema: "recovery-workspace/v1";
      readonly integrity: "invalid";
      readonly problems: readonly RecoveryProjectionProblem[];
      readonly review: null;
    }
  | {
      readonly schema: "recovery-workspace/v1";
      readonly integrity: "verified";
      readonly problems: readonly [];
      readonly review: RecoveryReviewProjectionInput;
    };
