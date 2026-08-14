import type {
  ClaimState,
  EvidenceAvailability,
  WorkspaceIncidentSummary,
  WorkspaceScopeClassification,
  WorkspaceTimelineCategory,
  WorkspaceTimelineStatus,
} from "@colortrace/workspace-model";

export type IncidentLifecycleStatus = WorkspaceIncidentSummary["status"];

type BadgeValue =
  | ClaimState
  | EvidenceAvailability
  | IncidentLifecycleStatus
  | WorkspaceScopeClassification
  | WorkspaceTimelineCategory
  | WorkspaceTimelineStatus
  | "approved"
  | "ambiguous"
  | "closed"
  | "color-resource"
  | "derivative"
  | "frame"
  | "integrity-error"
  | "late"
  | "pending"
  | "passed"
  | "post-action"
  | "pre-action"
  | "recovery_failed"
  | "recovery_unresolved"
  | "recovery_verified"
  | "verification_pending"
  | "verification_running";

const BADGE_LABEL: Readonly<Record<BadgeValue, string>> = {
  affected: "Affected",
  ambiguous: "Time ambiguous",
  approved: "Approved",
  available: "Available",
  causal: "Causal resource",
  closed: "Closed",
  "color-resource": "Color resource",
  confirmed: "Confirmed",
  derivative: "Derivative",
  "deterministic-result": "Deterministic result",
  error: "Collection error",
  failed: "Failed",
  frame: "Frame",
  "human-event": "Human event",
  inferred: "Inferred",
  informational: "Informational",
  "integrity-error": "Integrity error",
  late: "Late evidence",
  "model-reasoning": "Model reasoning",
  pending: "Pending",
  passed: "Passed",
  "post-action": "Post-action",
  "pre-action": "Pre-action",
  queued: "Queued",
  rejected: "Rejected",
  recovery_failed: "Recovery failed",
  recovery_unresolved: "Recovery unresolved",
  recovery_verified: "Recovery verified",
  resolved: "Resolved",
  running: "Running",
  safe: "Safe",
  stale: "Stale",
  "source-observation": "Source observation",
  succeeded: "Succeeded",
  unknown: "Unknown",
  unresolved: "Unresolved",
  verification_pending: "Verification pending",
  verification_running: "Verification running",
  "workflow-event": "Workflow event",
};

export type StatusBadgeProps = {
  readonly value: BadgeValue;
};

export function StatusBadge({ value }: StatusBadgeProps) {
  return (
    <span className="status-badge" data-status={value}>
      <span aria-hidden="true" className="status-badge__icon" />
      <span>{BADGE_LABEL[value]}</span>
    </span>
  );
}
