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
  | "color-resource"
  | "derivative"
  | "frame"
  | "integrity-error"
  | "pending";

const BADGE_LABEL: Readonly<Record<BadgeValue, string>> = {
  affected: "Affected",
  approved: "Approved",
  available: "Available",
  causal: "Causal resource",
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
  "model-reasoning": "Model reasoning",
  pending: "Pending",
  queued: "Queued",
  rejected: "Rejected",
  resolved: "Resolved",
  running: "Running",
  safe: "Safe",
  stale: "Stale",
  "source-observation": "Source observation",
  succeeded: "Succeeded",
  unknown: "Unknown",
  unresolved: "Unresolved",
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
