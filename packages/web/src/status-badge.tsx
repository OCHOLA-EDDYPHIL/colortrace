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
  | "integrity-error";

const BADGE_LABEL: Readonly<Record<BadgeValue, string>> = {
  affected: "Affected",
  available: "Available",
  causal: "Causal resource",
  confirmed: "Confirmed",
  "deterministic-result": "Deterministic result",
  error: "Collection error",
  failed: "Failed",
  "human-event": "Human event",
  inferred: "Inferred",
  informational: "Informational",
  "integrity-error": "Integrity error",
  "model-reasoning": "Model reasoning",
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
