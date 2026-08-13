import type { InvestigationWorkspace, WorkspaceIncidentSummary } from "@colortrace/workspace-model";

export type IncidentInboxItem = WorkspaceIncidentSummary;

type PendingIncidentState = {
  readonly incident: IncidentInboxItem;
};

export type IncidentWorkspaceViewState =
  | { readonly kind: "empty"; readonly message: string }
  | { readonly kind: "fetch-error"; readonly message: string }
  | {
      readonly incident: IncidentInboxItem | null;
      readonly kind: "integrity-error";
      readonly message: string;
    }
  | { readonly kind: "loading"; readonly message: string }
  | ({ readonly kind: "queued" } & PendingIncidentState)
  | ({ readonly kind: "running" } & PendingIncidentState)
  | { readonly kind: "workspace"; readonly workspace: InvestigationWorkspace };
