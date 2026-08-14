import { useEffect, useRef } from "react";

import { EvidenceView } from "./evidence-view.tsx";
import { IncidentInbox } from "./incident-inbox.tsx";
import { IncidentOverview } from "./incident-overview.tsx";
import { InvestigationTimeline } from "./investigation-timeline.tsx";
import { RecoveryVerification, type RecoveryVerificationProps } from "./recovery-verification.tsx";
import { ResponsePlanReview, type ResponsePlanReviewProps } from "./response-plan-review.tsx";
import { ScopeView } from "./scope-view.tsx";
import { StatusBadge } from "./status-badge.tsx";
import { Timestamp } from "./time.tsx";
import type { IncidentInboxItem, IncidentWorkspaceViewState } from "./view-state.ts";

export type AuthenticatedViewer = {
  readonly displayName: string;
  readonly kind: "authenticated";
  readonly principalKind: "human" | "service";
  readonly roles: readonly string[];
};

export type WorkspaceViewer =
  | AuthenticatedViewer
  | { readonly kind: "loading" }
  | { readonly kind: "expired"; readonly message: string }
  | { readonly kind: "unauthenticated"; readonly message: string }
  | { readonly kind: "error"; readonly message: string };

export type IncidentWorkspaceShellProps = {
  readonly focusRequest?: number;
  readonly incidents: readonly IncidentInboxItem[];
  readonly onRetry?: () => void;
  readonly onSelectIncident?: (incidentId: string) => void;
  readonly selectedIncidentId: string | null;
  readonly state: IncidentWorkspaceViewState;
  readonly viewer: WorkspaceViewer;
  readonly responsePlan: ResponsePlanReviewProps;
  readonly recovery?: RecoveryVerificationProps;
};

function SessionStatus({ viewer }: { readonly viewer: WorkspaceViewer }) {
  if (viewer.kind === "authenticated" || viewer.kind === "loading") return null;
  const error = viewer.kind === "error" || viewer.kind === "expired";
  return (
    <section
      aria-labelledby="session-status-title"
      className="panel session-notice"
      role={error ? "alert" : "status"}
    >
      <p className="eyebrow">Operator session</p>
      <h2 id="session-status-title">
        {viewer.kind === "expired"
          ? "Operator session expired or invalid"
          : error
            ? "Session check unavailable"
            : "Unauthenticated read-only session"}
      </h2>
      <p>{viewer.message}</p>
      <p>
        Public incident reads remain available; no browser state is treated as workflow authority.
      </p>
    </section>
  );
}

function SessionChip({ viewer }: { readonly viewer: WorkspaceViewer }) {
  const heading =
    viewer.kind === "authenticated"
      ? "Authenticated"
      : viewer.kind === "loading"
        ? "Checking session"
        : viewer.kind === "expired"
          ? "Credential rejected"
          : viewer.kind === "unauthenticated"
            ? "Unauthenticated"
            : "Session unavailable";
  const detail =
    viewer.kind === "authenticated"
      ? viewer.displayName
      : viewer.kind === "loading"
        ? "Waiting for identity"
        : viewer.kind === "expired"
          ? "Expired or invalid"
          : viewer.kind === "unauthenticated"
            ? "No verified operator"
            : "Identity unavailable";

  return (
    <div className="session-chip" data-session-kind={viewer.kind}>
      <span aria-hidden="true" className="session-chip__indicator" />
      <span>
        <strong>{heading}</strong>
        <span>{detail}</span>
      </span>
    </div>
  );
}

function StatePanel({
  heading,
  message,
  tone,
}: {
  readonly heading: string;
  readonly message: string;
  readonly tone: "error" | "neutral";
}) {
  return (
    <section
      aria-labelledby="workspace-state-title"
      className="panel state-panel"
      role={tone === "error" ? "alert" : "status"}
    >
      <p className="eyebrow">Workspace state</p>
      <h2 id="workspace-state-title">{heading}</h2>
      <p>{message}</p>
    </section>
  );
}

function PendingInvestigation({
  state,
}: {
  readonly state: Extract<IncidentWorkspaceViewState, { kind: "queued" | "running" }>;
}) {
  const queued = state.kind === "queued";
  const heading = queued ? "Investigation queued" : "Investigation in progress";
  const explanation = queued
    ? "A worker has not started this investigation. Evidence, deterministic results, and claims are not available yet."
    : state.incident.delayed
      ? "This investigation is delayed. The latest evidence or deterministic validation has not completed."
      : "Evidence collection and deterministic validation are still in progress.";

  return (
    <div className="pending-stack">
      <section aria-labelledby="pending-title" className="panel pending-panel" role="status">
        <div className="section-heading section-heading--wrap">
          <div>
            <p className="eyebrow">Current state</p>
            <h2 id="pending-title">{heading}</h2>
          </div>
          <StatusBadge value={state.kind} />
        </div>
        <p>{explanation}</p>
        <dl className="metadata-list">
          <div>
            <dt>Incident</dt>
            <dd>
              <code>{state.incident.id}</code>
            </dd>
          </div>
          <div>
            <dt>Alert</dt>
            <dd>{state.incident.alert_id}</dd>
          </div>
          <div>
            <dt>Last update</dt>
            <dd>
              <Timestamp value={state.incident.updated_at} />
            </dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="missing-title" className="panel">
        <p className="eyebrow">Incomplete investigation</p>
        <h2 id="missing-title">What is missing</h2>
        {state.incident.missing.length === 0 ? (
          <p>The next workflow record has not been persisted.</p>
        ) : (
          <ul className="plain-list">
            {state.incident.missing.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

function WorkspaceWarnings({
  states,
}: {
  readonly states: Extract<
    IncidentWorkspaceViewState,
    { kind: "workspace" }
  >["workspace"]["adverse_states"];
}) {
  if (states.length === 0) {
    return null;
  }

  return (
    <section aria-labelledby="conditions-title" className="panel adverse-panel">
      <p className="eyebrow">Uncertainty and missing records</p>
      <h2 id="conditions-title">Investigation conditions</h2>
      <ul className="adverse-list">
        {states.map((state) => (
          <li data-severity={state.severity} key={`${state.code}:${state.related_ids.join(":")}`}>
            <strong>{state.code.replaceAll("-", " ")}</strong>
            <p>{state.detail}</p>
            {state.related_ids.length === 0 ? null : (
              <p className="reason-codes">Related: {state.related_ids.join(", ")}</p>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

function WorkspaceContent({
  onRetry,
  recovery,
  responsePlan,
  state,
}: {
  readonly onRetry?: () => void;
  readonly recovery?: RecoveryVerificationProps;
  readonly responsePlan: ResponsePlanReviewProps;
  readonly state: IncidentWorkspaceViewState;
}) {
  switch (state.kind) {
    case "loading":
      return (
        <div aria-busy="true">
          <StatePanel heading="Loading incident" message={state.message} tone="neutral" />
        </div>
      );
    case "empty":
      return <StatePanel heading="No incidents" message={state.message} tone="neutral" />;
    case "fetch-error":
      return (
        <div className="state-stack">
          <StatePanel heading="Incident data unavailable" message={state.message} tone="error" />
          {onRetry === undefined ? null : (
            <button className="primary-button" onClick={onRetry} type="button">
              Try again
            </button>
          )}
        </div>
      );
    case "integrity-error":
      return (
        <div className="state-stack">
          <StatePanel
            heading="Incident replay could not be verified"
            message={state.message}
            tone="error"
          />
          <StatusBadge value="integrity-error" />
          <p className="state-detail">
            The workspace is withheld because the persisted incident and replay do not agree.
          </p>
        </div>
      );
    case "queued":
    case "running":
      return <PendingInvestigation state={state} />;
    case "workspace": {
      const { workspace } = state;
      if (workspace.overview.state === "invalid") {
        return (
          <StatePanel
            heading="Incident replay could not be verified"
            message="The workspace projection reported an integrity failure, so investigation details are withheld."
            tone="error"
          />
        );
      }

      return (
        <div className="workspace-page">
          <div className="workspace-content-grid">
            <div>
              <WorkspaceWarnings states={workspace.adverse_states} />
              <IncidentOverview workspace={workspace} />
            </div>
            <InvestigationTimeline
              entries={workspace.timeline}
              evidence={workspace.evidence.items}
            />
          </div>
          <div className="evidence-scope-grid">
            <ScopeView
              evidence={workspace.evidence.items}
              limitations={workspace.limitations}
              scope={workspace.scope}
            />
            <EvidenceView
              evidence={workspace.evidence.items}
              missingReferences={workspace.evidence.missing_references}
            />
          </div>
          <ResponsePlanReview
            {...responsePlan}
            key={
              responsePlan.state.kind === "ready"
                ? `plan:${responsePlan.state.review.plan.plan_sha256}:${responsePlan.state.review.state}`
                : `plan:${responsePlan.state.kind}`
            }
          />
          {recovery === undefined ? null : (
            <RecoveryVerification
              {...recovery}
              key={
                recovery.state.kind === "ready"
                  ? `recovery:${recovery.state.workspace.review.packet?.packet_sha256 ?? "pending"}:${recovery.state.workspace.review.state}`
                  : `recovery:${recovery.state.kind}`
              }
            />
          )}
        </div>
      );
    }
  }
}

export function inboxItemFromWorkspace(
  workspace: Extract<IncidentWorkspaceViewState, { kind: "workspace" }>["workspace"],
): IncidentInboxItem {
  return {
    alert_id: workspace.incident.alert_id,
    created_at: workspace.incident.created_at,
    delayed: false,
    id: workspace.incident.id,
    missing: [],
    status: workspace.incident.status,
    updated_at: workspace.incident.updated_at,
  };
}

export function IncidentWorkspaceShell({
  focusRequest = 0,
  incidents,
  onRetry,
  recovery,
  responsePlan,
  onSelectIncident,
  selectedIncidentId,
  state,
  viewer,
}: IncidentWorkspaceShellProps) {
  const mainRef = useRef<HTMLElement>(null);

  useEffect(() => {
    if (focusRequest > 0) mainRef.current?.focus();
  }, [focusRequest]);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#incident-content">
        Skip to incident details
      </a>
      <header className="app-header">
        <div>
          <p className="brand-mark">COLORTRACE</p>
          <h1>Incident workspace</h1>
        </div>
        <SessionChip viewer={viewer} />
      </header>

      <SessionStatus viewer={viewer} />
      <div className="app-layout">
        <IncidentInbox
          incidents={incidents}
          selectedIncidentId={selectedIncidentId}
          {...(onSelectIncident === undefined ? {} : { onSelectIncident })}
        />
        <main id="incident-content" ref={mainRef} tabIndex={-1}>
          <WorkspaceContent
            recovery={recovery}
            responsePlan={responsePlan}
            state={state}
            {...(onRetry === undefined ? {} : { onRetry })}
          />
        </main>
      </div>
    </div>
  );
}
