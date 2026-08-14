import type { RecoveryReview } from "@colortrace/api-client";
import type {
  RecoveryCheckName,
  RecoveryEvidenceRecord,
  RecoveryVerificationArtifact,
  RecoveryWorkspace,
} from "@colortrace/workspace-model";
import { type KeyboardEvent, useEffect, useRef, useState } from "react";

import { StatusBadge } from "./status-badge.tsx";
import { Timestamp } from "./time.tsx";

export type RecoveryPanelState =
  | { readonly kind: "absent" }
  | { readonly kind: "error"; readonly message: string }
  | { readonly kind: "integrity-error"; readonly message: string }
  | { readonly kind: "loading" }
  | {
      readonly kind: "ready";
      readonly workspace: Extract<RecoveryWorkspace, { integrity: "verified" }>;
    };

export type RecoveryCapabilities = {
  readonly canClose: boolean;
  readonly session: "active" | "expired" | "read-only";
};

export type RecoveryActionRecovery = {
  readonly kind: "mutation-failed" | "reconciliation-required";
  readonly onReconcile: () => void;
  readonly onRetry?: () => void;
};

export type RecoveryVerificationProps = {
  readonly actionError: string | null;
  readonly busy: boolean;
  readonly capabilities: RecoveryCapabilities;
  readonly onClose: (review: RecoveryReview, reason: string) => void;
  readonly recovery?: RecoveryActionRecovery | null;
  readonly state: RecoveryPanelState;
};

const CHECK_LABEL: Readonly<Record<RecoveryCheckName, string>> = {
  "active-publication": "Active publication",
  "approved-resource-state": "Approved resource state",
  "declared-reference-recovery": "Declared reference recovery",
  "exact-typed-lineage": "Exact typed lineage",
  "approved-recovery-scope": "Approved recovery scope",
  "safe-complement-preservation": "Safe complement preservation",
  "post-action-telemetry-correlation": "Post-action telemetry correlation",
};

function anchorId(kind: "artifact" | "evidence", id: string): string {
  const encoded = Array.from(id, (character) => character.codePointAt(0)?.toString(16)).join("-");
  return `recovery-${kind}-${encoded}`;
}

function CitationLinks({
  artifactIds,
  evidenceIds,
}: {
  readonly artifactIds: readonly string[];
  readonly evidenceIds: readonly string[];
}) {
  if (artifactIds.length === 0 && evidenceIds.length === 0) return <p>No cited records.</p>;
  return (
    <ul aria-label="Verification citations" className="recovery-citations">
      {evidenceIds.map((id) => (
        <li key={`evidence:${id}`}>
          <a href={`#${anchorId("evidence", id)}`}>
            <span>Post-action evidence</span>
            <code>{id}</code>
          </a>
        </li>
      ))}
      {artifactIds.map((id) => (
        <li key={`artifact:${id}`}>
          <a href={`#${anchorId("artifact", id)}`}>
            <span>Verification artifact</span>
            <code>{id}</code>
          </a>
        </li>
      ))}
    </ul>
  );
}

function VerificationChecks({
  review,
}: {
  readonly review: Extract<RecoveryWorkspace, { integrity: "verified" }>["review"];
}) {
  const packet = review.packet;
  if (packet === null) {
    return (
      <section aria-labelledby="recovery-checks-title" className="recovery-subsection">
        <h3 id="recovery-checks-title">Post-action verification</h3>
        <p>
          The immutable execution snapshot is available, but no verification packet has completed.
          Human closure remains unavailable.
        </p>
      </section>
    );
  }
  return (
    <section aria-labelledby="recovery-checks-title" className="recovery-subsection">
      <div className="section-heading section-heading--wrap">
        <div>
          <h3 id="recovery-checks-title">Post-action verification</h3>
          <p>
            Deterministic check states are displayed from the immutable recovery packet. The browser
            does not derive verification.
          </p>
        </div>
        <StatusBadge value={packet.status} />
      </div>
      <ol className="recovery-check-list">
        {packet.check_results.map((result) => (
          <li data-check-state={result.state} key={result.check}>
            <div className="section-heading section-heading--wrap">
              <div>
                <strong>{CHECK_LABEL[result.check]}</strong>
                <code>{result.policy}</code>
              </div>
              <StatusBadge value={result.state} />
            </div>
            {result.reason_codes.length === 0 ? (
              <p>No adverse reason codes.</p>
            ) : (
              <p className="reason-codes">Reasons: {result.reason_codes.join(", ")}</p>
            )}
            <CitationLinks artifactIds={result.artifact_ids} evidenceIds={result.evidence_ids} />
          </li>
        ))}
      </ol>
    </section>
  );
}

function EvidenceRecord({ record }: { readonly record: RecoveryEvidenceRecord }) {
  return (
    <li className="recovery-record" id={anchorId("evidence", record.evidence_id)} tabIndex={-1}>
      <div className="section-heading section-heading--wrap">
        <div>
          <strong>{record.source_label}</strong>
          <code>{record.evidence_id}</code>
        </div>
        <StatusBadge value={record.freshness} />
      </div>
      <p>{record.display_excerpt}</p>
      <dl className="metadata-list metadata-list--compact">
        <div>
          <dt>Observed</dt>
          <dd>
            <Timestamp value={record.observed_at} />
          </dd>
        </div>
        <div>
          <dt>Retrieved</dt>
          <dd>
            <Timestamp value={record.retrieved_at} />
          </dd>
        </div>
        <div>
          <dt>Signal</dt>
          <dd>{record.signal}</dd>
        </div>
        <div>
          <dt>Subject</dt>
          <dd>
            {record.subject_kind}: <code>{record.subject_id}</code>
          </dd>
        </div>
        <div>
          <dt>Record digest</dt>
          <dd>
            <code>{record.evidence_sha256}</code>
          </dd>
        </div>
      </dl>
    </li>
  );
}

function ArtifactRecord({ artifact }: { readonly artifact: RecoveryVerificationArtifact }) {
  return (
    <li className="recovery-record" id={anchorId("artifact", artifact.artifact_id)} tabIndex={-1}>
      <div className="section-heading section-heading--wrap">
        <div>
          <strong>{artifact.role.replaceAll("-", " ")}</strong>
          <code>{artifact.artifact_id}</code>
        </div>
        {artifact.target === null ? null : <StatusBadge value={artifact.target.kind} />}
      </div>
      <dl className="metadata-list metadata-list--compact">
        <div>
          <dt>Content digest</dt>
          <dd>
            <code>{artifact.sha256}</code>
          </dd>
        </div>
        <div>
          <dt>Publication pointer</dt>
          <dd>
            <code>{artifact.publication_pointer_sha256}</code>
          </dd>
        </div>
        <div>
          <dt>Bytes</dt>
          <dd>{artifact.size}</dd>
        </div>
      </dl>
    </li>
  );
}

function ClosureConfirmation({
  busy,
  onCancel,
  onConfirm,
  reason,
  review,
}: {
  readonly busy: boolean;
  readonly onCancel: () => void;
  readonly onConfirm: () => void;
  readonly reason: string;
  readonly review: RecoveryReview;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => confirmRef.current?.focus(), []);
  const packet = review.packet;
  if (packet === null) return null;

  const trapKeyboardFocus = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape" && !busy) {
      event.preventDefault();
      event.stopPropagation();
      onCancel();
      return;
    }
    if (event.key !== "Tab") return;
    const cancel = cancelRef.current;
    const confirm = confirmRef.current;
    if (cancel === null || confirm === null) return;
    if (event.shiftKey && document.activeElement === cancel) {
      event.preventDefault();
      confirm.focus();
    } else if (!event.shiftKey && document.activeElement === confirm) {
      event.preventDefault();
      cancel.focus();
    }
  };

  return (
    <div
      aria-labelledby="recovery-confirm-title"
      aria-modal="true"
      className="recovery-confirm"
      onKeyDown={trapKeyboardFocus}
      role="alertdialog"
    >
      <p className="eyebrow">Human closure confirmation</p>
      <h3 id="recovery-confirm-title">Close this exact verified recovery?</h3>
      <p>
        This decision binds incident version {review.current_incident_version}, workflow version{" "}
        {review.workflow_version}, packet <code>{packet.packet_sha256}</code>, and outcome{" "}
        <code>{packet.outcome_sha256}</code>.
      </p>
      <p>
        <strong>Reason:</strong> {reason}
      </p>
      <div className="recovery-confirm__actions">
        <button
          className="secondary-button"
          disabled={busy}
          onClick={onCancel}
          ref={cancelRef}
          type="button"
        >
          Cancel
        </button>
        <button
          className="primary-button"
          disabled={busy}
          onClick={onConfirm}
          ref={confirmRef}
          type="button"
        >
          {busy ? "Recording…" : "Confirm closure"}
        </button>
      </div>
    </div>
  );
}

function HumanClosure({
  actionError,
  busy,
  capabilities,
  onClose,
  recovery,
  review,
}: Omit<RecoveryVerificationProps, "state"> & { readonly review: RecoveryReview }) {
  const [reason, setReason] = useState("");
  const [confirmation, setConfirmation] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const restoreFocusRef = useRef(false);
  useEffect(() => {
    if (confirmation || !restoreFocusRef.current) return;
    restoreFocusRef.current = false;
    triggerRef.current?.focus();
  }, [confirmation]);

  const packet = review.packet;
  const closure = review.closure;
  if (closure !== null) {
    return (
      <section aria-labelledby="recovery-closure-title" className="recovery-subsection">
        <div className="section-heading section-heading--wrap">
          <div>
            <h3 id="recovery-closure-title">Human closure</h3>
            <p>The verified recovery has one immutable human closure record.</p>
          </div>
          <StatusBadge value="closed" />
        </div>
        <dl className="metadata-list">
          <div>
            <dt>Closed by</dt>
            <dd>
              {closure.actor.display_name} (<code>{closure.actor.subject}</code>)
            </dd>
          </div>
          <div>
            <dt>Closed at</dt>
            <dd>
              <Timestamp value={closure.closed_at} />
            </dd>
          </div>
          <div>
            <dt>Reason</dt>
            <dd>{closure.reason}</dd>
          </div>
          <div>
            <dt>Closure digest</dt>
            <dd>
              <code>{closure.closure_sha256}</code>
            </dd>
          </div>
        </dl>
      </section>
    );
  }

  const verified =
    review.state === "recovery_verified" &&
    packet?.status === "recovery_verified" &&
    packet.eligible_for_closure;
  const awaitingReconciliation = recovery !== null && recovery !== undefined;
  const reasonValid = reason.trim() === reason && reason.length > 0 && reason.length <= 512;
  return (
    <section aria-labelledby="recovery-closure-title" className="recovery-subsection">
      <h3 id="recovery-closure-title">Human closure</h3>
      {!verified ? (
        <p className="recovery-warning" role="status">
          Closure is unavailable. Only a current recovery_verified packet may be human-closed.
        </p>
      ) : capabilities.session === "expired" ? (
        <p className="recovery-warning" role="alert">
          The operator credential expired or was rejected. Closure remains disabled.
        </p>
      ) : capabilities.session === "read-only" ? (
        <p>Sign in with a verified human recovery.closer role to close this recovery.</p>
      ) : !capabilities.canClose ? (
        <p>The verified human session does not hold the recovery.closer role.</p>
      ) : null}
      <label className="recovery-reason">
        Closure reason
        <textarea
          disabled={!verified || !capabilities.canClose || busy || awaitingReconciliation}
          maxLength={512}
          onChange={(event) => setReason(event.currentTarget.value)}
          rows={3}
          value={reason}
        />
      </label>
      <p className="field-help">Required, 1–512 characters. This exact text is audited.</p>
      <button
        className="primary-button"
        disabled={
          !verified || !capabilities.canClose || busy || awaitingReconciliation || !reasonValid
        }
        onClick={() => setConfirmation(true)}
        ref={triggerRef}
        type="button"
      >
        Close verified recovery
      </button>
      {actionError === null ? null : (
        <p className="recovery-warning" role="alert">
          {actionError}
        </p>
      )}
      {recovery === null || recovery === undefined ? null : (
        <fieldset className="recovery-action-recovery">
          <legend className="sr-only">Closure action recovery</legend>
          {recovery.kind === "mutation-failed" && recovery.onRetry !== undefined ? (
            <button
              className="secondary-button"
              disabled={busy || capabilities.session !== "active" || !capabilities.canClose}
              onClick={recovery.onRetry}
              type="button"
            >
              Retry exact closure
            </button>
          ) : null}
          <button
            className="secondary-button"
            disabled={busy}
            onClick={recovery.onReconcile}
            type="button"
          >
            Reconcile recovery state
          </button>
        </fieldset>
      )}
      {!confirmation || packet === null ? null : (
        <ClosureConfirmation
          busy={busy}
          onCancel={() => {
            restoreFocusRef.current = true;
            setConfirmation(false);
          }}
          onConfirm={() => {
            restoreFocusRef.current = true;
            setConfirmation(false);
            onClose(review, reason);
          }}
          reason={reason}
          review={review}
        />
      )}
    </section>
  );
}

export function RecoveryVerification({
  actionError,
  busy,
  capabilities,
  onClose,
  recovery = null,
  state,
}: RecoveryVerificationProps) {
  if (state.kind === "loading") {
    return (
      <section aria-busy="true" className="panel recovery-panel">
        <p>Loading recovery verification.</p>
      </section>
    );
  }
  if (state.kind === "absent") {
    return (
      <section aria-labelledby="recovery-title" className="panel recovery-panel">
        <p className="eyebrow">Post-action authority</p>
        <h2 id="recovery-title">Recovery verification pending</h2>
        <p>No durable recovery workflow exists for this incident. Closure is unavailable.</p>
      </section>
    );
  }
  if (state.kind === "error" || state.kind === "integrity-error") {
    return (
      <section aria-labelledby="recovery-title" className="panel recovery-panel" role="alert">
        <p className="eyebrow">Post-action authority</p>
        <h2 id="recovery-title">
          {state.kind === "integrity-error"
            ? "Recovery verification could not be verified"
            : "Recovery verification unavailable"}
        </h2>
        <p>{state.message}</p>
        <p>No closure control is available while authoritative recovery state is unavailable.</p>
      </section>
    );
  }

  const { review } = state.workspace;
  const outcome = review.snapshot.action_outcome;
  return (
    <section aria-labelledby="recovery-title" className="panel recovery-panel">
      <div className="section-heading section-heading--wrap">
        <div>
          <p className="eyebrow">Post-action authority</p>
          <h2 id="recovery-title">Recovery verification and closure</h2>
        </div>
        <StatusBadge value={review.state} />
      </div>

      <section aria-labelledby="execution-record-title" className="recovery-subsection">
        <h3 id="execution-record-title">Execution record</h3>
        <p className="recovery-execution-note">
          Simulator execution succeeded. Command success alone does not establish recovery.
        </p>
        <dl className="metadata-list">
          <div>
            <dt>Action</dt>
            <dd>
              <code>{outcome.action_id}</code>
            </dd>
          </div>
          <div>
            <dt>Outcome digest</dt>
            <dd>
              <code>{outcome.outcome_sha256}</code>
            </dd>
          </div>
          <div>
            <dt>Action started</dt>
            <dd>
              <Timestamp value={outcome.action_started_at} />
            </dd>
          </div>
          <div>
            <dt>Execution completed</dt>
            <dd>
              <Timestamp value={outcome.completed_at} />
            </dd>
          </div>
          <div>
            <dt>Plan</dt>
            <dd>
              Version {outcome.plan_version} · <code>{outcome.plan_sha256}</code>
            </dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="safe-work-title" className="recovery-subsection recovery-safe-work">
        <h3 id="safe-work-title">Safe work preservation</h3>
        <p>
          Safe-work state is explicit; it is never inferred from missing observations. The active
          publication and packet determine the displayed verification state.
        </p>
        <dl className="metadata-list">
          <div>
            <dt>Before action</dt>
            <dd>
              <code>{outcome.safe_complement_before_sha256}</code>
            </dd>
          </div>
          <div>
            <dt>After action</dt>
            <dd>
              <code>{outcome.safe_complement_after_sha256}</code>
            </dd>
          </div>
          <div>
            <dt>Observed active state</dt>
            <dd>
              <code>{review.snapshot.active_publication.safe_complement_sha256}</code>
            </dd>
          </div>
          <div>
            <dt>Preservation proof</dt>
            <dd>
              <code>{outcome.safe_complement_proof_sha256}</code>
            </dd>
          </div>
        </dl>
      </section>

      <VerificationChecks review={review} />

      <details className="recovery-records">
        <summary>Open cited evidence and artifact records</summary>
        <section aria-labelledby="recovery-evidence-title">
          <h3 id="recovery-evidence-title">Post-action evidence</h3>
          {review.evidence_records.length === 0 ? (
            <p>No evidence records have been persisted.</p>
          ) : (
            <ul className="recovery-record-list">
              {review.evidence_records.map((record) => (
                <EvidenceRecord key={record.evidence_id} record={record} />
              ))}
            </ul>
          )}
        </section>
        <section aria-labelledby="recovery-artifacts-title">
          <h3 id="recovery-artifacts-title">Verification artifacts</h3>
          <ul className="recovery-record-list">
            {review.snapshot.verification_artifacts.map((artifact) => (
              <ArtifactRecord artifact={artifact} key={artifact.artifact_id} />
            ))}
          </ul>
        </section>
      </details>

      <HumanClosure
        actionError={actionError}
        busy={busy}
        capabilities={capabilities}
        onClose={onClose}
        recovery={recovery}
        review={review as RecoveryReview}
      />
    </section>
  );
}
