import type {
  ResponsePlan,
  ResponsePlanReview as ResponsePlanReviewRecord,
} from "@colortrace/api-client";
import { type KeyboardEvent, useEffect, useRef, useState } from "react";

import { StatusBadge } from "./status-badge.tsx";
import { Timestamp } from "./time.tsx";

export type ResponsePlanPanelState =
  | { readonly kind: "absent" }
  | { readonly kind: "error"; readonly message: string }
  | { readonly kind: "loading" }
  | { readonly kind: "ready"; readonly review: ResponsePlanReviewRecord };

export type ResponsePlanCapabilities = {
  readonly canApprove: boolean;
  readonly canEdit: boolean;
  readonly session: "active" | "expired" | "read-only";
};

export type ResponsePlanRevision = Pick<ResponsePlan, "commands" | "unresolved_acknowledged">;

export type ResponsePlanActionRecovery = {
  readonly kind: "mutation-failed" | "reconciliation-required";
  readonly onReconcile: () => void;
  readonly onRetry?: () => void;
};

export type ResponsePlanReviewProps = {
  readonly actionError: string | null;
  readonly busy: boolean;
  readonly capabilities: ResponsePlanCapabilities;
  readonly onApprove: (plan: ResponsePlan) => void;
  readonly onEdit: (plan: ResponsePlan, revision: ResponsePlanRevision) => void;
  readonly onReject: (
    plan: ResponsePlan,
    reason: "incorrect-command" | "insufficient-evidence" | "unresolved-risk" | "unsafe-scope",
  ) => void;
  readonly recovery?: ResponsePlanActionRecovery | null;
  readonly state: ResponsePlanPanelState;
};

type Action = "approve" | "edit" | "reject";

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/u;

function revisedCommands(
  plan: ResponsePlan,
  replacementResourceSha256: string,
): ResponsePlan["commands"] {
  return plan.commands.map((command) => ({
    ...command,
    action_envelope: {
      ...command.action_envelope,
      replacement_resource_sha256: replacementResourceSha256,
    },
  }));
}

function PlanTargets({ plan }: { readonly plan: ResponsePlan }) {
  return (
    <div className="plan-scope-grid">
      <section aria-labelledby="plan-targets-title" className="plan-subsection">
        <h3 id="plan-targets-title">Exact targets</h3>
        <ul className="plan-record-list">
          {plan.targets.map((target) => (
            <li key={`${target.kind}:${target.id}`}>
              <strong>{target.kind}</strong>
              <code>{target.id}</code>
            </li>
          ))}
        </ul>
      </section>
      <section aria-labelledby="plan-exclusions-title" className="plan-subsection">
        <h3 id="plan-exclusions-title">Protected exclusions</h3>
        <ul className="plan-record-list">
          {plan.exclusions.map((target) => (
            <li key={`${target.kind}:${target.id}`}>
              <strong>{target.kind}</strong>
              <code>{target.id}</code>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function PlanCommands({ plan }: { readonly plan: ResponsePlan }) {
  const envelope = plan.commands[0]?.action_envelope;
  if (envelope === undefined) return null;
  const envelopeBindings: readonly (readonly [string, string | number])[] = [
    ["Envelope schema", envelope.schema],
    ["Fixture", envelope.fixture_id],
    ["Fixture manifest", envelope.fixture_manifest_sha256],
    ["Fixture generation", envelope.fixture_generation],
    ["Source batch", envelope.source_batch_id],
    ["Source batch digest", envelope.source_batch_sha256],
    ["Runtime manifest", envelope.runtime_manifest_sha256],
    ["Runtime generation", envelope.runtime_generation],
    ["Publication pointer", envelope.expected_publication_pointer_sha256],
    ["Publication generation", envelope.expected_publication_generation],
    ["Expected active resource", envelope.expected_resource_sha256],
    ["Replacement destination", envelope.replacement_resource_logical_path],
    ["Approved replacement", envelope.replacement_resource_sha256],
    ["Declared resource manifest", envelope.declared_resource_manifest_sha256],
    ["OpenColorIO version", envelope.ocio_version],
    ["Preservation manifest", envelope.preservation_manifest_sha256],
    ["Safe complement", envelope.safe_complement_sha256],
    ["Lineage manifest", envelope.lineage_manifest_sha256],
    ["Lineage generation", envelope.lineage_generation],
  ];
  return (
    <div className="plan-command-stack">
      <section aria-labelledby="plan-envelope-title" className="plan-subsection">
        <h3 id="plan-envelope-title">Shared simulator action envelope</h3>
        <p className="plan-subsection__intro">
          Every command below carries this identical, approval-bound execution context.
        </p>
        <dl className="metadata-list metadata-list--compact plan-envelope-bindings">
          {envelopeBindings.map(([label, value]) => (
            <div key={label}>
              <dt>{label}</dt>
              <dd>
                <code>{value}</code>
              </dd>
            </div>
          ))}
        </dl>
      </section>
      <section aria-labelledby="plan-commands-title" className="plan-subsection">
        <h3 id="plan-commands-title">Typed simulator commands</h3>
        <ul className="plan-command-list">
          {plan.commands.map((command) => {
            const quarantine = "mode" in command;
            const derivative = "expected_derivative_sha256" in command;
            const bindings: (readonly [string, string])[] = [
              ["Command schema", command.schema],
              ["Namespace", command.namespace],
              ["Target kind", command.target.kind],
              ["Target identifier", command.target.id],
            ];
            if (quarantine) {
              bindings.push(
                ["Mode", command.mode],
                ["Expected old resource", command.expected_resource_sha256],
              );
            } else {
              bindings.push(
                ["Job", command.job_id],
                ["Transform", command.transform_id],
                ["Source", command.source_id],
                ["Source manifest", command.source_manifest_sha256],
                ["Source PNG", command.source_png_sha256],
                ["Expected config", command.expected_config_sha256],
                ["Lineage parent", command.lineage_parent_artifact_id],
              );
              if (derivative) {
                bindings.push(
                  ["Expected derivative", command.expected_derivative_sha256],
                  ["Expected derivative display", command.expected_derivative_display_sha256],
                );
              } else {
                bindings.push(
                  ["Expected output", command.expected_output_sha256],
                  ["Expected display", command.expected_display_sha256],
                );
              }
            }
            return (
              <li key={command.command_id}>
                <div className="section-heading section-heading--wrap">
                  <div>
                    <strong>
                      {quarantine
                        ? "Quarantine and replace LUT"
                        : derivative
                          ? "Derivative rerender binding"
                          : "Frame rerender binding"}
                    </strong>
                    <code>{command.command_id}</code>
                  </div>
                  <StatusBadge value={command.target.kind} />
                </div>
                <dl className="metadata-list metadata-list--compact">
                  {bindings.map(([label, value]) => (
                    <div key={label}>
                      <dt>{label}</dt>
                      <dd>
                        <code>{value}</code>
                      </dd>
                    </div>
                  ))}
                </dl>
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
}

function PlanUncertainty({ plan }: { readonly plan: ResponsePlan }) {
  const groups = [
    {
      description: "Non-blocking items require an explicit acknowledgement before approval.",
      id: "plan-unresolved-title",
      items: plan.unresolved_item_ids,
      title: "Unresolved items",
    },
    {
      description: "Any listed blocker prohibits approval even when acknowledged.",
      id: "plan-blockers-title",
      items: plan.blocking_unresolved_item_ids,
      title: "Blocking unresolved items",
    },
    {
      description: "Any unknown target prohibits approval and dispatch.",
      id: "plan-unknown-title",
      items: plan.unknown_target_ids,
      title: "Unknown targets",
    },
  ] as const;
  return (
    <section aria-labelledby="plan-uncertainty-title" className="plan-subsection">
      <h3 id="plan-uncertainty-title">Approval uncertainty</h3>
      <div className="plan-uncertainty-grid">
        {groups.map((group) => (
          <section aria-labelledby={group.id} key={group.id}>
            <h4 id={group.id}>{group.title}</h4>
            <p>{group.description}</p>
            {group.items.length === 0 ? (
              <p>None.</p>
            ) : (
              <ul className="plan-record-list">
                {group.items.map((item) => (
                  <li key={item}>
                    <code>{item}</code>
                  </li>
                ))}
              </ul>
            )}
          </section>
        ))}
      </div>
    </section>
  );
}

function Confirmation({
  action,
  busy,
  onCancel,
  onConfirm,
  plan,
  revision,
}: {
  readonly action: Action;
  readonly busy: boolean;
  readonly onCancel: () => void;
  readonly onConfirm: () => void;
  readonly plan: ResponsePlan;
  readonly revision: ResponsePlanRevision;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => confirmRef.current?.focus(), []);
  const verb = action === "approve" ? "Approve" : action === "reject" ? "Reject" : "Revise";
  const acknowledgement =
    action === "edit" ? revision.unresolved_acknowledged : plan.unresolved_acknowledged;

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
      aria-labelledby="plan-confirm-title"
      aria-modal="true"
      className="plan-confirm"
      onKeyDown={trapKeyboardFocus}
      role="alertdialog"
    >
      <p className="eyebrow">Human authority confirmation</p>
      <h3 id="plan-confirm-title">
        {verb} exact plan version {plan.version}?
      </h3>
      <p>
        This decision binds plan <code>{plan.plan_sha256}</code>, {plan.targets.length} targets,{" "}
        {plan.commands.length} typed commands, and the unresolved acknowledgement set to{" "}
        <strong>{acknowledgement ? "yes" : "no"}</strong>.
      </p>
      <dl className="plan-confirm__uncertainty">
        <div>
          <dt>Unresolved items</dt>
          <dd>
            {plan.unresolved_item_ids.length === 0 ? "None" : plan.unresolved_item_ids.join(", ")}
          </dd>
        </div>
        <div>
          <dt>Blocking items</dt>
          <dd>
            {plan.blocking_unresolved_item_ids.length === 0
              ? "None"
              : plan.blocking_unresolved_item_ids.join(", ")}
          </dd>
        </div>
        <div>
          <dt>Unknown targets</dt>
          <dd>
            {plan.unknown_target_ids.length === 0 ? "None" : plan.unknown_target_ids.join(", ")}
          </dd>
        </div>
      </dl>
      {action === "edit" ? (
        <p>
          The new immutable version will bind replacement resource{" "}
          <code>{revision.commands[0]?.action_envelope.replacement_resource_sha256}</code>. Creating
          it invalidates any approval for this version.
        </p>
      ) : null}
      <div className="plan-confirm__actions">
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
          {busy ? "Recording…" : `Confirm ${verb.toLowerCase()}`}
        </button>
      </div>
    </div>
  );
}

export function ResponsePlanReview({
  actionError,
  busy,
  capabilities,
  onApprove,
  onEdit,
  onReject,
  recovery = null,
  state,
}: ResponsePlanReviewProps) {
  const [confirmation, setConfirmation] = useState<Action | null>(null);
  const [reason, setReason] = useState<
    "incorrect-command" | "insufficient-evidence" | "unresolved-risk" | "unsafe-scope"
  >("unsafe-scope");
  const [replacementResourceSha256, setReplacementResourceSha256] = useState("");
  const [unresolvedAcknowledged, setUnresolvedAcknowledged] = useState(false);
  const returnFocusRef = useRef<HTMLButtonElement | null>(null);
  const restoreFocusRef = useRef(false);
  const observedPlanHashRef = useRef<string | null>(null);
  const activePlan = state.kind === "ready" ? state.review.plan : null;
  const activePlanHash = activePlan?.plan_sha256 ?? null;
  const activeReplacement = activePlan?.commands[0]?.action_envelope.replacement_resource_sha256;
  const activeAcknowledgement = activePlan?.unresolved_acknowledged ?? false;

  useEffect(() => {
    setReplacementResourceSha256(activeReplacement ?? "");
    setUnresolvedAcknowledged(activeAcknowledgement);
    if (
      activePlanHash !== null &&
      observedPlanHashRef.current !== null &&
      observedPlanHashRef.current !== activePlanHash
    ) {
      setConfirmation(null);
    }
    if (activePlanHash !== null) observedPlanHashRef.current = activePlanHash;
  }, [activeAcknowledgement, activePlanHash, activeReplacement]);

  useEffect(() => {
    if (confirmation !== null || !restoreFocusRef.current) return;
    restoreFocusRef.current = false;
    returnFocusRef.current?.focus();
  }, [confirmation]);

  const openConfirmation = (action: Action, trigger: HTMLButtonElement) => {
    returnFocusRef.current = trigger;
    setConfirmation(action);
  };
  const closeConfirmation = () => {
    restoreFocusRef.current = true;
    setConfirmation(null);
  };

  if (state.kind === "loading") {
    return (
      <section aria-busy="true" className="panel plan-panel">
        <p>Loading response plan.</p>
      </section>
    );
  }
  if (state.kind === "absent") {
    return (
      <section aria-labelledby="response-plan-title" className="panel plan-panel">
        <p className="eyebrow">Human authority</p>
        <h2 id="response-plan-title">Response plan pending</h2>
        <p>No immutable plan version has been recorded for this incident.</p>
      </section>
    );
  }
  if (state.kind === "error") {
    return (
      <section aria-labelledby="response-plan-title" className="panel plan-panel" role="alert">
        <p className="eyebrow">Human authority</p>
        <h2 id="response-plan-title">Response plan unavailable</h2>
        <p>{state.message}</p>
      </section>
    );
  }

  const { plan } = state.review;
  const revision: ResponsePlanRevision = {
    commands: revisedCommands(plan, replacementResourceSha256),
    unresolved_acknowledged: unresolvedAcknowledged,
  };
  const revisionValid = SHA256_PATTERN.test(replacementResourceSha256);
  const revisionChanged =
    replacementResourceSha256 !== plan.commands[0]?.action_envelope.replacement_resource_sha256 ||
    unresolvedAcknowledged !== plan.unresolved_acknowledged;
  const mutable = state.review.state !== "stale";
  const approvalPending = state.review.state === "pending";
  return (
    <section aria-labelledby="response-plan-title" className="panel plan-panel">
      <div className="section-heading section-heading--wrap">
        <div>
          <p className="eyebrow">Human authority</p>
          <h2 id="response-plan-title">Response plan review</h2>
        </div>
        <StatusBadge value={state.review.state} />
      </div>
      <dl className="metadata-list plan-identity">
        <div>
          <dt>Plan version</dt>
          <dd>{plan.version}</dd>
        </div>
        <div>
          <dt>Incident version</dt>
          <dd>{plan.incident_version}</dd>
        </div>
        <div>
          <dt>Plan hash</dt>
          <dd>
            <code>{plan.plan_sha256}</code>
          </dd>
        </div>
        <div>
          <dt>Packet hash</dt>
          <dd>
            <code>{plan.response_packet_sha256}</code>
          </dd>
        </div>
        <div>
          <dt>Scope hash</dt>
          <dd>
            <code>{plan.deterministic_scope_sha256}</code>
          </dd>
        </div>
        <div>
          <dt>Created</dt>
          <dd>
            <Timestamp value={plan.created_at} />
          </dd>
        </div>
      </dl>

      {state.review.state === "stale" ? (
        <p className="plan-warning" role="alert">
          The incident advanced to version {state.review.current_incident_version}. This plan is
          stale and cannot be decided or dispatched.
        </p>
      ) : null}
      {state.review.decision === null ? (
        <p className="plan-note">No decision has been recorded for this immutable version.</p>
      ) : (
        <p className="plan-note">
          {state.review.decision.outcome === "approved" ? "Approved" : "Rejected"} by{" "}
          <code>{state.review.decision.actor.subject}</code> at{" "}
          <Timestamp value={state.review.decision.decided_at} />.
        </p>
      )}

      <PlanUncertainty plan={plan} />
      <PlanTargets plan={plan} />
      <PlanCommands plan={plan} />

      <section aria-labelledby="approval-controls-title" className="plan-controls">
        <h3 id="approval-controls-title">Review controls</h3>
        {capabilities.session === "expired" ? (
          <p role="alert">
            The operator credential expired or was rejected. Controls remain disabled.
          </p>
        ) : capabilities.session === "read-only" ? (
          <p>Sign in with a verified human role to edit or decide this plan.</p>
        ) : null}
        <fieldset
          className="plan-revision-fields"
          disabled={!mutable || !capabilities.canEdit || busy}
        >
          <legend>Typed revision</legend>
          <label>
            Approved replacement SHA-256
            <input
              aria-describedby="replacement-resource-help"
              onChange={(event) => setReplacementResourceSha256(event.currentTarget.value)}
              pattern="sha256:[0-9a-f]{64}"
              spellCheck={false}
              type="text"
              value={replacementResourceSha256}
            />
          </label>
          <p id="replacement-resource-help">
            A revision updates this exact simulator action-envelope digest across every typed
            command. The deterministic target and exclusion scope remains fixed.
          </p>
          {plan.unresolved_item_ids.length === 0 ? null : (
            <label className="plan-revision-fields__checkbox">
              <input
                checked={unresolvedAcknowledged}
                onChange={(event) => setUnresolvedAcknowledged(event.currentTarget.checked)}
                type="checkbox"
              />
              Acknowledge all listed unresolved items for this version
            </label>
          )}
        </fieldset>
        <div className="plan-controls__buttons">
          <button
            className="primary-button"
            disabled={!mutable || !approvalPending || !capabilities.canApprove || busy}
            onClick={(event) => openConfirmation("approve", event.currentTarget)}
            type="button"
          >
            Approve exact plan
          </button>
          <label>
            Rejection reason
            <select
              disabled={!mutable || !approvalPending || !capabilities.canApprove || busy}
              onChange={(event) => setReason(event.currentTarget.value as typeof reason)}
              value={reason}
            >
              <option value="unsafe-scope">Unsafe scope</option>
              <option value="insufficient-evidence">Insufficient evidence</option>
              <option value="incorrect-command">Incorrect command</option>
              <option value="unresolved-risk">Unresolved risk</option>
            </select>
          </label>
          <button
            className="danger-button"
            disabled={!mutable || !approvalPending || !capabilities.canApprove || busy}
            onClick={(event) => openConfirmation("reject", event.currentTarget)}
            type="button"
          >
            Reject plan
          </button>
          <button
            className="secondary-button"
            disabled={
              !mutable || !capabilities.canEdit || busy || !revisionValid || !revisionChanged
            }
            onClick={(event) => openConfirmation("edit", event.currentTarget)}
            type="button"
          >
            Create revised version
          </button>
        </div>
        {actionError === null ? null : (
          <p className="plan-warning" role="alert">
            {actionError}
          </p>
        )}
        {recovery === null ? null : (
          <fieldset className="plan-recovery">
            <legend className="sr-only">Plan action recovery</legend>
            {recovery.kind === "mutation-failed" && recovery.onRetry !== undefined ? (
              <button
                className="secondary-button"
                disabled={busy || capabilities.session !== "active"}
                onClick={recovery.onRetry}
                type="button"
              >
                Retry exact action
              </button>
            ) : null}
            <button
              className="secondary-button"
              disabled={busy}
              onClick={recovery.onReconcile}
              type="button"
            >
              Reconcile plan state
            </button>
          </fieldset>
        )}
      </section>

      {confirmation === null ? null : (
        <Confirmation
          action={confirmation}
          busy={busy}
          onCancel={closeConfirmation}
          onConfirm={() => {
            closeConfirmation();
            if (confirmation === "approve") onApprove(plan);
            else if (confirmation === "reject") onReject(plan, reason);
            else onEdit(plan, revision);
          }}
          plan={plan}
          revision={revision}
        />
      )}
    </section>
  );
}
