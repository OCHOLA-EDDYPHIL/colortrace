import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  type DemoAdapter,
  DemoApiError,
  type DemoInvestigationProof,
  type DemoPhase,
  type DemoReceipt,
  type DemoReset,
  type DemoRun,
  type DemoVisualKind,
  DEMO_APPROVAL_PHRASE,
  type VerifiedDemoVisual,
  verifyDemoReceiptIntegrity,
} from "./demo-api.ts";

const SESSION_RUN_KEY = "colortrace.demo.run-id";
const SESSION_NONCE_KEY = "colortrace.demo.approval-nonce";
const SESSION_START_KEY = "colortrace.demo.start-idempotency-key";
const SESSION_RESET_KEY = "colortrace.demo.reset-idempotency-key";
const REQUIRED_APPROVAL_VISUALS: readonly DemoVisualKind[] = ["expected", "observed", "diff"];
const RECONCILE_INTERVAL_MILLISECONDS = 1_000;

const CANONICAL_SCOPE = {
  affected: ["job-b-01", "job-b-02", "job-b-03"],
  derivative: ["artifact-b-02-derivative"],
  safe: ["job-a-01", "job-a-02", "job-b-04"],
  unknown: [] as readonly string[],
} as const;

const TIMELINE = [
  { key: "alert", label: "Alert", detail: "Canonical scenario initialized" },
  { key: "investigation", label: "Investigation", detail: "Facade preparation completed" },
  { key: "plan", label: "Plan", detail: "Returned plan bindings ready" },
  { key: "approval", label: "Approval", detail: "Human boundary confirmation" },
  { key: "action", label: "Action", detail: "Bound simulator action" },
  { key: "recovery", label: "Recovery", detail: "Recovered output verified" },
  { key: "closure", label: "Closure", detail: "Immutable receipt recorded" },
] as const;

type DemoSessionStorage = Pick<Storage, "getItem" | "removeItem" | "setItem">;
type TimelineState = "complete" | "current" | "waiting" | "stopped";
type DecodedVisual = Pick<VerifiedDemoVisual, "sha256" | "src">;
type VisualFailure = {
  readonly sha256: string;
  readonly message: string;
};

export type ShotSafeColorRecoveryAppProps = {
  readonly adapter: DemoAdapter;
  readonly storage?: DemoSessionStorage;
};

type StoredSession = {
  readonly runId: string | null;
  readonly nonce: string | null;
  readonly startKey: string | null;
  readonly resetKey: string | null;
};

function readSession(storage: DemoSessionStorage): StoredSession {
  try {
    return {
      runId: storage.getItem(SESSION_RUN_KEY),
      nonce: storage.getItem(SESSION_NONCE_KEY),
      startKey: storage.getItem(SESSION_START_KEY),
      resetKey: storage.getItem(SESSION_RESET_KEY),
    };
  } catch {
    return { runId: null, nonce: null, startKey: null, resetKey: null };
  }
}

function persistPendingStart(
  storage: DemoSessionStorage,
  nonce: string,
  idempotencyKey: string,
): boolean {
  try {
    storage.setItem(SESSION_NONCE_KEY, nonce);
    storage.setItem(SESSION_START_KEY, idempotencyKey);
    return true;
  } catch {
    return false;
  }
}

function persistRun(storage: DemoSessionStorage, runId: string, nonce: string | null): void {
  try {
    storage.setItem(SESSION_RUN_KEY, runId);
    if (nonce === null) storage.removeItem(SESSION_NONCE_KEY);
    else storage.setItem(SESSION_NONCE_KEY, nonce);
    storage.removeItem(SESSION_START_KEY);
  } catch {
    // Failure to persist can only remove recovery convenience; authority remains fail-closed.
  }
}

function persistResetKey(storage: DemoSessionStorage, idempotencyKey: string): boolean {
  try {
    storage.setItem(SESSION_RESET_KEY, idempotencyKey);
    return true;
  } catch {
    return false;
  }
}

function clearSession(storage: DemoSessionStorage): void {
  try {
    storage.removeItem(SESSION_RUN_KEY);
    storage.removeItem(SESSION_NONCE_KEY);
    storage.removeItem(SESSION_START_KEY);
    storage.removeItem(SESSION_RESET_KEY);
  } catch {
    // A blocked storage API must not alter the server-side workflow.
  }
}

function mutationKey(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

function newApprovalNonce(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

function shortDigest(value: string | null | undefined): string {
  if (value === null || value === undefined) return "Not available";
  return `${value.slice(0, 15)}…${value.slice(-8)}`;
}

function errorMessage(error: unknown, action: "load" | "mutate" | "start"): string {
  if (error instanceof DemoApiError) {
    if (error.code === "demo-active-run-exists") {
      const identity = error.runId === null ? "" : ` Run ${error.runId} remains active.`;
      return `Another recovery run is active.${identity} This browser cannot replace or bypass it.`;
    }
    if (error.code === "demo-reset-required") {
      const identity = error.runId === null ? "" : ` Run ${error.runId} must be reset.`;
      return `A terminal recovery run still owns the demo slot.${identity}`;
    }
    if (error.code.includes("digest") || error.code === "demo-response-invalid") {
      return "The response could not be verified. Recovery controls are withheld.";
    }
    if (action === "mutate") {
      return `The action result is uncertain (${error.code}). Recheck the run before continuing.`;
    }
    return `The recovery service is unavailable (${error.code}).`;
  }
  return action === "mutate"
    ? "The action result is uncertain. Recheck the run before continuing."
    : "The recovery service is unavailable.";
}

function receiptMatchesRun(receipt: DemoReceipt, run: DemoRun): boolean {
  const approval = run.approval;
  const recovery = run.recovery;
  const expectedProofStages = [
    ...(run.execution === undefined ? [] : ["execution" as const]),
    ...(run.investigation === undefined ? [] : ["investigation" as const]),
  ];
  return (
    receipt.run_id === run.run_id &&
    receipt.incident_id === run.incident_id &&
    receipt.scenario_id === run.scenario_id &&
    receipt.source_commit === run.source_commit &&
    receipt.build_sha256 === run.build_sha256 &&
    receipt.provenance.source_commit === run.source_commit &&
    receipt.phase === run.phase &&
    receipt.run_version === run.version &&
    receipt.reason_code === run.terminal_reason &&
    receipt.bindings.incident_version === (approval?.incident_version ?? null) &&
    receipt.bindings.plan_version === (approval?.plan_version ?? null) &&
    receipt.bindings.plan_sha256 === (approval?.plan_sha256 ?? null) &&
    receipt.bindings.target_sha256 === (approval?.target_sha256 ?? null) &&
    receipt.bindings.outcome_id === (recovery?.outcome_id ?? null) &&
    receipt.bindings.outcome_sha256 === (recovery?.outcome_sha256 ?? null) &&
    receipt.bindings.workflow_id === (recovery?.workflow_id ?? null) &&
    receipt.bindings.workflow_version === (recovery?.workflow_version ?? null) &&
    receipt.bindings.packet_id === (recovery?.packet_id ?? null) &&
    receipt.bindings.packet_sha256 === (recovery?.packet_sha256 ?? null) &&
    receipt.bindings.closure_id === (recovery?.closure_id ?? null) &&
    receipt.bindings.closure_sha256 === (recovery?.closure_sha256 ?? null) &&
    receipt.proofs.length === expectedProofStages.length &&
    receipt.proofs.every((proof, index) => proof.stage === expectedProofStages[index]) &&
    receipt.visuals.length === Object.keys(run.visual_comparison).length &&
    receipt.visuals.every((visual) => run.visual_comparison[visual.kind]?.sha256 === visual.sha256)
  );
}

function phaseLabel(phase: DemoPhase): string {
  switch (phase) {
    case "preparing":
      return "Preparing evidence";
    case "awaiting-approval":
      return "Awaiting approval";
    case "executing":
      return "Applying recovery";
    case "awaiting-closure":
      return "Recovery verified";
    case "closing":
      return "Recording closure";
    case "closed":
      return "Closed";
    case "unresolved":
      return "Stopped unresolved";
    case "expired":
      return "Lease expired";
  }
}

function timelineStates(
  run: DemoRun,
): Readonly<Record<(typeof TIMELINE)[number]["key"], TimelineState>> {
  const terminalFailure = run.phase === "unresolved" || run.phase === "expired";
  const approvalComplete =
    run.phase === "executing" ||
    run.phase === "awaiting-closure" ||
    run.phase === "closing" ||
    run.phase === "closed";
  const recoveryComplete =
    run.phase === "awaiting-closure" || run.phase === "closing" || run.phase === "closed";
  return {
    alert: "complete",
    investigation: run.approval === null ? (terminalFailure ? "stopped" : "current") : "complete",
    plan: run.approval === null ? (terminalFailure ? "stopped" : "waiting") : "complete",
    approval: approvalComplete
      ? "complete"
      : run.phase === "awaiting-approval"
        ? "current"
        : terminalFailure
          ? "stopped"
          : "waiting",
    action: recoveryComplete
      ? "complete"
      : run.phase === "executing"
        ? "current"
        : terminalFailure
          ? "stopped"
          : "waiting",
    recovery: recoveryComplete ? "complete" : terminalFailure ? "stopped" : "waiting",
    closure:
      run.phase === "closed"
        ? "complete"
        : run.phase === "awaiting-closure" || run.phase === "closing"
          ? "current"
          : terminalFailure
            ? "stopped"
            : "waiting",
  };
}

function LeaseStatus({ expiresAt }: { readonly expiresAt: string | null }) {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (expiresAt === null) return;
    const interval = window.setInterval(() => setNow(Date.now()), 1_000);
    return () => window.clearInterval(interval);
  }, [expiresAt]);

  if (expiresAt === null) return <span>Lease ended</span>;
  const remainingSeconds = Math.max(0, Math.ceil((Date.parse(expiresAt) - now) / 1_000));
  const minutes = Math.floor(remainingSeconds / 60);
  const seconds = remainingSeconds % 60;
  return (
    <span>
      Lease {minutes}:{seconds.toString().padStart(2, "0")} remaining
    </span>
  );
}

function VisualCard({
  alt,
  kind,
  visual,
  onDecoded,
  onDecodeError,
}: {
  readonly alt: string;
  readonly kind: DemoVisualKind;
  readonly visual: VerifiedDemoVisual | undefined;
  readonly onDecoded: (visual: VerifiedDemoVisual) => void;
  readonly onDecodeError: (visual: VerifiedDemoVisual) => void;
}) {
  const labels: Readonly<Record<DemoVisualKind, string>> = {
    expected: "Expected",
    observed: "Observed fault",
    recovered: "Recovered",
    diff: "Pixel difference",
  };
  return (
    <figure className={`shot-visual shot-visual--${kind}`} data-visual-kind={kind}>
      <figcaption>
        <span>{labels[kind]}</span>
        <small>
          {visual === undefined ? "Verifying image" : "Illustrative image · digest verified"}
        </small>
      </figcaption>
      {visual === undefined ? (
        <div
          aria-label={`${labels[kind]} image is loading`}
          className="shot-visual__placeholder"
          role="img"
        />
      ) : (
        <img
          alt={alt}
          key={`${kind}:${visual.sha256}:${visual.src}`}
          onError={() => onDecodeError(visual)}
          onLoad={(event) => {
            const image = event.currentTarget;
            try {
              void image
                .decode()
                .then(() => onDecoded(visual))
                .catch(() => onDecodeError(visual));
            } catch {
              onDecodeError(visual);
            }
          }}
          src={visual.src}
        />
      )}
    </figure>
  );
}

function ScopeSummary({ investigation }: { readonly investigation?: DemoInvestigationProof }) {
  const scope = investigation?.scope;
  const groups = [
    { key: "affected", label: "Affected outputs", count: scope?.affected_count },
    { key: "safe", label: "Safe outputs", count: scope?.safe_count },
    { key: "unknown", label: "Unknown outputs", count: scope?.unknown_count },
  ] as const;
  return (
    <section aria-labelledby="shot-scope-title" className="shot-panel shot-scope">
      <div className="shot-section-heading">
        <div>
          <p className="shot-eyebrow">Validated investigation scope</p>
          <h2 id="shot-scope-title">Four affected outputs, three safe</h2>
        </div>
        <span className="shot-authority">Authoritative numeric proof</span>
      </div>
      <p>
        Counts come from the returned investigation proof. Names below are canonical scenario
        context and do not grant action authority.
      </p>
      <div className="shot-scope__groups">
        {groups.map((group) => (
          <section data-scope-group={group.key} key={group.key}>
            <strong>{group.count ?? "—"}</strong>
            <h3>{group.label}</h3>
          </section>
        ))}
      </div>
      <div className="shot-scope__context">
        <h3>Canonical names · context only</h3>
        <p>
          Primary affected: <code>{CANONICAL_SCOPE.affected.join(", ")}</code>
        </p>
        <p>
          Derivative affected: <code>{CANONICAL_SCOPE.derivative.join(", ")}</code>
        </p>
        <p>
          Safe: <code>{CANONICAL_SCOPE.safe.join(", ")}</code>
        </p>
        <p>Unknown: {CANONICAL_SCOPE.unknown.length === 0 ? "none" : "listed in context"}</p>
      </div>
    </section>
  );
}

function ProofTimeline({ run }: { readonly run: DemoRun }) {
  const states = timelineStates(run);
  return (
    <section aria-labelledby="shot-timeline-title" className="shot-panel shot-timeline">
      <div className="shot-section-heading">
        <div>
          <p className="shot-eyebrow">Proof path</p>
          <h2 id="shot-timeline-title">From alert to closure</h2>
        </div>
        <span aria-live="polite" className="shot-phase" data-phase={run.phase}>
          {phaseLabel(run.phase)}
        </span>
      </div>
      <ol>
        {TIMELINE.map((item) => (
          <li data-state={states[item.key]} key={item.key}>
            <span aria-hidden="true" className="shot-timeline__marker" />
            <div>
              <strong>{item.label}</strong>
              <p>{item.detail}</p>
            </div>
            <small>{states[item.key]}</small>
          </li>
        ))}
      </ol>
    </section>
  );
}

function TechnicalDetails({
  receipt,
  run,
  visuals,
}: {
  readonly receipt: DemoReceipt | null;
  readonly run: DemoRun;
  readonly visuals: Partial<Record<DemoVisualKind, VerifiedDemoVisual>>;
}) {
  return (
    <details className="shot-technical">
      <summary>Technical details</summary>
      <div className="shot-technical__content">
        <section>
          <h3>Verified query evidence</h3>
          {run.investigation === undefined ? (
            <p>Investigation proof pending.</p>
          ) : (
            <dl data-proof-section="investigation-evidence">
              {run.investigation.evidence.map((item) => (
                <div key={item.evidence_id}>
                  <dt>
                    <code>{item.query_key}</code>
                  </dt>
                  <dd>
                    <code>{item.tool}</code> · {item.freshness}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>
        <section>
          <h3>Model invocations</h3>
          {run.investigation === undefined ? (
            <p>Investigation proof pending.</p>
          ) : (
            <dl data-proof-section="model-invocations">
              {run.investigation.model_invocations.map((item) => (
                <div key={item.invocation_id}>
                  <dt>{item.turn_kind}</dt>
                  <dd>
                    <code>{item.model}</code> · {item.framework} · {item.result_class}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>
        <section>
          <h3>Bound versions</h3>
          <dl>
            <div>
              <dt>Run</dt>
              <dd>{run.version}</dd>
            </div>
            <div>
              <dt>Incident</dt>
              <dd>{run.approval?.incident_version ?? "Pending"}</dd>
            </div>
            <div>
              <dt>Plan</dt>
              <dd>{run.approval?.plan_version ?? "Pending"}</dd>
            </div>
            <div>
              <dt>Workflow</dt>
              <dd>{run.recovery?.workflow_version ?? "Pending"}</dd>
            </div>
          </dl>
        </section>
        <section className="shot-technical__digests">
          <h3>Digest bindings</h3>
          <dl>
            <div>
              <dt>Plan</dt>
              <dd>
                <code>{run.approval?.plan_sha256 ?? "Pending"}</code>
              </dd>
            </div>
            <div>
              <dt>Target</dt>
              <dd>
                <code>{run.approval?.target_sha256 ?? "Pending"}</code>
              </dd>
            </div>
            <div>
              <dt>Build</dt>
              <dd>
                <code>{run.build_sha256}</code>
              </dd>
            </div>
            <div>
              <dt>Outcome</dt>
              <dd>
                <code>{run.recovery?.outcome_sha256 ?? "Pending"}</code>
              </dd>
            </div>
            {run.execution === undefined ? null : (
              <div>
                <dt>Safe complement proof</dt>
                <dd>
                  <code>{run.execution.action.safe_complement_proof_sha256}</code>
                </dd>
              </div>
            )}
            {Object.values(visuals).map((visual) => (
              <div key={visual.kind}>
                <dt>{visual.kind} image</dt>
                <dd>
                  <code>{visual.sha256}</code>
                </dd>
              </div>
            ))}
            {receipt === null ? null : (
              <>
                {receipt.proofs.map((proof) => (
                  <div key={proof.stage}>
                    <dt>{proof.stage} proof</dt>
                    <dd>
                      <code>{proof.sha256}</code>
                    </dd>
                  </div>
                ))}
                <div>
                  <dt>Receipt</dt>
                  <dd>
                    <code>{receipt.receipt_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Provenance</dt>
                  <dd>
                    <code>{receipt.provenance.schema}</code>
                  </dd>
                </div>
              </>
            )}
          </dl>
        </section>
        {run.execution === undefined ? null : (
          <section>
            <h3>Recovery checks</h3>
            <dl data-proof-section="recovery-checks">
              {run.execution.recovery.checks.map((item) => (
                <div key={item.check}>
                  <dt>{item.check}</dt>
                  <dd>{item.status}</dd>
                </div>
              ))}
            </dl>
          </section>
        )}
        <p className="shot-technical__boundary">
          Raw logs, metric series, trace payloads, internal paths, and credentials are not exposed
          in this view.
        </p>
      </div>
    </details>
  );
}

function ApprovalPanel({
  actionError,
  busy,
  nonce,
  onApprove,
  onRecheck,
  run,
  visualsReady,
}: {
  readonly actionError: string | null;
  readonly busy: boolean;
  readonly nonce: string | null;
  readonly onApprove: (nonce: string, phrase: string) => void;
  readonly onRecheck: () => void;
  readonly run: DemoRun;
  readonly visualsReady: boolean;
}) {
  const [nonceInput, setNonceInput] = useState("");
  const [phraseInput, setPhraseInput] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const exact =
    nonce !== null &&
    nonceInput === nonce &&
    phraseInput === DEMO_APPROVAL_PHRASE &&
    confirmed &&
    visualsReady;

  if (actionError !== null) {
    return (
      <section aria-labelledby="approval-title" className="shot-panel shot-action-panel">
        <p className="shot-eyebrow">Approval boundary</p>
        <h2 id="approval-title">Action paused</h2>
        <p className="shot-alert" role="alert">
          {actionError}
        </p>
        <button className="shot-button shot-button--secondary" onClick={onRecheck} type="button">
          Recheck run state
        </button>
      </section>
    );
  }
  if (nonce === null) {
    return (
      <section aria-labelledby="approval-title" className="shot-panel shot-action-panel">
        <p className="shot-eyebrow">Approval boundary</p>
        <h2 id="approval-title">Approval cannot continue in this browser</h2>
        <p className="shot-alert" role="alert">
          The one-time approval nonce is unavailable. No recovery action can be sent.
        </p>
        <button className="shot-button shot-button--secondary" onClick={onRecheck} type="button">
          Recheck run state
        </button>
      </section>
    );
  }

  return (
    <section aria-labelledby="approval-title" className="shot-panel shot-action-panel">
      <p className="shot-eyebrow">Approval boundary</p>
      <h2 id="approval-title">Confirm the exact run and action</h2>
      <p>
        Approval applies only to run version {run.version}, plan version{" "}
        {run.approval?.plan_version}, and the displayed target digest.
      </p>
      <div className="shot-issued-nonce">
        <span>Run nonce</span>
        <code>{nonce}</code>
      </div>
      <div className="shot-form-grid">
        <div>
          <label htmlFor="shot-approval-nonce">Retype run nonce</label>
          <input
            autoComplete="off"
            id="shot-approval-nonce"
            onChange={(event) => setNonceInput(event.currentTarget.value)}
            spellCheck={false}
            value={nonceInput}
          />
        </div>
        <div>
          <label htmlFor="shot-approval-phrase">Type approval phrase</label>
          <input
            aria-describedby="shot-approval-phrase-hint"
            autoComplete="off"
            id="shot-approval-phrase"
            onChange={(event) => setPhraseInput(event.currentTarget.value)}
            spellCheck={false}
            value={phraseInput}
          />
          <small id="shot-approval-phrase-hint">
            <code>{DEMO_APPROVAL_PHRASE}</code>
          </small>
        </div>
      </div>
      <label className="shot-checkbox">
        <input
          checked={confirmed}
          onChange={(event) => setConfirmed(event.currentTarget.checked)}
          type="checkbox"
        />
        <span>
          I approve only the returned run, incident, plan, and target bindings; canonical context
          does not grant authority.
        </span>
      </label>
      <button
        className="shot-button shot-button--primary"
        disabled={!exact || busy}
        onClick={() => onApprove(nonceInput, phraseInput)}
        type="button"
      >
        {busy ? "Applying bound action…" : "Approve recovery action"}
      </button>
      {!visualsReady ? (
        <p className="shot-form-note">
          Approval unlocks after all comparison images pass digest verification.
        </p>
      ) : null}
    </section>
  );
}

function ClosurePanel({
  actionError,
  busy,
  onClose,
  onRecheck,
  recoveredReady,
  run,
}: {
  readonly actionError: string | null;
  readonly busy: boolean;
  readonly onClose: () => void;
  readonly onRecheck: () => void;
  readonly recoveredReady: boolean;
  readonly run: DemoRun;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const recovery = run.recovery;
  const safeDigest = run.execution?.action.safe_complement_proof_sha256;
  return (
    <section
      aria-labelledby="closure-title"
      className="shot-panel shot-action-panel shot-action-panel--success"
    >
      <p className="shot-eyebrow">Recovery verification</p>
      <h2 id="closure-title">Recovered output is ready for closure</h2>
      <p className="shot-safe-digest">
        <span>Safe digest</span>
        <code>{shortDigest(safeDigest)}</code>
      </p>
      {actionError === null ? null : (
        <p className="shot-alert" role="alert">
          {actionError}
        </p>
      )}
      <label className="shot-checkbox">
        <input
          checked={confirmed}
          disabled={actionError !== null}
          onChange={(event) => setConfirmed(event.currentTarget.checked)}
          type="checkbox"
        />
        <span>I verified the recovered image and bound recovery digest.</span>
      </label>
      <div className="shot-action-row">
        <button
          className="shot-button shot-button--primary"
          disabled={
            !confirmed ||
            !recoveredReady ||
            busy ||
            actionError !== null ||
            recovery === null ||
            safeDigest === undefined
          }
          onClick={onClose}
          type="button"
        >
          {busy ? "Recording closure…" : "Verify and close recovery"}
        </button>
        {actionError === null ? null : (
          <button className="shot-button shot-button--secondary" onClick={onRecheck} type="button">
            Recheck run state
          </button>
        )}
      </div>
    </section>
  );
}

function TerminalPanel({
  actionError,
  busy,
  onReset,
  receipt,
  run,
}: {
  readonly actionError: string | null;
  readonly busy: boolean;
  readonly onReset: () => void;
  readonly receipt: DemoReceipt | null;
  readonly run: DemoRun;
}) {
  const closed = run.phase === "closed";
  return (
    <section
      aria-labelledby="terminal-title"
      className="shot-panel shot-terminal"
      data-terminal-phase={run.phase}
    >
      <p className="shot-eyebrow">Run result</p>
      <h2 id="terminal-title">
        {closed ? "Recovery closed with a durable receipt" : "Run stopped without closure"}
      </h2>
      <p>
        {closed
          ? "The action, recovered output, and human closure are bound to one immutable receipt."
          : `No further action is permitted for this run (${run.terminal_reason ?? run.phase}).`}
      </p>
      {actionError === null ? null : (
        <p className="shot-alert" role="alert">
          {actionError}
        </p>
      )}
      {receipt === null && actionError === null ? (
        <p aria-live="polite">Loading receipt…</p>
      ) : receipt !== null ? (
        <dl className="shot-receipt">
          <div>
            <dt>Result</dt>
            <dd>{receipt.phase}</dd>
          </div>
          <div>
            <dt>Run version</dt>
            <dd>{receipt.run_version}</dd>
          </div>
          <div>
            <dt>Receipt</dt>
            <dd>
              <code>{shortDigest(receipt.receipt_sha256)}</code>
            </dd>
          </div>
          <div>
            <dt>Closure</dt>
            <dd>
              <code>{shortDigest(receipt.bindings.closure_sha256)}</code>
            </dd>
          </div>
        </dl>
      ) : null}
      {run.reset ? (
        <p className="shot-reset-state">This run is reset. Its receipt remains available.</p>
      ) : (
        <button
          className="shot-button shot-button--secondary"
          disabled={busy || receipt === null}
          onClick={onReset}
          type="button"
        >
          {busy ? "Resetting…" : "Reset for another run"}
        </button>
      )}
    </section>
  );
}

export function ShotSafeColorRecoveryApp({ adapter, storage }: ShotSafeColorRecoveryAppProps) {
  const sessionStorage = storage ?? window.sessionStorage;
  const resumed = useMemo(() => readSession(sessionStorage), [sessionStorage]);
  const [run, setRun] = useState<DemoRun | null>(null);
  const [approvalNonce, setApprovalNonce] = useState<string | null>(resumed.nonce);
  const [visuals, setVisuals] = useState<Partial<Record<DemoVisualKind, VerifiedDemoVisual>>>({});
  const [decodedVisuals, setDecodedVisuals] = useState<
    Partial<Record<DemoVisualKind, DecodedVisual>>
  >({});
  const [visualFailures, setVisualFailures] = useState<
    Partial<Record<DemoVisualKind, VisualFailure>>
  >({});
  const [receipt, setReceipt] = useState<DemoReceipt | null>(null);
  const [busy, setBusy] = useState(
    resumed.runId !== null || (resumed.nonce !== null && resumed.startKey !== null),
  );
  const [startError, setStartError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [resetNotice, setResetNotice] = useState<DemoReset["restoration"] | null>(null);
  const approvalKey = useRef<string | null>(null);
  const closureKey = useRef<string | null>(null);
  const pendingStartNonce = useRef<string | null>(resumed.runId === null ? resumed.nonce : null);
  const pendingStartKey = useRef<string | null>(resumed.runId === null ? resumed.startKey : null);
  const resetKey = useRef<string | null>(resumed.resetKey);
  const approvalNonceRef = useRef(approvalNonce);
  const visualsRef = useRef(visuals);
  const decodedVisualsRef = useRef(decodedVisuals);
  const runRef = useRef(run);
  const contentHeading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    visualsRef.current = visuals;
  }, [visuals]);

  useEffect(() => {
    decodedVisualsRef.current = decodedVisuals;
  }, [decodedVisuals]);

  useEffect(() => {
    runRef.current = run;
  }, [run]);

  useEffect(() => {
    approvalNonceRef.current = approvalNonce;
  }, [approvalNonce]);

  useEffect(
    () => () => {
      for (const visual of Object.values(visualsRef.current)) adapter.releaseVisual(visual);
    },
    [adapter],
  );

  const acceptRun = useCallback(
    (next: DemoRun, nonce: string | null = approvalNonceRef.current) => {
      const current = runRef.current;
      if (current?.run_id === next.run_id) {
        if (
          current.incident_id !== next.incident_id ||
          current.scenario_id !== next.scenario_id ||
          current.source_commit !== next.source_commit ||
          current.build_sha256 !== next.build_sha256
        ) {
          setActionError("The service returned conflicting immutable run bindings.");
          return;
        }
        if (next.version < current.version) return;
      }
      const usableNonce = next.phase === "awaiting-approval" ? nonce : null;
      approvalNonceRef.current = usableNonce;
      runRef.current = next;
      setRun(next);
      setApprovalNonce(usableNonce);
      pendingStartNonce.current = null;
      pendingStartKey.current = null;
      persistRun(sessionStorage, next.run_id, usableNonce);
    },
    [sessionStorage],
  );

  const finishReset = useCallback(
    (restoration: DemoReset["restoration"] | null) => {
      clearSession(sessionStorage);
      for (const visual of Object.values(visualsRef.current)) adapter.releaseVisual(visual);
      visualsRef.current = {};
      decodedVisualsRef.current = {};
      runRef.current = null;
      setVisuals({});
      setDecodedVisuals({});
      setVisualFailures({});
      setRun(null);
      setReceipt(null);
      approvalNonceRef.current = null;
      setApprovalNonce(null);
      setActionError(null);
      approvalKey.current = null;
      closureKey.current = null;
      pendingStartNonce.current = null;
      pendingStartKey.current = null;
      resetKey.current = null;
      setResetNotice(restoration);
    },
    [adapter, sessionStorage],
  );

  const recoverConflict = useCallback(
    async (error: unknown, signal?: AbortSignal): Promise<boolean> => {
      if (
        !(error instanceof DemoApiError) ||
        (error.code !== "demo-active-run-exists" && error.code !== "demo-reset-required") ||
        error.runId === null
      ) {
        return false;
      }
      const next = await adapter.get(error.runId, signal);
      acceptRun(next, null);
      return true;
    },
    [acceptRun, adapter],
  );

  useEffect(() => {
    if (resumed.runId === null && (resumed.nonce === null || resumed.startKey === null)) {
      setBusy(false);
      return;
    }
    const controller = new AbortController();
    let active = true;
    void (async () => {
      try {
        if (resumed.runId !== null) {
          const next = await adapter.get(resumed.runId, controller.signal);
          if (!active) return;
          acceptRun(next, resumed.nonce);
          if (next.terminal && resumed.resetKey !== null) {
            try {
              const acknowledgement = await adapter.reset(
                next.run_id,
                next.version,
                resumed.resetKey,
              );
              if (active) finishReset(acknowledgement.restoration);
            } catch (error) {
              if (active) setActionError(errorMessage(error, "mutate"));
            }
          } else if (next.reset) {
            finishReset(null);
          }
        } else if (resumed.nonce !== null && resumed.startKey !== null) {
          try {
            const next = await adapter.start(
              {
                approval_nonce: resumed.nonce,
                idempotency_key: resumed.startKey,
              },
              controller.signal,
            );
            if (active) acceptRun(next, next.approval_nonce ?? null);
          } catch (error) {
            if (!active || !(await recoverConflict(error, controller.signal))) throw error;
          }
        }
        if (active) setStartError(null);
      } catch (error) {
        if (active) setStartError(errorMessage(error, "load"));
      } finally {
        if (active) setBusy(false);
      }
    })();
    return () => {
      active = false;
      controller.abort();
    };
  }, [acceptRun, adapter, finishReset, recoverConflict, resumed]);

  useEffect(() => {
    if (run === null || run.terminal) return;
    const controller = new AbortController();
    let active = true;
    let timeout: number | undefined;
    const delay = Math.min(
      RECONCILE_INTERVAL_MILLISECONDS,
      Math.max(250, run.poll.after_milliseconds),
    );
    const reconcile = () => {
      void adapter
        .get(run.run_id, controller.signal)
        .then((next) => {
          if (!active) return;
          acceptRun(next);
          setActionError(null);
        })
        .catch((error: unknown) => {
          if (active) setActionError(errorMessage(error, "load"));
        })
        .finally(() => {
          if (active) timeout = window.setTimeout(reconcile, delay);
        });
    };
    timeout = window.setTimeout(reconcile, delay);
    return () => {
      active = false;
      if (timeout !== undefined) window.clearTimeout(timeout);
      controller.abort();
    };
  }, [acceptRun, adapter, run]);

  useEffect(() => {
    if (run === null) return;
    const currentVisuals = visualsRef.current;
    const retainedVisuals: Partial<Record<DemoVisualKind, VerifiedDemoVisual>> = {};
    let visualsChanged = false;
    for (const kind of Object.keys(currentVisuals) as DemoVisualKind[]) {
      const visual = currentVisuals[kind];
      if (visual === undefined) continue;
      if (run.visual_comparison[kind]?.sha256 === visual.sha256) {
        retainedVisuals[kind] = visual;
      } else {
        visualsChanged = true;
        adapter.releaseVisual(visual);
      }
    }
    if (visualsChanged) {
      visualsRef.current = retainedVisuals;
      setVisuals(retainedVisuals);
    }

    const currentDecoded = decodedVisualsRef.current;
    const retainedDecoded: Partial<Record<DemoVisualKind, DecodedVisual>> = {};
    let decodedChanged = false;
    for (const kind of Object.keys(currentDecoded) as DemoVisualKind[]) {
      const decoded = currentDecoded[kind];
      const visual = retainedVisuals[kind];
      if (
        decoded !== undefined &&
        visual !== undefined &&
        decoded.sha256 === visual.sha256 &&
        decoded.src === visual.src
      ) {
        retainedDecoded[kind] = decoded;
      } else {
        decodedChanged = true;
      }
    }
    if (decodedChanged) {
      decodedVisualsRef.current = retainedDecoded;
      setDecodedVisuals(retainedDecoded);
    }

    setVisualFailures((current) => {
      const retained: Partial<Record<DemoVisualKind, VisualFailure>> = {};
      let changed = false;
      for (const kind of Object.keys(current) as DemoVisualKind[]) {
        const failure = current[kind];
        if (failure !== undefined && run.visual_comparison[kind]?.sha256 === failure.sha256) {
          retained[kind] = failure;
        } else {
          changed = true;
        }
      }
      return changed ? retained : current;
    });
  }, [adapter, run]);

  useEffect(() => {
    if (run === null || run.approval === null) return;
    const wanted: DemoVisualKind[] = [...REQUIRED_APPROVAL_VISUALS];
    if (run.recovery !== null) wanted.push("recovered");
    const missing = wanted.filter((kind) => {
      const descriptor = run.visual_comparison[kind];
      const visual = visualsRef.current[kind];
      return descriptor === undefined || visual?.sha256 !== descriptor.sha256;
    });
    if (missing.length === 0) return;
    const controller = new AbortController();
    let active = true;
    void Promise.allSettled(
      missing.map((kind) => {
        const expected = run.visual_comparison[kind]?.sha256;
        return expected === undefined
          ? Promise.reject(new DemoApiError(null, "demo-response-invalid"))
          : adapter.visual(run.run_id, kind, expected, controller.signal);
      }),
    ).then((results) => {
      if (!active) {
        for (const result of results) {
          if (result.status === "fulfilled") adapter.releaseVisual(result.value);
        }
        return;
      }
      const nextVisuals = { ...visualsRef.current };
      const nextDecoded = { ...decodedVisualsRef.current };
      const failures = new Map<DemoVisualKind, VisualFailure | null>();
      let loadedAny = false;
      for (const [index, result] of results.entries()) {
        const kind = missing[index] as DemoVisualKind;
        const expected = run.visual_comparison[kind]?.sha256;
        const currentDescriptor = runRef.current?.visual_comparison[kind]?.sha256;
        if (result.status === "rejected") {
          if (expected !== undefined && currentDescriptor === expected) {
            failures.set(kind, {
              sha256: expected,
              message: errorMessage(result.reason, "load"),
            });
          }
          continue;
        }
        const visual = result.value;
        if (
          expected === undefined ||
          currentDescriptor !== expected ||
          visual.kind !== kind ||
          visual.sha256 !== expected
        ) {
          adapter.releaseVisual(visual);
          if (expected !== undefined && currentDescriptor === expected) {
            failures.set(kind, {
              sha256: expected,
              message: "The response could not be verified. Recovery controls are withheld.",
            });
          }
          continue;
        }
        const previous = nextVisuals[kind];
        if (previous !== undefined && previous.src !== visual.src) {
          adapter.releaseVisual(previous);
        }
        nextVisuals[kind] = visual;
        delete nextDecoded[kind];
        failures.set(kind, null);
        loadedAny = true;
      }
      if (loadedAny) {
        visualsRef.current = nextVisuals;
        decodedVisualsRef.current = nextDecoded;
        setVisuals(nextVisuals);
        setDecodedVisuals(nextDecoded);
      }
      setVisualFailures((current) => {
        const next = { ...current };
        for (const [kind, failure] of failures) {
          if (failure === null) delete next[kind];
          else next[kind] = failure;
        }
        return next;
      });
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [adapter, run]);

  useEffect(() => {
    if (run === null || !run.terminal) return;
    const controller = new AbortController();
    let active = true;
    void adapter
      .receipt(run.run_id, controller.signal)
      .then(async (next) => {
        if (!receiptMatchesRun(next, run) || !(await verifyDemoReceiptIntegrity(next, run))) {
          throw new DemoApiError(null, "demo-response-invalid");
        }
        if (!active) return;
        setReceipt(next);
        const mismatch = next.visuals.find(
          (expected) =>
            visualsRef.current[expected.kind] !== undefined &&
            visualsRef.current[expected.kind]?.sha256 !== expected.sha256,
        );
        if (mismatch !== undefined) {
          setVisualFailures((current) => ({
            ...current,
            [mismatch.kind]: {
              sha256: mismatch.sha256,
              message: "The displayed visual did not match the terminal receipt.",
            },
          }));
        }
      })
      .catch((error: unknown) => {
        if (active) setActionError(errorMessage(error, "load"));
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [adapter, run]);

  const markVisualDecoded = useCallback((visual: VerifiedDemoVisual) => {
    const currentDescriptor = runRef.current?.visual_comparison[visual.kind];
    const currentVisual = visualsRef.current[visual.kind];
    if (
      currentDescriptor?.sha256 !== visual.sha256 ||
      currentVisual?.sha256 !== visual.sha256 ||
      currentVisual.src !== visual.src
    ) {
      return;
    }
    const next = {
      ...decodedVisualsRef.current,
      [visual.kind]: { sha256: visual.sha256, src: visual.src },
    };
    decodedVisualsRef.current = next;
    setDecodedVisuals(next);
    setVisualFailures((current) => {
      if (current[visual.kind]?.sha256 !== visual.sha256) return current;
      const retained = { ...current };
      delete retained[visual.kind];
      return retained;
    });
  }, []);

  const markVisualDecodeFailure = useCallback((visual: VerifiedDemoVisual, message: string) => {
    const currentDescriptor = runRef.current?.visual_comparison[visual.kind];
    const currentVisual = visualsRef.current[visual.kind];
    if (
      currentDescriptor?.sha256 !== visual.sha256 ||
      currentVisual?.sha256 !== visual.sha256 ||
      currentVisual.src !== visual.src
    ) {
      return;
    }
    const nextDecoded = { ...decodedVisualsRef.current };
    delete nextDecoded[visual.kind];
    decodedVisualsRef.current = nextDecoded;
    setDecodedVisuals(nextDecoded);
    setVisualFailures((current) => ({
      ...current,
      [visual.kind]: { sha256: visual.sha256, message },
    }));
  }, []);

  const visualError = Object.values(visualFailures)[0]?.message ?? null;
  const visualIsReady = (kind: DemoVisualKind): boolean => {
    const descriptor = run?.visual_comparison[kind];
    const visual = visuals[kind];
    const decoded = decodedVisuals[kind];
    return (
      descriptor !== undefined &&
      visual?.sha256 === descriptor.sha256 &&
      decoded?.sha256 === descriptor.sha256 &&
      decoded.src === visual.src &&
      visualFailures[kind] === undefined
    );
  };
  const visualsReady = REQUIRED_APPROVAL_VISUALS.every(visualIsReady) && visualError === null;
  const recoveredReady = visualIsReady("recovered") && visualError === null;

  const currentRunId = run?.run_id;
  useEffect(() => {
    if (currentRunId !== undefined) contentHeading.current?.focus();
  }, [currentRunId]);

  const start = useCallback(() => {
    setBusy(true);
    setStartError(null);
    setResetNotice(null);
    void (async () => {
      try {
        const stored = readSession(sessionStorage);
        if (stored.runId !== null) {
          const next = await adapter.get(stored.runId);
          if (next.reset) finishReset(null);
          else acceptRun(next, stored.nonce);
          return;
        }
        const nonce = pendingStartNonce.current ?? stored.nonce ?? newApprovalNonce();
        const idempotencyKey =
          pendingStartKey.current ?? stored.startKey ?? mutationKey("demo-start");
        if (!persistPendingStart(sessionStorage, nonce, idempotencyKey)) {
          setStartError(
            "Session storage is unavailable. A recoverable investigation cannot be started.",
          );
          return;
        }
        pendingStartNonce.current = nonce;
        pendingStartKey.current = idempotencyKey;
        try {
          const next = await adapter.start({
            approval_nonce: nonce,
            idempotency_key: idempotencyKey,
          });
          acceptRun(next, next.approval_nonce ?? null);
        } catch (error) {
          if (!(await recoverConflict(error))) throw error;
        }
      } catch (error) {
        setStartError(errorMessage(error, "start"));
      } finally {
        setBusy(false);
      }
    })();
  }, [acceptRun, adapter, finishReset, recoverConflict, sessionStorage]);

  const recheck = useCallback(() => {
    if (run === null) return;
    setBusy(true);
    void adapter
      .get(run.run_id)
      .then((next) => {
        acceptRun(next);
        setActionError(null);
      })
      .catch((error: unknown) => setActionError(errorMessage(error, "load")))
      .finally(() => setBusy(false));
  }, [acceptRun, adapter, run]);

  const approve = useCallback(
    (nonce: string, phrase: string) => {
      if (run?.phase !== "awaiting-approval" || run.approval === null || !visualsReady) return;
      const key = approvalKey.current ?? mutationKey("demo-approve");
      approvalKey.current = key;
      setBusy(true);
      setActionError(null);
      void adapter
        .approve(run.run_id, {
          schema: "colortrace-demo-approval-request/v1",
          approval_nonce: nonce,
          approval_phrase: phrase,
          expected_run_version: run.version,
          expected_incident_version: run.approval.incident_version,
          expected_plan_version: run.approval.plan_version,
          expected_plan_sha256: run.approval.plan_sha256,
          expected_target_sha256: run.approval.target_sha256,
          idempotency_key: key,
        })
        .then((next) => {
          acceptRun(next, null);
        })
        .catch((error: unknown) => setActionError(errorMessage(error, "mutate")))
        .finally(() => setBusy(false));
    },
    [acceptRun, adapter, run, visualsReady],
  );

  const close = useCallback(() => {
    if (
      run?.phase !== "awaiting-closure" ||
      run.approval === null ||
      run.recovery === null ||
      !recoveredReady
    ) {
      return;
    }
    const key = closureKey.current ?? mutationKey("demo-close");
    closureKey.current = key;
    setBusy(true);
    setActionError(null);
    void adapter
      .close(run.run_id, {
        schema: "colortrace-demo-closure-request/v1",
        expected_run_version: run.version,
        expected_incident_version: run.approval.incident_version,
        expected_workflow_version: run.recovery.workflow_version,
        expected_packet_id: run.recovery.packet_id,
        expected_packet_sha256: run.recovery.packet_sha256,
        expected_outcome_id: run.recovery.outcome_id,
        expected_outcome_sha256: run.recovery.outcome_sha256,
        reason: "The verified recovery evidence is complete.",
        idempotency_key: key,
      })
      .then((next) => acceptRun(next, null))
      .catch((error: unknown) => setActionError(errorMessage(error, "mutate")))
      .finally(() => setBusy(false));
  }, [acceptRun, adapter, recoveredReady, run]);

  const reset = useCallback(() => {
    if (run === null || !run.terminal) return;
    const key = resetKey.current ?? mutationKey("demo-reset");
    if (!persistResetKey(sessionStorage, key)) {
      setActionError("Session storage is unavailable. A recoverable reset cannot be sent.");
      return;
    }
    resetKey.current = key;
    setBusy(true);
    void adapter
      .reset(run.run_id, run.version, key)
      .then((acknowledgement) => finishReset(acknowledgement.restoration))
      .catch((error: unknown) => setActionError(errorMessage(error, "mutate")))
      .finally(() => setBusy(false));
  }, [adapter, finishReset, run, sessionStorage]);

  return (
    <div className="shot-app">
      <a className="skip-link" href="#shot-main">
        Skip to recovery workspace
      </a>
      <header className="shot-header">
        <a aria-label="ColorTrace home" className="shot-brand" href="/">
          <span aria-hidden="true" className="shot-brand__mark">
            CT
          </span>
          <span>ColorTrace</span>
        </a>
        {run === null ? (
          <span className="shot-mode">Shot-safe recovery</span>
        ) : (
          <div className="shot-run-chip">
            <span data-phase={run.phase}>{phaseLabel(run.phase)}</span>
            <LeaseStatus expiresAt={run.lease_expires_at} />
          </div>
        )}
      </header>

      <main id="shot-main">
        {run === null ? (
          <section className="shot-landing">
            <div className="shot-landing__copy">
              <p className="shot-eyebrow">Shot-Safe Color Recovery</p>
              <h1>See the fault. Approve the boundary. Verify the recovery.</h1>
              <p className="shot-lede">
                Compare the declared look with the observed output, review canonical scenario
                context, then authorize one digest-bound recovery action.
              </p>
              {startError === null ? null : (
                <p className="shot-alert" role="alert">
                  {startError}
                </p>
              )}
              {resetNotice !== null ? (
                <p className="shot-success" role="status">
                  The prior run was reset to authored generation {resetNotice.generation}. Its
                  receipt remains stored.
                </p>
              ) : null}
              <button
                className="shot-button shot-button--primary shot-button--large"
                disabled={busy}
                onClick={start}
                type="button"
              >
                {busy ? "Preparing recovery…" : "Investigate with Gemini + Grafana"}
              </button>
              <p className="shot-landing__note">
                One active run · 15-minute lease · explicit human approval
              </p>
            </div>
            <div aria-hidden="true" className="shot-landing__visual">
              <div className="shot-gradient-card shot-gradient-card--expected">
                <span>Expected</span>
              </div>
              <div className="shot-gradient-card shot-gradient-card--observed">
                <span>Observed</span>
              </div>
              <div className="shot-scanline" />
            </div>
          </section>
        ) : (
          <div className="shot-workspace">
            <section aria-labelledby="comparison-title" className="shot-comparison">
              <div className="shot-comparison__intro">
                <div>
                  <p className="shot-eyebrow">Canonical representative job · job-b-02</p>
                  <h1 id="comparison-title" ref={contentHeading} tabIndex={-1}>
                    Expected versus observed
                  </h1>
                  <p>
                    Images illustrate the color fault. Returned plan and target digests establish
                    action authority; canonical scope context is labeled below.
                  </p>
                </div>
                <div className="shot-identity">
                  <span>Run {run.version}</span>
                  <code>{run.run_id}</code>
                </div>
              </div>
              {visualError === null ? null : (
                <p className="shot-alert" role="alert">
                  {visualError}
                </p>
              )}
              <div className="shot-visual-grid shot-visual-grid--primary">
                <VisualCard
                  alt="Declared expected output for job-b-02"
                  kind="expected"
                  onDecoded={markVisualDecoded}
                  onDecodeError={(visual) =>
                    markVisualDecodeFailure(
                      visual,
                      "The expected image could not be decoded. Recovery controls are withheld.",
                    )
                  }
                  visual={visuals.expected}
                />
                <VisualCard
                  alt="Observed output with a visible color shift for job-b-02"
                  kind="observed"
                  onDecoded={markVisualDecoded}
                  onDecodeError={(visual) =>
                    markVisualDecodeFailure(
                      visual,
                      "The observed image could not be decoded. Recovery controls are withheld.",
                    )
                  }
                  visual={visuals.observed}
                />
              </div>
              <div className="shot-diff-row">
                <VisualCard
                  alt="Illustrative pixel difference between expected and observed output"
                  kind="diff"
                  onDecoded={markVisualDecoded}
                  onDecodeError={(visual) =>
                    markVisualDecodeFailure(
                      visual,
                      "The difference image could not be decoded. Recovery controls are withheld.",
                    )
                  }
                  visual={visuals.diff}
                />
                <div className="shot-diff-copy">
                  <p className="shot-eyebrow">Visible signal</p>
                  <h2>The canonical scenario models a shadowed color transform.</h2>
                  <p>
                    The image is illustrative. The fixed counts below are scenario context, not
                    returned scope evidence.
                  </p>
                </div>
              </div>
            </section>

            <div className="shot-two-column">
              <ProofTimeline run={run} />
              <ScopeSummary investigation={run.investigation} />
            </div>

            {run.phase === "awaiting-approval" ? (
              <ApprovalPanel
                actionError={actionError}
                busy={busy}
                nonce={approvalNonce}
                onApprove={approve}
                onRecheck={recheck}
                run={run}
                visualsReady={visualsReady && visualError === null}
              />
            ) : null}

            {run.phase === "executing" || run.phase === "closing" || run.phase === "preparing" ? (
              <section aria-live="polite" className="shot-panel shot-pending" role="status">
                <span aria-hidden="true" className="shot-pending__indicator" />
                <div>
                  <p className="shot-eyebrow">Bound workflow</p>
                  <h2>{phaseLabel(run.phase)}</h2>
                  <p>No additional action is available while this operation is reconciled.</p>
                  {actionError === null ? null : (
                    <>
                      <p className="shot-alert" role="alert">
                        {actionError}
                      </p>
                      <button
                        className="shot-button shot-button--secondary"
                        onClick={recheck}
                        type="button"
                      >
                        Recheck run state
                      </button>
                    </>
                  )}
                </div>
              </section>
            ) : null}

            {run.recovery === null ? null : (
              <section aria-labelledby="recovered-title" className="shot-panel shot-recovered">
                <div className="shot-section-heading">
                  <div>
                    <p className="shot-eyebrow">Post-action comparison</p>
                    <h2 id="recovered-title">Recovered output</h2>
                  </div>
                  <span className="shot-authority">Bound to outcome digest</span>
                </div>
                <div className="shot-recovered__content">
                  <VisualCard
                    alt="Recovered output for job-b-02"
                    kind="recovered"
                    onDecoded={markVisualDecoded}
                    onDecodeError={(visual) =>
                      markVisualDecodeFailure(
                        visual,
                        "The recovered image could not be decoded. Closure controls are withheld.",
                      )
                    }
                    visual={visuals.recovered}
                  />
                  <div>
                    <p className="shot-safe-digest">
                      <span>Safe digest</span>
                      <code>{shortDigest(run.execution?.action.safe_complement_proof_sha256)}</code>
                    </p>
                    <p>
                      Canonical context lists three safe jobs; this statement is not a receipt
                      binding.
                    </p>
                  </div>
                </div>
              </section>
            )}

            {run.phase === "awaiting-closure" ? (
              <ClosurePanel
                actionError={actionError}
                busy={busy}
                onClose={close}
                onRecheck={recheck}
                recoveredReady={recoveredReady}
                run={run}
              />
            ) : null}

            {run.terminal ? (
              <TerminalPanel
                actionError={actionError}
                busy={busy}
                onReset={reset}
                receipt={receipt}
                run={run}
              />
            ) : null}

            <TechnicalDetails receipt={receipt} run={run} visuals={visuals} />
          </div>
        )}
      </main>
      <footer className="shot-footer">
        <span>ColorTrace</span>
        <span>Human approval remains the action boundary.</span>
      </footer>
    </div>
  );
}
