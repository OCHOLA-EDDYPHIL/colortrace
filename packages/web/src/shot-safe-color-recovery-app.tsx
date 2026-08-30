import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  type DemoAdapter,
  DemoApiError,
  type DemoInvestigationProof,
  type DemoPlanCommand,
  type DemoPlanTarget,
  type DemoPhase,
  type DemoReceipt,
  type DemoRejectionReason,
  type DemoReset,
  type DemoRun,
  type DemoVisualKind,
  DEMO_APPROVAL_PHRASE,
  DEMO_REJECTION_REASONS,
  type VerifiedDemoVisual,
  verifyDemoReceiptIntegrity,
} from "./demo-api.ts";

const SESSION_RUN_KEY = "colortrace.demo.run-id";
const SESSION_NONCE_KEY = "colortrace.demo.approval-nonce";
const SESSION_START_KEY = "colortrace.demo.start-idempotency-key";
const SESSION_RESET_KEY = "colortrace.demo.reset-idempotency-key";
const REQUIRED_APPROVAL_VISUALS: readonly DemoVisualKind[] = ["expected", "observed", "diff"];
const RECONCILE_INTERVAL_MILLISECONDS = 1_000;

type DemoSessionStorage = Pick<Storage, "getItem" | "removeItem" | "setItem">;
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
        <small>{visual === undefined ? "Verifying image" : "Image verified"}</small>
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

function TargetList({
  emptyText,
  targets,
}: {
  readonly emptyText: string;
  readonly targets: readonly DemoPlanTarget[];
}) {
  if (targets.length === 0) return <p>{emptyText}</p>;
  return (
    <ul className="shot-target-list">
      {targets.map((target) => (
        <li key={`${target.kind}:${target.id}`}>
          <span>{target.kind}</span>
          <code>
            {target.kind === "color-resource" && target.id.startsWith("sha256:")
              ? "show_look.cube"
              : target.id}
          </code>
        </li>
      ))}
    </ul>
  );
}

function TechnicalCommandDetails({
  command,
  index,
}: {
  readonly command: DemoPlanCommand;
  readonly index: number;
}) {
  const isQuarantine = command.schema === "simulator-quarantine-command/v1";
  return (
    <li className="shot-command">
      <div className="shot-command__heading">
        <span>{String(index + 1).padStart(2, "0")}</span>
        <div>
          <strong>{isQuarantine ? "Quarantine and replace resource" : "Targeted rerender"}</strong>
          <code>{command.schema}</code>
        </div>
      </div>
      <dl>
        <div>
          <dt>Command ID</dt>
          <dd>
            <code>{command.command_id}</code>
          </dd>
        </div>
        <div>
          <dt>Namespace</dt>
          <dd>
            <code>{command.namespace}</code>
          </dd>
        </div>
        <div>
          <dt>Target</dt>
          <dd>
            <code>
              {command.target.kind}:{command.target.id}
            </code>
          </dd>
        </div>
        {isQuarantine ? (
          <>
            <div>
              <dt>Expected resource</dt>
              <dd>
                <code>{command.expected_resource_sha256}</code>
              </dd>
            </div>
            <div>
              <dt>Mode</dt>
              <dd>
                <code>{command.mode}</code>
              </dd>
            </div>
          </>
        ) : (
          <>
            <div>
              <dt>Job</dt>
              <dd>
                <code>{command.job_id}</code>
              </dd>
            </div>
            <div>
              <dt>Source</dt>
              <dd>
                <code>{command.source_id}</code>
              </dd>
            </div>
            <div>
              <dt>Transform</dt>
              <dd>
                <code>{command.transform_id}</code>
              </dd>
            </div>
            <div>
              <dt>Source manifest</dt>
              <dd>
                <code>{command.source_manifest_sha256}</code>
              </dd>
            </div>
            <div>
              <dt>Source PNG</dt>
              <dd>
                <code>{command.source_png_sha256}</code>
              </dd>
            </div>
            <div>
              <dt>Expected config</dt>
              <dd>
                <code>{command.expected_config_sha256}</code>
              </dd>
            </div>
            {"expected_output_sha256" in command ? (
              <>
                <div>
                  <dt>Expected output</dt>
                  <dd>
                    <code>{command.expected_output_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Expected display</dt>
                  <dd>
                    <code>{command.expected_display_sha256}</code>
                  </dd>
                </div>
              </>
            ) : (
              <>
                <div>
                  <dt>Expected derivative</dt>
                  <dd>
                    <code>{command.expected_derivative_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Derivative display</dt>
                  <dd>
                    <code>{command.expected_derivative_display_sha256}</code>
                  </dd>
                </div>
              </>
            )}
            <div>
              <dt>Lineage parent</dt>
              <dd>
                <code>{command.lineage_parent_artifact_id}</code>
              </dd>
            </div>
          </>
        )}
      </dl>
    </li>
  );
}

function CommandSummary({
  command,
  index,
}: {
  readonly command: DemoPlanCommand;
  readonly index: number;
}) {
  const isResourceReplacement = command.schema === "simulator-quarantine-command/v1";
  return (
    <li className="shot-command">
      <div className="shot-command__heading">
        <span>{String(index + 1).padStart(2, "0")}</span>
        <div>
          <strong>
            {isResourceReplacement
              ? "Replace the shadowed LUT"
              : command.target.kind === "derivative"
                ? "Rerender the affected derivative"
                : "Rerender the affected frame"}
          </strong>
          <span>
            {command.target.kind}:{" "}
            {command.target.kind === "color-resource" && command.target.id.startsWith("sha256:")
              ? "show_look.cube"
              : command.target.id}
          </span>
        </div>
      </div>
      {isResourceReplacement ? (
        <p>Quarantine the mismatched resource and install the approved replacement.</p>
      ) : (
        <dl>
          <div>
            <dt>Job</dt>
            <dd>{command.job_id}</dd>
          </div>
          <div>
            <dt>Source</dt>
            <dd>{command.source_id}</dd>
          </div>
          <div>
            <dt>Transform</dt>
            <dd>{command.transform_id}</dd>
          </div>
        </dl>
      )}
    </li>
  );
}

function InvestigationReview({
  investigation,
}: {
  readonly investigation?: DemoInvestigationProof;
}) {
  if (investigation === undefined) {
    return (
      <section className="shot-panel">
        <p className="shot-eyebrow">Review evidence</p>
        <h2>Investigation proof pending</h2>
      </section>
    );
  }
  if (investigation.schema === "colortrace-demo-investigation-proof/v1") {
    return (
      <section aria-labelledby="shot-legacy-proof-title" className="shot-panel shot-legacy-proof">
        <p className="shot-eyebrow">Stored proof compatibility</p>
        <h2 id="shot-legacy-proof-title">Investigation proof v1</h2>
        <p>This earlier proof remains reviewable through the same verified recovery counts.</p>
        <dl className="shot-counts">
          <div>
            <dt>Affected</dt>
            <dd>{investigation.scope.affected_count}</dd>
          </div>
          <div>
            <dt>Protected</dt>
            <dd>{investigation.scope.safe_count}</dd>
          </div>
          <div>
            <dt>Unknown</dt>
            <dd>{investigation.scope.unknown_count}</dd>
          </div>
        </dl>
      </section>
    );
  }

  const { comparison, claims, plan, scope } = investigation;
  const claimState = (claimType: string) =>
    claims.find((claim) => claim.claim_type === claimType)?.state;
  return (
    <div className="shot-review">
      <section aria-labelledby="shot-comparison-proof-title" className="shot-panel">
        <div className="shot-section-heading">
          <div>
            <p className="shot-eyebrow">Diagnosis</p>
            <h2 id="shot-comparison-proof-title">Same configuration, different resolved LUT</h2>
          </div>
          <span className="shot-authority">Both renders succeeded</span>
        </div>
        <div className="shot-render-grid">
          {comparison.renders.map((render, index) => (
            <article key={render.job_id}>
              <div className="shot-render-heading">
                <strong>{render.job_id}</strong>
                <span>Succeeded</span>
              </div>
              <dl>
                <div>
                  <dt>Declared configuration</dt>
                  <dd>Matches</dd>
                </div>
                <div>
                  <dt>Resolved LUT</dt>
                  <dd>{index === 0 ? "Reference" : "Different"}</dd>
                </div>
              </dl>
            </article>
          ))}
        </div>
        <ul className="shot-finding-list">
          <li data-claim-state={claimState("causal-resource")}>
            <strong>Root cause confirmed</strong>
            <span>The resolved LUT content diverged on the affected work.</span>
          </li>
          <li data-claim-state={claimState("nominal-config")}>
            <strong>Declared configuration ruled out</strong>
            <span>Both renders used the same declared configuration.</span>
          </li>
          <li data-claim-state={claimState("worker-alone")}>
            <strong>Worker-only explanation rejected</strong>
            <span>The evidence points to the resolved resource, not the worker by itself.</span>
          </li>
        </ul>
      </section>

      <section aria-labelledby="shot-plan-title" className="shot-panel shot-plan-review">
        <div className="shot-section-heading">
          <div>
            <p className="shot-eyebrow">Bounded recovery plan</p>
            <h2 id="shot-plan-title">Recover only the affected work</h2>
          </div>
          <span className="shot-authority">Human approval required</span>
        </div>
        <dl className="shot-counts">
          <div>
            <dt>Affected</dt>
            <dd>{scope.affected_count}</dd>
          </div>
          <div>
            <dt>Protected</dt>
            <dd>{scope.safe_count}</dd>
          </div>
          <div>
            <dt>Unknown</dt>
            <dd>{scope.unknown_count}</dd>
          </div>
        </dl>
        <div className="shot-plan-summary">
          <p>
            <strong>Replace one shadowed LUT.</strong>
          </p>
          <p>Rerender three frames and one derivative.</p>
        </div>
        <div className="shot-plan-scope">
          <section>
            <h3>Action targets ({plan.targets.length})</h3>
            <TargetList emptyText="No action targets." targets={plan.targets} />
          </section>
          <section>
            <h3>Protected exclusions ({plan.protected_exclusions.length})</h3>
            <TargetList emptyText="No protected exclusions." targets={plan.protected_exclusions} />
          </section>
        </div>
        <ol className="shot-command-list">
          {plan.command_summaries.map((command, index) => (
            <CommandSummary command={command} index={index} key={command.command_id} />
          ))}
        </ol>
      </section>
    </div>
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
  const investigationV2 =
    run.investigation?.schema === "colortrace-demo-investigation-proof/v2"
      ? run.investigation
      : undefined;
  const actionEnvelopeRows: readonly (readonly [string, string | number])[] =
    investigationV2 === undefined
      ? []
      : [
          ["Schema", investigationV2.plan.shared_action_bindings.schema],
          ["Fixture", investigationV2.plan.shared_action_bindings.fixture_id],
          [
            "Fixture manifest SHA-256",
            investigationV2.plan.shared_action_bindings.fixture_manifest_sha256,
          ],
          ["Fixture generation", investigationV2.plan.shared_action_bindings.fixture_generation],
          ["Source batch", investigationV2.plan.shared_action_bindings.source_batch_id],
          ["Source batch SHA-256", investigationV2.plan.shared_action_bindings.source_batch_sha256],
          [
            "Runtime manifest SHA-256",
            investigationV2.plan.shared_action_bindings.runtime_manifest_sha256,
          ],
          ["Runtime generation", investigationV2.plan.shared_action_bindings.runtime_generation],
          [
            "Publication pointer SHA-256",
            investigationV2.plan.shared_action_bindings.expected_publication_pointer_sha256,
          ],
          [
            "Publication generation",
            investigationV2.plan.shared_action_bindings.expected_publication_generation,
          ],
          [
            "Expected resource SHA-256",
            investigationV2.plan.shared_action_bindings.expected_resource_sha256,
          ],
          [
            "Replacement path",
            investigationV2.plan.shared_action_bindings.replacement_resource_logical_path,
          ],
          [
            "Replacement resource SHA-256",
            investigationV2.plan.shared_action_bindings.replacement_resource_sha256,
          ],
          [
            "Declared resource manifest SHA-256",
            investigationV2.plan.shared_action_bindings.declared_resource_manifest_sha256,
          ],
          ["OCIO version", investigationV2.plan.shared_action_bindings.ocio_version],
          [
            "Preservation manifest SHA-256",
            investigationV2.plan.shared_action_bindings.preservation_manifest_sha256,
          ],
          [
            "Safe complement SHA-256",
            investigationV2.plan.shared_action_bindings.safe_complement_sha256,
          ],
          [
            "Lineage manifest SHA-256",
            investigationV2.plan.shared_action_bindings.lineage_manifest_sha256,
          ],
          ["Lineage generation", investigationV2.plan.shared_action_bindings.lineage_generation],
        ];
  return (
    <details className="shot-technical">
      <summary>Technical proof and provenance</summary>
      <div className="shot-technical__content">
        <section className="shot-technical__wide">
          <h3>Verified query evidence</h3>
          {run.investigation === undefined ? (
            <p>Investigation proof pending.</p>
          ) : (
            <div className="shot-technical-records" data-proof-section="investigation-evidence">
              {run.investigation.evidence.map((item) => (
                <article key={item.evidence_id}>
                  <strong>{item.query_key}</strong>
                  <dl>
                    <div>
                      <dt>Evidence ID</dt>
                      <dd>
                        <code>{item.evidence_id}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Tool</dt>
                      <dd>
                        <code>{item.tool}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Freshness</dt>
                      <dd>{item.freshness}</dd>
                    </div>
                    <div>
                      <dt>Inventory SHA-256</dt>
                      <dd>
                        <code>{item.inventory_sha256}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Content SHA-256</dt>
                      <dd>
                        <code>{item.content_sha256}</code>
                      </dd>
                    </div>
                  </dl>
                  {"display_excerpt" in item ? <pre>{item.display_excerpt}</pre> : null}
                </article>
              ))}
            </div>
          )}
        </section>
        {investigationV2 === undefined ? null : (
          <section className="shot-technical__wide">
            <h3>Adjudicated claims</h3>
            <div className="shot-technical-records" data-proof-section="adjudicated-claims">
              {investigationV2.claims.map((claim) => (
                <article key={claim.claim_id}>
                  <strong>{claim.claim_type}</strong>
                  <dl>
                    <div>
                      <dt>Claim ID</dt>
                      <dd>
                        <code>{claim.claim_id}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>State</dt>
                      <dd>{claim.state}</dd>
                    </div>
                    <div>
                      <dt>Subject</dt>
                      <dd>
                        <code>
                          {claim.subject.kind}:{claim.subject.value}
                        </code>
                      </dd>
                    </div>
                    <div>
                      <dt>Reason codes</dt>
                      <dd>
                        <code>{claim.reason_codes.join(", ")}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Evidence IDs</dt>
                      <dd>
                        <code>{claim.evidence_ids.join(", ")}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Validator result</dt>
                      <dd>
                        <code>{claim.source_validator_result_id}</code>
                      </dd>
                    </div>
                  </dl>
                </article>
              ))}
            </div>
          </section>
        )}
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
                    <br />
                    <code>{item.invocation_id}</code> · trace <code>{item.trace_id}</code>
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>
        <section>
          <h3>Run identity and versions</h3>
          <dl>
            <div>
              <dt>Run ID</dt>
              <dd>
                <code>{run.run_id}</code>
              </dd>
            </div>
            <div>
              <dt>Incident ID</dt>
              <dd>
                <code>{run.incident_id}</code>
              </dd>
            </div>
            <div>
              <dt>Scenario ID</dt>
              <dd>
                <code>{run.scenario_id}</code>
              </dd>
            </div>
            <div>
              <dt>Source commit</dt>
              <dd>
                <code>{run.source_commit}</code>
              </dd>
            </div>
            <div>
              <dt>Run version</dt>
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
        {investigationV2 === undefined ? null : (
          <>
            <section>
              <h3>Plan bindings</h3>
              <dl>
                <div>
                  <dt>Plan version</dt>
                  <dd>{investigationV2.plan.version}</dd>
                </div>
                <div>
                  <dt>Plan SHA-256</dt>
                  <dd>
                    <code>{investigationV2.plan.plan_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Targets SHA-256</dt>
                  <dd>
                    <code>{investigationV2.plan.target_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Exclusions SHA-256</dt>
                  <dd>
                    <code>{investigationV2.plan.exclusions_sha256}</code>
                  </dd>
                </div>
                <div>
                  <dt>Commands SHA-256</dt>
                  <dd>
                    <code>{investigationV2.plan.commands_sha256}</code>
                  </dd>
                </div>
              </dl>
            </section>
            <section className="shot-technical__wide">
              <h3>Shared action envelope</h3>
              <dl>
                {actionEnvelopeRows.map(([label, value]) => (
                  <div key={label}>
                    <dt>{label}</dt>
                    <dd>
                      <code>{value}</code>
                    </dd>
                  </div>
                ))}
              </dl>
            </section>
            <section className="shot-technical__wide">
              <h3>Raw command bindings</h3>
              <ol className="shot-command-list">
                {investigationV2.plan.command_summaries.map((command, index) => (
                  <TechnicalCommandDetails
                    command={command}
                    index={index}
                    key={command.command_id}
                  />
                ))}
              </ol>
            </section>
          </>
        )}
        <section className="shot-technical__digests">
          <h3>Digest bindings</h3>
          <dl>
            <div>
              <dt>Investigation packet</dt>
              <dd>
                <code>{run.investigation?.packet_sha256 ?? "Pending"}</code>
              </dd>
            </div>
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
                  <dt>Closure</dt>
                  <dd>
                    <code>{receipt.bindings.closure_sha256 ?? "Not applicable"}</code>
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
          <section className="shot-technical__wide">
            <h3>Recovery checks</h3>
            <dl data-proof-section="recovery-checks">
              {run.execution.recovery.checks.map((item) => (
                <div key={item.check}>
                  <dt>{item.check}</dt>
                  <dd>
                    {item.status} · <code>{item.result_sha256}</code>
                  </dd>
                </div>
              ))}
            </dl>
          </section>
        )}
        <p className="shot-technical__boundary">
          This disclosure contains the reviewable bindings. Raw logs, metric series, trace payloads,
          internal paths, and credentials remain private.
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
  onReject,
  onRecheck,
  visualsReady,
}: {
  readonly actionError: string | null;
  readonly busy: boolean;
  readonly nonce: string | null;
  readonly onApprove: (nonce: string, phrase: string) => void;
  readonly onReject: (nonce: string, reason: DemoRejectionReason) => void;
  readonly onRecheck: () => void;
  readonly visualsReady: boolean;
}) {
  const [nonceInput, setNonceInput] = useState("");
  const [phraseInput, setPhraseInput] = useState("");
  const [rejectionReason, setRejectionReason] = useState<DemoRejectionReason | "">("");
  const [confirmed, setConfirmed] = useState(false);
  const nonceMatches = nonce !== null && nonceInput === nonce;
  const approvalReady =
    nonceMatches && phraseInput === DEMO_APPROVAL_PHRASE && confirmed && visualsReady;

  if (actionError !== null) {
    return (
      <section aria-labelledby="approval-title" className="shot-panel shot-action-panel">
        <p className="shot-eyebrow">Human review boundary</p>
        <h2 id="approval-title">Decision paused</h2>
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
        <p className="shot-eyebrow">Human review boundary</p>
        <h2 id="approval-title">Review cannot continue in this browser</h2>
        <p className="shot-alert" role="alert">
          The one-time review nonce is unavailable. No approval or rejection can be sent.
        </p>
        <button className="shot-button shot-button--secondary" onClick={onRecheck} type="button">
          Recheck run state
        </button>
      </section>
    );
  }

  return (
    <section aria-labelledby="approval-title" className="shot-panel shot-action-panel">
      <p className="shot-eyebrow">Human review boundary</p>
      <h2 id="approval-title">Decide the exact plan</h2>
      <p>Either decision applies only to this investigation and the displayed recovery scope.</p>
      <div className="shot-issued-nonce">
        <span>Run nonce</span>
        <code>{nonce}</code>
      </div>
      <div className="shot-form-grid">
        <div>
          <label htmlFor="shot-approval-nonce">Retype review nonce</label>
          <input
            autoComplete="off"
            id="shot-approval-nonce"
            onChange={(event) => setNonceInput(event.currentTarget.value)}
            spellCheck={false}
            value={nonceInput}
          />
        </div>
        <div className="shot-approval-fields">
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
      <div className="shot-decision-grid">
        <section className="shot-decision-option">
          <div>
            <p className="shot-eyebrow">Approve</p>
            <h3>Authorize this recovery</h3>
            <p>Approval unlocks only after every comparison image is verified.</p>
          </div>
          <label className="shot-checkbox">
            <input
              checked={confirmed}
              onChange={(event) => setConfirmed(event.currentTarget.checked)}
              type="checkbox"
            />
            <span>I approve only the displayed targets and keep the exclusions protected.</span>
          </label>
          <button
            className="shot-button shot-button--primary"
            disabled={!approvalReady || busy}
            onClick={() => onApprove(nonceInput, phraseInput)}
            type="button"
          >
            {busy ? "Submitting decision…" : "Approve recovery action"}
          </button>
          {!visualsReady ? (
            <p className="shot-form-note">
              Approval unlocks after all comparison images are verified.
            </p>
          ) : null}
        </section>
        <section className="shot-decision-option shot-decision-option--reject">
          <div>
            <p className="shot-eyebrow">Reject</p>
            <h3>Stop this plan without dispatch</h3>
            <p>Rejection records a terminal receipt and sends no simulator action.</p>
          </div>
          <label htmlFor="shot-rejection-reason">Rejection reason</label>
          <select
            id="shot-rejection-reason"
            onChange={(event) =>
              setRejectionReason(event.currentTarget.value as DemoRejectionReason | "")
            }
            value={rejectionReason}
          >
            <option value="">Select a reason</option>
            {DEMO_REJECTION_REASONS.map((reason) => (
              <option key={reason} value={reason}>
                {reason}
              </option>
            ))}
          </select>
          <button
            className="shot-button shot-button--danger"
            disabled={!nonceMatches || rejectionReason === "" || busy}
            onClick={() => {
              if (rejectionReason !== "") onReject(nonceInput, rejectionReason);
            }}
            type="button"
          >
            {busy ? "Submitting decision…" : "Reject plan"}
          </button>
          <p className="shot-form-note">Verified visuals are not required to reject.</p>
        </section>
      </div>
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
      <h2 id="closure-title">Recovered image verified</h2>
      <p className="shot-result-summary">Protected outputs verified.</p>
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
        <span>I verified the recovered image and the protected outputs.</span>
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
  const rejected = run.terminal_reason?.startsWith("plan-rejected-") ?? false;
  return (
    <section
      aria-labelledby="terminal-title"
      className="shot-panel shot-terminal"
      data-terminal-phase={run.phase}
    >
      <p className="shot-eyebrow">Run result</p>
      <h2 id="terminal-title">
        {closed
          ? "Recovery closed with a verified receipt"
          : rejected
            ? "Plan rejected with a verified receipt"
            : "Run stopped without closure"}
      </h2>
      <p>
        {closed
          ? "The action, recovered output, and human decision are recorded together."
          : rejected
            ? "No simulator action was dispatched. The rejection and exact plan bindings are recorded in the immutable receipt."
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
            <dt>Action</dt>
            <dd>{closed ? "Completed" : rejected ? "Not dispatched" : "Stopped"}</dd>
          </div>
          <div>
            <dt>Receipt</dt>
            <dd>Recorded and verified</dd>
          </div>
          <div>
            <dt>{rejected ? "Decision reason" : "Closure"}</dt>
            <dd>{rejected ? receipt.reason_code : "Verified"}</dd>
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
  const rejectionKey = useRef<string | null>(null);
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
    (next: DemoRun, nonce: string | null = approvalNonceRef.current): boolean => {
      const current = runRef.current;
      if (current?.run_id === next.run_id) {
        if (
          current.incident_id !== next.incident_id ||
          current.scenario_id !== next.scenario_id ||
          current.source_commit !== next.source_commit ||
          current.build_sha256 !== next.build_sha256
        ) {
          setActionError("The service returned conflicting immutable run bindings.");
          return false;
        }
        if (next.version < current.version) return false;
      }
      const usableNonce = next.phase === "awaiting-approval" ? nonce : null;
      approvalNonceRef.current = usableNonce;
      runRef.current = next;
      setRun(next);
      setApprovalNonce(usableNonce);
      pendingStartNonce.current = null;
      pendingStartKey.current = null;
      persistRun(sessionStorage, next.run_id, usableNonce);
      return true;
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
      rejectionKey.current = null;
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
      return acceptRun(next, null);
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
          if (acceptRun(next)) setActionError(null);
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
        if (acceptRun(next)) setActionError(null);
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

  const reject = useCallback(
    (nonce: string, reason: DemoRejectionReason) => {
      if (run?.phase !== "awaiting-approval" || run.approval === null) return;
      const key = rejectionKey.current ?? mutationKey("demo-reject");
      rejectionKey.current = key;
      setBusy(true);
      setActionError(null);
      void adapter
        .reject(run.run_id, {
          schema: "colortrace-demo-rejection-request/v1",
          approval_nonce: nonce,
          expected_run_version: run.version,
          expected_incident_version: run.approval.incident_version,
          expected_plan_version: run.approval.plan_version,
          expected_plan_sha256: run.approval.plan_sha256,
          expected_target_sha256: run.approval.target_sha256,
          reason_code: reason,
          idempotency_key: key,
        })
        .then((next) => acceptRun(next, null))
        .catch((error: unknown) => setActionError(errorMessage(error, "mutate")))
        .finally(() => setBusy(false));
    },
    [acceptRun, adapter, run],
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
              <h1>A successful render can still be the wrong color.</h1>
              <p className="shot-lede">
                ColorTrace traces a color mismatch through read-only evidence, isolates the affected
                work, and keeps recovery behind human approval.
              </p>
              <ol className="shot-flow" aria-label="ColorTrace recovery flow">
                <li>
                  <strong>Detect</strong>
                  <span>Compare expected and observed output.</span>
                </li>
                <li>
                  <strong>Explain</strong>
                  <span>Trace the mismatch to its resolved resource.</span>
                </li>
                <li>
                  <strong>Approve</strong>
                  <span>Review exact targets and protected work.</span>
                </li>
                <li>
                  <strong>Verify</strong>
                  <span>Confirm the recovery and record the receipt.</span>
                </li>
              </ol>
              <p className="shot-landing__integration">
                Gemini guides evidence selection. Grafana supplies the operational record.
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
                {busy ? "Preparing recovery…" : "Investigate the color fault"}
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
                  <p className="shot-eyebrow">Color fault investigation</p>
                  <h1 id="comparison-title" ref={contentHeading} tabIndex={-1}>
                    Expected versus observed
                  </h1>
                  <p>
                    Compare the visible fault, understand its cause, and approve only the work that
                    needs recovery.
                  </p>
                </div>
                <div className="shot-identity">
                  <span>Current phase</span>
                  <strong>{phaseLabel(run.phase)}</strong>
                </div>
              </div>
              {visualError === null ? null : (
                <p className="shot-alert" role="alert">
                  {visualError}
                </p>
              )}
              <div className="shot-visual-grid shot-visual-grid--primary">
                <VisualCard
                  alt="Declared expected output"
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
                  alt="Observed output with a visible color shift"
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
                  <h2>The returned images show a visible output difference.</h2>
                  <p>
                    ColorTrace uses the operational record below to explain the mismatch and bound a
                    safe recovery plan.
                  </p>
                </div>
              </div>
            </section>

            <InvestigationReview investigation={run.investigation} />

            {run.phase === "awaiting-approval" ? (
              <ApprovalPanel
                actionError={actionError}
                busy={busy}
                nonce={approvalNonce}
                onApprove={approve}
                onReject={reject}
                onRecheck={recheck}
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
                  <span className="shot-authority">Recovery verified</span>
                </div>
                <div className="shot-recovered__content">
                  <VisualCard
                    alt="Recovered output"
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
                    <p className="shot-result-summary">
                      <strong>Protected outputs verified.</strong>
                    </p>
                    <p>The affected outputs changed; the excluded outputs remained intact.</p>
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
        <span>Human review remains the action boundary.</span>
      </footer>
    </div>
  );
}
