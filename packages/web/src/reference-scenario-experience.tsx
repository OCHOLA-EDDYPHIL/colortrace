import { useEffect, useMemo, useRef, useState } from "react";

import {
  REFERENCE_SCENARIO_IDS,
  type ReferenceBenchmarkSuite,
  type ReferenceDemoAdapter,
  type ReferenceIncidentClass,
  type ReferenceRecoveryKind,
  type ReferenceScenarioDetail,
  type ReferenceScenarioId,
  type ReferenceScenarioList,
  type ReferenceScenarioSummary,
  type ReferenceVisualDescriptor,
  type ReferenceVisualKind,
  type VerifiedLiveReferenceVisual,
  type VerifiedReferenceVisual,
} from "./reference-demo-api.ts";
import type {
  ReferenceActionIntent,
  ReferenceResponsePacket,
  ReferenceSelectionTraceEntry,
} from "./reference-run-contract.ts";
import {
  REFERENCE_APPROVAL_PHRASE,
  REFERENCE_DENIAL_PHRASE,
  type ReferenceRecoveryChoice,
  type ReferenceRecoveryDecision,
} from "./reference-recovery-contract.ts";

export type ReferenceScenarioExperienceProps = {
  readonly adapter: ReferenceDemoAdapter;
};

type IncidentPresentation = {
  readonly shortLabel: string;
  readonly causalField: string;
  readonly explanation: string;
};

const INCIDENT_PRESENTATION: Readonly<Record<ReferenceIncidentClass, IncidentPresentation>> = {
  "resource-resolution-drift/v1": {
    shortLabel: "Resource resolution",
    causalField: "Effective resource digest",
    explanation: "The worker resolved a different LUT than the approved reference.",
  },
  "configuration-rollout-drift/v1": {
    shortLabel: "Configuration rollout",
    causalField: "Effective config digest + generation",
    explanation: "An older color configuration stayed active while its LUT remained current.",
  },
  "stale-derivative-cache/v1": {
    shortLabel: "Derivative cache",
    causalField: "Derivative parent + cache generation",
    explanation: "The frame is correct, but the review derivative came from an older parent.",
  },
};

const RECOVERY_PRESENTATION: Readonly<Record<ReferenceRecoveryKind, string>> = {
  "reconcile-resource": "Restore the approved resource, then target only affected frames.",
  "pin-rollout": "Pin the approved configuration generation, then target only affected frames.",
  "invalidate-cache": "Invalidate the stale keys, then rebuild only affected derivatives.",
};

function visual(
  summary: ReferenceScenarioSummary,
  kind: ReferenceVisualKind,
): ReferenceVisualDescriptor | null {
  return summary.visuals.find((item) => item.kind === kind) ?? null;
}

function basisPoints(value: number): string {
  return `${String(value / 100)}%`;
}

function milliseconds(nanoseconds: number): string {
  return `${(nanoseconds / 1_000_000).toFixed(2)} ms`;
}

function loadErrorMessage(): string {
  return "Reference contracts are unavailable. No scenario result is being shown.";
}

function sourceRelationLabel(descriptor: ReferenceVisualDescriptor): string {
  switch (descriptor.source_relation) {
    case "current":
      return "Current worker output";
    case "stale-parent":
      return "Prior-parent derivative from stale cache";
    case "amplified-absolute-display-difference-8x":
      return "Absolute display difference · amplified 8×";
  }
}

function OpenFilmVisual({
  adapter,
  descriptor,
  label,
  loading = "lazy",
  scenarioSha256,
  scenarioTitle,
}: {
  readonly adapter: ReferenceDemoAdapter;
  readonly descriptor: ReferenceVisualDescriptor | null;
  readonly label: string;
  readonly loading?: "eager" | "lazy";
  readonly scenarioSha256: string;
  readonly scenarioTitle: string;
}) {
  const [loaded, setLoaded] = useState<VerifiedReferenceVisual | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (descriptor === null) return;
    const controller = new AbortController();
    let retained: VerifiedReferenceVisual | null = null;
    setLoaded(null);
    setFailed(false);
    void adapter
      .loadVisual(descriptor, scenarioSha256, controller.signal)
      .then((next) => {
        if (controller.signal.aborted) {
          adapter.releaseVisual(next);
          return;
        }
        retained = next;
        setLoaded(next);
      })
      .catch(() => {
        if (!controller.signal.aborted) setFailed(true);
      });
    return () => {
      controller.abort();
      if (retained !== null) adapter.releaseVisual(retained);
    };
  }, [adapter, descriptor, scenarioSha256]);

  return (
    <figure className="reference-visual" data-pixel-evidence="true">
      <figcaption>
        <strong>{label}</strong>
        <span>
          {failed
            ? "Pixel evidence withheld"
            : loaded === null
              ? "Verifying pixels…"
              : "PNG hash verified · pixel evidence"}
        </span>
      </figcaption>
      {descriptor === null || failed ? (
        <div
          aria-label={`${label} pixel preview unavailable`}
          className="reference-visual__fallback"
          role="img"
        >
          Pixel evidence withheld
        </div>
      ) : loaded === null ? (
        <div
          aria-label={`${label} pixel preview loading`}
          className="reference-visual__fallback"
          role="img"
        >
          Verifying open-film pixels…
        </div>
      ) : (
        <img
          alt={`${label} open-film pixel preview for ${scenarioTitle}`}
          height={loaded.height}
          loading={loading}
          onError={() => setFailed(true)}
          src={loaded.src}
          width={loaded.width}
        />
      )}
      {descriptor === null ? null : (
        <p className="reference-visual__relation">{sourceRelationLabel(descriptor)}</p>
      )}
      {descriptor === null || loaded === null || failed ? null : (
        <details className="reference-visual__provenance">
          <summary>Pixel provenance</summary>
          <dl>
            <div>
              <dt>Served artifact</dt>
              <dd>
                <code>{descriptor.served_artifact_id}</code>
              </dd>
            </div>
            <div>
              <dt>Source artifacts</dt>
              <dd>{descriptor.source_artifact_ids.length} bound</dd>
            </div>
            <div>
              <dt>Worker receipts</dt>
              <dd>{descriptor.source_receipt_sha256.length} bound</dd>
            </div>
            <div>
              <dt>Output digests</dt>
              <dd>{descriptor.source_output_sha256.length} bound</dd>
            </div>
            <div>
              <dt>Canonical pixel digests</dt>
              <dd>{descriptor.source_canonical_pixel_sha256.length} bound</dd>
            </div>
            <div>
              <dt>Preview SHA-256</dt>
              <dd>
                <code>{loaded.content_sha256}</code>
              </dd>
            </div>
          </dl>
        </details>
      )}
    </figure>
  );
}

export function ReferencePrimaryEvidence({ adapter }: ReferenceScenarioExperienceProps) {
  const [catalog, setCatalog] = useState<ReferenceScenarioList | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void adapter
      .listScenarios(controller.signal)
      .then((next) => {
        setCatalog(next);
        setCatalogError(null);
      })
      .catch(() => {
        if (!controller.signal.aborted) setCatalogError(loadErrorMessage());
      });
    return () => controller.abort();
  }, [adapter]);

  const summary =
    catalog?.items.find((item) => item.scenario_id === REFERENCE_SCENARIO_IDS[0]) ?? null;

  return (
    <section
      aria-labelledby="reference-primary-evidence-title"
      className="reference-primary-evidence"
    >
      <div className="reference-primary-evidence__heading">
        <div>
          <p className="shot-eyebrow">Checksum-verified open-film evidence</p>
          <h2 id="reference-primary-evidence-title">
            {summary?.title ?? "Verifying the sealed reference scenario"}
          </h2>
        </div>
        <span>{summary === null ? "Verifying contract" : "Receipt-bound pixels"}</span>
      </div>

      {catalogError === null ? null : (
        <p className="shot-alert" role="status">
          {catalogError}
        </p>
      )}

      {catalog === null || summary === null ? (
        catalogError === null ? (
          <div className="reference-primary-evidence__loading" role="status">
            Loading sealed open-film pixel evidence…
          </div>
        ) : null
      ) : (
        <>
          <div className="reference-primary-evidence__visuals">
            <OpenFilmVisual
              adapter={adapter}
              descriptor={visual(summary, "expected")}
              label="Expected state"
              loading="eager"
              scenarioSha256={summary.scenario_sha256}
              scenarioTitle={summary.title}
            />
            <OpenFilmVisual
              adapter={adapter}
              descriptor={visual(summary, "observed")}
              label="Observed failure"
              loading="eager"
              scenarioSha256={summary.scenario_sha256}
              scenarioTitle={summary.title}
            />
          </div>
          <p className="reference-primary-evidence__provenance">
            <span>Source</span>
            <strong>{catalog.provenance.attribution}</strong>
            <small>{catalog.provenance.license.spdx}</small>
          </p>
        </>
      )}
    </section>
  );
}

function SupportingPixelEvidence({
  adapter,
  scenarioSha256,
  scenarioTitle,
  summary,
}: {
  readonly adapter: ReferenceDemoAdapter;
  readonly scenarioSha256: string;
  readonly scenarioTitle: string;
  readonly summary: ReferenceScenarioSummary;
}) {
  const descriptor = visual(summary, "diff");

  return (
    <section
      aria-labelledby="reference-supporting-view-title"
      className="reference-supporting-view"
    >
      <div className="reference-supporting-view__heading">
        <div>
          <span>Supporting pixel evidence</span>
          <h4 id="reference-supporting-view-title">Inspect the amplified difference</h4>
        </div>
        <span className="reference-supporting-view__gate">
          Recovery appears only after approval
        </span>
      </div>
      <div className="reference-supporting-view__content">
        <OpenFilmVisual
          adapter={adapter}
          descriptor={descriptor}
          label="Difference ×8"
          scenarioSha256={scenarioSha256}
          scenarioTitle={scenarioTitle}
        />
        <p>
          The absolute display-pixel difference is amplified 8× so small changes remain visible. Its
          displayed intensity is not a direct measurement of error magnitude.
        </p>
      </div>
    </section>
  );
}

type LiveInvestigationState =
  | { readonly phase: "idle" }
  | { readonly phase: "running" }
  | { readonly phase: "failed" }
  | { readonly packet: ReferenceResponsePacket; readonly phase: "complete" };

function selectionAuthority(entry: ReferenceSelectionTraceEntry): string {
  return entry.selected_by === "model" ? "Gemini selected" : "Policy baseline";
}

function modelUsageSummary(invocation: NonNullable<ReferenceResponsePacket["model_invocation"]>) {
  const calls = `${invocation.model_calls} model ${invocation.model_calls === 1 ? "call" : "calls"}`;
  if (
    invocation.input_tokens === null &&
    invocation.output_tokens === null &&
    invocation.unobserved_model_calls === invocation.model_calls
  ) {
    return `${calls} · provider usage unavailable`;
  }
  if (invocation.unobserved_model_calls > 0) {
    const unobserved = `${invocation.unobserved_model_calls} ${invocation.unobserved_model_calls === 1 ? "call" : "calls"} unobserved`;
    return `${calls} · partial usage observed; exact token totals unavailable (${unobserved})`;
  }
  if (invocation.input_tokens === null || invocation.output_tokens === null) {
    return `${calls} · provider usage unavailable`;
  }
  return `${calls} · ${invocation.input_tokens} in / ${invocation.output_tokens} out`;
}

function attemptSummary(span: ReferenceResponsePacket["agent_trace"]["spans"][number]) {
  if (!span.attempts_complete) {
    return span.attempts === 0
      ? "attempt count unavailable"
      : `at least ${span.attempts} ${span.attempts === 1 ? "attempt" : "attempts"}`;
  }
  return `${span.attempts} ${span.attempts === 1 ? "attempt" : "attempts"}`;
}

function CorrelatedEvidenceTable({ packet }: { readonly packet: ReferenceResponsePacket }) {
  const observations = packet.runtime_evidence_projection.observations;

  return (
    <section
      aria-labelledby="reference-correlated-evidence-title"
      className="reference-live__correlation"
    >
      <div className="reference-live__subheading">
        <div>
          <span>Sanitized structured evidence</span>
          <h5 id="reference-correlated-evidence-title">Correlated Grafana facts</h5>
        </div>
        <small className="reference-live__subheading-note">job · trace · observed time</small>
      </div>
      {observations.length === 0 ? (
        <p>No normalized runtime observations were returned.</p>
      ) : (
        <div className="reference-live__correlation-table-wrap">
          <table>
            <caption>
              Affected and protected Grafana evidence bound to the same run and deterministic scope.
            </caption>
            <thead>
              <tr>
                <th scope="col">Scope</th>
                <th scope="col">Job</th>
                <th scope="col">Trace</th>
                <th scope="col">Observed</th>
                <th scope="col">Query / signal</th>
                <th scope="col">Decisive field / value</th>
                <th scope="col">Evidence ID</th>
              </tr>
            </thead>
            <tbody>
              {observations.map((observation) => (
                <tr data-scope-role={observation.scope_role} key={observation.fact_id}>
                  <td>
                    <strong>{observation.scope_role}</strong>
                  </td>
                  <td>
                    <code>{observation.job_id}</code>
                  </td>
                  <td>
                    <code>{observation.trace_id}</code>
                  </td>
                  <td>
                    <time dateTime={observation.observed_at}>{observation.observed_at}</time>
                  </td>
                  <td>
                    <code>{observation.query_key}</code>
                    <span>{observation.signal}</span>
                  </td>
                  <td>
                    <ul>
                      {observation.decisive_values.map(({ field, value }) => (
                        <li key={field}>
                          <code>{field}</code>
                          <span>=</span>
                          <code>{value}</code>
                        </li>
                      ))}
                    </ul>
                  </td>
                  <td>
                    <code>{observation.evidence_id}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ActionIntentView({ intent }: { readonly intent: ReferenceActionIntent }) {
  return (
    <section aria-labelledby="reference-action-intent-title" className="reference-live__intent">
      <div>
        <span>Non-authorizing action intent</span>
        <h5 id="reference-action-intent-title">{intent.command}</h5>
      </div>
      <dl>
        <div>
          <dt>Target</dt>
          <dd>{intent.target}</dd>
        </div>
        <div>
          <dt>Affected jobs</dt>
          <dd>{intent.affected_job_ids.length}</dd>
        </div>
        <div>
          <dt>Human approval</dt>
          <dd>{intent.requires_human_approval ? "Required" : "Not required"}</dd>
        </div>
        <div>
          <dt>Authorizes execution</dt>
          <dd>{intent.authorizes_execution ? "Yes" : "No"}</dd>
        </div>
      </dl>
      <details>
        <summary>Inspect exact intent and affected IDs</summary>
        <p>
          Intent ID: <code>{intent.action_intent_id}</code>
        </p>
        <ul>
          {intent.affected_job_ids.map((jobId) => (
            <li key={jobId}>
              <code>{jobId}</code>
            </li>
          ))}
        </ul>
        <pre>{JSON.stringify(intent.parameters, null, 2)}</pre>
      </details>
      <p className="reference-live__boundary">
        This proposed simulator intent does not authorize itself. A separate recorded human demo
        gesture is required before the simulator can apply it.
      </p>
    </section>
  );
}

type RecoveryDecisionState =
  | { readonly phase: "idle" }
  | { readonly choice: ReferenceRecoveryChoice; readonly phase: "pending" }
  | {
      readonly decision: ReferenceRecoveryDecision;
      readonly liveVisual: VerifiedLiveReferenceVisual | null;
      readonly phase: "complete";
    }
  | { readonly phase: "failed" };

function RecoveryDecisionResult({
  decision,
  liveVisual,
}: {
  readonly decision: ReferenceRecoveryDecision;
  readonly liveVisual: VerifiedLiveReferenceVisual | null;
}) {
  const applied = decision.outcome === "applied";
  const receipt = decision.receipt;
  const verification = decision.verification;

  return (
    <div className="reference-recovery__result">
      <div className="reference-recovery__result-heading">
        <div>
          <span>{applied ? "Applied and verified" : "Denied"}</span>
          <h5>
            {applied
              ? "Representative simulator recovery applied"
              : "Recovery denied; simulator unchanged"}
          </h5>
        </div>
        <strong data-decision-outcome={decision.outcome}>{decision.outcome}</strong>
      </div>

      <p className="reference-recovery__gesture">
        Human demo gesture recorded with an explicit phrase and unique nonce. Identity was not
        verified; assurance is <code>unverified-public-demo-gesture</code>.
      </p>

      {liveVisual === null ? null : (
        <figure className="reference-recovery__live-visual" data-pixel-evidence="true">
          <figcaption>
            <strong>Fresh recovered output</strong>
            <span>Rendered after approval · PNG and receipt bindings verified</span>
          </figcaption>
          <img
            alt="Fresh recovered open-film output produced after this approval"
            height={liveVisual.height}
            src={liveVisual.src}
            width={liveVisual.width}
          />
          <p>
            Request <code>{liveVisual.request_id}</code> · worker receipt{" "}
            <code>{liveVisual.worker_receipt_sha256}</code>
          </p>
        </figure>
      )}

      <dl className="reference-recovery__state-grid">
        <div>
          <dt>Generation</dt>
          <dd>
            {decision.before.generation} → {decision.after.generation}
          </dd>
        </div>
        <div>
          <dt>Before state</dt>
          <dd>
            <code>{decision.before.state_sha256}</code>
          </dd>
        </div>
        <div>
          <dt>After state</dt>
          <dd>
            <code>{decision.after.state_sha256}</code>
          </dd>
        </div>
        <div>
          <dt>Protected state</dt>
          <dd>{decision.protected_state_unchanged ? "Unchanged" : "Not established"}</dd>
        </div>
        <div>
          <dt>Receipt</dt>
          <dd>{receipt === null ? "Not issued" : receipt.receipt_id}</dd>
        </div>
        <div>
          <dt>Receipt SHA-256</dt>
          <dd>{receipt === null ? "Not issued" : <code>{receipt.receipt_sha256}</code>}</dd>
        </div>
      </dl>

      {verification === null ? (
        <p className="reference-recovery__verification">
          No recovery receipt or post-action verification was issued because the action was denied.
          The representative simulator state stayed unchanged.
        </p>
      ) : (
        <div className="reference-recovery__verification">
          <strong>Fresh simulator state verified</strong>
          <p>
            Generation advanced once; intent-expected fields matched for the affected exemplar; the
            protected hash and receipt state bindings matched.
          </p>
          <code>{verification.verification_sha256}</code>
          <p>
            The approved exemplar was rendered by the in-host worker and its canonical pixels match
            the expected output. This does not establish full-population behavior or production
            evidence.
          </p>
        </div>
      )}

      <p className="reference-recovery__scope">
        Representative scope only: {decision.scope.affected_job_count} affected exemplar +{" "}
        {decision.scope.protected_job_count} protected control. No full-population claim.
      </p>
      <p className="reference-recovery__production">
        Production untouched: no production access was used, no production state changed, and no
        production claim is made.
      </p>
    </div>
  );
}

function recoveryAuthoritySummary(
  packet: ReferenceResponsePacket,
  state: RecoveryDecisionState,
): string {
  const investigation = liveAuthoritySummary(packet).replace(
    " → human approval still required.",
    "",
  );
  if (state.phase === "idle") return liveAuthoritySummary(packet);
  if (state.phase === "pending") {
    return `${investigation} → human demo gesture submitted → awaiting simulator decision.`;
  }
  if (state.phase === "failed") {
    return `${investigation} → decision response unavailable or invalid; no outcome shown.`;
  }
  return state.decision.outcome === "applied"
    ? `${investigation} → human demo gesture recorded → representative simulator action applied → fresh worker pixels verified.`
    : `${investigation} → human denial recorded → simulator unchanged.`;
}

function ReferenceRecoveryDecisionControl({
  adapter,
  onStateChange,
  packet,
  state,
}: {
  readonly adapter: ReferenceDemoAdapter;
  readonly onStateChange: (state: RecoveryDecisionState) => void;
  readonly packet: ReferenceResponsePacket;
  readonly state: RecoveryDecisionState;
}) {
  const activeDecision = useRef<AbortController | null>(null);

  useEffect(() => {
    return () => activeDecision.current?.abort();
  }, []);

  const decide = (choice: ReferenceRecoveryChoice) => {
    activeDecision.current?.abort();
    const controller = new AbortController();
    activeDecision.current = controller;
    onStateChange({ choice, phase: "pending" });
    void adapter
      .decideRecovery(packet, choice, controller.signal)
      .then(async (decision) => {
        const liveVisual =
          decision.decision === "approved"
            ? await adapter.loadLiveRecoveredVisual(decision, controller.signal)
            : null;
        if (!controller.signal.aborted) {
          onStateChange({ decision, liveVisual, phase: "complete" });
        } else if (liveVisual !== null) {
          adapter.releaseVisual(liveVisual);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) onStateChange({ phase: "failed" });
      });
  };

  return (
    <section aria-labelledby="reference-recovery-decision-title" className="reference-recovery">
      <div className="reference-recovery__heading">
        <div>
          <span>Human decision boundary</span>
          <h5 id="reference-recovery-decision-title">Decide the representative simulator action</h5>
        </div>
        <small className="reference-recovery__boundary-note">
          Simulator only · 1 affected + 1 protected
        </small>
      </div>

      {state.phase === "complete" ? (
        <RecoveryDecisionResult decision={state.decision} liveVisual={state.liveVisual} />
      ) : (
        <>
          <p className="reference-recovery__limitations">
            This public demo gesture is not verified identity. It can change only representative
            simulator state; it cannot access production and does not establish full-population or
            pixel-output behavior.
          </p>
          <div className="reference-recovery__choices">
            <div>
              <button
                disabled={state.phase === "pending"}
                onClick={() => decide("approved")}
                type="button"
              >
                Approve simulator action
              </button>
              <code>{REFERENCE_APPROVAL_PHRASE}</code>
            </div>
            <div>
              <button
                disabled={state.phase === "pending"}
                onClick={() => decide("denied")}
                type="button"
              >
                Deny without change
              </button>
              <code>{REFERENCE_DENIAL_PHRASE}</code>
            </div>
          </div>
          {state.phase === "idle" ? (
            <p className="reference-recovery__status">
              No approval was requested or granted, and no recovery ran.
            </p>
          ) : state.phase === "pending" ? (
            <p aria-live="polite" className="reference-recovery__status" role="status">
              {state.choice === "approved"
                ? "Recording the approval gesture and waiting for the simulator…"
                : "Recording the denial gesture and confirming unchanged simulator state…"}
            </p>
          ) : (
            <p className="shot-alert" role="alert">
              Decision unavailable or invalid. No applied or denied outcome is being shown.
            </p>
          )}
        </>
      )}

      <p className="reference-live__authority">{recoveryAuthoritySummary(packet, state)}</p>
    </section>
  );
}

function LiveInvestigationResult({
  adapter,
  decisionState,
  onDecisionStateChange,
  packet,
  summary,
}: {
  readonly adapter: ReferenceDemoAdapter;
  readonly decisionState: RecoveryDecisionState;
  readonly onDecisionStateChange: (state: RecoveryDecisionState) => void;
  readonly packet: ReferenceResponsePacket;
  readonly summary: ReferenceScenarioSummary;
}) {
  const reconciliation = packet.diagnosis_reconciliation;
  const invocation = packet.model_invocation;
  const resolved = packet.status === "resolved";
  const diagnosis =
    reconciliation.status !== "supported" || reconciliation.incident_class === null
      ? null
      : INCIDENT_PRESENTATION[reconciliation.incident_class];
  const decisiveFields = [
    ...new Set(
      packet.runtime_evidence_projection.observations.flatMap((observation) =>
        observation.decisive_values.map(({ field }) => field),
      ),
    ),
  ];
  const affectedCount = reconciliation.scope.affected_job_ids.length;
  const protectedCount = reconciliation.scope.safe_job_ids.length;

  return (
    <div className="reference-live__result">
      <div className="reference-live__result-heading">
        <div>
          <span>Response packet v3</span>
          <h4>{resolved ? "Investigation resolved" : "Investigation remains unresolved"}</h4>
        </div>
        <strong data-run-status={packet.status}>{packet.status}</strong>
      </div>

      <section
        aria-label="Returned investigation conclusion"
        className="reference-live__conclusion"
      >
        <span>{resolved ? "Returned cause" : "Fail-closed conclusion"}</span>
        <strong>{diagnosis?.explanation ?? "No supported cause was returned."}</strong>
        <p>
          {resolved
            ? `Grafana MCP supplied ${packet.runtime_evidence_projection.observations.length} bound structured facts${
                decisiveFields.length === 0 ? "" : ` across ${decisiveFields.join(", ")}`
              }. Deterministic reconciliation scoped ${affectedCount} affected and ${protectedCount} protected ${
                protectedCount === 1 ? "job" : "jobs"
              }; Gemini only selected read-only queries.`
            : `Grafana MCP supplied ${packet.runtime_evidence_projection.observations.length} bound structured facts. Deterministic reconciliation ended ${reconciliation.status} (${reconciliation.reason_codes.join(
                ", ",
              )}); no recovery action was made available.`}
        </p>
      </section>

      <div className="reference-live__summary-grid">
        <section>
          <span>Grafana evidence</span>
          <strong>{packet.evidence_ids.length} bound evidence IDs</strong>
          <p>
            {packet.reference_evidence.signal_classes.length === 0
              ? "No runtime signal coverage"
              : `${packet.reference_evidence.signal_classes.join(" + ")} signal coverage`}
          </p>
        </section>
        <section>
          <span>Deterministic reconciliation</span>
          <strong>{reconciliation.status}</strong>
          <p>{reconciliation.incident_class ?? "No supported incident class"}</p>
        </section>
        <section>
          <span>Representative evidence</span>
          <strong>1 affected + 1 protected</strong>
          <p>not a {summary.scope.affected_artifact_count}-frame execution</p>
        </section>
        <section>
          <span>Model invocation</span>
          <strong>{invocation?.status ?? "not invoked"}</strong>
          <p>
            {invocation === null
              ? "No provider call"
              : `${invocation.provider} · ${invocation.model}`}
          </p>
        </section>
      </div>

      <details className="reference-live__technical">
        <summary>Inspect technical evidence</summary>
        <section
          aria-labelledby="reference-selection-trace-title"
          className="reference-live__trace"
        >
          <div className="reference-live__subheading">
            <div>
              <span>Adaptive path</span>
              <h5 id="reference-selection-trace-title">Selection trace</h5>
            </div>
            <small className="reference-live__subheading-note">
              {packet.reference_evidence.source} · read only
            </small>
          </div>
          <ol>
            {packet.selection_trace.map((entry) => (
              <li key={`${entry.sequence}-${entry.query_key}`}>
                <span>{String(entry.sequence + 1).padStart(2, "0")}</span>
                <div>
                  <strong>{entry.query_key}</strong>
                  <small>{selectionAuthority(entry)}</small>
                </div>
                <div>
                  <strong>{entry.disposition}</strong>
                  <small>{entry.reason_codes.join(" · ") || "No reason code"}</small>
                </div>
                <code>{entry.evidence_id ?? "No evidence returned"}</code>
              </li>
            ))}
          </ol>
        </section>

        <CorrelatedEvidenceTable packet={packet} />

        <div className="reference-live__inspection-grid">
          <details>
            <summary>Grafana evidence IDs</summary>
            {packet.evidence_ids.length === 0 ? (
              <p>No evidence IDs were returned.</p>
            ) : (
              <ul>
                {packet.evidence_ids.map((evidenceId) => (
                  <li key={evidenceId}>
                    <code>{evidenceId}</code>
                  </li>
                ))}
              </ul>
            )}
          </details>
          <details>
            <summary>Returned deterministic scope</summary>
            <strong>Affected</strong>
            <ul>
              {reconciliation.scope.affected_job_ids.map((jobId) => (
                <li key={jobId}>
                  <code>{jobId}</code>
                </li>
              ))}
            </ul>
            <strong>Protected</strong>
            <ul>
              {reconciliation.scope.safe_job_ids.map((jobId) => (
                <li key={jobId}>
                  <code>{jobId}</code>
                </li>
              ))}
            </ul>
          </details>
        </div>

        <p className="reference-live__representative">
          This live investigation exercises one affected exemplar and one protected control. It does
          not execute the full {summary.scope.affected_artifact_count}-frame catalog scenario.
        </p>

        <section aria-labelledby="reference-agent-trace-title" className="reference-live__spans">
          <div className="reference-live__subheading">
            <div>
              <span>Internal agent trace</span>
              <h5 id="reference-agent-trace-title">Model and tool spans</h5>
            </div>
            <small className="reference-live__subheading-note">
              {invocation === null ? "No model invocation" : modelUsageSummary(invocation)}
            </small>
          </div>
          <ol>
            {packet.agent_trace.spans.map((span) => (
              <li key={span.sequence}>
                <strong>{span.stage}</strong>
                <span>{span.query_key ?? "model"}</span>
                <span>{span.status}</span>
                <span>{span.duration_ms} ms</span>
                <span>{attemptSummary(span)}</span>
                <code>{span.error_code ?? "no error"}</code>
              </li>
            ))}
          </ol>
        </section>
      </details>

      {packet.action_intent === null ? (
        <section className="reference-live__no-action">
          <span>No action intent</span>
          <strong>{packet.no_action_reason}</strong>
          <p>No approval was requested, and no recovery ran.</p>
        </section>
      ) : (
        <>
          <ActionIntentView intent={packet.action_intent} />
          <ReferenceRecoveryDecisionControl
            adapter={adapter}
            onStateChange={onDecisionStateChange}
            packet={packet}
            state={decisionState}
          />
        </>
      )}

      {packet.action_intent === null ? (
        <p className="reference-live__authority">{liveAuthoritySummary(packet)}</p>
      ) : null}
    </div>
  );
}

function liveAuthoritySummary(packet: ReferenceResponsePacket): string {
  const modelState =
    packet.model_invocation === null
      ? "Gemini not invoked"
      : packet.model_invocation.status === "accepted"
        ? "Gemini selected queries"
        : packet.model_invocation.status === "failed"
          ? "Gemini invocation failed"
          : "Gemini output rejected";
  const grafanaState =
    packet.reference_evidence.evidence_ids.length > 0
      ? "Grafana returned evidence"
      : packet.no_action_reason === "evidence-unavailable"
        ? "Grafana evidence unavailable"
        : "Grafana returned no bound evidence";
  const validatorState = {
    conflicting: "validators reported conflicting evidence",
    insufficient: "validators reported insufficient evidence",
    rejected: "validators rejected the diagnosis",
    supported: "validators decided",
  }[packet.diagnosis_reconciliation.status];
  const approvalState =
    packet.action_intent === null
      ? "no action available for approval"
      : "human approval still required";

  return `${modelState} → ${grafanaState} → ${validatorState} → ${approvalState}.`;
}

function InvestigationProgress({
  decision,
  investigation,
}: {
  readonly decision: RecoveryDecisionState;
  readonly investigation: LiveInvestigationState;
}) {
  const investigationComplete = investigation.phase === "complete";
  const decisionComplete = decision.phase === "complete";
  const verified =
    decisionComplete && decision.decision.decision === "approved" && decision.liveVisual !== null;
  const denied = decisionComplete && decision.decision.decision === "denied";
  return (
    <ol aria-label="Investigation progress" className="reference-live__progress">
      <li data-state={investigationComplete ? "complete" : "active"}>
        <span>01</span>
        <strong>Detect</strong>
        <small>{investigationComplete ? "Evidence bound" : "Ready"}</small>
      </li>
      <li data-state={investigationComplete ? "complete" : "pending"}>
        <span>02</span>
        <strong>Explain</strong>
        <small>{investigationComplete ? "Cause reconciled" : "Pending"}</small>
      </li>
      <li data-state={decisionComplete ? "complete" : investigationComplete ? "active" : "pending"}>
        <span>03</span>
        <strong>Approve</strong>
        <small>{denied ? "Denied" : decisionComplete ? "Recorded" : "Human gate"}</small>
      </li>
      <li data-state={verified ? "complete" : denied ? "skipped" : "pending"}>
        <span>04</span>
        <strong>Verify</strong>
        <small>{verified ? "Pixels matched" : denied ? "No action" : "Pending"}</small>
      </li>
    </ol>
  );
}

function ReferenceLiveInvestigation({
  adapter,
  onPacket,
  summary,
}: {
  readonly adapter: ReferenceDemoAdapter;
  readonly onPacket: (packet: ReferenceResponsePacket) => void;
  readonly summary: ReferenceScenarioSummary;
}) {
  const [states, setStates] = useState<
    Partial<Record<ReferenceScenarioId, LiveInvestigationState>>
  >({});
  const [decisionStates, setDecisionStates] = useState<
    Partial<Record<ReferenceScenarioId, RecoveryDecisionState>>
  >({});
  const decisionStatesRef = useRef(decisionStates);
  const activeRequest = useRef<{
    readonly controller: AbortController;
    readonly scenarioId: ReferenceScenarioId;
  } | null>(null);
  const state = states[summary.scenario_id] ?? { phase: "idle" };
  const decisionState = decisionStates[summary.scenario_id] ?? { phase: "idle" };

  const setDecisionState = (next: RecoveryDecisionState) => {
    setDecisionStates((current) => {
      const previous = current[summary.scenario_id];
      if (previous?.phase === "complete" && previous.liveVisual !== null && previous !== next) {
        adapter.releaseVisual(previous.liveVisual);
      }
      const updated = { ...current, [summary.scenario_id]: next };
      decisionStatesRef.current = updated;
      return updated;
    });
  };

  useEffect(
    () => () => {
      activeRequest.current?.controller.abort();
      for (const retained of Object.values(decisionStatesRef.current)) {
        if (retained?.phase === "complete" && retained.liveVisual !== null) {
          adapter.releaseVisual(retained.liveVisual);
        }
      }
    },
    [adapter],
  );

  useEffect(() => {
    const scenarioId = summary.scenario_id;
    return () => {
      const active = activeRequest.current;
      if (active?.scenarioId === scenarioId) {
        active.controller.abort();
        activeRequest.current = null;
        setStates((current) => ({ ...current, [scenarioId]: { phase: "idle" } }));
      }
    };
  }, [summary.scenario_id]);

  const run = () => {
    const prior = activeRequest.current;
    if (prior !== null) {
      prior.controller.abort();
      setStates((current) => ({ ...current, [prior.scenarioId]: { phase: "idle" } }));
    }
    const controller = new AbortController();
    const scenarioId = summary.scenario_id;
    activeRequest.current = { controller, scenarioId };
    setDecisionState({ phase: "idle" });
    setStates((current) => ({ ...current, [scenarioId]: { phase: "running" } }));
    void adapter
      .runScenario(scenarioId, controller.signal)
      .then((packet) => {
        if (!controller.signal.aborted) {
          activeRequest.current = null;
          setStates((current) => ({ ...current, [scenarioId]: { packet, phase: "complete" } }));
          onPacket(packet);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          activeRequest.current = null;
          setStates((current) => ({ ...current, [scenarioId]: { phase: "failed" } }));
        }
      });
  };

  return (
    <section aria-labelledby="reference-live-title" className="reference-live">
      <div className="reference-live__heading">
        <div>
          <p className="shot-eyebrow">Live investigation</p>
          <h3 id="reference-live-title">Query the evidence, then reconcile it</h3>
          <p>
            Runs live queries over generated demonstration telemetry. Gemini can select bounded
            read-only Grafana queries; deterministic validators retain factual and scope authority.
          </p>
        </div>
        <button disabled={state.phase === "running"} onClick={run} type="button">
          {state.phase === "running"
            ? "Investigation running…"
            : state.phase === "complete"
              ? "Run a fresh investigation"
              : "Run live investigation"}
        </button>
      </div>

      <InvestigationProgress decision={decisionState} investigation={state} />

      {state.phase === "idle" ? (
        <p className="reference-live__notice">
          No live query has run for this selection. Starting one does not approve or execute a
          recovery.
        </p>
      ) : state.phase === "running" ? (
        <p aria-live="polite" className="reference-live__notice" role="status">
          Emitting demonstration telemetry and waiting for the bounded investigation…
        </p>
      ) : state.phase === "failed" ? (
        <p className="shot-alert" role="alert">
          Live investigation unavailable or invalid. No result or action is being shown.
        </p>
      ) : (
        <LiveInvestigationResult
          adapter={adapter}
          decisionState={decisionState}
          onDecisionStateChange={setDecisionState}
          packet={state.packet}
          summary={summary}
        />
      )}
    </section>
  );
}

function ScenarioScope({ summary }: { readonly summary: ReferenceScenarioSummary }) {
  const { scope } = summary;
  return (
    <section className="reference-scope" aria-label="Scenario scope">
      <div className="reference-scope__counts">
        <span>
          <strong>{scope.affected_artifact_count}</strong> affected
        </span>
        <span>
          <strong>{scope.protected_artifact_count}</strong> protected
        </span>
        <span>
          <strong>{scope.artifact_count}</strong> total
        </span>
      </div>
      <progress
        aria-label={
          String(scope.affected_artifact_count) +
          " of " +
          String(scope.artifact_count) +
          " artifacts affected"
        }
        max={scope.artifact_count}
        value={scope.affected_artifact_count}
      />
      <p>
        The recovery contract includes the affected set and explicitly excludes the protected set.
      </p>
    </section>
  );
}

function AuthorityAndEvidence({ detail }: { readonly detail: ReferenceScenarioDetail }) {
  return (
    <div className="reference-proof">
      <section aria-labelledby="reference-authority-title" className="reference-proof__authority">
        <p className="shot-eyebrow">Authority stays separated</p>
        <h3 id="reference-authority-title">
          Gemini may select → Grafana can return → validators decide → human may authorize
        </h3>
        <ol className="reference-authority-chain">
          <li>
            <strong>Gemini may select</strong>
            <span>A permitted next evidence query; advisory choice only.</span>
          </li>
          <li>
            <strong>Grafana can return</strong>
            <span>Read-only, structured observations bound to the run.</span>
          </li>
          <li>
            <strong>Validators decide</strong>
            <span>Cause, sufficiency, and exact recovery scope in deterministic code.</span>
          </li>
          <li>
            <strong>Human may authorize</strong>
            <span>
              A recorded demo gesture is required before the simulator can apply an intent.
            </span>
          </li>
        </ol>
      </section>

      <details className="reference-evidence-path">
        <summary>Inspect the bounded query and evidence contract</summary>
        <div>
          <p>
            Resolve only after at least{" "}
            {detail.evidence_requirements.minimum_complementary_signal_classes} complementary signal
            classes provide structured Grafana observations.
          </p>
          <dl>
            <div>
              <dt>Required causal fields</dt>
              <dd>
                <ul>
                  {detail.evidence_requirements.required_fact_fields.map((field) => (
                    <li key={field}>
                      <code>{field}</code>
                    </li>
                  ))}
                </ul>
              </dd>
            </div>
            <div>
              <dt>Fact authority</dt>
              <dd>Deterministic validators</dd>
            </div>
            <div>
              <dt>Failure behavior</dt>
              <dd>Missing, conflicting, or cross-run evidence stays unresolved.</dd>
            </div>
            <div>
              <dt>Action boundary</dt>
              <dd>Human approval; simulator target only.</dd>
            </div>
          </dl>
          <p className="reference-proof__state">
            This panel describes the catalog contract only; it does not claim a diagnosis. Live
            results, when run, appear above.
          </p>
        </div>
      </details>
    </div>
  );
}

function BenchmarkState({
  benchmark,
  error,
  selectedScenarioId,
  selectedScenarioSha256,
}: {
  readonly benchmark: ReferenceBenchmarkSuite | null;
  readonly error: string | null;
  readonly selectedScenarioId: ReferenceScenarioId;
  readonly selectedScenarioSha256: string;
}) {
  if (error !== null) {
    return (
      <section aria-labelledby="reference-benchmark-title" className="reference-benchmark">
        <p className="shot-eyebrow">Evaluation boundary</p>
        <h3 id="reference-benchmark-title">Benchmark definition unavailable</h3>
        <p role="alert">{error}</p>
      </section>
    );
  }
  if (benchmark === null) {
    return (
      <section aria-labelledby="reference-benchmark-title" className="reference-benchmark">
        <p className="shot-eyebrow">Evaluation boundary</p>
        <h3 id="reference-benchmark-title">Loading the sealed benchmark definition…</h3>
      </section>
    );
  }

  const selected = benchmark.scenarios.find(
    (scenario) => scenario.scenario_id === selectedScenarioId,
  );
  if (selected === undefined || selected.scenario_sha256 !== selectedScenarioSha256) {
    return (
      <section aria-labelledby="reference-benchmark-title" className="reference-benchmark">
        <p className="shot-eyebrow">Evaluation boundary</p>
        <h3 id="reference-benchmark-title">Benchmark bindings conflict</h3>
        <p role="alert">No benchmark requirement is being shown for this scenario.</p>
      </section>
    );
  }
  const requirements = benchmark.acceptance_requirements;

  if (benchmark.result_state === "recorded") {
    const result = benchmark.result;
    if (result === null) {
      return (
        <section aria-labelledby="reference-benchmark-title" className="reference-benchmark">
          <p className="shot-eyebrow">Evaluation boundary</p>
          <h3 id="reference-benchmark-title">Recorded benchmark unavailable</h3>
          <p role="alert">No measured result is being shown.</p>
        </section>
      );
    }
    const coreMissionPassed =
      result.checks.balanced_resolvable_classes &&
      result.checks.classification_at_least_95_percent &&
      result.checks.all_negative_cases_fail_closed &&
      result.checks.display_text_cannot_change_authority &&
      result.checks.zero_false_action_intents &&
      result.checks.zero_false_authorized_actions &&
      result.checks.output_equivalence &&
      result.checks.protected_output_integrity;
    const impactTargetsPassed =
      result.checks.median_compute_avoided_at_least_40_percent &&
      result.checks.median_application_bytes_avoided_at_least_40_percent;
    return (
      <section
        aria-labelledby="reference-benchmark-title"
        className="reference-benchmark reference-benchmark--recorded"
      >
        <div className="reference-benchmark__heading">
          <div>
            <p className="shot-eyebrow">Recorded benchmark</p>
            <h3 id="reference-benchmark-title">
              {coreMissionPassed ? "Product gates passed" : "Product gates failed"}
            </h3>
          </div>
          <span data-result-state={coreMissionPassed && impactTargetsPassed ? "passed" : "failed"}>
            {coreMissionPassed
              ? impactTargetsPassed
                ? "Impact target passed"
                : "Impact target not met"
              : "Product gates failed"}
          </span>
        </div>
        <p className="reference-benchmark__source">
          Full impact benchmark · {result.passed ? "passed" : "not passed"}
        </p>
        <p className="reference-benchmark__source">
          Measured from recorded worker receipts · {result.evidence.observation_count} artifact
          observations · recorded evaluator output · 39 fail-closed control cases tested separately,
          including explicitly approved state transitions and insufficient or ambiguous evidence
        </p>
        <p className="reference-benchmark__source">
          Source-bound worker evidence · revision{" "}
          {result.evidence.execution_identity.source_revision.slice(0, 8)} · tree{" "}
          {result.evidence.execution_identity.source_tree.slice(0, 8)}
        </p>
        <p>
          Product success requires correct diagnosis, fail-closed controls, equivalent recovery,
          intact protected outputs, and zero false-authorized actions. Compute and byte avoidance
          are separate controlled-workload impact targets, not the mission itself.
        </p>
        <section aria-label="Recorded benchmark metrics" className="reference-benchmark__metrics">
          <div>
            <strong>{basisPoints(result.metrics.classification_accuracy_basis_points)}</strong>
            <span>
              deterministic validator classification on 60 resolvable sealed holdouts · threshold ≥
              {basisPoints(requirements.minimum_resolvable_holdout_accuracy_basis_points)}
            </span>
          </div>
          <div>
            <strong>{result.metrics.false_authorized_actions}</strong>
            <span>false-authorized actions · required 0</span>
          </div>
          <div>
            <strong>{basisPoints(result.metrics.median_compute_avoided_basis_points)}</strong>
            <span>median net compute avoided · threshold ≥40%</span>
          </div>
          <div>
            <strong>
              {basisPoints(result.metrics.median_application_bytes_avoided_basis_points)}
            </strong>
            <span>median net application bytes avoided · threshold ≥40%</span>
          </div>
        </section>

        <div className="reference-benchmark__table-wrap">
          <table>
            <caption>Recorded output checks across all three open-film scenarios</caption>
            <thead>
              <tr>
                <th scope="col">Scenario</th>
                <th scope="col">Artifacts</th>
                <th scope="col">Output equivalence</th>
                <th scope="col">Protected output</th>
                <th scope="col">Net compute avoided</th>
                <th scope="col">Net bytes avoided</th>
              </tr>
            </thead>
            <tbody>
              {result.scenario_results.map((item) => (
                <tr data-selected={item.scenario_id === selectedScenarioId} key={item.scenario_id}>
                  <th scope="row">{INCIDENT_PRESENTATION[item.incident_class].shortLabel}</th>
                  <td>
                    {item.affected_artifact_count} affected + {item.protected_artifact_count}{" "}
                    protected
                  </td>
                  <td data-check={item.output_equivalence}>
                    {item.output_equivalence ? "Equivalent" : "Failed"}
                  </td>
                  <td data-check={item.protected_output_integrity}>
                    {item.protected_output_integrity ? "Intact" : "Changed"}
                  </td>
                  <td>{basisPoints(item.compute_avoided_basis_points)}</td>
                  <td>{basisPoints(item.application_bytes_avoided_basis_points)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="reference-benchmark__table-note">
          A negative scenario value means net verification or invalidation overhead exceeded the
          work avoided there. Acceptance uses the median across all three scenarios.
        </p>

        <details className="reference-benchmark__timing">
          <summary>Informational timing (excluded from acceptance)</summary>
          <dl>
            <div>
              <dt>Baseline CPU</dt>
              <dd>{milliseconds(result.timing.baseline_cpu_nanoseconds)}</dd>
            </div>
            <div>
              <dt>Selective CPU</dt>
              <dd>{milliseconds(result.timing.selective_cpu_nanoseconds)}</dd>
            </div>
            <div>
              <dt>Baseline wall</dt>
              <dd>{milliseconds(result.timing.baseline_wall_nanoseconds)}</dd>
            </div>
            <div>
              <dt>Selective wall</dt>
              <dd>{milliseconds(result.timing.selective_wall_nanoseconds)}</dd>
            </div>
          </dl>
        </details>
        <p>
          Correctness, safety, output integrity, and controlled-workload efficiency above are
          recorded measurements. Timing is informational only and excluded from acceptance.
        </p>
      </section>
    );
  }

  return (
    <section aria-labelledby="reference-benchmark-title" className="reference-benchmark">
      <div className="reference-benchmark__heading">
        <div>
          <p className="shot-eyebrow">Evaluation boundary</p>
          <h3 id="reference-benchmark-title">Sealed benchmark; results not reported</h3>
        </div>
        <span data-result-state={benchmark.result_state}>No measured result</span>
      </div>
      <section className="reference-benchmark__metrics" aria-label="Benchmark requirements">
        <div>
          <strong>Required</strong>
          <span>equivalent recovered outputs</span>
        </div>
        <div>
          <strong>Unchanged</strong>
          <span>required protected outputs</span>
        </div>
        <div>
          <strong>{requirements.maximum_false_authorized_actions}</strong>
          <span>maximum false-authorized actions</span>
        </div>
        <div>
          <strong>
            ≥{basisPoints(requirements.minimum_resolvable_holdout_accuracy_basis_points)}
          </strong>
          <span>required correct resolution on resolvable holdouts</span>
        </div>
      </section>
      <p>
        Only after those correctness and safety gates pass, the impact target is ≥
        {basisPoints(requirements.minimum_median_compute_avoided_basis_points)} median compute and ≥
        {basisPoints(requirements.minimum_median_bytes_avoided_basis_points)} median application
        bytes avoided. This scenario definition excludes{" "}
        {basisPoints(selected.scope_reduction_basis_points)} of its scope from recovery. This
        endpoint reports requirements and scope arithmetic only; it does not report compute, byte,
        time, cost, or accuracy results.
      </p>
    </section>
  );
}

function ReferenceScenarioPanel({
  adapter,
  benchmark,
  benchmarkError,
  detail,
  onPacket,
  summary,
}: {
  readonly adapter: ReferenceDemoAdapter;
  readonly benchmark: ReferenceBenchmarkSuite | null;
  readonly benchmarkError: string | null;
  readonly detail: ReferenceScenarioDetail;
  readonly onPacket: (packet: ReferenceResponsePacket) => void;
  readonly summary: ReferenceScenarioSummary;
}) {
  const incident = INCIDENT_PRESENTATION[summary.incident_class];
  const expected = visual(summary, "expected");
  const observed = visual(summary, "observed");

  return (
    <article aria-labelledby="reference-scenario-title" className="reference-scenario-panel">
      <div className="reference-scenario-panel__intro">
        <div>
          <span className="reference-scenario-panel__class">{incident.shortLabel}</span>
          <h3 id="reference-scenario-title">{summary.title}</h3>
          <p>{summary.symptom}</p>
        </div>
        <div className="reference-scenario-panel__state">
          <span>Open-film evidence</span>
          <strong>Receipt-bound pixels</strong>
          <small>Live result appears below when run</small>
        </div>
      </div>

      <div className="reference-visual-grid">
        <OpenFilmVisual
          adapter={adapter}
          descriptor={expected}
          label="Expected state"
          scenarioSha256={summary.scenario_sha256}
          scenarioTitle={summary.title}
        />
        <OpenFilmVisual
          adapter={adapter}
          descriptor={observed}
          label="Observed failure"
          scenarioSha256={summary.scenario_sha256}
          scenarioTitle={summary.title}
        />
      </div>
      {summary.incident_class === "stale-derivative-cache/v1" ? (
        <p className="reference-pixel-note">
          The observed image is intentionally the prior-parent review derivative served by the stale
          cache. The current source frame itself remains correct.
        </p>
      ) : null}

      <SupportingPixelEvidence
        adapter={adapter}
        key={`supporting-${summary.scenario_id}`}
        scenarioSha256={summary.scenario_sha256}
        scenarioTitle={summary.title}
        summary={summary}
      />

      <ReferenceLiveInvestigation adapter={adapter} onPacket={onPacket} summary={summary} />

      <div className="reference-explanation-grid">
        <section>
          <span>Visual failure</span>
          <strong>{incident.explanation}</strong>
        </section>
        <section>
          <span>Causal discriminator</span>
          <strong>{incident.causalField}</strong>
        </section>
        <section>
          <span>Bounded recovery</span>
          <strong>{RECOVERY_PRESENTATION[summary.recovery_kind]}</strong>
        </section>
      </div>

      <ScenarioScope summary={summary} />
      <AuthorityAndEvidence detail={detail} key={`authority-${summary.scenario_id}`} />
      <details className="reference-benchmark-disclosure">
        <summary>Historical benchmark evidence · separate from this live run</summary>
        <BenchmarkState
          benchmark={benchmark}
          error={benchmarkError}
          selectedScenarioId={summary.scenario_id}
          selectedScenarioSha256={summary.scenario_sha256}
        />
      </details>
    </article>
  );
}

function InvestigationComparison({
  packets,
  summaries,
}: {
  readonly packets: readonly ReferenceResponsePacket[];
  readonly summaries: readonly ReferenceScenarioSummary[];
}) {
  if (packets.length < 2) return null;
  return (
    <section aria-labelledby="reference-comparison-title" className="reference-comparison">
      <div>
        <p className="shot-eyebrow">Live comparison</p>
        <h3 id="reference-comparison-title">Different faults, one guarded workflow</h3>
        <p>
          Both results came from live, request-bound investigations—not the historical benchmark.
        </p>
      </div>
      <div className="reference-comparison__grid">
        {packets.slice(0, 2).map((packet) => {
          const summary = summaries.find((item) => item.scenario_id === packet.scenario_id);
          const incident = packet.diagnosis_reconciliation.incident_class;
          return (
            <article key={packet.scenario_id}>
              <span>{summary === undefined ? packet.scenario_id : summary.title}</span>
              <strong>
                {incident === null
                  ? "No supported cause"
                  : INCIDENT_PRESENTATION[incident].shortLabel}
              </strong>
              <dl>
                <div>
                  <dt>Evidence</dt>
                  <dd>{packet.evidence_ids.length} bound facts</dd>
                </div>
                <div>
                  <dt>Scope</dt>
                  <dd>
                    {packet.diagnosis_reconciliation.scope.affected_job_ids.length} affected ·{" "}
                    {packet.diagnosis_reconciliation.scope.safe_job_ids.length} protected
                  </dd>
                </div>
                <div>
                  <dt>Outcome</dt>
                  <dd>{packet.status}</dd>
                </div>
              </dl>
            </article>
          );
        })}
      </div>
    </section>
  );
}

export function ReferenceScenarioExperience({ adapter }: ReferenceScenarioExperienceProps) {
  const [catalog, setCatalog] = useState<ReferenceScenarioList | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<ReferenceScenarioId>(REFERENCE_SCENARIO_IDS[0]);
  const [details, setDetails] = useState<
    Partial<Record<ReferenceScenarioId, ReferenceScenarioDetail>>
  >({});
  const [detailError, setDetailError] = useState<string | null>(null);
  const [benchmark, setBenchmark] = useState<ReferenceBenchmarkSuite | null>(null);
  const [benchmarkError, setBenchmarkError] = useState<string | null>(null);
  const [investigations, setInvestigations] = useState<
    Partial<Record<ReferenceScenarioId, ReferenceResponsePacket>>
  >({});

  useEffect(() => {
    const controller = new AbortController();
    void adapter
      .listScenarios(controller.signal)
      .then((next) => {
        setCatalog(next);
        setCatalogError(null);
      })
      .catch(() => {
        if (!controller.signal.aborted) setCatalogError(loadErrorMessage());
      });
    return () => controller.abort();
  }, [adapter]);

  useEffect(() => {
    const controller = new AbortController();
    void Promise.all(
      REFERENCE_SCENARIO_IDS.map(
        async (scenarioId) =>
          [scenarioId, await adapter.getScenario(scenarioId, controller.signal)] as const,
      ),
    )
      .then((entries) => {
        setDetails(Object.fromEntries(entries));
        setDetailError(null);
      })
      .catch(() => {
        if (!controller.signal.aborted) setDetailError(loadErrorMessage());
      });
    return () => controller.abort();
  }, [adapter]);

  useEffect(() => {
    const controller = new AbortController();
    void adapter
      .benchmarkSuite(controller.signal)
      .then((next) => {
        setBenchmark(next);
        setBenchmarkError(null);
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setBenchmarkError("Benchmark definition unavailable. No result is being shown.");
        }
      });
    return () => controller.abort();
  }, [adapter]);

  const orderedItems = useMemo(() => {
    if (catalog === null) return [];
    return REFERENCE_SCENARIO_IDS.map((scenarioId) =>
      catalog.items.find((item) => item.scenario_id === scenarioId),
    ).filter((item): item is ReferenceScenarioSummary => item !== undefined);
  }, [catalog]);
  const selectedSummary = orderedItems.find((item) => item.scenario_id === selectedId) ?? null;
  const selectedDetail = details[selectedId] ?? null;
  const investigatedPackets = REFERENCE_SCENARIO_IDS.map(
    (scenarioId) => investigations[scenarioId],
  ).filter((packet): packet is ReferenceResponsePacket => packet !== undefined);
  const nextScenario = orderedItems.find((item) => investigations[item.scenario_id] === undefined);

  return (
    <section aria-labelledby="reference-suite-title" className="reference-suite">
      <div className="reference-suite__heading">
        <div>
          <p className="shot-eyebrow">Open-film reference pipeline</p>
          <h2 id="reference-suite-title">Three ways a successful render can still be wrong</h2>
          <p>
            Compare receipt-bound Tears of Steel pixel previews for resource, configuration, and
            derivative-cache failures. Selection changes the failure contract; it does not run or
            authorize a recovery.
          </p>
        </div>
        <div className="reference-suite__provenance">
          <span>Source material</span>
          <strong>{catalog?.provenance.attribution ?? "Verifying attribution…"}</strong>
          <small className="reference-suite__license">
            {catalog === null ? "" : catalog.provenance.license.spdx}
          </small>
        </div>
      </div>

      {catalogError === null ? null : (
        <p className="shot-alert" role="status">
          {catalogError}
        </p>
      )}

      {catalog === null ? (
        catalogError === null ? (
          <p className="reference-suite__loading" role="status">
            Loading sealed scenario contracts…
          </p>
        ) : null
      ) : (
        <>
          <nav aria-label="Reference failure scenarios" className="reference-scenario-picker">
            {orderedItems.map((item, index) => (
              <button
                aria-pressed={item.scenario_id === selectedId}
                key={item.scenario_id}
                onClick={() => setSelectedId(item.scenario_id)}
                type="button"
              >
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>{INCIDENT_PRESENTATION[item.incident_class].shortLabel}</strong>
                <small>{item.scope.affected_artifact_count} affected</small>
              </button>
            ))}
          </nav>

          {investigatedPackets.length === 0 || nextScenario === undefined ? null : (
            <aside className="reference-next-investigation">
              <div>
                <span>One live diagnosis is now evidence</span>
                <strong>Test a different failure class next.</strong>
              </div>
              <button onClick={() => setSelectedId(nextScenario.scenario_id)} type="button">
                Compare {INCIDENT_PRESENTATION[nextScenario.incident_class].shortLabel}
              </button>
            </aside>
          )}

          <InvestigationComparison packets={investigatedPackets} summaries={orderedItems} />

          {detailError === null ? null : (
            <p className="shot-alert" role="alert">
              {detailError}
            </p>
          )}
          {selectedSummary === null || selectedDetail === null ? (
            detailError === null ? (
              <p className="reference-suite__loading" role="status">
                Loading selected evidence contract…
              </p>
            ) : null
          ) : selectedDetail.summary.scenario_sha256 !== selectedSummary.scenario_sha256 ? (
            <p className="shot-alert" role="alert">
              Scenario bindings conflict. No scenario result is being shown.
            </p>
          ) : (
            <ReferenceScenarioPanel
              adapter={adapter}
              benchmark={benchmark}
              benchmarkError={benchmarkError}
              detail={selectedDetail}
              onPacket={(packet) =>
                setInvestigations((current) => ({
                  ...current,
                  [packet.scenario_id]: packet,
                }))
              }
              summary={selectedSummary}
            />
          )}
        </>
      )}
    </section>
  );
}
