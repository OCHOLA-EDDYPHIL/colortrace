import {
  FIXTURE_IMPACT_CALCULATION_POLICY,
  type FixtureImpactReport,
} from "@colortrace/workspace-model";

type ImpactMetricProps = {
  readonly label: string;
  readonly value: string;
};

function ImpactMetric({ label, value }: ImpactMetricProps) {
  return (
    <div className="impact-metric">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

export function formatImpactCount(value: number | null): string {
  return value === null ? "Not recorded" : new Intl.NumberFormat("en").format(value);
}

export function formatImpactDuration(value: number | null): string {
  if (value === null) return "Not recorded";
  if (value < 1_000) return `${value} ms`;
  const seconds = Math.round(value / 100) / 10;
  return `${new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(seconds)} s`;
}

export function ImpactReport({ report }: { readonly report: FixtureImpactReport }) {
  const observed = report.observed;
  const hypothetical = report.hypothetical;

  return (
    <section aria-labelledby="impact-report-title" className="panel impact-report">
      <div className="section-heading section-heading--wrap">
        <div>
          <p className="eyebrow">Synthetic fixture report</p>
          <h2 id="impact-report-title">Incident-level impact</h2>
        </div>
        <span className="impact-report__scope">Not a production benchmark</span>
      </div>
      <p>
        These figures describe this recorded simulator incident only. Missing measurements remain
        unknown.
      </p>

      <div className="impact-report__columns">
        <section aria-labelledby="observed-impact-title" className="impact-report__observed">
          <p className="impact-report__classification">Observed records</p>
          <h3 id="observed-impact-title">Recorded incident and run values</h3>
          <dl className="impact-metric-grid">
            <ImpactMetric
              label="Affected frames"
              value={formatImpactCount(observed.affected_frames.value)}
            />
            <ImpactMetric
              label="Verified-safe frames"
              value={formatImpactCount(observed.verified_safe_frames.value)}
            />
            <ImpactMetric
              label="Affected derivatives"
              value={formatImpactCount(observed.affected_derivatives.value)}
            />
            <ImpactMetric
              label="Frame rerender outcomes"
              value={formatImpactCount(observed.frame_rerender_outcomes.value)}
            />
            <ImpactMetric
              label="Derivative rerender outcomes"
              value={formatImpactCount(observed.derivative_rerender_outcomes.value)}
            />
            <ImpactMetric
              label="Investigation elapsed"
              value={formatImpactDuration(observed.investigation_elapsed.value)}
            />
            <ImpactMetric
              label="Recovery elapsed"
              value={formatImpactDuration(observed.recovery_elapsed.value)}
            />
            <ImpactMetric label="Provider cost" value="Not recorded" />
            <ImpactMetric label="Compute time" value="Not recorded" />
          </dl>
        </section>

        <aside aria-labelledby="hypothetical-impact-title" className="impact-report__hypothetical">
          <p className="impact-report__classification">Hypothetical comparison</p>
          <h3 id="hypothetical-impact-title">Rerender every observed source frame</h3>
          <p>{hypothetical.assumption}</p>
          <dl className="impact-metric-grid impact-metric-grid--counterfactual">
            <ImpactMetric
              label="Assumed source-frame rerenders"
              value={formatImpactCount(hypothetical.source_frame_rerenders.value)}
            />
            <ImpactMetric
              label="Rerenders avoided under assumption"
              value={formatImpactCount(hypothetical.source_frame_rerenders_avoided.value)}
            />
          </dl>
          <p className="impact-report__caution">
            This arithmetic is not an observed cost, time saving, or production forecast.
          </p>
        </aside>
      </div>

      <details className="impact-report__policy">
        <summary>Calculation policy, bindings, and limitations</summary>
        <div className="impact-report__policy-content">
          <section aria-labelledby="impact-policy-title">
            <h3 id="impact-policy-title">Calculation policy</h3>
            <dl className="metadata-list">
              <div>
                <dt>Policy</dt>
                <dd>
                  <code>{FIXTURE_IMPACT_CALCULATION_POLICY.policy_id}</code>
                </dd>
              </div>
              <div>
                <dt>Observed scope</dt>
                <dd>{FIXTURE_IMPACT_CALCULATION_POLICY.observed_scope}</dd>
              </div>
              <div>
                <dt>Observed rerenders</dt>
                <dd>{FIXTURE_IMPACT_CALCULATION_POLICY.observed_rerenders}</dd>
              </div>
              <div>
                <dt>Elapsed time</dt>
                <dd>
                  {FIXTURE_IMPACT_CALCULATION_POLICY.investigation_elapsed}{" "}
                  {FIXTURE_IMPACT_CALCULATION_POLICY.recovery_elapsed}
                </dd>
              </div>
              <div>
                <dt>Unknown values</dt>
                <dd>{FIXTURE_IMPACT_CALCULATION_POLICY.unknowns}</dd>
              </div>
              <div>
                <dt>Display units</dt>
                <dd>{FIXTURE_IMPACT_CALCULATION_POLICY.display_rounding}</dd>
              </div>
            </dl>
          </section>
          <section aria-labelledby="impact-bindings-title">
            <h3 id="impact-bindings-title">Recorded bindings</h3>
            <dl className="metadata-list">
              <div>
                <dt>Incident</dt>
                <dd>
                  <code>
                    {report.incident.id}@v{report.incident.version}
                  </code>
                </dd>
              </div>
              <div>
                <dt>Scope policy</dt>
                <dd>
                  <code>{report.incident.scope_policy}</code>
                </dd>
              </div>
              <div>
                <dt>Recovery outcome</dt>
                <dd>
                  {report.bindings.recovery_outcome_id === null ? (
                    "Not recorded"
                  ) : (
                    <code>{report.bindings.recovery_outcome_id}</code>
                  )}
                </dd>
              </div>
              <div>
                <dt>Recovery packet</dt>
                <dd>
                  {report.bindings.recovery_packet_id === null ? (
                    "Not recorded"
                  ) : (
                    <code>{report.bindings.recovery_packet_id}</code>
                  )}
                </dd>
              </div>
            </dl>
          </section>
          <section aria-labelledby="impact-limitations-title">
            <h3 id="impact-limitations-title">Limitations</h3>
            <ul className="plain-list">
              {report.limitations.map((limitation) => (
                <li key={limitation}>{limitation}</li>
              ))}
            </ul>
          </section>
        </div>
      </details>
    </section>
  );
}
