import type {
  ClaimState,
  InvestigationWorkspace,
  WorkspaceClaim,
} from "@colortrace/workspace-model";

import { EvidenceCitation } from "./evidence-citation.tsx";
import { StatusBadge } from "./status-badge.tsx";
import { Timestamp } from "./time.tsx";

const CLAIM_STATES: readonly ClaimState[] = ["confirmed", "inferred", "rejected", "unresolved"];

const NEXT_AUTHORITY_LABEL: Readonly<
  Record<InvestigationWorkspace["overview"]["next_authority"], string>
> = {
  "human-plan-review": "Human plan review",
  "investigation-required": "Further investigation",
  none: "No next authority recorded",
};

function Claim({
  claim,
  evidence,
}: {
  readonly claim: WorkspaceClaim;
  readonly evidence: InvestigationWorkspace["evidence"]["items"];
}) {
  const subject = claim.subject_value === null ? claim.subject_kind : claim.subject_value;

  return (
    <li className="claim-card">
      <div className="claim-card__heading">
        <div>
          <p className="claim-card__type">{claim.type}</p>
          <code>{subject}</code>
        </div>
        <StatusBadge value={claim.state} />
      </div>
      <dl className="metadata-list metadata-list--compact">
        <div>
          <dt>Policy</dt>
          <dd>{claim.policy}</dd>
        </div>
        <div>
          <dt>Packet finalized</dt>
          <dd>
            <Timestamp basis={claim.time_basis} value={claim.timestamp} />
          </dd>
        </div>
      </dl>
      {claim.reason_codes.length === 0 ? null : (
        <p className="reason-codes">Reasons: {claim.reason_codes.join(", ")}</p>
      )}
      {claim.citations.length === 0 ? (
        <p className="citation-empty">No citations recorded.</p>
      ) : (
        <ul aria-label="Claim citations" className="citation-list">
          {claim.citations.map((citation) => (
            <li key={`${citation.namespace}:${citation.id}`}>
              <EvidenceCitation citation={citation} evidence={evidence} />
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export type IncidentOverviewProps = {
  readonly workspace: InvestigationWorkspace;
};

export function IncidentOverview({ workspace }: IncidentOverviewProps) {
  const { incident, overview } = workspace;

  return (
    <div className="overview-stack">
      <section aria-labelledby="overview-title" className="panel overview-panel">
        <div className="section-heading section-heading--wrap">
          <div>
            <p className="eyebrow">Current state</p>
            <h2 id="overview-title">Incident overview</h2>
          </div>
          <StatusBadge value={incident.status} />
        </div>

        <p className="current-state-copy">
          {incident.status === "resolved"
            ? "The persisted investigation packet is complete. Review the cited claims before the next authority acts."
            : "The investigation is unresolved. Review the missing or contradictory records before any plan review."}
        </p>

        <dl className="metadata-list">
          <div>
            <dt>Incident</dt>
            <dd>
              <code>{incident.id}</code>
            </dd>
          </div>
          <div>
            <dt>Alert</dt>
            <dd>{incident.alert_id}</dd>
          </div>
          <div>
            <dt>Updated</dt>
            <dd>
              <Timestamp value={incident.updated_at} />
            </dd>
          </div>
          <div>
            <dt>Finalized</dt>
            <dd>
              <Timestamp basis="finalized-at" value={incident.finalized_at} />
            </dd>
          </div>
          <div>
            <dt>Next authority</dt>
            <dd>{NEXT_AUTHORITY_LABEL[overview.next_authority]}</dd>
          </div>
          <div>
            <dt>Plan state</dt>
            <dd>{overview.candidate_plan.state.replaceAll("-", " ")}</dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="claim-summary-title" className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Authority</p>
            <h2 id="claim-summary-title">Claim summary</h2>
          </div>
        </div>
        <dl className="metric-grid">
          {CLAIM_STATES.map((state) => (
            <div key={state}>
              <dt>
                <StatusBadge value={state} />
              </dt>
              <dd>{overview.claim_counts[state]}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section aria-labelledby="claims-title" className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Cited findings</p>
            <h2 id="claims-title">Claims</h2>
          </div>
        </div>
        {workspace.claims.length === 0 ? (
          <p className="empty-copy">No claims are recorded.</p>
        ) : (
          <ul className="claim-list">
            {workspace.claims.map((claim) => (
              <Claim claim={claim} evidence={workspace.evidence.items} key={claim.id} />
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="limitations-title" className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Interpretation boundary</p>
            <h2 id="limitations-title">Known limitations</h2>
          </div>
        </div>
        {workspace.limitations.length === 0 ? (
          <p className="empty-copy">No display limitations are recorded.</p>
        ) : (
          <ul className="plain-list">
            {workspace.limitations.map((limitation) => (
              <li key={`${limitation.code}:${limitation.related_ids.join(":")}`}>
                <strong>{limitation.code.replaceAll("-", " ")}</strong>
                <p>{limitation.detail}</p>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
