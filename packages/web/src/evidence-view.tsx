import type {
  WorkspaceDeterministicDerivationEvidence,
  WorkspaceEvidence,
  WorkspaceProviderEvidence,
  WorkspaceValidatorArtifactEvidence,
} from "@colortrace/workspace-model";

import { evidenceAnchorId, EvidenceCitation } from "./evidence-citation.tsx";
import { StatusBadge } from "./status-badge.tsx";
import { Timestamp } from "./time.tsx";

function EvidenceHeading({ item }: { readonly item: WorkspaceEvidence }) {
  const label =
    item.kind === "provider"
      ? (item.query_key ?? item.observation_kind)
      : item.kind === "validator-artifact"
        ? item.artifact_kind
        : "Deterministic derivation";

  return (
    <div className="evidence-card__heading">
      <div>
        <p className="evidence-card__kind">{item.kind.replaceAll("-", " ")}</p>
        <h3>{label}</h3>
      </div>
      <StatusBadge value={item.availability} />
    </div>
  );
}

function Digest({ value }: { readonly value: string }) {
  return <code className="digest-value">{value}</code>;
}

function ProviderEvidence({ item }: { readonly item: WorkspaceProviderEvidence }) {
  return (
    <>
      <dl className="metadata-list metadata-list--compact evidence-metadata">
        <div>
          <dt>Source</dt>
          <dd>
            {item.source_kind} · {item.observation_kind}
          </dd>
        </div>
        <div>
          <dt>Tool and query</dt>
          <dd>
            {item.tool ?? "Tool unavailable"} · {item.query_key ?? "Query unavailable"}
          </dd>
        </div>
        <div>
          <dt>Observed</dt>
          <dd>
            <Timestamp basis={item.time_basis} value={item.timestamp} />
          </dd>
        </div>
        <div>
          <dt>Content digest</dt>
          <dd>
            <Digest value={item.content_sha256} />
          </dd>
        </div>
      </dl>
      {item.error_code === null ? null : (
        <p className="evidence-error">Collection error: {item.error_code}</p>
      )}
      <div>
        <p className="preview-label">Bounded provider excerpt · display only</p>
        <textarea
          aria-label={`Bounded text preview for ${item.evidence_id}`}
          className="evidence-preview"
          readOnly
          rows={6}
          value={item.display_excerpt || "No display excerpt is available."}
        />
      </div>
    </>
  );
}

function ValidatorArtifactEvidence({
  item,
}: {
  readonly item: WorkspaceValidatorArtifactEvidence;
}) {
  const preview = `Artifact kind: ${item.artifact_kind}\nPath: ${item.path}\nSHA-256: ${item.content_sha256}`;

  return (
    <>
      <dl className="metadata-list metadata-list--compact evidence-metadata">
        <div>
          <dt>Validator result</dt>
          <dd>
            <code>{item.validator_result_id}</code>
          </dd>
        </div>
        <div>
          <dt>Artifact path</dt>
          <dd>
            <code>{item.path}</code>
          </dd>
        </div>
        <div>
          <dt>Content digest</dt>
          <dd>
            <Digest value={item.content_sha256} />
          </dd>
        </div>
      </dl>
      <p className="preview-label">Digest-linked bounded artifact metadata</p>
      <textarea
        aria-label={`Bounded artifact metadata preview for ${item.evidence_id}`}
        className="evidence-preview"
        readOnly
        rows={6}
        value={preview}
      />
      <p className="preview-limitation">
        Raw artifact bytes are not included in the investigation replay. This metadata preview does
        not establish visual intent or artifact contents.
      </p>
    </>
  );
}

function DeterministicDerivationEvidence({
  evidence,
  item,
}: {
  readonly evidence: readonly WorkspaceEvidence[];
  readonly item: WorkspaceDeterministicDerivationEvidence;
}) {
  const policies = Object.entries(item.policy_versions).sort(([left], [right]) =>
    left.localeCompare(right, "en"),
  );

  return (
    <>
      <dl className="metadata-list metadata-list--compact evidence-metadata">
        <div>
          <dt>Derivation digest</dt>
          <dd>
            <Digest value={item.derivation_sha256} />
          </dd>
        </div>
        <div>
          <dt>Validator result</dt>
          <dd>{item.validator_result_id ?? "Unavailable"}</dd>
        </div>
        <div>
          <dt>Claim</dt>
          <dd>{item.claim_id ?? "Result-level derivation"}</dd>
        </div>
      </dl>
      <div>
        <p className="preview-label">Derivation policies</p>
        {policies.length === 0 ? (
          <p className="empty-copy">No derivation policies are recorded.</p>
        ) : (
          <dl className="policy-list">
            {policies.map(([name, value]) => (
              <div key={name}>
                <dt>{name}</dt>
                <dd>{value}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>
      {item.citations.length === 0 ? null : (
        <div className="evidence-support">
          <p className="preview-label">Supporting evidence</p>
          <ul
            aria-label={`Supporting evidence for ${item.evidence_id}`}
            className="scope-citations"
          >
            {item.citations.map((citation) => (
              <li key={`${citation.namespace}:${citation.id}`}>
                <EvidenceCitation citation={citation} evidence={evidence} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

function EvidenceCard({
  evidence,
  item,
}: {
  readonly evidence: readonly WorkspaceEvidence[];
  readonly item: WorkspaceEvidence;
}) {
  return (
    <article
      className="evidence-card"
      data-availability={item.availability}
      data-evidence-item={item.kind}
      id={evidenceAnchorId(item.workspace_id)}
      tabIndex={-1}
    >
      <EvidenceHeading item={item} />
      <p className="evidence-card__id">
        Evidence <code>{item.evidence_id}</code>
      </p>
      {item.kind === "provider" ? (
        <ProviderEvidence item={item} />
      ) : item.kind === "validator-artifact" ? (
        <ValidatorArtifactEvidence item={item} />
      ) : (
        <DeterministicDerivationEvidence evidence={evidence} item={item} />
      )}
    </article>
  );
}

export type EvidenceViewProps = {
  readonly evidence: readonly WorkspaceEvidence[];
  readonly missingReferences: readonly string[];
};

export function EvidenceView({ evidence, missingReferences }: EvidenceViewProps) {
  return (
    <section aria-labelledby="evidence-title" className="panel evidence-panel">
      <div className="section-heading section-heading--wrap">
        <div>
          <p className="eyebrow">Provenance, availability, and bounded previews</p>
          <h2 id="evidence-title">Evidence details</h2>
        </div>
        <span className="count-pill">
          <span aria-hidden="true">{evidence.length}</span>
          <span className="sr-only">{evidence.length} evidence records</span>
        </span>
      </div>

      {missingReferences.length === 0 ? null : (
        <div className="missing-evidence" role="alert">
          <h3>Referenced evidence is missing</h3>
          <p>These identifiers were cited but were not present in the verified replay.</p>
          <ul>
            {missingReferences.map((reference) => (
              <li key={reference}>
                <code>{reference}</code>
              </li>
            ))}
          </ul>
        </div>
      )}

      {evidence.length === 0 ? (
        <p className="empty-copy">No evidence records are available.</p>
      ) : (
        <div className="evidence-list">
          {evidence.map((item) => (
            <EvidenceCard evidence={evidence} item={item} key={item.workspace_id} />
          ))}
        </div>
      )}
    </section>
  );
}
