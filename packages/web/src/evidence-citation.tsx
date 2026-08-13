import type { WorkspaceCitation, WorkspaceEvidence } from "@colortrace/workspace-model";

const EVIDENCE_KIND_BY_NAMESPACE = {
  "deterministic-derivation": "deterministic-derivation",
  "provider-evidence": "provider",
  "validator-artifact": "validator-artifact",
} as const;

export function evidenceAnchorId(workspaceId: string): string {
  const encoded = Array.from(workspaceId, (character) =>
    character.codePointAt(0)?.toString(16),
  ).join("-");
  return `workspace-evidence-${encoded}`;
}

function citationTarget(
  citation: WorkspaceCitation,
  evidence: readonly WorkspaceEvidence[],
): WorkspaceEvidence | null {
  if (!(citation.namespace in EVIDENCE_KIND_BY_NAMESPACE)) {
    return null;
  }

  const namespace = citation.namespace as keyof typeof EVIDENCE_KIND_BY_NAMESPACE;
  const expectedKind = EVIDENCE_KIND_BY_NAMESPACE[namespace];
  const matches = evidence.filter(
    (item) => item.kind === expectedKind && item.evidence_id === citation.id,
  );
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

export type EvidenceCitationProps = {
  readonly citation: WorkspaceCitation;
  readonly evidence: readonly WorkspaceEvidence[];
};

export function EvidenceCitation({ citation, evidence }: EvidenceCitationProps) {
  const target = citationTarget(citation, evidence);
  const content = (
    <>
      <span>{citation.namespace.replaceAll("-", " ")}</span>
      <code>{citation.id}</code>
    </>
  );

  if (target === null) {
    return <span className="evidence-citation evidence-citation--unlinked">{content}</span>;
  }

  return (
    <a className="evidence-citation" href={`#${evidenceAnchorId(target.workspace_id)}`}>
      {content}
      <span className="sr-only">Open evidence detail</span>
    </a>
  );
}
