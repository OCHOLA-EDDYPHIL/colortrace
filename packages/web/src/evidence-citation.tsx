import type { WorkspaceCitation, WorkspaceEvidence } from "@colortrace/workspace-model";

const EVIDENCE_KIND_BY_NAMESPACE = {
  "deterministic-derivation": "deterministic-derivation",
  "provider-evidence": "provider",
  "validator-artifact": "validator-artifact",
} as const;

export type EvidenceCitationResolution =
  | { readonly status: "ambiguous" | "missing" | "unsupported-namespace" }
  | {
      readonly actualKinds: readonly WorkspaceEvidence["kind"][];
      readonly expectedKind: WorkspaceEvidence["kind"];
      readonly status: "wrong-kind";
    }
  | { readonly evidence: WorkspaceEvidence; readonly status: "resolved" };

export function evidenceAnchorId(workspaceId: string): string {
  const encoded = Array.from(workspaceId, (character) =>
    character.codePointAt(0)?.toString(16),
  ).join("-");
  return `workspace-evidence-${encoded}`;
}

export function resolveEvidenceCitation(
  citation: WorkspaceCitation,
  evidence: readonly WorkspaceEvidence[],
): EvidenceCitationResolution {
  if (!Object.hasOwn(EVIDENCE_KIND_BY_NAMESPACE, citation.namespace)) {
    return { status: "unsupported-namespace" };
  }

  const namespace = citation.namespace as keyof typeof EVIDENCE_KIND_BY_NAMESPACE;
  const expectedKind = EVIDENCE_KIND_BY_NAMESPACE[namespace];
  const matches = evidence.filter(
    (item) => item.kind === expectedKind && item.evidence_id === citation.id,
  );
  const [target] = matches;
  if (target === undefined) {
    const actualKinds = [
      ...new Set(
        evidence.filter((item) => item.evidence_id === citation.id).map((item) => item.kind),
      ),
    ].sort((left, right) => left.localeCompare(right, "en"));
    if (actualKinds.length > 0) return { actualKinds, expectedKind, status: "wrong-kind" };
    return { status: "missing" };
  }
  if (matches.length !== 1) return { status: "ambiguous" };
  return { evidence: target, status: "resolved" };
}

export type EvidenceCitationProps = {
  readonly citation: WorkspaceCitation;
  readonly evidence: readonly WorkspaceEvidence[];
};

export function EvidenceCitation({ citation, evidence }: EvidenceCitationProps) {
  const resolution = resolveEvidenceCitation(citation, evidence);
  const content = (
    <>
      <span>{citation.namespace.replaceAll("-", " ")}</span>
      <code>{citation.id}</code>
    </>
  );

  if (resolution.status !== "resolved") {
    return <span className="evidence-citation evidence-citation--unlinked">{content}</span>;
  }

  return (
    <a
      className="evidence-citation"
      href={`#${evidenceAnchorId(resolution.evidence.workspace_id)}`}
    >
      {content}
      <span className="sr-only">Open evidence detail</span>
    </a>
  );
}
