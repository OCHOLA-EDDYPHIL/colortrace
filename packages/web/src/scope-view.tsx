import type {
  WorkspaceEvidence,
  WorkspaceFrameScopeNode,
  WorkspaceLimitation,
  WorkspaceScopeEdge,
  WorkspaceScopeGraph,
  WorkspaceScopeNode,
} from "@colortrace/workspace-model";

import { EvidenceCitation, resolveEvidenceCitation } from "./evidence-citation.tsx";
import { StatusBadge } from "./status-badge.tsx";

type ScopeGroup = {
  readonly id: string;
  readonly label: string;
  readonly nodes: readonly WorkspaceScopeNode[];
};

type WithheldEdge = {
  readonly edge: WorkspaceScopeEdge;
  readonly reasons: readonly string[];
};

function edgeSupportReasons(
  edge: WorkspaceScopeEdge,
  evidence: readonly WorkspaceEvidence[],
): readonly string[] {
  const reasons: string[] = [];
  if (edge.policy.trim().length === 0) reasons.push("derivation policy is missing");
  if (edge.citations.length === 0) reasons.push("evidence citations are missing");

  for (const citation of edge.citations) {
    const label = `${citation.namespace}:${citation.id}`;
    const resolution = resolveEvidenceCitation(citation, evidence);
    if (resolution.status === "unsupported-namespace") {
      reasons.push(`${label} does not identify a linkable evidence namespace`);
    } else if (resolution.status === "missing") {
      reasons.push(`${label} is missing`);
    } else if (resolution.status === "ambiguous") {
      reasons.push(`${label} resolves to more than one evidence record`);
    } else if (resolution.status === "wrong-kind") {
      reasons.push(
        `${label} expects ${resolution.expectedKind} evidence but only ${resolution.actualKinds.join(
          ", ",
        )} evidence is present`,
      );
    } else if (
      resolution.status === "resolved" &&
      resolution.evidence.availability !== "available"
    ) {
      reasons.push(`${label} is ${resolution.evidence.availability}`);
    }
  }

  return [...new Set(reasons)].sort((left, right) => left.localeCompare(right, "en"));
}

function scopeGroups(nodes: readonly WorkspaceScopeNode[]): readonly ScopeGroup[] {
  return [
    {
      id: "causal-resource",
      label: "Causal resource",
      nodes: nodes.filter((node) => node.classification === "causal"),
    },
    {
      id: "affected-frames",
      label: "Affected frames",
      nodes: nodes.filter((node) => node.kind === "frame" && node.classification === "affected"),
    },
    {
      id: "affected-derivatives",
      label: "Affected derivatives",
      nodes: nodes.filter(
        (node) => node.kind === "derivative" && node.classification === "affected",
      ),
    },
    {
      id: "verified-safe",
      label: "Verified safe work",
      nodes: nodes.filter((node) => node.classification === "safe"),
    },
    {
      id: "unknown-scope",
      label: "Unknown scope",
      nodes: nodes.filter((node) => node.classification === "unknown"),
    },
  ];
}

function nodeKindLabel(node: WorkspaceScopeNode): string {
  if (node.kind === "resource") return "Resource digest";
  if (node.kind === "derivative") return "Derivative artifact";
  return "Frame";
}

function ScopeNodeCard({
  evidence,
  node,
}: {
  readonly evidence: readonly WorkspaceEvidence[];
  readonly node: WorkspaceScopeNode;
}) {
  return (
    <article className="scope-node" data-kind={node.kind} data-scope-node={node.classification}>
      <div className="scope-node__heading">
        <div>
          <p>{nodeKindLabel(node)}</p>
          <code>{node.id}</code>
        </div>
        <StatusBadge value={node.classification} />
      </div>

      {node.kind === "frame" ? (
        <dl className="scope-node__metadata">
          <div>
            <dt>Job</dt>
            <dd>{node.job_id}</dd>
          </div>
          <div>
            <dt>Output</dt>
            <dd>{node.output_id ?? "Unavailable"}</dd>
          </div>
          <div>
            <dt>Worker</dt>
            <dd>{node.worker_id ?? "Unavailable"}</dd>
          </div>
        </dl>
      ) : node.kind === "derivative" ? (
        <p className="scope-node__parent">
          Parent artifact <code>{node.parent_artifact_id ?? "Unavailable"}</code>
        </p>
      ) : null}

      {node.kind === "frame" && node.safe_on_implicated_worker ? (
        <p className="same-worker-safe">Safe on implicated worker</p>
      ) : null}

      {node.reason_codes.length === 0 ? null : (
        <p className="reason-codes">Reasons: {node.reason_codes.join(", ")}</p>
      )}

      {node.citations.length === 0 ? null : (
        <ul aria-label={`Evidence for ${node.id}`} className="scope-citations">
          {node.citations.map((citation) => (
            <li key={`${citation.namespace}:${citation.id}`}>
              <EvidenceCitation citation={citation} evidence={evidence} />
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function EdgeRelationship({
  edge,
  evidence,
  nodeByKey,
}: {
  readonly edge: WorkspaceScopeEdge;
  readonly evidence: readonly WorkspaceEvidence[];
  readonly nodeByKey: ReadonlyMap<string, WorkspaceScopeNode>;
}) {
  const from = nodeByKey.get(edge.from)?.id ?? edge.from;
  const to = nodeByKey.get(edge.to)?.id ?? edge.to;

  return (
    <li className="scope-edge" data-scope-edge={edge.kind}>
      <div className="scope-edge__path">
        <code>{from}</code>
        <span>to</span>
        <code>{to}</code>
      </div>
      <dl className="scope-edge__metadata">
        <div>
          <dt>Relationship</dt>
          <dd>{edge.kind.replaceAll("-", " ")}</dd>
        </div>
        <div>
          <dt>Derivation policy</dt>
          <dd>
            <code>{edge.policy}</code>
          </dd>
        </div>
      </dl>
      <ul aria-label={`Evidence for relationship ${from} to ${to}`} className="scope-citations">
        {edge.citations.map((citation) => (
          <li key={`${citation.namespace}:${citation.id}`}>
            <EvidenceCitation citation={citation} evidence={evidence} />
          </li>
        ))}
      </ul>
    </li>
  );
}

function ScopeListFallback({
  edges,
  evidence,
  nodes,
  nodeByKey,
}: {
  readonly edges: readonly WorkspaceScopeEdge[];
  readonly evidence: readonly WorkspaceEvidence[];
  readonly nodes: readonly WorkspaceScopeNode[];
  readonly nodeByKey: ReadonlyMap<string, WorkspaceScopeNode>;
}) {
  return (
    <details className="scope-list-fallback">
      <summary>Open scope list fallback</summary>
      <div className="table-scroll">
        <table>
          <caption>Authoritative projected scope nodes</caption>
          <thead>
            <tr>
              <th scope="col">Item</th>
              <th scope="col">Kind</th>
              <th scope="col">State</th>
              <th scope="col">Worker or parent</th>
            </tr>
          </thead>
          <tbody>
            {nodes.map((node) => (
              <tr key={node.key}>
                <th scope="row">
                  <code>{node.id}</code>
                </th>
                <td>{node.kind}</td>
                <td>{node.classification}</td>
                <td>
                  {node.kind === "frame"
                    ? (node.worker_id ?? "Unavailable")
                    : node.kind === "derivative"
                      ? (node.parent_artifact_id ?? "Unavailable")
                      : "Not applicable"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="table-scroll">
        <table>
          <caption>Decisive scope relationships</caption>
          <thead>
            <tr>
              <th scope="col">From</th>
              <th scope="col">To</th>
              <th scope="col">Policy</th>
              <th scope="col">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {edges.map((edge) => (
              <tr key={edge.id}>
                <th scope="row">
                  <code>{nodeByKey.get(edge.from)?.id ?? edge.from}</code>
                </th>
                <td>
                  <code>{nodeByKey.get(edge.to)?.id ?? edge.to}</code>
                </td>
                <td>
                  <code>{edge.policy}</code>
                </td>
                <td>
                  <ul className="table-citations">
                    {edge.citations.map((citation) => (
                      <li key={`${citation.namespace}:${citation.id}`}>
                        <EvidenceCitation citation={citation} evidence={evidence} />
                      </li>
                    ))}
                  </ul>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

export type ScopeViewProps = {
  readonly evidence: readonly WorkspaceEvidence[];
  readonly limitations: readonly WorkspaceLimitation[];
  readonly scope: WorkspaceScopeGraph;
};

export function ScopeView({ evidence, limitations, scope }: ScopeViewProps) {
  const groups = scopeGroups(scope.nodes);
  const sameWorkerSafe = scope.nodes.filter(
    (node): node is WorkspaceFrameScopeNode =>
      node.kind === "frame" && node.safe_on_implicated_worker,
  );
  const assessedEdges = scope.edges.map((edge) => ({
    edge,
    reasons: edgeSupportReasons(edge, evidence),
  }));
  const supportedEdges = assessedEdges
    .filter((assessment) => assessment.reasons.length === 0)
    .map((assessment) => assessment.edge);
  const withheldEdges: readonly WithheldEdge[] = assessedEdges.filter(
    (assessment) => assessment.reasons.length > 0,
  );
  const nodeByKey = new Map(scope.nodes.map((node) => [node.key, node] as const));
  const referenceLimitations = limitations.filter(
    (limitation) => limitation.code === "reference-policy-technical-only",
  );

  return (
    <section aria-labelledby="scope-title" className="panel scope-panel">
      <div className="section-heading section-heading--wrap">
        <div>
          <p className="eyebrow">Exact resource and transform use</p>
          <h2 id="scope-title">Affected scope</h2>
        </div>
        {scope.state === "invalid" ? (
          <StatusBadge value="integrity-error" />
        ) : (
          <StatusBadge value={scope.state} />
        )}
      </div>

      <dl className="scope-policy-summary">
        <div>
          <dt>Scope policy</dt>
          <dd>
            <code>{scope.policy}</code>
          </dd>
        </div>
        <div>
          <dt>Packet-to-validator parity</dt>
          <dd>{scope.parity.status.replaceAll("-", " ")}</dd>
        </div>
      </dl>

      <dl aria-label="Authoritative scope counts" className="scope-count-summary">
        {groups.map((group) => (
          <div data-scope-count={group.id} key={group.id}>
            <dt>{group.label}</dt>
            <dd>{group.nodes.length}</dd>
          </div>
        ))}
      </dl>

      {sameWorkerSafe.length === 0 ? null : (
        <aside aria-labelledby="same-worker-safe-title" className="same-worker-safe-callout">
          <p className="eyebrow">Worker-alone failure rejected</p>
          <h3 id="same-worker-safe-title">Safe work on the implicated worker</h3>
          <ul>
            {sameWorkerSafe.map((node) => (
              <li key={node.key}>
                <strong>{node.job_id}</strong> · frame <code>{node.id}</code> · worker{" "}
                <code>{node.worker_id ?? "Unavailable"}</code>
              </li>
            ))}
          </ul>
        </aside>
      )}

      <section aria-labelledby="reference-limits-title" className="reference-limitations">
        <h3 id="reference-limits-title">Reference-comparison limitation</h3>
        {referenceLimitations.length === 0 ? (
          <p>No reference-comparison limitation was supplied with this workspace projection.</p>
        ) : (
          <ul>
            {referenceLimitations.map((limitation) => (
              <li key={limitation.code}>{limitation.detail}</li>
            ))}
          </ul>
        )}
      </section>

      {withheldEdges.length === 0 ? null : (
        <div
          aria-labelledby="withheld-scope-relationships-title"
          className="missing-evidence"
          role="alert"
        >
          <h3 id="withheld-scope-relationships-title">Unsupported relationships withheld</h3>
          <p>
            {withheldEdges.length} projected relationship{withheldEdges.length === 1 ? "" : "s"}{" "}
            cannot be displayed as decisive because every relationship requires one derivation
            policy and uniquely linked, available evidence.
          </p>
          <ul>
            {withheldEdges.map(({ edge, reasons }) => (
              <li key={edge.id}>
                <code>{edge.id}</code>
                <ul>
                  {reasons.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        </div>
      )}

      <section
        aria-describedby="scope-graph-description"
        aria-labelledby="scope-graph-title"
        className="scope-graph"
      >
        <h3 id="scope-graph-title">Evidence-linked scope graph</h3>
        <p className="scope-graph__description" id="scope-graph-description">
          {scope.nodes.length} scope nodes and {supportedEdges.length} decisive relationships.
          Worker identifiers are metadata; resource and lineage policies define the displayed
          relationships.
        </p>

        <div className="scope-groups">
          {groups.map((group) => (
            <section
              aria-labelledby={`scope-group-${group.id}`}
              className="scope-group"
              key={group.id}
            >
              <div className="scope-group__heading">
                <h4 id={`scope-group-${group.id}`}>{group.label}</h4>
                <span>{group.nodes.length}</span>
              </div>
              {group.nodes.length === 0 ? (
                <p className="empty-copy">None recorded.</p>
              ) : (
                <div className="scope-node-list">
                  {group.nodes.map((node) => (
                    <ScopeNodeCard evidence={evidence} key={node.key} node={node} />
                  ))}
                </div>
              )}
            </section>
          ))}
        </div>

        <section aria-labelledby="scope-edges-title" className="scope-edges">
          <div className="scope-group__heading">
            <h4 id="scope-edges-title">Decisive relationships</h4>
            <span>{supportedEdges.length}</span>
          </div>
          {supportedEdges.length === 0 ? (
            <p className="empty-copy">No evidence-supported causal or lineage edge is recorded.</p>
          ) : (
            <ol className="scope-edge-list">
              {supportedEdges.map((edge) => (
                <EdgeRelationship
                  edge={edge}
                  evidence={evidence}
                  key={edge.id}
                  nodeByKey={nodeByKey}
                />
              ))}
            </ol>
          )}
        </section>
      </section>

      <ScopeListFallback
        edges={supportedEdges}
        evidence={evidence}
        nodeByKey={nodeByKey}
        nodes={scope.nodes}
      />
    </section>
  );
}
