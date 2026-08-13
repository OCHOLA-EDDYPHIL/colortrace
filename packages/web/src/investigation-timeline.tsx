import type {
  WorkspaceEvidence,
  WorkspaceTimelineCategory,
  WorkspaceTimelineEntry,
} from "@colortrace/workspace-model";
import { useId } from "react";

import { EvidenceCitation } from "./evidence-citation.tsx";
import { StatusBadge } from "./status-badge.tsx";
import { Timestamp } from "./time.tsx";

const TIMELINE_CATEGORIES: readonly WorkspaceTimelineCategory[] = [
  "source-observation",
  "model-reasoning",
  "deterministic-result",
  "workflow-event",
  "human-event",
];

function TimelineEntry({
  entry,
  evidence,
}: {
  readonly entry: WorkspaceTimelineEntry;
  readonly evidence: readonly WorkspaceEvidence[];
}) {
  const headingId = useId();

  return (
    <li className="timeline-entry" data-category={entry.category}>
      <div aria-hidden="true" className="timeline-entry__rail" />
      <article aria-labelledby={headingId} className="timeline-entry__content">
        <div className="timeline-entry__heading">
          <div>
            <StatusBadge value={entry.category} />
            <h3 id={headingId}>{entry.label}</h3>
          </div>
          <StatusBadge value={entry.status} />
        </div>
        <Timestamp basis={entry.time_basis} value={entry.timestamp} />
        {entry.detail === null ? null : <p>{entry.detail}</p>}
        <p className="record-id">
          Record <code>{entry.record_id}</code>
        </p>
        {entry.citations.length === 0 ? (
          <p className="citation-empty">No citations recorded.</p>
        ) : (
          <ul aria-label="Citations" className="citation-list">
            {entry.citations.map((citation) => (
              <li key={`${citation.namespace}:${citation.id}`}>
                <EvidenceCitation citation={citation} evidence={evidence} />
              </li>
            ))}
          </ul>
        )}
      </article>
    </li>
  );
}

export type InvestigationTimelineProps = {
  readonly entries: readonly WorkspaceTimelineEntry[];
  readonly evidence: readonly WorkspaceEvidence[];
};

export function InvestigationTimeline({ entries, evidence }: InvestigationTimelineProps) {
  return (
    <section aria-labelledby="timeline-title" className="panel timeline-panel">
      <div className="section-heading section-heading--wrap">
        <div>
          <p className="eyebrow">Chronology and provenance</p>
          <h2 id="timeline-title">Investigation timeline</h2>
        </div>
        <span className="count-pill">
          <span aria-hidden="true">{entries.length}</span>
          <span className="sr-only">{entries.length} timeline records</span>
        </span>
      </div>

      <ul aria-label="Timeline record categories" className="timeline-legend">
        {TIMELINE_CATEGORIES.map((category) => (
          <li key={category}>
            <StatusBadge value={category} />
            <span>{entries.filter((entry) => entry.category === category).length}</span>
          </li>
        ))}
      </ul>

      {entries.length === 0 ? (
        <p className="empty-copy">No timeline records are available.</p>
      ) : (
        <ol className="timeline-list">
          {entries.map((entry) => (
            <TimelineEntry entry={entry} evidence={evidence} key={entry.id} />
          ))}
        </ol>
      )}
    </section>
  );
}
