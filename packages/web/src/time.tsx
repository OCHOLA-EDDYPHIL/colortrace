import type { WorkspaceTimeBasis } from "@colortrace/workspace-model";

const TIME_BASIS_LABEL: Readonly<Record<WorkspaceTimeBasis, string>> = {
  "event-time": "Event time",
  "finalized-at": "Recorded when the packet was finalized",
  "occurred-at": "Workflow event time",
  "retrieved-at": "Evidence retrieval time",
  "source-time": "Source time",
  unavailable: "Time unavailable",
};

const DATE_FORMAT = new Intl.DateTimeFormat("en", {
  dateStyle: "medium",
  timeStyle: "medium",
  timeZone: "UTC",
});

export function formatTimestamp(value: string): string | null {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.valueOf()) ? null : `${DATE_FORMAT.format(timestamp)} UTC`;
}

export type TimestampProps = {
  readonly basis?: WorkspaceTimeBasis;
  readonly value: string | null;
};

export function Timestamp({ basis, value }: TimestampProps) {
  const formatted = value === null ? null : formatTimestamp(value);
  const basisLabel = basis === undefined ? null : TIME_BASIS_LABEL[basis];

  if (value === null || formatted === null) {
    return (
      <span className="timestamp timestamp--unavailable">{basisLabel ?? "Time unavailable"}</span>
    );
  }

  return (
    <span className="timestamp">
      <time dateTime={value}>{formatted}</time>
      {basisLabel === null ? null : <span className="timestamp__basis"> · {basisLabel}</span>}
    </span>
  );
}
