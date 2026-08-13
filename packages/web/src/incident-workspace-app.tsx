import type {
  IncidentSummary,
  IncidentWorkspaceSource,
  OperatorSession,
} from "@colortrace/api-client";
import { projectIncidentReplay } from "@colortrace/workspace-model";
import { useCallback, useEffect, useMemo, useState } from "react";

import { IncidentApiError, type IncidentReadAdapter } from "./api-adapter.ts";
import { IncidentWorkspaceShell, type WorkspaceViewer } from "./incident-workspace-shell.tsx";
import type { IncidentInboxItem, IncidentWorkspaceViewState } from "./view-state.ts";

export type IncidentWorkspaceAppProps = {
  readonly adapter: IncidentReadAdapter;
};

export function incidentInboxItemFromSummary(summary: IncidentSummary): IncidentInboxItem {
  return {
    alert_id: summary.alert_id,
    created_at: summary.created_at,
    delayed: summary.delayed,
    id: summary.incident_id,
    missing: [...summary.missing],
    status: summary.status,
    updated_at: summary.updated_at,
  };
}

function integrityError(incident: IncidentInboxItem, message: string): IncidentWorkspaceViewState {
  return { incident, kind: "integrity-error", message };
}

function sameJsonValue(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return false;
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    return left.every((value, index) => sameJsonValue(value, right[index]));
  }

  const leftRecord = left as Readonly<Record<string, unknown>>;
  const rightRecord = right as Readonly<Record<string, unknown>>;
  const leftKeys = Object.keys(leftRecord).sort();
  const rightKeys = Object.keys(rightRecord).sort();
  return (
    leftKeys.length === rightKeys.length &&
    leftKeys.every(
      (key, index) => key === rightKeys[index] && sameJsonValue(leftRecord[key], rightRecord[key]),
    )
  );
}

export function projectWorkspaceSource(
  source: IncidentWorkspaceSource,
  summary: IncidentSummary,
): IncidentWorkspaceViewState {
  const incident = incidentInboxItemFromSummary(summary);
  if (
    source.view.incident.incident_id !== summary.incident_id ||
    source.view.incident.alert_id !== summary.alert_id ||
    source.view.task.incident_id !== summary.incident_id
  ) {
    return integrityError(
      incident,
      "The workspace response did not match the selected incident identity.",
    );
  }

  if (source.replay_state === "pending") {
    if (source.replay !== null) {
      return integrityError(
        incident,
        "The pending workspace included replay data and was withheld.",
      );
    }
    const status = source.view.incident.status;
    if (status !== "queued" && status !== "running") {
      return integrityError(
        incident,
        "The pending workspace reported a completed incident state and was withheld.",
      );
    }
    return { incident: { ...incident, status }, kind: status };
  }

  if (source.replay === null) {
    return integrityError(incident, "The ready workspace did not include its verified replay.");
  }
  if (source.view.packet === null) {
    return integrityError(
      incident,
      "The ready workspace did not include the persisted response packet.",
    );
  }
  if (!sameJsonValue(source.view.packet, source.replay.packet)) {
    return integrityError(
      incident,
      "The persisted response packet did not match the verified replay.",
    );
  }
  if (
    source.replay.incident.incident_id !== source.view.incident.incident_id ||
    source.replay.incident.alert_id !== source.view.incident.alert_id ||
    source.replay.incident.packet_id !== source.view.incident.packet_id ||
    source.replay.incident.status !== source.view.incident.status ||
    source.replay.incident.trace_id !== source.view.incident.trace_id
  ) {
    return integrityError(
      incident,
      "The verified replay did not match the selected incident identity.",
    );
  }

  try {
    return {
      kind: "workspace",
      workspace: projectIncidentReplay({
        ...source.replay,
        human_events: source.human_events,
      }),
    };
  } catch {
    return integrityError(
      incident,
      "The verified replay could not be projected into an investigation workspace.",
    );
  }
}

function apiFailureLabel(error: unknown): string {
  if (!(error instanceof IncidentApiError) || error.code === null) return "request-failed";
  return error.code.slice(0, 120);
}

function workspaceFailure(error: unknown, incident: IncidentInboxItem): IncidentWorkspaceViewState {
  const code = apiFailureLabel(error);
  if (error instanceof IncidentApiError && error.status === 409) {
    return integrityError(
      incident,
      `The persisted incident workspace failed integrity verification (${code}).`,
    );
  }
  return {
    kind: "fetch-error",
    message: `The selected incident workspace could not be loaded (${code}).`,
  };
}

function viewerFromSession(session: OperatorSession): WorkspaceViewer {
  return {
    displayName: session.display_name,
    kind: "authenticated",
  };
}

export function IncidentWorkspaceApp({ adapter }: IncidentWorkspaceAppProps) {
  const [generation, setGeneration] = useState(0);
  const [summaries, setSummaries] = useState<readonly IncidentSummary[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [state, setState] = useState<IncidentWorkspaceViewState>({
    kind: "loading",
    message: "Loading the incident list.",
  });
  const [viewer, setViewer] = useState<WorkspaceViewer>({ kind: "loading" });
  const [focusRequest, setFocusRequest] = useState(0);

  const incidents = useMemo(() => summaries.map(incidentInboxItemFromSummary), [summaries]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setSummaries([]);
    setSelectedIncidentId(null);
    setState({
      kind: "loading",
      message: generation === 0 ? "Loading the incident list." : "Reloading the incident list.",
    });
    setViewer({ kind: "loading" });

    void adapter
      .getSession(controller.signal)
      .then((session) => {
        if (active) setViewer(viewerFromSession(session));
      })
      .catch((error: unknown) => {
        if (!active) return;
        if (error instanceof IncidentApiError && error.status === 401) {
          setViewer({
            kind: "unauthenticated",
            message: "No verified operator session is available.",
          });
          return;
        }
        setViewer({
          kind: "error",
          message: `The operator session could not be checked (${apiFailureLabel(error)}).`,
        });
      });

    void adapter
      .listIncidents(controller.signal)
      .then((items) => {
        if (!active) return;
        const next = [...items];
        setSummaries(next);
        if (next.length === 0) {
          setSelectedIncidentId(null);
          setState({ kind: "empty", message: "No incident records were returned." });
          return;
        }
        setSelectedIncidentId(next[0]?.incident_id ?? null);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setState({
          kind: "fetch-error",
          message: `The incident list could not be loaded (${apiFailureLabel(error)}).`,
        });
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [adapter, generation]);

  useEffect(() => {
    if (selectedIncidentId === null) return;
    const summary = summaries.find((item) => item.incident_id === selectedIncidentId);
    if (summary === undefined) return;

    const controller = new AbortController();
    let active = true;
    setState({ kind: "loading", message: "Loading the selected incident workspace." });

    void adapter
      .getWorkspace(selectedIncidentId, controller.signal)
      .then((source) => {
        if (active) setState(projectWorkspaceSource(source, summary));
      })
      .catch((error: unknown) => {
        if (active) setState(workspaceFailure(error, incidentInboxItemFromSummary(summary)));
      });

    return () => {
      active = false;
      controller.abort();
    };
  }, [adapter, selectedIncidentId, summaries]);

  const retry = useCallback(() => {
    setFocusRequest((value) => value + 1);
    setGeneration((value) => value + 1);
  }, []);
  const selectIncident = useCallback((incidentId: string) => {
    setState({ kind: "loading", message: "Loading the selected incident workspace." });
    setFocusRequest((value) => value + 1);
    setSelectedIncidentId(incidentId);
  }, []);

  return (
    <IncidentWorkspaceShell
      incidents={incidents}
      focusRequest={focusRequest}
      onRetry={retry}
      onSelectIncident={selectIncident}
      selectedIncidentId={selectedIncidentId}
      state={state}
      viewer={viewer}
    />
  );
}
