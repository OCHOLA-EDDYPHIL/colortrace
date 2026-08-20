import type {
  IncidentSummary,
  IncidentWorkspaceSource,
  OperatorSession,
  RecoveryReview,
  ResponsePlan,
} from "@colortrace/api-client";
import { projectIncidentReplay, projectRecoveryReview } from "@colortrace/workspace-model";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  IncidentApiError,
  type IncidentReadAdapter,
  type ResponsePlanRevision,
} from "./api-adapter.ts";
import { IncidentWorkspaceShell, type WorkspaceViewer } from "./incident-workspace-shell.tsx";
import type { RecoveryCapabilities, RecoveryPanelState } from "./recovery-verification.tsx";
import type { ResponsePlanCapabilities, ResponsePlanPanelState } from "./response-plan-review.tsx";
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

export function projectRecoverySource(
  review: RecoveryReview,
  incidentId: string,
): RecoveryPanelState {
  try {
    const workspace = projectRecoveryReview(review, incidentId);
    if (workspace.integrity === "invalid") {
      return {
        kind: "integrity-error",
        message:
          "The persisted recovery review failed identity, digest, citation, or status verification " +
          `(${workspace.problems.join(", ")}).`,
      };
    }
    return { kind: "ready", workspace };
  } catch {
    return {
      kind: "integrity-error",
      message: "The persisted recovery review could not be projected safely.",
    };
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
    principalKind: session.principal_kind,
    roles: session.roles,
  };
}

function mutationKey(operation: string): string {
  return `${operation}-${crypto.randomUUID()}`;
}

type PlanMutationAttempt = {
  readonly execute: (idempotencyKey: string) => Promise<unknown>;
  readonly identity: string;
  readonly key: string;
  readonly plan: ResponsePlan;
};

type PlanRecoveryKind = "mutation-failed" | "reconciliation-required";

type RecoveryMutationAttempt = {
  readonly identity: string;
  readonly incidentId: string;
  readonly key: string;
  readonly reason: string;
  readonly review: RecoveryReview;
};

function isExactClosedRecovery(review: RecoveryReview, attempt: RecoveryMutationAttempt): boolean {
  const expectedPacket = attempt.review.packet;
  const closure = review.closure;
  if (expectedPacket === null || closure === null) return false;
  return (
    projectRecoverySource(review, attempt.incidentId).kind === "ready" &&
    review.state === "closed" &&
    review.snapshot.incident_id === attempt.incidentId &&
    closure.workflow_version_before === attempt.review.workflow_version &&
    closure.workflow_version_after === review.workflow_version &&
    closure.packet_id === expectedPacket.packet_id &&
    closure.packet_sha256 === expectedPacket.packet_sha256 &&
    closure.outcome_id === expectedPacket.outcome_id &&
    closure.outcome_sha256 === expectedPacket.outcome_sha256
  );
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
  const [responsePlan, setResponsePlan] = useState<ResponsePlanPanelState>({ kind: "absent" });
  const [planBusy, setPlanBusy] = useState(false);
  const [planActionError, setPlanActionError] = useState<string | null>(null);
  const [planRecoveryKind, setPlanRecoveryKind] = useState<PlanRecoveryKind | null>(null);
  const [recoveryState, setRecoveryState] = useState<RecoveryPanelState>({ kind: "absent" });
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryActionError, setRecoveryActionError] = useState<string | null>(null);
  const [recoveryRecoveryKind, setRecoveryRecoveryKind] = useState<PlanRecoveryKind | null>(null);
  const pendingPlanAttempt = useRef<PlanMutationAttempt | null>(null);
  const pendingRecoveryAttempt = useRef<RecoveryMutationAttempt | null>(null);
  const selectedIncidentRef = useRef<string | null>(null);

  const incidents = useMemo(() => summaries.map(incidentInboxItemFromSummary), [summaries]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    setSummaries([]);
    selectedIncidentRef.current = null;
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
          setViewer(
            adapter.credentialConfigured
              ? {
                  kind: "expired",
                  message: "The configured operator credential expired or was rejected.",
                }
              : {
                  kind: "unauthenticated",
                  message: "No verified operator session is available.",
                },
          );
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
          selectedIncidentRef.current = null;
          setSelectedIncidentId(null);
          setState({ kind: "empty", message: "No incident records were returned." });
          return;
        }
        const nextIncidentId = next[0]?.incident_id ?? null;
        selectedIncidentRef.current = nextIncidentId;
        setSelectedIncidentId(nextIncidentId);
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

  useEffect(() => {
    if (selectedIncidentId === null) {
      pendingPlanAttempt.current = null;
      setPlanBusy(false);
      setPlanActionError(null);
      setPlanRecoveryKind(null);
      setResponsePlan({ kind: "absent" });
      return;
    }
    const controller = new AbortController();
    let active = true;
    pendingPlanAttempt.current = null;
    setPlanBusy(false);
    setPlanRecoveryKind(null);
    setPlanActionError(null);
    setResponsePlan({ kind: "loading" });
    void adapter
      .getResponsePlan(selectedIncidentId, controller.signal)
      .then((review) => {
        if (active)
          setResponsePlan(review === null ? { kind: "absent" } : { kind: "ready", review });
      })
      .catch((error: unknown) => {
        if (!active) return;
        setResponsePlan({
          kind: "error",
          message: `The response plan could not be loaded (${apiFailureLabel(error)}).`,
        });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [adapter, selectedIncidentId]);

  useEffect(() => {
    if (selectedIncidentId === null) {
      pendingRecoveryAttempt.current = null;
      setRecoveryBusy(false);
      setRecoveryActionError(null);
      setRecoveryRecoveryKind(null);
      setRecoveryState({ kind: "absent" });
      return;
    }
    const controller = new AbortController();
    let active = true;
    pendingRecoveryAttempt.current = null;
    setRecoveryBusy(false);
    setRecoveryActionError(null);
    setRecoveryRecoveryKind(null);
    setRecoveryState({ kind: "loading" });
    void adapter
      .getRecoveryReview(selectedIncidentId, controller.signal)
      .then((review) => {
        if (!active) return;
        setRecoveryState(
          review === null ? { kind: "absent" } : projectRecoverySource(review, selectedIncidentId),
        );
      })
      .catch((error: unknown) => {
        if (!active) return;
        setRecoveryState({
          kind:
            error instanceof IncidentApiError && error.status === 409 ? "integrity-error" : "error",
          message: `The recovery review could not be loaded (${apiFailureLabel(error)}).`,
        });
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [adapter, selectedIncidentId]);

  const refreshResponsePlan = useCallback(
    async (incidentId: string) => {
      const review = await adapter.getResponsePlan(incidentId);
      if (selectedIncidentRef.current !== incidentId) return false;
      setResponsePlan(review === null ? { kind: "absent" } : { kind: "ready", review });
      return true;
    },
    [adapter],
  );

  const refreshRecovery = useCallback(
    async (incidentId: string): Promise<RecoveryReview | null | undefined> => {
      const review = await adapter.getRecoveryReview(incidentId);
      if (selectedIncidentRef.current !== incidentId) return undefined;
      setRecoveryState(
        review === null ? { kind: "absent" } : projectRecoverySource(review, incidentId),
      );
      return review;
    },
    [adapter],
  );

  const runPlanMutation = useCallback(
    async (attempt: PlanMutationAttempt) => {
      const incidentId = attempt.plan.incident_id;
      if (selectedIncidentRef.current !== incidentId) return;
      setPlanBusy(true);
      setPlanActionError(null);
      setPlanRecoveryKind(null);
      try {
        await attempt.execute(attempt.key);
      } catch (error) {
        if (selectedIncidentRef.current !== incidentId) return;
        if (error instanceof IncidentApiError && error.status === 401) {
          setViewer({
            kind: "expired",
            message: "The configured operator credential expired or was rejected.",
          });
        }
        setPlanActionError(
          `The plan mutation did not complete authoritatively (${apiFailureLabel(error)}). ` +
            "Reconcile state or retry the exact action with its retained idempotency key.",
        );
        setPlanRecoveryKind("mutation-failed");
        setPlanBusy(false);
        return;
      }
      if (selectedIncidentRef.current !== incidentId) return;
      try {
        if (!(await refreshResponsePlan(incidentId))) return;
        if (pendingPlanAttempt.current?.identity === attempt.identity) {
          pendingPlanAttempt.current = null;
        }
      } catch (error) {
        if (selectedIncidentRef.current !== incidentId) return;
        setPlanActionError(
          `The plan mutation was accepted, but authoritative state could not be reconciled ` +
            `(${apiFailureLabel(error)}). Do not resubmit the mutation; reconcile plan state.`,
        );
        setPlanRecoveryKind("reconciliation-required");
      } finally {
        if (selectedIncidentRef.current === incidentId) setPlanBusy(false);
      }
    },
    [refreshResponsePlan],
  );

  const submitPlanMutation = useCallback(
    (
      plan: ResponsePlan,
      identity: string,
      operation: string,
      execute: (idempotencyKey: string) => Promise<unknown>,
    ) => {
      const retained = pendingPlanAttempt.current;
      const attempt: PlanMutationAttempt =
        retained?.identity === identity
          ? { ...retained, execute, plan }
          : { execute, identity, key: mutationKey(operation), plan };
      pendingPlanAttempt.current = attempt;
      void runPlanMutation(attempt);
    },
    [runPlanMutation],
  );

  const retryPlanMutation = useCallback(() => {
    const attempt = pendingPlanAttempt.current;
    if (attempt !== null) void runPlanMutation(attempt);
  }, [runPlanMutation]);

  const reconcilePlanMutation = useCallback(() => {
    const incidentId = selectedIncidentRef.current;
    if (incidentId === null) return;
    setPlanBusy(true);
    setPlanActionError(null);
    void refreshResponsePlan(incidentId)
      .then((current) => {
        if (!current || selectedIncidentRef.current !== incidentId) return;
        pendingPlanAttempt.current = null;
        setPlanRecoveryKind(null);
      })
      .catch((error: unknown) => {
        if (selectedIncidentRef.current !== incidentId) return;
        setPlanActionError(
          `Authoritative plan state is still unavailable (${apiFailureLabel(error)}).`,
        );
        setPlanRecoveryKind("reconciliation-required");
      })
      .finally(() => {
        if (selectedIncidentRef.current === incidentId) setPlanBusy(false);
      });
  }, [refreshResponsePlan]);

  const approvePlan = useCallback(
    (plan: ResponsePlan) => {
      const incidentId = selectedIncidentRef.current;
      if (incidentId === null || plan.incident_id !== incidentId) return;
      submitPlanMutation(plan, `approve:${plan.plan_sha256}`, "plan-approve", (key) =>
        adapter.approveResponsePlan(incidentId, plan, key),
      );
    },
    [adapter, submitPlanMutation],
  );
  const editPlan = useCallback(
    (plan: ResponsePlan, revision: ResponsePlanRevision) => {
      const incidentId = selectedIncidentRef.current;
      if (incidentId === null || plan.incident_id !== incidentId) return;
      const identity = `edit:${plan.plan_sha256}:${JSON.stringify(revision)}`;
      submitPlanMutation(plan, identity, "plan-edit", (key) =>
        adapter.editResponsePlan(incidentId, plan, revision, key),
      );
    },
    [adapter, submitPlanMutation],
  );
  const rejectPlan = useCallback(
    (
      plan: ResponsePlan,
      reason: "incorrect-command" | "insufficient-evidence" | "unresolved-risk" | "unsafe-scope",
    ) => {
      const incidentId = selectedIncidentRef.current;
      if (incidentId === null || plan.incident_id !== incidentId) return;
      submitPlanMutation(plan, `reject:${plan.plan_sha256}:${reason}`, "plan-reject", (key) =>
        adapter.rejectResponsePlan(incidentId, plan, reason, key),
      );
    },
    [adapter, submitPlanMutation],
  );

  const runRecoveryClosure = useCallback(
    async (attempt: RecoveryMutationAttempt) => {
      if (selectedIncidentRef.current !== attempt.incidentId) return;
      setRecoveryBusy(true);
      setRecoveryActionError(null);
      setRecoveryRecoveryKind(null);
      try {
        await adapter.closeRecovery(
          attempt.incidentId,
          attempt.review,
          attempt.reason,
          attempt.key,
        );
      } catch (error) {
        if (selectedIncidentRef.current !== attempt.incidentId) return;
        if (error instanceof IncidentApiError && error.status === 401) {
          setViewer({
            kind: "expired",
            message: "The configured operator credential expired or was rejected.",
          });
        }
        const retryable =
          !(error instanceof IncidentApiError) ||
          error.status === null ||
          (error.status >= 500 && error.status <= 599);
        if (!retryable && pendingRecoveryAttempt.current?.identity === attempt.identity) {
          pendingRecoveryAttempt.current = null;
        }
        setRecoveryActionError(
          retryable
            ? `The closure response was ambiguous (${apiFailureLabel(error)}). Reconcile state or ` +
                "retry the exact closure with its retained idempotency key."
            : `Closure was not accepted (${apiFailureLabel(error)}). Reconcile authoritative ` +
                "recovery state before taking another action.",
        );
        setRecoveryRecoveryKind(retryable ? "mutation-failed" : "reconciliation-required");
        setRecoveryBusy(false);
        return;
      }
      if (selectedIncidentRef.current !== attempt.incidentId) return;
      try {
        const review = await refreshRecovery(attempt.incidentId);
        if (review === undefined) return;
        if (review === null) {
          throw new IncidentApiError(
            404,
            "recovery-review-not-found-after-closure",
            new Error("recovery review missing after closure"),
          );
        }
        if (!isExactClosedRecovery(review, attempt)) {
          setRecoveryActionError(
            "The closure request returned, but the authoritative read did not contain the exact " +
              "bound closure. Do not submit another closure; reconcile recovery state.",
          );
          setRecoveryRecoveryKind("reconciliation-required");
          return;
        }
        if (pendingRecoveryAttempt.current?.identity === attempt.identity) {
          pendingRecoveryAttempt.current = null;
        }
      } catch (error) {
        if (selectedIncidentRef.current !== attempt.incidentId) return;
        setRecoveryActionError(
          `Closure may have been accepted, but authoritative recovery state could not be ` +
            `reconciled (${apiFailureLabel(error)}). Do not submit a new closure; reconcile state.`,
        );
        setRecoveryRecoveryKind("reconciliation-required");
      } finally {
        if (selectedIncidentRef.current === attempt.incidentId) setRecoveryBusy(false);
      }
    },
    [adapter, refreshRecovery],
  );

  const closeRecovery = useCallback(
    (review: RecoveryReview, reason: string) => {
      const incidentId = selectedIncidentRef.current;
      const packet = review.packet;
      if (incidentId === null || packet === null || review.snapshot.incident_id !== incidentId) {
        return;
      }
      if (pendingRecoveryAttempt.current !== null) {
        setRecoveryActionError(
          "A prior closure attempt has not been reconciled. Reconcile its authoritative result " +
            "before taking another closure action.",
        );
        setRecoveryRecoveryKind("reconciliation-required");
        return;
      }
      const identity = `close:${packet.packet_sha256}:${packet.outcome_sha256}:${reason}`;
      const attempt: RecoveryMutationAttempt = {
        identity,
        incidentId,
        key: mutationKey("recovery-close"),
        reason,
        review,
      };
      pendingRecoveryAttempt.current = attempt;
      void runRecoveryClosure(attempt);
    },
    [runRecoveryClosure],
  );

  const retryRecoveryClosure = useCallback(() => {
    const attempt = pendingRecoveryAttempt.current;
    if (attempt !== null) void runRecoveryClosure(attempt);
  }, [runRecoveryClosure]);

  const reconcileRecoveryClosure = useCallback(() => {
    const incidentId = selectedIncidentRef.current;
    if (incidentId === null) return;
    setRecoveryBusy(true);
    setRecoveryActionError(null);
    void refreshRecovery(incidentId)
      .then((review) => {
        if (review === undefined || selectedIncidentRef.current !== incidentId) return;
        if (review === null) {
          setRecoveryActionError("Authoritative recovery state is still unavailable.");
          setRecoveryRecoveryKind("reconciliation-required");
          return;
        }
        const attempt = pendingRecoveryAttempt.current;
        if (
          projectRecoverySource(review, incidentId).kind !== "ready" ||
          (attempt !== null && !isExactClosedRecovery(review, attempt))
        ) {
          setRecoveryActionError(
            "Authoritative recovery state still does not contain the exact bound closure. " +
              "No new closure may be submitted.",
          );
          setRecoveryRecoveryKind("reconciliation-required");
          return;
        }
        pendingRecoveryAttempt.current = null;
        setRecoveryRecoveryKind(null);
      })
      .catch((error: unknown) => {
        if (selectedIncidentRef.current !== incidentId) return;
        setRecoveryActionError(
          `Authoritative recovery state is still unavailable (${apiFailureLabel(error)}).`,
        );
        setRecoveryRecoveryKind("reconciliation-required");
      })
      .finally(() => {
        if (selectedIncidentRef.current === incidentId) setRecoveryBusy(false);
      });
  }, [refreshRecovery]);

  const planCapabilities = useMemo<ResponsePlanCapabilities>(() => {
    if (viewer.kind === "expired") {
      return { canApprove: false, canEdit: false, session: "expired" };
    }
    if (viewer.kind !== "authenticated" || viewer.principalKind !== "human") {
      return { canApprove: false, canEdit: false, session: "read-only" };
    }
    return {
      canApprove: viewer.roles.includes("response-plan.approver"),
      canEdit: viewer.roles.includes("response-plan.editor"),
      session: "active",
    };
  }, [viewer]);

  const recoveryCapabilities = useMemo<RecoveryCapabilities>(() => {
    if (viewer.kind === "expired") return { canClose: false, session: "expired" };
    if (viewer.kind !== "authenticated" || viewer.principalKind !== "human") {
      return { canClose: false, session: "read-only" };
    }
    return {
      canClose: viewer.roles.includes("recovery.closer"),
      session: "active",
    };
  }, [viewer]);

  const retry = useCallback(() => {
    selectedIncidentRef.current = null;
    setFocusRequest((value) => value + 1);
    setGeneration((value) => value + 1);
  }, []);
  const selectIncident = useCallback((incidentId: string) => {
    selectedIncidentRef.current = incidentId;
    pendingPlanAttempt.current = null;
    pendingRecoveryAttempt.current = null;
    setPlanBusy(false);
    setPlanActionError(null);
    setPlanRecoveryKind(null);
    setRecoveryBusy(false);
    setRecoveryActionError(null);
    setRecoveryRecoveryKind(null);
    setState({ kind: "loading", message: "Loading the selected incident workspace." });
    setFocusRequest((value) => value + 1);
    setSelectedIncidentId(incidentId);
  }, []);

  return (
    <IncidentWorkspaceShell
      incidents={incidents}
      focusRequest={focusRequest}
      onRetry={retry}
      onReset={retry}
      onSelectIncident={selectIncident}
      selectedIncidentId={selectedIncidentId}
      state={state}
      viewer={viewer}
      recovery={{
        actionError: recoveryActionError,
        busy: recoveryBusy,
        capabilities: recoveryCapabilities,
        onClose: closeRecovery,
        recovery:
          recoveryRecoveryKind === null
            ? null
            : {
                kind: recoveryRecoveryKind,
                onReconcile: reconcileRecoveryClosure,
                ...(recoveryRecoveryKind === "mutation-failed"
                  ? { onRetry: retryRecoveryClosure }
                  : {}),
              },
        state: recoveryState,
      }}
      responsePlan={{
        actionError: planActionError,
        busy: planBusy,
        capabilities: planCapabilities,
        onApprove: approvePlan,
        onEdit: editPlan,
        onReject: rejectPlan,
        recovery:
          planRecoveryKind === null
            ? null
            : {
                kind: planRecoveryKind,
                onReconcile: reconcilePlanMutation,
                ...(planRecoveryKind === "mutation-failed" ? { onRetry: retryPlanMutation } : {}),
              },
        state: responsePlan,
      }}
    />
  );
}
