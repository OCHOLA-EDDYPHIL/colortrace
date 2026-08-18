import {
  approveResponsePlan,
  closeRecovery as closeRecoveryRequest,
  createClient,
  editResponsePlan,
  getIncidentWorkspace,
  getOperatorSession,
  getRecoveryReview,
  getResponsePlanReview,
  type IncidentSummary,
  type IncidentWorkspaceSource,
  listIncidents,
  type OperatorSession,
  type RecoveryClosureResult,
  type RecoveryReview,
  type ResponsePlan,
  type ResponsePlanDecision,
  type ResponsePlanReview,
  rejectResponsePlan,
} from "@colortrace/api-client";

export type BearerTokenProvider = () => Promise<string | undefined> | string | undefined;

export type ResponsePlanRevision = Pick<ResponsePlan, "commands" | "unresolved_acknowledged">;

export type IncidentReadAdapter = {
  readonly credentialConfigured: boolean;
  readonly approveResponsePlan: (
    incidentId: string,
    plan: ResponsePlan,
    idempotencyKey: string,
  ) => Promise<ResponsePlanDecision>;
  readonly closeRecovery: (
    incidentId: string,
    review: RecoveryReview,
    reason: string,
    idempotencyKey: string,
  ) => Promise<RecoveryClosureResult>;
  readonly editResponsePlan: (
    incidentId: string,
    plan: ResponsePlan,
    revision: ResponsePlanRevision,
    idempotencyKey: string,
  ) => Promise<ResponsePlan>;
  readonly getResponsePlan: (
    incidentId: string,
    signal?: AbortSignal,
  ) => Promise<ResponsePlanReview | null>;
  readonly getRecoveryReview: (
    incidentId: string,
    signal?: AbortSignal,
  ) => Promise<RecoveryReview | null>;
  readonly getSession: (signal?: AbortSignal) => Promise<OperatorSession>;
  readonly getWorkspace: (
    incidentId: string,
    signal?: AbortSignal,
  ) => Promise<IncidentWorkspaceSource>;
  readonly listIncidents: (signal?: AbortSignal) => Promise<readonly IncidentSummary[]>;
  readonly rejectResponsePlan: (
    incidentId: string,
    plan: ResponsePlan,
    reasonCode: "incorrect-command" | "insufficient-evidence" | "unresolved-risk" | "unsafe-scope",
    idempotencyKey: string,
  ) => Promise<ResponsePlanDecision>;
};

export type IncidentReadAdapterOptions = {
  readonly baseUrl: string;
  readonly fetch?: typeof fetch;
  /**
   * Supplies a bearer token from caller-owned memory. The adapter never persists it.
   */
  readonly tokenProvider?: BearerTokenProvider;
};

function apiErrorCode(error: unknown): string | null {
  if (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string"
  ) {
    return error.code;
  }
  return null;
}

export class IncidentApiError extends Error {
  readonly code: string | null;
  readonly status: number | null;

  constructor(status: number | null, code: string | null, cause: unknown) {
    const detail = code === null ? "unclassified failure" : code;
    const statusDetail = status === null ? "without an HTTP response" : `with HTTP ${status}`;
    super(`Incident API request failed ${statusDetail}: ${detail}`, { cause });
    this.name = "IncidentApiError";
    this.code = code;
    this.status = status;
  }
}

/**
 * Creates the generated read client. Production passes window.location.origin;
 * tests may inject a fetch implementation and an in-memory token provider.
 */
export function createIncidentReadAdapter({
  baseUrl,
  fetch: fetchImplementation,
  tokenProvider,
}: IncidentReadAdapterOptions): IncidentReadAdapter {
  const client = createClient({
    baseUrl,
    credentials: "omit",
    ...(fetchImplementation === undefined ? {} : { fetch: fetchImplementation }),
    ...(tokenProvider === undefined ? {} : { auth: () => tokenProvider() }),
  });

  client.interceptors.error.use((error, response) => {
    if (error instanceof IncidentApiError) return error;
    return new IncidentApiError(response?.status ?? null, apiErrorCode(error), error);
  });

  return {
    credentialConfigured: tokenProvider !== undefined,
    approveResponsePlan: (incidentId, plan, idempotencyKey) =>
      approveResponsePlan(
        {
          incidentId,
          decideResponsePlanRequest: {
            expected_incident_version: plan.incident_version,
            expected_plan_version: plan.version,
            expected_plan_sha256: plan.plan_sha256,
            idempotency_key: idempotencyKey,
          },
        },
        { client, throwOnError: true },
      ),
    closeRecovery: (incidentId, review, reason, idempotencyKey) => {
      const packet = review.packet;
      if (packet === null) {
        return Promise.reject(
          new IncidentApiError(null, "recovery-packet-missing", new Error("packet missing")),
        );
      }
      return closeRecoveryRequest(
        {
          incidentId,
          recoveryClosureRequest: {
            schema: "recovery-closure-request/v1",
            expected_incident_version: review.current_incident_version,
            expected_workflow_version: review.workflow_version,
            expected_packet_id: packet.packet_id,
            expected_packet_sha256: packet.packet_sha256,
            expected_outcome_id: packet.outcome_id,
            expected_outcome_sha256: packet.outcome_sha256,
            reason,
            idempotency_key: idempotencyKey,
          },
        },
        { client, throwOnError: true },
      );
    },
    editResponsePlan: (incidentId, plan, revision, idempotencyKey) =>
      editResponsePlan(
        {
          incidentId,
          editResponsePlanRequest: {
            expected_incident_version: plan.incident_version,
            expected_plan_version: plan.version,
            expected_plan_sha256: plan.plan_sha256,
            response_packet_id: plan.response_packet_id,
            response_packet_sha256: plan.response_packet_sha256,
            deterministic_scope_sha256: plan.deterministic_scope_sha256,
            targets: plan.targets,
            exclusions: plan.exclusions,
            commands: revision.commands,
            unresolved_acknowledged: revision.unresolved_acknowledged,
            idempotency_key: idempotencyKey,
          },
        },
        { client, throwOnError: true },
      ),
    getSession: (signal) =>
      getOperatorSession({
        client,
        throwOnError: true,
        ...(signal === undefined ? {} : { signal }),
      }),
    getWorkspace: (incidentId, signal) =>
      getIncidentWorkspace(
        { incidentId },
        {
          client,
          throwOnError: true,
          ...(signal === undefined ? {} : { signal }),
        },
      ),
    getResponsePlan: async (incidentId, signal) => {
      try {
        return await getResponsePlanReview(
          { incidentId },
          {
            client,
            throwOnError: true,
            ...(signal === undefined ? {} : { signal }),
          },
        );
      } catch (error) {
        if (error instanceof IncidentApiError && error.status === 404) return null;
        throw error;
      }
    },
    getRecoveryReview: async (incidentId, signal) => {
      try {
        return await getRecoveryReview(
          { incidentId },
          {
            client,
            throwOnError: true,
            ...(signal === undefined ? {} : { signal }),
          },
        );
      } catch (error) {
        if (error instanceof IncidentApiError && error.status === 404) return null;
        throw error;
      }
    },
    listIncidents: async (signal) => {
      const response = await listIncidents(undefined, {
        client,
        throwOnError: true,
        ...(signal === undefined ? {} : { signal }),
      });
      return response.items;
    },
    rejectResponsePlan: (incidentId, plan, reasonCode, idempotencyKey) =>
      rejectResponsePlan(
        {
          incidentId,
          rejectResponsePlanRequest: {
            expected_incident_version: plan.incident_version,
            expected_plan_version: plan.version,
            expected_plan_sha256: plan.plan_sha256,
            reason_code: reasonCode,
            idempotency_key: idempotencyKey,
          },
        },
        { client, throwOnError: true },
      ),
  };
}
