import {
  createClient,
  getIncidentWorkspace,
  getOperatorSession,
  type IncidentSummary,
  type IncidentWorkspaceSource,
  listIncidents,
  type OperatorSession,
} from "@colortrace/api-client";

export type BearerTokenProvider = () => Promise<string | undefined> | string | undefined;

export type IncidentReadAdapter = {
  readonly getSession: (signal?: AbortSignal) => Promise<OperatorSession>;
  readonly getWorkspace: (
    incidentId: string,
    signal?: AbortSignal,
  ) => Promise<IncidentWorkspaceSource>;
  readonly listIncidents: (signal?: AbortSignal) => Promise<readonly IncidentSummary[]>;
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
    credentials: "same-origin",
    ...(fetchImplementation === undefined ? {} : { fetch: fetchImplementation }),
    ...(tokenProvider === undefined ? {} : { auth: () => tokenProvider() }),
  });

  client.interceptors.error.use((error, response) => {
    if (error instanceof IncidentApiError) return error;
    return new IncidentApiError(response?.status ?? null, apiErrorCode(error), error);
  });

  return {
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
    listIncidents: async (signal) => {
      const response = await listIncidents(undefined, {
        client,
        throwOnError: true,
        ...(signal === undefined ? {} : { signal }),
      });
      return response.items;
    },
  };
}
