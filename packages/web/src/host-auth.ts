import type { BearerTokenProvider } from "./api-adapter.ts";

export const HOST_OIDC_TOKEN_PROVIDER_CONTRACT = "colortrace.host.oidc-token-provider/v1";

/**
 * Captures the host's one-shot in-memory provider installation. The contract is
 * deliberately a configurable own symbol property so the browser-visible
 * installation can be removed before React starts.
 */
export function captureHostOidcTokenProvider(
  host: object = globalThis,
): BearerTokenProvider | undefined {
  const key = Symbol.for(HOST_OIDC_TOKEN_PROVIDER_CONTRACT);
  const descriptor = Object.getOwnPropertyDescriptor(host, key);
  if (
    descriptor === undefined ||
    descriptor.configurable !== true ||
    typeof descriptor.value !== "function"
  ) {
    return undefined;
  }
  if (!Reflect.deleteProperty(host, key)) return undefined;
  const provider = descriptor.value as BearerTokenProvider;
  return () => provider();
}
