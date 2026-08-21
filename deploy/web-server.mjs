import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_REQUEST_URL_BYTES = 2048;
const MAX_API_RESPONSE_BYTES = 4 * 1024 * 1024;
const API_TIMEOUT_MS = 10_000;
const METADATA_IDENTITY_URL =
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";
const PUBLIC_ROOT = fileURLToPath(new URL("./public/", import.meta.url));
const INCIDENT_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const INCIDENT_PROJECTION_PATH = /^\/v1\/incidents\/([^/]+)\/(workspace|response-plan|recovery)$/;
const LIST_QUERY_FIELDS = new Set(["cursor", "limit"]);

const CONTENT_TYPES = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".woff2", "font/woff2"],
]);

function hasOnlyQueryFields(requestUrl, allowedFields) {
  const observed = new Set();
  for (const field of requestUrl.searchParams.keys()) {
    if (!allowedFields.has(field) || observed.has(field)) return false;
    observed.add(field);
  }
  return true;
}

function decodeIncidentIdentifier(segment) {
  let identifier;
  try {
    identifier = decodeURIComponent(segment);
  } catch {
    return null;
  }
  if (!INCIDENT_IDENTIFIER.test(identifier)) return null;
  if (identifier.split("/").some((part) => part === "." || part === "..")) return null;
  return identifier;
}

function publicApiTarget(method, requestUrl) {
  if (method !== "GET") return null;
  if (requestUrl.pathname === "/v1/incidents") {
    if (!hasOnlyQueryFields(requestUrl, LIST_QUERY_FIELDS)) return null;
    return `${requestUrl.pathname}${requestUrl.search}`;
  }
  if (requestUrl.searchParams.size !== 0) return null;
  const match = INCIDENT_PROJECTION_PATH.exec(requestUrl.pathname);
  if (match === null) return null;
  const identifier = decodeIncidentIdentifier(match[1]);
  if (identifier === null) return null;
  return `/v1/incidents/${encodeURIComponent(identifier)}/${match[2]}`;
}

export function isPublicApiRequest(method, requestTarget) {
  try {
    return publicApiTarget(method, new URL(requestTarget, "https://colortrace.invalid")) !== null;
  } catch {
    return false;
  }
}

export function loadConfiguration(environment) {
  const portValue = environment.PORT ?? "8080";
  if (!/^[1-9][0-9]{0,4}$/.test(portValue)) throw new Error("port-invalid");
  const port = Number(portValue);
  if (port > 65535) throw new Error("port-invalid");
  const apiOrigin = new URL(environment.COLORTRACE_API_ORIGIN ?? "");
  const apiAudience = new URL(environment.COLORTRACE_API_AUDIENCE ?? "");
  for (const value of [apiOrigin, apiAudience]) {
    if (
      value.protocol !== "https:" ||
      value.username !== "" ||
      value.password !== "" ||
      value.pathname !== "/" ||
      value.search !== "" ||
      value.hash !== ""
    ) {
      throw new Error("api-boundary-invalid");
    }
  }
  if (apiOrigin.origin !== apiAudience.origin) throw new Error("api-boundary-invalid");
  return { port, apiOrigin: apiOrigin.origin, apiAudience: apiAudience.origin };
}

function responseHeaders(contentType) {
  return {
    "Cache-Control": "no-store",
    "Content-Security-Policy":
      "default-src 'self'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'",
    "Content-Type": contentType,
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
  };
}

function jsonResponse(response, status, code) {
  response.writeHead(status, responseHeaders("application/json; charset=utf-8"));
  response.end(`${JSON.stringify({ code })}\n`);
}

async function identityToken(audience, fetchImplementation) {
  const url = new URL(METADATA_IDENTITY_URL);
  url.searchParams.set("audience", audience);
  url.searchParams.set("format", "full");
  const response = await fetchImplementation(url, {
    headers: { "Metadata-Flavor": "Google" },
    redirect: "error",
    signal: AbortSignal.timeout(API_TIMEOUT_MS),
  });
  const token = await response.text();
  if (
    !response.ok ||
    token.length < 100 ||
    token.length > 16_384 ||
    token !== token.trim() ||
    /\s/.test(token)
  ) {
    throw new Error("identity-token-unavailable");
  }
  return token;
}

async function readBoundedBody(upstream) {
  if (upstream.body === null) return Buffer.alloc(0);
  const reader = upstream.body.getReader();
  const body = Buffer.allocUnsafe(MAX_API_RESPONSE_BYTES);
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return body.subarray(0, length);
      if (value.byteLength > MAX_API_RESPONSE_BYTES - length) {
        throw new Error("api-response-invalid");
      }
      body.set(value, length);
      length += value.byteLength;
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}

async function proxyApi(request, response, requestUrl, configuration, fetchImplementation) {
  if (request.method === "GET" && requestUrl.pathname === "/v1/session") {
    jsonResponse(response, 401, "authentication-required");
    return;
  }
  const targetPath = publicApiTarget(request.method, requestUrl);
  if (targetPath === null) {
    jsonResponse(response, request.method === "GET" ? 404 : 405, "request-not-allowed");
    return;
  }
  const token = await identityToken(configuration.apiAudience, fetchImplementation);
  const target = new URL(targetPath, configuration.apiOrigin);
  const upstream = await fetchImplementation(target, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
    method: "GET",
    redirect: "error",
    signal: AbortSignal.timeout(API_TIMEOUT_MS),
  });
  const contentType = upstream.headers.get("content-type") ?? "";
  if (contentType.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    await upstream.body?.cancel();
    throw new Error("api-response-invalid");
  }
  const body = await readBoundedBody(upstream);
  response.writeHead(upstream.status, responseHeaders("application/json; charset=utf-8"));
  response.end(body);
}

async function serveStatic(response, pathname) {
  const relative = pathname.startsWith("/assets/") ? normalize(pathname.slice(1)) : "index.html";
  if (relative.startsWith("..") || !/^[A-Za-z0-9._/-]+$/.test(relative)) {
    jsonResponse(response, 404, "asset-not-found");
    return;
  }
  const path = join(PUBLIC_ROOT, relative);
  let information;
  try {
    information = await stat(path);
  } catch {
    jsonResponse(response, 404, "asset-not-found");
    return;
  }
  if (!information.isFile() || information.size > MAX_API_RESPONSE_BYTES) {
    jsonResponse(response, 404, "asset-not-found");
    return;
  }
  response.writeHead(
    200,
    responseHeaders(CONTENT_TYPES.get(extname(path)) ?? "application/octet-stream"),
  );
  createReadStream(path).pipe(response);
}

export function createApplication(configuration, dependencies = {}) {
  const fetchImplementation = dependencies.fetch ?? fetch;
  return createServer(async (request, response) => {
    try {
      if (request.url === undefined || Buffer.byteLength(request.url) > MAX_REQUEST_URL_BYTES) {
        jsonResponse(response, 400, "request-invalid");
        return;
      }
      const requestUrl = new URL(request.url, "https://colortrace.invalid");
      if (requestUrl.pathname.startsWith("/v1/") || request.method !== "GET") {
        await proxyApi(request, response, requestUrl, configuration, fetchImplementation);
      } else {
        await serveStatic(response, requestUrl.pathname);
      }
    } catch {
      jsonResponse(response, 503, "service-unavailable");
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const configuration = loadConfiguration(process.env);
  createApplication(configuration).listen(configuration.port, "0.0.0.0");
}
