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
const INCIDENT_ID = "[A-Za-z0-9][A-Za-z0-9._:-]{0,255}";
const API_PATHS = [
  /^\/v1\/incidents$/,
  new RegExp(`^/v1/incidents/${INCIDENT_ID}$`),
  new RegExp(`^/v1/incidents/${INCIDENT_ID}/replay$`),
  new RegExp(`^/v1/incidents/${INCIDENT_ID}/workspace$`),
  new RegExp(`^/v1/incidents/${INCIDENT_ID}/response-plan(?:/draft)?$`),
  new RegExp(`^/v1/incidents/${INCIDENT_ID}/recovery$`),
];

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

export function isPublicApiRequest(method, pathname) {
  return method === "GET" && API_PATHS.some((pattern) => pattern.test(pathname));
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
  };
}

function jsonResponse(response, status, code) {
  response.writeHead(status, responseHeaders("application/json; charset=utf-8"));
  response.end(`${JSON.stringify({ code })}\n`);
}

async function identityToken(audience) {
  const url = new URL(METADATA_IDENTITY_URL);
  url.searchParams.set("audience", audience);
  url.searchParams.set("format", "full");
  const response = await fetch(url, {
    headers: { "Metadata-Flavor": "Google" },
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

async function proxyApi(request, response, requestUrl, configuration) {
  if (request.method === "GET" && requestUrl.pathname === "/v1/session") {
    jsonResponse(response, 401, "authentication-required");
    return;
  }
  if (!isPublicApiRequest(request.method, requestUrl.pathname)) {
    jsonResponse(response, request.method === "GET" ? 404 : 405, "request-not-allowed");
    return;
  }
  const token = await identityToken(configuration.apiAudience);
  const target = new URL(`${requestUrl.pathname}${requestUrl.search}`, configuration.apiOrigin);
  const upstream = await fetch(target, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
    method: "GET",
    redirect: "error",
    signal: AbortSignal.timeout(API_TIMEOUT_MS),
  });
  const contentType = upstream.headers.get("content-type") ?? "";
  const body = Buffer.from(await upstream.arrayBuffer());
  if (!contentType.toLowerCase().startsWith("application/json") || body.length > MAX_API_RESPONSE_BYTES) {
    throw new Error("api-response-invalid");
  }
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
  response.writeHead(200, responseHeaders(CONTENT_TYPES.get(extname(path)) ?? "application/octet-stream"));
  createReadStream(path).pipe(response);
}

export function createApplication(configuration) {
  return createServer(async (request, response) => {
    try {
      if (request.url === undefined || Buffer.byteLength(request.url) > MAX_REQUEST_URL_BYTES) {
        jsonResponse(response, 400, "request-invalid");
        return;
      }
      const requestUrl = new URL(request.url, "https://colortrace.invalid");
      if (requestUrl.pathname === "/health/startup" || requestUrl.pathname === "/health/live") {
        response.writeHead(200, responseHeaders("application/json; charset=utf-8"));
        response.end(`${JSON.stringify({ status: "ready" })}\n`);
      } else if (requestUrl.pathname.startsWith("/v1/") || request.method !== "GET") {
        await proxyApi(request, response, requestUrl, configuration);
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
