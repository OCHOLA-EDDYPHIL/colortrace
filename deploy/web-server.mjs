import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_REQUEST_URL_BYTES = 2048;
const MAX_STATIC_FILE_BYTES = 4 * 1024 * 1024;
const PUBLIC_ROOT = fileURLToPath(new URL("./public/", import.meta.url));

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

export function loadConfiguration(environment) {
  const portValue = environment.PORT ?? "8080";
  if (!/^[1-9][0-9]{0,4}$/.test(portValue)) throw new Error("port-invalid");
  const port = Number(portValue);
  if (port > 65535) throw new Error("port-invalid");
  return { port };
}

function responseHeaders(contentType) {
  return {
    "Cache-Control": "no-store",
    "Content-Security-Policy":
      "default-src 'self'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' blob: data:; object-src 'none'; script-src 'self'; style-src 'self'",
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

async function serveStatic(response, pathname, publicRoot) {
  const relative = pathname.startsWith("/assets/") ? normalize(pathname.slice(1)) : "index.html";
  if (relative.startsWith("..") || !/^[A-Za-z0-9._/-]+$/.test(relative)) {
    jsonResponse(response, 404, "asset-not-found");
    return;
  }
  const path = join(publicRoot, relative);
  let information;
  try {
    information = await stat(path);
  } catch {
    jsonResponse(response, 404, "asset-not-found");
    return;
  }
  if (!information.isFile() || information.size > MAX_STATIC_FILE_BYTES) {
    jsonResponse(response, 404, "asset-not-found");
    return;
  }
  response.writeHead(
    200,
    responseHeaders(CONTENT_TYPES.get(extname(path)) ?? "application/octet-stream"),
  );
  createReadStream(path).pipe(response);
}

export function createApplication({ publicRoot = PUBLIC_ROOT } = {}) {
  return createServer(async (request, response) => {
    try {
      if (request.url === undefined || Buffer.byteLength(request.url) > MAX_REQUEST_URL_BYTES) {
        jsonResponse(response, 400, "request-invalid");
        return;
      }
      const requestUrl = new URL(request.url, "https://colortrace.invalid");
      if (request.method !== "GET") {
        jsonResponse(response, 405, "request-not-allowed");
        return;
      }
      if (requestUrl.pathname === "/v1" || requestUrl.pathname.startsWith("/v1/")) {
        jsonResponse(response, 404, "request-not-allowed");
        return;
      }
      await serveStatic(response, requestUrl.pathname, publicRoot);
    } catch {
      jsonResponse(response, 503, "service-unavailable");
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const configuration = loadConfiguration(process.env);
  createApplication().listen(configuration.port, "0.0.0.0");
}
