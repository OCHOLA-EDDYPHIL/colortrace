import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createApplication, loadConfiguration } from "./web-server.mjs";

const INDEX = "<!doctype html><title>ColorTrace</title><main>Shot-Safe Color Recovery</main>";
const JAVASCRIPT = 'document.documentElement.dataset.app = "colortrace";\n';

function assertSecurityHeaders(response, contentType) {
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("content-type"), contentType);
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow, noarchive");
  assert.equal(
    response.headers.get("content-security-policy"),
    "default-src 'self'; base-uri 'none'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; img-src 'self' blob: data:; object-src 'none'; script-src 'self'; style-src 'self'",
  );
}

async function withApplication(run) {
  const publicRoot = await mkdtemp(join(tmpdir(), "colortrace-web-"));
  await mkdir(join(publicRoot, "assets"));
  await writeFile(join(publicRoot, "index.html"), INDEX, "utf8");
  await writeFile(join(publicRoot, "assets", "app.js"), JAVASCRIPT, "utf8");
  const server = createApplication({ publicRoot });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.notEqual(address, null);
    assert.equal(typeof address, "object");
    if (address === null || typeof address === "string") throw new Error("listener-invalid");
    await run({ origin: `http://127.0.0.1:${address.port}`, publicRoot });
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error === undefined ? resolve() : reject(error)));
      server.closeIdleConnections?.();
    });
    await rm(publicRoot, { force: true, recursive: true });
  }
}

test("configuration accepts only a valid listening port", () => {
  assert.deepEqual(loadConfiguration({}), { port: 8080 });
  assert.deepEqual(loadConfiguration({ PORT: "1" }), { port: 1 });
  assert.deepEqual(loadConfiguration({ PORT: "65535" }), { port: 65535 });

  for (const port of ["", "0", "0001", "65536", "-1", "8080 ", "not-a-port"]) {
    assert.throws(() => loadConfiguration({ PORT: port }), /port-invalid/);
  }
});

test("the SPA and its assets are served with restrictive headers", async () => {
  await withApplication(async ({ origin }) => {
    for (const path of ["/", "/workspace", "/v10/not-an-api-route"]) {
      const response = await fetch(`${origin}${path}`);
      assert.equal(response.status, 200, path);
      assertSecurityHeaders(response, "text/html; charset=utf-8");
      assert.equal(await response.text(), INDEX);
    }

    const asset = await fetch(`${origin}/assets/app.js`);
    assert.equal(asset.status, 200);
    assertSecurityHeaders(asset, "text/javascript; charset=utf-8");
    assert.equal(await asset.text(), JAVASCRIPT);
  });
});

test("missing, invalid, and oversized assets are rejected", async () => {
  await withApplication(async ({ origin, publicRoot }) => {
    await writeFile(join(publicRoot, "assets", "oversized.bin"), Buffer.alloc(4 * 1024 * 1024 + 1));

    for (const path of [
      "/assets/missing.js",
      "/assets/app%20name.js",
      "/assets/%2e%2e%2fsecret.txt",
      "/assets/oversized.bin",
    ]) {
      const response = await fetch(`${origin}${path}`);
      assert.equal(response.status, 404, path);
      assertSecurityHeaders(response, "application/json; charset=utf-8");
      assert.deepEqual(await response.json(), { code: "asset-not-found" });
    }
  });
});

test("oversized request targets are rejected", async () => {
  await withApplication(async ({ origin }) => {
    const response = await fetch(`${origin}/assets/${"a".repeat(2050)}`);
    assert.equal(response.status, 400);
    assertSecurityHeaders(response, "application/json; charset=utf-8");
    assert.deepEqual(await response.json(), { code: "request-invalid" });
  });
});

test("all non-GET requests are rejected", async () => {
  await withApplication(async ({ origin }) => {
    for (const [method, path] of [
      ["POST", "/"],
      ["PUT", "/assets/app.js"],
      ["DELETE", "/v1/demo/runs/example"],
      ["OPTIONS", "/workspace"],
    ]) {
      const response = await fetch(`${origin}${path}`, { method });
      assert.equal(response.status, 405, `${method} ${path}`);
      assertSecurityHeaders(response, "application/json; charset=utf-8");
      assert.deepEqual(await response.json(), { code: "request-not-allowed" });
    }
  });
});

test("direct API-shaped GET requests are rejected", async () => {
  await withApplication(async ({ origin }) => {
    for (const path of [
      "/v1",
      "/v1/",
      "/v1/session",
      "/v1/incidents",
      "/v1/demo",
      "/v1/demo/runs/example?view=full",
    ]) {
      const response = await fetch(`${origin}${path}`);
      assert.equal(response.status, 404, path);
      assertSecurityHeaders(response, "application/json; charset=utf-8");
      assert.deepEqual(await response.json(), { code: "request-not-allowed" });
    }
  });
});
