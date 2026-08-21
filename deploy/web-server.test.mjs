import assert from "node:assert/strict";
import test from "node:test";

import { createApplication, isPublicApiRequest, loadConfiguration } from "./web-server.mjs";

test("only bounded read paths are public", () => {
  assert.equal(isPublicApiRequest("GET", "/v1/incidents"), true);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/workspace"), true);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/response-plan/draft"), true);
  assert.equal(isPublicApiRequest("POST", "/v1/incidents"), false);
  assert.equal(isPublicApiRequest("GET", "/internal/v1/incidents/example"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/session"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/../session"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example%2F..%2Fsession"), false);
});

test("configuration binds one exact private API origin", () => {
  assert.deepEqual(
    loadConfiguration({
      PORT: "8080",
      COLORTRACE_API_ORIGIN: "https://api.example.run.app",
      COLORTRACE_API_AUDIENCE: "https://api.example.run.app",
    }),
    {
      port: 8080,
      apiOrigin: "https://api.example.run.app",
      apiAudience: "https://api.example.run.app",
    },
  );
  assert.throws(
    () =>
      loadConfiguration({
        COLORTRACE_API_ORIGIN: "https://api.example.run.app/path",
        COLORTRACE_API_AUDIENCE: "https://api.example.run.app/path",
      }),
    /api-boundary-invalid/,
  );
  assert.throws(
    () =>
      loadConfiguration({
        COLORTRACE_API_ORIGIN: "https://api.example.run.app",
        COLORTRACE_API_AUDIENCE: "https://other.example.run.app",
      }),
    /api-boundary-invalid/,
  );
});

test("credential-free public sessions fail closed without contacting the API", async () => {
  const server = createApplication({
    port: 0,
    apiOrigin: "https://api.example.run.app",
    apiAudience: "https://api.example.run.app",
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.notEqual(address, null);
    assert.equal(typeof address, "object");
    if (address === null || typeof address === "string") throw new Error("listener-invalid");
    const response = await fetch(`http://127.0.0.1:${address.port}/v1/session`);
    assert.equal(response.status, 401);
    assert.deepEqual(await response.json(), { code: "authentication-required" });
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }
});
