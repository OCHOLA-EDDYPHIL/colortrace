import assert from "node:assert/strict";
import test from "node:test";

import { isPublicApiRequest, loadConfiguration } from "./web-server.mjs";

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
