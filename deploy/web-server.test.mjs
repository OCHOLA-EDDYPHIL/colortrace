import assert from "node:assert/strict";
import test from "node:test";

import { createApplication, isPublicApiRequest, loadConfiguration } from "./web-server.mjs";

const API_ORIGIN = "https://api.example.run.app";
const CONFIGURATION = {
  port: 0,
  apiOrigin: API_ORIGIN,
  apiAudience: API_ORIGIN,
};
const IDENTITY_TOKEN = `header.${"a".repeat(128)}.signature`;
const METADATA_URL =
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity" +
  "?audience=https%3A%2F%2Fapi.example.run.app&format=full";

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json; charset=utf-8" },
    status,
  });
}

function headersOf(options) {
  return Object.fromEntries(new Headers(options.headers).entries());
}

async function withApplication(fetchImplementation, run) {
  const server = createApplication(CONFIGURATION, { fetch: fetchImplementation });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    const address = server.address();
    assert.notEqual(address, null);
    assert.equal(typeof address, "object");
    if (address === null || typeof address === "string") throw new Error("listener-invalid");
    await run(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve, reject) => {
      server.close((error) => (error === undefined ? resolve() : reject(error)));
      server.closeIdleConnections?.();
    });
  }
}

test("only the four UI read projections and their bounded queries are public", () => {
  const encodedIdentifier = encodeURIComponent("source:folder/item.v1");
  assert.equal(isPublicApiRequest("GET", "/v1/incidents"), true);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents?limit=50&cursor=next%2Fpage"), true);
  assert.equal(isPublicApiRequest("GET", `/v1/incidents/${encodedIdentifier}/workspace`), true);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/response-plan"), true);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/recovery"), true);

  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/replay"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/response-plan/draft"), false);
  assert.equal(isPublicApiRequest("POST", "/v1/incidents"), false);
  assert.equal(isPublicApiRequest("GET", "/internal/v1/incidents/example"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/session"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents?sort=created_at"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents?limit=10&limit=20"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/workspace?limit=1"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example/../session"), false);
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example%2F..%2Fsession/workspace"), false);
  assert.equal(
    isPublicApiRequest("GET", "/v1/incidents/example%2F%2E%2E%2Fsession/workspace"),
    false,
  );
  assert.equal(isPublicApiRequest("GET", "/v1/incidents/example%ZZ/workspace"), false);
});

test("configuration binds one exact private API origin", () => {
  assert.deepEqual(
    loadConfiguration({
      PORT: "8080",
      COLORTRACE_API_ORIGIN: API_ORIGIN,
      COLORTRACE_API_AUDIENCE: API_ORIGIN,
    }),
    {
      port: 8080,
      apiOrigin: API_ORIGIN,
      apiAudience: API_ORIGIN,
    },
  );
  assert.throws(
    () =>
      loadConfiguration({
        COLORTRACE_API_ORIGIN: `${API_ORIGIN}/path`,
        COLORTRACE_API_AUDIENCE: `${API_ORIGIN}/path`,
      }),
    /api-boundary-invalid/,
  );
  assert.throws(
    () =>
      loadConfiguration({
        COLORTRACE_API_ORIGIN: API_ORIGIN,
        COLORTRACE_API_AUDIENCE: "https://other.example.run.app",
      }),
    /api-boundary-invalid/,
  );
});

test("credential-free public sessions fail closed without any network fetch", async () => {
  let fetches = 0;
  await withApplication(
    () => {
      fetches += 1;
      throw new Error("unexpected-network-fetch");
    },
    async (origin) => {
      const response = await fetch(`${origin}/v1/session`, {
        headers: {
          Authorization: "Bearer browser-token",
          Cookie: "colortrace_session=browser-session",
        },
      });
      assert.equal(response.status, 401);
      assert.deepEqual(await response.json(), { code: "authentication-required" });
    },
  );
  assert.equal(fetches, 0);
});

test("the BFF uses the exact audience and target while replacing browser credentials", async () => {
  const calls = [];
  const fetchImplementation = async (input, options = {}) => {
    const url = new URL(input);
    calls.push({ headers: headersOf(options), options, url: url.toString() });
    if (url.hostname === "metadata.google.internal") return new Response(IDENTITY_TOKEN);
    return jsonResponse({ target: `${url.pathname}${url.search}` });
  };

  await withApplication(fetchImplementation, async (origin) => {
    const browserHeaders = {
      Authorization: "Bearer browser-token",
      Cookie: "colortrace_session=browser-session",
      "X-Browser-Only": "do-not-forward",
    };
    const list = await fetch(`${origin}/v1/incidents?limit=10&cursor=next%2Fpage`, {
      headers: browserHeaders,
    });
    assert.equal(list.status, 200);
    assert.equal(list.headers.get("x-robots-tag"), "noindex, nofollow, noarchive");
    assert.deepEqual(await list.json(), {
      target: "/v1/incidents?limit=10&cursor=next%2Fpage",
    });

    const identifier = "source:folder/item.v1";
    const workspace = await fetch(
      `${origin}/v1/incidents/${encodeURIComponent(identifier)}/workspace`,
      { headers: browserHeaders },
    );
    assert.equal(workspace.status, 200);
    assert.deepEqual(await workspace.json(), {
      target: "/v1/incidents/source%3Afolder%2Fitem.v1/workspace",
    });
  });

  assert.equal(calls.length, 4);
  for (const call of [calls[0], calls[2]]) {
    assert.equal(call.url, METADATA_URL);
    assert.equal(call.options.redirect, "error");
    assert.deepEqual(call.headers, { "metadata-flavor": "Google" });
  }
  assert.equal(calls[1].url, `${API_ORIGIN}/v1/incidents?limit=10&cursor=next%2Fpage`);
  assert.equal(calls[3].url, `${API_ORIGIN}/v1/incidents/source%3Afolder%2Fitem.v1/workspace`);
  for (const call of [calls[1], calls[3]]) {
    assert.equal(call.options.method, "GET");
    assert.equal(call.options.redirect, "error");
    assert.deepEqual(call.headers, {
      accept: "application/json",
      authorization: `Bearer ${IDENTITY_TOKEN}`,
    });
  }
});

test("blocked routes, queries, and methods never reach metadata or the API", async () => {
  let fetches = 0;
  const blocked = [
    ["GET", "/v1/incidents/example", 404],
    ["GET", "/v1/incidents/example/replay", 404],
    ["GET", "/v1/incidents/example/response-plan/draft", 404],
    ["GET", "/v1/incidents?sort=created_at", 404],
    ["GET", "/v1/incidents?limit=10&limit=20", 404],
    ["GET", "/v1/incidents/example/workspace?cursor=next", 404],
    ["GET", "/v1/incidents/example%2F..%2Fsession/workspace", 404],
    ["POST", "/v1/incidents", 405],
    ["PUT", "/v1/incidents/example/response-plan", 405],
    ["POST", "/health/startup", 405],
    ["PUT", "/health/live", 405],
  ];
  await withApplication(
    () => {
      fetches += 1;
      throw new Error("unexpected-network-fetch");
    },
    async (origin) => {
      for (const [method, path, expectedStatus] of blocked) {
        const response = await fetch(`${origin}${path}`, { method });
        assert.equal(response.status, expectedStatus, `${method} ${path}`);
        assert.deepEqual(await response.json(), { code: "request-not-allowed" });
      }
    },
  );
  assert.equal(fetches, 0);
});

test("health-looking paths are not public diagnostic endpoints", async () => {
  let fetches = 0;
  await withApplication(
    () => {
      fetches += 1;
      throw new Error("unexpected-network-fetch");
    },
    async (origin) => {
      for (const path of ["/health/startup", "/health/live"]) {
        const response = await fetch(`${origin}${path}`);
        assert.equal(response.status, 404);
        assert.deepEqual(await response.json(), { code: "asset-not-found" });
      }
    },
  );
  assert.equal(fetches, 0);
});

test("invalid upstream media, oversized streams, and redirects fail closed", async (context) => {
  await context.test("non-JSON media type", async () => {
    await withApplication(
      async (input) => {
        const url = new URL(input);
        if (url.hostname === "metadata.google.internal") return new Response(IDENTITY_TOKEN);
        return new Response("not-json", { headers: { "Content-Type": "text/plain" } });
      },
      async (origin) => {
        const response = await fetch(`${origin}/v1/incidents`);
        assert.equal(response.status, 503);
        assert.deepEqual(await response.json(), { code: "service-unavailable" });
      },
    );
  });

  await context.test("more than four MiB", async () => {
    let cancelled = false;
    let pulls = 0;
    await withApplication(
      async (input) => {
        const url = new URL(input);
        if (url.hostname === "metadata.google.internal") return new Response(IDENTITY_TOKEN);
        const body = new ReadableStream({
          cancel() {
            cancelled = true;
          },
          pull(controller) {
            pulls += 1;
            controller.enqueue(new Uint8Array(1024 * 1024));
            if (pulls === 100) controller.close();
          },
        });
        return new Response(body, { headers: { "Content-Type": "application/json" } });
      },
      async (origin) => {
        const response = await fetch(`${origin}/v1/incidents`);
        assert.equal(response.status, 503);
        assert.deepEqual(await response.json(), { code: "service-unavailable" });
      },
    );
    assert.equal(cancelled, true);
    assert.ok(pulls < 100);
  });

  await context.test("upstream redirect", async () => {
    const redirects = [];
    await withApplication(
      async (input, options = {}) => {
        const url = new URL(input);
        if (url.hostname === "metadata.google.internal") return new Response(IDENTITY_TOKEN);
        redirects.push(options.redirect);
        if (options.redirect === "error") throw new TypeError("redirect-not-allowed");
        return jsonResponse({ followed: true });
      },
      async (origin) => {
        const response = await fetch(`${origin}/v1/incidents`);
        assert.equal(response.status, 503);
        assert.deepEqual(await response.json(), { code: "service-unavailable" });
      },
    );
    assert.deepEqual(redirects, ["error"]);
  });
});
