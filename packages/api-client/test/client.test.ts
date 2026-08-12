import { describe, expect, it } from "vitest";

import { createClient, getSyntheticOperation } from "../src/index";

describe("generated fetch client", () => {
  it("serializes the synthetic path and query parameters", async () => {
    const requests: Request[] = [];
    const fetchFixture: typeof fetch = async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      requests.push(request);

      return new Response(JSON.stringify({ fixtureId: "fixture 1", status: "ok" }), {
        headers: { "Content-Type": "application/json" },
        status: 200,
      });
    };
    const generatedClient = createClient({
      baseUrl: "https://example.invalid",
      fetch: fetchFixture,
    });

    const response = await getSyntheticOperation(
      { fixtureId: "fixture 1", includeMetadata: true },
      { client: generatedClient, throwOnError: true },
    );

    expect(response).toEqual({ fixtureId: "fixture 1", status: "ok" });
    expect(requests).toHaveLength(1);
    expect(requests[0]?.method).toBe("GET");
    expect(requests[0]?.url).toBe(
      "https://example.invalid/synthetic/fixture%201?includeMetadata=true",
    );
  });

  it("surfaces synthetic error responses when configured to throw", async () => {
    const generatedClient = createClient({
      baseUrl: "https://example.invalid",
      fetch: async () =>
        new Response(JSON.stringify({ message: "missing" }), {
          headers: { "Content-Type": "application/json" },
          status: 404,
        }),
    });

    await expect(
      getSyntheticOperation(
        { fixtureId: "missing" },
        { client: generatedClient, throwOnError: true },
      ),
    ).rejects.toEqual({ message: "missing" });
  });
});
