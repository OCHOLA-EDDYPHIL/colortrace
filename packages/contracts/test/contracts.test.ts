import { describe, expect, it } from "vitest";

import syntheticFixture from "../fixtures/synthetic-operation.openapi.json";
import canonicalContract from "../openapi.json";

describe("canonical API contract", () => {
  it("is OpenAPI 3.1 and contains no product operations", () => {
    expect(canonicalContract.openapi).toMatch(/^3\.1\./u);
    expect(canonicalContract.paths).toEqual({});
  });
});

describe("generation fixture", () => {
  it("contains exactly one explicitly synthetic operation", () => {
    expect(syntheticFixture.openapi).toMatch(/^3\.1\./u);
    expect(Object.keys(syntheticFixture.paths)).toEqual(["/synthetic/{fixtureId}"]);
    expect(syntheticFixture.paths["/synthetic/{fixtureId}"].get.operationId).toBe(
      "getSyntheticOperation",
    );
  });
});
