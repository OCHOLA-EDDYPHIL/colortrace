import { describe, expect, it } from "vitest";

import syntheticFixture from "../fixtures/synthetic-operation.openapi.json";
import canonicalContract from "../openapi.json";

describe("canonical API contract", () => {
  it("exposes only alert intake, incident read, and provenance replay", () => {
    expect(canonicalContract.openapi).toMatch(/^3\.1\./u);
    expect(Object.keys(canonicalContract.paths).sort()).toEqual([
      "/v1/incidents",
      "/v1/incidents/{incidentId}",
      "/v1/incidents/{incidentId}/replay",
    ]);
    expect(canonicalContract.paths["/v1/incidents"].post.operationId).toBe("createIncident");
    expect(canonicalContract.paths["/v1/incidents/{incidentId}"].get.operationId).toBe(
      "getIncident",
    );
    expect(canonicalContract.paths["/v1/incidents/{incidentId}/replay"].get.operationId).toBe(
      "replayIncident",
    );
    expect(canonicalContract.components.schemas.ResponsePacket.properties.status.enum).toEqual([
      "resolved",
      "unresolved",
    ]);
    expect(canonicalContract.components.schemas.Claim.properties.state.enum).toEqual([
      "confirmed",
      "inferred",
      "rejected",
      "unresolved",
    ]);
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
