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
    const packet = canonicalContract.components.schemas.ResponsePacket.properties;
    expect(packet.deterministic_results.items.$ref).toBe(
      "#/components/schemas/DeterministicResult",
    );
    expect(packet.invocation_records.items.$ref).toBe("#/components/schemas/ModelInvocation");
    expect(packet.unresolved_items.items.$ref).toBe("#/components/schemas/UnresolvedItem");
    expect(packet.candidate_plan.oneOf[1]?.$ref).toBe("#/components/schemas/CandidatePlan");
    expect(packet.model_advisory.oneOf[1]?.$ref).toBe("#/components/schemas/ModelAdvisory");
    expect(packet.no_action_reason.oneOf[1]?.enum).toEqual([
      "budget-exhausted",
      "contradictory-evidence",
      "evidence-unavailable",
      "incomplete-evidence",
      "invalid-intake",
      "model-unavailable",
      "no-affected-targets",
      "policy-drift",
      "stale-evidence",
      "validator-unresolved",
    ]);

    const replay = canonicalContract.components.schemas.IncidentReplay.properties;
    expect(replay.evidence.items.$ref).toBe("#/components/schemas/EvidenceEnvelope");
    expect(replay.evidence_batches.items.$ref).toBe("#/components/schemas/EvidenceBatch");
    expect(replay.validator_results.items.$ref).toBe("#/components/schemas/ValidatorResult");
    expect(replay.invocations.items.$ref).toBe("#/components/schemas/ModelInvocation");
    expect(canonicalContract.components.schemas.TraceEvent.properties.event_type.enum).toEqual([
      "api.intake.accepted",
      "task.queued",
      "worker.started",
      "packet.persisted",
      "incident.completed",
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
