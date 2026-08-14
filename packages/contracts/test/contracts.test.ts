import { describe, expect, it } from "vitest";

import syntheticFixture from "../fixtures/synthetic-operation.openapi.json";
import canonicalContract from "../openapi.json";

describe("canonical API contract", () => {
  it("exposes incident intake, workspace reads, and authenticated session projection", () => {
    expect(canonicalContract.openapi).toMatch(/^3\.1\./u);
    expect(Object.keys(canonicalContract.paths).sort()).toEqual([
      "/internal/v1/incidents/{incidentId}/recovery/verifications",
      "/internal/v1/incidents/{incidentId}/simulator-actions",
      "/private/v1/recovery-verification-tasks/{taskKey}",
      "/v1/incidents",
      "/v1/incidents/{incidentId}",
      "/v1/incidents/{incidentId}/recovery",
      "/v1/incidents/{incidentId}/recovery/close",
      "/v1/incidents/{incidentId}/replay",
      "/v1/incidents/{incidentId}/response-plan",
      "/v1/incidents/{incidentId}/response-plan/approve",
      "/v1/incidents/{incidentId}/response-plan/dispatch-authorizations",
      "/v1/incidents/{incidentId}/response-plan/dispatch-consumptions",
      "/v1/incidents/{incidentId}/response-plan/draft",
      "/v1/incidents/{incidentId}/response-plan/reject",
      "/v1/incidents/{incidentId}/workspace",
      "/v1/session",
    ]);
    expect(
      canonicalContract.paths["/internal/v1/incidents/{incidentId}/recovery/verifications"].post
        .operationId,
    ).toBe("admitRecoveryVerification");
    expect(
      canonicalContract.paths["/private/v1/recovery-verification-tasks/{taskKey}"].post.operationId,
    ).toBe("executeRecoveryVerificationTask");
    expect(
      canonicalContract.paths["/internal/v1/incidents/{incidentId}/simulator-actions"].post
        .operationId,
    ).toBe("admitSimulatorAction");
    expect(canonicalContract.paths["/v1/incidents"].get.operationId).toBe("listIncidents");
    expect(canonicalContract.paths["/v1/incidents"].post.operationId).toBe("createIncident");
    expect(canonicalContract.paths["/v1/incidents/{incidentId}"].get.operationId).toBe(
      "getIncident",
    );
    expect(canonicalContract.paths["/v1/incidents/{incidentId}/replay"].get.operationId).toBe(
      "replayIncident",
    );
    expect(canonicalContract.paths["/v1/incidents/{incidentId}/recovery"].get.operationId).toBe(
      "getRecoveryReview",
    );
    expect(
      canonicalContract.paths["/v1/incidents/{incidentId}/recovery/close"].post.operationId,
    ).toBe("closeRecovery");
    expect(canonicalContract.paths["/v1/incidents/{incidentId}/workspace"].get.operationId).toBe(
      "getIncidentWorkspace",
    );
    expect(
      canonicalContract.paths["/v1/incidents/{incidentId}/response-plan"].get.operationId,
    ).toBe("getResponsePlanReview");
    expect(
      canonicalContract.paths["/v1/incidents/{incidentId}/response-plan"].post.operationId,
    ).toBe("createResponsePlan");
    expect(
      canonicalContract.paths["/v1/incidents/{incidentId}/response-plan"].put.operationId,
    ).toBe("editResponsePlan");
    expect(canonicalContract.paths["/v1/session"].get.operationId).toBe("getOperatorSession");
    expect(canonicalContract.components.securitySchemes.operatorOidc.scheme).toBe("bearer");
    const session = canonicalContract.components.schemas.OperatorSession;
    expect(session.properties.subject.$ref).toBe("#/components/schemas/OidcSubject");
    expect(session.required).toContain("principal_kind");
    expect(session.properties.principal_kind.enum).toEqual(["human", "service"]);
    const workspace = canonicalContract.components.schemas.IncidentWorkspaceSource;
    expect(workspace.required).toContain("human_events");
    expect(workspace.properties.human_events.items.$ref).toBe(
      "#/components/schemas/HumanAuditEvent",
    );
    expect(canonicalContract.components.schemas.HumanAuditEvent.additionalProperties).toBe(false);
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

  it("keeps typed response-plan requests bounded and command targets discriminated", () => {
    const schemas = canonicalContract.components.schemas;
    expect(schemas.SimulatorQuarantineCommand.properties.target.allOf[1]).toMatchObject({
      properties: { kind: { const: "color-resource" } },
    });
    expect(schemas.SimulatorFrameRerenderCommand.properties.target.allOf[1]).toMatchObject({
      properties: { kind: { const: "frame" } },
    });
    expect(schemas.SimulatorDerivativeRerenderCommand.properties.target.allOf[1]).toMatchObject({
      properties: { kind: { const: "derivative" } },
    });
    for (const request of [schemas.CreateResponsePlanRequest, schemas.EditResponsePlanRequest]) {
      expect(request.additionalProperties).toBe(false);
      expect(request.properties.targets.maxItems).toBe(64);
      expect(request.properties.exclusions.maxItems).toBe(64);
      expect(request.properties.commands.maxItems).toBe(64);
    }
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
