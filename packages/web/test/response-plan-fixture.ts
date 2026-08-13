import type {
  ResponsePlan,
  ResponsePlanDecision,
  ResponsePlanReview,
  SimulatorActionEnvelope,
  SimulatorTarget,
} from "@colortrace/api-client";

const digest = (character: string) => `sha256:${character.repeat(64)}`;

export const RESPONSE_PLAN_HASH = digest("a");
export const RESPONSE_PLAN_INCIDENT_ID = "incident-response-plan-review";

function actionEnvelope(): SimulatorActionEnvelope {
  return {
    schema: "simulator-action-envelope/v1",
    fixture_id: "ct-shadowed-lut-v1",
    fixture_manifest_sha256: digest("0"),
    fixture_generation: 4,
    source_batch_id: "fixture-run-response-plan",
    source_batch_sha256: digest("1"),
    runtime_manifest_sha256: digest("2"),
    runtime_generation: 4,
    expected_publication_pointer_sha256: digest("3"),
    expected_publication_generation: 4,
    expected_resource_sha256: digest("4"),
    replacement_resource_logical_path: "luts/show_look.cube",
    replacement_resource_sha256: digest("5"),
    declared_resource_manifest_sha256: digest("6"),
    ocio_version: "2.5.2",
    preservation_manifest_sha256: digest("7"),
    safe_complement_sha256: digest("8"),
    lineage_manifest_sha256: digest("9"),
    lineage_generation: 4,
  };
}

function plan(commandId: string, incidentId: string): ResponsePlan {
  const resource = {
    schema: "simulator-target/v1",
    namespace: "colortrace-simulator",
    kind: "color-resource",
    id: digest("4"),
  } satisfies SimulatorTarget;
  const frame = {
    schema: "simulator-target/v1",
    namespace: "colortrace-simulator",
    kind: "frame",
    id: "frame-affected-0001",
  } satisfies SimulatorTarget;
  const derivative = {
    schema: "simulator-target/v1",
    namespace: "colortrace-simulator",
    kind: "derivative",
    id: "derivative-affected-0001",
  } satisfies SimulatorTarget;
  const targets = [resource, frame, derivative];
  const exclusions: SimulatorTarget[] = [
    {
      schema: "simulator-target/v1",
      namespace: "colortrace-simulator",
      kind: "frame",
      id: "frame-safe-0002",
    },
  ];
  const envelope = actionEnvelope();
  return {
    schema: "response-plan/v1",
    plan_id: `response-plan:${"b".repeat(64)}`,
    incident_id: incidentId,
    incident_version: 7,
    version: 1,
    previous_plan_sha256: null,
    response_packet_id: `response-packet:${"c".repeat(64)}`,
    response_packet_sha256: digest("c"),
    deterministic_scope_sha256: digest("d"),
    targets,
    exclusions,
    commands: [
      {
        schema: "simulator-quarantine-command/v1",
        command_id: commandId,
        namespace: "colortrace-simulator",
        target: resource,
        action_envelope: envelope,
        expected_resource_sha256: envelope.expected_resource_sha256,
        mode: "quarantine-and-install-approved-replacement",
      },
      {
        schema: "simulator-targeted-rerender-command/v1",
        command_id: "rerender-frame-affected-0001",
        namespace: "colortrace-simulator",
        target: frame,
        action_envelope: envelope,
        job_id: "frame-job-0001",
        transform_id: "look/main/v1",
        source_id: "source-image-0001",
        source_manifest_sha256: digest("e"),
        source_png_sha256: digest("f"),
        expected_config_sha256: digest("1"),
        expected_output_sha256: digest("2"),
        expected_display_sha256: digest("3"),
        lineage_parent_artifact_id: "source-image-0001",
      },
      {
        schema: "simulator-targeted-rerender-command/v1",
        command_id: "rerender-derivative-affected-0001",
        namespace: "colortrace-simulator",
        target: derivative,
        action_envelope: envelope,
        job_id: "derivative-job-0001",
        transform_id: "look/main/v1",
        source_id: "source-image-0001",
        source_manifest_sha256: digest("e"),
        source_png_sha256: digest("f"),
        expected_config_sha256: digest("1"),
        expected_derivative_sha256: digest("6"),
        expected_derivative_display_sha256: digest("7"),
        lineage_parent_artifact_id: "frame-affected-0001",
      },
    ],
    unresolved_item_ids: [],
    blocking_unresolved_item_ids: [],
    unknown_target_ids: [],
    unresolved_acknowledged: false,
    created_by: {
      issuer: "https://identity.example.test/tenant",
      subject: "editor@example.test",
      audience: "colortrace-api",
      kind: "human",
    },
    created_at: "2026-08-13T18:00:00.000Z",
    plan_sha256: RESPONSE_PLAN_HASH,
  };
}

function decision(
  selectedPlan: ResponsePlan,
  outcome: "approved" | "rejected",
): ResponsePlanDecision {
  return {
    schema: "response-plan-decision/v1",
    decision_id: `response-plan-decision:${"e".repeat(64)}`,
    outcome,
    incident_id: selectedPlan.incident_id,
    incident_version: selectedPlan.incident_version,
    plan_id: selectedPlan.plan_id,
    plan_version: selectedPlan.version,
    plan_sha256: selectedPlan.plan_sha256,
    response_packet_id: selectedPlan.response_packet_id,
    response_packet_sha256: selectedPlan.response_packet_sha256,
    deterministic_scope_sha256: selectedPlan.deterministic_scope_sha256,
    targets: selectedPlan.targets,
    exclusions: selectedPlan.exclusions,
    commands: selectedPlan.commands,
    targets_sha256: digest("1"),
    exclusions_sha256: digest("2"),
    commands_sha256: digest("3"),
    unresolved_item_ids: selectedPlan.unresolved_item_ids,
    blocking_unresolved_item_ids: selectedPlan.blocking_unresolved_item_ids,
    unknown_target_ids: selectedPlan.unknown_target_ids,
    unresolved_acknowledged: selectedPlan.unresolved_acknowledged,
    reason_code: outcome === "rejected" ? "unsafe-scope" : null,
    actor: {
      issuer: "https://identity.example.test/tenant",
      subject: "approver@example.test",
      audience: "colortrace-api",
      kind: "human",
    },
    idempotency_key: `${outcome}-response-plan-v1`,
    decided_at: "2026-08-13T18:05:00.000Z",
    decision_sha256: digest("e"),
  };
}

export function responsePlanReviewFixture(
  options: {
    readonly blockingUnresolvedItemIds?: readonly string[];
    readonly commandId?: string;
    readonly currentIncidentVersion?: number;
    readonly incidentId?: string;
    readonly state?: ResponsePlanReview["state"];
    readonly unknownTargetIds?: readonly string[];
    readonly unresolvedAcknowledged?: boolean;
    readonly unresolvedItemIds?: readonly string[];
  } = {},
): ResponsePlanReview {
  const basePlan = plan(
    options.commandId ?? "quarantine-shadowed-lut",
    options.incidentId ?? RESPONSE_PLAN_INCIDENT_ID,
  );
  const selectedPlan: ResponsePlan = {
    ...basePlan,
    blocking_unresolved_item_ids: [...(options.blockingUnresolvedItemIds ?? [])],
    unknown_target_ids: [...(options.unknownTargetIds ?? [])],
    unresolved_acknowledged: options.unresolvedAcknowledged ?? basePlan.unresolved_acknowledged,
    unresolved_item_ids: [...(options.unresolvedItemIds ?? [])],
  };
  const state = options.state ?? "pending";
  const selectedDecision =
    state === "approved" || state === "rejected" ? decision(selectedPlan, state) : null;
  return {
    schema: "response-plan-review/v1",
    state,
    current_incident_version: options.currentIncidentVersion ?? selectedPlan.incident_version,
    plan: selectedPlan,
    decision: selectedDecision,
    audit_events: [
      {
        schema: "response-plan-audit-event/v1",
        event_id: `response-plan-audit-event:${"f".repeat(64)}`,
        sequence: 1,
        event_type: "plan.created",
        incident_id: selectedPlan.incident_id,
        plan_id: selectedPlan.plan_id,
        plan_version: selectedPlan.version,
        plan_sha256: selectedPlan.plan_sha256,
        record_sha256: selectedPlan.plan_sha256,
        actor: selectedPlan.created_by,
        idempotency_key: "create-response-plan-v1",
        predecessor_event_sha256: null,
        occurred_at: selectedPlan.created_at,
        event_sha256: digest("f"),
      },
    ],
  };
}
