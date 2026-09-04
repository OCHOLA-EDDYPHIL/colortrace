import type {
  ReferenceActionIntent,
  ReferencePacketSha256,
  ReferenceResponsePacket,
  ReferenceRunIncidentClass,
} from "./reference-run-contract.ts";

export const REFERENCE_APPROVAL_PHRASE = "APPROVE_COLORTRACE_SIMULATOR_ACTION";
export const REFERENCE_DENIAL_PHRASE = "DENY_COLORTRACE_SIMULATOR_ACTION";

export type ReferenceRecoveryChoice = "approved" | "denied";

export type ReferenceRecoveryDecisionRequest = {
  readonly schema: "reference-recovery-decision-request/v1";
  readonly request_id: string;
  readonly decision: ReferenceRecoveryChoice;
  readonly approval_phrase: typeof REFERENCE_APPROVAL_PHRASE | typeof REFERENCE_DENIAL_PHRASE;
  readonly approval_nonce: string;
  readonly packet_id: string;
  readonly packet_sha256: string;
  readonly expected_state_sha256: string;
  readonly reconciliation_id: string;
  readonly action_intent_id: string;
  readonly action_intent_sha256: string;
};

export type ReferenceRecoveryStateReference = {
  readonly generation: number;
  readonly state_sha256: string;
  readonly protected_state_sha256: string;
};

export type ReferenceRecoveryVerificationField =
  | "effective_resource_sha256"
  | "effective_config_sha256"
  | "config_generation"
  | "derivative_parent_sha256"
  | "derivative_generation";

export type ReferenceRecoveryVerification = {
  readonly schema: "reference-recovery-verification/v1";
  readonly verifier: "deterministic-simulator-state";
  readonly result: "verified";
  readonly scenario_id: ReferenceResponsePacket["scenario_id"];
  readonly incident_class: ReferenceRunIncidentClass;
  readonly action_intent_id: string;
  readonly action_intent_sha256: string;
  readonly reconciliation_id: string;
  readonly before: ReferenceRecoveryStateReference;
  readonly after: ReferenceRecoveryStateReference;
  readonly affected_job_ids: readonly string[];
  readonly affected_expected_field_checks: readonly {
    readonly field: ReferenceRecoveryVerificationField;
    readonly expected_value: string | number;
    readonly matched_job_ids: readonly string[];
  }[];
  readonly checks: {
    readonly generation_advanced_exactly_once: true;
    readonly all_affected_expected_fields_match: true;
    readonly protected_state_unchanged: true;
    readonly receipt_state_bindings_match: true;
  };
  readonly establishes_pixel_output: false;
  readonly establishes_full_population_scope: false;
  readonly production_evidence: false;
  readonly verification_sha256: string;
};

export type ReferenceHumanApproval = {
  readonly schema: "reference-human-approval/v3";
  readonly decision: ReferenceRecoveryChoice;
  readonly approver: {
    readonly audience: "colortrace-simulator";
    readonly kind: "human";
    readonly identity_verified: false;
    readonly identity_assurance: "unverified-public-demo-gesture";
    readonly gesture: "explicit-phrase-and-nonce";
  };
  readonly approval_nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
  readonly action_intent_id: string;
  readonly action_intent_sha256: string;
  readonly reconciliation_id: string;
  readonly scenario_id: ReferenceResponsePacket["scenario_id"];
  readonly incident_class: ReferenceRunIncidentClass;
  readonly command: ReferenceActionIntent["command"];
  readonly affected_job_ids: readonly string[];
  readonly state_generation: number;
  readonly state_sha256: string;
  readonly protected_state_sha256: string;
  readonly approval_id: string;
  readonly approval_sha256: string;
};

export type ReferenceRecoveryReceipt = {
  readonly schema: "reference-recovery-receipt/v3";
  readonly approval_id: string;
  readonly approval_sha256: string;
  readonly action_intent_id: string;
  readonly action_intent_sha256: string;
  readonly reconciliation_id: string;
  readonly scenario_id: ReferenceResponsePacket["scenario_id"];
  readonly incident_class: ReferenceRunIncidentClass;
  readonly command: ReferenceActionIntent["command"];
  readonly before: ReferenceRecoveryStateReference;
  readonly after: ReferenceRecoveryStateReference;
  readonly affected_job_ids: readonly string[];
  readonly protected_job_ids: readonly string[];
  readonly mutations: readonly {
    readonly job_id: string;
    readonly before_job_state_sha256: string;
    readonly after_job_state_sha256: string;
    readonly changed_components: readonly ("frame" | "derivative")[];
  }[];
  readonly protected_state_unchanged: true;
  readonly action_intent_requires_human_approval: true;
  readonly action_intent_authorizes_execution: false;
  readonly verification: ReferenceRecoveryVerification;
  readonly result: "applied";
  readonly receipt_id: string;
  readonly receipt_sha256: string;
};

export type ReferenceRecoveryDecision = {
  readonly schema: "reference-recovery-decision/v1";
  readonly scenario_id: ReferenceResponsePacket["scenario_id"];
  readonly request_id: string;
  readonly run_id: string;
  readonly packet_id: string;
  readonly packet_sha256: string;
  readonly decision: ReferenceRecoveryChoice;
  readonly outcome: "applied" | "denied";
  readonly approval: ReferenceHumanApproval;
  readonly before: ReferenceRecoveryStateReference;
  readonly after: ReferenceRecoveryStateReference;
  readonly protected_state_unchanged: true;
  readonly receipt: ReferenceRecoveryReceipt | null;
  readonly verification: ReferenceRecoveryVerification | null;
  readonly scope: {
    readonly kind: "representative-simulator-state";
    readonly affected_job_count: 1;
    readonly protected_job_count: 1;
    readonly establishes_full_population_scope: false;
  };
  readonly execution_boundary: {
    readonly approval_actor_kind: "human";
    readonly approval_gesture: "explicit-phrase-and-nonce";
    readonly identity_verified: false;
    readonly identity_assurance: "unverified-public-demo-gesture";
    readonly execution_target: "colortrace-simulator";
    readonly simulator_state_changed: boolean;
    readonly production_access_used: false;
    readonly production_state_changed: false;
    readonly production_claim: "none";
  };
  readonly decision_sha256: string;
};

const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/u;
const REQUEST_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/u;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const PACKET_ID = /^response-packet:[0-9a-f]{64}$/u;
const ACTION_INTENT_ID = /^action-intent:[0-9a-f]{64}$/u;
const RECONCILIATION_ID = /^diagnosis-reconciliation:[0-9a-f]{64}$/u;
const APPROVAL_ID = /^reference-approval:[0-9a-f]{64}$/u;
const RECEIPT_ID = /^reference-recovery:[0-9a-f]{64}$/u;

const DECISION_KEYS = new Set([
  "schema",
  "scenario_id",
  "request_id",
  "run_id",
  "packet_id",
  "packet_sha256",
  "decision",
  "outcome",
  "approval",
  "before",
  "after",
  "protected_state_unchanged",
  "receipt",
  "verification",
  "scope",
  "execution_boundary",
  "decision_sha256",
]);
const APPROVAL_KEYS = new Set([
  "schema",
  "decision",
  "approver",
  "approval_nonce",
  "issued_at",
  "expires_at",
  "action_intent_id",
  "action_intent_sha256",
  "reconciliation_id",
  "scenario_id",
  "incident_class",
  "command",
  "affected_job_ids",
  "state_generation",
  "state_sha256",
  "protected_state_sha256",
  "approval_id",
  "approval_sha256",
]);
const RECEIPT_KEYS = new Set([
  "schema",
  "approval_id",
  "approval_sha256",
  "action_intent_id",
  "action_intent_sha256",
  "reconciliation_id",
  "scenario_id",
  "incident_class",
  "command",
  "before",
  "after",
  "affected_job_ids",
  "protected_job_ids",
  "mutations",
  "protected_state_unchanged",
  "action_intent_requires_human_approval",
  "action_intent_authorizes_execution",
  "verification",
  "result",
  "receipt_id",
  "receipt_sha256",
]);
const STATE_KEYS = new Set(["generation", "state_sha256", "protected_state_sha256"]);
const VERIFICATION_KEYS = new Set([
  "schema",
  "verifier",
  "result",
  "scenario_id",
  "incident_class",
  "action_intent_id",
  "action_intent_sha256",
  "reconciliation_id",
  "before",
  "after",
  "affected_job_ids",
  "affected_expected_field_checks",
  "checks",
  "establishes_pixel_output",
  "establishes_full_population_scope",
  "production_evidence",
  "verification_sha256",
]);
const VERIFICATION_FIELD_CHECK_KEYS = new Set(["field", "expected_value", "matched_job_ids"]);
const VERIFICATION_CHECK_KEYS = new Set([
  "generation_advanced_exactly_once",
  "all_affected_expected_fields_match",
  "protected_state_unchanged",
  "receipt_state_bindings_match",
]);

function invalidRecovery(): Error {
  return new Error("reference-recovery-response-invalid");
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function record(value: unknown): Readonly<Record<string, unknown>> {
  if (!isRecord(value)) throw invalidRecovery();
  return value;
}

function exactKeys(value: Readonly<Record<string, unknown>>, keys: ReadonlySet<string>): void {
  const actual = Object.keys(value);
  if (actual.length !== keys.size || actual.some((key) => !keys.has(key))) {
    throw invalidRecovery();
  }
}

function stringValue(value: unknown, pattern: RegExp = IDENTIFIER): string {
  if (typeof value !== "string" || !pattern.test(value)) throw invalidRecovery();
  return value;
}

function integerValue(value: unknown, minimum = 0): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) throw invalidRecovery();
  return value as number;
}

function stringArray(
  value: unknown,
  pattern: RegExp,
  minimum: number,
  maximum: number,
): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > maximum ||
    value.some((item) => typeof item !== "string" || !pattern.test(item)) ||
    new Set(value).size !== value.length
  ) {
    throw invalidRecovery();
  }
  return value as readonly string[];
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  throw invalidRecovery();
}

function utf8(value: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(value);
  return encoded.buffer.slice(
    encoded.byteOffset,
    encoded.byteOffset + encoded.byteLength,
  ) as ArrayBuffer;
}

function withoutKeys(
  value: Readonly<Record<string, unknown>>,
  keys: ReadonlySet<string>,
): Readonly<Record<string, unknown>> {
  return Object.fromEntries(Object.entries(value).filter(([key]) => !keys.has(key)));
}

async function verifyDerived(
  value: Readonly<Record<string, unknown>>,
  digestKey: string,
  excludedKeys: ReadonlySet<string>,
  sha256: ReferencePacketSha256,
): Promise<string> {
  const declared = stringValue(value[digestKey], DIGEST);
  const actual = await sha256(utf8(canonicalJson(withoutKeys(value, excludedKeys))));
  if (!DIGEST.test(actual) || actual !== declared) throw invalidRecovery();
  return declared;
}

function assertIdentityDigest(identifier: string, digest: string, prefix: string): void {
  if (identifier !== `${prefix}:${digest.slice("sha256:".length)}`) throw invalidRecovery();
}

function sameDocument(left: unknown, right: unknown): boolean {
  return canonicalJson(left) === canonicalJson(right);
}

function parseState(value: unknown): ReferenceRecoveryStateReference {
  const source = record(value);
  exactKeys(source, STATE_KEYS);
  return {
    generation: integerValue(source.generation, 1),
    state_sha256: stringValue(source.state_sha256, DIGEST),
    protected_state_sha256: stringValue(source.protected_state_sha256, DIGEST),
  };
}

function expectedChangedComponents(
  incidentClass: ReferenceRunIncidentClass,
): readonly ("frame" | "derivative")[] {
  return incidentClass === "stale-derivative-cache/v1" ? ["derivative"] : ["frame", "derivative"];
}

const EXPECTED_VERIFICATION_FIELDS: Readonly<
  Record<ReferenceRunIncidentClass, readonly ReferenceRecoveryVerificationField[]>
> = {
  "resource-resolution-drift/v1": ["effective_resource_sha256"],
  "configuration-rollout-drift/v1": ["config_generation", "effective_config_sha256"],
  "stale-derivative-cache/v1": ["derivative_generation", "derivative_parent_sha256"],
};

export function createReferenceRecoveryDecisionRequest(
  packet: ReferenceResponsePacket,
  decision: ReferenceRecoveryChoice,
  approvalNonce: string,
): ReferenceRecoveryDecisionRequest {
  const intent = packet.action_intent;
  if (
    packet.status !== "resolved" ||
    intent === null ||
    packet.expected_state_assessment.status !== "supported" ||
    !REQUEST_IDENTIFIER.test(packet.request_id) ||
    !REQUEST_IDENTIFIER.test(approvalNonce) ||
    (decision !== "approved" && decision !== "denied")
  ) {
    throw invalidRecovery();
  }
  return {
    schema: "reference-recovery-decision-request/v1",
    request_id: packet.request_id,
    decision,
    approval_phrase: decision === "approved" ? REFERENCE_APPROVAL_PHRASE : REFERENCE_DENIAL_PHRASE,
    approval_nonce: approvalNonce,
    packet_id: packet.packet_id,
    packet_sha256: packet.derivation_sha256,
    expected_state_sha256: packet.expected_state_assessment.expected_state_sha256,
    reconciliation_id: packet.diagnosis_reconciliation.reconciliation_id,
    action_intent_id: intent.action_intent_id,
    action_intent_sha256: intent.derivation_sha256,
  };
}

async function parseApproval(
  value: unknown,
  packet: ReferenceResponsePacket,
  expectedDecision: ReferenceRecoveryChoice,
  expectedNonce: string,
  before: ReferenceRecoveryStateReference,
  sha256: ReferencePacketSha256,
): Promise<ReferenceHumanApproval> {
  const source = record(value);
  exactKeys(source, APPROVAL_KEYS);
  const approver = record(source.approver);
  exactKeys(
    approver,
    new Set(["audience", "kind", "identity_verified", "identity_assurance", "gesture"]),
  );
  const intent = packet.action_intent;
  if (
    intent === null ||
    source.schema !== "reference-human-approval/v3" ||
    source.decision !== expectedDecision ||
    source.approval_nonce !== expectedNonce ||
    source.action_intent_id !== intent.action_intent_id ||
    source.action_intent_sha256 !== intent.derivation_sha256 ||
    source.reconciliation_id !== packet.diagnosis_reconciliation.reconciliation_id ||
    source.scenario_id !== packet.scenario_id ||
    source.incident_class !== intent.incident_class ||
    source.command !== intent.command ||
    !sameStrings(stringArray(source.affected_job_ids, IDENTIFIER, 1, 1), intent.affected_job_ids) ||
    source.state_generation !== before.generation ||
    source.state_sha256 !== before.state_sha256 ||
    source.protected_state_sha256 !== before.protected_state_sha256 ||
    approver.audience !== "colortrace-simulator" ||
    approver.kind !== "human" ||
    approver.identity_verified !== false ||
    approver.identity_assurance !== "unverified-public-demo-gesture" ||
    approver.gesture !== "explicit-phrase-and-nonce"
  ) {
    throw invalidRecovery();
  }
  const issuedAt = stringValue(source.issued_at, TIMESTAMP);
  const expiresAt = stringValue(source.expires_at, TIMESTAMP);
  const issuedTime = Date.parse(issuedAt);
  const expiresTime = Date.parse(expiresAt);
  if (
    Number.isNaN(issuedTime) ||
    Number.isNaN(expiresTime) ||
    expiresTime <= issuedTime ||
    expiresTime - issuedTime > 10 * 60 * 1000
  ) {
    throw invalidRecovery();
  }
  const approvalId = stringValue(source.approval_id, APPROVAL_ID);
  const approvalSha256 = await verifyDerived(
    source,
    "approval_sha256",
    new Set(["approval_id", "approval_sha256"]),
    sha256,
  );
  assertIdentityDigest(approvalId, approvalSha256, "reference-approval");
  return {
    schema: "reference-human-approval/v3",
    decision: expectedDecision,
    approver: {
      audience: "colortrace-simulator",
      kind: "human",
      identity_verified: false,
      identity_assurance: "unverified-public-demo-gesture",
      gesture: "explicit-phrase-and-nonce",
    },
    approval_nonce: expectedNonce,
    issued_at: issuedAt,
    expires_at: expiresAt,
    action_intent_id: stringValue(source.action_intent_id, ACTION_INTENT_ID),
    action_intent_sha256: stringValue(source.action_intent_sha256, DIGEST),
    reconciliation_id: stringValue(source.reconciliation_id, RECONCILIATION_ID),
    scenario_id: packet.scenario_id,
    incident_class: intent.incident_class,
    command: intent.command,
    affected_job_ids: intent.affected_job_ids,
    state_generation: before.generation,
    state_sha256: before.state_sha256,
    protected_state_sha256: before.protected_state_sha256,
    approval_id: approvalId,
    approval_sha256: approvalSha256,
  };
}

async function parseVerification(
  value: unknown,
  packet: ReferenceResponsePacket,
  before: ReferenceRecoveryStateReference,
  after: ReferenceRecoveryStateReference,
  sha256: ReferencePacketSha256,
): Promise<ReferenceRecoveryVerification> {
  const source = record(value);
  exactKeys(source, VERIFICATION_KEYS);
  const intent = packet.action_intent;
  if (intent === null) throw invalidRecovery();
  const expectedParameters = record(intent.parameters.expected);
  const expectedFields = EXPECTED_VERIFICATION_FIELDS[intent.incident_class];
  const affectedJobIds = stringArray(source.affected_job_ids, IDENTIFIER, 1, 1);
  const sortedAffectedJobIds = [...intent.affected_job_ids].sort();
  if (
    source.schema !== "reference-recovery-verification/v1" ||
    source.verifier !== "deterministic-simulator-state" ||
    source.result !== "verified" ||
    source.scenario_id !== packet.scenario_id ||
    source.incident_class !== intent.incident_class ||
    source.action_intent_id !== intent.action_intent_id ||
    source.action_intent_sha256 !== intent.derivation_sha256 ||
    source.reconciliation_id !== packet.diagnosis_reconciliation.reconciliation_id ||
    !sameDocument(source.before, before) ||
    !sameDocument(source.after, after) ||
    !sameStrings(affectedJobIds, sortedAffectedJobIds) ||
    source.establishes_pixel_output !== false ||
    source.establishes_full_population_scope !== false ||
    source.production_evidence !== false
  ) {
    throw invalidRecovery();
  }
  if (
    !Array.isArray(source.affected_expected_field_checks) ||
    source.affected_expected_field_checks.length !== expectedFields.length
  ) {
    throw invalidRecovery();
  }
  const affectedExpectedFieldChecks = source.affected_expected_field_checks.map(
    (candidate, index) => {
      const check = record(candidate);
      exactKeys(check, VERIFICATION_FIELD_CHECK_KEYS);
      const expectedField = expectedFields[index];
      if (expectedField === undefined || check.field !== expectedField) throw invalidRecovery();
      const expectedValue = expectedParameters[expectedField];
      if (expectedField.endsWith("generation")) {
        if (integerValue(check.expected_value, 1) !== expectedValue) throw invalidRecovery();
      } else if (stringValue(check.expected_value, DIGEST) !== expectedValue) {
        throw invalidRecovery();
      }
      const matchedJobIds = stringArray(check.matched_job_ids, IDENTIFIER, 1, 1);
      if (!sameStrings(matchedJobIds, sortedAffectedJobIds)) throw invalidRecovery();
      return {
        field: expectedField,
        expected_value: expectedValue as string | number,
        matched_job_ids: matchedJobIds,
      };
    },
  );
  const checks = record(source.checks);
  exactKeys(checks, VERIFICATION_CHECK_KEYS);
  if (
    checks.generation_advanced_exactly_once !== true ||
    checks.all_affected_expected_fields_match !== true ||
    checks.protected_state_unchanged !== true ||
    checks.receipt_state_bindings_match !== true
  ) {
    throw invalidRecovery();
  }
  const verificationSha256 = await verifyDerived(
    source,
    "verification_sha256",
    new Set(["verification_sha256"]),
    sha256,
  );
  return {
    schema: "reference-recovery-verification/v1",
    verifier: "deterministic-simulator-state",
    result: "verified",
    scenario_id: packet.scenario_id,
    incident_class: intent.incident_class,
    action_intent_id: intent.action_intent_id,
    action_intent_sha256: intent.derivation_sha256,
    reconciliation_id: intent.reconciliation_id,
    before,
    after,
    affected_job_ids: affectedJobIds,
    affected_expected_field_checks: affectedExpectedFieldChecks,
    checks: {
      generation_advanced_exactly_once: true,
      all_affected_expected_fields_match: true,
      protected_state_unchanged: true,
      receipt_state_bindings_match: true,
    },
    establishes_pixel_output: false,
    establishes_full_population_scope: false,
    production_evidence: false,
    verification_sha256: verificationSha256,
  };
}

async function parseReceipt(
  value: unknown,
  packet: ReferenceResponsePacket,
  approval: ReferenceHumanApproval,
  before: ReferenceRecoveryStateReference,
  after: ReferenceRecoveryStateReference,
  sha256: ReferencePacketSha256,
): Promise<ReferenceRecoveryReceipt> {
  const source = record(value);
  exactKeys(source, RECEIPT_KEYS);
  const intent = packet.action_intent;
  if (
    intent === null ||
    source.schema !== "reference-recovery-receipt/v3" ||
    source.approval_id !== approval.approval_id ||
    source.approval_sha256 !== approval.approval_sha256 ||
    source.action_intent_id !== intent.action_intent_id ||
    source.action_intent_sha256 !== intent.derivation_sha256 ||
    source.reconciliation_id !== packet.diagnosis_reconciliation.reconciliation_id ||
    source.scenario_id !== packet.scenario_id ||
    source.incident_class !== intent.incident_class ||
    source.command !== intent.command ||
    !sameDocument(source.before, before) ||
    !sameDocument(source.after, after) ||
    !sameStrings(stringArray(source.affected_job_ids, IDENTIFIER, 1, 1), intent.affected_job_ids) ||
    !sameStrings(
      stringArray(source.protected_job_ids, IDENTIFIER, 1, 1),
      packet.diagnosis_reconciliation.scope.safe_job_ids,
    ) ||
    source.protected_state_unchanged !== true ||
    source.action_intent_requires_human_approval !== true ||
    source.action_intent_authorizes_execution !== false ||
    source.result !== "applied"
  ) {
    throw invalidRecovery();
  }
  if (!Array.isArray(source.mutations) || source.mutations.length !== 1) {
    throw invalidRecovery();
  }
  const mutation = record(source.mutations[0]);
  exactKeys(
    mutation,
    new Set(["job_id", "before_job_state_sha256", "after_job_state_sha256", "changed_components"]),
  );
  const changedComponents = stringArray(mutation.changed_components, IDENTIFIER, 1, 2);
  const expectedComponents = expectedChangedComponents(intent.incident_class);
  if (
    mutation.job_id !== intent.affected_job_ids[0] ||
    !DIGEST.test(String(mutation.before_job_state_sha256)) ||
    !DIGEST.test(String(mutation.after_job_state_sha256)) ||
    mutation.before_job_state_sha256 === mutation.after_job_state_sha256 ||
    !sameStrings(changedComponents, expectedComponents)
  ) {
    throw invalidRecovery();
  }
  const verification = await parseVerification(source.verification, packet, before, after, sha256);
  const receiptId = stringValue(source.receipt_id, RECEIPT_ID);
  const receiptSha256 = await verifyDerived(
    source,
    "receipt_sha256",
    new Set(["receipt_id", "receipt_sha256"]),
    sha256,
  );
  assertIdentityDigest(receiptId, receiptSha256, "reference-recovery");
  return {
    schema: "reference-recovery-receipt/v3",
    approval_id: approval.approval_id,
    approval_sha256: approval.approval_sha256,
    action_intent_id: intent.action_intent_id,
    action_intent_sha256: intent.derivation_sha256,
    reconciliation_id: intent.reconciliation_id,
    scenario_id: packet.scenario_id,
    incident_class: intent.incident_class,
    command: intent.command,
    before,
    after,
    affected_job_ids: intent.affected_job_ids,
    protected_job_ids: packet.diagnosis_reconciliation.scope.safe_job_ids,
    mutations: [
      {
        job_id: stringValue(mutation.job_id),
        before_job_state_sha256: stringValue(mutation.before_job_state_sha256, DIGEST),
        after_job_state_sha256: stringValue(mutation.after_job_state_sha256, DIGEST),
        changed_components: changedComponents as readonly ("frame" | "derivative")[],
      },
    ],
    protected_state_unchanged: true,
    action_intent_requires_human_approval: true,
    action_intent_authorizes_execution: false,
    verification,
    result: "applied",
    receipt_id: receiptId,
    receipt_sha256: receiptSha256,
  };
}

export async function parseReferenceRecoveryDecision(
  value: unknown,
  packet: ReferenceResponsePacket,
  expectedDecision: ReferenceRecoveryChoice,
  expectedNonce: string,
  sha256: ReferencePacketSha256,
): Promise<ReferenceRecoveryDecision> {
  if (
    packet.status !== "resolved" ||
    packet.action_intent === null ||
    !REQUEST_IDENTIFIER.test(expectedNonce)
  ) {
    throw invalidRecovery();
  }
  const source = record(value);
  exactKeys(source, DECISION_KEYS);
  if (
    source.schema !== "reference-recovery-decision/v1" ||
    source.scenario_id !== packet.scenario_id ||
    source.request_id !== packet.request_id ||
    source.run_id !== packet.run_id ||
    source.packet_id !== packet.packet_id ||
    source.packet_sha256 !== packet.derivation_sha256 ||
    source.decision !== expectedDecision ||
    source.outcome !== (expectedDecision === "approved" ? "applied" : "denied") ||
    source.protected_state_unchanged !== true
  ) {
    throw invalidRecovery();
  }
  stringValue(source.packet_id, PACKET_ID);
  stringValue(source.packet_sha256, DIGEST);
  const before = parseState(source.before);
  const after = parseState(source.after);
  if (before.protected_state_sha256 !== after.protected_state_sha256) {
    throw invalidRecovery();
  }
  const approval = await parseApproval(
    source.approval,
    packet,
    expectedDecision,
    expectedNonce,
    before,
    sha256,
  );
  const scope = record(source.scope);
  exactKeys(
    scope,
    new Set([
      "kind",
      "affected_job_count",
      "protected_job_count",
      "establishes_full_population_scope",
    ]),
  );
  if (
    scope.kind !== "representative-simulator-state" ||
    scope.affected_job_count !== 1 ||
    scope.protected_job_count !== 1 ||
    scope.establishes_full_population_scope !== false
  ) {
    throw invalidRecovery();
  }
  const boundary = record(source.execution_boundary);
  exactKeys(
    boundary,
    new Set([
      "approval_actor_kind",
      "approval_gesture",
      "identity_verified",
      "identity_assurance",
      "execution_target",
      "simulator_state_changed",
      "production_access_used",
      "production_state_changed",
      "production_claim",
    ]),
  );
  const simulatorChanged = expectedDecision === "approved";
  if (
    boundary.approval_actor_kind !== "human" ||
    boundary.approval_gesture !== "explicit-phrase-and-nonce" ||
    boundary.identity_verified !== false ||
    boundary.identity_assurance !== "unverified-public-demo-gesture" ||
    boundary.execution_target !== "colortrace-simulator" ||
    boundary.simulator_state_changed !== simulatorChanged ||
    boundary.production_access_used !== false ||
    boundary.production_state_changed !== false ||
    boundary.production_claim !== "none"
  ) {
    throw invalidRecovery();
  }
  let receipt: ReferenceRecoveryReceipt | null = null;
  let verification: ReferenceRecoveryVerification | null = null;
  if (expectedDecision === "approved") {
    if (
      after.generation !== before.generation + 1 ||
      after.state_sha256 === before.state_sha256 ||
      source.receipt === null ||
      source.verification === null
    ) {
      throw invalidRecovery();
    }
    receipt = await parseReceipt(source.receipt, packet, approval, before, after, sha256);
    if (!sameDocument(source.verification, receipt.verification)) throw invalidRecovery();
    verification = receipt.verification;
  } else if (
    source.receipt !== null ||
    source.verification !== null ||
    !sameDocument(before, after)
  ) {
    throw invalidRecovery();
  }
  const decisionSha256 = await verifyDerived(
    source,
    "decision_sha256",
    new Set(["decision_sha256"]),
    sha256,
  );
  return {
    schema: "reference-recovery-decision/v1",
    scenario_id: packet.scenario_id,
    request_id: packet.request_id,
    run_id: packet.run_id,
    packet_id: packet.packet_id,
    packet_sha256: packet.derivation_sha256,
    decision: expectedDecision,
    outcome: expectedDecision === "approved" ? "applied" : "denied",
    approval,
    before,
    after,
    protected_state_unchanged: true,
    receipt,
    verification,
    scope: {
      kind: "representative-simulator-state",
      affected_job_count: 1,
      protected_job_count: 1,
      establishes_full_population_scope: false,
    },
    execution_boundary: {
      approval_actor_kind: "human",
      approval_gesture: "explicit-phrase-and-nonce",
      identity_verified: false,
      identity_assurance: "unverified-public-demo-gesture",
      execution_target: "colortrace-simulator",
      simulator_state_changed: simulatorChanged,
      production_access_used: false,
      production_state_changed: false,
      production_claim: "none",
    },
    decision_sha256: decisionSha256,
  };
}
