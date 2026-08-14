import { describe, expect, it } from "vitest";

import { canonicalJsonSha256 } from "../src/canonical-sha256.ts";
import { projectRecoveryReview } from "../src/recovery.ts";
import type { RecoveryReviewProjectionInput } from "../src/recovery-types.ts";
import { cloneRecoveryReview, recoveryReviewFixture } from "./recovery-fixture.ts";

type Mutable<T> = T extends readonly (infer Item)[]
  ? Mutable<Item>[]
  : T extends object
    ? { -readonly [Key in keyof T]: Mutable<T[Key]> }
    : T;

function mutable(
  review: RecoveryReviewProjectionInput = recoveryReviewFixture(),
): Mutable<RecoveryReviewProjectionInput> {
  return cloneRecoveryReview(review) as Mutable<RecoveryReviewProjectionInput>;
}

function resealSnapshot(review: Mutable<RecoveryReviewProjectionInput>): void {
  const snapshot = review.snapshot;
  const body = Object.fromEntries(
    Object.entries(snapshot).filter(([key]) => key !== "snapshot_id" && key !== "snapshot_sha256"),
  );
  const sha256 = `sha256:${canonicalJsonSha256(body)}`;
  snapshot.snapshot_id = `recovery-snapshot:${sha256.slice("sha256:".length)}`;
  snapshot.snapshot_sha256 = sha256;
}

function resealPacket(review: Mutable<RecoveryReviewProjectionInput>): void {
  const packet = review.packet;
  if (packet === null) throw new Error("fixture must contain a recovery packet");
  const body = Object.fromEntries(
    Object.entries(packet).filter(([key]) => key !== "packet_id" && key !== "packet_sha256"),
  );
  const sha256 = `sha256:${canonicalJsonSha256(body)}`;
  packet.packet_id = `recovery-packet:${sha256.slice("sha256:".length)}`;
  packet.packet_sha256 = sha256;
}

describe("projectRecoveryReview", () => {
  it.each(["recovery_verified", "recovery_failed", "recovery_unresolved", "closed"] as const)(
    "verifies and freezes a canonical %s aggregate",
    (state) => {
      const workspace = projectRecoveryReview(recoveryReviewFixture(state), "incident-recovery-24");

      expect(workspace.integrity).toBe("verified");
      expect(workspace.problems).toEqual([]);
      expect(Object.isFrozen(workspace)).toBe(true);
      if (workspace.integrity === "verified") {
        expect(workspace.review.state).toBe(state);
        expect(Object.isFrozen(workspace.review.snapshot.verification_artifacts)).toBe(true);
      }
    },
  );

  it("fails closed when the selected incident and snapshot identity differ", () => {
    const workspace = projectRecoveryReview(recoveryReviewFixture(), "incident-other");

    expect(workspace).toMatchObject({
      integrity: "invalid",
      review: null,
      problems: expect.arrayContaining(["identity-binding"]),
    });
  });

  it("fails closed when a sealed verification result is altered", () => {
    const review = mutable();
    const result = review.packet?.check_results[0];
    if (result === undefined) throw new Error("fixture must contain the first result");
    result.reason_codes.push("post-seal-change");

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("digest-binding");
  });

  it("recomputes the nested action outcome seal instead of trusting a resealed snapshot", () => {
    const review = mutable();
    review.snapshot.action_outcome.plan_id = "tampered-response-plan";
    resealSnapshot(review);

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("digest-binding");
  });

  it("rejects uncited evidence identity and extra raw provider fields", () => {
    const review = mutable();
    const record = review.evidence_records[0];
    if (record === undefined) throw new Error("fixture must contain evidence");
    record.evidence_id = "uncited-provider-record";
    (record as unknown as Record<string, unknown>).raw_query = "must never enter the workspace";

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toEqual(
      expect.arrayContaining(["citation-binding", "schema-binding"]),
    );
  });

  it("does not accept replayed pre-action evidence as verified recovery", () => {
    const review = mutable();
    const record = review.evidence_records[0];
    if (record === undefined) throw new Error("fixture must contain evidence");
    record.freshness = "pre-action";
    record.observed_at = "2026-08-14T11:59:00.000Z";
    record.emitted_at = "2026-08-14T11:59:10.000Z";
    record.retrieved_at = "2026-08-14T12:02:20.000Z";

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("status-binding");
  });

  it.each([
    ["signal", "profile"],
    ["subject_kind", "provider-query"],
    ["freshness", "assumed-fresh"],
  ] as const)("runtime-checks the evidence %s enum", (field, value) => {
    const review = mutable();
    const record = review.evidence_records[0];
    if (record === undefined) throw new Error("fixture must contain evidence");
    (record as unknown as Record<string, unknown>)[field] = value;

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("schema-binding");
  });

  it("requires verified evidence retrieval inside the evaluation window", () => {
    const review = mutable();
    const record = review.evidence_records[0];
    if (record === undefined) throw new Error("fixture must contain evidence");
    record.observed_at = "2026-08-14T12:01:10.000Z";
    record.emitted_at = "2026-08-14T12:01:20.000Z";
    record.retrieved_at = "2026-08-14T12:01:30.000Z";

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("status-binding");
  });

  it("rejects verified evidence retrieved more than sixty seconds before completion", () => {
    const review = mutable();
    const packet = review.packet;
    if (packet === null) throw new Error("fixture must contain a recovery packet");
    packet.evaluation_completed_at = "2026-08-14T12:03:21.000Z";
    resealPacket(review);

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("status-binding");
  });

  it("rejects unknown audit event types at runtime", () => {
    const review = mutable();
    const event = review.audit_events[0];
    if (event === undefined) throw new Error("fixture must contain an audit event");
    (event as unknown as { event_type: string }).event_type = "verification.assumed";

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("audit-binding");
  });

  it("requires service verifier authority for verification audit events", () => {
    const review = mutable();
    const event = review.audit_events[0];
    if (event === undefined) throw new Error("fixture must contain an audit event");
    event.actor.kind = "human";
    event.actor.authorized_role = "recovery.closer";

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("audit-binding");
  });

  it("requires human closer authority for closure audit events", () => {
    const review = mutable(recoveryReviewFixture("closed"));
    const event = review.audit_events.at(-1);
    if (event === undefined) throw new Error("closed fixture must contain a closure event");
    event.actor.kind = "service";
    event.actor.authorized_role = "recovery.verifier";

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toContain("audit-binding");
  });

  it("rejects a non-human closure actor even when all packet bindings remain current", () => {
    const review = mutable(recoveryReviewFixture("closed"));
    if (review.closure === null) throw new Error("closed fixture must contain closure");
    (review.closure.actor as { kind: string }).kind = "service";

    const workspace = projectRecoveryReview(review, "incident-recovery-24");

    expect(workspace.integrity).toBe("invalid");
    expect(workspace.problems).toEqual(
      expect.arrayContaining(["digest-binding", "schema-binding"]),
    );
  });
});
