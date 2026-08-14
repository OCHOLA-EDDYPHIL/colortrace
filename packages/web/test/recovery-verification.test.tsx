import { projectRecoveryReview } from "@colortrace/workspace-model";
import {
  cloneRecoveryReview,
  recoveryReviewFixture,
} from "@colortrace/workspace-model/recovery-test-fixture";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  RecoveryVerification,
  type RecoveryVerificationProps,
} from "../src/recovery-verification.tsx";

afterEach(cleanup);

function readyState(review = recoveryReviewFixture()): RecoveryVerificationProps["state"] {
  const workspace = projectRecoveryReview(review, review.snapshot.incident_id);
  if (workspace.integrity !== "verified") throw new Error("fixture must project as verified");
  return { kind: "ready", workspace };
}

function props(overrides: Partial<RecoveryVerificationProps> = {}): RecoveryVerificationProps {
  return {
    actionError: null,
    busy: false,
    capabilities: { canClose: true, session: "active" },
    onClose: vi.fn(),
    state: readyState(),
    ...overrides,
  };
}

describe("RecoveryVerification", () => {
  it("separates execution from deterministic recovery and displays all seven cited checks", () => {
    render(<RecoveryVerification {...props()} />);

    expect(screen.getByText(/command success alone does not establish recovery/i)).toBeVisible();
    expect(screen.getAllByText("Recovery verified").length).toBeGreaterThan(0);
    for (const label of [
      "Active publication",
      "Approved resource state",
      "Declared reference recovery",
      "Exact typed lineage",
      "Approved recovery scope",
      "Safe complement preservation",
      "Post-action telemetry correlation",
    ]) {
      expect(screen.getByText(label)).toBeVisible();
    }
    expect(document.querySelectorAll(".recovery-check-list > li")).toHaveLength(7);
    expect(document.querySelectorAll(".recovery-citations a").length).toBeGreaterThanOrEqual(7);
    expect(screen.getByText("Before action").parentElement).toHaveTextContent(
      `sha256:${"3".repeat(64)}`,
    );
    expect(screen.getByText("After action").parentElement).toHaveTextContent(
      `sha256:${"3".repeat(64)}`,
    );
  });

  it("requires a current verified packet, exact reason, and explicit human confirmation", async () => {
    const onClose = vi.fn();
    render(<RecoveryVerification {...props({ onClose })} />);

    const trigger = screen.getByRole("button", { name: "Close verified recovery" });
    expect(trigger).toBeDisabled();
    fireEvent.change(screen.getByRole("textbox", { name: "Closure reason" }), {
      target: { value: "Reviewed post-action evidence and safe-work preservation." },
    });
    expect(trigger).toBeEnabled();
    fireEvent.click(trigger);

    const dialog = screen.getByRole("alertdialog", { name: "Close this exact verified recovery?" });
    expect(dialog).toHaveTextContent("Reviewed post-action evidence");
    expect(dialog).toHaveTextContent("sha256:");
    const confirm = within(dialog).getByRole("button", { name: "Confirm closure" });
    await waitFor(() => expect(confirm).toHaveFocus());
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("alertdialog")).toBeNull();
    await waitFor(() => expect(trigger).toHaveFocus());

    fireEvent.click(trigger);
    fireEvent.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: "Confirm closure",
      }),
    );
    expect(onClose).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledWith(
      expect.objectContaining({
        state: "recovery_verified",
        packet: expect.objectContaining({
          status: "recovery_verified",
          eligible_for_closure: true,
        }),
      }),
      "Reviewed post-action evidence and safe-work preservation.",
    );
  });

  it.each([
    ["recovery_failed", "Recovery failed"],
    ["recovery_unresolved", "Recovery unresolved"],
  ] as const)("keeps closure disabled for %s", (state, label) => {
    render(
      <RecoveryVerification {...props({ state: readyState(recoveryReviewFixture(state)) })} />,
    );

    expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    expect(screen.getByRole("textbox", { name: "Closure reason" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Close verified recovery" })).toBeDisabled();
    expect(screen.getByText(/only a current recovery_verified packet/i)).toBeVisible();
    if (state === "recovery_unresolved") {
      fireEvent.click(screen.getByText("Open cited evidence and artifact records"));
      expect(screen.getByText("Late evidence")).toBeVisible();
    }
  });

  it("requires an authenticated human recovery.closer role", () => {
    render(
      <RecoveryVerification {...props({ capabilities: { canClose: false, session: "active" } })} />,
    );

    expect(screen.getByText(/does not hold the recovery.closer role/i)).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Closure reason" })).toBeDisabled();
  });

  it("renders immutable closure authority without another closure control", () => {
    render(
      <RecoveryVerification {...props({ state: readyState(recoveryReviewFixture("closed")) })} />,
    );

    expect(screen.getAllByText("Closed").length).toBeGreaterThan(0);
    expect(screen.getByText(/Pipeline operator/)).toBeVisible();
    expect(screen.getByText(/Verified recovery reviewed/)).toBeVisible();
    expect(screen.queryByRole("button", { name: "Close verified recovery" })).toBeNull();
  });

  it("withholds all recovery details when the aggregate fails integrity projection", () => {
    render(
      <RecoveryVerification
        {...props({
          state: {
            kind: "integrity-error",
            message: "The recovery packet digest did not match its immutable content.",
          },
        })}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Recovery verification could not be verified",
    );
    expect(screen.queryByText("Execution record")).toBeNull();
    expect(screen.queryByRole("button", { name: "Close verified recovery" })).toBeNull();
  });

  it("renders sanitized evidence excerpts as inert text", () => {
    const review = cloneRecoveryReview();
    const record = review.evidence_records[0];
    if (record === undefined) throw new Error("fixture must contain evidence");
    (record as { display_excerpt: string }).display_excerpt =
      '<img src=x onerror="globalThis.__recoveryPwned=true">';
    render(<RecoveryVerification {...props({ state: readyState(review) })} />);

    fireEvent.click(screen.getByText("Open cited evidence and artifact records"));
    expect(screen.getByText(/<img src=x/)).toBeVisible();
    expect(document.querySelector(".recovery-record img")).toBeNull();
  });

  it("offers exact replay only for ambiguous transport failure", () => {
    const onRetry = vi.fn();
    const onReconcile = vi.fn();
    render(
      <RecoveryVerification
        {...props({
          actionError: "The closure response was ambiguous.",
          recovery: { kind: "mutation-failed", onRetry, onReconcile },
        })}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: "Retry exact closure" }));
    fireEvent.click(screen.getByRole("button", { name: "Reconcile recovery state" }));
    expect(onRetry).toHaveBeenCalledOnce();
    expect(onReconcile).toHaveBeenCalledOnce();
  });
});
