import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ResponsePlanReview, type ResponsePlanReviewProps } from "../src/response-plan-review.tsx";
import { RESPONSE_PLAN_HASH, responsePlanReviewFixture } from "./response-plan-fixture.ts";

afterEach(cleanup);

function props(overrides: Partial<ResponsePlanReviewProps> = {}): ResponsePlanReviewProps {
  return {
    actionError: null,
    busy: false,
    capabilities: { canApprove: true, canEdit: true, session: "active" },
    onApprove: vi.fn(),
    onEdit: vi.fn(),
    onReject: vi.fn(),
    state: { kind: "ready", review: responsePlanReviewFixture() },
    ...overrides,
  };
}

describe("ResponsePlanReview", () => {
  it("renders exact immutable bindings and keeps command text inert", () => {
    const payload = '<img src=x onerror="globalThis.compromised=true"><script>alert(1)</script>';
    const { container } = render(
      <ResponsePlanReview
        {...props({
          state: {
            kind: "ready",
            review: responsePlanReviewFixture({ commandId: payload }),
          },
        })}
      />,
    );

    expect(screen.getByText(RESPONSE_PLAN_HASH)).toBeVisible();
    expect(screen.getAllByText("frame-affected-0001").length).toBeGreaterThan(0);
    expect(screen.getByText("frame-safe-0002")).toBeVisible();
    expect(screen.getByText(payload)).toBeVisible();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(Reflect.get(globalThis, "compromised")).not.toBe(true);
  });

  it("renders the complete shared envelope, command fields, and exact uncertainty IDs", () => {
    const review = responsePlanReviewFixture({
      blockingUnresolvedItemIds: ["validator-blocker"],
      unknownTargetIds: ["frame-unknown-0009"],
      unresolvedItemIds: ["validator-blocker", "operator-review-note"],
    });
    render(<ResponsePlanReview {...props({ state: { kind: "ready", review } })} />);

    const envelope = screen.getByRole("region", { name: "Shared simulator action envelope" });
    for (const label of [
      "Fixture manifest",
      "Source batch digest",
      "Runtime manifest",
      "Publication pointer",
      "Declared resource manifest",
      "Preservation manifest",
      "Safe complement",
      "Lineage manifest",
    ]) {
      expect(within(envelope).getByText(label)).toBeVisible();
    }
    const commands = screen.getByRole("region", { name: "Typed simulator commands" });
    for (const label of [
      "Command schema",
      "Job",
      "Transform",
      "Source PNG",
      "Expected config",
      "Expected display",
      "Expected derivative display",
    ]) {
      expect(within(commands).getAllByText(label).length).toBeGreaterThan(0);
    }

    const uncertainty = screen.getByRole("region", { name: "Approval uncertainty" });
    expect(within(uncertainty).getAllByText("validator-blocker")).toHaveLength(2);
    expect(within(uncertainty).getByText("operator-review-note")).toBeVisible();
    expect(within(uncertainty).getByText("frame-unknown-0009")).toBeVisible();
    expect(
      screen.getByRole("checkbox", {
        name: "Acknowledge all listed unresolved items for this version",
      }),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Approve exact plan" }));
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent("validator-blocker");
    expect(dialog).toHaveTextContent("frame-unknown-0009");
  });

  it("requires a second exact-plan confirmation before approval", () => {
    const onApprove = vi.fn();
    const selected = props({ onApprove });
    render(<ResponsePlanReview {...selected} />);

    fireEvent.click(screen.getByRole("button", { name: "Approve exact plan" }));

    expect(onApprove).not.toHaveBeenCalled();
    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent(RESPONSE_PLAN_HASH);
    expect(dialog).toHaveTextContent("3 targets");
    expect(dialog).toHaveTextContent("3 typed commands");
    const confirm = screen.getByRole("button", { name: "Confirm approve" });
    expect(confirm).toHaveFocus();
    fireEvent.click(confirm);
    const review = selected.state.kind === "ready" ? selected.state.review : null;
    expect(review).not.toBeNull();
    expect(onApprove).toHaveBeenCalledWith(review?.plan);
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(screen.getByRole("button", { name: "Approve exact plan" })).toHaveFocus();
  });

  it("requires a typed change and makes approval invalidation explicit before revision", () => {
    const onEdit = vi.fn();
    render(<ResponsePlanReview {...props({ onEdit })} />);

    const createRevision = screen.getByRole("button", { name: "Create revised version" });
    expect(createRevision).toBeDisabled();
    const replacement = `sha256:${"4".repeat(64)}`;
    fireEvent.change(screen.getByRole("textbox", { name: "Approved replacement SHA-256" }), {
      target: { value: replacement },
    });
    expect(createRevision).toBeEnabled();
    fireEvent.click(createRevision);

    const dialog = screen.getByRole("alertdialog");
    expect(dialog).toHaveTextContent(/invalidates any approval/i);
    expect(dialog).toHaveTextContent(replacement);
    expect(onEdit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm revise" }));
    expect(onEdit).toHaveBeenCalledWith(
      responsePlanReviewFixture().plan,
      expect.objectContaining({
        commands: expect.arrayContaining([
          expect.objectContaining({
            action_envelope: expect.objectContaining({
              replacement_resource_sha256: replacement,
            }),
          }),
        ]),
        unresolved_acknowledged: false,
      }),
    );
  });

  it("traps dialog focus, cancels with Escape, and restores the originating action", () => {
    render(<ResponsePlanReview {...props()} />);
    const trigger = screen.getByRole("button", { name: "Approve exact plan" });
    fireEvent.click(trigger);

    const dialog = screen.getByRole("alertdialog");
    const cancel = screen.getByRole("button", { name: "Cancel" });
    const confirm = screen.getByRole("button", { name: "Confirm approve" });
    cancel.focus();
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(confirm).toHaveFocus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(cancel).toHaveFocus();
    fireEvent.keyDown(dialog, { key: "Escape" });

    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(trigger).toHaveFocus();
  });

  it("binds rejection to the selected bounded reason", () => {
    const onReject = vi.fn();
    render(<ResponsePlanReview {...props({ onReject })} />);

    fireEvent.change(screen.getByRole("combobox", { name: "Rejection reason" }), {
      target: { value: "unresolved-risk" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Reject plan" }));
    expect(onReject).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Confirm reject" }));

    expect(onReject).toHaveBeenCalledWith(responsePlanReviewFixture().plan, "unresolved-risk");
  });

  it.each([
    {
      capabilities: { canApprove: false, canEdit: false, session: "read-only" } as const,
      review: responsePlanReviewFixture(),
      message: /verified human role/i,
    },
    {
      capabilities: { canApprove: false, canEdit: false, session: "expired" } as const,
      review: responsePlanReviewFixture(),
      message: /credential expired or was rejected/i,
    },
    {
      capabilities: { canApprove: true, canEdit: true, session: "active" } as const,
      review: responsePlanReviewFixture({ currentIncidentVersion: 8, state: "stale" }),
      message: /stale and cannot be decided or dispatched/i,
    },
  ])("disables every mutation for read-only, expired, and stale states", (value) => {
    render(
      <ResponsePlanReview
        {...props({
          capabilities: value.capabilities,
          state: { kind: "ready", review: value.review },
        })}
      />,
    );

    expect(screen.getByText(value.message)).toBeVisible();
    expect(screen.getByRole("button", { name: "Approve exact plan" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Reject plan" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Create revised version" })).toBeDisabled();
  });
});
