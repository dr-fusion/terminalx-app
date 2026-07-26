import { describe, expect, it } from "vitest";
import {
  describeDeadline,
  isOverdue,
  type AttentionItemView,
} from "@/components/attention/AttentionInboxView";
import { formatUnreadBadge } from "@/components/attention/InboxBadge";

function item(deadlineAtMs: number | null): AttentionItemView {
  return {
    itemId: "handoff-offer:s:1",
    kind: "handoff-offer",
    sessionId: "s",
    teamId: "t",
    projectId: "p",
    sessionName: "Session",
    sessionStatus: "active",
    itemSequence: 1,
    createdAtMs: 0,
    deadlineAtMs,
    read: false,
    escalated: false,
    actorUserId: null,
    summary: "A handoff is awaiting your response",
  };
}

describe("describeDeadline", () => {
  it("returns null without a deadline", () => {
    expect(describeDeadline(null, 1_000)).toBeNull();
  });

  it("phrases upcoming and past deadlines", () => {
    expect(describeDeadline(1_000 + 30 * 60_000, 1_000)).toContain("30");
    expect(describeDeadline(1_000 - 30 * 60_000, 1_000)).toContain("30");
  });
});

describe("isOverdue", () => {
  it("is true only once the deadline has passed", () => {
    expect(isOverdue(item(500), 1_000)).toBe(true);
    expect(isOverdue(item(2_000), 1_000)).toBe(false);
    expect(isOverdue(item(null), 1_000)).toBe(false);
  });
});

describe("formatUnreadBadge", () => {
  it("hides a zero or negative count", () => {
    expect(formatUnreadBadge(0)).toBeNull();
    expect(formatUnreadBadge(-5)).toBeNull();
  });

  it("caps at 99+", () => {
    expect(formatUnreadBadge(5)).toBe("5");
    expect(formatUnreadBadge(99)).toBe("99");
    expect(formatUnreadBadge(150)).toBe("99+");
  });
});
