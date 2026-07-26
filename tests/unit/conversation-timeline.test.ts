import { describe, expect, it } from "vitest";
import {
  conversationActivityLabel,
  splitMentionSegments,
  windowConversation,
  type ConversationEvent,
} from "@/components/team-sessions/ConversationTimeline";

function event(type: string): ConversationEvent {
  return {
    eventId: `event-${type}`,
    sessionId: "session-1",
    sequence: 1,
    type,
    occurredAtMs: 1,
    actor: {
      userId: "user-1",
      displayName: "Ada",
    },
    sourceAdapter: "internal",
    payload: {},
  };
}

describe("conversationActivityLabel", () => {
  it.each([
    ["session.participant.joined", "Ada joined the session"],
    ["session.runtime-authorization.advanced", "Runtime authorization is being updated"],
    ["session.runtime-authorization.enforced", "Runtime authorization is enforced"],
    ["session.runtime-authorization.quarantined", "Runtime authorization entered quarantine"],
  ])("renders canonical %s events", (type, expected) => {
    expect(conversationActivityLabel(event(type))).toBe(expected);
  });

  it.each([
    "session.joined",
    "runtime.authorization.requested",
    "runtime.authorization.enforced",
    "runtime.authorization.quarantined",
  ])("does not silently treat legacy %s as canonical", (type) => {
    expect(conversationActivityLabel(event(type))).toBe("Session state changed");
  });
});

describe("windowConversation", () => {
  it("returns every event when under the cap", () => {
    const events = [1, 2, 3];
    expect(windowConversation(events, 200)).toEqual({ visible: [1, 2, 3], hiddenBefore: 0 });
  });

  it("keeps only the most recent events and reports the withheld count", () => {
    const events = Array.from({ length: 250 }, (_, index) => index);
    const { visible, hiddenBefore } = windowConversation(events, 200);
    expect(visible).toHaveLength(200);
    expect(visible[0]).toBe(50);
    expect(visible.at(-1)).toBe(249);
    expect(hiddenBefore).toBe(50);
  });
});

describe("splitMentionSegments", () => {
  it("splits @mentions out of surrounding text", () => {
    expect(splitMentionSegments("hi @user-bob and @user-cara!")).toEqual([
      { kind: "text", value: "hi " },
      { kind: "mention", value: "@user-bob" },
      { kind: "text", value: " and " },
      { kind: "mention", value: "@user-cara" },
      { kind: "text", value: "!" },
    ]);
  });

  it("returns a single text segment when there is no mention", () => {
    expect(splitMentionSegments("plain text")).toEqual([{ kind: "text", value: "plain text" }]);
  });
});
