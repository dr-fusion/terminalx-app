import { describe, expect, it } from "vitest";
import {
  conversationActivityLabel,
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
