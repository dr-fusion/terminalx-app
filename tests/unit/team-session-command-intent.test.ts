import { describe, expect, it } from "vitest";
import {
  shouldPreserveTeamSessionCommandIntent,
  teamSessionCommandIntentFingerprint,
} from "@/components/team-sessions/command-intent";
import { HttpError } from "@/lib/team-sessions/browser-client";

describe("team Session command intent", () => {
  it("ignores refreshed authorization fences without ignoring the human action", () => {
    const first = teamSessionCommandIntentFingerprint({
      type: "session.invitation.create",
      sessionId: "session-1",
      membershipRole: "guest",
      expiresAtMs: 2_000_000_000_000,
      expectedAccessRevision: 3,
    });
    const refreshed = teamSessionCommandIntentFingerprint({
      type: "session.invitation.create",
      sessionId: "session-1",
      membershipRole: "guest",
      expiresAtMs: 2_000_000_000_000,
      expectedAccessRevision: 4,
    });
    const differentRole = teamSessionCommandIntentFingerprint({
      type: "session.invitation.create",
      sessionId: "session-1",
      membershipRole: "member",
      expiresAtMs: 2_000_000_000_000,
      expectedAccessRevision: 4,
    });

    expect(refreshed).toBe(first);
    expect(differentRole).not.toBe(first);
  });

  it("preserves uncertain failures and releases definite client rejections", () => {
    expect(shouldPreserveTeamSessionCommandIntent(new TypeError("network failed"))).toBe(true);
    expect(
      shouldPreserveTeamSessionCommandIntent(new HttpError(503, "unavailable", "try again"))
    ).toBe(true);
    expect(
      shouldPreserveTeamSessionCommandIntent(new HttpError(409, "conflict", "stale revision"))
    ).toBe(false);
    expect(
      shouldPreserveTeamSessionCommandIntent(new HttpError(403, "not-authorized", "denied"))
    ).toBe(false);
  });
});
