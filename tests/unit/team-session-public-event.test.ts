import { describe, expect, it } from "vitest";
import { projectPublicSessionEvent } from "@/lib/team-sessions/public-event";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type ActorContext,
  type SessionEvent,
} from "@/lib/team-sessions";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";
const ALICE: ActorContext = { kind: "human", userId: "user-alice", displayName: "Alice" };
const PENDING_GUEST: ActorContext = {
  kind: "human",
  userId: "pending-guest-private-id",
  displayName: "Pending Guest Private Name",
};

describe("public Team Session event projection", () => {
  it.each([
    {
      type: "comment.added",
      payload: {
        commentId: "comment-1",
        body: "A review note",
        invitationId: "private-invitation",
        accessRevision: 42,
        apiToken: "private-token",
      },
      expected: { commentId: "comment-1", body: "A review note" },
    },
    {
      type: "suggestion.added",
      payload: {
        suggestionId: "suggestion-1",
        suggestionVersion: 3,
        body: "Run the focused test",
        resolutionId: "private-resolution",
        steeringRevision: 17,
      },
      expected: {
        suggestionId: "suggestion-1",
        suggestionVersion: 3,
        body: "Run the focused test",
      },
    },
    {
      type: "suggestion.resolved",
      payload: {
        suggestionId: "suggestion-1",
        suggestionVersion: 4,
        resolution: "accept-edited",
        resolutionId: "private-resolution",
        directiveId: "private-derived-directive",
        suggestionSequence: 12,
      },
      expected: {
        suggestionId: "suggestion-1",
        suggestionVersion: 4,
        resolution: "accept-edited",
      },
    },
    {
      type: "directive.queued",
      payload: {
        directiveId: "directive-1",
        body: "Continue with the migration",
        origin: { kind: "suggestion", suggestionId: "private-origin" },
        steeringRevision: 18,
        queueSequence: 99,
      },
      expected: { directiveId: "directive-1", body: "Continue with the migration" },
    },
  ])("keeps only the browser conversation contract for $type", ({ type, payload, expected }) => {
    const source = event(type, payload, ALICE, "slack:workspace-private-id");

    const projected = projectPublicSessionEvent(source);

    expect(projected).toMatchObject({
      type,
      actor: ALICE,
      sourceAdapter: "slack",
      payload: expected,
    });
    expect(projected.payload).toEqual(expected);
    expect(projected).not.toHaveProperty("source");
    expect(JSON.stringify(projected)).not.toContain("private-token");
    expect(source.payload).toEqual(payload);
  });

  it.each(["session.invitation.redeemed", "team.membership.joined", "team.membership.reinstated"])(
    "anonymizes the pre-admission actor and all %s internals",
    (type) => {
      const projected = projectPublicSessionEvent(
        event(
          type,
          {
            invitationId: "private-invitation",
            teamId: "private-team",
            userId: PENDING_GUEST.userId,
            membershipRole: "guest",
            invitationVersion: 2,
            accessRevision: 9,
          },
          PENDING_GUEST,
          "http:pending-guest-private-id"
        )
      );

      expect(projected).toMatchObject({
        type: "session.activity",
        actor: {
          kind: "system",
          userId: "session-system",
          displayName: "Session system",
        },
        sourceAdapter: "internal",
        payload: {},
      });
      expect(JSON.stringify(projected)).not.toContain(PENDING_GUEST.userId);
      expect(JSON.stringify(projected)).not.toContain(PENDING_GUEST.displayName);
      expect(JSON.stringify(projected)).not.toContain("private-invitation");
      expect(JSON.stringify(projected)).not.toContain("private-team");
    }
  );

  it.each([
    "session.invitation.created",
    "session.invitation.revoked",
    "session.share.created",
    "session.access.revision.advanced",
  ])("strips identifiers and revisions from admission administration event %s", (type) => {
    const projected = projectPublicSessionEvent(
      event(
        type,
        {
          invitationId: "private-invitation",
          teamId: "private-team",
          projectId: "private-project",
          userId: "private-target-user",
          createdByUserId: ALICE.userId,
          invitationVersion: 3,
          shareVersion: 4,
          accessRevision: 10,
        },
        ALICE
      )
    );

    expect(projected).toMatchObject({
      type: "session.activity",
      actor: {
        kind: "system",
        userId: "session-system",
        displayName: "Session system",
      },
      sourceAdapter: "internal",
      payload: {},
    });
    expect(JSON.stringify(projected)).not.toMatch(
      /private-invitation|private-team|private-project|private-target-user|accessRevision/
    );
  });

  it("reveals the joining actor only at the admitted Participant transition", () => {
    const projected = projectPublicSessionEvent(
      event(
        "session.participant.joined",
        {
          participantId: "participant-private-id",
          userId: PENDING_GUEST.userId,
          invitationId: "private-invitation",
          participantVersion: 1,
          accessRevision: 10,
        },
        PENDING_GUEST
      )
    );

    expect(projected).toMatchObject({
      type: "session.participant.joined",
      actor: PENDING_GUEST,
      payload: {},
    });
    expect(JSON.stringify(projected)).not.toContain("participant-private-id");
    expect(JSON.stringify(projected)).not.toContain("private-invitation");
  });

  it("fails closed for new kernel event types", () => {
    const projected = projectPublicSessionEvent(
      event(
        "session.future-administration-event",
        {
          userId: "future-private-user",
          arbitraryRevision: 100,
          credential: "future-private-credential",
        },
        ALICE,
        "telegram:private-chat-id"
      )
    );

    expect(projected).toMatchObject({
      type: "session.activity",
      actor: { kind: "system", userId: "session-system" },
      sourceAdapter: "internal",
      payload: {},
    });
    expect(JSON.stringify(projected)).not.toContain("future-private");
  });
});

function event(
  type: string,
  payload: Record<string, unknown>,
  actor: ActorContext,
  scope = "http:user-alice"
): SessionEvent {
  return {
    schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
    eventId: `event-${type}`,
    sessionId: SESSION_ID,
    sequence: 7,
    type,
    occurredAtMs: 2_000_000_000_000,
    actor,
    source: { scope, key: "private-idempotency-key" },
    payload,
  };
}
