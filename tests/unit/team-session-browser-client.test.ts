import { afterEach, describe, expect, it, vi } from "vitest";
import {
  fetchTeamSessionAdmission,
  fetchTeamSessionDetail,
  fetchTeamSessionDiscovery,
  fetchTeamSessionEvents,
  fetchTeamSessionInbox,
  HttpError,
  parseTeamSessionEvent,
  submitTeamSessionCommand,
} from "@/lib/team-sessions/browser-client";

const SESSION_ID = "33333333-3333-4333-8333-333333333333";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Team Session browser client", () => {
  it("loads and validates the public discovery, inbox, and detail projections", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      const path = String(input);
      if (path === "/api/team-sessions/discovery") {
        return jsonResponse({ discovery: discoveryFixture() });
      }
      if (path === "/api/team-sessions") {
        return jsonResponse({ sessions: [inboxFixture()] });
      }
      if (path === `/api/team-sessions/sessions/${SESSION_ID}`) {
        return jsonResponse({ session: detailFixture() });
      }
      throw new Error(`Unexpected request: ${path}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTeamSessionDiscovery()).resolves.toEqual(discoveryFixture());
    await expect(fetchTeamSessionInbox()).resolves.toEqual([inboxFixture()]);
    await expect(fetchTeamSessionDetail(SESSION_ID)).resolves.toEqual(detailFixture());
    expect(fetchMock).toHaveBeenCalledTimes(3);
    for (const [, init] of fetchMock.mock.calls) {
      expect(init).toMatchObject({ cache: "no-store", credentials: "same-origin" });
      expect((init?.headers as Headers).get("accept")).toBe("application/json");
    }
  });

  it("fails closed if a public Session response gains an internal Runtime field", async () => {
    const unsafe = detailFixture() as Record<string, unknown>;
    unsafe.runtime = { ...(unsafe.runtime as object), tmuxName: "must-not-enter-the-browser" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ session: unsafe }))
    );

    await expect(fetchTeamSessionDetail(SESSION_ID)).rejects.toMatchObject({
      name: "HttpError",
      code: "invalid-response",
    });
  });

  it("loads only the strict private Session admission projection", async () => {
    const fixture = admissionFixture();
    const fetchMock = vi.fn(async () => jsonResponse({ admission: fixture }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchTeamSessionAdmission(SESSION_ID)).resolves.toEqual(fixture);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/team-sessions/sessions/${SESSION_ID}/admission`,
      expect.objectContaining({ cache: "no-store", credentials: "same-origin" })
    );

    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({
          admission: {
            ...fixture,
            tokenDigest: "must-never-enter-the-browser",
          },
        })
      )
    );
    await expect(fetchTeamSessionAdmission(SESSION_ID)).rejects.toMatchObject({
      code: "invalid-response",
    });
  });

  it("uses abortable, bounded event catch-up and accepts only redacted public events", async () => {
    const controller = new AbortController();
    const event = eventFixture(4);
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({ events: [event] })
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchTeamSessionEvents(SESSION_ID, {
        afterSequence: 3,
        limit: 10,
        signal: controller.signal,
      })
    ).resolves.toEqual([event]);
    expect(fetchMock).toHaveBeenCalledWith(
      `/api/team-sessions/sessions/${SESSION_ID}/events?afterSequence=3&limit=10`,
      expect.objectContaining({ signal: controller.signal })
    );

    const unredacted = eventFixture(5);
    unredacted.payload = { apiToken: "plaintext-provider-token" };
    expect(() => parseTeamSessionEvent(unredacted, SESSION_ID)).toThrowError(
      expect.objectContaining({ code: "invalid-response" })
    );

    let boundedDeepValue: unknown = "[redacted]";
    for (let depth = 0; depth < 16; depth += 1) {
      boundedDeepValue = { nested: boundedDeepValue };
    }
    expect(() =>
      parseTeamSessionEvent({ ...eventFixture(6), payload: { deep: boundedDeepValue } }, SESSION_ID)
    ).not.toThrow();
  });

  it("submits only the command body with a caller-reusable idempotency key", async () => {
    const event = eventFixture(8);
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse({
        result: {
          accepted: true,
          commandType: "comment.add",
          replayed: false,
          data: { sessionId: SESSION_ID, commentId: "comment-1", sequence: 8 },
          events: [event],
        },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await submitTeamSessionCommand(
      { type: "comment.add", sessionId: SESSION_ID, body: "Review note" },
      { idempotencyKey: "web:test-comment-1" }
    );

    expect(result.commandType).toBe("comment.add");
    const [, init] = fetchMock.mock.calls[0]!;
    expect((init?.headers as Headers).get("idempotency-key")).toBe("web:test-comment-1");
    expect(JSON.parse(String(init?.body))).toEqual({
      type: "comment.add",
      sessionId: SESSION_ID,
      body: "Review note",
    });
  });

  it("preserves structured HTTP problems and exposes whether retry is useful", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse(
          { error: { code: "stale-revision", message: "State changed; refresh and retry" } },
          409
        )
      )
    );

    const error = await fetchTeamSessionInbox().catch((cause: unknown) => cause);
    expect(error).toBeInstanceOf(HttpError);
    expect(error).toMatchObject({
      status: 409,
      code: "stale-revision",
      message: "State changed; refresh and retry",
      retryable: false,
    });
  });

  it("allows only the intentional root invitation token in an invitation receipt", async () => {
    const command = {
      type: "session.invitation.create" as const,
      sessionId: SESSION_ID,
      membershipRole: "guest" as const,
      expiresAtMs: 2_000,
      expectedAccessRevision: 1,
    };
    const result = (data: Record<string, unknown>) =>
      jsonResponse({
        result: {
          accepted: true,
          commandType: command.type,
          replayed: false,
          data,
          events: [],
        },
      });
    const fetchMock = vi
      .fn(async (_input: RequestInfo | URL, _init?: RequestInit) => result({}))
      .mockResolvedValueOnce(result({ invitationToken: "one-time-token" }))
      .mockResolvedValueOnce(result({ nested: { invitationToken: "must-not-pass" } }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      submitTeamSessionCommand(command, { idempotencyKey: "web:invitation-safe" })
    ).resolves.toMatchObject({ data: { invitationToken: "one-time-token" } });
    await expect(
      submitTeamSessionCommand(command, { idempotencyKey: "web:invitation-unsafe" })
    ).rejects.toMatchObject({ code: "invalid-response" });
  });
});

function discoveryFixture() {
  return {
    teams: [
      {
        teamId: "team-1",
        name: "Acme",
        createdAtMs: 100,
        viewerMembership: { role: "owner" as const, version: 1 },
        capabilities: { createProject: true, manageMemberships: true },
        projects: [
          {
            projectId: "project-1",
            name: "TerminalX",
            createdAtMs: 101,
            visibility: "content" as const,
            viewerAccess: { role: "maintainer" as const, version: 1 },
            capabilities: { viewContent: true, startSession: true, manageAccess: true },
          },
        ],
      },
    ],
  };
}

function admissionFixture() {
  return {
    sessionId: SESSION_ID,
    accessRevision: 4,
    capabilities: {
      canRevokeInvitations: true,
      canGrantGuestShare: true,
      canGrantProjectAccess: false,
    },
    activeInvitations: [
      {
        invitationId: "invitation-active",
        membershipRole: "guest" as const,
        version: 1,
        expiresAtMs: 2_000,
      },
    ],
    accessCandidates: [
      {
        invitationId: "invitation-guest",
        userId: "guest-1",
        displayName: "Guest One",
        membershipRole: "guest" as const,
        requiredGrant: "session-share" as const,
      },
      {
        invitationId: "invitation-member",
        userId: "member-1",
        displayName: "Member One",
        membershipRole: "member" as const,
        requiredGrant: "project-access" as const,
        expectedProjectAccessVersion: 0,
      },
    ],
  };
}

function inboxFixture() {
  return {
    sessionId: SESSION_ID,
    teamId: "team-1",
    projectId: "project-1",
    name: "Investigate parser",
    status: "active" as const,
    steeringPolicy: "shared" as const,
    runtime: {
      kind: "local-tmux" as const,
      isolation: "trusted-shared-host" as const,
      yoloEligible: false as const,
      authorizationGeneration: 1,
      authorizationState: "enforced" as const,
    },
    responsibilities: {
      assignee: identityFixture("alice"),
      supervisors: [identityFixture("alice")],
      steerers: [identityFixture("alice")],
      controller: identityFixture("alice"),
    },
    viewer: {
      ...identityFixture("alice"),
      membershipRole: "owner" as const,
      responsibilities: ["assignee", "supervisor", "steerer", "controller"] as const,
      basis: {
        participantVersion: 1,
        teamMembershipVersion: 1,
        projectAccessVersion: 1,
        responsibilityVersions: { assignee: 1, supervisor: 1, steerer: 1, controller: 1 },
        accessRevision: 1,
        assigneeRevision: 1,
        supervisionRevision: 1,
        steeringRevision: 1,
        controlRevision: 1,
        controlEpoch: 1,
        runtimeAuthorizationGeneration: 1,
        latestSequence: 3,
      },
      capabilities: Object.fromEntries(
        [
          "addComment",
          "addSuggestion",
          "resolveSuggestion",
          "enqueueDirective",
          "observeTerminal",
          "mutateTerminal",
          "createInvitation",
          "revokeInvitation",
          "manageShares",
          "manageParticipants",
          "manageSupervisors",
          "manageSteerers",
          "transferControl",
          "releaseControl",
          "offerHandoff",
          "acceptHandoff",
          "cancelHandoff",
          "claimAssignee",
        ].map((capability) => [capability, true])
      ),
    },
    latestSequence: 3,
    createdAtMs: 102,
  };
}

function detailFixture() {
  const inbox = inboxFixture();
  return {
    ...inbox,
    viewer: { ...inbox.viewer, responsibilities: [...inbox.viewer.responsibilities] },
    participants: [
      {
        ...identityFixture("alice"),
        membershipRole: "owner" as const,
        observer: false,
        responsibilities: ["assignee", "supervisor", "steerer", "controller"] as const,
        responsibilityVersions: { assignee: 1, supervisor: 1, steerer: 1, controller: 1 },
        joinedAtMs: 102,
        version: 1,
      },
    ],
    shares: [],
    openHandoffs: [],
  };
}

function identityFixture(userId: string) {
  return { participantId: `participant-${userId}`, userId, displayName: "Alice" };
}

function eventFixture(sequence: number): import("@/types/team-session").TeamSessionEvent {
  return {
    schemaVersion: 1 as const,
    eventId: `event-${sequence}`,
    sessionId: SESSION_ID,
    sequence,
    type: "comment.added",
    occurredAtMs: 1_000 + sequence,
    actor: { kind: "human" as const, userId: "alice", displayName: "Alice" },
    sourceAdapter: "web" as const,
    payload: { commentId: `comment-${sequence}`, body: "Safe", apiToken: "[redacted]" },
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return Response.json(body, { status });
}
