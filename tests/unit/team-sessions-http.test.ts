import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  TeamSessionError,
  createTeamSessions,
  type SessionCommand,
  type SessionEvent,
  type TeamSessions,
} from "@/lib/team-sessions";
import {
  deriveHttpIdempotencyKey,
  deriveHttpIdempotencyScope,
  deriveHttpResourceId,
  deriveHttpTmuxName,
  handleProjectAccess,
  handleSessionAdmission,
  handleSessionEvents,
  handleSessionGet,
  handleSessionList,
  handleTeamAccess,
  handleTeamSessionCommand,
  handleWorkspaceDiscovery,
  type TeamSessionHttpDependencies,
} from "@/lib/team-sessions/http";
import type { RequestActor } from "@/lib/request-actor";

const ALICE: RequestActor = {
  kind: "human",
  userId: "user-alice",
  username: "alice",
  displayName: "Alice",
  legacyRole: "user",
};

const BOB: RequestActor = {
  kind: "human",
  userId: "user-bob",
  username: "bob",
  displayName: "Bob",
  legacyRole: "admin",
};

const CALLER_TEAM_ID = "11111111-1111-4111-8111-111111111111";
const CALLER_PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const CALLER_SESSION_ID = "33333333-3333-4333-8333-333333333333";

function actorResolver(actor: RequestActor | null) {
  return async () => actor;
}

function commandRequest(
  body: unknown,
  key = "request-1",
  extraHeaders: Record<string, string> = {}
): Request {
  return new Request("https://terminalx.test/api/team-sessions/commands", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": key,
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  });
}

function getRequest(pathname: string): Request {
  return new Request(`https://terminalx.test${pathname}`);
}

async function responseBody(response: Response): Promise<Record<string, unknown>> {
  return (await response.json()) as Record<string, unknown>;
}

async function acceptedData(response: Response): Promise<Record<string, unknown>> {
  expect(response.status).toBe(200);
  const body = await responseBody(response);
  return (body.result as { data: Record<string, unknown> }).data;
}

describe("Team Session HTTP adapter", () => {
  let directory: string;
  let teamSessions: TeamSessions;
  let dependencies: TeamSessionHttpDependencies;
  let teamId: string;
  let projectId: string;
  let sessionId: string;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-team-http-"));
    teamSessions = createTeamSessions({
      filename: path.join(directory, "team-sessions.sqlite"),
      clock: () => 2_000_000_000_000,
    });
    dependencies = {
      teamSessions,
      resolveActor: actorResolver(ALICE),
    };
    process.env.TERMINALX_AUTH_MODE = "local";
  });

  afterEach(() => {
    teamSessions.close();
    fs.rmSync(directory, { recursive: true, force: true });
    delete process.env.TERMINALX_AUTH_MODE;
    delete process.env.TERMINALX_TRUST_PROXY_HEADERS;
    delete process.env.TERMINALX_PUBLIC_URL;
    delete process.env.TERMINALX_ALLOW_AUTH_NONE;
  });

  async function post(body: unknown, key?: string, actor = ALICE): Promise<Response> {
    return handleTeamSessionCommand(commandRequest(body, key), {
      ...dependencies,
      resolveActor: actorResolver(actor),
    });
  }

  async function bootstrap(): Promise<void> {
    const team = await acceptedData(
      await post(
        {
          type: "team.create",
          name: "Acme",
        },
        "create-team"
      )
    );
    teamId = team.teamId as string;

    const project = await acceptedData(
      await post(
        {
          type: "project.create",
          teamId,
          name: "Terminal X",
        },
        "create-project"
      )
    );
    projectId = project.projectId as string;

    const session = await acceptedData(
      await post(
        {
          type: "session.start",
          teamId,
          projectId,
          name: "Multiplayer",
          steeringPolicy: "shared",
        },
        "start-session"
      )
    );
    sessionId = session.sessionId as string;
  }

  it("ignores spoofed identity headers and requires a freshly verified credential", async () => {
    const response = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Spoofed" }, "spoofed", {
        "x-user-id": "attacker",
        "x-username": "admin",
        "x-user-role": "admin",
      }),
      { teamSessions }
    );

    expect(response.status).toBe(401);
    expect(await responseBody(response)).toEqual({
      error: { code: "authentication-required", message: "Authentication required" },
    });
  });

  it("fails closed in auth-none mode unless the separate development opt-in is explicit", async () => {
    process.env.TERMINALX_AUTH_MODE = "none";

    const denied = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Denied" }, "auth-none-denied"),
      { teamSessions }
    );
    expect(denied.status).toBe(401);

    process.env.TERMINALX_ALLOW_AUTH_NONE = "true";
    const allowed = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Allowed" }, "auth-none-allowed"),
      { teamSessions }
    );
    expect(allowed.status).toBe(200);

    process.env.TERMINALX_AUTH_MODE = "typo";
    const typo = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Typo" }, "auth-typo"),
      { teamSessions }
    );
    expect(typo.status).toBe(401);
  });

  it("does not mutate canonical Team Session state in global read-only mode", async () => {
    const response = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Blocked" }, "read-only"),
      { ...dependencies, isReadOnly: () => true }
    );

    expect(response.status).toBe(403);
    expect(await responseBody(response)).toEqual({
      error: { code: "read-only", message: "Server is read-only" },
    });
    await expect(
      teamSessions.inspect({
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        type: "session.list",
        actor: { kind: "human", userId: ALICE.userId, displayName: ALICE.displayName },
      })
    ).resolves.toEqual([]);
  });

  it("keeps actor, schema, and idempotency envelope fields server-owned", async () => {
    for (const reserved of ["actor", "schemaVersion", "idempotency"]) {
      const response = await post(
        {
          type: "team.create",
          name: "Acme",
          [reserved]: reserved === "schemaVersion" ? 999 : { userId: "attacker" },
        },
        `reserved-${reserved}`
      );
      expect(response.status).toBe(400);
      expect(await responseBody(response)).toEqual({
        error: {
          code: "reserved-command-field",
          message: "Request contains a server-owned command field",
        },
      });
    }

    const metadata = await post(
      {
        type: "team.create",
        name: "Acme",
        metadata: {
          actor: "historical author",
          token: "must-not-reach-the-audit-ledger",
        },
      },
      "unknown-metadata"
    );
    expect(metadata.status).toBe(400);
    expect(await responseBody(metadata)).toEqual({
      error: {
        code: "unknown-command-field",
        message: "Request contains an unknown command field",
      },
    });

    const accepted = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Acme" }, "real-actor", {
        "x-user-id": BOB.userId,
        "x-user-role": "admin",
      }),
      dependencies
    );
    expect(accepted.status).toBe(200);
    const acceptedBody = await responseBody(accepted);
    expect(acceptedBody.result).not.toHaveProperty("acceptedSequence");
    const createdTeamId = (acceptedBody.result as { data: { teamId: string } }).data.teamId;

    const projection = await handleTeamAccess(
      getRequest(`/api/team-sessions/teams/${createdTeamId}/access`),
      createdTeamId,
      dependencies
    );
    const body = await responseBody(projection);
    expect(body.team).toMatchObject({
      memberships: [{ userId: ALICE.userId, role: "owner" }],
    });
  });

  it("rejects caller-selected global resource IDs and tmux names", async () => {
    const attempts = [
      {
        body: { type: "team.create", teamId: CALLER_TEAM_ID, name: "Caller team" },
        key: "caller-team-id",
      },
      {
        body: {
          type: "project.create",
          teamId: CALLER_TEAM_ID,
          projectId: CALLER_PROJECT_ID,
          name: "Caller project",
        },
        key: "caller-project-id",
      },
      {
        body: {
          type: "session.start",
          teamId: CALLER_TEAM_ID,
          projectId: CALLER_PROJECT_ID,
          sessionId: CALLER_SESSION_ID,
          name: "Caller Session",
        },
        key: "caller-session-id",
      },
      {
        body: {
          type: "session.start",
          teamId: CALLER_TEAM_ID,
          projectId: CALLER_PROJECT_ID,
          name: "Caller tmux",
          tmuxName: "caller-selected-tmux",
        },
        key: "caller-tmux-name",
      },
    ];

    for (const attempt of attempts) {
      const response = await post(attempt.body, attempt.key);
      expect(response.status).toBe(400);
      expect(await responseBody(response)).toEqual({
        error: {
          code: "unknown-command-field",
          message: "Request contains an unknown command field",
        },
      });
    }
  });

  it("admits only the public conversation command fields and keeps item IDs server-owned", async () => {
    const dispatched: SessionCommand[] = [];
    const captureSessions = {
      dispatch: async (command: SessionCommand) => {
        dispatched.push(command);
        return {
          accepted: true,
          acceptedSequence: dispatched.length,
          commandType: command.type,
          replayed: false,
          data: {},
          events: [],
        };
      },
    } as unknown as TeamSessions;
    const conversationDependencies = { ...dependencies, teamSessions: captureSessions };
    const commands = [
      { type: "comment.add", sessionId: CALLER_SESSION_ID, body: "Please check this." },
      { type: "suggestion.add", sessionId: CALLER_SESSION_ID, body: "Run the tests." },
      {
        type: "suggestion.resolve",
        sessionId: CALLER_SESSION_ID,
        suggestionId: "suggestion-1",
        resolution: "accept",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: 2,
      },
      {
        type: "suggestion.resolve",
        sessionId: CALLER_SESSION_ID,
        suggestionId: "suggestion-2",
        resolution: "reject",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: 2,
      },
      {
        type: "suggestion.resolve",
        sessionId: CALLER_SESSION_ID,
        suggestionId: "suggestion-3",
        resolution: "accept-edited",
        editedBody: "Run only the focused tests.",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: 2,
      },
      {
        type: "directive.enqueue",
        sessionId: CALLER_SESSION_ID,
        body: "Continue with the focused tests.",
        expectedSteeringRevision: 2,
      },
    ] as const;

    for (const [index, command] of commands.entries()) {
      const response = await handleTeamSessionCommand(
        commandRequest(command, `conversation-command-${index}`),
        conversationDependencies
      );
      expect(response.status).toBe(200);
    }

    expect(dispatched).toHaveLength(commands.length);
    for (const [index, command] of commands.entries()) {
      expect(dispatched[index]).toMatchObject({
        ...command,
        schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
        actor: { kind: "human", userId: ALICE.userId, displayName: ALICE.displayName },
      });
    }
    expect(dispatched[0]).not.toHaveProperty("commentId");
    expect(dispatched[1]).not.toHaveProperty("suggestionId");
    expect(dispatched[5]).not.toHaveProperty("directiveId");
  });

  it("projects response events and exposes only the intentional one-time invitation token", async () => {
    const sourceEvent: SessionEvent = {
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      eventId: "event-command-response",
      sessionId: CALLER_SESSION_ID,
      sequence: 7,
      type: "comment.added",
      occurredAtMs: 2_000_000_000_000,
      actor: { kind: "human", userId: ALICE.userId, displayName: ALICE.displayName },
      source: { scope: "private:adapter", key: "private-idempotency-key" },
      payload: {
        commentId: "comment-1",
        body: "A visible comment",
        apiToken: "must-not-leak-from-event",
      },
    };
    const commandSessions = {
      dispatch: async (command: SessionCommand) => ({
        accepted: true,
        acceptedSequence: 7,
        commandType: command.type,
        replayed: false,
        data: {
          invitationId: "invitation-1",
          sessionId: CALLER_SESSION_ID,
          invitationToken: "intentional-one-time-token",
          invitationVersion: 1,
          accessRevision: 2,
          runtimeOutboxId: "must-not-leak-from-result-data",
          internalCredential: "must-not-leak-from-result-data",
        },
        events: [sourceEvent],
        internalDiagnostics: "must-not-leak-from-result-envelope",
      }),
    } as unknown as TeamSessions;

    const response = await handleTeamSessionCommand(
      commandRequest(
        {
          type: "session.invitation.create",
          sessionId: CALLER_SESSION_ID,
          membershipRole: "guest",
          expiresAtMs: 2_000_000_060_000,
          expectedAccessRevision: 1,
        },
        "project-command-events"
      ),
      { ...dependencies, teamSessions: commandSessions }
    );
    const body = await responseBody(response);
    const result = body.result as Record<string, unknown>;
    const [event] = result.events as Array<Record<string, unknown>>;

    expect(response.status).toBe(200);
    expect(result.data).toEqual({
      invitationId: "invitation-1",
      sessionId: CALLER_SESSION_ID,
      invitationToken: "intentional-one-time-token",
      invitationVersion: 1,
      accessRevision: 2,
    });
    expect(result).not.toHaveProperty("internalDiagnostics");
    expect(JSON.stringify(result)).not.toContain("must-not-leak-from-result");
    expect(event).toMatchObject({
      eventId: sourceEvent.eventId,
      actor: sourceEvent.actor,
      sourceAdapter: "internal",
      payload: { commentId: "comment-1", body: "A visible comment" },
    });
    expect(event?.payload).not.toHaveProperty("apiToken");
    expect(event).not.toHaveProperty("source");
    expect(sourceEvent.payload.apiToken).toBe("must-not-leak-from-event");
  });

  it("keeps runtime and unknown kernel receipt fields behind the HTTP boundary", async () => {
    const commandSessions = {
      dispatch: async (command: SessionCommand) => ({
        accepted: true,
        acceptedSequence: 8,
        commandType: command.type,
        replayed: false,
        data: {
          sessionId: CALLER_SESSION_ID,
          runtimeOutboxId: "outbox-private",
          tmuxName: "tmux-private",
          runtimeLease: { workerId: "worker-private" },
          privateKey: "private-key-material",
        },
        events: [],
      }),
    } as unknown as TeamSessions;

    const response = await handleTeamSessionCommand(
      commandRequest(
        {
          type: "session.start",
          teamId: CALLER_TEAM_ID,
          projectId: CALLER_PROJECT_ID,
          name: "Boundary test",
          steeringPolicy: "single",
        },
        "project-session-start-receipt"
      ),
      { ...dependencies, teamSessions: commandSessions }
    );
    const result = (await responseBody(response)).result as {
      data: Record<string, unknown>;
    };

    expect(response.status).toBe(200);
    expect(result.data).toEqual({ sessionId: CALLER_SESSION_ID });
    expect(JSON.stringify(result)).not.toMatch(
      /runtimeOutboxId|tmux-private|worker-private|private-key/
    );
  });

  it("fails closed when an allowlisted receipt field is not a finite scalar", async () => {
    const malformedValues: unknown[] = [
      { token: "nested-secret" },
      ["array-secret"],
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
    ];
    const reportedErrors: string[] = [];

    for (const [index, malformedValue] of malformedValues.entries()) {
      const commandSessions = {
        dispatch: async (command: SessionCommand) => ({
          accepted: true,
          acceptedSequence: 9 + index,
          commandType: command.type,
          replayed: false,
          data: { sessionId: malformedValue },
          events: [],
        }),
      } as unknown as TeamSessions;
      const response = await handleTeamSessionCommand(
        commandRequest(
          {
            type: "session.start",
            teamId: CALLER_TEAM_ID,
            projectId: CALLER_PROJECT_ID,
            name: "Malformed receipt test",
            steeringPolicy: "single",
          },
          `malformed-session-start-receipt-${index}`
        ),
        {
          ...dependencies,
          teamSessions: commandSessions,
          reportInternalError: (errorName) => reportedErrors.push(errorName),
        }
      );
      const body = await responseBody(response);

      expect(response.status).toBe(500);
      expect(body).toEqual({
        error: { code: "internal-error", message: "Internal server error" },
      });
      expect(JSON.stringify(body)).not.toMatch(/nested-secret|array-secret/);
    }

    expect(reportedErrors).toEqual(malformedValues.map(() => "InternalError"));
  });

  it("never returns an invitation token from a replayed command receipt", async () => {
    const commandSessions = {
      dispatch: async (command: SessionCommand) => ({
        accepted: true,
        acceptedSequence: 9,
        commandType: command.type,
        replayed: true,
        data: {
          invitationId: "invitation-1",
          sessionId: CALLER_SESSION_ID,
          invitationToken: "must-not-replay",
          invitationVersion: 1,
          accessRevision: 2,
          invitationTokenUnavailable: true,
          recoveryAction: "revoke-and-reissue",
          runtimeOutboxId: "also-private",
        },
        events: [],
      }),
    } as unknown as TeamSessions;

    const response = await handleTeamSessionCommand(
      commandRequest(
        {
          type: "session.invitation.create",
          sessionId: CALLER_SESSION_ID,
          membershipRole: "guest",
          expiresAtMs: 2_000_000_060_000,
          expectedAccessRevision: 1,
        },
        "project-invitation-replay-receipt"
      ),
      { ...dependencies, teamSessions: commandSessions }
    );

    expect(response.status).toBe(200);
    expect(
      ((await responseBody(response)).result as { data: Record<string, unknown> }).data
    ).toEqual({
      invitationId: "invitation-1",
      sessionId: CALLER_SESSION_ID,
      invitationVersion: 1,
      accessRevision: 2,
      invitationTokenUnavailable: true,
      recoveryAction: "revoke-and-reissue",
    });
  });

  it("rejects client conversation IDs, source data, and invalid suggestion resolution edits", async () => {
    const invalidCommands = [
      {
        type: "comment.add",
        sessionId: CALLER_SESSION_ID,
        body: "Comment",
        commentId: "caller-comment",
      },
      {
        type: "suggestion.add",
        sessionId: CALLER_SESSION_ID,
        body: "Suggestion",
        suggestionId: "caller-suggestion",
      },
      {
        type: "directive.enqueue",
        sessionId: CALLER_SESSION_ID,
        body: "Directive",
        expectedSteeringRevision: 2,
        directiveId: "caller-directive",
      },
      {
        type: "comment.add",
        sessionId: CALLER_SESSION_ID,
        body: "Comment",
        source: { scope: "caller", key: "caller" },
      },
      {
        type: "suggestion.resolve",
        sessionId: CALLER_SESSION_ID,
        suggestionId: "suggestion-1",
        resolution: "accept",
        editedBody: "Not allowed",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: 2,
      },
      {
        type: "suggestion.resolve",
        sessionId: CALLER_SESSION_ID,
        suggestionId: "suggestion-1",
        resolution: "reject",
        editedBody: "Not allowed",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: 2,
      },
      {
        type: "suggestion.resolve",
        sessionId: CALLER_SESSION_ID,
        suggestionId: "suggestion-1",
        resolution: "accept-edited",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: 2,
      },
      {
        type: "suggestion.resolve",
        sessionId: CALLER_SESSION_ID,
        suggestionId: "suggestion-1",
        resolution: "merge",
        expectedSuggestionVersion: 1,
        expectedSteeringRevision: 2,
      },
    ];

    for (const [index, command] of invalidCommands.entries()) {
      const response = await post(command, `invalid-conversation-command-${index}`);
      expect(response.status).toBe(400);
    }
  });

  it("derives deterministic, domain-separated UUIDs and valid opaque tmux names", () => {
    const internalKey = deriveHttpIdempotencyKey("same-request");
    const ids = {
      team: deriveHttpResourceId("team", ALICE.userId, internalKey),
      project: deriveHttpResourceId("project", ALICE.userId, internalKey),
      session: deriveHttpResourceId("session", ALICE.userId, internalKey),
    };
    const uuidV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

    expect(new Set(Object.values(ids)).size).toBe(3);
    for (const id of Object.values(ids)) expect(id).toMatch(uuidV4);
    expect(deriveHttpResourceId("session", ALICE.userId, internalKey)).toBe(ids.session);
    expect(deriveHttpResourceId("session", BOB.userId, internalKey)).not.toBe(ids.session);

    const tmuxName = deriveHttpTmuxName(ids.session);
    expect(tmuxName).toMatch(/^txs-[0-9a-f]{32}$/);
    expect(deriveHttpTmuxName(ids.session)).toBe(tmuxName);
    expect(deriveHttpTmuxName(ids.project)).not.toBe(tmuxName);
  });

  it("replays every public create with the same generated identifiers", async () => {
    await bootstrap();

    const teamReplay = (
      await responseBody(await post({ type: "team.create", name: "Acme" }, "create-team"))
    ).result as { replayed: boolean; data: { teamId: string } };
    const projectReplay = (
      await responseBody(
        await post({ type: "project.create", teamId, name: "Terminal X" }, "create-project")
      )
    ).result as { replayed: boolean; data: { projectId: string } };
    const sessionReplay = (
      await responseBody(
        await post(
          {
            type: "session.start",
            teamId,
            projectId,
            name: "Multiplayer",
            steeringPolicy: "shared",
          },
          "start-session"
        )
      )
    ).result as { replayed: boolean; data: { sessionId: string } };

    expect(teamReplay).toMatchObject({ replayed: true, data: { teamId } });
    expect(projectReplay).toMatchObject({ replayed: true, data: { projectId } });
    expect(sessionReplay).toMatchObject({ replayed: true, data: { sessionId } });
  });

  it.each([
    "run.start",
    "run.policy.revise",
    "run.pause",
    "run.resume",
    "run.stop",
    "run.emergency-stop",
    "goal.add",
    "goal.criteria.strengthen",
    "goal.dependency.add",
    "goal.reorder",
    "goal.evidence.review",
    "run.final-review.resolve",
    "approval.resolve",
    "grant.revoke",
    "grant.review.resolve",
    "attention.resolve",
  ])("keeps the %s mutation outside generic HTTP", async (type) => {
    const response = await post({ type }, `gated-${type}`);

    expect(response.status).toBe(400);
    expect(await responseBody(response)).toEqual({
      error: { code: "unsupported-command", message: "Command type is not supported" },
    });
  });

  it("rejects runtime-worker commands and structurally unknown Handoff briefing data", async () => {
    const runtimeCommand = await post(
      {
        type: "runtime.outbox.acknowledge",
        outboxId: "outbox-1",
        workerId: "attacker-worker",
        expectedAttempt: 1,
      },
      "runtime-command"
    );
    expect(runtimeCommand.status).toBe(400);
    expect(await responseBody(runtimeCommand)).toEqual({
      error: { code: "unsupported-command", message: "Command type is not supported" },
    });

    const unknownBriefing = await post(
      {
        type: "session.handoff.offer",
        sessionId: CALLER_SESSION_ID,
        recipientParticipantId: "participant-1",
        expectedAssigneeRevision: 1,
        expectedRecipientParticipantVersion: 1,
        expectedOffererResponsibilityVersion: 1,
        briefing: {
          summary: "Safe summary",
          token: "must-not-reach-the-audit-ledger",
        },
      },
      "unknown-briefing"
    );
    expect(unknownBriefing.status).toBe(400);
    expect(await responseBody(unknownBriefing)).toEqual({
      error: {
        code: "unknown-briefing-field",
        message: "Handoff briefing has an unknown field",
      },
    });

    const malformedBriefing = await post(
      {
        type: "session.handoff.offer",
        sessionId: CALLER_SESSION_ID,
        recipientParticipantId: "participant-1",
        expectedAssigneeRevision: 1,
        expectedRecipientParticipantVersion: 1,
        expectedOffererResponsibilityVersion: 1,
        briefing: {
          summary: "Safe summary",
          blockers: ["expected string", { token: "not-a-string" }],
        },
      },
      "malformed-briefing"
    );
    expect(malformedBriefing.status).toBe(400);
    expect(await responseBody(malformedBriefing)).toEqual({
      error: { code: "invalid-briefing", message: "Handoff briefing is invalid" },
    });
  });

  it("requires a bounded, unambiguous Idempotency-Key", async () => {
    const missing = commandRequest({ type: "team.create", name: "Acme" });
    missing.headers.delete("idempotency-key");
    const missingResponse = await handleTeamSessionCommand(missing, dependencies);
    expect(missingResponse.status).toBe(400);
    expect(await responseBody(missingResponse)).toEqual({
      error: { code: "idempotency-key-required", message: "Idempotency-Key is required" },
    });

    for (const invalidKey of ["two words", "x".repeat(129), "one,two"]) {
      const response = await post({ type: "team.create", name: "Acme" }, invalidKey);
      expect(response.status).toBe(400);
      expect((await responseBody(response)).error).toEqual({
        code: "invalid-idempotency-key",
        message: "Idempotency-Key is invalid",
      });
    }
  });

  it("replays identical commands and rejects key reuse for a different payload", async () => {
    const command = { type: "team.create", name: "Acme" };
    const first = await post(command, "stable-request");
    const replay = await post(command, "stable-request");
    const conflict = await post({ ...command, name: "Different" }, "stable-request");

    expect(first.status).toBe(200);
    expect(replay.status).toBe(200);
    const firstResult = (await responseBody(first)).result as {
      replayed: boolean;
      data: { teamId: string };
    };
    const replayResult = (await responseBody(replay)).result as {
      replayed: boolean;
      data: { teamId: string };
    };
    expect(firstResult.replayed).toBe(false);
    expect(replayResult.replayed).toBe(true);
    expect(replayResult.data.teamId).toBe(firstResult.data.teamId);
    expect(conflict.status).toBe(409);
    expect(await responseBody(conflict)).toEqual({
      error: {
        code: "idempotency-conflict",
        message: "The idempotency key was already used for another request",
      },
    });
  });

  it("derives a stable, actor-separated idempotency scope", async () => {
    expect(deriveHttpIdempotencyScope(ALICE.userId)).toBe(deriveHttpIdempotencyScope(ALICE.userId));
    expect(deriveHttpIdempotencyScope(ALICE.userId)).not.toBe(
      deriveHttpIdempotencyScope(BOB.userId)
    );

    const alice = await post({ type: "team.create", name: "Alice team" }, "same-key", ALICE);
    const bob = await post(
      {
        type: "team.create",
        name: "Bob team",
      },
      "same-key",
      BOB
    );
    expect(alice.status).toBe(200);
    expect(bob.status).toBe(200);
    const aliceId = ((await responseBody(alice)).result as { data: { teamId: string } }).data
      .teamId;
    const bobId = ((await responseBody(bob)).result as { data: { teamId: string } }).data.teamId;
    expect(aliceId).not.toBe(bobId);
  });

  it("hashes external idempotency keys before they enter results or the event ledger", async () => {
    const externalKey = "caller-secret-looking-key";
    const response = await post({ type: "team.create", name: "Hashed key" }, externalKey);
    const serialized = JSON.stringify(await responseBody(response));
    const database = new Database(path.join(directory, "team-sessions.sqlite"), {
      readonly: true,
    });
    const ledger = database
      .prepare(
        `SELECT source_key, payload_json, result_json
           FROM accepted_commands
          WHERE command_type = 'team.create'`
      )
      .get() as { source_key: string; payload_json: string; result_json: string };
    database.close();

    expect(response.status).toBe(200);
    expect(serialized).not.toContain(externalKey);
    expect(ledger.source_key).toBe(deriveHttpIdempotencyKey(externalKey));
    expect(JSON.stringify(ledger)).not.toContain(externalKey);
    expect(deriveHttpIdempotencyKey(externalKey)).toBe(deriveHttpIdempotencyKey(externalKey));
    expect(deriveHttpIdempotencyKey(externalKey)).not.toBe(externalKey);
  });

  it("enforces same-origin requests for cookie mutations and permits bearer-only clients", async () => {
    const body = {
      type: "team.create",
      name: "Acme",
    };
    const missingOrigin = await handleTeamSessionCommand(
      commandRequest(body, "cookie-missing-origin", {
        cookie: "terminalx-session=current-token",
        host: "terminalx.test",
      }),
      dependencies
    );
    const foreignOrigin = await handleTeamSessionCommand(
      commandRequest(body, "cookie-foreign-origin", {
        cookie: "terminalx-session=current-token",
        host: "terminalx.test",
        origin: "https://evil.test",
      }),
      dependencies
    );
    expect(missingOrigin.status).toBe(403);
    expect(foreignOrigin.status).toBe(403);
    expect(await responseBody(foreignOrigin)).toEqual({
      error: { code: "cross-origin-request", message: "Cross-origin request denied" },
    });

    const sameOrigin = await handleTeamSessionCommand(
      commandRequest(body, "cookie-same-origin", {
        cookie: "terminalx-session=current-token",
        host: "terminalx.test",
        origin: "https://terminalx.test",
      }),
      dependencies
    );
    expect(sameOrigin.status).toBe(200);

    const bearerOnly = await handleTeamSessionCommand(
      commandRequest(
        {
          type: "team.create",
          name: "API team",
        },
        "bearer-without-origin",
        { authorization: "Bearer api-token" }
      ),
      dependencies
    );
    expect(bearerOnly.status).toBe(200);
  });

  it("trusts forwarding headers only behind the explicit proxy boundary", async () => {
    const direct = await handleTeamSessionCommand(
      commandRequest(
        {
          type: "team.create",
          name: "Direct team",
        },
        "untrusted-forwarding",
        {
          cookie: "terminalx-session=current-token",
          host: "terminalx.test",
          origin: "https://terminalx.test",
          "x-forwarded-host": "evil.test",
          "x-forwarded-proto": "http",
        }
      ),
      dependencies
    );
    expect(direct.status).toBe(200);

    process.env.TERMINALX_TRUST_PROXY_HEADERS = "true";
    const proxied = new Request("http://127.0.0.1/api/team-sessions/commands", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": "trusted-forwarding",
        cookie: "terminalx-session=current-token",
        host: "127.0.0.1",
        origin: "https://terminalx.example",
        "x-forwarded-host": "terminalx.example",
        "x-forwarded-proto": "https",
      },
      body: JSON.stringify({
        type: "team.create",
        name: "Proxied team",
      }),
    });
    expect((await handleTeamSessionCommand(proxied, dependencies)).status).toBe(200);
  });

  it("enforces the body limit from streamed bytes even when Content-Length is absent or false", async () => {
    const request = commandRequest(
      { type: "team.create", name: "A name larger than the limit" },
      "stream-limit",
      { "content-length": "1" }
    );
    const response = await handleTeamSessionCommand(request, {
      ...dependencies,
      maxBodyBytes: 32,
    });

    expect(response.status).toBe(413);
    expect(await responseBody(response)).toEqual({
      error: { code: "request-too-large", message: "Request body is too large" },
    });
  });

  it("rejects malformed, non-object, deeply nested, and non-JSON request bodies", async () => {
    const malformed = new Request("https://terminalx.test/api/team-sessions/commands", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": "malformed",
      },
      body: "{",
    });
    expect((await handleTeamSessionCommand(malformed, dependencies)).status).toBe(400);
    expect((await post([], "array-body")).status).toBe(400);

    let nested: Record<string, unknown> = { leaf: true };
    for (let index = 0; index < 34; index += 1) nested = { nested };
    const deep = await post({ type: "team.create", nested }, "deep-body");
    expect(deep.status).toBe(400);

    const wrongMediaType = new Request("https://terminalx.test/api/team-sessions/commands", {
      method: "POST",
      headers: {
        "content-type": "text/plain",
        "idempotency-key": "wrong-media",
      },
      body: "{}",
    });
    expect((await handleTeamSessionCommand(wrongMediaType, dependencies)).status).toBe(415);
  });

  it("returns minimized discovery, inbox, detail, events, and administrative projections", async () => {
    await bootstrap();

    const discovery = await handleWorkspaceDiscovery(
      getRequest("/api/team-sessions/discovery"),
      dependencies
    );
    const list = await handleSessionList(
      getRequest(`/api/team-sessions?teamId=${teamId}`),
      dependencies
    );
    const get = await handleSessionGet(
      getRequest(`/api/team-sessions/sessions/${sessionId}`),
      sessionId,
      dependencies
    );
    const events = await handleSessionEvents(
      getRequest(`/api/team-sessions/sessions/${sessionId}/events?afterSequence=0&limit=10`),
      sessionId,
      dependencies
    );
    const admission = await handleSessionAdmission(
      getRequest(`/api/team-sessions/sessions/${sessionId}/admission`),
      sessionId,
      dependencies
    );
    const team = await handleTeamAccess(
      getRequest(`/api/team-sessions/teams/${teamId}/access`),
      teamId,
      dependencies
    );
    const project = await handleProjectAccess(
      getRequest(`/api/team-sessions/projects/${projectId}/access`),
      projectId,
      dependencies
    );

    expect((await responseBody(list)).sessions).toEqual([
      expect.objectContaining({ sessionId, steeringPolicy: "shared" }),
    ]);
    expect((await responseBody(discovery)).discovery).toMatchObject({
      teams: [
        {
          teamId,
          name: "Acme",
          createdAtMs: 2_000_000_000_000,
          viewerMembership: { role: "owner", version: 1 },
          capabilities: { createProject: true, manageMemberships: true },
          projects: [
            expect.objectContaining({
              projectId,
              visibility: "content",
              capabilities: { viewContent: true, startSession: true, manageAccess: true },
            }),
          ],
        },
      ],
    });
    const publicSession = (await responseBody(get)).session as Record<string, unknown>;
    expect(publicSession).toMatchObject({
      sessionId,
      projectId,
      runtime: {
        kind: "local-tmux",
        authorizationGeneration: 1,
        authorizationState: "pending",
      },
      viewer: {
        userId: ALICE.userId,
        displayName: ALICE.displayName,
        capabilities: { addComment: true, enqueueDirective: true, mutateTerminal: false },
      },
    });
    const serializedPublicSession = JSON.stringify(publicSession);
    expect(serializedPublicSession).not.toContain(deriveHttpTmuxName(sessionId));
    expect(serializedPublicSession).not.toContain("tmuxName");
    expect(serializedPublicSession).not.toContain("invitations");
    expect(serializedPublicSession).not.toContain("revokedAtMs");
    expect((await responseBody(events)).events).toEqual([
      expect.objectContaining({
        sessionId,
        type: "session.started",
        sourceAdapter: "web",
      }),
    ]);
    expect((await responseBody(admission)).admission).toMatchObject({
      sessionId,
      accessRevision: 1,
    });
    expect((await responseBody(team)).team).toMatchObject({ teamId, name: "Acme" });
    expect((await responseBody(project)).project).toMatchObject({
      projectId,
      teamId,
    });
    for (const response of [discovery, list, get, events, admission, team, project]) {
      expect(response.headers.get("cache-control")).toBe("private, no-store");
      expect(response.headers.get("vary")).toBe("Cookie, Authorization");
    }
  });

  it("returns only the explicit conversation payload projection over HTTP", async () => {
    let deep: unknown = { visible: "too-deep" };
    for (let index = 0; index < 18; index += 1) deep = { nested: deep };
    const many = Object.fromEntries(
      Array.from({ length: 1_100 }, (_entry, index) => [`field${index}`, index])
    );
    const sourceEvent: SessionEvent = {
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      eventId: "event-public-projection",
      sessionId: CALLER_SESSION_ID,
      sequence: 42,
      type: "suggestion.added",
      occurredAtMs: 2_000_000_000_000,
      actor: { kind: "human", userId: ALICE.userId, displayName: ALICE.displayName },
      source: { scope: "private:adapter", key: "private-idempotency-key" },
      payload: {
        suggestionId: "suggestion-public",
        suggestionVersion: 3,
        body: "Review the parser boundary",
        visible: "ok",
        invitationId: "private-invitation-id",
        accessRevision: 99,
        apiToken: "must-not-leak",
        apiKey: "must-not-leak",
        encryptionKey: "must-not-leak",
        mnemonic: "must-not-leak",
        recoveryPhrase: "must-not-leak",
        authorization: "must-not-leak",
        nested: [{ privateKey: "must-not-leak", safe: true }],
        runtimeAuthorizationGeneration: 12,
        deep,
        many,
      },
    };
    const eventSessions = {
      inspect: async () => [sourceEvent],
    } as unknown as TeamSessions;

    const response = await handleSessionEvents(
      getRequest(`/api/team-sessions/sessions/${CALLER_SESSION_ID}/events`),
      CALLER_SESSION_ID,
      { ...dependencies, teamSessions: eventSessions }
    );
    const responseJson = await responseBody(response);
    const [event] = responseJson.events as Array<Record<string, unknown>>;
    const payload = event?.payload as Record<string, unknown>;

    expect(response.status).toBe(200);
    expect(Object.keys(event ?? {}).sort()).toEqual([
      "actor",
      "eventId",
      "occurredAtMs",
      "payload",
      "schemaVersion",
      "sequence",
      "sessionId",
      "sourceAdapter",
      "type",
    ]);
    expect(event).toMatchObject({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      eventId: sourceEvent.eventId,
      sessionId: CALLER_SESSION_ID,
      sequence: 42,
      type: sourceEvent.type,
      occurredAtMs: sourceEvent.occurredAtMs,
      actor: sourceEvent.actor,
      sourceAdapter: "internal",
      payload: {
        suggestionId: "suggestion-public",
        suggestionVersion: 3,
        body: "Review the parser boundary",
      },
    });
    expect(event).not.toHaveProperty("source");
    expect(payload).toEqual({
      suggestionId: "suggestion-public",
      suggestionVersion: 3,
      body: "Review the parser boundary",
    });
    expect(JSON.stringify(event)).not.toContain("private-invitation-id");
    expect(JSON.stringify(event)).not.toContain("must-not-leak");
    expect(JSON.stringify(event)).not.toContain("accessRevision");
    expect(sourceEvent.payload).toMatchObject({
      apiToken: "must-not-leak",
      nested: [{ privateKey: "must-not-leak" }],
    });
  });

  it("keeps private Session misses and higher-scope access uniformly unavailable", async () => {
    await bootstrap();
    const bobDependencies = { ...dependencies, resolveActor: actorResolver(BOB) };

    const discovery = await handleWorkspaceDiscovery(
      getRequest("/api/team-sessions/discovery"),
      bobDependencies
    );
    const list = await handleSessionList(getRequest("/api/team-sessions"), bobDependencies);
    const get = await handleSessionGet(
      getRequest(`/api/team-sessions/sessions/${sessionId}`),
      sessionId,
      bobDependencies
    );
    const events = await handleSessionEvents(
      getRequest(`/api/team-sessions/sessions/${sessionId}/events`),
      sessionId,
      bobDependencies
    );
    const team = await handleTeamAccess(
      getRequest(`/api/team-sessions/teams/${teamId}/access`),
      teamId,
      bobDependencies
    );

    expect(await responseBody(discovery)).toEqual({
      discovery: { teams: [] },
    });
    expect(discovery.headers.get("cache-control")).toBe("private, no-store");
    expect(await responseBody(list)).toEqual({ sessions: [] });
    expect(await responseBody(events)).toEqual({ events: [] });
    for (const response of [get, team]) {
      expect(response.status).toBe(404);
      expect(await responseBody(response)).toEqual({
        error: { code: "resource-unavailable", message: "Resource is unavailable" },
      });
    }
  });

  it("redacts kernel details and unexpected adapter errors", async () => {
    const privateKernelError = {
      dispatch: async () => {
        throw new TeamSessionError(
          "invalid-command",
          "private token txi_secret and /srv/private/path"
        );
      },
    } as unknown as TeamSessions;
    const kernelResponse = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Acme" }, "kernel-error"),
      { ...dependencies, teamSessions: privateKernelError }
    );
    expect(kernelResponse.status).toBe(400);
    expect(JSON.stringify(await responseBody(kernelResponse))).not.toContain("txi_secret");
    expect(
      await responseBody(
        await handleTeamSessionCommand(
          commandRequest({ type: "team.create", name: "Acme" }, "kernel-error-2"),
          { ...dependencies, teamSessions: privateKernelError }
        )
      )
    ).toEqual({ error: { code: "invalid-request", message: "Invalid request" } });

    const reported: string[] = [];
    const poisoned = new Error("secret provider output and /home/private/key");
    poisoned.name = "SECRET_FROM_PROVIDER\nFORGED_LOG";
    const unexpectedError = {
      dispatch: async () => {
        throw poisoned;
      },
    } as unknown as TeamSessions;
    const internalResponse = await handleTeamSessionCommand(
      commandRequest({ type: "team.create", name: "Acme" }, "internal-error"),
      {
        ...dependencies,
        teamSessions: unexpectedError,
        reportInternalError: (name) => reported.push(name),
      }
    );
    const serialized = JSON.stringify(await responseBody(internalResponse));
    expect(internalResponse.status).toBe(500);
    expect(serialized).toBe(
      JSON.stringify({ error: { code: "internal-error", message: "Internal server error" } })
    );
    expect(serialized).not.toContain("private/key");
    expect(reported).toEqual(["InternalError"]);
  });

  it("validates pagination and duplicate query parameters before inspecting", async () => {
    await bootstrap();
    const duplicate = await handleSessionEvents(
      getRequest(`/api/team-sessions/sessions/${sessionId}/events?limit=10&limit=20`),
      sessionId,
      dependencies
    );
    const zero = await handleSessionEvents(
      getRequest(`/api/team-sessions/sessions/${sessionId}/events?limit=0`),
      sessionId,
      dependencies
    );
    const unsafe = await handleSessionEvents(
      getRequest(`/api/team-sessions/sessions/${sessionId}/events?afterSequence=9007199254740992`),
      sessionId,
      dependencies
    );
    expect(duplicate.status).toBe(400);
    expect(zero.status).toBe(400);
    expect(unsafe.status).toBe(400);
  });
});
