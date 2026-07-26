import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createTeamSessionKernel, type TeamSessionKernel } from "@/lib/team-sessions/module";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  type ActorContext,
  type SessionCommand,
} from "@/lib/team-sessions";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";

const ALICE: ActorContext = { kind: "human", userId: "user-alice", displayName: "Alice" };
const BOB: ActorContext = { kind: "human", userId: "user-bob", displayName: "Bob" };

describe("comment mentions and attachments", () => {
  let directory: string;
  let filename: string;
  let kernel: TeamSessionKernel | undefined;
  let nowMs = 1_000;
  let generatedId = 0;
  let commandNumber = 0;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-mentions-"));
    filename = path.join(directory, "team-sessions.sqlite");
    nowMs = 1_000;
    generatedId = 0;
    commandNumber = 0;
    kernel = createTeamSessionKernel({
      filename,
      clock: () => nowMs,
      idGenerator: () => {
        generatedId += 1;
        return `00000000-0000-4000-8000-${String(generatedId).padStart(12, "0")}`;
      },
      invitationTokenGenerator: () => `txi_${"x".repeat(68)}`,
    });
  });

  afterEach(() => {
    kernel?.teamSessions.close();
    kernel = undefined;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function dispatch(input: Record<string, unknown>, actor: ActorContext = ALICE) {
    const command = {
      ...input,
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: { scope: "vitest:mentions", key: `command-${(commandNumber += 1)}` },
      occurredAtMs: nowMs,
    } as unknown as SessionCommand;
    return kernel!.teamSessions.dispatch(command);
  }

  async function bootstrapWithBob(): Promise<void> {
    await dispatch({ type: "team.create", teamId: TEAM_ID, name: "Acme" });
    await dispatch({
      type: "project.create",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      name: "Terminal X",
    });
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: SESSION_ID,
      name: "Session",
      tmuxName: "session-tmux",
    });
    await dispatch({
      type: "team.membership.grant",
      teamId: TEAM_ID,
      userId: BOB.userId,
      role: "member",
      expectedMembershipVersion: 0,
    });
    await dispatch({
      type: "project.access.grant",
      projectId: PROJECT_ID,
      userId: BOB.userId,
      role: "contributor",
      expectedAccessVersion: 0,
    });
    const view = await kernel!.teamSessions.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor: ALICE,
      type: "session.get",
      sessionId: SESSION_ID,
    });
    await dispatch({
      type: "session.participant.grant",
      sessionId: SESSION_ID,
      userId: BOB.userId,
      expectedParticipantVersion: 0,
      expectedAccessRevision: view!.accessRevision,
    });
  }

  function readonlyDb(): Database.Database {
    return new Database(filename, { readonly: true });
  }

  it("resolves an @mention to an active Participant and feeds the inbox", async () => {
    await bootstrapWithBob();
    const receipt = await dispatch({
      type: "comment.add",
      sessionId: SESSION_ID,
      body: `Please review @${BOB.userId} and also @user-nobody`,
    });
    expect(receipt.data.mentionedUserIds).toEqual([BOB.userId]);

    const db = readonlyDb();
    try {
      const mentions = db
        .prepare("SELECT mentioned_user_id, author_user_id FROM comment_mentions")
        .all();
      expect(mentions).toEqual([{ mentioned_user_id: BOB.userId, author_user_id: ALICE.userId }]);
    } finally {
      db.close();
    }

    const inbox = kernel!.attentionInbox.listInbox({ userId: BOB.userId });
    expect(inbox.items.map((item) => item.kind)).toEqual(["mention"]);
    expect(inbox.unreadCount).toBe(1);
    // Alice, the author, is not mentioned.
    expect(kernel!.attentionInbox.listInbox({ userId: ALICE.userId }).items).toEqual([]);
  });

  it("records bounded attachments and rejects invalid ones", async () => {
    await bootstrapWithBob();
    const receipt = await dispatch({
      type: "comment.add",
      sessionId: SESSION_ID,
      body: "See the artifact",
      attachments: [{ artifactRef: "artifact:run-1:log", mediaType: "text/plain", byteSize: 42 }],
    });
    expect(receipt.data.attachmentCount).toBe(1);

    const db = readonlyDb();
    try {
      expect(
        db.prepare("SELECT artifact_ref, media_type, byte_size FROM comment_attachments").all()
      ).toEqual([{ artifact_ref: "artifact:run-1:log", media_type: "text/plain", byte_size: 42 }]);
    } finally {
      db.close();
    }

    await expect(
      dispatch({
        type: "comment.add",
        sessionId: SESSION_ID,
        body: "bad",
        attachments: [{ artifactRef: "", mediaType: "text/plain", byteSize: 1 }],
      })
    ).rejects.toThrow();
  });

  it("does not resolve a mention to a non-participant", async () => {
    await bootstrapWithBob();
    await dispatch({
      type: "comment.add",
      sessionId: SESSION_ID,
      body: "Hello @user-ghost, are you there?",
    });
    const db = readonlyDb();
    try {
      expect(db.prepare("SELECT COUNT(*) AS n FROM comment_mentions").get()).toEqual({ n: 0 });
    } finally {
      db.close();
    }
  });
});
