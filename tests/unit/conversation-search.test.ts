import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  TEAM_SESSION_SCHEMA_VERSION,
  TeamSessionError,
  createTeamSessions,
  type ActorContext,
  type ConversationSearchResultView,
  type SessionCommand,
  type TeamSessions,
} from "@/lib/team-sessions";

const ALICE: ActorContext = { kind: "human", userId: "user-alice", displayName: "Alice" };
const MALLORY: ActorContext = { kind: "human", userId: "user-mallory", displayName: "Mallory" };

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";

describe("conversation search + structured handoff briefing", () => {
  let directory: string;
  let filename: string;
  let kernel: TeamSessions;
  let nowMs: number;
  let commandNumber: number;
  let generatedId: number;

  beforeEach(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-search-"));
    filename = path.join(directory, "team-sessions.sqlite");
    nowMs = 2_000_000_000_000;
    commandNumber = 0;
    generatedId = 0;
    kernel = createTeamSessions({
      filename,
      clock: () => nowMs,
      idGenerator: () => {
        generatedId += 1;
        return `00000000-0000-4000-8000-${String(generatedId).padStart(12, "0")}`;
      },
      invitationTokenGenerator: () => `txi_${"x".repeat(68)}`,
    });
    await dispatch({ type: "team.create", teamId: TEAM_ID, name: "Acme" });
    await dispatch({
      type: "project.create",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      name: "Terminal X",
      sourceRef: "/srv/terminalx",
    });
    await dispatch({
      type: "session.start",
      teamId: TEAM_ID,
      projectId: PROJECT_ID,
      sessionId: SESSION_ID,
      name: "Multiplayer kernel",
      tmuxName: "multiplayer-kernel",
    });
  });

  afterEach(() => {
    kernel.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });

  function dispatch(
    input: Omit<SessionCommand, "schemaVersion" | "actor" | "idempotency" | "occurredAtMs">,
    actor: ActorContext = ALICE
  ) {
    commandNumber += 1;
    return kernel.dispatch({
      ...input,
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      actor,
      idempotency: { scope: "vitest:search", key: `command-${commandNumber}` },
      occurredAtMs: nowMs,
    } as SessionCommand);
  }

  function search(
    text: string,
    actor: ActorContext = ALICE,
    options: { afterSequence?: number; limit?: number } = {}
  ): Promise<ConversationSearchResultView> {
    return kernel.inspect({
      schemaVersion: TEAM_SESSION_SCHEMA_VERSION,
      type: "session.conversation-search",
      actor,
      sessionId: SESSION_ID,
      text,
      ...options,
    });
  }

  async function comment(body: string): Promise<void> {
    await dispatch({ type: "comment.add", sessionId: SESSION_ID, body });
  }

  it("matches comment bodies and returns safe projected fields", async () => {
    await comment("Investigating the migration failure on staging");
    await comment("Unrelated note about lunch");
    const result = await search("migration");
    expect(result.matches).toHaveLength(1);
    const match = result.matches[0]!;
    expect(match.body).toContain("migration failure");
    expect(match.actor.userId).toBe(ALICE.userId);
    expect(Object.keys(match).sort()).toEqual(
      ["actor", "body", "eventId", "occurredAtMs", "sequence"].sort()
    );
  });

  it("only searches comments, not suggestions or system events", async () => {
    await dispatch({ type: "suggestion.add", sessionId: SESSION_ID, body: "migration suggestion" });
    const result = await search("migration");
    expect(result.matches).toHaveLength(0);
  });

  it("is fenced to Session visibility: a non-participant gets a fail-closed empty result", async () => {
    await comment("secret migration detail");
    const outsider = await search("migration", MALLORY);
    expect(outsider.matches).toEqual([]);
    expect(outsider.nextAfterSequence).toBeNull();
  });

  it("paginates by sequence with a stable next cursor", async () => {
    for (let index = 0; index < 5; index += 1) {
      await comment(`deploy attempt number ${index}`);
    }
    const first = await search("deploy", ALICE, { limit: 2 });
    expect(first.matches).toHaveLength(2);
    expect(first.nextAfterSequence).not.toBeNull();

    const second = await search("deploy", ALICE, {
      limit: 2,
      afterSequence: first.nextAfterSequence!,
    });
    expect(second.matches).toHaveLength(2);
    const firstSequences = first.matches.map((m) => m.sequence);
    const secondSequences = second.matches.map((m) => m.sequence);
    expect(firstSequences.every((s) => secondSequences.every((later) => later > s))).toBe(true);

    const third = await search("deploy", ALICE, {
      limit: 2,
      afterSequence: second.nextAfterSequence!,
    });
    expect(third.matches).toHaveLength(1);
    expect(third.nextAfterSequence).toBeNull();
  });

  it("matches needles literally, escaping LIKE wildcards", async () => {
    await comment("progress is 50% complete");
    await comment("progress is 5X complete");
    const result = await search("50%");
    expect(result.matches).toHaveLength(1);
    expect(result.matches[0]!.body).toContain("50%");
  });

  it("rejects an empty needle and out-of-bounds limits", async () => {
    await expect(search("   ")).rejects.toBeInstanceOf(TeamSessionError);
    await expect(search("x", ALICE, { limit: 0 })).rejects.toBeInstanceOf(TeamSessionError);
    await expect(search("x", ALICE, { limit: 51 })).rejects.toBeInstanceOf(TeamSessionError);
    await expect(search("x".repeat(201))).rejects.toBeInstanceOf(TeamSessionError);
  });
});
