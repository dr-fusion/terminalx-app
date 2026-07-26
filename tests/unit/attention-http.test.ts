import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { SESSION_EVENT_CHAIN_GENESIS } from "@/lib/team-sessions/session-event-chain";
import { AttentionInboxStore } from "@/lib/attention/store";
import {
  handleAttentionInbox,
  handleAttentionRead,
  handleAttentionUnreadCount,
  type AttentionHttpDependencies,
} from "@/lib/attention/http";
import type { RequestActor } from "@/lib/request-actor";

const ORIGIN = "https://terminalx.test";

function actor(userId: string): RequestActor {
  return { kind: "human", userId, username: userId, displayName: userId, legacyRole: "user" };
}

let counter = 0;

function seed(db: TeamSessionDatabase["db"]): void {
  db.exec(`
    INSERT INTO teams (id, name, created_at_ms) VALUES ('team-1', 'Team', 1);
    INSERT INTO projects (id, team_id, name, created_at_ms) VALUES ('project-1', 'team-1', 'P', 1);
    INSERT INTO sessions
      (id, team_id, project_id, name, status, steering_policy,
       runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
      VALUES ('session-1', 'team-1', 'project-1', 'Session One', 'active', 'shared',
        'local-tmux', 'trusted-shared-host', 'session-1-tmux', 0, 1);
    INSERT INTO session_participants (id, session_id, user_id, status, version, joined_at_ms)
      VALUES ('p-alice', 'session-1', 'alice', 'active', 1, 1),
             ('p-bob', 'session-1', 'bob', 'active', 1, 1);
  `);
  db.prepare(
    `INSERT INTO session_events
       (session_id, sequence, event_id, type, occurred_at_ms,
        actor_kind, actor_user_id, actor_display_name,
        source_scope, source_key, payload_json, prev_hash, hash)
     VALUES ('session-1', 1, 'e1', 'comment.added', 100,
        'human', 'bob', 'bob', 'test', 'k1', '{"commentId":"c1","body":"@alice"}', ?, ?)`
  ).run(SESSION_EVENT_CHAIN_GENESIS, createHash("sha256").update("x").digest("hex"));
  db.exec(`
    INSERT INTO conversation_identities (id, session_id, kind, created_sequence, created_at_ms)
      VALUES ('c1', 'session-1', 'comment', 1, 100);
    INSERT INTO comment_mentions
      (id, session_id, comment_id, comment_sequence, mentioned_user_id, author_user_id, created_at_ms)
      VALUES ('m1', 'session-1', 'c1', 1, 'alice', 'bob', 100);
  `);
}

function deps(database: TeamSessionDatabase, who: RequestActor | null): AttentionHttpDependencies {
  return {
    attentionInbox: new AttentionInboxStore(database.db, {
      clock: () => 1_000,
      idGenerator: () => `id-${(counter += 1)}`,
    }),
    resolveActor: async () => who,
    isReadOnly: () => false,
    isMutationAvailable: () => true,
  };
}

describe("attention HTTP", () => {
  let database: TeamSessionDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
    counter = 0;
  });

  it("returns the actor-scoped inbox and rejects unauthenticated callers", async () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seed(database.db);

    const anon = await handleAttentionInbox(
      new Request(`${ORIGIN}/api/attention`),
      deps(database, null)
    );
    expect(anon.status).toBe(401);

    const response = await handleAttentionInbox(
      new Request(`${ORIGIN}/api/attention`),
      deps(database, actor("alice"))
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { inbox: { items: unknown[]; unreadCount: number } };
    expect(body.inbox.items).toHaveLength(1);
    expect(body.inbox.unreadCount).toBe(1);
  });

  it("does not leak another user's inbox items", async () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seed(database.db);
    const response = await handleAttentionInbox(
      new Request(`${ORIGIN}/api/attention`),
      deps(database, actor("bob"))
    );
    const body = (await response.json()) as { inbox: { items: unknown[] } };
    expect(body.inbox.items).toHaveLength(0);
  });

  it("reports an unread count", async () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seed(database.db);
    const response = await handleAttentionUnreadCount(
      new Request(`${ORIGIN}/api/attention/unread-count`),
      deps(database, actor("alice"))
    );
    expect(await response.json()).toEqual({ unreadCount: 1 });
  });

  it("advances the read cursor and enforces same-origin for cookie auth", async () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seed(database.db);

    const crossOrigin = await handleAttentionRead(
      new Request(`${ORIGIN}/api/attention/read`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: "terminalx-session=abc",
          origin: "https://evil.test",
          host: "terminalx.test",
        },
        body: JSON.stringify({ sessionId: "session-1", throughSequence: 1 }),
      }),
      deps(database, actor("alice"))
    );
    expect(crossOrigin.status).toBe(403);

    const ok = await handleAttentionRead(
      new Request(`${ORIGIN}/api/attention/read`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionId: "session-1", throughSequence: 1 }),
      }),
      deps(database, actor("alice"))
    );
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({
      read: { sessionId: "session-1", readThroughSequence: 1 },
    });
    expect(
      database.db.prepare("SELECT read_through_sequence AS n FROM user_attention_reads").get()
    ).toEqual({ n: 1 });
  });

  it("fails closed when a non-participant marks read", async () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seed(database.db);
    const response = await handleAttentionRead(
      new Request(`${ORIGIN}/api/attention/read`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ sessionId: "session-1", throughSequence: 1 }),
      }),
      deps(database, actor("stranger"))
    );
    expect(response.status).toBe(404);
  });
});
