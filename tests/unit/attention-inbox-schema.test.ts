import { afterEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { SESSION_EVENT_CHAIN_GENESIS } from "@/lib/team-sessions/session-event-chain";

const HASH = "b".repeat(64);

/**
 * Seed a Session with one participant and one session event so the append-only
 * evidence tables (which fence to real participants and real events) have valid
 * parents to reference.
 */
function seedSession(db: TeamSessionDatabase["db"]): void {
  db.exec(`
    INSERT INTO teams (id, name, created_at_ms) VALUES ('team-1', 'Team', 1);
    INSERT INTO projects (id, team_id, name, created_at_ms)
      VALUES ('project-1', 'team-1', 'Project', 1);
    INSERT INTO sessions
      (id, team_id, project_id, name, status, steering_policy,
       runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
      VALUES ('session-1', 'team-1', 'project-1', 'Session', 'active', 'shared',
        'local-tmux', 'trusted-shared-host', 'session-1-tmux', 0, 1);
    INSERT INTO session_participants
      (id, session_id, user_id, status, version, joined_at_ms)
      VALUES ('participant-1', 'session-1', 'alice', 'active', 1, 1);
  `);
  db.prepare(
    `INSERT INTO session_events
       (session_id, sequence, event_id, type, occurred_at_ms,
        actor_kind, actor_user_id, actor_display_name,
        source_scope, source_key, payload_json, prev_hash, hash)
     VALUES ('session-1', 1, 'event-1', 'comment.added', 10,
        'human', 'alice', 'Alice', 'test', 'k-1', '{"commentId":"comment-1","body":"hi"}', ?, ?)`
  ).run(SESSION_EVENT_CHAIN_GENESIS, HASH);
  db.prepare(
    `INSERT INTO conversation_identities (id, session_id, kind, created_sequence, created_at_ms)
     VALUES ('comment-1', 'session-1', 'comment', 1, 10)`
  ).run();
}

describe("attention inbox schema (v18)", () => {
  let database: TeamSessionDatabase | undefined;

  afterEach(() => {
    database?.close();
    database = undefined;
  });

  it("creates the additive v18 attention + chat tables", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    expect(database.db.pragma("user_version", { simple: true })).toBe(18);
    const tables = [
      "attention_deliveries",
      "attention_escalations",
      "comment_attachments",
      "comment_mentions",
      "user_attention_reads",
    ];
    expect(
      database.db
        .prepare(
          `SELECT name FROM sqlite_schema
           WHERE type = 'table' AND name IN (${tables.map(() => "?").join(", ")})
           ORDER BY name`
        )
        .all(...tables)
    ).toEqual(tables.toSorted().map((name) => ({ name })));
  });

  it("fences a mention to a real Session Participant and keeps it append-only", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedSession(database.db);

    // A non-participant cannot be mentioned into the Session's inbox.
    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO comment_mentions
             (id, session_id, comment_id, comment_sequence, mentioned_user_id,
              author_user_id, created_at_ms)
           VALUES ('m-x', 'session-1', 'comment-1', 1, 'stranger', 'alice', 11)`
        )
        .run()
    ).toThrow();

    database.db
      .prepare(
        `INSERT INTO comment_mentions
           (id, session_id, comment_id, comment_sequence, mentioned_user_id,
            author_user_id, created_at_ms)
         VALUES ('m-1', 'session-1', 'comment-1', 1, 'alice', 'alice', 11)`
      )
      .run();
    expect(() =>
      database!.db
        .prepare("UPDATE comment_mentions SET mentioned_user_id = 'bob' WHERE id = 'm-1'")
        .run()
    ).toThrow(/append-only/);
    expect(() =>
      database!.db.prepare("DELETE FROM comment_mentions WHERE id = 'm-1'").run()
    ).toThrow(/append-only/);
  });

  it("keeps the read cursor monotonic", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedSession(database.db);
    database.db
      .prepare(
        `INSERT INTO user_attention_reads (user_id, session_id, read_through_sequence, updated_at_ms)
         VALUES ('alice', 'session-1', 5, 20)`
      )
      .run();
    expect(() =>
      database!.db
        .prepare(
          `UPDATE user_attention_reads SET read_through_sequence = 3, updated_at_ms = 30
           WHERE user_id = 'alice' AND session_id = 'session-1'`
        )
        .run()
    ).toThrow(/must not regress/);
    database.db
      .prepare(
        `UPDATE user_attention_reads SET read_through_sequence = 7, updated_at_ms = 30
         WHERE user_id = 'alice' AND session_id = 'session-1'`
      )
      .run();
    expect(
      database.db
        .prepare(
          `SELECT read_through_sequence FROM user_attention_reads
           WHERE user_id = 'alice' AND session_id = 'session-1'`
        )
        .get()
    ).toEqual({ read_through_sequence: 7 });
  });

  it("makes escalation and delivery logs append-only and idempotent", () => {
    database = openTeamSessionDatabase({ filename: ":memory:" });
    seedSession(database.db);
    database.db
      .prepare(
        `INSERT INTO attention_escalations
           (id, session_id, sequence, item_kind, item_sequence,
            responsible_user_id, supervisor_user_id, deadline_at_ms, escalated_at_ms,
            prev_hash, hash, created_at_ms)
         VALUES ('e-1', 'session-1', 1, 'handoff-offer', 1,
            'alice', 'bob', 5, 6, ?, ?, 6)`
      )
      .run(SESSION_EVENT_CHAIN_GENESIS, HASH);
    // Idempotency: a second escalation of the same item to the same supervisor is rejected.
    expect(() =>
      database!.db
        .prepare(
          `INSERT INTO attention_escalations
             (id, session_id, sequence, item_kind, item_sequence,
              responsible_user_id, supervisor_user_id, deadline_at_ms, escalated_at_ms,
              prev_hash, hash, created_at_ms)
           VALUES ('e-2', 'session-1', 2, 'handoff-offer', 1,
              'alice', 'bob', 5, 7, ?, ?, 7)`
        )
        .run(HASH, HASH)
    ).toThrow();
    expect(() =>
      database!.db.prepare("DELETE FROM attention_escalations WHERE id = 'e-1'").run()
    ).toThrow(/append-only/);
  });
});
