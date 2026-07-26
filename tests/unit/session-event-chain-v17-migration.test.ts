import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import { createSessionEventChainStore } from "@/lib/team-sessions/sqlite-session-event-chain-store";
import {
  chainedSessionEventHashes,
  digestSessionEvent,
  previousChainHash,
  verifySessionEventChain,
  SESSION_EVENT_CHAIN_GENESIS,
  SESSION_EVENT_CHAIN_SCHEMA,
} from "@/lib/team-sessions/session-event-chain";
import { insertChainedSessionEvent } from "../helpers/session-events";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_A = "33333333-3333-4333-8333-333333333333";
const SESSION_B = "44444444-4444-4444-8444-444444444444";

interface LegacyEvent {
  readonly sequence: number;
  readonly type: string;
  readonly occurredAtMs: number;
  readonly actorKind: "human" | "system";
  readonly actorUserId: string;
  readonly actorDisplayName: string;
  readonly sourceScope: string;
  readonly sourceKey: string;
  readonly payload: unknown;
}

interface LegacySession {
  readonly id: string;
  readonly name: string;
  readonly tmuxName: string;
  readonly events: readonly LegacyEvent[];
}

/**
 * The three session_events artifacts v17 adds; a genuine pre-v17 database has
 * none of them. The remaining session_events triggers (the conditional
 * immutability guards added in v5/v7/v8) stay in place, exactly as they would in
 * a committed v16 database.
 */
const PHASE10_SESSION_EVENT_TRIGGERS = [
  "session_events_hash_chain_insert",
  "session_events_append_only_update",
  "session_events_append_only_delete",
] as const;

/**
 * The v5/v7/v8 conditional immutability triggers on session_events. The v17
 * migration drops these, backfills the chain, then restores them verbatim before
 * installing the unconditional append-only guard; asserting they survive proves
 * the drop/restore path did not lose them.
 */
const CONDITIONAL_IMMUTABILITY_TRIGGERS = [
  "runtime_run_referenced_session_events_immutable_update",
  "runtime_run_referenced_session_events_immutable_delete",
  "runtime_compensation_referenced_events_immutable_update",
  "runtime_compensation_referenced_events_immutable_delete",
  "runtime_outbox_source_event_immutable_update",
  "runtime_outbox_source_event_immutable_delete",
] as const;

/**
 * Synthesize a genuine v16 database on disk: a fresh v17 schema with the Phase 10
 * session-event chain columns, tables, and triggers stripped back out and the
 * user_version reset to 16, then populated with the given legacy events (with no
 * prev_hash/hash). Reopening it drives the real v16 -> v17 migration + backfill.
 */
function seedV16Database(filename: string, sessions: readonly LegacySession[]): void {
  const database = openTeamSessionDatabase({ filename });
  try {
    const db = database.db;
    db.prepare(`INSERT INTO teams (id, name, created_at_ms) VALUES (?, 'Acme', 1)`).run(TEAM_ID);
    db.prepare(
      `INSERT INTO projects (id, team_id, name, created_at_ms) VALUES (?, ?, 'Terminal X', 1)`
    ).run(PROJECT_ID, TEAM_ID);
    const insertSession = db.prepare(
      `INSERT INTO sessions
         (id, team_id, project_id, name, status, steering_policy,
          runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
       VALUES (?, ?, ?, ?, 'active', 'shared',
         'local-tmux', 'trusted-shared-host', ?, 0, 1)`
    );
    for (const session of sessions) {
      insertSession.run(session.id, TEAM_ID, PROJECT_ID, session.name, session.tmuxName);
    }

    // Strip the database back to a genuine v16: drop the Phase 10 session-event
    // triggers, the additive Gate 7/8 tables, and the additive columns, then
    // reset user_version. The conditional immutability triggers stay in place.
    for (const trigger of PHASE10_SESSION_EVENT_TRIGGERS) {
      db.exec(`DROP TRIGGER ${trigger}`);
    }
    db.exec(`
      DROP TABLE session_platform_security_actions;
      DROP TABLE evidence_review_history;
      DROP TABLE goal_version_lineage;
      DROP TABLE session_event_checkpoints;
      ALTER TABLE session_events DROP COLUMN hash;
      ALTER TABLE session_events DROP COLUMN prev_hash;
      ALTER TABLE sessions DROP COLUMN terminal_reason;
      ALTER TABLE sessions DROP COLUMN retention_expires_at_ms;
      ALTER TABLE sessions DROP COLUMN archived_at_ms;
      ALTER TABLE sessions DROP COLUMN ended_at_ms;
      PRAGMA user_version = 16;
    `);

    // Populate session_events without the chain columns (insertChainedSessionEvent
    // detects their absence and inserts a plain pre-v17 row).
    for (const session of sessions) {
      for (const event of session.events) {
        insertChainedSessionEvent(db, {
          sessionId: session.id,
          sequence: event.sequence,
          eventId: `${session.id}:event:${event.sequence}`,
          type: event.type,
          occurredAtMs: event.occurredAtMs,
          actorKind: event.actorKind,
          actorUserId: event.actorUserId,
          actorDisplayName: event.actorDisplayName,
          sourceScope: event.sourceScope,
          sourceKey: event.sourceKey,
          payloadJson: JSON.stringify(event.payload),
        });
      }
    }
  } finally {
    database.close();
  }
}

function populatedSessions(): readonly LegacySession[] {
  return [
    {
      id: SESSION_A,
      name: "Session A",
      tmuxName: "session-a",
      events: [
        {
          sequence: 1,
          type: "session.started",
          occurredAtMs: 100,
          actorKind: "human",
          actorUserId: "alice",
          actorDisplayName: "Alice",
          sourceScope: "vitest:migration",
          sourceKey: "a-1",
          payload: { sessionId: SESSION_A, steeringPolicy: "shared", nested: { keep: [1, 2, 3] } },
        },
        {
          sequence: 2,
          type: "comment.added",
          occurredAtMs: 200,
          actorKind: "human",
          actorUserId: "alice",
          actorDisplayName: "Alice",
          sourceScope: "vitest:migration",
          sourceKey: "a-2",
          payload: { body: "first note", tags: ["latency", "checkout"] },
        },
        {
          sequence: 3,
          type: "suggestion.added",
          occurredAtMs: 300,
          actorKind: "system",
          actorUserId: "runtime-worker",
          actorDisplayName: "Runtime Worker",
          sourceScope: "vitest:migration",
          sourceKey: "a-3",
          payload: { body: "look at the DB", zeta: 1, alpha: 2 },
        },
      ],
    },
    {
      id: SESSION_B,
      name: "Session B",
      tmuxName: "session-b",
      events: [
        {
          sequence: 1,
          type: "session.started",
          occurredAtMs: 150,
          actorKind: "human",
          actorUserId: "bob",
          actorDisplayName: "Bob",
          sourceScope: "vitest:migration",
          sourceKey: "b-1",
          payload: { sessionId: SESSION_B, steeringPolicy: "shared" },
        },
        {
          sequence: 2,
          type: "comment.added",
          occurredAtMs: 250,
          actorKind: "human",
          actorUserId: "bob",
          actorDisplayName: "Bob",
          sourceScope: "vitest:migration",
          sourceKey: "b-2",
          payload: { body: "second session note" },
        },
      ],
    },
  ];
}

function expectedChainFor(session: LegacySession): Array<{ prevHash: string; hash: string }> {
  const chain: Array<{ prevHash: string; hash: string }> = [];
  let priorHash: string | null = null;
  for (const event of session.events) {
    const { prevHash, hash } = chainedSessionEventHashes(priorHash, {
      schema: SESSION_EVENT_CHAIN_SCHEMA,
      sessionId: session.id,
      sequence: event.sequence,
      type: event.type,
      occurredAtMs: event.occurredAtMs,
      actor: {
        kind: event.actorKind,
        userId: event.actorUserId,
        displayName: event.actorDisplayName,
      },
      source: { scope: event.sourceScope, key: event.sourceKey },
      payload: event.payload,
    });
    chain.push({ prevHash, hash });
    priorHash = hash;
  }
  return chain;
}

describe("session event chain v16 -> v17 migration", () => {
  let directory: string;
  let filename: string;
  let database: TeamSessionDatabase | undefined;

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "terminalx-v17-migration-"));
    filename = path.join(directory, "team-sessions.sqlite");
  });

  afterEach(() => {
    database?.close();
    database = undefined;
    fs.rmSync(directory, { recursive: true, force: true });
  });

  it("backfills a deterministic hash chain over a populated v16 database", () => {
    const sessions = populatedSessions();
    seedV16Database(filename, sessions);

    database = openTeamSessionDatabase({ filename });
    expect(database.db.pragma("user_version", { simple: true })).toBe(17);

    // (a) every event has the exact deterministic prev_hash/hash: genesis root
    // at sequence 1, chained thereafter.
    for (const session of sessions) {
      const rows = database.db
        .prepare(
          `SELECT sequence, prev_hash, hash FROM session_events
           WHERE session_id = ? ORDER BY sequence ASC`
        )
        .all(session.id) as Array<{ sequence: number; prev_hash: string; hash: string }>;
      const expected = expectedChainFor(session);
      expect(rows).toHaveLength(expected.length);
      rows.forEach((row, index) => {
        expect(row.prev_hash).toBe(expected[index].prevHash);
        expect(row.hash).toBe(expected[index].hash);
      });
      expect(rows[0].prev_hash).toBe(SESSION_EVENT_CHAIN_GENESIS);
    }

    // (b) the store's chain verification passes for each session.
    const store = createSessionEventChainStore(database.db);
    for (const session of sessions) {
      const verification = store.verifyChain(session.id);
      expect(verification.ok).toBe(true);
      if (verification.ok) {
        expect(verification.headSequence).toBe(session.events.length);
      }
    }
  });

  it("restores the conditional immutability triggers and installs the append-only guard", () => {
    const sessions = populatedSessions();
    seedV16Database(filename, sessions);

    database = openTeamSessionDatabase({ filename });
    const db = database.db;

    const triggers = new Set(
      (
        db
          .prepare(
            `SELECT name FROM sqlite_master
             WHERE type = 'trigger' AND tbl_name = 'session_events'`
          )
          .all() as Array<{ name: string }>
      ).map((row) => row.name)
    );
    // (c) the prior conditional immutability triggers were restored verbatim...
    for (const trigger of CONDITIONAL_IMMUTABILITY_TRIGGERS) {
      expect(triggers.has(trigger)).toBe(true);
    }
    // ...and the new unconditional append-only + chain-insert guards are present.
    for (const trigger of PHASE10_SESSION_EVENT_TRIGGERS) {
      expect(triggers.has(trigger)).toBe(true);
    }

    // The append-only guard rejects any post-migration UPDATE or DELETE.
    expect(() =>
      db
        .prepare(
          `UPDATE session_events SET type = 'tampered' WHERE session_id = ? AND sequence = 1`
        )
        .run(SESSION_A)
    ).toThrow(/append-only/);
    expect(() =>
      db.prepare(`DELETE FROM session_events WHERE session_id = ? AND sequence = 3`).run(SESSION_A)
    ).toThrow(/append-only/);
  });

  it("continues the chain from the backfilled head on a subsequent append", () => {
    const sessions = populatedSessions();
    seedV16Database(filename, sessions);

    database = openTeamSessionDatabase({ filename });
    const db = database.db;

    const head = db
      .prepare(
        `SELECT sequence, hash FROM session_events
         WHERE session_id = ? ORDER BY sequence DESC LIMIT 1`
      )
      .get(SESSION_A) as { sequence: number; hash: string };

    // insertChainedSessionEvent routes through the same chainedSessionEventHashes
    // helper the kernel's appendEvent uses; it must chain from the backfilled head
    // and satisfy the real v17 hash-chain INSERT trigger.
    const nextPayload = { body: "post-migration append" };
    insertChainedSessionEvent(db, {
      sessionId: SESSION_A,
      sequence: head.sequence + 1,
      eventId: `${SESSION_A}:event:live`,
      type: "comment.added",
      occurredAtMs: 400,
      actorKind: "human",
      actorUserId: "alice",
      actorDisplayName: "Alice",
      sourceScope: "vitest:migration",
      sourceKey: "a-live",
      payloadJson: JSON.stringify(nextPayload),
    });

    const appended = db
      .prepare(`SELECT prev_hash, hash FROM session_events WHERE session_id = ? AND sequence = ?`)
      .get(SESSION_A, head.sequence + 1) as { prev_hash: string; hash: string };
    expect(appended.prev_hash).toBe(head.hash);
    const expectedHash = digestSessionEvent({
      schema: SESSION_EVENT_CHAIN_SCHEMA,
      sessionId: SESSION_A,
      sequence: head.sequence + 1,
      type: "comment.added",
      occurredAtMs: 400,
      actor: { kind: "human", userId: "alice", displayName: "Alice" },
      source: { scope: "vitest:migration", key: "a-live" },
      payload: nextPayload,
      prevHash: head.hash,
    });
    expect(appended.hash).toBe(expectedHash);

    const store = createSessionEventChainStore(db);
    const verification = store.verifyChain(SESSION_A);
    expect(verification.ok).toBe(true);
    if (verification.ok) expect(verification.headSequence).toBe(head.sequence + 1);

    // A broken continuation is rejected by the trigger, confirming the guard is live.
    expect(() =>
      db
        .prepare(
          `INSERT INTO session_events
             (session_id, sequence, event_id, type, occurred_at_ms,
              actor_kind, actor_user_id, actor_display_name,
              source_scope, source_key, payload_json, prev_hash, hash)
           VALUES (?, ?, ?, 'comment.added', 500, 'human', 'alice', 'Alice',
                   'vitest:migration', 'a-break', '{}', ?, ?)`
        )
        .run(
          SESSION_A,
          head.sequence + 2,
          `${SESSION_A}:event:break`,
          "0".repeat(64),
          "1".repeat(64)
        )
    ).toThrow(/hash chain/);
  });

  it("is idempotent: reopening a migrated database does not re-migrate", () => {
    const sessions = populatedSessions();
    seedV16Database(filename, sessions);

    database = openTeamSessionDatabase({ filename });
    const before = database.db
      .prepare(
        `SELECT session_id, sequence, prev_hash, hash FROM session_events
         ORDER BY session_id ASC, sequence ASC`
      )
      .all();
    database.close();
    database = undefined;

    // Reopening again is a clean no-op — no double-migrate error, hashes unchanged.
    database = openTeamSessionDatabase({ filename });
    expect(database.db.pragma("user_version", { simple: true })).toBe(17);
    const after = database.db
      .prepare(
        `SELECT session_id, sequence, prev_hash, hash FROM session_events
         ORDER BY session_id ASC, sequence ASC`
      )
      .all();
    expect(after).toEqual(before);

    const store = createSessionEventChainStore(database.db);
    for (const session of sessions) {
      expect(store.verifyChain(session.id).ok).toBe(true);
    }
  });

  it("fails closed and rolls back when a legacy sequence is non-contiguous", () => {
    // Session A has a gap (sequence 1 then 3): the backfill must refuse to forge a
    // link rather than migrate a torn chain.
    seedV16Database(filename, [
      {
        id: SESSION_A,
        name: "Session A",
        tmuxName: "session-a",
        events: [
          {
            sequence: 1,
            type: "session.started",
            occurredAtMs: 100,
            actorKind: "human",
            actorUserId: "alice",
            actorDisplayName: "Alice",
            sourceScope: "vitest:migration",
            sourceKey: "a-1",
            payload: { sessionId: SESSION_A },
          },
          {
            sequence: 3,
            type: "comment.added",
            occurredAtMs: 300,
            actorKind: "human",
            actorUserId: "alice",
            actorDisplayName: "Alice",
            sourceScope: "vitest:migration",
            sourceKey: "a-3",
            payload: { body: "gap" },
          },
        ],
      },
    ]);

    expect(() => openTeamSessionDatabase({ filename })).toThrow(/non-contiguous session event/);

    // The migration rolled back atomically: user_version stays 16 and the chain
    // columns were never added.
    const after = new Database(filename, { readonly: true, fileMustExist: true });
    try {
      expect(after.pragma("user_version", { simple: true })).toBe(16);
      const columns = (
        after.prepare(`PRAGMA table_info(session_events)`).all() as Array<{ name: string }>
      ).map((row) => row.name);
      expect(columns).not.toContain("prev_hash");
      expect(columns).not.toContain("hash");
    } finally {
      after.close();
    }
  });

  it("verifies the backfilled chain against an independent re-derivation", () => {
    const sessions = populatedSessions();
    seedV16Database(filename, sessions);
    database = openTeamSessionDatabase({ filename });

    const store = createSessionEventChainStore(database.db);
    for (const session of sessions) {
      const records = store.readChain(session.id);
      // previousChainHash is the primitive the migration used; re-derive the
      // whole chain from it and confirm it matches, then verify end to end.
      let priorHash: string | null = null;
      for (const record of records) {
        expect(record.prevHash).toBe(previousChainHash(record.sequence, priorHash));
        priorHash = record.hash;
      }
      expect(verifySessionEventChain(records).ok).toBe(true);
    }
  });
});
