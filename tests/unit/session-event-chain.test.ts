import { generateKeyPairSync } from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type BetterSqlite3 from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openTeamSessionDatabase, type TeamSessionDatabase } from "@/lib/team-sessions/sqlite";
import {
  chainedSessionEventHashes,
  digestSessionEvent,
  SESSION_EVENT_CHAIN_GENESIS,
  SESSION_EVENT_CHAIN_SCHEMA,
  verifyExportedSessionEventChain,
  verifySessionEventChain,
  type SessionEventChainRecord,
} from "@/lib/team-sessions/session-event-chain";
import {
  createSessionEventChainStore,
  SessionEventChainStoreError,
} from "@/lib/team-sessions/sqlite-session-event-chain-store";
import { insertChainedSessionEvent } from "../helpers/session-events";

const TEAM_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const SESSION_ID = "33333333-3333-4333-8333-333333333333";

function seedSession(db: BetterSqlite3.Database): void {
  db.prepare(`INSERT INTO teams (id, name, created_at_ms) VALUES (?, 'Acme', 1)`).run(TEAM_ID);
  db.prepare(`INSERT INTO projects (id, team_id, name, created_at_ms) VALUES (?, ?, 'TX', 1)`).run(
    PROJECT_ID,
    TEAM_ID
  );
  db.prepare(
    `INSERT INTO sessions
       (id, team_id, project_id, name, status, steering_policy, runtime_authorization_state,
        runtime_kind, isolation, tmux_name, yolo_eligible, created_at_ms)
     VALUES (?, ?, ?, 'S', 'active', 'shared', 'enforced',
       'local-tmux', 'trusted-shared-host', 'chain', 0, 1)`
  ).run(SESSION_ID, TEAM_ID, PROJECT_ID);
}

function seedEvents(db: BetterSqlite3.Database, count: number): void {
  for (let sequence = 1; sequence <= count; sequence += 1) {
    insertChainedSessionEvent(db, {
      sessionId: SESSION_ID,
      sequence,
      eventId: `event:${sequence}`,
      type: sequence === 1 ? "session.started" : "comment.added",
      occurredAtMs: 100 + sequence,
      actorKind: "human",
      actorUserId: "user-alice",
      actorDisplayName: "Alice",
      sourceScope: "vitest",
      sourceKey: `key-${sequence}`,
      payloadJson: JSON.stringify({ index: sequence, note: `event ${sequence}` }),
    });
  }
  db.prepare(`UPDATE sessions SET next_sequence = ? WHERE id = ?`).run(count + 1, SESSION_ID);
}

describe("session event hash chain", () => {
  let tmp: string;
  let filename: string;
  let database: TeamSessionDatabase | undefined;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "chain-"));
    filename = path.join(tmp, "team-sessions.sqlite");
  });

  afterEach(() => {
    database?.close();
    database = undefined;
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  it("derives a deterministic digest and a fixed genesis root", () => {
    const input = {
      schema: SESSION_EVENT_CHAIN_SCHEMA,
      sessionId: SESSION_ID,
      sequence: 1,
      type: "session.started",
      occurredAtMs: 101,
      actor: { kind: "human" as const, userId: "u", displayName: "U" },
      source: { scope: "s", key: "k" },
      payload: { a: 1 },
      prevHash: SESSION_EVENT_CHAIN_GENESIS,
    };
    expect(digestSessionEvent(input)).toBe(digestSessionEvent({ ...input }));
    expect(SESSION_EVENT_CHAIN_GENESIS).toMatch(/^[0-9a-f]{64}$/);
    // A changed field yields a different digest.
    expect(digestSessionEvent({ ...input, occurredAtMs: 102 })).not.toBe(digestSessionEvent(input));
  });

  it("verifies a well-formed chain and detects tamper, gap, and reorder", () => {
    database = openTeamSessionDatabase({ filename });
    seedSession(database.db);
    seedEvents(database.db, 4);
    const store = createSessionEventChainStore(database.db);
    const result = store.verifyChain(SESSION_ID);
    expect(result).toEqual({ ok: true, headSequence: 4, headHash: expect.any(String) });

    const records = store.readChain(SESSION_ID);

    // Tamper: rewrite the stored hash of an event.
    const tampered = records.map((record, index) =>
      index === 2 ? { ...record, payload: { index: 999 } } : record
    );
    expect(verifySessionEventChain(tampered)).toEqual({
      ok: false,
      failure: { kind: "hash-mismatch", sequence: 3 },
    });

    // Reorder.
    const reordered = [records[1], records[0], ...records.slice(2)];
    expect(verifySessionEventChain(reordered).ok).toBe(false);

    // Gap.
    const gapped = [records[0], records[2], records[3]];
    expect(verifySessionEventChain(gapped)).toEqual({
      ok: false,
      failure: { kind: "gap", sequence: 2 },
    });

    // Broken link.
    const relinked = records.map((record, index) =>
      index === 2 ? { ...record, prevHash: SESSION_EVENT_CHAIN_GENESIS } : record
    );
    expect(verifySessionEventChain(relinked)).toEqual({
      ok: false,
      failure: { kind: "prev-hash-mismatch", sequence: 3 },
    });

    expect(verifySessionEventChain([])).toEqual({ ok: false, failure: { kind: "empty" } });
  });

  it("detects on-disk tamper after the append-only guard is bypassed", () => {
    database = openTeamSessionDatabase({ filename });
    seedSession(database.db);
    seedEvents(database.db, 3);
    const store = createSessionEventChainStore(database.db);
    expect(store.verifyChain(SESSION_ID).ok).toBe(true);

    // Simulate external, out-of-band tampering: drop the append-only guard and
    // rewrite a payload without recomputing its hash.
    database.db.prepare(`DROP TRIGGER session_events_append_only_update`).run();
    database.db
      .prepare(`UPDATE session_events SET payload_json = '{"forged":true}' WHERE sequence = 2`)
      .run();
    expect(store.verifyChain(SESSION_ID)).toEqual({
      ok: false,
      failure: { kind: "hash-mismatch", sequence: 2 },
    });
  });

  it("reproduces the live chain hashes from a deterministic backfill", () => {
    database = openTeamSessionDatabase({ filename });
    seedSession(database.db);
    seedEvents(database.db, 5);
    const store = createSessionEventChainStore(database.db);
    const live = store.readChain(SESSION_ID);

    // Re-derive the whole chain from the stored content exactly as the migration
    // backfill does, and assert it matches the live-appended hashes.
    let prior: string | null = null;
    for (const record of live) {
      const { prevHash, hash } = chainedSessionEventHashes(prior, {
        schema: SESSION_EVENT_CHAIN_SCHEMA,
        sessionId: record.sessionId,
        sequence: record.sequence,
        type: record.type,
        occurredAtMs: record.occurredAtMs,
        actor: record.actor,
        source: record.source,
        payload: record.payload,
      });
      expect(prevHash).toBe(record.prevHash);
      expect(hash).toBe(record.hash);
      prior = hash;
    }
  });

  it("signs, verifies, and rejects tampered checkpoints", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    database = openTeamSessionDatabase({ filename });
    seedSession(database.db);
    seedEvents(database.db, 3);
    const store = createSessionEventChainStore(database.db, {
      signingKey: privateKey,
      signingKeyId: "chain-key-1",
      verificationKeys: new Map([["chain-key-1", publicKey]]),
    });
    const proof = store.emitCheckpoint({
      sessionId: SESSION_ID,
      checkpointId: "checkpoint-1",
      nowMs: 500,
    });
    expect(proof.payload.headSequence).toBe(3);

    const verified = store.verifyStoredCheckpoints(SESSION_ID);
    expect(verified).toHaveLength(1);
    expect(verified[0].payload?.headHash).toBe(proof.payload.headHash);

    // A checkpoint verified against the wrong key fails closed.
    const strangerStore = createSessionEventChainStore(database.db, {
      verificationKeys: new Map([["chain-key-1", generateKeyPairSync("ed25519").publicKey]]),
    });
    expect(strangerStore.verifyStoredCheckpoints(SESSION_ID)[0].payload).toBeNull();
  });

  it("fails closed when no signing key is configured", () => {
    database = openTeamSessionDatabase({ filename });
    seedSession(database.db);
    seedEvents(database.db, 1);
    const store = createSessionEventChainStore(database.db);
    expect(() =>
      store.emitCheckpoint({ sessionId: SESSION_ID, checkpointId: "c1", nowMs: 1 })
    ).toThrow(SessionEventChainStoreError);
  });

  it("exports a self-verifying bundle and rejects a tampered one on import", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const verificationKeys = new Map([["chain-key-1", publicKey]]);
    database = openTeamSessionDatabase({ filename });
    seedSession(database.db);
    seedEvents(database.db, 4);
    const store = createSessionEventChainStore(database.db, {
      signingKey: privateKey,
      signingKeyId: "chain-key-1",
      verificationKeys,
    });
    store.emitCheckpoint({ sessionId: SESSION_ID, checkpointId: "c1", nowMs: 400 });
    const bundle = store.exportChain(SESSION_ID);

    const imported = verifyExportedSessionEventChain(bundle, verificationKeys);
    expect(imported).toEqual({
      ok: true,
      sessionId: SESSION_ID,
      headSequence: 4,
      headHash: bundle.events[3].hash,
      verifiedCheckpoints: 1,
    });

    // Tampering with an exported event breaks the re-derived chain.
    const forgedEvents = bundle.events.map((event, index) =>
      index === 1 ? ({ ...event, payload: { forged: true } } as SessionEventChainRecord) : event
    );
    expect(
      verifyExportedSessionEventChain({ ...bundle, events: forgedEvents }, verificationKeys).ok
    ).toBe(false);

    // A checkpoint from an untrusted key is rejected.
    expect(verifyExportedSessionEventChain(bundle, new Map()).ok).toBe(false);
  });
});
