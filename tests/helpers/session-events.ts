import type Database from "better-sqlite3";
import {
  chainedSessionEventHashes,
  SESSION_EVENT_CHAIN_SCHEMA,
} from "@/lib/team-sessions/session-event-chain";

export interface ChainedSessionEventFields {
  readonly sessionId: string;
  readonly sequence: number;
  readonly eventId: string;
  readonly type: string;
  readonly occurredAtMs: number;
  readonly actorKind: "human" | "system";
  readonly actorUserId: string;
  readonly actorDisplayName: string;
  readonly sourceScope: string;
  readonly sourceKey: string;
  readonly payloadJson: string;
}

/**
 * Insert a session_events row that satisfies the Phase 10 append-only hash chain
 * trigger. Test fixtures that seed events directly (bypassing the kernel) must
 * produce a valid `prev_hash`/`hash` pair, exactly as the kernel and the Runtime
 * journals do; this helper computes them from the predecessor's hash.
 */
export function insertChainedSessionEvent(
  db: Database.Database,
  fields: ChainedSessionEventFields
): void {
  const columns = db.pragma(`table_info(session_events)`) as Array<{ name: string }>;
  if (!columns.some((column) => column.name === "hash")) {
    // A pre-v17 fixture database has no chain columns yet; the v17 migration
    // will backfill this event's hash when the database is later opened.
    db.prepare(
      `INSERT INTO session_events
         (session_id, sequence, event_id, type, occurred_at_ms,
          actor_kind, actor_user_id, actor_display_name,
          source_scope, source_key, payload_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      fields.sessionId,
      fields.sequence,
      fields.eventId,
      fields.type,
      fields.occurredAtMs,
      fields.actorKind,
      fields.actorUserId,
      fields.actorDisplayName,
      fields.sourceScope,
      fields.sourceKey,
      fields.payloadJson
    );
    return;
  }
  const priorRow =
    fields.sequence === 1
      ? undefined
      : (db
          .prepare(`SELECT hash FROM session_events WHERE session_id = ? AND sequence = ?`)
          .get(fields.sessionId, fields.sequence - 1) as { hash: string } | undefined);
  const { prevHash, hash } = chainedSessionEventHashes(priorRow?.hash ?? null, {
    schema: SESSION_EVENT_CHAIN_SCHEMA,
    sessionId: fields.sessionId,
    sequence: fields.sequence,
    type: fields.type,
    occurredAtMs: fields.occurredAtMs,
    actor: {
      kind: fields.actorKind,
      userId: fields.actorUserId,
      displayName: fields.actorDisplayName,
    },
    source: { scope: fields.sourceScope, key: fields.sourceKey },
    payload: JSON.parse(fields.payloadJson),
  });
  db.prepare(
    `INSERT INTO session_events
       (session_id, sequence, event_id, type, occurred_at_ms,
        actor_kind, actor_user_id, actor_display_name,
        source_scope, source_key, payload_json, prev_hash, hash)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    fields.sessionId,
    fields.sequence,
    fields.eventId,
    fields.type,
    fields.occurredAtMs,
    fields.actorKind,
    fields.actorUserId,
    fields.actorDisplayName,
    fields.sourceScope,
    fields.sourceKey,
    fields.payloadJson,
    prevHash,
    hash
  );
}
