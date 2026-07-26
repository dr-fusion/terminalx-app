import type { KeyObject } from "node:crypto";
import type Database from "better-sqlite3";
import {
  digestSessionEventCheckpoint,
  SESSION_EVENT_CHAIN_EXPORT_SCHEMA,
  SESSION_EVENT_CHAIN_GENESIS,
  SESSION_EVENT_CHECKPOINT_KIND,
  SESSION_EVENT_CHECKPOINT_SCHEMA,
  signSessionEventCheckpoint,
  verifySessionEventChain,
  verifySessionEventCheckpoint,
  type ChainVerificationResult,
  type SessionEventChainExport,
  type SessionEventChainRecord,
  type SessionEventCheckpointPayload,
  type SessionEventCheckpointProof,
} from "./session-event-chain";

/**
 * Phase 10 Gate 8 — durable side of the session-event hash chain.
 *
 * Reads the ordered chain, verifies it (detecting tamper/gap/reorder), emits
 * Ed25519-signed checkpoints over the chain head, and exports a self-verifying
 * bundle (events + signed checkpoints) for external retention. Signing and
 * verification are fail-closed: emitting a checkpoint without a configured
 * signing key throws, and a stored checkpoint that does not verify is reported
 * as unverified rather than trusted.
 */

export interface SessionEventChainStoreOptions {
  readonly signingKey?: KeyObject;
  readonly signingKeyId?: string;
  /** Trusted verification keys by key id, used to authenticate stored checkpoints. */
  readonly verificationKeys?: ReadonlyMap<string, KeyObject>;
}

export class SessionEventChainStoreError extends Error {
  readonly code: "signing-unavailable" | "empty-chain" | "chain-invalid";
  constructor(code: SessionEventChainStoreError["code"], message: string) {
    super(message);
    this.name = "SessionEventChainStoreError";
    this.code = code;
  }
}

export interface StoredCheckpointVerification {
  readonly checkpoint: SessionEventCheckpointProof;
  readonly payload: SessionEventCheckpointPayload | null;
}

export interface SessionEventChainStore {
  readChain(sessionId: string): SessionEventChainRecord[];
  verifyChain(sessionId: string): ChainVerificationResult;
  emitCheckpoint(input: {
    sessionId: string;
    checkpointId: string;
    nowMs: number;
  }): SessionEventCheckpointProof;
  readCheckpoints(sessionId: string): SessionEventCheckpointProof[];
  verifyStoredCheckpoints(sessionId: string): StoredCheckpointVerification[];
  exportChain(sessionId: string): SessionEventChainExport;
}

export function createSessionEventChainStore(
  db: Database.Database,
  options: SessionEventChainStoreOptions = {}
): SessionEventChainStore {
  const selectEvents = db.prepare<[string]>(
    `SELECT session_id, sequence, event_id, type, occurred_at_ms, actor_kind,
            actor_user_id, actor_display_name, source_scope, source_key,
            payload_json, prev_hash, hash
       FROM session_events WHERE session_id = ? ORDER BY sequence ASC`
  );
  const selectHead = db.prepare<[string]>(
    `SELECT sequence, hash FROM session_events
       WHERE session_id = ? ORDER BY sequence DESC LIMIT 1`
  );
  const selectCheckpoints = db.prepare<[string]>(
    `SELECT session_id, head_sequence, head_hash, genesis_root, signing_key_id,
            signature, issued_at_ms
       FROM session_event_checkpoints WHERE session_id = ? ORDER BY head_sequence ASC`
  );
  const insertCheckpoint = db.prepare(
    `INSERT INTO session_event_checkpoints (
       id, session_id, head_sequence, head_hash, genesis_root, signing_key_id,
       checkpoint_digest, signature, issued_at_ms, created_at_ms
     ) VALUES (
       @id, @session_id, @head_sequence, @head_hash, @genesis_root, @signing_key_id,
       @checkpoint_digest, @signature, @issued_at_ms, @created_at_ms
     )`
  );

  function readChain(sessionId: string): SessionEventChainRecord[] {
    const rows = selectEvents.all(sessionId) as Array<Record<string, unknown>>;
    return rows.map((row) => ({
      schema: 1,
      sessionId: row.session_id as string,
      sequence: row.sequence as number,
      eventId: row.event_id as string,
      type: row.type as string,
      occurredAtMs: row.occurred_at_ms as number,
      actor: {
        kind: row.actor_kind as "human" | "system",
        userId: row.actor_user_id as string,
        displayName: row.actor_display_name as string,
      },
      source: { scope: row.source_scope as string, key: row.source_key as string },
      payload: JSON.parse(row.payload_json as string),
      prevHash: row.prev_hash as string,
      hash: row.hash as string,
    }));
  }

  function checkpointProofFromRow(row: Record<string, unknown>): SessionEventCheckpointProof {
    return {
      payload: {
        schema: SESSION_EVENT_CHECKPOINT_SCHEMA,
        kind: SESSION_EVENT_CHECKPOINT_KIND,
        signingKeyId: row.signing_key_id as string,
        sessionId: row.session_id as string,
        headSequence: row.head_sequence as number,
        headHash: row.head_hash as string,
        genesisRoot: row.genesis_root as string,
        issuedAtMs: row.issued_at_ms as number,
      },
      signature: row.signature as string,
    };
  }

  const emitTx = db.transaction(
    (input: { sessionId: string; checkpointId: string; nowMs: number }) => {
      if (!options.signingKey || !options.signingKeyId) {
        throw new SessionEventChainStoreError(
          "signing-unavailable",
          "No session-event checkpoint signing key is configured"
        );
      }
      const head = selectHead.get(input.sessionId) as
        | { sequence: number; hash: string }
        | undefined;
      if (!head) {
        throw new SessionEventChainStoreError(
          "empty-chain",
          "Cannot checkpoint a session with no events"
        );
      }
      // Never sign a head the chain does not actually support.
      const verified = verifySessionEventChain(readChain(input.sessionId));
      if (!verified.ok || verified.headHash !== head.hash) {
        throw new SessionEventChainStoreError(
          "chain-invalid",
          "Refusing to checkpoint an invalid session event chain"
        );
      }
      const payload: SessionEventCheckpointPayload = {
        schema: SESSION_EVENT_CHECKPOINT_SCHEMA,
        kind: SESSION_EVENT_CHECKPOINT_KIND,
        signingKeyId: options.signingKeyId,
        sessionId: input.sessionId,
        headSequence: head.sequence,
        headHash: head.hash,
        genesisRoot: SESSION_EVENT_CHAIN_GENESIS,
        issuedAtMs: input.nowMs,
      };
      const proof = signSessionEventCheckpoint(payload, options.signingKey);
      insertCheckpoint.run({
        id: input.checkpointId,
        session_id: proof.payload.sessionId,
        head_sequence: proof.payload.headSequence,
        head_hash: proof.payload.headHash,
        genesis_root: proof.payload.genesisRoot,
        signing_key_id: proof.payload.signingKeyId,
        checkpoint_digest: digestSessionEventCheckpoint(proof.payload),
        signature: proof.signature,
        issued_at_ms: proof.payload.issuedAtMs,
        created_at_ms: input.nowMs,
      });
      return proof;
    }
  );

  return Object.freeze({
    readChain,
    verifyChain(sessionId: string): ChainVerificationResult {
      return verifySessionEventChain(readChain(sessionId));
    },
    emitCheckpoint(input): SessionEventCheckpointProof {
      return emitTx.immediate(input);
    },
    readCheckpoints(sessionId: string): SessionEventCheckpointProof[] {
      const rows = selectCheckpoints.all(sessionId) as Array<Record<string, unknown>>;
      return rows.map(checkpointProofFromRow);
    },
    verifyStoredCheckpoints(sessionId: string): StoredCheckpointVerification[] {
      const rows = selectCheckpoints.all(sessionId) as Array<Record<string, unknown>>;
      return rows.map((row) => {
        const checkpoint = checkpointProofFromRow(row);
        const key = options.verificationKeys?.get(checkpoint.payload.signingKeyId);
        const payload = key ? verifySessionEventCheckpoint(checkpoint, key) : null;
        return { checkpoint, payload };
      });
    },
    exportChain(sessionId: string): SessionEventChainExport {
      return Object.freeze({
        schema: SESSION_EVENT_CHAIN_EXPORT_SCHEMA,
        sessionId,
        genesisRoot: SESSION_EVENT_CHAIN_GENESIS,
        events: readChain(sessionId),
        checkpoints: (selectCheckpoints.all(sessionId) as Array<Record<string, unknown>>).map(
          checkpointProofFromRow
        ),
      });
    },
  });
}
