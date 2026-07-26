import { createHash, sign, verify, type KeyObject } from "node:crypto";
import { canonicalRuntimeJson } from "../runtime/runtime-command-canonical";

/**
 * Phase 10 Gate 8 — Session event hash chain and signed checkpoints.
 *
 * Every `session_events` row is bound into an append-only hash chain: each event
 * commits to its immutable content and to the hash of its predecessor, so a
 * later reader can recompute the chain and detect any tamper, gap, reorder, or
 * deletion. The chain begins from a single, fixed, domain-separated genesis
 * root (the same constant for every session — the per-event commitment to
 * `sessionId` already prevents chains from being swapped between sessions).
 *
 * A signed checkpoint is an Ed25519 signature over the chain head (the session,
 * the head sequence, and the head hash). It lets an external retainer prove the
 * head it holds was attested by the authority without holding the signing key,
 * and — combined with a re-derivation of the chain — proves the retained events
 * are exactly the attested ones. Only digests and opaque identifiers are signed;
 * never secret material.
 *
 * ## Key management
 *
 * The session-event-checkpoint signing key is a trust key managed exactly like
 * the other TerminalX main-process trust keys (the runtime authority keys, the
 * Secret Broker receipt key, and the Phase 9 approval-provenance key): an
 * Ed25519 key pair whose private half is loaded once at composition time from a
 * `0600` key file under the server's trust root and never leaves the main
 * process, and whose public half is published for local verification. It is a
 * DISTINCT key from every other trust key so the ability to attest an event
 * chain cannot be conflated with the ability to issue runtime commands, resolve
 * credential handles, or sign approval provenance. Rotation follows the same
 * key-id-tagged discipline: each checkpoint records its `signingKeyId`, and a
 * verifier is composed with the set of currently trusted checkpoint keys.
 * Verification fails closed: any tampering, a foreign key, or a malformed field
 * returns a failure result rather than throwing a distinguishing error.
 */

/** Event schema committed by the chain; matches the wire `SessionEvent.schemaVersion`. */
export const SESSION_EVENT_CHAIN_SCHEMA = 1 as const;

const SESSION_EVENT_DIGEST_DOMAIN = "terminalx/session-event-chain/event/v1\0";
const SESSION_EVENT_GENESIS_DOMAIN = "terminalx/session-event-chain/genesis/v1\0";

export const SESSION_EVENT_CHECKPOINT_KIND = "terminalx.session-event-checkpoint" as const;
export const SESSION_EVENT_CHECKPOINT_SCHEMA = 1 as const;
const CHECKPOINT_SIGNATURE_DOMAIN = "terminalx/session-event-checkpoint/v1\0";
const CHECKPOINT_DIGEST_DOMAIN = "terminalx/session-event-checkpoint-digest/v1\0";

const SHA256 = /^[0-9a-f]{64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;

/**
 * The fixed, domain-separated genesis root every session chain descends from.
 * Computed once so it can be embedded verbatim in the SQLite chain trigger and
 * reused by the TypeScript hasher and verifier.
 */
export const SESSION_EVENT_CHAIN_GENESIS: string = createHash("sha256")
  .update(SESSION_EVENT_GENESIS_DOMAIN, "utf8")
  .digest("hex");

export interface SessionEventChainActor {
  readonly kind: "human" | "system";
  readonly userId: string;
  readonly displayName: string;
}

export interface SessionEventChainSource {
  readonly scope: string;
  readonly key: string;
}

/** The exact, immutable content a chain hash commits to. */
export interface SessionEventChainInput {
  readonly schema: number;
  readonly sessionId: string;
  readonly sequence: number;
  readonly type: string;
  readonly occurredAtMs: number;
  readonly actor: SessionEventChainActor;
  readonly source: SessionEventChainSource;
  /** JSON value (already round-tripped through `JSON.parse`) that was persisted. */
  readonly payload: unknown;
  readonly prevHash: string;
}

/**
 * Lowercase SHA-256 over the domain separator and the canonical event content,
 * including the predecessor hash. Deterministic: the same fields always yield
 * the same digest, which is what makes the migration backfill reproducible.
 */
export function digestSessionEvent(input: SessionEventChainInput): string {
  return createHash("sha256")
    .update(SESSION_EVENT_DIGEST_DOMAIN, "utf8")
    .update(
      canonicalRuntimeJson({
        schema: input.schema,
        sessionId: input.sessionId,
        sequence: input.sequence,
        type: input.type,
        occurredAtMs: input.occurredAtMs,
        actor: {
          kind: input.actor.kind,
          userId: input.actor.userId,
          displayName: input.actor.displayName,
        },
        source: { scope: input.source.scope, key: input.source.key },
        payload: input.payload,
        prevHash: input.prevHash,
      }),
      "utf8"
    )
    .digest("hex");
}

/**
 * Compute the `prev_hash`/`hash` pair for a new event from the predecessor's
 * hash. Shared by every `session_events` writer (the Team Session kernel and the
 * Runtime lifecycle/compensation/receipt-follow journals) so all appends produce
 * the identical chain the SQLite trigger and the verifier expect.
 */
export function chainedSessionEventHashes(
  priorHash: string | null,
  input: Omit<SessionEventChainInput, "prevHash">
): { readonly prevHash: string; readonly hash: string } {
  const prevHash = previousChainHash(input.sequence, priorHash);
  const hash = digestSessionEvent({ ...input, prevHash });
  return { prevHash, hash };
}

/** The predecessor hash for a given sequence: genesis for the first event. */
export function previousChainHash(sequence: number, priorHash: string | null): string {
  if (sequence === 1) return SESSION_EVENT_CHAIN_GENESIS;
  if (priorHash === null || !SHA256.test(priorHash)) {
    throw new SessionEventChainError("missing-prior-hash");
  }
  return priorHash;
}

export class SessionEventChainError extends Error {
  readonly code:
    | "missing-prior-hash"
    | "invalid-payload"
    | "invalid-signature"
    | "invalid-checkpoint";
  constructor(code: SessionEventChainError["code"]) {
    super("Session event chain input is invalid");
    this.name = "SessionEventChainError";
    this.code = code;
  }
}

/** A single event as it appears in an exported, self-verifying chain bundle. */
export interface SessionEventChainRecord {
  readonly schema: number;
  readonly sessionId: string;
  readonly sequence: number;
  readonly eventId: string;
  readonly type: string;
  readonly occurredAtMs: number;
  readonly actor: SessionEventChainActor;
  readonly source: SessionEventChainSource;
  readonly payload: unknown;
  readonly prevHash: string;
  readonly hash: string;
}

export interface SessionEventCheckpointPayload {
  readonly schema: typeof SESSION_EVENT_CHECKPOINT_SCHEMA;
  readonly kind: typeof SESSION_EVENT_CHECKPOINT_KIND;
  readonly signingKeyId: string;
  readonly sessionId: string;
  readonly headSequence: number;
  readonly headHash: string;
  readonly genesisRoot: string;
  readonly issuedAtMs: number;
}

export interface SessionEventCheckpointProof {
  readonly payload: SessionEventCheckpointPayload;
  readonly signature: string;
}

function checkpointSigningInput(payload: SessionEventCheckpointPayload): Buffer {
  return Buffer.from(`${CHECKPOINT_SIGNATURE_DOMAIN}${canonicalRuntimeJson(payload)}`, "utf8");
}

/** Lowercase SHA-256 over the canonical, domain-separated checkpoint payload. */
export function digestSessionEventCheckpoint(payload: SessionEventCheckpointPayload): string {
  return createHash("sha256")
    .update(CHECKPOINT_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(snapshotCheckpointPayload(payload)), "utf8")
    .digest("hex");
}

export function snapshotCheckpointPayload(value: unknown): SessionEventCheckpointPayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new SessionEventChainError("invalid-checkpoint");
  }
  const record = value as Record<string, unknown>;
  const signingKeyId = record.signingKeyId;
  const sessionId = record.sessionId;
  const headSequence = record.headSequence;
  const headHash = record.headHash;
  const genesisRoot = record.genesisRoot;
  const issuedAtMs = record.issuedAtMs;
  if (
    record.schema !== SESSION_EVENT_CHECKPOINT_SCHEMA ||
    record.kind !== SESSION_EVENT_CHECKPOINT_KIND ||
    typeof signingKeyId !== "string" ||
    signingKeyId.length < 1 ||
    signingKeyId.length > 300 ||
    typeof sessionId !== "string" ||
    sessionId.length < 1 ||
    sessionId.length > 300 ||
    !Number.isSafeInteger(headSequence) ||
    headSequence < 1 ||
    typeof headHash !== "string" ||
    !SHA256.test(headHash) ||
    typeof genesisRoot !== "string" ||
    !SHA256.test(genesisRoot) ||
    !Number.isSafeInteger(issuedAtMs) ||
    issuedAtMs < 0
  ) {
    throw new SessionEventChainError("invalid-checkpoint");
  }
  return Object.freeze({
    schema: SESSION_EVENT_CHECKPOINT_SCHEMA,
    kind: SESSION_EVENT_CHECKPOINT_KIND,
    signingKeyId,
    sessionId,
    headSequence,
    headHash,
    genesisRoot,
    issuedAtMs,
  });
}

export function signSessionEventCheckpoint(
  payload: SessionEventCheckpointPayload,
  signingPrivateKey: KeyObject
): SessionEventCheckpointProof {
  assertEd25519Key(signingPrivateKey, "private");
  const snapshot = snapshotCheckpointPayload(payload);
  const signature = sign(null, checkpointSigningInput(snapshot), signingPrivateKey).toString(
    "base64url"
  );
  if (!SIGNATURE.test(signature)) throw new SessionEventChainError("invalid-signature");
  return Object.freeze({ payload: snapshot, signature });
}

/**
 * Verify a checkpoint proof against `verificationPublicKey`, returning the
 * validated payload or `null`. Fails closed on any error.
 */
export function verifySessionEventCheckpoint(
  proof: unknown,
  verificationPublicKey: KeyObject
): SessionEventCheckpointPayload | null {
  try {
    assertEd25519Key(verificationPublicKey, "public");
    if (typeof proof !== "object" || proof === null || Array.isArray(proof)) return null;
    const record = proof as Record<string, unknown>;
    const signature = record.signature;
    if (typeof signature !== "string" || !SIGNATURE.test(signature)) return null;
    const payload = snapshotCheckpointPayload(record.payload);
    const valid = verify(
      null,
      checkpointSigningInput(payload),
      verificationPublicKey,
      Buffer.from(signature, "base64url")
    );
    return valid ? payload : null;
  } catch {
    return null;
  }
}

export type ChainVerificationFailure =
  | { readonly kind: "empty" }
  | { readonly kind: "gap"; readonly sequence: number }
  | { readonly kind: "reorder"; readonly sequence: number }
  | { readonly kind: "prev-hash-mismatch"; readonly sequence: number }
  | { readonly kind: "hash-mismatch"; readonly sequence: number }
  | { readonly kind: "genesis-mismatch"; readonly sequence: number }
  | { readonly kind: "invalid-record"; readonly index: number };

export type ChainVerificationResult =
  | { readonly ok: true; readonly headSequence: number; readonly headHash: string }
  | { readonly ok: false; readonly failure: ChainVerificationFailure };

/**
 * Recompute a chain from ordered event records, detecting tamper (a recomputed
 * hash that does not match the stored hash), gaps, reorders, and broken links.
 * Pure: no database access, so an external retainer can call it on an exported
 * bundle. `expectedGenesis` defaults to the canonical genesis root.
 */
export function verifySessionEventChain(
  records: readonly SessionEventChainRecord[],
  expectedGenesis: string = SESSION_EVENT_CHAIN_GENESIS
): ChainVerificationResult {
  if (records.length === 0) return { ok: false, failure: { kind: "empty" } };
  let previous = expectedGenesis;
  let expectedSequence = 1;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (!isChainRecord(record)) {
      return { ok: false, failure: { kind: "invalid-record", index } };
    }
    if (record.sequence < expectedSequence) {
      return { ok: false, failure: { kind: "reorder", sequence: record.sequence } };
    }
    if (record.sequence > expectedSequence) {
      return { ok: false, failure: { kind: "gap", sequence: expectedSequence } };
    }
    if (record.sequence === 1 && record.prevHash !== expectedGenesis) {
      return { ok: false, failure: { kind: "genesis-mismatch", sequence: record.sequence } };
    }
    if (record.prevHash !== previous) {
      return { ok: false, failure: { kind: "prev-hash-mismatch", sequence: record.sequence } };
    }
    const recomputed = digestSessionEvent({
      schema: record.schema,
      sessionId: record.sessionId,
      sequence: record.sequence,
      type: record.type,
      occurredAtMs: record.occurredAtMs,
      actor: record.actor,
      source: record.source,
      payload: record.payload,
      prevHash: record.prevHash,
    });
    if (recomputed !== record.hash) {
      return { ok: false, failure: { kind: "hash-mismatch", sequence: record.sequence } };
    }
    previous = record.hash;
    expectedSequence += 1;
  }
  return { ok: true, headSequence: records[records.length - 1].sequence, headHash: previous };
}

/** Export format version for a self-verifying chain bundle. */
export const SESSION_EVENT_CHAIN_EXPORT_SCHEMA = 1 as const;

/**
 * A self-verifying, externally-retainable bundle: the ordered event chain plus
 * every signed checkpoint. This is the externally-retainable release evidence
 * that Phase 8's internal ledger explicitly was not — a holder can re-derive the
 * chain and check the checkpoint signatures without any TerminalX state.
 */
export interface SessionEventChainExport {
  readonly schema: typeof SESSION_EVENT_CHAIN_EXPORT_SCHEMA;
  readonly sessionId: string;
  readonly genesisRoot: string;
  readonly events: readonly SessionEventChainRecord[];
  readonly checkpoints: readonly SessionEventCheckpointProof[];
}

export type ChainImportResult =
  | {
      readonly ok: true;
      readonly sessionId: string;
      readonly headSequence: number;
      readonly headHash: string;
      readonly verifiedCheckpoints: number;
    }
  | {
      readonly ok: false;
      readonly reason:
        | "malformed-bundle"
        | "chain-invalid"
        | "checkpoint-unverified"
        | "checkpoint-head-mismatch"
        | "checkpoint-session-mismatch";
      readonly detail?: ChainVerificationFailure;
    };

/**
 * Verify an exported bundle end to end: re-derive the event chain, then confirm
 * every checkpoint is signed by a trusted key and pins a head hash/sequence that
 * matches the re-derived chain. Fails closed — an unverifiable checkpoint or a
 * head that does not match the chain rejects the whole bundle. Pure: usable by
 * an external retainer holding only the bundle and the trusted public keys.
 */
export function verifyExportedSessionEventChain(
  bundle: unknown,
  verificationKeys: ReadonlyMap<string, KeyObject>
): ChainImportResult {
  if (typeof bundle !== "object" || bundle === null || Array.isArray(bundle)) {
    return { ok: false, reason: "malformed-bundle" };
  }
  const record = bundle as Record<string, unknown>;
  if (
    record.schema !== SESSION_EVENT_CHAIN_EXPORT_SCHEMA ||
    typeof record.sessionId !== "string" ||
    typeof record.genesisRoot !== "string" ||
    !SHA256.test(record.genesisRoot) ||
    !Array.isArray(record.events) ||
    !Array.isArray(record.checkpoints)
  ) {
    return { ok: false, reason: "malformed-bundle" };
  }
  const events = record.events as SessionEventChainRecord[];
  if (events.some((event) => !isChainRecord(event) || event.sessionId !== record.sessionId)) {
    return { ok: false, reason: "malformed-bundle" };
  }
  const chain = verifySessionEventChain(events, record.genesisRoot);
  if (!chain.ok) return { ok: false, reason: "chain-invalid", detail: chain.failure };
  const bySequence = new Map(events.map((event) => [event.sequence, event.hash] as const));
  let verifiedCheckpoints = 0;
  for (const rawCheckpoint of record.checkpoints as unknown[]) {
    const checkpointRecord =
      typeof rawCheckpoint === "object" && rawCheckpoint !== null
        ? (rawCheckpoint as Record<string, unknown>)
        : undefined;
    const payloadRecord =
      checkpointRecord && typeof checkpointRecord.payload === "object"
        ? (checkpointRecord.payload as Record<string, unknown>)
        : undefined;
    const keyId = payloadRecord?.signingKeyId;
    const key = typeof keyId === "string" ? verificationKeys.get(keyId) : undefined;
    if (!key) return { ok: false, reason: "checkpoint-unverified" };
    const payload = verifySessionEventCheckpoint(rawCheckpoint, key);
    if (!payload) return { ok: false, reason: "checkpoint-unverified" };
    if (payload.sessionId !== record.sessionId || payload.genesisRoot !== record.genesisRoot) {
      return { ok: false, reason: "checkpoint-session-mismatch" };
    }
    if (bySequence.get(payload.headSequence) !== payload.headHash) {
      return { ok: false, reason: "checkpoint-head-mismatch" };
    }
    verifiedCheckpoints += 1;
  }
  return {
    ok: true,
    sessionId: record.sessionId,
    headSequence: chain.headSequence,
    headHash: chain.headHash,
    verifiedCheckpoints,
  };
}

function isChainRecord(value: unknown): value is SessionEventChainRecord {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record.sessionId === "string" &&
    Number.isSafeInteger(record.sequence) &&
    (record.sequence as number) >= 1 &&
    typeof record.type === "string" &&
    Number.isSafeInteger(record.occurredAtMs) &&
    typeof record.prevHash === "string" &&
    SHA256.test(record.prevHash as string) &&
    typeof record.hash === "string" &&
    SHA256.test(record.hash as string) &&
    isActor(record.actor) &&
    isSource(record.source)
  );
}

function isActor(value: unknown): value is SessionEventChainActor {
  if (typeof value !== "object" || value === null) return false;
  const actor = value as Record<string, unknown>;
  return (
    (actor.kind === "human" || actor.kind === "system") &&
    typeof actor.userId === "string" &&
    typeof actor.displayName === "string"
  );
}

function isSource(value: unknown): value is SessionEventChainSource {
  if (typeof value !== "object" || value === null) return false;
  const source = value as Record<string, unknown>;
  return typeof source.scope === "string" && typeof source.key === "string";
}

function assertEd25519Key(value: unknown, type: "public" | "private"): asserts value is KeyObject {
  if (
    !(value instanceof Object) ||
    (value as KeyObject).type !== type ||
    (value as KeyObject).asymmetricKeyType !== "ed25519"
  ) {
    throw new SessionEventChainError(
      type === "private" ? "invalid-signature" : "invalid-checkpoint"
    );
  }
}
