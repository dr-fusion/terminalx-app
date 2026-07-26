import { createHash, timingSafeEqual, type randomBytes as RandomBytes } from "node:crypto";
import { canonicalRuntimeJson } from "./runtime-command-canonical";

/**
 * Gate 6 (Phase 9) YOLO challenge.
 *
 * A YOLO challenge is a server-issued, expiring, single-use proof that gates
 * minting the first autonomous ("yolo") Action Grant for a Run. It is bound to
 * the exact actor, session, run policy, and Sandbox identity so that a proof
 * issued for one boundary cannot mint an autonomous grant against a different
 * actor, session, policy, or Sandbox generation.
 *
 * Only the digest of the opaque token is ever persisted (mirroring the Link
 * Challenge discipline in `src/lib/connections/`), and the binding the proof
 * commits to is reduced to a single domain-separated digest. The challenge is
 * consumed ATOMICALLY with the initial Action Grant: the store marks the row
 * consumed and mints the grant in one SQLite transaction, so a crash or a
 * duplicate submission can never mint two autonomous grants from one proof.
 *
 * This module is the pure token/binding/digest layer. The single-use row,
 * issuance rate limits, and atomic consumption live in
 * `src/lib/team-sessions/sqlite-yolo-challenge-store.ts`.
 *
 * Per the roadmap this authority is "Open and unexposed": the lifecycle and
 * atomic consumption are implemented and tested, but no browser route lets a
 * user obtain a YOLO challenge in the running app yet — that is a Phase 11
 * product decision.
 */

export const YOLO_CHALLENGE_TOKEN_PREFIX = "txyc_v1_" as const;
const YOLO_CHALLENGE_TOKEN = /^txyc_v1_[0-9a-f]{64}$/;
const YOLO_CHALLENGE_BINDING_DOMAIN = "terminalx/yolo-challenge-binding/v1\0";
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;

export const YOLO_CHALLENGE_MIN_TTL_MS = 30 * 1_000;
export const YOLO_CHALLENGE_MAX_TTL_MS = 15 * 60 * 1_000;
export const YOLO_CHALLENGE_ISSUANCE_WINDOW_MS = 60 * 60 * 1_000;
export const YOLO_CHALLENGE_MAX_ISSUED_PER_ACTOR_SESSION_WINDOW = 10;
export const YOLO_CHALLENGE_MAX_ACTIVE_PER_ACTOR_SESSION = 3;

export class YoloChallengeError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "YoloChallengeError";
  }
}

/**
 * The exact boundary a YOLO challenge is bound to. Every field participates in
 * the binding digest, so any change (a new policy digest, a superseded Sandbox
 * generation, a different actor) yields a different digest and the outstanding
 * proof no longer resolves.
 */
export interface YoloChallengeBinding {
  readonly userId: string;
  readonly sessionId: string;
  readonly runPolicyDigest: string;
  readonly runtimeAssignmentId: string;
  readonly runtimeAssignmentGeneration: number;
  readonly sandboxId: string;
  readonly sandboxGeneration: number;
  readonly runtimePrincipalId: string;
  readonly runtimeAuthorizationGeneration: number;
}

const BINDING_FIELDS: readonly (keyof YoloChallengeBinding)[] = [
  "userId",
  "sessionId",
  "runPolicyDigest",
  "runtimeAssignmentId",
  "runtimeAssignmentGeneration",
  "sandboxId",
  "sandboxGeneration",
  "runtimePrincipalId",
  "runtimeAuthorizationGeneration",
];

/** Generate a fresh opaque challenge token. Never persisted in the clear. */
export function generateYoloChallengeToken(randomBytes: typeof RandomBytes): string {
  const bytes = randomBytes(32);
  if (!Buffer.isBuffer(bytes) || bytes.length !== 32) {
    throw new YoloChallengeError("Challenge randomness is unavailable");
  }
  return `${YOLO_CHALLENGE_TOKEN_PREFIX}${bytes.toString("hex")}`;
}

/** Validate an untrusted token's shape without revealing which check failed. */
export function assertYoloChallengeToken(token: unknown): string {
  if (typeof token !== "string" || !YOLO_CHALLENGE_TOKEN.test(token)) {
    throw new YoloChallengeError("YOLO challenge token is invalid");
  }
  return token;
}

/** Digest-only persistence key for a token. */
export function digestYoloChallengeToken(token: string): string {
  return createHash("sha256").update(assertYoloChallengeToken(token), "utf8").digest("hex");
}

/** Domain-separated commitment to the exact bound boundary. */
export function digestYoloChallengeBinding(binding: YoloChallengeBinding): string {
  const snapshot = snapshotBinding(binding);
  return createHash("sha256")
    .update(YOLO_CHALLENGE_BINDING_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(snapshot), "utf8")
    .digest("hex");
}

/** Constant-time comparison of two binding digests. */
export function bindingDigestsMatch(left: string, right: string): boolean {
  if (typeof left !== "string" || typeof right !== "string") return false;
  if (!SHA256.test(left) || !SHA256.test(right)) return false;
  try {
    return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
  } catch {
    return false;
  }
}

export function snapshotYoloChallengeBinding(binding: YoloChallengeBinding): YoloChallengeBinding {
  return snapshotBinding(binding);
}

function snapshotBinding(value: unknown): YoloChallengeBinding {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new YoloChallengeError("YOLO challenge binding must be an object");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (
    keys.length !== BINDING_FIELDS.length ||
    keys.some((k) => !BINDING_FIELDS.includes(k as never))
  ) {
    throw new YoloChallengeError("YOLO challenge binding has unexpected fields");
  }
  return Object.freeze({
    userId: safeRef(record.userId),
    sessionId: safeRef(record.sessionId),
    runPolicyDigest: sha256(record.runPolicyDigest),
    runtimeAssignmentId: safeRef(record.runtimeAssignmentId),
    runtimeAssignmentGeneration: positiveInteger(record.runtimeAssignmentGeneration),
    sandboxId: safeRef(record.sandboxId),
    sandboxGeneration: positiveInteger(record.sandboxGeneration),
    runtimePrincipalId: safeRef(record.runtimePrincipalId),
    runtimeAuthorizationGeneration: positiveInteger(record.runtimeAuthorizationGeneration),
  });
}

function safeRef(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REF.test(value)) {
    throw new YoloChallengeError("YOLO challenge binding reference is invalid");
  }
  return value;
}

function sha256(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new YoloChallengeError("YOLO challenge binding digest is invalid");
  }
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new YoloChallengeError("YOLO challenge binding generation is invalid");
  }
  return value as number;
}
