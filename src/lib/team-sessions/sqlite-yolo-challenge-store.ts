import { randomBytes as nodeRandomBytes } from "node:crypto";
import type Database from "better-sqlite3";
import {
  YOLO_CHALLENGE_ISSUANCE_WINDOW_MS,
  YOLO_CHALLENGE_MAX_ACTIVE_PER_ACTOR_SESSION,
  YOLO_CHALLENGE_MAX_ISSUED_PER_ACTOR_SESSION_WINDOW,
  YOLO_CHALLENGE_MAX_TTL_MS,
  YOLO_CHALLENGE_MIN_TTL_MS,
  assertYoloChallengeToken,
  bindingDigestsMatch,
  digestYoloChallengeBinding,
  digestYoloChallengeToken,
  generateYoloChallengeToken,
  snapshotYoloChallengeBinding,
  type YoloChallengeBinding,
} from "../runtime/yolo-challenge";

/**
 * Gate 6 (Phase 9) YOLO challenge store.
 *
 * A challenge is issued server-side, rate-limited per actor/session (mirroring
 * the Link Challenge discipline), and persisted digest-only and single-use. It
 * is consumed ATOMICALLY with the initial Action Grant: the `mint` callback runs
 * inside the same transaction that flips the single-use row to `consumed`, so a
 * crash or a duplicate submission can never mint two autonomous grants from one
 * proof. A changed Sandbox / execution boundary invalidates outstanding
 * challenges (ties to Gate 4 revocation).
 *
 * Per the roadmap this authority stays "Open and unexposed": there is no browser
 * route that lets a user obtain a challenge in the running app; the lifecycle and
 * atomic consumption are implemented and tested for a Phase 11 product decision.
 */

export interface YoloChallengeStoreOptions {
  readonly randomBytes?: typeof nodeRandomBytes;
}

export interface IssueYoloChallengeInput {
  readonly challengeId: string;
  readonly userId: string;
  readonly binding: YoloChallengeBinding;
  readonly ttlMs?: number;
  readonly nowMs: number;
}

export interface IssuedYoloChallenge {
  readonly challenge: string;
  readonly challengeId: string;
  readonly expiresAtMs: number;
  readonly bindingDigest: string;
}

export interface ConsumeYoloChallengeInput {
  readonly challenge: string;
  readonly binding: YoloChallengeBinding;
  readonly nowMs: number;
}

export type ConsumeYoloChallengeOutcome<T> =
  | { readonly outcome: "consumed"; readonly grantId: string; readonly result: T }
  | { readonly outcome: "unknown" }
  | { readonly outcome: "expired" }
  | { readonly outcome: "boundary-mismatch" }
  | { readonly outcome: "already-resolved"; readonly status: string };

export class YoloChallengeStoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "YoloChallengeStoreError";
  }
}

interface ChallengeRow {
  id: string;
  challenge_digest: string;
  binding_digest: string;
  user_id: string;
  session_id: string;
  status: string;
  expires_at_ms: number;
}

export interface YoloChallengeStore {
  issue(input: IssueYoloChallengeInput): IssuedYoloChallenge;
  /**
   * Atomically consume the single-use challenge and mint the initial Action
   * Grant. `mint` receives the validated binding and must return the minted
   * grant id (plus any caller result); it runs in the consuming transaction, so
   * it must not perform I/O outside `db`.
   */
  consumeWithGrant<T>(
    input: ConsumeYoloChallengeInput,
    mint: (binding: YoloChallengeBinding) => { readonly grantId: string; readonly result: T }
  ): ConsumeYoloChallengeOutcome<T>;
  invalidateForBoundaryChange(input: {
    readonly sessionId: string;
    readonly currentBindingDigest: string;
    readonly nowMs: number;
  }): number;
  expireStale(nowMs: number): number;
}

export function createYoloChallengeStore(
  db: Database.Database,
  options: YoloChallengeStoreOptions = {}
): YoloChallengeStore {
  const randomBytes = options.randomBytes ?? nodeRandomBytes;

  const countIssuedInWindow = db.prepare<[string, string, number]>(
    `SELECT COUNT(*) AS count FROM yolo_challenges
     WHERE user_id = ? AND session_id = ? AND issued_at_ms >= ?`
  );
  const countActive = db.prepare<[string, string, number]>(
    `SELECT COUNT(*) AS count FROM yolo_challenges
     WHERE user_id = ? AND session_id = ? AND status = 'active' AND expires_at_ms > ?`
  );
  const insertChallenge = db.prepare(
    `INSERT INTO yolo_challenges (
       id, challenge_digest, binding_digest, user_id, session_id, run_policy_digest,
       runtime_assignment_id, runtime_assignment_generation, sandbox_id, sandbox_generation,
       runtime_principal_id, runtime_authorization_generation, status, consumed_grant_id,
       issued_at_ms, expires_at_ms, resolved_at_ms
     ) VALUES (
       @id, @challenge_digest, @binding_digest, @user_id, @session_id, @run_policy_digest,
       @runtime_assignment_id, @runtime_assignment_generation, @sandbox_id, @sandbox_generation,
       @runtime_principal_id, @runtime_authorization_generation, 'active', NULL,
       @issued_at_ms, @expires_at_ms, NULL
     )`
  );
  const findByDigest = db.prepare<[string]>(
    "SELECT * FROM yolo_challenges WHERE challenge_digest = ?"
  );
  const consumeRow = db.prepare<[string, number, string]>(
    `UPDATE yolo_challenges
     SET status = 'consumed', consumed_grant_id = ?, resolved_at_ms = ?
     WHERE challenge_digest = ? AND status = 'active'`
  );
  const invalidateBoundary = db.prepare<[number, string, string]>(
    `UPDATE yolo_challenges
     SET status = 'invalidated', resolved_at_ms = ?
     WHERE session_id = ? AND status = 'active' AND binding_digest <> ?`
  );
  const expireRows = db.prepare<[number, number]>(
    `UPDATE yolo_challenges
     SET status = 'expired', resolved_at_ms = ?
     WHERE status = 'active' AND expires_at_ms <= ?`
  );

  const issueTx = db.transaction((input: IssueYoloChallengeInput): IssuedYoloChallenge => {
    if (!Number.isSafeInteger(input.nowMs) || input.nowMs < 0) {
      throw new YoloChallengeStoreError("nowMs must be a non-negative integer");
    }
    const binding = snapshotYoloChallengeBinding(input.binding);
    if (binding.userId !== input.userId) {
      throw new YoloChallengeStoreError("Issuer must match the bound user");
    }
    const ttlMs = input.ttlMs ?? YOLO_CHALLENGE_MAX_TTL_MS;
    if (
      !Number.isSafeInteger(ttlMs) ||
      ttlMs < YOLO_CHALLENGE_MIN_TTL_MS ||
      ttlMs > YOLO_CHALLENGE_MAX_TTL_MS
    ) {
      throw new YoloChallengeStoreError("YOLO challenge TTL is out of range");
    }
    const windowStart = Math.max(0, input.nowMs - YOLO_CHALLENGE_ISSUANCE_WINDOW_MS);
    const issued = countIssuedInWindow.get(input.userId, binding.sessionId, windowStart) as {
      count: number;
    };
    if (issued.count >= YOLO_CHALLENGE_MAX_ISSUED_PER_ACTOR_SESSION_WINDOW) {
      throw new YoloChallengeStoreError("YOLO challenge issuance rate exceeded");
    }
    const active = countActive.get(input.userId, binding.sessionId, input.nowMs) as {
      count: number;
    };
    if (active.count >= YOLO_CHALLENGE_MAX_ACTIVE_PER_ACTOR_SESSION) {
      throw new YoloChallengeStoreError("Too many active YOLO challenges");
    }
    const token = generateYoloChallengeToken(randomBytes);
    const expiresAtMs = input.nowMs + ttlMs;
    const bindingDigest = digestYoloChallengeBinding(binding);
    insertChallenge.run({
      id: input.challengeId,
      challenge_digest: digestYoloChallengeToken(token),
      binding_digest: bindingDigest,
      user_id: input.userId,
      session_id: binding.sessionId,
      run_policy_digest: binding.runPolicyDigest,
      runtime_assignment_id: binding.runtimeAssignmentId,
      runtime_assignment_generation: binding.runtimeAssignmentGeneration,
      sandbox_id: binding.sandboxId,
      sandbox_generation: binding.sandboxGeneration,
      runtime_principal_id: binding.runtimePrincipalId,
      runtime_authorization_generation: binding.runtimeAuthorizationGeneration,
      issued_at_ms: input.nowMs,
      expires_at_ms: expiresAtMs,
    });
    return Object.freeze({
      challenge: token,
      challengeId: input.challengeId,
      expiresAtMs,
      bindingDigest,
    });
  });

  return Object.freeze({
    issue(input: IssueYoloChallengeInput): IssuedYoloChallenge {
      return issueTx.immediate(input);
    },
    consumeWithGrant<T>(
      input: ConsumeYoloChallengeInput,
      mint: (binding: YoloChallengeBinding) => { readonly grantId: string; readonly result: T }
    ): ConsumeYoloChallengeOutcome<T> {
      const token = assertYoloChallengeToken(input.challenge);
      const digest = digestYoloChallengeToken(token);
      const presentedBinding = snapshotYoloChallengeBinding(input.binding);
      const presentedDigest = digestYoloChallengeBinding(presentedBinding);
      const tx = db.transaction((): ConsumeYoloChallengeOutcome<T> => {
        const row = findByDigest.get(digest) as ChallengeRow | undefined;
        if (!row) return { outcome: "unknown" };
        if (row.status !== "active") {
          return { outcome: "already-resolved", status: row.status };
        }
        if (row.expires_at_ms <= input.nowMs) {
          expireRows.run(input.nowMs, input.nowMs);
          return { outcome: "expired" };
        }
        if (!bindingDigestsMatch(row.binding_digest, presentedDigest)) {
          return { outcome: "boundary-mismatch" };
        }
        const minted = mint(presentedBinding);
        if (!minted || typeof minted.grantId !== "string" || minted.grantId.length === 0) {
          throw new YoloChallengeStoreError("mint callback must return a grant id");
        }
        const updated = consumeRow.run(minted.grantId, input.nowMs, digest);
        if (updated.changes !== 1) {
          // Another consumer won the single-use race; abort so nothing is minted.
          throw new YoloChallengeStoreError("YOLO challenge consumption race");
        }
        return { outcome: "consumed", grantId: minted.grantId, result: minted.result };
      });
      return tx.immediate();
    },
    invalidateForBoundaryChange(input: {
      readonly sessionId: string;
      readonly currentBindingDigest: string;
      readonly nowMs: number;
    }): number {
      const result = invalidateBoundary.run(
        input.nowMs,
        input.sessionId,
        input.currentBindingDigest
      );
      return result.changes;
    },
    expireStale(nowMs: number): number {
      return expireRows.run(nowMs, nowMs).changes;
    },
  });
}
