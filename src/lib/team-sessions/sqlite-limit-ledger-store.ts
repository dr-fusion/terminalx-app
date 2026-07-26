import type Database from "better-sqlite3";
import {
  addCanonicalResourceEffects,
  canonicalizeResourceEffect,
  canonicalizeRunLimits,
  evaluateReservation,
  limitStatusBand,
  peakUtilisationRatio,
  zeroCanonicalResourceEffect,
  type CanonicalResourceEffect,
  type LimitStatusBand,
  type ReservationDecision,
} from "../runtime/authoritative-limits";
import type { ResourceEffect, RunLimits } from "./contracts";

/**
 * Gate 5 (Phase 9) durable reservation/accounting ledger.
 *
 * Reservations are keyed to Runtime-receipt identity: `reserve` is idempotent by
 * the reserve receipt digest, and `settle`/`release` are idempotent by the
 * settle receipt digest. A duplicate receipt therefore never double-counts, and
 * a crash between reserve and settle leaves a durable reserved row that still
 * counts against the cap (conservative) until it is settled to actual usage or
 * released.
 *
 * Enforcement is fail-closed: `reserve` admits an effect only when the projected
 * committed usage stays within the canonical run limits, and it never invents
 * usage. If the ledger cannot be read or written the caller sees the thrown
 * error and must deny the effect.
 */

const SHA256 = /^[0-9a-f]{64}$/;
const CURRENCY = /^[A-Z]{3}$/;

export class LimitLedgerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LimitLedgerError";
  }
}

export interface ReserveInput {
  readonly reservationId: string;
  readonly sessionId: string;
  readonly agentRunId: string;
  readonly reserveReceiptDigest: string;
  readonly request: ResourceEffect;
  readonly limits: RunLimits;
  readonly nowMs: number;
}

export type ReserveResult =
  | { readonly reservationId: string; readonly decision: { readonly admitted: true } }
  | { readonly decision: Extract<ReservationDecision, { admitted: false }> };

export interface SettleInput {
  readonly reservationId: string;
  readonly settleReceiptDigest: string;
  readonly actualUsage: ResourceEffect;
  readonly nowMs: number;
}

export interface ReleaseInput {
  readonly reservationId: string;
  readonly settleReceiptDigest: string;
  readonly currency: string;
  readonly nowMs: number;
}

interface EffectColumns {
  currency: string;
  wall_clock_ms: number;
  model_tokens: number;
  model_spend_minor: number;
  outbound_bytes: number;
  action_local: number;
  action_scoped_external: number;
  action_protected: number;
  action_forbidden: number;
}

export interface LimitLedgerStore {
  reserve(input: ReserveInput): ReserveResult;
  settle(input: SettleInput): void;
  release(input: ReleaseInput): void;
  committedUsage(agentRunId: string, currency: string): CanonicalResourceEffect;
  limitStatus(agentRunId: string, limits: RunLimits, fallbackCurrency: string): LimitStatusBand;
}

function assertDigest(value: string, label: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new LimitLedgerError(`${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function assertCurrency(value: string): string {
  if (typeof value !== "string" || !CURRENCY.test(value)) {
    throw new LimitLedgerError("Currency must be an ISO-4217 code");
  }
  return value;
}

function assertNow(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new LimitLedgerError("nowMs must be a non-negative safe integer");
  }
  return value;
}

function effectColumns(effect: CanonicalResourceEffect): Record<string, string | number> {
  return {
    currency: effect.modelSpend.currency,
    wall_clock_ms: effect.wallClockMs,
    model_tokens: effect.modelTokens,
    model_spend_minor: effect.modelSpend.minorUnits,
    outbound_bytes: effect.outboundBytes,
    action_local: effect.actionCounts.local,
    action_scoped_external: effect.actionCounts["scoped-external"],
    action_protected: effect.actionCounts.protected,
    action_forbidden: effect.actionCounts.forbidden,
  };
}

function rowToEffect(row: EffectColumns): CanonicalResourceEffect {
  return Object.freeze({
    wallClockMs: row.wall_clock_ms,
    modelTokens: row.model_tokens,
    modelSpend: Object.freeze({ currency: row.currency, minorUnits: row.model_spend_minor }),
    outboundBytes: row.outbound_bytes,
    actionCounts: Object.freeze({
      local: row.action_local,
      "scoped-external": row.action_scoped_external,
      protected: row.action_protected,
      forbidden: row.action_forbidden,
    }),
  });
}

export function createLimitLedgerStore(db: Database.Database): LimitLedgerStore {
  const findByReserveReceipt = db.prepare<[string]>(
    "SELECT reservation_id FROM limit_reservations WHERE reserve_receipt_digest = ?"
  );
  const findReservation = db.prepare<[string]>(
    "SELECT * FROM limit_reservations WHERE reservation_id = ?"
  );
  const findSettlement = db.prepare<[string]>(
    "SELECT * FROM limit_settlements WHERE reservation_id = ?"
  );
  const findSettlementByReceipt = db.prepare<[string]>(
    "SELECT reservation_id FROM limit_settlements WHERE settle_receipt_digest = ?"
  );
  const insertReservation = db.prepare(
    `INSERT INTO limit_reservations (
       reservation_id, session_id, agent_run_id, reserve_receipt_digest, currency,
       wall_clock_ms, model_tokens, model_spend_minor, outbound_bytes,
       action_local, action_scoped_external, action_protected, action_forbidden, created_at_ms
     ) VALUES (
       @reservation_id, @session_id, @agent_run_id, @reserve_receipt_digest, @currency,
       @wall_clock_ms, @model_tokens, @model_spend_minor, @outbound_bytes,
       @action_local, @action_scoped_external, @action_protected, @action_forbidden, @created_at_ms
     )`
  );
  const insertSettlement = db.prepare(
    `INSERT INTO limit_settlements (
       reservation_id, disposition, settle_receipt_digest, currency,
       wall_clock_ms, model_tokens, model_spend_minor, outbound_bytes,
       action_local, action_scoped_external, action_protected, action_forbidden, created_at_ms
     ) VALUES (
       @reservation_id, @disposition, @settle_receipt_digest, @currency,
       @wall_clock_ms, @model_tokens, @model_spend_minor, @outbound_bytes,
       @action_local, @action_scoped_external, @action_protected, @action_forbidden, @created_at_ms
     )`
  );

  // Committed usage = settled actuals + still-open reservations (reserved, not
  // yet settled or released). Released reservations contribute nothing.
  const sumOpenReserved = db.prepare<[string]>(
    `SELECT
       COALESCE(SUM(r.wall_clock_ms), 0) AS wall_clock_ms,
       COALESCE(SUM(r.model_tokens), 0) AS model_tokens,
       COALESCE(SUM(r.model_spend_minor), 0) AS model_spend_minor,
       COALESCE(SUM(r.outbound_bytes), 0) AS outbound_bytes,
       COALESCE(SUM(r.action_local), 0) AS action_local,
       COALESCE(SUM(r.action_scoped_external), 0) AS action_scoped_external,
       COALESCE(SUM(r.action_protected), 0) AS action_protected,
       COALESCE(SUM(r.action_forbidden), 0) AS action_forbidden
     FROM limit_reservations r
     WHERE r.agent_run_id = ?
       AND NOT EXISTS (SELECT 1 FROM limit_settlements s WHERE s.reservation_id = r.reservation_id)`
  );
  const sumSettled = db.prepare<[string]>(
    `SELECT
       COALESCE(SUM(s.wall_clock_ms), 0) AS wall_clock_ms,
       COALESCE(SUM(s.model_tokens), 0) AS model_tokens,
       COALESCE(SUM(s.model_spend_minor), 0) AS model_spend_minor,
       COALESCE(SUM(s.outbound_bytes), 0) AS outbound_bytes,
       COALESCE(SUM(s.action_local), 0) AS action_local,
       COALESCE(SUM(s.action_scoped_external), 0) AS action_scoped_external,
       COALESCE(SUM(s.action_protected), 0) AS action_protected,
       COALESCE(SUM(s.action_forbidden), 0) AS action_forbidden
     FROM limit_settlements s
     JOIN limit_reservations r ON r.reservation_id = s.reservation_id
     WHERE r.agent_run_id = ? AND s.disposition = 'settled'`
  );

  function committedUsage(agentRunId: string, currency: string): CanonicalResourceEffect {
    assertCurrency(currency);
    const open = sumOpenReserved.get(agentRunId) as Record<string, number>;
    const settled = sumSettled.get(agentRunId) as Record<string, number>;
    const openEffect = rowToEffect({ ...(open as unknown as EffectColumns), currency });
    const settledEffect = rowToEffect({ ...(settled as unknown as EffectColumns), currency });
    return addCanonicalResourceEffects(openEffect, settledEffect);
  }

  const reserveTx = db.transaction((input: ReserveInput): ReserveResult => {
    const existing = findByReserveReceipt.get(input.reserveReceiptDigest) as
      | { reservation_id: string }
      | undefined;
    if (existing) {
      // Idempotent retry of the same receipt: never re-evaluate or double-count.
      return { reservationId: existing.reservation_id, decision: { admitted: true } };
    }
    const request = canonicalizeResourceEffect(input.request, "Reservation request");
    const limits = canonicalizeRunLimits(input.limits);
    const committed = committedUsage(input.agentRunId, request.modelSpend.currency);
    const decision = evaluateReservation({ limits, committed, request });
    if (!decision.admitted) return { decision };
    insertReservation.run({
      reservation_id: input.reservationId,
      session_id: input.sessionId,
      agent_run_id: input.agentRunId,
      reserve_receipt_digest: input.reserveReceiptDigest,
      ...effectColumns(request),
      created_at_ms: input.nowMs,
    });
    return { reservationId: input.reservationId, decision: { admitted: true } };
  });

  const settleTx = db.transaction((input: SettleInput): void => {
    const byReceipt = findSettlementByReceipt.get(input.settleReceiptDigest) as
      | { reservation_id: string }
      | undefined;
    if (byReceipt) {
      if (byReceipt.reservation_id !== input.reservationId) {
        throw new LimitLedgerError("Settle receipt already bound to a different reservation");
      }
      return; // idempotent duplicate settle
    }
    const reservation = findReservation.get(input.reservationId) as EffectColumns | undefined;
    if (!reservation) throw new LimitLedgerError("Unknown reservation");
    if (findSettlement.get(input.reservationId)) {
      throw new LimitLedgerError("Reservation already settled or released");
    }
    const actual = canonicalizeResourceEffect(input.actualUsage, "Settlement usage");
    if (actual.modelSpend.currency !== reservation.currency) {
      throw new LimitLedgerError("Settlement currency does not match the reservation");
    }
    insertSettlement.run({
      reservation_id: input.reservationId,
      disposition: "settled",
      settle_receipt_digest: input.settleReceiptDigest,
      ...effectColumns(actual),
      created_at_ms: input.nowMs,
    });
  });

  const releaseTx = db.transaction((input: ReleaseInput): void => {
    const byReceipt = findSettlementByReceipt.get(input.settleReceiptDigest) as
      | { reservation_id: string }
      | undefined;
    if (byReceipt) {
      if (byReceipt.reservation_id !== input.reservationId) {
        throw new LimitLedgerError("Release receipt already bound to a different reservation");
      }
      return; // idempotent duplicate release
    }
    const reservation = findReservation.get(input.reservationId) as EffectColumns | undefined;
    if (!reservation) throw new LimitLedgerError("Unknown reservation");
    if (findSettlement.get(input.reservationId)) {
      throw new LimitLedgerError("Reservation already settled or released");
    }
    insertSettlement.run({
      reservation_id: input.reservationId,
      disposition: "released",
      settle_receipt_digest: input.settleReceiptDigest,
      ...effectColumns(zeroCanonicalResourceEffect(reservation.currency)),
      created_at_ms: input.nowMs,
    });
  });

  return Object.freeze({
    reserve(input: ReserveInput): ReserveResult {
      assertDigest(input.reserveReceiptDigest, "Reserve receipt digest");
      assertNow(input.nowMs);
      return reserveTx.immediate(input);
    },
    settle(input: SettleInput): void {
      assertDigest(input.settleReceiptDigest, "Settle receipt digest");
      assertNow(input.nowMs);
      settleTx.immediate(input);
    },
    release(input: ReleaseInput): void {
      assertDigest(input.settleReceiptDigest, "Settle receipt digest");
      assertCurrency(input.currency);
      assertNow(input.nowMs);
      releaseTx.immediate(input);
    },
    committedUsage,
    limitStatus(agentRunId: string, limits: RunLimits, fallbackCurrency: string): LimitStatusBand {
      const canonicalLimits = canonicalizeRunLimits(limits);
      const currency = canonicalLimits.modelSpend?.currency ?? assertCurrency(fallbackCurrency);
      const committed = committedUsage(agentRunId, currency);
      return limitStatusBand(peakUtilisationRatio(canonicalLimits, committed));
    },
  });
}
