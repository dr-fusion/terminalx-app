import type { ActionClass, Money, ResourceEffect } from "../team-sessions/contracts";
import type { RunLimit, RunLimits } from "../team-sessions/contracts";

/**
 * Gate 5 (Phase 9) canonical-unit and reservation arithmetic.
 *
 * Every quantity is reduced to an explicit canonical integer unit before any
 * comparison or accumulation, so no binary floating-point value, negative
 * value, or non-integer ever reaches the durable reservation ledger:
 *
 * - wall time: whole milliseconds (from {@link Duration.milliseconds})
 * - model tokens: whole tokens
 * - model spend: whole currency minor units, tagged by an exact currency code
 * - outbound bytes: whole bytes
 * - action counts: whole counts, one canonical bucket per {@link ActionClass}
 *
 * An unset user limit is UNLIMITED, and that is the explicit default: a
 * {@link RunLimit} is a closed union of `unconfigured` (unlimited) and
 * `capped`, never `null`/`0`/`Infinity` used as a sentinel. Callers that must
 * make unlimited a deliberate, audited configuration record the
 * `unconfigured` variant explicitly; a missing row is never silently treated
 * as either unlimited or zero by this module.
 */

const ACTION_CLASSES: readonly ActionClass[] = [
  "local",
  "scoped-external",
  "protected",
  "forbidden",
];

/** Largest value any canonical quantity may hold; overflow fails closed. */
export const MAX_CANONICAL_QUANTITY = Number.MAX_SAFE_INTEGER;

const CURRENCY = /^[A-Z]{3}$/;

export class AuthoritativeLimitsError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "AuthoritativeLimitsError";
  }
}

/** Explicit rounding mode. Consumption rounds up; headroom rounds down. */
export type RoundingMode = "ceil" | "floor" | "exact";

/**
 * Round a real-valued measurement to a canonical non-negative integer under an
 * explicit mode. `exact` rejects any fractional input rather than guessing.
 */
export function roundToCanonicalInteger(value: number, mode: RoundingMode, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new AuthoritativeLimitsError(`${label} must be a finite non-negative number`);
  }
  let rounded: number;
  if (mode === "ceil") rounded = Math.ceil(value);
  else if (mode === "floor") rounded = Math.floor(value);
  else {
    if (!Number.isInteger(value)) {
      throw new AuthoritativeLimitsError(`${label} must be an exact integer`);
    }
    rounded = value;
  }
  if (!Number.isSafeInteger(rounded) || rounded > MAX_CANONICAL_QUANTITY) {
    throw new AuthoritativeLimitsError(`${label} exceeds the canonical integer range`);
  }
  return rounded;
}

function canonicalInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new AuthoritativeLimitsError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

export interface CanonicalMoney {
  readonly currency: string;
  readonly minorUnits: number;
}

function canonicalMoney(value: Money, label: string): CanonicalMoney {
  if (!value || typeof value !== "object") {
    throw new AuthoritativeLimitsError(`${label} must be a Money object`);
  }
  if (typeof value.currency !== "string" || !CURRENCY.test(value.currency)) {
    throw new AuthoritativeLimitsError(`${label} currency must be an ISO-4217 code`);
  }
  return Object.freeze({
    currency: value.currency,
    minorUnits: canonicalInteger(value.minorUnits, `${label} minor units`),
  });
}

/** A fully validated, integer-canonical resource effect. */
export interface CanonicalResourceEffect {
  readonly wallClockMs: number;
  readonly modelTokens: number;
  readonly modelSpend: CanonicalMoney;
  readonly outboundBytes: number;
  readonly actionCounts: Readonly<Record<ActionClass, number>>;
}

export function canonicalizeResourceEffect(
  effect: ResourceEffect,
  label = "Resource effect"
): CanonicalResourceEffect {
  if (!effect || typeof effect !== "object") {
    throw new AuthoritativeLimitsError(`${label} must be an object`);
  }
  if (!effect.wallClock || typeof effect.wallClock !== "object") {
    throw new AuthoritativeLimitsError(`${label} wall clock must be a Duration`);
  }
  const actionCounts = effect.actionCounts;
  if (!actionCounts || typeof actionCounts !== "object") {
    throw new AuthoritativeLimitsError(`${label} action counts must be an object`);
  }
  const counts: Record<ActionClass, number> = {
    local: canonicalInteger(actionCounts.local, `${label} local action count`),
    "scoped-external": canonicalInteger(
      actionCounts["scoped-external"],
      `${label} scoped-external action count`
    ),
    protected: canonicalInteger(actionCounts.protected, `${label} protected action count`),
    forbidden: canonicalInteger(actionCounts.forbidden, `${label} forbidden action count`),
  };
  return Object.freeze({
    wallClockMs: canonicalInteger(effect.wallClock.milliseconds, `${label} wall clock ms`),
    modelTokens: canonicalInteger(effect.modelTokens, `${label} model tokens`),
    modelSpend: canonicalMoney(effect.modelSpend, `${label} model spend`),
    outboundBytes: canonicalInteger(effect.outboundBytes, `${label} outbound bytes`),
    actionCounts: Object.freeze(counts),
  });
}

/** The zero effect for a currency. Used to seed an empty ledger. */
export function zeroCanonicalResourceEffect(currency: string): CanonicalResourceEffect {
  if (typeof currency !== "string" || !CURRENCY.test(currency)) {
    throw new AuthoritativeLimitsError("Zero effect currency must be an ISO-4217 code");
  }
  return Object.freeze({
    wallClockMs: 0,
    modelTokens: 0,
    modelSpend: Object.freeze({ currency, minorUnits: 0 }),
    outboundBytes: 0,
    actionCounts: Object.freeze({
      local: 0,
      "scoped-external": 0,
      protected: 0,
      forbidden: 0,
    }),
  });
}

function addChecked(left: number, right: number, label: string): number {
  const sum = left + right;
  if (!Number.isSafeInteger(sum) || sum > MAX_CANONICAL_QUANTITY) {
    throw new AuthoritativeLimitsError(`${label} accumulation overflowed the canonical range`);
  }
  return sum;
}

/**
 * Exact conservative addition of two canonical effects. Currencies must match;
 * a mismatch fails closed rather than coercing. Overflow fails closed.
 */
export function addCanonicalResourceEffects(
  left: CanonicalResourceEffect,
  right: CanonicalResourceEffect
): CanonicalResourceEffect {
  if (left.modelSpend.currency !== right.modelSpend.currency) {
    throw new AuthoritativeLimitsError("Cannot add effects with mismatched spend currencies");
  }
  return Object.freeze({
    wallClockMs: addChecked(left.wallClockMs, right.wallClockMs, "Wall clock"),
    modelTokens: addChecked(left.modelTokens, right.modelTokens, "Model tokens"),
    modelSpend: Object.freeze({
      currency: left.modelSpend.currency,
      minorUnits: addChecked(
        left.modelSpend.minorUnits,
        right.modelSpend.minorUnits,
        "Model spend"
      ),
    }),
    outboundBytes: addChecked(left.outboundBytes, right.outboundBytes, "Outbound bytes"),
    actionCounts: Object.freeze({
      local: addChecked(left.actionCounts.local, right.actionCounts.local, "Local actions"),
      "scoped-external": addChecked(
        left.actionCounts["scoped-external"],
        right.actionCounts["scoped-external"],
        "Scoped-external actions"
      ),
      protected: addChecked(
        left.actionCounts.protected,
        right.actionCounts.protected,
        "Protected actions"
      ),
      forbidden: addChecked(
        left.actionCounts.forbidden,
        right.actionCounts.forbidden,
        "Forbidden actions"
      ),
    }),
  });
}

/**
 * Exact conservative subtraction (`left - right`). Used to release a reserved
 * effect back to the available pool. Underflow (releasing more than reserved)
 * fails closed because it would corrupt the ledger.
 */
export function subtractCanonicalResourceEffects(
  left: CanonicalResourceEffect,
  right: CanonicalResourceEffect
): CanonicalResourceEffect {
  if (left.modelSpend.currency !== right.modelSpend.currency) {
    throw new AuthoritativeLimitsError("Cannot subtract effects with mismatched spend currencies");
  }
  const sub = (a: number, b: number, label: string): number => {
    const diff = a - b;
    if (!Number.isSafeInteger(diff) || diff < 0) {
      throw new AuthoritativeLimitsError(`${label} release underflowed the canonical range`);
    }
    return diff;
  };
  return Object.freeze({
    wallClockMs: sub(left.wallClockMs, right.wallClockMs, "Wall clock"),
    modelTokens: sub(left.modelTokens, right.modelTokens, "Model tokens"),
    modelSpend: Object.freeze({
      currency: left.modelSpend.currency,
      minorUnits: sub(left.modelSpend.minorUnits, right.modelSpend.minorUnits, "Model spend"),
    }),
    outboundBytes: sub(left.outboundBytes, right.outboundBytes, "Outbound bytes"),
    actionCounts: Object.freeze({
      local: sub(left.actionCounts.local, right.actionCounts.local, "Local actions"),
      "scoped-external": sub(
        left.actionCounts["scoped-external"],
        right.actionCounts["scoped-external"],
        "Scoped-external actions"
      ),
      protected: sub(
        left.actionCounts.protected,
        right.actionCounts.protected,
        "Protected actions"
      ),
      forbidden: sub(
        left.actionCounts.forbidden,
        right.actionCounts.forbidden,
        "Forbidden actions"
      ),
    }),
  });
}

/** One canonical, per-dimension optional cap. `null` is UNLIMITED (explicit). */
export interface CanonicalRunLimits {
  readonly wallClockMs: number | null;
  readonly modelTokens: number | null;
  readonly modelSpend: CanonicalMoney | null;
  readonly outboundBytes: number | null;
  readonly actionCounts: Readonly<Record<ActionClass, number | null>>;
}

function canonicalLimit(limit: RunLimit<number>, label: string): number | null {
  if (!limit || typeof limit !== "object") {
    throw new AuthoritativeLimitsError(`${label} must be a RunLimit`);
  }
  if (limit.kind === "unconfigured") return null;
  if (limit.kind === "capped") return canonicalInteger(limit.value, `${label} cap`);
  throw new AuthoritativeLimitsError(`${label} has an unknown RunLimit kind`);
}

export function canonicalizeRunLimits(limits: RunLimits): CanonicalRunLimits {
  if (!limits || typeof limits !== "object") {
    throw new AuthoritativeLimitsError("Run limits must be an object");
  }
  const spend = limits.modelSpend;
  let canonicalSpend: CanonicalMoney | null;
  if (!spend || typeof spend !== "object") {
    throw new AuthoritativeLimitsError("Model spend limit must be a RunLimit");
  }
  if (spend.kind === "unconfigured") canonicalSpend = null;
  else if (spend.kind === "capped")
    canonicalSpend = canonicalMoney(spend.value, "Model spend limit");
  else throw new AuthoritativeLimitsError("Model spend limit has an unknown RunLimit kind");

  const wallClock = limits.wallClock;
  let canonicalWallClock: number | null;
  if (!wallClock || typeof wallClock !== "object") {
    throw new AuthoritativeLimitsError("Wall clock limit must be a RunLimit");
  }
  if (wallClock.kind === "unconfigured") canonicalWallClock = null;
  else if (wallClock.kind === "capped") {
    canonicalWallClock = canonicalInteger(wallClock.value.milliseconds, "Wall clock limit ms");
  } else throw new AuthoritativeLimitsError("Wall clock limit has an unknown RunLimit kind");

  const counts = limits.actionCounts;
  if (!counts || typeof counts !== "object") {
    throw new AuthoritativeLimitsError("Action-count limits must be an object");
  }
  return Object.freeze({
    wallClockMs: canonicalWallClock,
    modelTokens: canonicalLimit(limits.modelTokens, "Model tokens limit"),
    modelSpend: canonicalSpend,
    outboundBytes: canonicalLimit(limits.outboundBytes, "Outbound bytes limit"),
    actionCounts: Object.freeze({
      local: canonicalLimit(counts.local, "Local action-count limit"),
      "scoped-external": canonicalLimit(counts["scoped-external"], "Scoped-external limit"),
      protected: canonicalLimit(counts.protected, "Protected action-count limit"),
      forbidden: canonicalLimit(counts.forbidden, "Forbidden action-count limit"),
    }),
  });
}

export type LimitDimension =
  | "wall-clock"
  | "model-tokens"
  | "model-spend"
  | "outbound-bytes"
  | `action-count:${ActionClass}`
  | "spend-currency-mismatch";

export type ReservationDecision =
  | { readonly admitted: true }
  | { readonly admitted: false; readonly exceeded: ReadonlyArray<LimitDimension> };

/**
 * Would committing `request` on top of already `committed` usage stay within
 * `limits`? An unlimited (`null`) dimension never denies. A spend-currency
 * mismatch always denies — an authoritative ledger must never compare money in
 * two currencies. `committed` is the current reserved-plus-settled total.
 */
export function evaluateReservation(input: {
  readonly limits: CanonicalRunLimits;
  readonly committed: CanonicalResourceEffect;
  readonly request: CanonicalResourceEffect;
}): ReservationDecision {
  const { limits, committed, request } = input;
  const exceeded: LimitDimension[] = [];

  const projected = addCanonicalResourceEffects(committed, request);

  if (limits.wallClockMs !== null && projected.wallClockMs > limits.wallClockMs) {
    exceeded.push("wall-clock");
  }
  if (limits.modelTokens !== null && projected.modelTokens > limits.modelTokens) {
    exceeded.push("model-tokens");
  }
  if (limits.modelSpend !== null) {
    if (limits.modelSpend.currency !== projected.modelSpend.currency) {
      exceeded.push("spend-currency-mismatch");
    } else if (projected.modelSpend.minorUnits > limits.modelSpend.minorUnits) {
      exceeded.push("model-spend");
    }
  }
  if (limits.outboundBytes !== null && projected.outboundBytes > limits.outboundBytes) {
    exceeded.push("outbound-bytes");
  }
  for (const actionClass of ACTION_CLASSES) {
    const cap = limits.actionCounts[actionClass];
    if (cap !== null && projected.actionCounts[actionClass] > cap) {
      exceeded.push(`action-count:${actionClass}`);
    }
  }

  return exceeded.length === 0
    ? { admitted: true }
    : { admitted: false, exceeded: Object.freeze(exceeded) };
}

/** The five utilisation ratios, capped at 1, ignoring unlimited dimensions. */
export function peakUtilisationRatio(
  limits: CanonicalRunLimits,
  committed: CanonicalResourceEffect
): number {
  let peak = 0;
  const consider = (used: number, cap: number | null): void => {
    if (cap === null) return;
    if (cap === 0) {
      peak = Math.max(peak, used > 0 ? 1 : 0);
      return;
    }
    peak = Math.max(peak, Math.min(1, used / cap));
  };
  consider(committed.wallClockMs, limits.wallClockMs);
  consider(committed.modelTokens, limits.modelTokens);
  consider(committed.outboundBytes, limits.outboundBytes);
  if (limits.modelSpend !== null && limits.modelSpend.currency === committed.modelSpend.currency) {
    consider(committed.modelSpend.minorUnits, limits.modelSpend.minorUnits);
  } else if (limits.modelSpend !== null) {
    // A mismatched currency cannot be reasoned about; treat as fully utilised.
    peak = 1;
  }
  for (const actionClass of ACTION_CLASSES) {
    consider(committed.actionCounts[actionClass], limits.actionCounts[actionClass]);
  }
  return peak;
}

export type LimitStatusBand =
  | "within-configured-limits"
  | "warning-75-percent"
  | "approaching-90-percent"
  | "configured-limit-reached";

/** Map a peak utilisation ratio onto the read-model band thresholds. */
export function limitStatusBand(ratio: number): LimitStatusBand {
  if (ratio >= 1) return "configured-limit-reached";
  if (ratio >= 0.9) return "approaching-90-percent";
  if (ratio >= 0.75) return "warning-75-percent";
  return "within-configured-limits";
}
