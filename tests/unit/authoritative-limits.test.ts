import { describe, expect, it } from "vitest";
import {
  AuthoritativeLimitsError,
  addCanonicalResourceEffects,
  canonicalizeResourceEffect,
  canonicalizeRunLimits,
  evaluateReservation,
  limitStatusBand,
  peakUtilisationRatio,
  roundToCanonicalInteger,
  subtractCanonicalResourceEffects,
  zeroCanonicalResourceEffect,
} from "@/lib/runtime/authoritative-limits";
import type { ResourceEffect, RunLimits } from "@/lib/team-sessions/contracts";

function effect(overrides: Partial<ResourceEffect> = {}): ResourceEffect {
  return {
    wallClock: { milliseconds: 1_000 },
    modelTokens: 100,
    modelSpend: { currency: "USD", minorUnits: 50 },
    outboundBytes: 200,
    actionCounts: { local: 1, "scoped-external": 0, protected: 0, forbidden: 0 },
    ...overrides,
  };
}

const unlimited: RunLimits = {
  wallClock: { kind: "unconfigured" },
  modelTokens: { kind: "unconfigured" },
  modelSpend: { kind: "unconfigured" },
  outboundBytes: { kind: "unconfigured" },
  actionCounts: {
    local: { kind: "unconfigured" },
    "scoped-external": { kind: "unconfigured" },
    protected: { kind: "unconfigured" },
    forbidden: { kind: "unconfigured" },
  },
};

describe("authoritative limits — canonical units and rounding", () => {
  it("rounds up for consumption, down for headroom, and rejects non-integers when exact", () => {
    expect(roundToCanonicalInteger(1.0001, "ceil", "x")).toBe(2);
    expect(roundToCanonicalInteger(1.9999, "floor", "x")).toBe(1);
    expect(roundToCanonicalInteger(3, "exact", "x")).toBe(3);
    expect(() => roundToCanonicalInteger(1.5, "exact", "x")).toThrow(AuthoritativeLimitsError);
    expect(() => roundToCanonicalInteger(-1, "ceil", "x")).toThrow(AuthoritativeLimitsError);
    // exact rounding boundary: whole values pass every mode identically
    expect(roundToCanonicalInteger(10, "ceil", "x")).toBe(10);
    expect(roundToCanonicalInteger(10, "floor", "x")).toBe(10);
  });

  it("rejects fractional, negative, or non-object canonical effects", () => {
    expect(() => canonicalizeResourceEffect(effect({ modelTokens: 1.5 }))).toThrow(
      AuthoritativeLimitsError
    );
    expect(() => canonicalizeResourceEffect(effect({ outboundBytes: -1 }))).toThrow(
      AuthoritativeLimitsError
    );
    expect(() =>
      canonicalizeResourceEffect(effect({ modelSpend: { currency: "usd", minorUnits: 1 } }))
    ).toThrow(AuthoritativeLimitsError);
  });

  it("adds and subtracts effects exactly and fails closed on currency mismatch or underflow", () => {
    const a = canonicalizeResourceEffect(effect());
    const b = canonicalizeResourceEffect(effect({ modelTokens: 5 }));
    expect(addCanonicalResourceEffects(a, b).modelTokens).toBe(105);
    expect(subtractCanonicalResourceEffects(addCanonicalResourceEffects(a, b), b)).toEqual(a);
    expect(() => subtractCanonicalResourceEffects(a, b)).not.toThrow();
    expect(() =>
      subtractCanonicalResourceEffects(
        canonicalizeResourceEffect(effect({ modelTokens: 1 })),
        canonicalizeResourceEffect(effect({ modelTokens: 5 }))
      )
    ).toThrow(AuthoritativeLimitsError);
    const eur = canonicalizeResourceEffect(
      effect({ modelSpend: { currency: "EUR", minorUnits: 1 } })
    );
    expect(() => addCanonicalResourceEffects(a, eur)).toThrow(AuthoritativeLimitsError);
  });

  it("fails closed on accumulation overflow near the safe-integer ceiling", () => {
    const big = canonicalizeResourceEffect(effect({ outboundBytes: Number.MAX_SAFE_INTEGER }));
    const one = canonicalizeResourceEffect(effect({ outboundBytes: 1 }));
    expect(() => addCanonicalResourceEffects(big, one)).toThrow(AuthoritativeLimitsError);
  });
});

describe("authoritative limits — unlimited default and reservation", () => {
  it("treats every unconfigured dimension as unlimited and never denies", () => {
    const limits = canonicalizeRunLimits(unlimited);
    expect(limits.wallClockMs).toBeNull();
    expect(limits.modelSpend).toBeNull();
    const decision = evaluateReservation({
      limits,
      committed: canonicalizeResourceEffect(effect({ modelTokens: Number.MAX_SAFE_INTEGER - 1 })),
      request: canonicalizeResourceEffect(effect({ modelTokens: 0 })),
    });
    expect(decision.admitted).toBe(true);
  });

  it("denies exactly the dimensions that a projected reservation would exceed", () => {
    const limits = canonicalizeRunLimits({
      ...unlimited,
      modelTokens: { kind: "capped", value: 150 },
      outboundBytes: { kind: "capped", value: 250 },
    });
    const committed = canonicalizeResourceEffect(effect({ modelTokens: 100, outboundBytes: 200 }));
    const withinExact = evaluateReservation({
      limits,
      committed,
      request: canonicalizeResourceEffect(effect({ modelTokens: 50, outboundBytes: 50 })),
    });
    expect(withinExact.admitted).toBe(true); // boundary: exactly at cap is admitted
    const over = evaluateReservation({
      limits,
      committed,
      request: canonicalizeResourceEffect(effect({ modelTokens: 51, outboundBytes: 51 })),
    });
    expect(over).toEqual({ admitted: false, exceeded: ["model-tokens", "outbound-bytes"] });
  });

  it("denies a spend reservation whose currency differs from the cap", () => {
    const limits = canonicalizeRunLimits({
      ...unlimited,
      modelSpend: { kind: "capped", value: { currency: "USD", minorUnits: 1_000 } },
    });
    const decision = evaluateReservation({
      limits,
      committed: zeroCanonicalResourceEffect("EUR"),
      request: canonicalizeResourceEffect(
        effect({ modelSpend: { currency: "EUR", minorUnits: 1 } })
      ),
    });
    expect(decision).toMatchObject({ admitted: false, exceeded: ["spend-currency-mismatch"] });
  });

  it("maps utilisation onto the read-model status bands including the zero-cap edge", () => {
    const limits = canonicalizeRunLimits({
      ...unlimited,
      modelTokens: { kind: "capped", value: 100 },
    });
    expect(limitStatusBand(peakUtilisationRatio(limits, zeroCanonicalResourceEffect("USD")))).toBe(
      "within-configured-limits"
    );
    expect(
      limitStatusBand(
        peakUtilisationRatio(limits, canonicalizeResourceEffect(effect({ modelTokens: 76 })))
      )
    ).toBe("warning-75-percent");
    expect(
      limitStatusBand(
        peakUtilisationRatio(limits, canonicalizeResourceEffect(effect({ modelTokens: 95 })))
      )
    ).toBe("approaching-90-percent");
    expect(
      limitStatusBand(
        peakUtilisationRatio(limits, canonicalizeResourceEffect(effect({ modelTokens: 100 })))
      )
    ).toBe("configured-limit-reached");

    const zeroCap = canonicalizeRunLimits({
      ...unlimited,
      actionCounts: {
        ...unlimited.actionCounts,
        protected: { kind: "capped", value: 0 },
      },
    });
    expect(
      limitStatusBand(
        peakUtilisationRatio(
          zeroCap,
          canonicalizeResourceEffect(
            effect({ actionCounts: { local: 0, "scoped-external": 0, protected: 1, forbidden: 0 } })
          )
        )
      )
    ).toBe("configured-limit-reached");
  });
});
