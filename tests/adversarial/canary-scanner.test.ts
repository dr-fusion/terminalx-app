import { describe, expect, it } from "vitest";
import {
  assertCanaryOnlyIn,
  assertNoCanaryLeak,
  canaryEncodings,
  findCanaryLeaks,
  serializeForScan,
} from "./canary-scanner";

const CANARY = "canary-8g-3f9a1c7e5b2d4088aa17c33e91fe0042d6";

describe("8G canary scanner", () => {
  it("detects the literal secret", () => {
    expect(findCanaryLeaks(`prefix ${CANARY} suffix`, CANARY)).toContainEqual({
      encoding: "literal",
      kind: "whole",
    });
  });

  it("detects base64, base64url, hex, percent, and utf16le encodings", () => {
    const buffer = Buffer.from(CANARY, "utf8");
    const forms: Record<string, string> = {
      base64: buffer.toString("base64"),
      base64url: buffer.toString("base64url"),
      "hex-lower": buffer.toString("hex"),
      "hex-upper": buffer.toString("hex").toUpperCase(),
      "percent-encoded": encodeURIComponent(CANARY),
      "utf16le-hex": Buffer.from(CANARY, "utf16le").toString("hex"),
    };
    for (const [name, value] of Object.entries(forms)) {
      const leaks = findCanaryLeaks(`noise ${value} noise`, CANARY);
      expect(leaks.length, `expected ${name} form to be detected`).toBeGreaterThan(0);
    }
  });

  it("detects a secret smuggled as ordered split chunks across fields", () => {
    const third = Math.floor(CANARY.length / 3);
    const smuggled = {
      a: CANARY.slice(0, third),
      unrelated: "x".repeat(100),
      b: CANARY.slice(third, third * 2),
      more: "y".repeat(50),
      c: CANARY.slice(third * 2),
    };
    const leaks = findCanaryLeaks(smuggled, CANARY);
    expect(leaks).toContainEqual({ encoding: "literal", kind: "split-chunk" });
  });

  it("does not flag out-of-order chunks or unrelated text", () => {
    const third = Math.floor(CANARY.length / 3);
    const reordered = {
      c: CANARY.slice(third * 2),
      b: CANARY.slice(third, third * 2),
      a: CANARY.slice(0, third),
    };
    expect(findCanaryLeaks(reordered, CANARY)).toEqual([]);
    expect(findCanaryLeaks("nothing sensitive here at all", CANARY)).toEqual([]);
  });

  it("deep-serializes Buffers, Errors, Maps, and nested objects", () => {
    const nested = {
      buffer: Buffer.from(CANARY, "utf8"),
    };
    expect(findCanaryLeaks(nested, CANARY).length).toBeGreaterThan(0);

    const error = new Error(`upstream said ${CANARY}`);
    expect(findCanaryLeaks(error, CANARY).length).toBeGreaterThan(0);

    const map = new Map<string, unknown>([["token", CANARY]]);
    expect(findCanaryLeaks(map, CANARY).length).toBeGreaterThan(0);

    const serialized = serializeForScan({ set: new Set([CANARY]) });
    expect(serialized).toContain(CANARY);
  });

  it("tolerates circular references and throwing getters", () => {
    const circular: Record<string, unknown> = { safe: "value" };
    circular.self = circular;
    Object.defineProperty(circular, "hostile", {
      enumerable: true,
      get() {
        throw new Error("hostile getter");
      },
    });
    expect(() => findCanaryLeaks(circular, CANARY)).not.toThrow();
    expect(findCanaryLeaks(circular, CANARY)).toEqual([]);
  });

  it("assertNoCanaryLeak throws with the channel and encoding", () => {
    expect(() =>
      assertNoCanaryLeak("proxy-result", { token: Buffer.from(CANARY).toString("base64") }, CANARY)
    ).toThrow(/proxy-result.*base64/);
    expect(() => assertNoCanaryLeak("proxy-result", { ok: true }, CANARY)).not.toThrow();
  });

  it("assertCanaryOnlyIn passes when the secret reaches only the authorized channel", () => {
    expect(() =>
      assertCanaryOnlyIn(
        "authorization-header",
        {
          "authorization-header": `Bearer ${CANARY}`,
          "result-projection": { ok: true, messageId: "m1" },
          "accounting-row": { requestBytes: 12, responseBytes: 4 },
        },
        CANARY
      )
    ).not.toThrow();
  });

  it("assertCanaryOnlyIn fails when the secret also leaks to another channel", () => {
    expect(() =>
      assertCanaryOnlyIn(
        "authorization-header",
        {
          "authorization-header": `Bearer ${CANARY}`,
          "result-projection": { echoed: CANARY },
        },
        CANARY
      )
    ).toThrow(/result-projection/);
  });

  it("enumerates encodings without duplicates", () => {
    const encodings = canaryEncodings(CANARY);
    const values = encodings.map((encoding) => encoding.value);
    expect(new Set(values).size).toBe(values.length);
    expect(encodings.some((encoding) => encoding.name === "literal")).toBe(true);
  });
});
