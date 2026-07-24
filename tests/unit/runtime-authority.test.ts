import { describe, expect, expectTypeOf, it } from "vitest";
import {
  RUNTIME_COMMAND_CAPABILITY,
  RuntimeAuthorityBindingError,
  assertRuntimeCommandAuthorityBinding,
  assertRuntimeRetireAuthorityBinding,
  type RuntimeCommand,
  type RuntimeRetireRequest,
} from "@/lib/runtime";

describe("Runtime authority binding", () => {
  it("binds every Runtime command kind to one exact capability", () => {
    for (const [kind, capability] of Object.entries(RUNTIME_COMMAND_CAPABILITY)) {
      expect(() =>
        assertRuntimeCommandAuthorityBinding({
          kind,
          authority: authority(
            kind === "safety.quarantine" ? "platform-security" : "team-session",
            capability
          ),
        })
      ).not.toThrow();
    }

    expectTypeOf<
      Extract<RuntimeCommand, { kind: "terminal.input" }>["authority"]["capability"]
    >().toEqualTypeOf<"terminal.input">();
    expectTypeOf<
      Extract<RuntimeCommand, { kind: "run.pause" }>["authority"]["capability"]
    >().toEqualTypeOf<"run.pause">();
    expectTypeOf<
      Extract<RuntimeCommand, { kind: "terminal.input" }>["authority"]["issuer"]
    >().toEqualTypeOf<"team-session">();
  });

  it("allows platform security only for its exact emergency capabilities", () => {
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "run.emergency-stop",
        authority: authority("platform-security", "run.emergency-stop"),
      })
    ).not.toThrow();
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "safety.quarantine",
        authority: authority("platform-security", "safety.quarantine"),
      })
    ).not.toThrow();
    expectTypeOf<
      Extract<RuntimeCommand, { kind: "run.emergency-stop" }>["authority"]["issuer"]
    >().toEqualTypeOf<"team-session" | "platform-security">();
    expectTypeOf<
      Extract<RuntimeCommand, { kind: "safety.quarantine" }>["authority"]["issuer"]
    >().toEqualTypeOf<"platform-security">();
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "safety.quarantine",
        authority: authority("team-session", "safety.quarantine"),
      })
    ).toThrow(RuntimeAuthorityBindingError);
  });

  it("rejects capability substitution and unauthorized issuers", () => {
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "terminal.input",
        authority: authority("team-session", "run.pause"),
      })
    ).toThrow(RuntimeAuthorityBindingError);
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "terminal.input",
        authority: authority("platform-security", "terminal.input"),
      })
    ).toThrow(RuntimeAuthorityBindingError);
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "run.emergency-stop",
        authority: authority("platform-security", "safety.quarantine"),
      })
    ).toThrow(RuntimeAuthorityBindingError);
  });

  it("uses a distinct Team Session authority for destructive retirement", () => {
    expect(() =>
      assertRuntimeRetireAuthorityBinding({
        authority: authority("team-session", "runtime.retire"),
      })
    ).not.toThrow();
    expect(() =>
      assertRuntimeRetireAuthorityBinding({
        authority: authority("team-session", "run.stop"),
      })
    ).toThrow(RuntimeAuthorityBindingError);
    expect(() =>
      assertRuntimeRetireAuthorityBinding({
        authority: authority("platform-security", "runtime.retire"),
      })
    ).toThrow(RuntimeAuthorityBindingError);
    expectTypeOf<
      RuntimeRetireRequest["authority"]["capability"]
    >().toEqualTypeOf<"runtime.retire">();
    expectTypeOf<RuntimeRetireRequest["authority"]["issuer"]>().toEqualTypeOf<"team-session">();
  });

  it("rejects non-canonical or extended authority envelopes", () => {
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "run.pause",
        authority: { ...authority("team-session", "run.pause"), unexpected: true },
      })
    ).toThrow(RuntimeAuthorityBindingError);
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "run.pause",
        authority: {
          ...authority("team-session", "run.pause"),
          claimsDigest: "not-a-digest",
        },
      })
    ).toThrow(RuntimeAuthorityBindingError);
    expect(() =>
      assertRuntimeCommandAuthorityBinding({
        kind: "run.pause",
        authority: {
          ...authority("team-session", "run.pause"),
          expiresAtMs: 10,
          issuedAtMs: 10,
        },
      })
    ).toThrow(RuntimeAuthorityBindingError);
  });
});

function authority(issuer: string, capability: string): Record<string, unknown> {
  return {
    issuerKeyId: "runtime-key:v1",
    audience: "runtime",
    claimsDigest: "a".repeat(64),
    issuedAtMs: 10,
    expiresAtMs: 20,
    signature: "signed-envelope",
    issuer,
    capability,
  };
}
