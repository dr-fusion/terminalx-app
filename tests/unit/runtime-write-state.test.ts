import { describe, expect, it } from "vitest";
import { createRuntimeWriteStateRegistry } from "@/lib/runtime";

describe("Runtime write-state registry", () => {
  it("allows kernel-authorized writes by default and rejects stale generations after a fence", () => {
    const registry = createRuntimeWriteStateRegistry();
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 2 })
    ).toBe(true);

    registry.update({
      sessionId: "session-one",
      runtimeAuthorizationGeneration: 3,
      state: "fenced",
    });
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 2 })
    ).toBe(false);
    // Generation 3 represents the post-fence authority. The kernel keeps it
    // pending until the effect is acknowledged, then permits new clients.
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 3 })
    ).toBe(true);
  });

  it("never rolls a fence backward and keeps a retired generation closed", () => {
    const registry = createRuntimeWriteStateRegistry();
    registry.update({
      sessionId: "session-one",
      runtimeAuthorizationGeneration: 5,
      state: "retired",
    });
    registry.update({
      sessionId: "session-one",
      runtimeAuthorizationGeneration: 4,
      state: "active",
    });
    registry.update({
      sessionId: "session-one",
      runtimeAuthorizationGeneration: 5,
      state: "fenced",
    });

    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 5 })
    ).toBe(false);
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 6 })
    ).toBe(true);
  });

  it("rejects malformed external fence data", () => {
    const registry = createRuntimeWriteStateRegistry();
    expect(() =>
      registry.update({
        sessionId: "bad\nsession",
        runtimeAuthorizationGeneration: 1,
        state: "active",
      })
    ).toThrow(TypeError);
    expect(() =>
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 0 })
    ).toThrow(TypeError);
  });
});
