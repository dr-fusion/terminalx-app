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
    expect(() =>
      registry.isWriteAllowed({
        sessionId: " session-one",
        runtimeAuthorizationGeneration: 1,
      })
    ).toThrow(TypeError);
  });

  it("fails closed until one complete durable restart snapshot is installed", () => {
    const registry = createRuntimeWriteStateRegistry({ requireBootstrap: true });
    expect(registry.isBootstrapped).toBe(false);
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 3 })
    ).toBe(false);

    registry.bootstrap([
      {
        sessionId: "session-one",
        runtimeAuthorizationGeneration: 3,
        state: "active",
      },
      {
        sessionId: "session-two",
        runtimeAuthorizationGeneration: 8,
        state: "retired",
      },
    ]);

    expect(registry.isBootstrapped).toBe(true);
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 3 })
    ).toBe(true);
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 2 })
    ).toBe(false);
    expect(
      registry.isWriteAllowed({ sessionId: "session-two", runtimeAuthorizationGeneration: 8 })
    ).toBe(false);
    expect(() => registry.bootstrap([])).toThrow(TypeError);
  });

  it("merges a callback update that races snapshot loading without rolling its fence back", () => {
    const registry = createRuntimeWriteStateRegistry({ requireBootstrap: true });
    registry.update({
      sessionId: "session-one",
      runtimeAuthorizationGeneration: 5,
      state: "retired",
    });
    registry.bootstrap([
      {
        sessionId: "session-one",
        runtimeAuthorizationGeneration: 4,
        state: "active",
      },
    ]);

    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 5 })
    ).toBe(false);
  });

  it("rejects duplicate snapshot sessions and accessor-backed input without invoking it", () => {
    const registry = createRuntimeWriteStateRegistry({ requireBootstrap: true });
    expect(() =>
      registry.bootstrap([
        { sessionId: "session-one", runtimeAuthorizationGeneration: 1, state: "active" },
        { sessionId: "session-one", runtimeAuthorizationGeneration: 2, state: "fenced" },
      ])
    ).toThrow(TypeError);
    expect(registry.isBootstrapped).toBe(false);

    let getterCalls = 0;
    const hostile = Object.defineProperty(
      {
        sessionId: "session-one",
        runtimeAuthorizationGeneration: 1,
      },
      "state",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          return "active";
        },
      }
    );
    expect(() => registry.update(hostile as never)).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it("rejects hostile write-fence descriptors without invoking value getters", () => {
    const registry = createRuntimeWriteStateRegistry({ requireBootstrap: true });
    registry.bootstrap([]);
    let getterCalls = 0;
    const accessor = Object.defineProperty(
      { sessionId: "session-one" },
      "runtimeAuthorizationGeneration",
      {
        enumerable: true,
        get() {
          getterCalls += 1;
          throw new Error("provider-secret-fence-getter");
        },
      }
    );
    expect(() => registry.isWriteAllowed(accessor as never)).toThrow("Invalid Runtime write fence");
    expect(getterCalls).toBe(0);

    const proxy = new Proxy(
      { sessionId: "session-one", runtimeAuthorizationGeneration: 1 },
      {
        getOwnPropertyDescriptor() {
          throw new Error("provider-secret-fence-proxy");
        },
      }
    );
    expect(() => registry.isWriteAllowed(proxy)).toThrow("Invalid Runtime write fence");
  });

  it("leaves raced state untouched after a partially invalid bootstrap and merges it on retry", () => {
    const registry = createRuntimeWriteStateRegistry({ requireBootstrap: true });
    registry.update({
      sessionId: "session-one",
      runtimeAuthorizationGeneration: 5,
      state: "retired",
    });

    expect(() =>
      registry.bootstrap([
        { sessionId: "session-two", runtimeAuthorizationGeneration: 1, state: "active" },
        {
          sessionId: "bad\nsession",
          runtimeAuthorizationGeneration: 2,
          state: "fenced",
        },
      ])
    ).toThrow("Invalid Runtime write-state bootstrap");
    expect(registry.isBootstrapped).toBe(false);

    registry.bootstrap([
      { sessionId: "session-one", runtimeAuthorizationGeneration: 4, state: "active" },
    ]);
    expect(registry.isBootstrapped).toBe(true);
    expect(
      registry.isWriteAllowed({ sessionId: "session-one", runtimeAuthorizationGeneration: 5 })
    ).toBe(false);
  });
});
