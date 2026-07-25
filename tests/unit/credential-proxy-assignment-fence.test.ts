import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { establishBrokerRoot } from "../../packages/secret-broker/src/broker-root";
import { openSecretBrokerStateStore } from "../../packages/secret-broker/src/state-store";
import { openProxyAccountingStore } from "../../packages/secret-broker/src/proxy/accounting-store";
import { openAtRest, sealAtRest } from "../../packages/secret-broker/src/at-rest";
import { createCredentialProxy } from "../../packages/secret-broker/src/proxy/credential-proxy";
import {
  openAssignmentEligibilityStore,
  type AssignmentEligibilityStore,
} from "../../packages/secret-broker/src/proxy/assignment-eligibility-store";
import type {
  ProxyCallerFence,
  ProxyResultClass,
} from "../../packages/secret-broker/src/proxy/proxy-protocol";
import type { ProxyOutboundRequest } from "../../packages/secret-broker/src/proxy/network-client";

const TELEGRAM_EXPECTATION = "a".repeat(64);
const SANDBOX_DIGEST_A = "c".repeat(64);
const SANDBOX_DIGEST_B = "d".repeat(64);

interface Harness {
  execute(
    handleId: string,
    caller: ProxyCallerFence | undefined
  ): Promise<{ resultClass: ProxyResultClass; errorCode: string | null }>;
  activeHandle(): string;
  revoke(handleId: string): void;
  eligibility: AssignmentEligibilityStore;
  cleanup(): void;
}

function createHarness(options: { withEligibility?: boolean } = {}): Harness {
  const rootDir = fs.mkdtempSync(path.join(os.tmpdir(), "assignment-fence-"));
  fs.chmodSync(rootDir, 0o700);
  const root = establishBrokerRoot({ rootDir });
  const store = openSecretBrokerStateStore({ databasePath: ":memory:" });
  const accounting = openProxyAccountingStore({ databasePath: ":memory:" });
  const eligibility = openAssignmentEligibilityStore({ databasePath: ":memory:" });
  const requests: ProxyOutboundRequest[] = [];
  const clock = { now: 1_700_000_000_000 };
  let counter = 0;
  const proxy = createCredentialProxy({
    store,
    accounting,
    clock: () => clock.now,
    resolveCredential: (brokerKind, material) =>
      brokerKind === "oauth-envelope" ? openAtRest(material, root.atRestKey) : null,
    ...(options.withEligibility === false ? {} : { assignmentEligibility: eligibility }),
    network: {
      async send(request: ProxyOutboundRequest) {
        requests.push(request);
        return {
          status: 200,
          body: Buffer.from(JSON.stringify({ ok: true, result: { message_id: 1, date: 1 } })),
        };
      },
    },
  });
  return {
    async execute(handleId, caller) {
      const result = await proxy.execute({
        operationId: `op_${(counter += 1)}`,
        operation: "telegram.sendMessage",
        authority: {
          provider: "telegram",
          handleId,
          handleGeneration: 1,
          expectationDigest: TELEGRAM_EXPECTATION,
          installationId: "inst",
          installationRevision: 1,
          bindingId: null,
          bindingRevision: null,
        },
        ...(caller ? { caller } : {}),
        params: { chatId: "1", text: "x" },
      });
      return { resultClass: result.resultClass, errorCode: result.errorCode };
    },
    activeHandle() {
      counter += 1;
      const handleId = `hnd_${counter}`;
      store.prepare({
        operationId: `prep_${counter}`,
        handleId,
        receiptId: `rcp_${counter}`,
        provider: "telegram",
        brokerKind: "oauth-envelope",
        usage: "installation",
        expectationDigest: TELEGRAM_EXPECTATION,
        replacesHandleId: null,
        issuedAtMs: clock.now,
        expiresAtMs: clock.now + 60_000,
        secretMaterial: sealAtRest(Buffer.from("bot-token", "utf8"), root.atRestKey),
      });
      store.finalize(handleId, `rcp_${counter}`);
      return handleId;
    },
    revoke(handleId) {
      store.revoke(handleId);
      eligibility.revoke(handleId, clock.now);
    },
    eligibility,
    cleanup() {
      store.close();
      accounting.close();
      eligibility.close();
      fs.rmSync(rootDir, { recursive: true, force: true });
    },
  };
}

function hosted(
  runtimeAssignmentId: string,
  generation: number,
  sandboxIdentityDigest = SANDBOX_DIGEST_A
): ProxyCallerFence {
  return {
    class: "hosted-assignment",
    runtimeAssignmentId,
    runtimeAssignmentGeneration: generation,
    sandboxIdentityDigest,
  };
}

describe("credential proxy assignment fence", () => {
  let h: Harness;

  beforeEach(() => {
    h = createHarness();
  });

  afterEach(() => {
    h.cleanup();
  });

  it("binds on first hosted use and allows the same assignment + generation + Sandbox", async () => {
    const handle = h.activeHandle();
    expect((await h.execute(handle, hosted("assign-1", 5))).resultClass).toBe("ok");
    expect((await h.execute(handle, hosted("assign-1", 5))).resultClass).toBe("ok");
    expect(h.eligibility.get(handle)?.runtimeAssignmentGeneration).toBe(5);
  });

  it("denies a mismatched assignment id", async () => {
    const handle = h.activeHandle();
    await h.execute(handle, hosted("assign-1", 5));
    const denied = await h.execute(handle, hosted("assign-2", 5));
    expect(denied.resultClass).toBe("denied");
    expect(denied.errorCode).toBe("authority-mismatch");
  });

  it("denies a different Sandbox identity claiming the same generation", async () => {
    const handle = h.activeHandle();
    await h.execute(handle, hosted("assign-1", 5, SANDBOX_DIGEST_A));
    const denied = await h.execute(handle, hosted("assign-1", 5, SANDBOX_DIGEST_B));
    expect(denied.resultClass).toBe("denied");
    expect(denied.errorCode).toBe("authority-mismatch");
  });

  it("advances the fence on a newer generation and then denies the superseded generation", async () => {
    const handle = h.activeHandle();
    await h.execute(handle, hosted("assign-1", 5));
    expect((await h.execute(handle, hosted("assign-1", 6, SANDBOX_DIGEST_B))).resultClass).toBe(
      "ok"
    );
    const stale = await h.execute(handle, hosted("assign-1", 5));
    expect(stale.resultClass).toBe("denied");
    expect(stale.errorCode).toBe("authority-mismatch");
  });

  it("revokes in-flight eligibility when the assignment is superseded out of band", async () => {
    const handle = h.activeHandle();
    await h.execute(handle, hosted("assign-1", 5));
    h.eligibility.supersede(handle, "assign-1", 9, SANDBOX_DIGEST_B, 1_700_000_000_001);
    const stale = await h.execute(handle, hosted("assign-1", 5));
    expect(stale.resultClass).toBe("denied");
    expect((await h.execute(handle, hosted("assign-1", 9, SANDBOX_DIGEST_B))).resultClass).toBe(
      "ok"
    );
  });

  it("denies a revoked handle's assignment eligibility", async () => {
    const handle = h.activeHandle();
    await h.execute(handle, hosted("assign-1", 5));
    h.eligibility.revoke(handle, 1_700_000_000_001);
    // The proxy denies on the revoked registration first; the eligibility store
    // independently records the revocation.
    expect(h.eligibility.get(handle)?.revoked).toBe(true);
  });

  it("fails closed for a hosted caller when no eligibility store is configured", async () => {
    const bare = createHarness({ withEligibility: false });
    try {
      const handle = bare.activeHandle();
      const denied = await bare.execute(handle, hosted("assign-1", 5));
      expect(denied.resultClass).toBe("denied");
      expect(denied.errorCode).toBe("authority-mismatch");
    } finally {
      bare.cleanup();
    }
  });

  it("does not assignment-fence human-session or legacy callers", async () => {
    const handle = h.activeHandle();
    const human = await h.execute(handle, {
      class: "human-session",
      humanSessionFenceId: "human-fence-1",
    });
    expect(human.resultClass).toBe("ok");
    const legacy = await h.execute(handle, undefined);
    expect(legacy.resultClass).toBe("ok");
    // Neither caller class created an assignment binding.
    expect(h.eligibility.get(handle)).toBeNull();
  });
});

describe("assignment eligibility store", () => {
  it("returns the exact outcome for each generation-fence transition", () => {
    const store = openAssignmentEligibilityStore({ databasePath: ":memory:" });
    try {
      const base = {
        handleId: "h",
        runtimeAssignmentId: "a",
        sandboxIdentityDigest: SANDBOX_DIGEST_A,
      };
      expect(store.evaluate({ ...base, runtimeAssignmentGeneration: 3 }, 1)).toBe("eligible");
      expect(store.evaluate({ ...base, runtimeAssignmentGeneration: 3 }, 2)).toBe("eligible");
      expect(
        store.evaluate({ ...base, runtimeAssignmentId: "b", runtimeAssignmentGeneration: 3 }, 3)
      ).toBe("denied-mismatch");
      expect(store.evaluate({ ...base, runtimeAssignmentGeneration: 4 }, 4)).toBe("eligible");
      expect(store.evaluate({ ...base, runtimeAssignmentGeneration: 3 }, 5)).toBe("denied-stale");
      store.revoke("h", 6);
      expect(store.evaluate({ ...base, runtimeAssignmentGeneration: 4 }, 7)).toBe("denied-revoked");
    } finally {
      store.close();
    }
  });

  it("rejects malformed input", () => {
    const store = openAssignmentEligibilityStore({ databasePath: ":memory:" });
    try {
      expect(() =>
        store.evaluate(
          {
            handleId: "h",
            runtimeAssignmentId: "a",
            runtimeAssignmentGeneration: 0,
            sandboxIdentityDigest: SANDBOX_DIGEST_A,
          },
          1
        )
      ).toThrow();
      expect(() =>
        store.evaluate(
          {
            handleId: "h",
            runtimeAssignmentId: "a",
            runtimeAssignmentGeneration: 1,
            sandboxIdentityDigest: "not-a-digest",
          },
          1
        )
      ).toThrow();
    } finally {
      store.close();
    }
  });
});
