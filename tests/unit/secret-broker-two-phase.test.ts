import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createSecretBroker, type SecretBroker } from "../../packages/secret-broker/src/broker";
import { establishBrokerRoot } from "../../packages/secret-broker/src/broker-root";
import { createOauthEnvelopeAdapter } from "../../packages/secret-broker/src/adapters/oauth-envelope";
import {
  openSecretBrokerStateStore,
  type SecretBrokerStateStore,
} from "../../packages/secret-broker/src/state-store";
import type { SecretBrokerRequest } from "../../packages/secret-broker/src/ndjson";
import { createSecretBrokerReconciler } from "@/lib/connections/secret-broker-reconciler";
import type { SecretBrokerClient } from "@/lib/connections/secret-broker-client";

const TTL = 60_000;
const temporaryDirectories: string[] = [];

function temporaryRoot(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secret-broker-2p-"));
  fs.chmodSync(dir, 0o700);
  temporaryDirectories.push(dir);
  return dir;
}
afterEach(() => {
  while (temporaryDirectories.length > 0) {
    fs.rmSync(temporaryDirectories.pop()!, { recursive: true, force: true });
  }
});

interface Harness {
  broker: SecretBroker;
  store: SecretBrokerStateStore;
  clock: { now: number };
  prepare(replaces?: { handleId: string }): Promise<{ handleId: string; receiptId: string }>;
  call(method: SecretBrokerRequest["method"], params: unknown): Promise<unknown>;
  client: SecretBrokerClient;
}

function harness(): Harness {
  const root = establishBrokerRoot({ rootDir: temporaryRoot() });
  const store = openSecretBrokerStateStore({ databasePath: root.databasePath });
  const clock = { now: 1_000_000 };
  const broker = createSecretBroker({
    root,
    store,
    adapters: { "oauth-envelope": createOauthEnvelopeAdapter(root.atRestKey) },
    clock: () => clock.now,
    receiptTtlMs: TTL,
  });
  const call = (method: SecretBrokerRequest["method"], params: unknown): Promise<unknown> =>
    broker.handle({ version: 1, sequence: 1, method, params });

  const prepare = async (replaces?: {
    handleId: string;
  }): Promise<{ handleId: string; receiptId: string }> => {
    const result = (await call(replaces ? "rotation.prepare" : "registration.prepare", {
      operationId: `op_${Math.random().toString(36).slice(2)}`,
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "installation",
      expectationDigest: "a".repeat(64),
      replaces: replaces ?? null,
      secretMaterial: Buffer.from("oauth-secret").toString("base64"),
    })) as { receipt: { payload: { handleId: string; receiptId: string } } };
    return {
      handleId: result.receipt.payload.handleId,
      receiptId: result.receipt.payload.receiptId,
    };
  };

  const client = {
    finalizeRegistration: async (h: string, r: string) =>
      void (await call("registration.finalize", { handleId: h, receiptId: r })),
    abortRegistration: async (r: string) =>
      void (await call("registration.abort", { receiptId: r })),
    finalizeRotation: async (h: string, r: string) =>
      void (await call("rotation.finalize", { handleId: h, receiptId: r })),
    abortRotation: async (r: string) => void (await call("rotation.abort", { receiptId: r })),
  } as unknown as SecretBrokerClient;

  return { broker, store, clock, prepare, call, client };
}

describe("Secret Broker two-phase registration convergence", () => {
  it("commits the happy path: prepare then finalize", async () => {
    const h = harness();
    const { handleId, receiptId } = await h.prepare();
    expect(h.store.getByHandleId(handleId)?.status).toBe("pending");
    await h.call("registration.finalize", { handleId, receiptId });
    expect(h.store.getByHandleId(handleId)?.status).toBe("active");
  });

  it("crash after prepare (never finalized) is reaped to aborted at TTL", async () => {
    const h = harness();
    const { handleId } = await h.prepare();
    // No finalize; the process 'crashes'. On restart the sweep runs past TTL.
    h.clock.now += TTL + 1;
    const { reaped } = h.broker.reconcile();
    expect(reaped).toBe(1);
    const row = h.store.getByHandleId(handleId);
    expect(row?.status).toBe("aborted");
    expect(row?.hasSecretMaterial).toBe(false);
  });

  it("crash between authority commit and finalize converges via the reconciler", async () => {
    const h = harness();
    const { handleId, receiptId } = await h.prepare();
    // The authority transaction committed the handle row, then the process died
    // before finalize. Only the main reconciler knows the commit happened.
    const committed = new Set([handleId]);
    const reconciler = createSecretBrokerReconciler({
      client: h.client,
      authorityHandleCommitted: (id) => committed.has(id),
      clock: () => h.clock.now,
    });
    const outcome = await reconciler.reconcile({
      handleId,
      receiptId,
      expiresAtMs: h.clock.now + TTL,
      rotation: false,
    });
    expect(outcome.action).toBe("finalized");
    expect(h.store.getByHandleId(handleId)?.status).toBe("active");
  });

  it("rollback then abort is idempotent and no orphan remains active", async () => {
    const h = harness();
    const { handleId, receiptId } = await h.prepare();
    await h.call("registration.abort", { receiptId });
    await h.call("registration.abort", { receiptId }); // duplicate retry
    expect(h.store.getByHandleId(handleId)?.status).toBe("aborted");
  });

  it("uniqueness/rollback with no commit is aborted only after TTL, deferred before", async () => {
    const h = harness();
    const { handleId, receiptId } = await h.prepare();
    const reconciler = createSecretBrokerReconciler({
      client: h.client,
      authorityHandleCommitted: () => false, // the authority txn rolled back
      clock: () => h.clock.now,
    });
    const early = await reconciler.reconcile({
      handleId,
      receiptId,
      expiresAtMs: h.clock.now + TTL,
      rotation: false,
    });
    expect(early.action).toBe("deferred");
    expect(h.store.getByHandleId(handleId)?.status).toBe("pending");

    h.clock.now += TTL + 1;
    const late = await reconciler.reconcile({
      handleId,
      receiptId,
      expiresAtMs: h.clock.now - TTL - 1 + TTL,
      rotation: false,
    });
    expect(late.action).toBe("aborted");
    expect(h.store.getByHandleId(handleId)?.status).toBe("aborted");
  });

  it("duplicate prepare retries are idempotent by operationId", async () => {
    const h = harness();
    const operationId = "op_fixed";
    const params = {
      operationId,
      provider: "slack",
      brokerKind: "oauth-envelope",
      usage: "installation",
      expectationDigest: "a".repeat(64),
      replaces: null,
      secretMaterial: Buffer.from("s").toString("base64"),
    };
    const first = (await h.call("registration.prepare", params)) as {
      receipt: { payload: { handleId: string } };
    };
    const retry = (await h.call("registration.prepare", params)) as {
      receipt: { payload: { handleId: string } };
    };
    expect(retry.receipt.payload.handleId).toBe(first.receipt.payload.handleId);
    expect(h.store.countPending()).toBe(1);
  });
});

describe("Secret Broker rotation convergence", () => {
  async function activeHandle(h: Harness): Promise<string> {
    const { handleId, receiptId } = await h.prepare();
    await h.call("registration.finalize", { handleId, receiptId });
    return handleId;
  }

  it("keeps the replaced secret until the replacement finalizes, then revokes it", async () => {
    const h = harness();
    const original = await activeHandle(h);
    const replacement = await h.prepare({ handleId: original });
    expect(h.store.getByHandleId(original)?.hasSecretMaterial).toBe(true);
    await h.call("rotation.finalize", {
      handleId: replacement.handleId,
      receiptId: replacement.receiptId,
    });
    expect(h.store.getByHandleId(replacement.handleId)?.status).toBe("active");
    expect(h.store.getByHandleId(original)?.status).toBe("revoked");
    expect(h.store.getByHandleId(original)?.hasSecretMaterial).toBe(false);
  });

  it("a crash mid-rotation converges to finalize via the reconciler", async () => {
    const h = harness();
    const original = await activeHandle(h);
    const replacement = await h.prepare({ handleId: original });
    const committed = new Set([replacement.handleId]);
    const reconciler = createSecretBrokerReconciler({
      client: h.client,
      authorityHandleCommitted: (id) => committed.has(id),
      clock: () => h.clock.now,
    });
    const outcome = await reconciler.reconcile({
      handleId: replacement.handleId,
      receiptId: replacement.receiptId,
      expiresAtMs: h.clock.now + TTL,
      rotation: true,
    });
    expect(outcome.action).toBe("finalized");
    expect(h.store.getByHandleId(replacement.handleId)?.status).toBe("active");
    expect(h.store.getByHandleId(original)?.status).toBe("revoked");
  });

  it("aborting a rotation leaves the replaced handle active with its secret intact", async () => {
    const h = harness();
    const original = await activeHandle(h);
    const replacement = await h.prepare({ handleId: original });
    await h.call("rotation.abort", { receiptId: replacement.receiptId });
    expect(h.store.getByHandleId(replacement.handleId)?.status).toBe("aborted");
    expect(h.store.getByHandleId(original)?.status).toBe("active");
    expect(h.store.getByHandleId(original)?.hasSecretMaterial).toBe(true);
  });
});
