import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { canonicalJson } from "../../packages/secret-broker/src/protocol";
import { ProxyNetworkError } from "../../packages/secret-broker/src/proxy/network-client";
import {
  openProxyAccountingStore,
  type ProxyAccountingInput,
} from "../../packages/secret-broker/src/proxy/accounting-store";
import {
  createProxyHarness,
  SLACK_EXPECTATION_DIGEST,
  TELEGRAM_EXPECTATION_DIGEST,
  type ProxyHarness,
} from "./support/credential-proxy-harness";

let harness: ProxyHarness;
const tempFiles: string[] = [];
afterEach(() => {
  harness?.cleanup();
  while (tempFiles.length > 0) fs.rmSync(tempFiles.pop()!, { recursive: true, force: true });
});

let nonce = 0;
async function execute(
  h: ProxyHarness,
  operation: string,
  authority: ReturnType<ProxyHarness["authority"]>,
  params: unknown
) {
  nonce += 1;
  return h.proxy.execute({ operationId: `op_acct_${nonce}`, operation, authority, params });
}

function tempDbPath(): string {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "proxy-acct-")), "acct.sqlite");
  tempFiles.push(path.dirname(file));
  return file;
}

const SAMPLE: ProxyAccountingInput = {
  operationId: "op_1",
  provider: "telegram",
  operation: "telegram.sendMessage",
  destinationHost: "api.telegram.org",
  resultClass: "ok",
  ambiguous: false,
  errorCode: null,
  requestBytes: 10,
  responseBytes: 20,
  handleId: "hnd_1",
  handleGeneration: 1,
  installationRevision: 1,
  bindingRevision: null,
  authoritySnapshotDigest: "d".repeat(64),
  startedAtMs: 100,
  completedAtMs: 200,
};

describe("Credential Proxy outbound accounting", () => {
  it("records exact request/response byte counts excluding credential bytes", async () => {
    harness = createProxyHarness();
    const handle = harness.activeHandle({
      token: "12345:VERY-LONG-BOT-TOKEN-EXCLUDED",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    const responseBody = JSON.stringify({ ok: true, result: { message_id: 1, date: 2 } });
    harness.network.enqueue({ status: 200, body: responseBody });

    const result = await execute(
      harness,
      "telegram.sendMessage",
      harness.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { chatId: "1001", text: "hello" }
    );

    const expectedBody = canonicalJson({ chat_id: "1001", text: "hello" });
    const expectedRequestBytes =
      Buffer.byteLength(expectedBody) +
      Buffer.byteLength("content-type") +
      Buffer.byteLength("application/json");
    expect(result.requestBytes).toBe(expectedRequestBytes);
    expect(result.responseBytes).toBe(Buffer.byteLength(responseBody));

    const row = harness.accounting.getByOperationId(`op_acct_${nonce}`)!;
    expect(row.requestBytes).toBe(expectedRequestBytes);
    expect(row.responseBytes).toBe(Buffer.byteLength(responseBody));
    // The bot token length never contributes to the accounted request bytes.
    expect(row.requestBytes).toBeLessThan(100);
  });

  it("records an ambiguous timeout-after-send as retryable + ambiguous", async () => {
    harness = createProxyHarness();
    const handle = harness.activeHandle({
      token: "t",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    harness.network.enqueue({ throw: new ProxyNetworkError("timeout-after-send") });
    const result = await execute(
      harness,
      "telegram.sendMessage",
      harness.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { chatId: "1", text: "x" }
    );
    expect(result.resultClass).toBe("retryable");
    expect(result.ambiguous).toBe(true);
    expect(result.errorCode).toBe("timeout-ambiguous");
    const row = harness.accounting.getByOperationId(`op_acct_${nonce}`)!;
    expect(row.ambiguous).toBe(true);
    expect(row.resultClass).toBe("retryable");
  });

  it("covers ok / denied / retryable / provider-error result classes, monotonically ordered", async () => {
    harness = createProxyHarness();
    const tg = harness.activeHandle({
      token: "t",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    const slack = harness.activeHandle({
      token: "s",
      provider: "slack",
      expectationDigest: SLACK_EXPECTATION_DIGEST,
    });
    const tgAuth = harness.authority({
      provider: "telegram",
      handleId: tg.handleId,
      expectationDigest: tg.expectationDigest,
    });
    const slackAuth = harness.authority({
      provider: "slack",
      handleId: slack.handleId,
      expectationDigest: slack.expectationDigest,
    });

    harness.network.enqueue({
      status: 200,
      body: JSON.stringify({ ok: true, result: { message_id: 1, date: 2 } }),
    });
    await execute(harness, "telegram.sendMessage", tgAuth, { chatId: "1", text: "x" }); // ok

    await execute(harness, "telegram.unknownOp", tgAuth, {}); // denied

    harness.network.enqueue({ throw: new ProxyNetworkError("transport") });
    await execute(harness, "telegram.sendMessage", tgAuth, { chatId: "1", text: "x" }); // retryable

    harness.network.enqueue({ status: 200, body: JSON.stringify({ ok: false, error: "no" }) });
    await execute(harness, "slack.chat.postMessage", slackAuth, { channel: "C1", text: "x" }); // provider-error

    const rows = harness.accounting.list();
    expect(rows.map((row) => row.resultClass)).toEqual([
      "ok",
      "denied",
      "retryable",
      "provider-error",
    ]);
    const rowIds = rows.map((row) => row.rowId);
    expect(rowIds).toEqual([...rowIds].sort((a, b) => a - b));
    expect(new Set(rowIds).size).toBe(rowIds.length);
  });

  it("keeps accounting rows immutable: UPDATE and DELETE are rejected", () => {
    const dbPath = tempDbPath();
    const store = openProxyAccountingStore({ databasePath: dbPath });
    const row = store.record(SAMPLE);
    expect(row.rowId).toBeGreaterThan(0);
    store.close();

    const raw = new Database(dbPath);
    try {
      expect(() => raw.prepare("UPDATE proxy_accounting SET response_bytes = 999").run()).toThrow(
        /append-only/
      );
      expect(() => raw.prepare("DELETE FROM proxy_accounting").run()).toThrow(/append-only/);
      const persisted = raw.prepare("SELECT response_bytes FROM proxy_accounting").get() as {
        response_bytes: number;
      };
      expect(persisted.response_bytes).toBe(20);
    } finally {
      raw.close();
    }
  });

  it("converges a duplicate operationId on the recorded row without a second insert", () => {
    const store = openProxyAccountingStore({ databasePath: ":memory:" });
    try {
      const first = store.record(SAMPLE);
      const second = store.record({ ...SAMPLE, responseBytes: 999 });
      expect(second.rowId).toBe(first.rowId);
      expect(second.responseBytes).toBe(20);
      expect(store.list()).toHaveLength(1);
    } finally {
      store.close();
    }
  });
});
