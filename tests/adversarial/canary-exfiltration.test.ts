import { spawnSync } from "node:child_process";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ProxyNetworkError } from "../../packages/secret-broker/src/proxy/network-client";
import { assertCanaryOnlyIn, assertNoCanaryLeak, findCanaryLeaks } from "./canary-scanner";
import { createCanaryBrokerHarness, type CanaryBrokerHarness } from "./canary-broker-harness";

/**
 * Slice 8G adversarial evidence. A canary secret is sealed into the broker as
 * real material through the real 8C at-rest path, then hostile scenarios attempt
 * to exfiltrate it through every observable surface. Each channel is its own
 * test, and every assertion covers the canary's common encodings, not just the
 * literal. The scanner is a reusable helper so Phase 12 reruns these scenarios
 * against the real hosted Daytona Runtime unchanged.
 */
const CANARY = "8G-canary/bot0token+SEED~3f9a1c7e5b2d4088aa17c33e91fe0042d6QRS";
const TELEGRAM_EXPECTATION = "a".repeat(64);

let harness: CanaryBrokerHarness;

beforeEach(() => {
  harness = createCanaryBrokerHarness();
});

afterEach(() => {
  harness.cleanup();
});

async function sendTelegram(handleId: string): Promise<unknown> {
  return harness.proxy.execute({
    operationId: `op_send_${Math.random().toString(36).slice(2)}`,
    operation: "telegram.sendMessage",
    authority: harness.authority({
      provider: "telegram",
      handleId,
      expectationDigest: TELEGRAM_EXPECTATION,
    }),
    params: { chatId: "12345", text: "hello from the agent" },
  });
}

describe("8G canary exfiltration — credential boundary", () => {
  it("does not leak the canary through the handle/registration API", () => {
    const handleId = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    const row = harness.store.getByHandleId(handleId);
    expect(row?.status).toBe("active");
    expect(row?.hasSecretMaterial).toBe(true);
    assertNoCanaryLeak("registration-row", row, CANARY);
  });

  it("does not leak the canary into the persisted broker files (encrypted at rest)", () => {
    harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    const bytes = harness.readPersistedBytes();
    expect(bytes.byteLength).toBeGreaterThan(0);
    assertNoCanaryLeak("broker-state-files", bytes, CANARY);
  });

  it("does not leak the canary through the proxy result projection", async () => {
    const handleId = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    harness.enqueue({
      status: 200,
      body: JSON.stringify({ ok: true, result: { message_id: 7, date: 1 } }),
    });
    const result = await sendTelegram(handleId);
    assertNoCanaryLeak("proxy-result", result, CANARY);
  });

  it("does not leak the canary through denied/error classification", async () => {
    const handleId = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    harness.revoke(handleId);
    const denied = await sendTelegram(handleId);
    assertNoCanaryLeak("proxy-denied", denied, CANARY);

    const live = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    // A hostile upstream that echoes the token in its error body must never be forwarded.
    harness.enqueue({
      status: 401,
      body: JSON.stringify({ ok: false, description: `bad token ${CANARY}` }),
    });
    const providerError = await sendTelegram(live);
    assertNoCanaryLeak("proxy-provider-error", providerError, CANARY);
  });

  it("does not leak the canary through a transport error", async () => {
    const handleId = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    harness.enqueue({ throw: new ProxyNetworkError("timeout-after-send") });
    const result = await sendTelegram(handleId);
    assertNoCanaryLeak("proxy-transport-error", result, CANARY);
  });

  it("does not leak the canary through outbound accounting rows", async () => {
    const handleId = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    harness.enqueue({
      status: 200,
      body: JSON.stringify({ ok: true, result: { message_id: 7, date: 1 } }),
    });
    await sendTelegram(handleId);
    const rows = harness.accounting.list();
    expect(rows.length).toBe(1);
    assertNoCanaryLeak("accounting-rows", rows, CANARY);
  });

  it("does not leak the canary through audit events, evidence, or logs", async () => {
    const handleId = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    const logged: unknown[] = [];
    const consoleMethods = ["log", "info", "warn", "error", "debug"] as const;
    const originals = consoleMethods.map((name) => console[name]);
    for (const name of consoleMethods) {
      console[name] = (...args: unknown[]) => {
        logged.push(...args);
      };
    }
    try {
      harness.enqueue({
        status: 200,
        body: JSON.stringify({ ok: true, result: { message_id: 7, date: 1 } }),
      });
      await sendTelegram(handleId);
    } finally {
      consoleMethods.forEach((name, index) => {
        console[name] = originals[index] as typeof console.log;
      });
    }
    assertNoCanaryLeak("audit-events", harness.audits, CANARY);
    assertNoCanaryLeak("captured-logs", logged, CANARY);
  });

  it("sends the canary ONLY to the authorized outbound credential path and nowhere else", async () => {
    const handleId = harness.activeHandle(CANARY, "telegram", TELEGRAM_EXPECTATION);
    harness.enqueue({
      status: 200,
      body: JSON.stringify({ ok: true, result: { message_id: 7, date: 1 } }),
    });
    const result = await sendTelegram(handleId);
    const request = harness.requests.at(-1);
    expect(request).toBeDefined();
    // Telegram places the credential in the URL path; it must appear there and
    // in no observable projection, header, body, accounting row, or audit event.
    assertCanaryOnlyIn(
      "outbound-credential-path",
      {
        "outbound-credential-path": request?.path,
        "request-headers": request?.headers,
        "request-body": request?.body,
        "request-query": request?.query,
        "result-envelope": result,
        "accounting-rows": harness.accounting.list(),
        "audit-events": harness.audits,
      },
      CANARY
    );
  });

  it("excludes the credential bytes from the accounted request byte count", async () => {
    // A large credential proves the accounted request bytes are independent of
    // the token length: the token is placed in the path and never accounted.
    const largeToken = `${CANARY}-${"z".repeat(512)}`;
    const handleId = harness.activeHandle(largeToken, "telegram", TELEGRAM_EXPECTATION);
    harness.enqueue({
      status: 200,
      body: JSON.stringify({ ok: true, result: { message_id: 7, date: 1 } }),
    });
    const result = (await sendTelegram(handleId)) as { requestBytes: number };
    expect(result.requestBytes).toBeLessThan(200);
    expect(result.requestBytes).toBeLessThan(largeToken.length);
  });

  it("keeps the canary out of the environment, argv, and /proc of a spawned harness process", () => {
    const script = [
      "const fs = require('node:fs');",
      "let secret = '';",
      "process.stdin.on('data', (c) => { secret += c.toString('utf8'); });",
      "process.stdin.on('end', () => {",
      "  const held = Buffer.from(secret.trim(), 'utf8');",
      "  const surfaces = {",
      "    env: JSON.stringify(process.env),",
      "    argv: process.argv.join(' '),",
      "    environ: safeRead('/proc/self/environ'),",
      "    cmdline: safeRead('/proc/self/cmdline'),",
      "  };",
      "  held.fill(0);",
      "  process.stdout.write(Buffer.from(JSON.stringify(surfaces), 'utf8').toString('base64'));",
      "});",
      "function safeRead(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } }",
    ].join("\n");
    const child = spawnSync(process.execPath, ["-e", script], {
      input: `${CANARY}\n`,
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "" },
    });
    expect(child.status).toBe(0);
    const surfaces = JSON.parse(Buffer.from(child.stdout, "base64").toString("utf8")) as Record<
      string,
      string
    >;
    for (const [channel, value] of Object.entries(surfaces)) {
      assertNoCanaryLeak(`spawned-process-${channel}`, value, CANARY);
    }
    // Sanity: the scanner would have caught the secret had it been present.
    expect(findCanaryLeaks(`leaked ${CANARY}`, CANARY).length).toBeGreaterThan(0);
  });
});
