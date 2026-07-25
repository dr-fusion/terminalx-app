import { afterEach, describe, expect, it } from "vitest";
import { assertClosedProxyResponse } from "../../packages/secret-broker/src/proxy/proxy-protocol";
import {
  createProxyHarness,
  SLACK_EXPECTATION_DIGEST,
  TELEGRAM_EXPECTATION_DIGEST,
  type ProxyHarness,
} from "./support/credential-proxy-harness";

let harness: ProxyHarness;
afterEach(() => harness?.cleanup());

const TELEGRAM_TOKEN = "12345:SECRET-BOT-TOKEN";
const SLACK_TOKEN = "xoxb-super-secret-slack-token";

let nonce = 0;
async function execute(
  h: ProxyHarness,
  operation: string,
  authority: ReturnType<ProxyHarness["authority"]>,
  params: unknown
) {
  nonce += 1;
  return h.proxy.execute({ operationId: `op_ne_${nonce}`, operation, authority, params });
}

describe("Credential Proxy non-exposure", () => {
  it("attaches the Slack bearer at the client boundary but never in the result, log, or projection", async () => {
    harness = createProxyHarness();
    const handle = harness.activeHandle({
      token: SLACK_TOKEN,
      provider: "slack",
      expectationDigest: SLACK_EXPECTATION_DIGEST,
    });
    // A poisoned upstream response echoes the token and injects extra fields.
    harness.network.enqueue({
      status: 200,
      body: JSON.stringify({
        ok: true,
        ts: "1.2",
        channel: "C1",
        token: SLACK_TOKEN,
        authorization: `Bearer ${SLACK_TOKEN}`,
        secret: "LEAK",
      }),
    });

    const result = await execute(
      harness,
      "slack.chat.postMessage",
      harness.authority({
        provider: "slack",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { channel: "C1", text: "hi" }
    );

    // The credential is present at the network client boundary...
    expect(harness.network.requests[0]!.headers.authorization).toBe(`Bearer ${SLACK_TOKEN}`);
    // ...but never in the returned result or its projection.
    expect(result.projection).toEqual({ ts: "1.2", channel: "C1" });
    const serializedResult = JSON.stringify(result);
    expect(serializedResult).not.toContain(SLACK_TOKEN);
    expect(serializedResult).not.toContain("authorization");
    expect(serializedResult).not.toContain("secret");
    // ...and never in any audit line.
    expect(JSON.stringify(harness.audits)).not.toContain(SLACK_TOKEN);
    // The closed-response guard accepts the result envelope.
    expect(() => assertClosedProxyResponse(result)).not.toThrow();
  });

  it("never returns the token-bearing Telegram download URL nor the bot token", async () => {
    harness = createProxyHarness();
    const handle = harness.activeHandle({
      token: TELEGRAM_TOKEN,
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    harness.network.enqueue({
      status: 200,
      body: JSON.stringify({
        ok: true,
        result: {
          file_id: "F1",
          file_unique_id: "U1",
          file_size: 10,
          file_path: "photos/file_0.jpg",
          // A hostile provider echoes the token-bearing URL back.
          file_url: `https://api.telegram.org/file/bot${TELEGRAM_TOKEN}/photos/file_0.jpg`,
        },
      }),
    });

    const result = await execute(
      harness,
      "telegram.getFile",
      harness.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { fileId: "F1" }
    );

    // The token is attached in the request path at the boundary...
    expect(harness.network.requests[0]!.path).toContain(TELEGRAM_TOKEN);
    // ...but the projection carries only the safe file metadata.
    expect(result.projection).toEqual({
      fileUniqueId: "U1",
      fileSize: 10,
      filePath: "photos/file_0.jpg",
    });
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(TELEGRAM_TOKEN);
    expect(serialized).not.toContain("/bot");
    expect(serialized).not.toContain("file_url");
  });

  it("strips unknown/poisoned fields from a Telegram message projection", async () => {
    harness = createProxyHarness();
    const handle = harness.activeHandle({
      token: TELEGRAM_TOKEN,
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    harness.network.enqueue({
      status: 200,
      body: JSON.stringify({
        ok: true,
        result: { message_id: 9, date: 5, secret: "LEAK", token: TELEGRAM_TOKEN },
      }),
    });
    const result = await execute(
      harness,
      "telegram.sendMessage",
      harness.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { chatId: "1", text: "hi" }
    );
    expect(result.projection).toEqual({ messageId: 9, date: 5 });
    expect(Object.keys(result.projection!)).toEqual(["messageId", "date"]);
    expect(JSON.stringify(result)).not.toContain("LEAK");
  });

  it("projects a provider ok:false as a bounded provider-error without any upstream body", async () => {
    harness = createProxyHarness();
    const handle = harness.activeHandle({
      token: SLACK_TOKEN,
      provider: "slack",
      expectationDigest: SLACK_EXPECTATION_DIGEST,
    });
    harness.network.enqueue({
      status: 200,
      body: JSON.stringify({ ok: false, error: "channel_not_found", needed: "chat:write" }),
    });
    const result = await execute(
      harness,
      "slack.chat.postMessage",
      harness.authority({
        provider: "slack",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { channel: "C1", text: "hi" }
    );
    expect(result.resultClass).toBe("provider-error");
    expect(result.errorCode).toBe("provider-declined");
    expect(result.projection).toBeNull();
    expect(JSON.stringify(result)).not.toContain("channel_not_found");
  });
});
