import { afterEach, describe, expect, it } from "vitest";
import { ProxyNetworkError } from "../../packages/secret-broker/src/proxy/network-client";
import {
  CREDENTIAL_PROXY_OPERATIONS,
  CREDENTIAL_PROXY_ALLOWED_HOSTS,
} from "../../packages/secret-broker/src/proxy/operations";
import {
  createProxyHarness,
  SLACK_EXPECTATION_DIGEST,
  TELEGRAM_EXPECTATION_DIGEST,
  type ProxyHarness,
} from "./support/credential-proxy-harness";

let harness: ProxyHarness;
afterEach(() => harness?.cleanup());

function newHarness(): ProxyHarness {
  harness = createProxyHarness();
  return harness;
}

let nonce = 0;
async function execute(
  h: ProxyHarness,
  operation: string,
  authority: ReturnType<ProxyHarness["authority"]>,
  params: unknown
) {
  nonce += 1;
  return h.proxy.execute({
    operationId: `op_call_${nonce}`,
    operation,
    authority,
    params,
  });
}

describe("Credential Proxy typed operation registry", () => {
  it("exposes only the closed telegram+slack operation set and its two hosts", () => {
    expect([...CREDENTIAL_PROXY_OPERATIONS.keys()].sort()).toEqual([
      "slack.chat.postMessage",
      "slack.chat.update",
      "slack.conversations.info",
      "telegram.downloadFile",
      "telegram.editMessageText",
      "telegram.getFile",
      "telegram.sendMessage",
    ]);
    expect([...CREDENTIAL_PROXY_ALLOWED_HOSTS].sort()).toEqual(["api.telegram.org", "slack.com"]);
  });

  it("performs telegram.sendMessage: bot token in path, JSON body, projected result", async () => {
    const h = newHarness();
    const handle = h.activeHandle({
      token: "12345:BOT-TOKEN",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    h.network.enqueue({
      status: 200,
      body: JSON.stringify({ ok: true, result: { message_id: 42, date: 1700 } }),
    });
    const result = await execute(
      h,
      "telegram.sendMessage",
      h.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { chatId: "1001", text: "hello" }
    );

    expect(result.resultClass).toBe("ok");
    expect(result.errorCode).toBeNull();
    expect(result.projection).toEqual({ messageId: 42, date: 1700 });
    expect(result.destinationHost).toBe("api.telegram.org");
    const request = h.network.requests[0]!;
    expect(request.path).toBe("/bot12345:BOT-TOKEN/sendMessage");
    expect(request.method).toBe("POST");
    expect(JSON.parse(request.body!)).toEqual({ chat_id: "1001", text: "hello" });
  });

  it("performs slack.chat.postMessage: bearer header, JSON body, projected result", async () => {
    const h = newHarness();
    const handle = h.activeHandle({
      token: "xoxb-slack-token",
      provider: "slack",
      expectationDigest: SLACK_EXPECTATION_DIGEST,
    });
    h.network.enqueue({
      status: 200,
      body: JSON.stringify({ ok: true, ts: "1700.1", channel: "C123" }),
    });
    const result = await execute(
      h,
      "slack.chat.postMessage",
      h.authority({
        provider: "slack",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { channel: "C123", text: "hello" }
    );

    expect(result.resultClass).toBe("ok");
    expect(result.projection).toEqual({ ts: "1700.1", channel: "C123" });
    const request = h.network.requests[0]!;
    expect(request.path).toBe("/api/chat.postMessage");
    expect(request.headers.authorization).toBe("Bearer xoxb-slack-token");
  });

  it("denies an unknown operation", async () => {
    const h = newHarness();
    const handle = h.activeHandle({
      token: "t",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    const result = await execute(
      h,
      "telegram.deleteEverything",
      h.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      {}
    );
    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("unsupported-operation");
    expect(h.network.requests).toHaveLength(0);
  });

  it("denies when the operation provider does not match the authority provider", async () => {
    const h = newHarness();
    const handle = h.activeHandle({
      token: "t",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    const result = await execute(
      h,
      "telegram.sendMessage",
      h.authority({
        provider: "slack",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { chatId: "1", text: "x" }
    );
    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("provider-mismatch");
    expect(h.network.requests).toHaveLength(0);
  });

  it("denies when the handle's provider does not match the operation (cross-provider handle)", async () => {
    const h = newHarness();
    const telegramHandle = h.activeHandle({
      token: "t",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    const result = await execute(
      h,
      "slack.chat.postMessage",
      h.authority({
        provider: "slack",
        handleId: telegramHandle.handleId,
        expectationDigest: telegramHandle.expectationDigest,
      }),
      { channel: "C1", text: "x" }
    );
    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("provider-mismatch");
    expect(h.network.requests).toHaveLength(0);
  });

  it("refuses telegram.downloadFile path traversal and never sends a request", async () => {
    const h = newHarness();
    const handle = h.activeHandle({
      token: "12345:BOT",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    for (const filePath of ["../secret", "/etc/passwd", "a/../../b", "photos//x", "x/"]) {
      const result = await execute(
        h,
        "telegram.downloadFile",
        h.authority({
          provider: "telegram",
          handleId: handle.handleId,
          expectationDigest: handle.expectationDigest,
        }),
        { filePath }
      );
      expect(result.resultClass, filePath).toBe("denied");
      expect(result.errorCode, filePath).toBe("invalid-params");
    }
    expect(h.network.requests).toHaveLength(0);
  });

  it("builds a token-scoped download path for a valid file_path", async () => {
    const h = newHarness();
    const handle = h.activeHandle({
      token: "12345:BOT",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    h.network.enqueue({ status: 200, body: Buffer.from([1, 2, 3, 4]) });
    const result = await execute(
      h,
      "telegram.downloadFile",
      h.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { filePath: "photos/file_0.jpg" }
    );
    expect(result.resultClass).toBe("ok");
    expect(result.projection).toEqual({
      contentBase64: Buffer.from([1, 2, 3, 4]).toString("base64"),
      byteLength: 4,
    });
    expect(h.network.requests[0]!.path).toBe("/file/bot12345:BOT/photos/file_0.jpg");
  });

  it("rejects malformed and oversized parameters as denied", async () => {
    const h = newHarness();
    const telegram = h.activeHandle({
      token: "t",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    const slack = h.activeHandle({
      token: "s",
      provider: "slack",
      expectationDigest: SLACK_EXPECTATION_DIGEST,
    });
    const tgAuth = h.authority({
      provider: "telegram",
      handleId: telegram.handleId,
      expectationDigest: telegram.expectationDigest,
    });
    const slackAuth = h.authority({
      provider: "slack",
      handleId: slack.handleId,
      expectationDigest: slack.expectationDigest,
    });

    const badChannel = await execute(h, "slack.chat.postMessage", slackAuth, {
      channel: "not a channel",
      text: "x",
    });
    expect(badChannel.errorCode).toBe("invalid-params");

    const extraKey = await execute(h, "telegram.sendMessage", tgAuth, {
      chatId: "1",
      text: "x",
      evil: 1,
    });
    expect(extraKey.errorCode).toBe("invalid-params");

    const oversizedTelegram = await execute(h, "telegram.sendMessage", tgAuth, {
      chatId: "1",
      text: "a".repeat(4097),
    });
    expect(oversizedTelegram.errorCode).toBe("params-too-large");

    const oversizedSlack = await execute(h, "slack.chat.postMessage", slackAuth, {
      channel: "C1",
      text: "a".repeat(40_001),
    });
    expect(oversizedSlack.errorCode).toBe("params-too-large");

    expect(h.network.requests).toHaveLength(0);
  });

  it("classifies an oversized response as denied", async () => {
    const h = newHarness();
    const handle = h.activeHandle({
      token: "t",
      provider: "telegram",
      expectationDigest: TELEGRAM_EXPECTATION_DIGEST,
    });
    h.network.enqueue({ throw: new ProxyNetworkError("response-too-large") });
    const result = await execute(
      h,
      "telegram.getFile",
      h.authority({
        provider: "telegram",
        handleId: handle.handleId,
        expectationDigest: handle.expectationDigest,
      }),
      { fileId: "file123" }
    );
    expect(result.resultClass).toBe("denied");
    expect(result.errorCode).toBe("response-too-large");
  });
});
