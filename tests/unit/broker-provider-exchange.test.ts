import { createHmac, randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createProviderExchange } from "@/../packages/secret-broker/src/exchange/exchange";
import { openWebhookSecretStore } from "@/../packages/secret-broker/src/exchange/webhook-secret-store";
import {
  ProviderExchangeError,
  type ProviderExchangeClient,
} from "@/../packages/secret-broker/src/exchange/provider-exchange-client";
import type { SecretBrokerReceipt } from "@/../packages/secret-broker/src/receipt-schema";

const BOT_TOKEN = "998877:AA-Secret-Bot-Token-Value";
const SLACK_BOT_TOKEN = "xoxb-slack-secret-bot-token";
const SIGNING_SECRET = "8f742b0c-slack-signing-secret";
const DIGEST = "a".repeat(64);

function fakeReceipt(handleId: string): SecretBrokerReceipt {
  return {
    payload: {
      schema: 1,
      kind: "terminalx.secret-broker-registration-receipt",
      brokerInstanceId: "b".repeat(32),
      brokerEpoch: 1,
      signingKeyId: "c".repeat(64),
      operationId: "op",
      handleId,
      receiptId: "rcp",
      provider: "telegram",
      brokerKind: "oauth-envelope",
      usage: "installation",
      expectationDigest: DIGEST,
      hasReplacement: false,
      issuedAtMs: 1_000,
      expiresAtMs: 2_000,
    },
    signature: "s".repeat(86),
  } as unknown as SecretBrokerReceipt;
}

function harness(overrides: Partial<ProviderExchangeClient> = {}, clock = () => 1_700_000_000_000) {
  const webhookSecrets = openWebhookSecretStore({
    databasePath: ":memory:",
    atRestKey: randomBytes(32),
    clock,
  });
  const preparedTokens: string[] = [];
  const client: ProviderExchangeClient = {
    slackOauthAccess: overrides.slackOauthAccess
      ? overrides.slackOauthAccess
      : async () => ({
          botToken: SLACK_BOT_TOKEN,
          teamId: "T1",
          appId: "A1",
          botUserId: "U-BOT",
          grantedScopes: ["chat:write", "channels:read"],
        }),
    telegramGetMe: overrides.telegramGetMe
      ? overrides.telegramGetMe
      : async () => ({ botId: "998877", username: "example_bot" }),
    telegramSetWebhook: overrides.telegramSetWebhook ?? (async () => undefined),
  };
  const exchange = createProviderExchange({
    client,
    webhookSecrets,
    clock,
    randomBytes: () => Buffer.alloc(32, 7),
    prepareInstallationCredential: async ({ tokenUtf8 }) => {
      preparedTokens.push(tokenUtf8.toString("utf8"));
      return fakeReceipt("txch_v1_" + "0".repeat(64));
    },
  });
  return { exchange, webhookSecrets, preparedTokens };
}

describe("broker provider exchange — slack oauth", () => {
  it("seals the bot token, stores the signing secret, and never returns the token", async () => {
    const { exchange, preparedTokens } = harness();
    const result = await exchange.slackOauth({
      operationId: "op-1",
      code: "oauth-code-123",
      expectedTenantId: "T1",
      expectedAppId: "A1",
      expectationDigest: DIGEST,
      signingSecret: SIGNING_SECRET,
      redirectUri: "https://x/cb",
    });
    // The bot token was routed into the sealing path, not the response.
    expect(preparedTokens).toEqual([SLACK_BOT_TOKEN]);
    expect(JSON.stringify(result)).not.toContain(SLACK_BOT_TOKEN);
    expect(JSON.stringify(result)).not.toContain(SIGNING_SECRET);
    expect(result.installation).toMatchObject({
      provider: "slack",
      externalTenantId: "T1",
      externalAppId: "A1",
      externalBotUserId: "U-BOT",
      grantedScopes: ["chat:write", "channels:read"],
    });
  });

  it("fails closed when the provider identity does not match the expected installation", async () => {
    const { exchange, preparedTokens } = harness();
    await expect(
      exchange.slackOauth({
        operationId: "op-1",
        code: "oauth-code-123",
        expectedTenantId: "T-OTHER",
        expectedAppId: "A1",
        expectationDigest: DIGEST,
        signingSecret: SIGNING_SECRET,
      })
    ).rejects.toMatchObject({ code: "permission-denied" });
    // No credential was sealed for a mismatched installation.
    expect(preparedTokens).toEqual([]);
  });

  it("maps a provider decline to permission-denied without sealing", async () => {
    const { exchange, preparedTokens } = harness({
      slackOauthAccess: async () => {
        throw new ProviderExchangeError("provider-declined");
      },
    });
    await expect(
      exchange.slackOauth({
        operationId: "op-1",
        code: "bad",
        expectedTenantId: "T1",
        expectedAppId: "A1",
        expectationDigest: DIGEST,
        signingSecret: SIGNING_SECRET,
      })
    ).rejects.toMatchObject({ code: "permission-denied" });
    expect(preparedTokens).toEqual([]);
  });
});

describe("broker provider exchange — telegram bot token", () => {
  it("validates the bot, sets the webhook, seals the token, and returns only a digest", async () => {
    const setWebhook = vi.fn(async () => undefined);
    const { exchange, preparedTokens } = harness({ telegramSetWebhook: setWebhook });
    const result = await exchange.telegramBotToken({
      operationId: "op-1",
      botToken: BOT_TOKEN,
      expectedTenantId: "998877",
      expectedAppId: "998877",
      webhookUrl: "https://x/tg",
      expectationDigest: DIGEST,
    });
    expect(preparedTokens).toEqual([BOT_TOKEN]);
    expect(setWebhook).toHaveBeenCalledOnce();
    // The webhook secret token is generated in-broker; only its digest leaves.
    expect(JSON.stringify(result)).not.toContain(BOT_TOKEN);
    expect(result.webhookSecretTokenDigest).toMatch(/^[0-9a-f]{64}$/);
    // The set secret token (deterministic in the harness) is not surfaced raw.
    const rawSecret = Buffer.alloc(32, 7).toString("hex");
    expect(JSON.stringify(result)).not.toContain(rawSecret);
    expect(setWebhook).toHaveBeenCalledWith(BOT_TOKEN, "https://x/tg", rawSecret);
    expect(result.botIdentity).toMatchObject({ provider: "telegram", botId: "998877" });
  });

  it("rejects a bot whose id does not match the expected tenant", async () => {
    const { exchange, preparedTokens } = harness();
    await expect(
      exchange.telegramBotToken({
        operationId: "op-1",
        botToken: BOT_TOKEN,
        expectedTenantId: "111111",
        expectedAppId: "111111",
        webhookUrl: "https://x/tg",
        expectationDigest: DIGEST,
      })
    ).rejects.toMatchObject({ code: "permission-denied" });
    expect(preparedTokens).toEqual([]);
  });
});

describe("broker provider exchange — slack webhook verification", () => {
  const nowMs = 1_700_000_000_000;
  const timestamp = Math.floor(nowMs / 1000);

  function sign(secret: string, body: string, ts: number): string {
    return `v0=${createHmac("sha256", secret).update(`v0:${ts}:${body}`, "utf8").digest("hex")}`;
  }

  it("returns valid for a correct HMAC within the replay window", async () => {
    const { exchange } = harness(undefined, () => nowMs);
    await exchange.slackOauth({
      operationId: "op-1",
      code: "c",
      expectedTenantId: "T1",
      expectedAppId: "A1",
      expectationDigest: DIGEST,
      signingSecret: SIGNING_SECRET,
    });
    const body = '{"type":"event_callback"}';
    expect(
      exchange.verifySlackWebhook({
        expectationDigest: DIGEST,
        timestamp,
        body,
        signature: sign(SIGNING_SECRET, body, timestamp),
      })
    ).toEqual({ valid: true, withinReplayWindow: true });
  });

  it("rejects an incorrect signature", async () => {
    const { exchange } = harness(undefined, () => nowMs);
    await exchange.slackOauth({
      operationId: "op-1",
      code: "c",
      expectedTenantId: "T1",
      expectedAppId: "A1",
      expectationDigest: DIGEST,
      signingSecret: SIGNING_SECRET,
    });
    const body = '{"type":"event_callback"}';
    expect(
      exchange.verifySlackWebhook({
        expectationDigest: DIGEST,
        timestamp,
        body,
        signature: sign("wrong-secret", body, timestamp),
      })
    ).toEqual({ valid: true === false, withinReplayWindow: true });
  });

  it("flags a stale timestamp as outside the replay window", async () => {
    const { exchange } = harness(undefined, () => nowMs);
    await exchange.slackOauth({
      operationId: "op-1",
      code: "c",
      expectedTenantId: "T1",
      expectedAppId: "A1",
      expectationDigest: DIGEST,
      signingSecret: SIGNING_SECRET,
    });
    const staleTs = timestamp - 3600;
    const body = "b";
    const result = exchange.verifySlackWebhook({
      expectationDigest: DIGEST,
      timestamp: staleTs,
      body,
      signature: sign(SIGNING_SECRET, body, staleTs),
    });
    expect(result.withinReplayWindow).toBe(false);
  });

  it("returns valid=false when no signing secret is bound to the installation", async () => {
    const { exchange } = harness(undefined, () => nowMs);
    expect(
      exchange.verifySlackWebhook({
        expectationDigest: "f".repeat(64),
        timestamp,
        body: "b",
        signature: sign(SIGNING_SECRET, "b", timestamp),
      })
    ).toEqual({ valid: false, withinReplayWindow: true });
  });
});
