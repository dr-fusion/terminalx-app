import {
  createHmac,
  randomBytes as cryptoRandomBytes,
  timingSafeEqual,
  createHash,
} from "node:crypto";
import {
  boundedIdentifier,
  digestField,
  exactRecord,
  field,
  SecretBrokerProtocolError,
} from "../protocol";
import type { SecretBrokerReceipt } from "../receipt-schema";
import { ProviderExchangeError, type ProviderExchangeClient } from "./provider-exchange-client";
import type { WebhookSecretStore } from "./webhook-secret-store";

const SLACK_REPLAY_WINDOW_MS = 5 * 60 * 1000;
const MAX_WEBHOOK_BODY_BYTES = 256 * 1024;
const MAX_SIGNING_SECRET_BYTES = 4096;

/**
 * Seal an acquired provider token as an `oauth-envelope` secret and return the
 * signed Registration Receipt. Supplied by the broker so the exchange handler
 * reuses the exact two-phase prepare path; the token buffer is zeroed by the
 * broker's adapter after sealing.
 */
export type PrepareInstallationCredential = (input: {
  readonly operationId: string;
  readonly provider: string;
  readonly expectationDigest: string;
  readonly tokenUtf8: Buffer;
}) => Promise<SecretBrokerReceipt>;

export interface CreateProviderExchangeOptions {
  readonly client: ProviderExchangeClient;
  readonly webhookSecrets: WebhookSecretStore;
  readonly prepareInstallationCredential: PrepareInstallationCredential;
  readonly randomBytes?: (size: number) => Buffer;
  readonly clock?: () => number;
  readonly slackReplayWindowMs?: number;
}

export interface ProviderExchange {
  slackOauth(params: unknown): Promise<{ receipt: SecretBrokerReceipt; installation: object }>;
  telegramBotToken(params: unknown): Promise<{
    receipt: SecretBrokerReceipt;
    botIdentity: object;
    webhookAuthDigest: string;
  }>;
  verifySlackWebhook(params: unknown): { valid: boolean; withinReplayWindow: boolean };
}

/**
 * The Slice 8E credential-acquisition handler. Each operation performs the
 * provider network call inside the broker, seals the acquired token/secret, and
 * returns only a receipt plus non-secret installation identity — the raw token,
 * signing secret, and webhook secret token never cross the socket.
 */
export function createProviderExchange(options: CreateProviderExchangeOptions): ProviderExchange {
  const randomBytes = options.randomBytes ?? cryptoRandomBytes;
  const clock = options.clock ?? Date.now;
  const replayWindowMs = options.slackReplayWindowMs ?? SLACK_REPLAY_WINDOW_MS;
  const { client, webhookSecrets, prepareInstallationCredential } = options;

  return Object.freeze({
    async slackOauth(
      params: unknown
    ): Promise<{ receipt: SecretBrokerReceipt; installation: object }> {
      const request = snapshotSlackOauthParams(params);
      let acquired;
      try {
        acquired = await client.slackOauthAccess({
          code: request.code,
          ...(request.redirectUri === undefined ? {} : { redirectUri: request.redirectUri }),
        });
      } catch (error) {
        throw mapExchangeError(error);
      }
      // The credential is bound to the exact expected installation identity; a
      // provider result for a different team/app fails closed before sealing.
      if (
        acquired.teamId !== request.expectedTenantId ||
        acquired.appId !== request.expectedAppId
      ) {
        throw new SecretBrokerProtocolError("permission-denied");
      }
      const signingSecret = Buffer.from(request.signingSecret, "utf8");
      try {
        webhookSecrets.put("slack", request.expectationDigest, signingSecret);
      } finally {
        signingSecret.fill(0);
      }
      const receipt = await prepareInstallationCredential({
        operationId: request.operationId,
        provider: "slack",
        expectationDigest: request.expectationDigest,
        tokenUtf8: Buffer.from(acquired.botToken, "utf8"),
      });
      return {
        receipt,
        installation: Object.freeze({
          provider: "slack",
          externalTenantId: acquired.teamId,
          externalAppId: acquired.appId,
          externalBotUserId: acquired.botUserId,
          grantedScopes: Object.freeze([...acquired.grantedScopes]),
        }),
      };
    },

    async telegramBotToken(params: unknown): Promise<{
      receipt: SecretBrokerReceipt;
      botIdentity: object;
      webhookAuthDigest: string;
    }> {
      const request = snapshotTelegramParams(params);
      let identity;
      try {
        identity = await client.telegramGetMe(request.botToken);
      } catch (error) {
        throw mapExchangeError(error);
      }
      // The Telegram "tenant" is the bot itself; bind the token to the exact
      // expected bot id so an operator cannot install a different bot.
      if (identity.botId !== request.expectedTenantId) {
        throw new SecretBrokerProtocolError("permission-denied");
      }
      // The webhook secret token is generated inside the broker and set on
      // Telegram here using the (broker-only) bot token; only its digest leaves.
      const secretTokenBytes = randomBytes(32);
      const secretToken = secretTokenBytes.toString("hex");
      secretTokenBytes.fill(0);
      try {
        await client.telegramSetWebhook(request.botToken, request.webhookUrl, secretToken);
      } catch (error) {
        throw mapExchangeError(error);
      }
      const webhookAuthDigest = createHash("sha256").update(secretToken, "utf8").digest("hex");
      const receipt = await prepareInstallationCredential({
        operationId: request.operationId,
        provider: "telegram",
        expectationDigest: request.expectationDigest,
        tokenUtf8: Buffer.from(request.botToken, "utf8"),
      });
      return {
        receipt,
        botIdentity: Object.freeze({
          provider: "telegram",
          externalTenantId: identity.botId,
          externalAppId: request.expectedAppId,
          botId: identity.botId,
          username: identity.username,
        }),
        webhookAuthDigest,
      };
    },

    verifySlackWebhook(params: unknown): { valid: boolean; withinReplayWindow: boolean } {
      const request = snapshotVerifySlackParams(params);
      const nowSeconds = Math.floor(clock() / 1000);
      const withinReplayWindow =
        Number.isSafeInteger(request.timestamp) &&
        Math.abs(nowSeconds - request.timestamp) * 1000 <= replayWindowMs;
      const secret = webhookSecrets.reveal("slack", request.expectationDigest);
      if (!secret) return Object.freeze({ valid: false, withinReplayWindow });
      try {
        const base = `v0:${request.timestamp}:${request.body}`;
        const computed = `v0=${createHmac("sha256", secret).update(base, "utf8").digest("hex")}`;
        const valid = safeEqualStrings(computed, request.signature);
        return Object.freeze({ valid, withinReplayWindow });
      } finally {
        secret.fill(0);
      }
    },
  });
}

function mapExchangeError(error: unknown): SecretBrokerProtocolError {
  if (error instanceof SecretBrokerProtocolError) return error;
  if (error instanceof ProviderExchangeError) {
    if (error.kind === "provider-declined")
      return new SecretBrokerProtocolError("permission-denied");
    return new SecretBrokerProtocolError("unavailable");
  }
  return new SecretBrokerProtocolError("internal");
}

interface SlackOauthRequest {
  readonly operationId: string;
  readonly code: string;
  readonly expectedTenantId: string;
  readonly expectedAppId: string;
  readonly expectationDigest: string;
  readonly signingSecret: string;
  readonly redirectUri: string | undefined;
}

function snapshotSlackOauthParams(params: unknown): SlackOauthRequest {
  try {
    // `redirectUri` is optional: the client drops it (undefined/null) when the
    // reviewed app does not require one, so it may be absent on the wire.
    const record = recordWithOptionalKeys(
      params,
      [
        "operationId",
        "code",
        "expectedTenantId",
        "expectedAppId",
        "expectationDigest",
        "signingSecret",
      ],
      ["redirectUri"]
    );
    const code = field(record, "code");
    const signingSecret = field(record, "signingSecret");
    const redirectUriRaw = "redirectUri" in record ? record.redirectUri : undefined;
    if (
      typeof code !== "string" ||
      code.length < 1 ||
      code.length > 4096 ||
      typeof signingSecret !== "string" ||
      signingSecret.length < 1 ||
      Buffer.byteLength(signingSecret, "utf8") > MAX_SIGNING_SECRET_BYTES ||
      (redirectUriRaw !== undefined &&
        redirectUriRaw !== null &&
        typeof redirectUriRaw !== "string")
    ) {
      throw new SecretBrokerProtocolError("invalid-request");
    }
    return Object.freeze({
      operationId: boundedIdentifier(field(record, "operationId")),
      code,
      expectedTenantId: boundedIdentifier(field(record, "expectedTenantId"), 1024),
      expectedAppId: boundedIdentifier(field(record, "expectedAppId"), 1024),
      expectationDigest: digestField(field(record, "expectationDigest")),
      signingSecret,
      redirectUri:
        typeof redirectUriRaw === "string" && redirectUriRaw.length > 0
          ? redirectUriRaw
          : undefined,
    });
  } catch (error) {
    if (error instanceof SecretBrokerProtocolError) throw error;
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

/**
 * Like {@link exactRecord} but permits a bounded set of optional keys to be
 * absent. Rejects proxies, exotic prototypes, and any key outside the union.
 */
function recordWithOptionalKeys(
  value: unknown,
  required: readonly string[],
  optional: readonly string[]
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const record = value as Record<string, unknown>;
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new TypeError();
  }
  for (const key of required) {
    if (!(key in record)) throw new TypeError();
    field(record, key);
  }
  return record;
}

interface TelegramRequest {
  readonly operationId: string;
  readonly botToken: string;
  readonly expectedTenantId: string;
  readonly expectedAppId: string;
  readonly webhookUrl: string;
  readonly expectationDigest: string;
}

function snapshotTelegramParams(params: unknown): TelegramRequest {
  try {
    const record = exactRecord(params, [
      "operationId",
      "botToken",
      "expectedTenantId",
      "expectedAppId",
      "webhookUrl",
      "expectationDigest",
    ]);
    const botToken = field(record, "botToken");
    const webhookUrl = field(record, "webhookUrl");
    if (
      typeof botToken !== "string" ||
      botToken.length < 1 ||
      botToken.length > 4096 ||
      typeof webhookUrl !== "string" ||
      webhookUrl.length < 1 ||
      webhookUrl.length > 4096
    ) {
      throw new SecretBrokerProtocolError("invalid-request");
    }
    return Object.freeze({
      operationId: boundedIdentifier(field(record, "operationId")),
      botToken,
      expectedTenantId: boundedIdentifier(field(record, "expectedTenantId"), 1024),
      expectedAppId: boundedIdentifier(field(record, "expectedAppId"), 1024),
      webhookUrl,
      expectationDigest: digestField(field(record, "expectationDigest")),
    });
  } catch (error) {
    if (error instanceof SecretBrokerProtocolError) throw error;
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

interface VerifySlackRequest {
  readonly expectationDigest: string;
  readonly timestamp: number;
  readonly body: string;
  readonly signature: string;
}

function snapshotVerifySlackParams(params: unknown): VerifySlackRequest {
  try {
    const record = exactRecord(params, ["expectationDigest", "timestamp", "body", "signature"]);
    const timestamp = field(record, "timestamp");
    const body = field(record, "body");
    const signature = field(record, "signature");
    if (
      !Number.isSafeInteger(timestamp) ||
      (timestamp as number) < 0 ||
      typeof body !== "string" ||
      Buffer.byteLength(body, "utf8") > MAX_WEBHOOK_BODY_BYTES ||
      typeof signature !== "string" ||
      signature.length < 1 ||
      signature.length > 512
    ) {
      throw new SecretBrokerProtocolError("invalid-request");
    }
    return Object.freeze({
      expectationDigest: digestField(field(record, "expectationDigest")),
      timestamp: timestamp as number,
      body,
      signature,
    });
  } catch (error) {
    if (error instanceof SecretBrokerProtocolError) throw error;
    throw new SecretBrokerProtocolError("invalid-request");
  }
}

function safeEqualStrings(left: string, right: string): boolean {
  const leftBuffer = Buffer.from(left, "utf8");
  const rightBuffer = Buffer.from(right, "utf8");
  if (leftBuffer.byteLength !== rightBuffer.byteLength) return false;
  return timingSafeEqual(leftBuffer, rightBuffer);
}
