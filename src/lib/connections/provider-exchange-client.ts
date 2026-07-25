import { randomBytes } from "node:crypto";
import { connect, type Socket } from "node:net";
import {
  canonicalJson,
  SECRET_BROKER_PROTOCOL_VERSION,
} from "../../../packages/secret-broker/src/protocol";
import {
  snapshotReceipt,
  type SecretBrokerReceipt,
} from "../../../packages/secret-broker/src/receipt-schema";

const MAX_RESPONSE_BYTES = 256 * 1024;

export class ProviderExchangeClientError extends Error {
  readonly code: string;
  constructor(code: string) {
    super(`Provider exchange request failed: ${code}`);
    this.code = code;
    this.name = "ProviderExchangeClientError";
  }
}

export interface SlackOauthExchangeInput {
  readonly operationId?: string;
  readonly code: string;
  readonly expectedTenantId: string;
  readonly expectedAppId: string;
  readonly expectationDigest: string;
  readonly signingSecret: string;
  readonly redirectUri?: string;
  /** Non-null routes the broker seal through rotation.prepare with this linkage. */
  readonly replaces?: { readonly handleId: string } | null;
}

export interface SlackInstallationIdentity {
  readonly provider: "slack";
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly externalBotUserId: string;
  readonly grantedScopes: readonly string[];
}

export interface SlackOauthExchangeResult {
  readonly receipt: SecretBrokerReceipt;
  readonly installation: SlackInstallationIdentity;
}

export interface TelegramBotTokenExchangeInput {
  readonly operationId?: string;
  readonly botToken: string;
  readonly expectedTenantId: string;
  readonly expectedAppId: string;
  readonly webhookUrl: string;
  readonly expectationDigest: string;
  /** Non-null routes the broker seal through rotation.prepare with this linkage. */
  readonly replaces?: { readonly handleId: string } | null;
}

export interface TelegramBotIdentity {
  readonly provider: "telegram";
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly botId: string;
  readonly username: string;
}

export interface TelegramBotTokenExchangeResult {
  readonly receipt: SecretBrokerReceipt;
  readonly botIdentity: TelegramBotIdentity;
  /** SHA-256 of the broker-generated Telegram webhook `secret_token`. */
  readonly webhookAuthDigest: string;
}

export interface SlackWebhookVerifyInput {
  readonly expectationDigest: string;
  readonly timestamp: number;
  readonly body: string;
  readonly signature: string;
}

export interface SlackWebhookVerifyResult {
  readonly valid: boolean;
  readonly withinReplayWindow: boolean;
}

export interface SlackOidcVerifyInput {
  readonly idToken: string;
  readonly expectedIssuer: string;
  readonly expectedAudience: string;
  readonly expectedTenantId: string;
  readonly expectedAppId: string;
  readonly challengeDigest: string;
}

export interface SlackOidcVerifiedIdentity {
  readonly provider: "slack";
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly externalSubject: string;
  readonly challenge: string;
  readonly replayId: string;
}

export interface ProviderExchangeClient {
  slackOauth(input: SlackOauthExchangeInput): Promise<SlackOauthExchangeResult>;
  telegramBotToken(input: TelegramBotTokenExchangeInput): Promise<TelegramBotTokenExchangeResult>;
  verifySlackWebhook(input: SlackWebhookVerifyInput): Promise<SlackWebhookVerifyResult>;
  slackOidc(input: SlackOidcVerifyInput): Promise<SlackOidcVerifiedIdentity>;
}

export interface CreateProviderExchangeClientOptions {
  readonly socketPath: string;
  readonly requestTimeoutMs?: number;
}

/**
 * Main-process NDJSON client for the Secret Broker provider credential-acquisition
 * operations. It sends the OAuth `code` / operator bot token one way and receives
 * only a Registration Receipt plus non-secret installation identity — the raw bot
 * token, refresh token, signing secret, and webhook secret token never come back.
 */
export function createProviderExchangeClient(
  options: CreateProviderExchangeClientOptions
): ProviderExchangeClient {
  const socketPath = options.socketPath;
  const timeoutMs = options.requestTimeoutMs ?? 15_000;
  if (typeof socketPath !== "string" || socketPath.length < 1) throw new TypeError();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
    throw new TypeError();
  }

  function newOperationId(): string {
    return `xch_${randomBytes(24).toString("base64url")}`;
  }

  return Object.freeze({
    async slackOauth(input: SlackOauthExchangeInput): Promise<SlackOauthExchangeResult> {
      const result = (await request(socketPath, timeoutMs, "exchange.slack-oauth", {
        operationId: input.operationId ?? newOperationId(),
        code: input.code,
        expectedTenantId: input.expectedTenantId,
        expectedAppId: input.expectedAppId,
        expectationDigest: input.expectationDigest,
        signingSecret: input.signingSecret,
        redirectUri: input.redirectUri,
        ...(input.replaces ? { replaces: { handleId: input.replaces.handleId } } : {}),
      })) as { receipt: unknown; installation: unknown };
      return Object.freeze({
        receipt: snapshotReceipt(result.receipt),
        installation: snapshotSlackInstallation(result.installation),
      });
    },
    async telegramBotToken(
      input: TelegramBotTokenExchangeInput
    ): Promise<TelegramBotTokenExchangeResult> {
      const result = (await request(socketPath, timeoutMs, "exchange.telegram-bot-token", {
        operationId: input.operationId ?? newOperationId(),
        botToken: input.botToken,
        expectedTenantId: input.expectedTenantId,
        expectedAppId: input.expectedAppId,
        webhookUrl: input.webhookUrl,
        expectationDigest: input.expectationDigest,
        ...(input.replaces ? { replaces: { handleId: input.replaces.handleId } } : {}),
      })) as { receipt: unknown; botIdentity: unknown; webhookAuthDigest: unknown };
      const digest = result.webhookAuthDigest;
      if (typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
        throw new ProviderExchangeClientError("internal");
      }
      return Object.freeze({
        receipt: snapshotReceipt(result.receipt),
        botIdentity: snapshotTelegramIdentity(result.botIdentity),
        webhookAuthDigest: digest,
      });
    },
    async slackOidc(input: SlackOidcVerifyInput): Promise<SlackOidcVerifiedIdentity> {
      const result = (await request(socketPath, timeoutMs, "exchange.slack-oidc", {
        idToken: input.idToken,
        expectedIssuer: input.expectedIssuer,
        expectedAudience: input.expectedAudience,
        expectedTenantId: input.expectedTenantId,
        expectedAppId: input.expectedAppId,
        challengeDigest: input.challengeDigest,
      })) as { identity: unknown };
      return snapshotSlackOidcIdentity(result.identity);
    },
    async verifySlackWebhook(input: SlackWebhookVerifyInput): Promise<SlackWebhookVerifyResult> {
      const result = (await request(socketPath, timeoutMs, "webhook.verify-slack", {
        expectationDigest: input.expectationDigest,
        timestamp: input.timestamp,
        body: input.body,
        signature: input.signature,
      })) as { valid: unknown; withinReplayWindow: unknown };
      if (typeof result.valid !== "boolean" || typeof result.withinReplayWindow !== "boolean") {
        throw new ProviderExchangeClientError("internal");
      }
      return Object.freeze({ valid: result.valid, withinReplayWindow: result.withinReplayWindow });
    },
  });
}

function snapshotSlackInstallation(value: unknown): SlackInstallationIdentity {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProviderExchangeClientError("internal");
  }
  const record = value as Record<string, unknown>;
  const grantedScopes = record.grantedScopes;
  if (
    record.provider !== "slack" ||
    typeof record.externalTenantId !== "string" ||
    typeof record.externalAppId !== "string" ||
    typeof record.externalBotUserId !== "string" ||
    !Array.isArray(grantedScopes) ||
    grantedScopes.some((s) => typeof s !== "string")
  ) {
    throw new ProviderExchangeClientError("internal");
  }
  return Object.freeze({
    provider: "slack",
    externalTenantId: record.externalTenantId,
    externalAppId: record.externalAppId,
    externalBotUserId: record.externalBotUserId,
    grantedScopes: Object.freeze([...(grantedScopes as string[])]),
  });
}

function snapshotSlackOidcIdentity(value: unknown): SlackOidcVerifiedIdentity {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProviderExchangeClientError("internal");
  }
  const record = value as Record<string, unknown>;
  if (
    record.provider !== "slack" ||
    typeof record.externalTenantId !== "string" ||
    typeof record.externalAppId !== "string" ||
    typeof record.externalSubject !== "string" ||
    typeof record.challenge !== "string" ||
    typeof record.replayId !== "string"
  ) {
    throw new ProviderExchangeClientError("internal");
  }
  return Object.freeze({
    provider: "slack",
    externalTenantId: record.externalTenantId,
    externalAppId: record.externalAppId,
    externalSubject: record.externalSubject,
    challenge: record.challenge,
    replayId: record.replayId,
  });
}

function snapshotTelegramIdentity(value: unknown): TelegramBotIdentity {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProviderExchangeClientError("internal");
  }
  const record = value as Record<string, unknown>;
  if (
    record.provider !== "telegram" ||
    typeof record.externalTenantId !== "string" ||
    typeof record.externalAppId !== "string" ||
    typeof record.botId !== "string" ||
    typeof record.username !== "string"
  ) {
    throw new ProviderExchangeClientError("internal");
  }
  return Object.freeze({
    provider: "telegram",
    externalTenantId: record.externalTenantId,
    externalAppId: record.externalAppId,
    botId: record.botId,
    username: record.username,
  });
}

async function request(
  socketPath: string,
  timeoutMs: number,
  method: string,
  params: unknown
): Promise<unknown> {
  const frame = `${canonicalJson({
    version: SECRET_BROKER_PROTOCOL_VERSION,
    sequence: 1,
    method,
    params,
  })}\n`;
  return new Promise<unknown>((resolve, reject) => {
    const socket: Socket = connect(socketPath);
    let settled = false;
    let received = Buffer.alloc(0);
    const timer = setTimeout(
      () => finish(new ProviderExchangeClientError("unavailable")),
      timeoutMs
    );
    timer.unref();

    const finish = (error: Error | null, value?: unknown): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else resolve(value);
    };

    socket.once("connect", () => {
      socket.write(frame, "utf8");
    });
    socket.on("data", (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (received.byteLength > MAX_RESPONSE_BYTES) {
        finish(new ProviderExchangeClientError("unavailable"));
        return;
      }
      const newline = received.indexOf(0x0a);
      if (newline < 0) return;
      try {
        finish(null, parseResponse(received.subarray(0, newline).toString("utf8")));
      } catch (error) {
        finish(error instanceof Error ? error : new ProviderExchangeClientError("internal"));
      }
    });
    socket.once("error", () => finish(new ProviderExchangeClientError("unavailable")));
    socket.once("close", () => finish(new ProviderExchangeClientError("unavailable")));
  });
}

function parseResponse(line: string): unknown {
  const parsed = JSON.parse(line) as unknown;
  if (typeof parsed !== "object" || parsed === null) {
    throw new ProviderExchangeClientError("internal");
  }
  const record = parsed as Record<string, unknown>;
  if (record.version !== SECRET_BROKER_PROTOCOL_VERSION) {
    throw new ProviderExchangeClientError("internal");
  }
  if (record.ok === true) return record.result;
  const error = record.error as { code?: unknown } | undefined;
  throw new ProviderExchangeClientError(
    error && typeof error.code === "string" ? error.code : "internal"
  );
}
