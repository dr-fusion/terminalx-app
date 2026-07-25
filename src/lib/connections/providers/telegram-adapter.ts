import { createHash, timingSafeEqual } from "node:crypto";
import { sha256 } from "../contracts";
import type { ProviderProofExpectation, VerifiedProviderIdentity } from "../authority";
import type { NormalizedInboundMessage, VerifiedTelegramDeepLink } from "./types";

/**
 * Verify that an inbound `X-Telegram-Bot-Api-Secret-Token` header matches the
 * per-installation secret token by comparing its SHA-256 digest to the stored
 * digest (the main process never holds the raw secret token — the broker
 * generated it and set it on Telegram; only the digest is persisted). Constant
 * time over the digest bytes.
 */
export function verifyTelegramWebhookSecretToken(
  headerSecretToken: string | null | undefined,
  storedDigestHex: string
): boolean {
  if (typeof headerSecretToken !== "string" || headerSecretToken.length === 0) return false;
  if (!/^[0-9a-f]{64}$/.test(storedDigestHex)) return false;
  const presented = createHash("sha256").update(headerSecretToken, "utf8").digest();
  const stored = Buffer.from(storedDigestHex, "hex");
  return presented.byteLength === stored.byteLength && timingSafeEqual(presented, stored);
}

/**
 * The injected `verifyProviderProof` for Telegram deep-link linking. It accepts
 * ONLY a {@link VerifiedTelegramDeepLink} built from an authenticated webhook
 * delivery and binds it to the expected challenge digest and installation
 * identity. A forged/tampered challenge fails the digest check and returns null.
 */
export function verifyTelegramDeepLinkProof(input: {
  proof: unknown;
  expected: Readonly<ProviderProofExpectation>;
}): VerifiedProviderIdentity | null {
  const { proof, expected } = input;
  if (expected.provider !== "telegram") return null;
  if (!isVerifiedTelegramDeepLink(proof)) return null;
  if (proof.externalTenantId !== expected.externalTenantId) return null;
  if (proof.externalAppId !== expected.externalAppId) return null;
  // Bind the raw challenge from the deep link to the challenge digest the
  // authority is expecting; never trust a caller-supplied subject otherwise.
  if (sha256(proof.challenge) !== expected.challengeDigest) return null;
  if (proof.externalSubject.length === 0 || proof.replayId.length === 0) return null;
  return Object.freeze({
    provider: "telegram",
    externalTenantId: expected.externalTenantId,
    externalAppId: expected.externalAppId,
    installationId: expected.installationId,
    installationRevision: expected.installationRevision,
    challengeDigest: expected.challengeDigest,
    requestedScopesDigest: expected.requestedScopesDigest,
    externalSubject: proof.externalSubject,
    // Telegram deep-link linking grants exactly the requested identity scope set.
    grantedScopes: [...expected.requestedScopes],
    grantedScopesDigest: expected.requestedScopesDigest,
    proofReplayId: proof.replayId,
  });
}

function isVerifiedTelegramDeepLink(value: unknown): value is VerifiedTelegramDeepLink {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.kind === "telegram-deeplink" &&
    typeof record.externalTenantId === "string" &&
    typeof record.externalAppId === "string" &&
    typeof record.externalSubject === "string" &&
    typeof record.challenge === "string" &&
    typeof record.replayId === "string"
  );
}

export interface TelegramNormalization {
  /** A `/start <challenge>` deep link, when present. */
  readonly deepLink: VerifiedTelegramDeepLink | null;
  /** A normalized conversation message, when present. */
  readonly message: NormalizedInboundMessage | null;
}

/**
 * Normalize an authenticated Telegram webhook update. Returns a deep-link (for
 * linking) and/or a conversation message (for inbound attribution). The
 * `externalTenantId`/`externalAppId` (the bot identity) are supplied by the
 * caller from the resolved installation, not parsed from the untrusted update.
 */
export function normalizeTelegramUpdate(
  update: unknown,
  installationIdentity: { externalTenantId: string; externalAppId: string }
): TelegramNormalization {
  if (typeof update !== "object" || update === null) return { deepLink: null, message: null };
  const record = update as Record<string, unknown>;
  const updateId = record.update_id;
  const replayId = Number.isSafeInteger(updateId) ? String(updateId) : null;
  const message = asRecord(record.message);
  if (!replayId || !message) return { deepLink: null, message: null };
  const from = asRecord(message.from);
  const chat = asRecord(message.chat);
  const fromId = from && Number.isSafeInteger(from.id) ? String(from.id) : null;
  const chatId = chat && Number.isSafeInteger(chat.id) ? String(chat.id) : null;
  const text = typeof message.text === "string" ? message.text : null;
  if (!fromId || !chatId || text === null) return { deepLink: null, message: null };

  const threadId =
    Number.isSafeInteger(message.message_thread_id) && message.message_thread_id !== undefined
      ? String(message.message_thread_id)
      : "";
  const conversationKind = threadId.length > 0 ? "topic" : "channel";

  const startMatch = /^\/start\s+(\S+)/.exec(text);
  const deepLink: VerifiedTelegramDeepLink | null =
    startMatch && startMatch[1]
      ? Object.freeze({
          kind: "telegram-deeplink" as const,
          externalTenantId: installationIdentity.externalTenantId,
          externalAppId: installationIdentity.externalAppId,
          externalSubject: fromId,
          challenge: startMatch[1],
          replayId,
        })
      : null;

  const normalizedMessage: NormalizedInboundMessage = Object.freeze({
    provider: "telegram" as const,
    externalTenantId: installationIdentity.externalTenantId,
    externalSubject: fromId,
    conversationKind,
    externalConversationId: chatId,
    externalThreadId: threadId,
    text,
    replayId,
    isMention: false,
  });

  return {
    deepLink,
    // A pure `/start <challenge>` message is a linking action, not a comment.
    message: deepLink ? null : normalizedMessage,
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}
