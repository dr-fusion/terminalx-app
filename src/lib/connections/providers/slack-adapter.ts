import { sha256 } from "../contracts";
import type { ProviderProofExpectation, VerifiedProviderIdentity } from "../authority";
import type { ProviderExchangeClient } from "../provider-exchange-client";
import type { NormalizedInboundMessage, VerifiedSlackOidcProof } from "./types";

/**
 * The injected `verifyProviderProof` for Sign in with Slack (OIDC) linking. It
 * accepts ONLY a {@link VerifiedSlackOidcProof} whose OIDC subject was verified
 * out of band and binds it to the expected challenge digest (carried in the OAuth
 * `state`) and installation identity. A forged/tampered `state` fails the digest
 * check and returns null.
 */
export function verifySlackOidcProof(input: {
  proof: unknown;
  expected: Readonly<ProviderProofExpectation>;
}): VerifiedProviderIdentity | null {
  const { proof, expected } = input;
  if (expected.provider !== "slack") return null;
  if (!isVerifiedSlackOidcProof(proof)) return null;
  if (proof.externalTenantId !== expected.externalTenantId) return null;
  if (proof.externalAppId !== expected.externalAppId) return null;
  if (sha256(proof.challenge) !== expected.challengeDigest) return null;
  if (proof.externalSubject.length === 0 || proof.replayId.length === 0) return null;
  return Object.freeze({
    provider: "slack",
    externalTenantId: expected.externalTenantId,
    externalAppId: expected.externalAppId,
    installationId: expected.installationId,
    installationRevision: expected.installationRevision,
    challengeDigest: expected.challengeDigest,
    requestedScopesDigest: expected.requestedScopesDigest,
    externalSubject: proof.externalSubject,
    grantedScopes: [...expected.requestedScopes],
    grantedScopesDigest: expected.requestedScopesDigest,
    proofReplayId: proof.replayId,
  });
}

function isVerifiedSlackOidcProof(value: unknown): value is VerifiedSlackOidcProof {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return (
    record.kind === "slack-oidc" &&
    typeof record.externalTenantId === "string" &&
    typeof record.externalAppId === "string" &&
    typeof record.externalSubject === "string" &&
    typeof record.challenge === "string" &&
    typeof record.replayId === "string"
  );
}

/**
 * Verify a Slack Events API webhook via the broker's `webhook.verify-slack`
 * operation: the v0 HMAC is computed inside the broker with the installation's
 * stored signing secret. Returns valid only when the signature matches AND the
 * timestamp is within the ±300s replay window.
 */
export async function verifySlackWebhookSignature(
  exchangeClient: ProviderExchangeClient,
  input: {
    expectationDigest: string;
    timestampHeader: string | null | undefined;
    rawBody: string;
    signatureHeader: string | null | undefined;
  }
): Promise<boolean> {
  const timestamp = Number(input.timestampHeader);
  if (
    !Number.isSafeInteger(timestamp) ||
    timestamp < 0 ||
    typeof input.signatureHeader !== "string" ||
    input.signatureHeader.length === 0
  ) {
    return false;
  }
  const result = await exchangeClient.verifySlackWebhook({
    expectationDigest: input.expectationDigest,
    timestamp,
    body: input.rawBody,
    signature: input.signatureHeader,
  });
  return result.valid && result.withinReplayWindow;
}

export interface SlackNormalization {
  /** Slack URL-verification challenge echo, when present. */
  readonly urlVerificationChallenge: string | null;
  readonly message: NormalizedInboundMessage | null;
}

/**
 * Normalize an authenticated Slack Events API envelope. The `externalTenantId`
 * is taken from the verified envelope `team_id`; the caller must additionally
 * confirm it matches the resolved installation before acting.
 */
export function normalizeSlackEvent(envelope: unknown): SlackNormalization {
  if (typeof envelope !== "object" || envelope === null) {
    return { urlVerificationChallenge: null, message: null };
  }
  const record = envelope as Record<string, unknown>;
  if (record.type === "url_verification") {
    const challenge = typeof record.challenge === "string" ? record.challenge : null;
    return { urlVerificationChallenge: challenge, message: null };
  }
  if (record.type !== "event_callback") return { urlVerificationChallenge: null, message: null };
  const teamId = typeof record.team_id === "string" ? record.team_id : null;
  const eventId = typeof record.event_id === "string" ? record.event_id : null;
  const event = asRecord(record.event);
  if (!teamId || !eventId || !event) return { urlVerificationChallenge: null, message: null };
  const eventType = event.type;
  if (eventType !== "message" && eventType !== "app_mention") {
    return { urlVerificationChallenge: null, message: null };
  }
  // Ignore bot/subtype echoes to prevent loops.
  if (typeof event.bot_id === "string" || typeof event.subtype === "string") {
    return { urlVerificationChallenge: null, message: null };
  }
  const user = typeof event.user === "string" ? event.user : null;
  const channel = typeof event.channel === "string" ? event.channel : null;
  const text = typeof event.text === "string" ? event.text : null;
  if (!user || !channel || text === null) {
    return { urlVerificationChallenge: null, message: null };
  }
  const threadTs = typeof event.thread_ts === "string" ? event.thread_ts : "";
  return {
    urlVerificationChallenge: null,
    message: Object.freeze({
      provider: "slack" as const,
      externalTenantId: teamId,
      externalSubject: user,
      conversationKind: threadTs.length > 0 ? "thread" : "channel",
      externalConversationId: channel,
      externalThreadId: threadTs,
      text,
      replayId: eventId,
      isMention: eventType === "app_mention",
    }),
  };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}
