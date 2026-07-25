import type { ConnectionProvider, ConversationKind } from "../contracts";

/**
 * A provider inbound message normalized to the authority's routing vocabulary.
 * Adapters build this ONLY from provider-verified material (an authenticated
 * webhook delivery), never from a caller-supplied DTO.
 */
export interface NormalizedInboundMessage {
  readonly provider: ConnectionProvider;
  readonly externalTenantId: string;
  /** The external user who authored the message (attribution subject). */
  readonly externalSubject: string;
  readonly conversationKind: ConversationKind;
  readonly externalConversationId: string;
  /** "" when the message is not in a thread. */
  readonly externalThreadId: string;
  readonly text: string;
  /** Provider replay id: Telegram `update_id` or Slack `event_id`, stringified. */
  readonly replayId: string;
  /** True when the message is a direct mention of the bot (Slack `app_mention`). */
  readonly isMention: boolean;
}

/**
 * A verified Telegram deep-link `/start <challenge>` observed on an authenticated
 * webhook delivery. The raw challenge is carried so the injected
 * `verifyProviderProof` can bind it to the expected challenge digest.
 */
export interface VerifiedTelegramDeepLink {
  readonly kind: "telegram-deeplink";
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly externalSubject: string;
  readonly challenge: string;
  readonly replayId: string;
}

/**
 * A verified Sign in with Slack (OIDC) completion. The adapter/route obtains and
 * verifies the OIDC subject out of band; the `challenge` was carried in the OAuth
 * `state` and the `replayId` is a single-use nonce/jti.
 */
export interface VerifiedSlackOidcProof {
  readonly kind: "slack-oidc";
  readonly externalTenantId: string;
  readonly externalAppId: string;
  readonly externalSubject: string;
  readonly challenge: string;
  readonly replayId: string;
}

/** The bounded outcome of an outbound provider send through the 8D proxy. */
export type OutboundDeliveryClass = "delivered" | "retryable" | "denied";

export interface OutboundDeliveryResult {
  readonly deliveryClass: OutboundDeliveryClass;
  readonly ambiguous: boolean;
  readonly provider: ConnectionProvider;
  readonly errorCode: string | null;
  readonly accountingRowId: number | null;
  readonly projection: Record<string, unknown> | null;
}

export interface OutboundSendContent {
  readonly text: string;
  /** True when the outbound message carries artifacts (gated by Binding policy). */
  readonly includesArtifacts: boolean;
}

export type { ConnectionProvider, ConversationKind };
