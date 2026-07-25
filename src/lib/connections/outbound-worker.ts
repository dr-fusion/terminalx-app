import type { OutboundBindingResolution } from "./contracts";
import type { CredentialProxyClient } from "./credential-proxy-client";
import { sendOutboundThroughProxy } from "./providers/outbound";
import type { OutboundDeliveryResult } from "./providers/types";

/**
 * The Team Session outbound worker's per-message delivery step (Slice 8E,
 * decision 5). It resolves the Binding outbound policy for one session
 * message/mention, sends through the 8D Credential Proxy, and classifies the
 * result for durable delivery state:
 *
 * - `resolveOutboundBinding` fences policy (disabled/mentions-only), artifact
 *   gating, and stale installation/binding revisions; a `null` resolution means
 *   the message is not routed and must not be retried.
 * - A `retryable` proxy result may be retried up to `maxAttempts`; a `denied`
 *   result (e.g. a rotation/revocation mid-flight resolving to a stale
 *   `expectationDigest` → `authority-mismatch`) is terminal and never retried.
 */
export interface OutboundDeliveryDecision {
  readonly delivered: boolean;
  readonly shouldRetry: boolean;
  readonly reason: "delivered" | "not-routed" | "retry-scheduled" | "retries-exhausted" | "denied";
  readonly result: OutboundDeliveryResult | null;
}

export interface DeliverOutboundInput {
  readonly bindingId: string;
  readonly expectedBindingRevision: number;
  readonly expectedInstallationRevision: number;
  readonly messageKind: "mention" | "session-message";
  readonly includesArtifacts: boolean;
  readonly text: string;
  /** How many times this message has already been attempted (0 on first try). */
  readonly attempt: number;
  readonly maxAttempts?: number;
}

export interface DeliverOutboundDeps {
  readonly proxyClient: CredentialProxyClient;
  readonly resolveOutboundBinding: (input: {
    bindingId: string;
    expectedBindingRevision: number;
    expectedInstallationRevision: number;
    messageKind: "mention" | "session-message";
    includesArtifacts: boolean;
  }) => OutboundBindingResolution | null;
  readonly audit?: (event: {
    bindingId: string;
    reason: OutboundDeliveryDecision["reason"];
    errorCode: string | null;
  }) => void;
}

const DEFAULT_MAX_ATTEMPTS = 5;

export async function deliverOutboundMessage(
  deps: DeliverOutboundDeps,
  input: DeliverOutboundInput
): Promise<OutboundDeliveryDecision> {
  const maxAttempts = input.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const resolution = deps.resolveOutboundBinding({
    bindingId: input.bindingId,
    expectedBindingRevision: input.expectedBindingRevision,
    expectedInstallationRevision: input.expectedInstallationRevision,
    messageKind: input.messageKind,
    includesArtifacts: input.includesArtifacts,
  });
  if (!resolution) {
    // Policy fence, artifact gate, or stale revision: not routed, never retried.
    deps.audit?.({ bindingId: input.bindingId, reason: "not-routed", errorCode: null });
    return { delivered: false, shouldRetry: false, reason: "not-routed", result: null };
  }

  const result = await sendOutboundThroughProxy(deps.proxyClient, resolution, {
    text: input.text,
    includesArtifacts: input.includesArtifacts,
  });

  if (result.deliveryClass === "delivered") {
    deps.audit?.({ bindingId: input.bindingId, reason: "delivered", errorCode: null });
    return { delivered: true, shouldRetry: false, reason: "delivered", result };
  }
  if (result.deliveryClass === "denied") {
    // A revoked/rotated handle or stale authority target fails closed; terminal.
    deps.audit?.({ bindingId: input.bindingId, reason: "denied", errorCode: result.errorCode });
    return { delivered: false, shouldRetry: false, reason: "denied", result };
  }
  // retryable
  const shouldRetry = input.attempt + 1 < maxAttempts;
  const reason = shouldRetry ? "retry-scheduled" : "retries-exhausted";
  deps.audit?.({ bindingId: input.bindingId, reason, errorCode: result.errorCode });
  return { delivered: false, shouldRetry, reason, result };
}
