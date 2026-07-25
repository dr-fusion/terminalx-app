import { secretBrokerExpectationDigest } from "../secret-broker-shared";
import type { OutboundBindingResolution } from "../contracts";
import type { CredentialProxyClient } from "../credential-proxy-client";
import type { ProxyAuthoritySnapshot } from "../../../../packages/secret-broker/src/proxy/proxy-protocol";
import type { OutboundDeliveryResult, OutboundSendContent } from "./types";

/**
 * The installation credential's `expectationDigest`, recomputed from the
 * outbound resolution. It must equal the digest the broker stored at credential
 * acquisition time, so the proxy's per-send fence matches; a mismatch (e.g. a
 * stale installation revision) fails closed in the proxy.
 */
export function installationExpectationDigest(resolution: OutboundBindingResolution): string {
  return secretBrokerExpectationDigest({
    provider: resolution.provider,
    brokerKind: "oauth-envelope",
    usage: "installation",
    authorityBinding: Object.freeze({
      kind: "installation",
      teamId: resolution.session.teamId,
      externalTenantId: resolution.installation.externalTenantId,
      externalAppId: resolution.installation.externalAppId,
    }),
    replaces: null,
  });
}

/** Build the exact per-send authority snapshot the 8D proxy revalidates. */
export function outboundProxyAuthority(
  resolution: OutboundBindingResolution
): ProxyAuthoritySnapshot {
  return Object.freeze({
    provider: resolution.provider,
    handleId: resolution.installation.credentialHandleId,
    handleGeneration: resolution.installation.credentialHandleGeneration,
    expectationDigest: installationExpectationDigest(resolution),
    installationId: resolution.installation.id,
    installationRevision: resolution.installation.revision,
    bindingId: resolution.binding.id,
    bindingRevision: resolution.binding.revision,
  });
}

/**
 * Send one outbound message through the 8D Credential Proxy for a resolved
 * Channel Binding. The credential is never touched here — only a typed operation
 * name, validated params, and the exact authority snapshot are sent. The result
 * is projected to a bounded delivery classification for the outbound worker's
 * retry logic. Artifact-bearing sends are gated by the caller/binding, not here.
 */
export async function sendOutboundThroughProxy(
  proxyClient: CredentialProxyClient,
  resolution: OutboundBindingResolution,
  content: OutboundSendContent
): Promise<OutboundDeliveryResult> {
  const operation =
    resolution.provider === "telegram" ? "telegram.sendMessage" : "slack.chat.postMessage";
  const params =
    resolution.provider === "telegram"
      ? telegramParams(resolution, content.text)
      : slackParams(resolution, content.text);

  const result = await proxyClient.execute({
    operation,
    authority: outboundProxyAuthority(resolution),
    params,
  });

  const deliveryClass =
    result.resultClass === "ok"
      ? "delivered"
      : result.resultClass === "retryable"
        ? "retryable"
        : "denied";

  return Object.freeze({
    deliveryClass,
    ambiguous: result.ambiguous,
    provider: resolution.provider,
    errorCode: result.errorCode,
    accountingRowId: result.accountingRowId,
    projection: result.projection,
  });
}

function telegramParams(
  resolution: OutboundBindingResolution,
  text: string
): Record<string, unknown> {
  const params: Record<string, unknown> = {
    chatId: resolution.binding.externalConversationId,
    text,
  };
  if (
    resolution.binding.conversationKind === "topic" &&
    resolution.binding.externalThreadId.length > 0
  ) {
    const thread = Number(resolution.binding.externalThreadId);
    if (Number.isSafeInteger(thread) && thread >= 1) params.messageThreadId = thread;
  }
  return params;
}

function slackParams(resolution: OutboundBindingResolution, text: string): Record<string, unknown> {
  const params: Record<string, unknown> = {
    channel: resolution.binding.externalConversationId,
    text,
  };
  if (
    resolution.binding.conversationKind === "thread" &&
    resolution.binding.externalThreadId.length > 0
  ) {
    params.threadTs = resolution.binding.externalThreadId;
  }
  return params;
}
