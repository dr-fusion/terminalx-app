import { describe, expect, it, vi } from "vitest";
import {
  canonicalStringSet,
  sha256,
  type OutboundBindingResolution,
} from "@/lib/connections/contracts";
import type { ProviderProofExpectation } from "@/lib/connections/authority";
import {
  normalizeTelegramUpdate,
  verifyTelegramDeepLinkProof,
  verifyTelegramWebhookSecretToken,
} from "@/lib/connections/providers/telegram-adapter";
import {
  normalizeSlackEvent,
  verifySlackOidcProof,
} from "@/lib/connections/providers/slack-adapter";
import {
  installationExpectationDigest,
  sendOutboundThroughProxy,
} from "@/lib/connections/providers/outbound";
import {
  SLACK_IDENTITY_LINK_SCOPES,
  TELEGRAM_IDENTITY_LINK_SCOPES,
} from "@/lib/connections/providers/scopes";

function expectation(
  provider: "slack" | "telegram",
  challenge: string,
  scopes: readonly string[],
  overrides: Partial<ProviderProofExpectation> = {}
): ProviderProofExpectation {
  const requested = canonicalStringSet(scopes, "scopes");
  return Object.freeze({
    provider,
    externalTenantId: "T1",
    externalAppId: "A1",
    installationId: "inst-1",
    installationRevision: 1,
    challengeDigest: sha256(challenge),
    requestedScopes: requested.values,
    requestedScopesDigest: requested.digest,
    ...overrides,
  });
}

describe("telegram deep-link proof verification", () => {
  const challenge = "txlc_v1_" + "a".repeat(64);
  const expected = expectation("telegram", challenge, TELEGRAM_IDENTITY_LINK_SCOPES);
  const proof = {
    kind: "telegram-deeplink",
    externalTenantId: "T1",
    externalAppId: "A1",
    externalSubject: "555",
    challenge,
    replayId: "42",
  };

  it("verifies a well-formed deep link into the exact expectation", () => {
    const verified = verifyTelegramDeepLinkProof({ proof, expected });
    expect(verified).toMatchObject({
      provider: "telegram",
      externalSubject: "555",
      proofReplayId: "42",
      grantedScopesDigest: expected.requestedScopesDigest,
    });
    expect(verified?.grantedScopes).toEqual([...TELEGRAM_IDENTITY_LINK_SCOPES]);
  });

  it("fails closed on a tampered challenge (digest mismatch)", () => {
    expect(
      verifyTelegramDeepLinkProof({ proof: { ...proof, challenge: challenge + "x" }, expected })
    ).toBeNull();
  });

  it("fails closed on a forged proof of the wrong shape", () => {
    expect(verifyTelegramDeepLinkProof({ proof: { challenge }, expected })).toBeNull();
    expect(verifyTelegramDeepLinkProof({ proof: "nope", expected })).toBeNull();
  });

  it("fails closed on a wrong-installation binding (tenant/app mismatch)", () => {
    expect(
      verifyTelegramDeepLinkProof({ proof: { ...proof, externalTenantId: "T2" }, expected })
    ).toBeNull();
    expect(
      verifyTelegramDeepLinkProof({ proof: { ...proof, externalAppId: "A2" }, expected })
    ).toBeNull();
  });

  it("refuses a proof for the wrong provider", () => {
    expect(
      verifyTelegramDeepLinkProof({ proof, expected: { ...expected, provider: "slack" } })
    ).toBeNull();
  });
});

describe("slack OIDC proof verification", () => {
  const challenge = "txlc_v1_" + "b".repeat(64);
  const expected = expectation("slack", challenge, SLACK_IDENTITY_LINK_SCOPES);
  const proof = {
    kind: "slack-oidc",
    externalTenantId: "T1",
    externalAppId: "A1",
    externalSubject: "U777",
    challenge,
    replayId: "nonce-1",
  };

  it("verifies a well-formed OIDC completion", () => {
    const verified = verifySlackOidcProof({ proof, expected });
    expect(verified).toMatchObject({ provider: "slack", externalSubject: "U777" });
    expect(verified?.grantedScopes).toEqual([...SLACK_IDENTITY_LINK_SCOPES]);
  });

  it("fails closed on a tampered state challenge and forged shapes", () => {
    expect(verifySlackOidcProof({ proof: { ...proof, challenge: "other" }, expected })).toBeNull();
    expect(
      verifySlackOidcProof({ proof: { ...proof, kind: "telegram-deeplink" }, expected })
    ).toBeNull();
  });
});

describe("telegram webhook secret-token verification", () => {
  it("matches only the exact secret token by digest", () => {
    const raw = "0123456789abcdef";
    const digest = sha256(raw);
    expect(verifyTelegramWebhookSecretToken(raw, digest)).toBe(true);
    expect(verifyTelegramWebhookSecretToken("wrong", digest)).toBe(false);
    expect(verifyTelegramWebhookSecretToken(null, digest)).toBe(false);
    expect(verifyTelegramWebhookSecretToken(raw, "z".repeat(64))).toBe(false);
  });
});

describe("telegram update normalization", () => {
  const identity = { externalTenantId: "998877", externalAppId: "998877" };

  it("extracts a /start deep link as a linking action, not a comment", () => {
    const { deepLink, message } = normalizeTelegramUpdate(
      { update_id: 10, message: { from: { id: 5 }, chat: { id: -100 }, text: "/start CHAL" } },
      identity
    );
    expect(message).toBeNull();
    expect(deepLink).toMatchObject({ challenge: "CHAL", externalSubject: "5", replayId: "10" });
  });

  it("normalizes a plain topic message with attribution and thread", () => {
    const { deepLink, message } = normalizeTelegramUpdate(
      {
        update_id: 11,
        message: { from: { id: 5 }, chat: { id: -100 }, message_thread_id: 7, text: "hello" },
      },
      identity
    );
    expect(deepLink).toBeNull();
    expect(message).toMatchObject({
      externalSubject: "5",
      externalConversationId: "-100",
      conversationKind: "topic",
      externalThreadId: "7",
      text: "hello",
      replayId: "11",
      isMention: false,
    });
  });

  it("drops updates missing an author, chat, or text", () => {
    expect(normalizeTelegramUpdate({ update_id: 1 }, identity).message).toBeNull();
    expect(normalizeTelegramUpdate({ message: {} }, identity).message).toBeNull();
  });
});

describe("slack event normalization", () => {
  it("echoes a url_verification challenge without producing a message", () => {
    const { urlVerificationChallenge, message } = normalizeSlackEvent({
      type: "url_verification",
      challenge: "abc",
    });
    expect(urlVerificationChallenge).toBe("abc");
    expect(message).toBeNull();
  });

  it("normalizes a channel message and flags app_mention", () => {
    const base = {
      type: "event_callback",
      team_id: "T1",
      event_id: "Ev1",
      event: { type: "message", user: "U1", channel: "C1", text: "hi" },
    };
    expect(normalizeSlackEvent(base).message).toMatchObject({
      externalTenantId: "T1",
      externalSubject: "U1",
      externalConversationId: "C1",
      conversationKind: "channel",
      replayId: "Ev1",
      isMention: false,
    });
    const mention = normalizeSlackEvent({
      ...base,
      event_id: "Ev2",
      event: {
        type: "app_mention",
        user: "U1",
        channel: "C1",
        text: "<@bot> hi",
        thread_ts: "1.2",
      },
    });
    expect(mention.message).toMatchObject({
      isMention: true,
      conversationKind: "thread",
      externalThreadId: "1.2",
    });
  });

  it("ignores bot echoes and subtypes to prevent loops", () => {
    expect(
      normalizeSlackEvent({
        type: "event_callback",
        team_id: "T1",
        event_id: "Ev3",
        event: { type: "message", user: "U1", channel: "C1", text: "x", bot_id: "B1" },
      }).message
    ).toBeNull();
  });
});

describe("outbound send through the proxy", () => {
  const resolution: OutboundBindingResolution = Object.freeze({
    direction: "outbound",
    messageKind: "session-message",
    includesArtifacts: false,
    provider: "telegram",
    session: Object.freeze({
      id: "session-1",
      teamId: "team-1",
      accessRevision: 1,
      steeringRevision: 1,
      controlRevision: 1,
      runtimeAuthorizationGeneration: 1,
    }),
    installation: Object.freeze({
      id: "inst-1",
      revision: 2,
      externalTenantId: "998877",
      externalAppId: "998877",
      credentialHandleId: "txch_v1_" + "0".repeat(64),
      credentialHandleGeneration: 1,
    }),
    binding: Object.freeze({
      id: "binding-1",
      revision: 3,
      conversationKind: "topic",
      externalConversationId: "-100",
      externalThreadId: "7",
      outboundPolicy: Object.freeze({ mode: "all-session-messages", allowArtifacts: false }),
      outboundPolicyDigest: "d".repeat(64),
    }),
  });

  it("maps telegram sends to telegram.sendMessage with the exact authority snapshot", async () => {
    const execute = vi.fn(async (input) => {
      expect(input.operation).toBe("telegram.sendMessage");
      expect(input.params).toEqual({ chatId: "-100", text: "hello", messageThreadId: 7 });
      expect(input.authority).toMatchObject({
        provider: "telegram",
        handleId: resolution.installation.credentialHandleId,
        installationRevision: 2,
        bindingId: "binding-1",
        bindingRevision: 3,
        expectationDigest: installationExpectationDigest(resolution),
      });
      return {
        resultClass: "ok",
        ambiguous: false,
        errorCode: null,
        accountingRowId: 5,
        projection: { messageId: 1 },
      };
    });
    const result = await sendOutboundThroughProxy({ execute } as never, resolution, {
      text: "hello",
      includesArtifacts: false,
    });
    expect(result.deliveryClass).toBe("delivered");
  });

  it("classifies retryable and denied results for the worker", async () => {
    const retry = await sendOutboundThroughProxy(
      {
        execute: async () => ({
          resultClass: "retryable",
          ambiguous: true,
          errorCode: "timeout-ambiguous",
          accountingRowId: 1,
          projection: null,
        }),
      } as never,
      resolution,
      { text: "x", includesArtifacts: false }
    );
    expect(retry).toMatchObject({ deliveryClass: "retryable", ambiguous: true });

    const denied = await sendOutboundThroughProxy(
      {
        execute: async () => ({
          resultClass: "denied",
          ambiguous: false,
          errorCode: "authority-mismatch",
          accountingRowId: 2,
          projection: null,
        }),
      } as never,
      resolution,
      { text: "x", includesArtifacts: false }
    );
    expect(denied.deliveryClass).toBe("denied");
  });

  it("routes slack sends to slack.chat.postMessage", async () => {
    const slackResolution = {
      ...resolution,
      provider: "slack" as const,
      binding: {
        ...resolution.binding,
        conversationKind: "thread" as const,
        externalConversationId: "C1",
        externalThreadId: "1.2",
      },
    };
    const execute = vi.fn(async (input) => {
      expect(input.operation).toBe("slack.chat.postMessage");
      expect(input.params).toEqual({ channel: "C1", text: "hi", threadTs: "1.2" });
      return {
        resultClass: "ok",
        ambiguous: false,
        errorCode: null,
        accountingRowId: 9,
        projection: {},
      };
    });
    const result = await sendOutboundThroughProxy({ execute } as never, slackResolution as never, {
      text: "hi",
      includesArtifacts: false,
    });
    expect(result.deliveryClass).toBe("delivered");
    expect(execute).toHaveBeenCalledOnce();
  });
});
