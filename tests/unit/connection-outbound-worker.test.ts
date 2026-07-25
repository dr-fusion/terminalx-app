import { describe, expect, it, vi } from "vitest";
import {
  deliverOutboundMessage,
  type DeliverOutboundDeps,
} from "@/lib/connections/outbound-worker";
import type { OutboundBindingResolution } from "@/lib/connections/contracts";

function resolution(): OutboundBindingResolution {
  return Object.freeze({
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
      revision: 1,
      externalTenantId: "998877",
      externalAppId: "998877",
      credentialHandleId: "txch_v1_" + "0".repeat(64),
      credentialHandleGeneration: 1,
    }),
    binding: Object.freeze({
      id: "binding-1",
      revision: 1,
      conversationKind: "channel",
      externalConversationId: "-100",
      externalThreadId: "",
      outboundPolicy: Object.freeze({ mode: "all-session-messages", allowArtifacts: false }),
      outboundPolicyDigest: "d".repeat(64),
    }),
  });
}

function input(overrides = {}) {
  return {
    bindingId: "binding-1",
    expectedBindingRevision: 1,
    expectedInstallationRevision: 1,
    messageKind: "session-message" as const,
    includesArtifacts: false,
    text: "update",
    attempt: 0,
    maxAttempts: 3,
    ...overrides,
  };
}

describe("outbound worker delivery step", () => {
  it("delivers when the binding resolves and the proxy accepts", async () => {
    const deps: DeliverOutboundDeps = {
      proxyClient: {
        execute: async () => ({
          resultClass: "ok",
          ambiguous: false,
          errorCode: null,
          accountingRowId: 1,
          projection: {},
        }),
      } as never,
      resolveOutboundBinding: () => resolution(),
    };
    const decision = await deliverOutboundMessage(deps, input());
    expect(decision).toMatchObject({ delivered: true, shouldRetry: false, reason: "delivered" });
  });

  it("does not route (and never retries) when policy fences the message", async () => {
    const execute = vi.fn();
    const deps: DeliverOutboundDeps = {
      proxyClient: { execute } as never,
      resolveOutboundBinding: () => null,
    };
    const decision = await deliverOutboundMessage(deps, input({ messageKind: "mention" }));
    expect(decision).toMatchObject({ delivered: false, shouldRetry: false, reason: "not-routed" });
    expect(execute).not.toHaveBeenCalled();
  });

  it("retries a retryable result within the attempt budget, then exhausts", async () => {
    const deps: DeliverOutboundDeps = {
      proxyClient: {
        execute: async () => ({
          resultClass: "retryable",
          ambiguous: false,
          errorCode: "rate-limited",
          accountingRowId: 1,
          projection: null,
        }),
      } as never,
      resolveOutboundBinding: () => resolution(),
    };
    expect(await deliverOutboundMessage(deps, input({ attempt: 0 }))).toMatchObject({
      shouldRetry: true,
      reason: "retry-scheduled",
    });
    expect(await deliverOutboundMessage(deps, input({ attempt: 2 }))).toMatchObject({
      shouldRetry: false,
      reason: "retries-exhausted",
    });
  });

  it("never retries a denied result (rotation/revocation mid-flight)", async () => {
    const deps: DeliverOutboundDeps = {
      proxyClient: {
        execute: async () => ({
          resultClass: "denied",
          ambiguous: false,
          errorCode: "authority-mismatch",
          accountingRowId: 1,
          projection: null,
        }),
      } as never,
      resolveOutboundBinding: () => resolution(),
    };
    const decision = await deliverOutboundMessage(deps, input());
    expect(decision).toMatchObject({ delivered: false, shouldRetry: false, reason: "denied" });
    expect(decision.result?.errorCode).toBe("authority-mismatch");
  });

  it("gates artifact-bearing sends through resolveOutboundBinding", async () => {
    const resolveOutboundBinding = vi.fn((i: { includesArtifacts: boolean }) =>
      i.includesArtifacts ? null : resolution()
    );
    const deps: DeliverOutboundDeps = {
      proxyClient: {
        execute: async () => ({
          resultClass: "ok",
          ambiguous: false,
          errorCode: null,
          accountingRowId: 1,
          projection: {},
        }),
      } as never,
      resolveOutboundBinding: resolveOutboundBinding as never,
    };
    // Artifact-bearing send is fenced (binding does not allow artifacts).
    expect(await deliverOutboundMessage(deps, input({ includesArtifacts: true }))).toMatchObject({
      reason: "not-routed",
    });
    // Non-artifact send is delivered.
    expect(await deliverOutboundMessage(deps, input({ includesArtifacts: false }))).toMatchObject({
      delivered: true,
    });
  });
});
