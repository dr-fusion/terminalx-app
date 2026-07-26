import { describe, expect, it, vi } from "vitest";
import { createProductionAttentionDeliveryDeps } from "@/lib/ops/attention-delivery-adapter";
import type { CredentialProxyClient } from "@/lib/connections/credential-proxy-client";

const NULL_PROXY = null;

describe("production attention delivery adapter", () => {
  it("is fully fail-closed when no Credential Proxy is configured", async () => {
    const deps = createProductionAttentionDeliveryDeps({ proxyClient: NULL_PROXY });
    expect(deps.resolveSessionBinding("s1")).toBeNull();
    const decision = await deps.deliverOutbound({
      bindingId: "b1",
      expectedBindingRevision: 1,
      expectedInstallationRevision: 1,
      messageKind: "mention",
      includesArtifacts: false,
      text: "hi",
      attempt: 0,
    });
    expect(decision).toEqual({ delivered: false, shouldRetry: false, reason: "not-routed" });
  });

  it("resolves a session binding from the connection database", () => {
    const withDatabase = vi.fn(
      <T>(operation: (db: unknown) => T): T =>
        operation({
          prepare: () => ({
            get: () => ({ id: "b1", revision: 3, installation_revision: 5 }),
          }),
        })
    );
    const deps = createProductionAttentionDeliveryDeps({
      proxyClient: {} as CredentialProxyClient,
      withDatabase: withDatabase as never,
    });
    expect(deps.resolveSessionBinding("s1")).toEqual({
      bindingId: "b1",
      expectedBindingRevision: 3,
      expectedInstallationRevision: 5,
    });
  });

  it("routes delivery through deliverOutboundMessage and the authority re-fence", async () => {
    // The authority returns null (no active binding), so deliverOutboundMessage
    // classifies the send as not-routed without ever touching the proxy/network.
    const withAuthority = vi.fn(
      <T>(operation: (authority: unknown) => T): T =>
        operation({ resolveOutboundBinding: () => null })
    );
    const deps = createProductionAttentionDeliveryDeps({
      proxyClient: {} as CredentialProxyClient,
      withAuthority: withAuthority as never,
      resolveSessionBinding: () => ({
        bindingId: "b1",
        expectedBindingRevision: 1,
        expectedInstallationRevision: 1,
      }),
    });
    const decision = await deps.deliverOutbound({
      bindingId: "b1",
      expectedBindingRevision: 1,
      expectedInstallationRevision: 1,
      messageKind: "mention",
      includesArtifacts: false,
      text: "hi",
      attempt: 0,
    });
    expect(withAuthority).toHaveBeenCalledTimes(1);
    expect(decision).toEqual({ delivered: false, shouldRetry: false, reason: "not-routed" });
  });
});
