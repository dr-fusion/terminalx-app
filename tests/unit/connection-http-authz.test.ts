import { describe, expect, it } from "vitest";
import {
  handleIssueLinkChallenge,
  handleCreateBinding,
  handleRevokeInstallation,
  type ConnectionHttpDependencies,
} from "@/lib/connections/http";
import type { RequestActor } from "@/lib/request-actor";

const canonicalActor: RequestActor = {
  kind: "human",
  userId: "user-1",
  username: "alice",
  displayName: "Alice",
  legacyRole: "admin",
  authentication: {
    provider: "local",
    subject: "alice",
    userGeneration: 1,
    identityGeneration: 1,
    authenticatedAtMs: 1_000,
    credentialIssuedAtMs: 1_000,
    credentialExpiresAtMs: 10_000,
    credentialJtiDigest: "a".repeat(64),
    device: { provenance: "browser" },
  },
};

// A legacy/auth-disabled actor has no `authentication` block.
const legacyActor: RequestActor = {
  kind: "human",
  userId: "single-user",
  username: "admin",
  displayName: "admin",
  legacyRole: "admin",
};

function request(body: unknown): Request {
  return new Request("https://terminalx.example/api/connections/link-challenges", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("connections HTTP authorization", () => {
  it("rejects an unauthenticated caller with 401", async () => {
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => null,
      withConnectionAuthority: () => {
        throw new Error("must not reach authority");
      },
    };
    const res = await handleIssueLinkChallenge(request({}), deps);
    expect(res.status).toBe(401);
  });

  it("rejects a legacy/auth-disabled actor (no canonical identity) with 401", async () => {
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => legacyActor,
      withConnectionAuthority: () => {
        throw new Error("must not reach authority");
      },
    };
    const res = await handleIssueLinkChallenge(request({}), deps);
    expect(res.status).toBe(401);
  });

  it("maps a non-member / non-owner authority denial to 403", async () => {
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => canonicalActor,
      withConnectionAuthority: () => {
        throw new Error("Team owner or admin authority is required");
      },
    };
    const res = await handleRevokeInstallation(request({ expectedRevision: 1 }), "inst-1", deps);
    expect(res.status).toBe(403);
  });

  it("maps a stale live-session gate to 403", async () => {
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => canonicalActor,
      withConnectionAuthority: () => {
        throw new Error("Connection authentication session is unavailable");
      },
    };
    const res = await handleCreateBinding(
      request({
        sessionId: "s",
        installationId: "i",
        expectedInstallationRevision: 1,
        conversationKind: "channel",
        externalConversationId: "c",
        inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
        outboundPolicy: { mode: "disabled", allowArtifacts: false },
      }),
      deps
    );
    expect(res.status).toBe(403);
  });

  it("maps a fenced/stale-revision conflict to 409", async () => {
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => canonicalActor,
      withConnectionAuthority: () => {
        throw new Error("Channel Installation revocation was fenced");
      },
    };
    const res = await handleRevokeInstallation(request({ expectedRevision: 2 }), "inst-1", deps);
    expect(res.status).toBe(409);
  });

  it("maps an unavailable broker/verifier to 503", async () => {
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => canonicalActor,
      withConnectionAuthority: () => {
        throw new Error("Verified Secret Broker registration is unavailable");
      },
    };
    const res = await handleCreateBinding(
      request({
        sessionId: "s",
        installationId: "i",
        expectedInstallationRevision: 1,
        conversationKind: "channel",
        externalConversationId: "c",
        inboundPolicy: { mode: "comments-only", requireLinkedIdentity: true },
        outboundPolicy: { mode: "disabled", allowArtifacts: false },
      }),
      deps
    );
    expect(res.status).toBe(503);
  });

  it("returns the issued Link Challenge once on success", async () => {
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => canonicalActor,
      withConnectionAuthority: (op) =>
        op({
          issueLinkChallenge: () => ({
            challenge: "txlc_v1_" + "0".repeat(64),
            expiresAtMs: 5_000,
            installationId: "inst-1",
            installationRevision: 1,
            requestedScopes: ["identity:telegram"],
          }),
        } as never),
    };
    const res = await handleIssueLinkChallenge(
      request({
        installationId: "inst-1",
        expectedInstallationRevision: 1,
        requestedScopes: ["identity:telegram"],
      }),
      deps
    );
    expect(res.status).toBe(200);
    const json = (await res.json()) as { linkChallenge: { challenge: string } };
    expect(json.linkChallenge.challenge).toMatch(/^txlc_v1_[0-9a-f]{64}$/);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("rejects a cross-origin cookie mutation with 403", async () => {
    const crossOrigin = new Request("https://terminalx.example/api/connections/link-challenges", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie: "terminalx-session=abc",
        origin: "https://evil.example",
        host: "terminalx.example",
      },
      body: JSON.stringify({}),
    });
    const deps: ConnectionHttpDependencies = {
      resolveActor: async () => canonicalActor,
      withConnectionAuthority: () => {
        throw new Error("must not reach authority");
      },
    };
    const res = await handleIssueLinkChallenge(crossOrigin, deps);
    expect(res.status).toBe(403);
  });
});
