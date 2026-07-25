import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  handleCompleteSlackOidcLink,
  type SlackOidcLinkDependencies,
} from "@/lib/connections/http";
import type { RequestActor } from "@/lib/request-actor";
import type {
  ProviderExchangeClient,
  SlackOidcVerifiedIdentity,
} from "@/lib/connections/provider-exchange-client";

const canonicalActor: RequestActor = {
  kind: "human",
  userId: "user-1",
  username: "alice",
  displayName: "Alice",
  legacyRole: "member",
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

const CHALLENGE = "link-challenge-xyz-0123456789";
const CHALLENGE_DIGEST = createHash("sha256").update(CHALLENGE, "utf8").digest("hex");

const identity: SlackOidcVerifiedIdentity = {
  provider: "slack",
  externalTenantId: "T0001",
  externalAppId: "A0001",
  externalSubject: "U-alice",
  challenge: CHALLENGE,
  replayId: "jti-1",
};

function exchangeClient(
  capture: { input?: unknown },
  override?: Partial<Pick<ProviderExchangeClient, "slackOidc">>
): ProviderExchangeClient {
  return {
    async slackOauth() {
      throw new Error("unused");
    },
    async telegramBotToken() {
      throw new Error("unused");
    },
    async verifySlackWebhook() {
      throw new Error("unused");
    },
    slackOidc:
      override?.slackOidc ??
      (async (input) => {
        capture.input = input;
        return identity;
      }),
  };
}

function request(body: unknown): Request {
  return new Request(
    "https://terminalx.example/api/connections/identity-connections/slack/callback",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }
  );
}

const expectation = {
  expectedIssuer: "https://slack.com",
  expectedAudience: "client-id",
  expectedTenantId: "T0001",
  expectedAppId: "A0001",
};

describe("Slack OIDC identity-link callback handler", () => {
  it("verifies the id_token in the broker and completes the link challenge", async () => {
    const capture: { input?: unknown } = {};
    let completedProof: unknown;
    const deps: SlackOidcLinkDependencies = {
      resolveActor: async () => canonicalActor,
      exchangeClient: exchangeClient(capture),
      resolveSlackOidcExpectation: () => expectation,
      withConnectionAuthority: (op) =>
        op({
          completeLinkChallenge: (input: { challenge: string; providerProof: unknown }) => {
            completedProof = input.providerProof;
            expect(input.challenge).toBe(CHALLENGE);
            return { connectionId: "conn-1", provider: "slack" };
          },
        } as never),
    };
    const response = await handleCompleteSlackOidcLink(
      request({ installationId: "inst-1", challenge: CHALLENGE, idToken: "header.payload.sig" }),
      deps
    );
    expect(response.status).toBe(200);
    expect(capture.input).toMatchObject({ challengeDigest: CHALLENGE_DIGEST, ...expectation });
    expect(completedProof).toMatchObject({ kind: "slack-oidc", externalSubject: "U-alice" });
  });

  it("fails closed with 401 when the broker declines the id_token", async () => {
    const deps: SlackOidcLinkDependencies = {
      resolveActor: async () => canonicalActor,
      exchangeClient: exchangeClient(
        {},
        {
          slackOidc: async () => {
            throw new Error("declined");
          },
        }
      ),
      resolveSlackOidcExpectation: () => expectation,
      withConnectionAuthority: () => {
        throw new Error("must not reach authority");
      },
    };
    const response = await handleCompleteSlackOidcLink(
      request({ installationId: "inst-1", challenge: CHALLENGE, idToken: "a.b.c" }),
      deps
    );
    expect(response.status).toBe(401);
  });

  it("rejects an unauthenticated caller", async () => {
    const deps: SlackOidcLinkDependencies = {
      resolveActor: async () => null,
      exchangeClient: exchangeClient({}),
      resolveSlackOidcExpectation: () => expectation,
      withConnectionAuthority: () => {
        throw new Error("unused");
      },
    };
    const response = await handleCompleteSlackOidcLink(
      request({ installationId: "inst-1", challenge: CHALLENGE, idToken: "a.b.c" }),
      deps
    );
    expect(response.status).toBe(401);
  });

  it("fails closed with 404 when no expectation resolves for the installation", async () => {
    const deps: SlackOidcLinkDependencies = {
      resolveActor: async () => canonicalActor,
      exchangeClient: exchangeClient({}),
      resolveSlackOidcExpectation: () => null,
      withConnectionAuthority: () => {
        throw new Error("unused");
      },
    };
    const response = await handleCompleteSlackOidcLink(
      request({ installationId: "inst-1", challenge: CHALLENGE, idToken: "a.b.c" }),
      deps
    );
    expect(response.status).toBe(404);
  });
});
