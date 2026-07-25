import { createHash, createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createSlackOidcVerifier,
  type SlackJsonWebKey,
  type SlackOidcJwksClient,
} from "../../packages/secret-broker/src/exchange/slack-oidc";
import { createProviderExchange } from "../../packages/secret-broker/src/exchange/exchange";
import { SecretBrokerProtocolError } from "../../packages/secret-broker/src/protocol";

const ISSUER = "https://slack.com";
const AUDIENCE = "client-id-123";
const TEAM_ID = "T0001";
const APP_ID = "A0001";
const CHALLENGE = "link-challenge-nonce-abcdef0123456789";
const CHALLENGE_DIGEST = createHash("sha256").update(CHALLENGE, "utf8").digest("hex");
const NOW = 1_700_000_000_000;

interface Signer {
  readonly jwk: SlackJsonWebKey;
  readonly privateKey: KeyObject;
  readonly kid: string;
}

function makeSigner(kid: string): Signer {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" }) as unknown as { n: string; e: string };
  return {
    kid,
    privateKey,
    jwk: { kid, kty: "RSA", alg: "RS256", n: jwk.n, e: jwk.e, use: "sig" },
  };
}

function idToken(signer: Signer, claims: Record<string, unknown>, headerKid = signer.kid): string {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: headerKid }));
  const payload = base64url(JSON.stringify(claims));
  const signingInput = `${header}.${payload}`;
  const sign = createSign("RSA-SHA256");
  sign.update(signingInput);
  sign.end();
  const signature = sign.sign(signer.privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function base64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function baseClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "U-subject-1",
    exp: Math.floor(NOW / 1000) + 300,
    iat: Math.floor(NOW / 1000) - 5,
    nonce: CHALLENGE,
    jti: "jti-1",
    "https://slack.com/team_id": TEAM_ID,
    ...overrides,
  };
}

function jwksClient(keys: SlackJsonWebKey[], counter?: { calls: number }): SlackOidcJwksClient {
  return {
    async fetchSlackOidcJwks() {
      if (counter) counter.calls += 1;
      return { keys };
    },
  };
}

function verifierFor(signer: Signer, counter?: { calls: number }) {
  return createSlackOidcVerifier({
    jwks: jwksClient([signer.jwk], counter),
    clock: () => NOW,
  });
}

const EXPECTED = {
  expectedIssuer: ISSUER,
  expectedAudience: AUDIENCE,
  expectedTenantId: TEAM_ID,
  expectedAppId: APP_ID,
  challengeDigest: CHALLENGE_DIGEST,
} as const;

describe("Slack OIDC in-broker id_token verification", () => {
  it("verifies a valid id_token and returns only the non-secret identity", async () => {
    const signer = makeSigner("kid-1");
    const verifier = verifierFor(signer);
    const identity = await verifier.verify({ idToken: idToken(signer, baseClaims()), ...EXPECTED });
    expect(identity).toEqual({
      provider: "slack",
      externalTenantId: TEAM_ID,
      externalAppId: APP_ID,
      externalSubject: "U-subject-1",
      challenge: CHALLENGE,
      replayId: "jti-1",
    });
  });

  it("rejects a tampered signature", async () => {
    const signer = makeSigner("kid-1");
    const verifier = verifierFor(signer);
    const token = `${idToken(signer, baseClaims())}x`;
    await expect(verifier.verify({ idToken: token, ...EXPECTED })).rejects.toBeInstanceOf(
      SecretBrokerProtocolError
    );
  });

  it("rejects a token signed by a key outside the JWKS", async () => {
    const signer = makeSigner("kid-1");
    const foreign = makeSigner("kid-1");
    const verifier = verifierFor(signer);
    await expect(
      verifier.verify({ idToken: idToken(foreign, baseClaims()), ...EXPECTED })
    ).rejects.toBeInstanceOf(SecretBrokerProtocolError);
  });

  it("rejects wrong issuer, audience, tenant, expiry, and nonce binding", async () => {
    const signer = makeSigner("kid-1");
    const verifier = verifierFor(signer);
    const cases: Record<string, unknown>[] = [
      { iss: "https://evil.example" },
      { aud: "other-client" },
      { "https://slack.com/team_id": "T-OTHER" },
      { exp: Math.floor(NOW / 1000) - 3600 },
      { nonce: "a-different-nonce" },
      { sub: "" },
    ];
    for (const overrides of cases) {
      await expect(
        verifier.verify({ idToken: idToken(signer, baseClaims(overrides)), ...EXPECTED })
      ).rejects.toBeInstanceOf(SecretBrokerProtocolError);
    }
  });

  it("caches JWKS within the TTL and refreshes once on an unknown kid", async () => {
    const signer = makeSigner("kid-1");
    const counter = { calls: 0 };
    const verifier = verifierFor(signer, counter);
    await verifier.verify({ idToken: idToken(signer, baseClaims()), ...EXPECTED });
    await verifier.verify({ idToken: idToken(signer, baseClaims()), ...EXPECTED });
    expect(counter.calls).toBe(1);
    // An unknown kid triggers exactly one refresh, then still fails closed.
    await expect(
      verifier.verify({ idToken: idToken(signer, baseClaims(), "kid-unknown"), ...EXPECTED })
    ).rejects.toBeInstanceOf(SecretBrokerProtocolError);
    expect(counter.calls).toBe(2);
  });

  it("exposes slackOidc through the provider exchange with a closed identity response", async () => {
    const signer = makeSigner("kid-1");
    const exchange = createProviderExchange({
      client: {
        async slackOauthAccess() {
          throw new Error("unused");
        },
        async telegramGetMe() {
          throw new Error("unused");
        },
        async telegramSetWebhook() {
          throw new Error("unused");
        },
        async fetchSlackOidcJwks() {
          return { keys: [signer.jwk] };
        },
      },
      webhookSecrets: { put() {}, reveal: () => null, delete() {} },
      prepareInstallationCredential: async () => {
        throw new Error("unused");
      },
      clock: () => NOW,
      slackOidcJwks: { fetchSlackOidcJwks: async () => ({ keys: [signer.jwk] }) },
    });
    const result = await exchange.slackOidc({
      idToken: idToken(signer, baseClaims()),
      ...EXPECTED,
    });
    expect(result.identity).toMatchObject({ provider: "slack", externalSubject: "U-subject-1" });
  });
});
