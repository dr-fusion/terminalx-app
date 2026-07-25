import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resolveConfiguredProviderProofVerifier } from "@/lib/connections/secret-broker-composition";
import { sha256 } from "@/lib/connections/contracts";
import type { ProviderProofExpectation } from "@/lib/connections/authority";

const BROKER_ROOT_ENV = "TERMINALX_SECRET_BROKER_ROOT";

const CHALLENGE = "txlc_v1_" + "a".repeat(64);

function expectation(
  provider: "telegram" | "slack",
  overrides: Partial<ProviderProofExpectation> = {}
): ProviderProofExpectation {
  return {
    provider,
    externalTenantId: "T-1",
    externalAppId: "A-1",
    installationId: "inst-1",
    installationRevision: 1,
    challengeDigest: sha256(CHALLENGE),
    requestedScopes: ["identity:telegram"],
    requestedScopesDigest: sha256("identity:telegram"),
    ...overrides,
  };
}

describe("production verifyProviderProof composition", () => {
  const saved = process.env[BROKER_ROOT_ENV];

  beforeEach(() => {
    delete process.env[BROKER_ROOT_ENV];
  });

  afterEach(() => {
    if (saved === undefined) delete process.env[BROKER_ROOT_ENV];
    else process.env[BROKER_ROOT_ENV] = saved;
  });

  it("returns null when no Secret Broker is configured (fails closed exactly as today)", () => {
    expect(resolveConfiguredProviderProofVerifier()).toBeNull();
  });

  it("dispatches Telegram deep-link proofs when a broker is configured", () => {
    process.env[BROKER_ROOT_ENV] = "/tmp/terminalx-broker-root";
    const verify = resolveConfiguredProviderProofVerifier();
    expect(verify).not.toBeNull();
    const proof = {
      kind: "telegram-deeplink",
      externalTenantId: "T-1",
      externalAppId: "A-1",
      externalSubject: "user-42",
      challenge: CHALLENGE,
      replayId: "replay-1",
    };
    const verified = verify?.({ proof, expected: expectation("telegram") });
    expect(verified).toMatchObject({ provider: "telegram", externalSubject: "user-42" });
    // A Slack-shaped proof under a Telegram expectation fails closed.
    expect(
      verify?.({ proof: { ...proof, kind: "slack-oidc" }, expected: expectation("telegram") })
    ).toBeNull();
  });

  it("dispatches Slack OIDC proofs when a broker is configured", () => {
    process.env[BROKER_ROOT_ENV] = "/tmp/terminalx-broker-root";
    const verify = resolveConfiguredProviderProofVerifier();
    const proof = {
      kind: "slack-oidc",
      externalTenantId: "T-1",
      externalAppId: "A-1",
      externalSubject: "U-slack",
      challenge: CHALLENGE,
      replayId: "jti-1",
    };
    const verified = verify?.({
      proof,
      expected: expectation("slack", {
        requestedScopes: ["openid"],
        requestedScopesDigest: sha256("openid"),
      }),
    });
    expect(verified).toMatchObject({ provider: "slack", externalSubject: "U-slack" });
  });

  it("returns null for a provider outside the closed set", () => {
    process.env[BROKER_ROOT_ENV] = "/tmp/terminalx-broker-root";
    const verify = resolveConfiguredProviderProofVerifier();
    const verified = verify?.({
      proof: {},
      expected: expectation("telegram", {
        provider: "discord" as unknown as ProviderProofExpectation["provider"],
      }),
    });
    expect(verified).toBeNull();
  });
});
