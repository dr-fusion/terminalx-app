import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  signSecretBrokerReceipt,
  verifySecretBrokerReceipt,
  type SecretBrokerReceiptPayload,
} from "../../packages/secret-broker/src/receipt-schema";
import {
  createBrokerReceiptVerifier,
  type BrokerReceiptVerifier,
} from "@/lib/connections/secret-broker-verifier";
import { secretBrokerExpectationDigest } from "@/lib/connections/secret-broker-shared";
import type { CredentialHandleRegistrationExpectation } from "@/lib/connections/authority";

const ISSUED = 1_000_000;
const TTL = 5 * 60 * 1000;

function keys(): { signingKey: KeyObject; verificationKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { signingKey: privateKey, verificationKey: publicKey };
}

const installationExpectation: CredentialHandleRegistrationExpectation = Object.freeze({
  provider: "slack",
  brokerKind: "oauth-envelope",
  usage: "installation",
  authorityBinding: Object.freeze({
    kind: "installation",
    teamId: "team_1",
    externalTenantId: "T-TENANT",
    externalAppId: "A-APP",
  }),
  replaces: null,
});

function receiptPayload(
  expected: CredentialHandleRegistrationExpectation,
  overrides: Partial<SecretBrokerReceiptPayload> = {}
): SecretBrokerReceiptPayload {
  return {
    schema: 1,
    kind: "terminalx.secret-broker-registration-receipt",
    brokerInstanceId: "00112233445566778899aabbccddeeff",
    brokerEpoch: 1,
    signingKeyId: "a".repeat(64),
    operationId: "op_test",
    handleId: "hnd_test",
    receiptId: "rcp_test",
    provider: expected.provider,
    brokerKind: expected.brokerKind,
    usage: expected.usage,
    expectationDigest: secretBrokerExpectationDigest(expected),
    hasReplacement: expected.replaces !== null,
    issuedAtMs: ISSUED,
    expiresAtMs: ISSUED + TTL,
    ...overrides,
  };
}

function verifierAt(now: number, verificationKey: KeyObject): BrokerReceiptVerifier {
  return createBrokerReceiptVerifier({ verificationPublicKey: verificationKey, clock: () => now });
}

describe("Secret Broker receipt verification", () => {
  it("accepts a well-formed, in-window, exactly-bound receipt", () => {
    const { signingKey, verificationKey } = keys();
    const receipt = signSecretBrokerReceipt(receiptPayload(installationExpectation), signingKey);
    const verify = verifierAt(ISSUED + 1000, verificationKey);
    const result = verify({ proof: receipt, expected: installationExpectation });
    expect(result).not.toBeNull();
    expect(result?.handleId).toBe("hnd_test");
    expect(result?.receiptId).toBe("rcp_test");
    expect(result?.authorityBinding).toEqual(installationExpectation.authorityBinding);
  });

  it("rejects a forged signature", () => {
    const { signingKey } = keys();
    const foreign = keys();
    const receipt = signSecretBrokerReceipt(receiptPayload(installationExpectation), signingKey);
    const verify = verifierAt(ISSUED + 1000, foreign.verificationKey);
    expect(verify({ proof: receipt, expected: installationExpectation })).toBeNull();
  });

  it("rejects a receipt whose payload was tampered after signing", () => {
    const { signingKey, verificationKey } = keys();
    const receipt = signSecretBrokerReceipt(receiptPayload(installationExpectation), signingKey);
    const tampered = {
      payload: { ...receipt.payload, handleId: "hnd_swapped" },
      signature: receipt.signature,
    };
    const verify = verifierAt(ISSUED + 1000, verificationKey);
    expect(verify({ proof: tampered, expected: installationExpectation })).toBeNull();
    // The unbroken receipt still verifies via the low-level helper.
    expect(verifySecretBrokerReceipt(receipt, verificationKey)).not.toBeNull();
    expect(verifySecretBrokerReceipt(tampered, verificationKey)).toBeNull();
  });

  it("rejects an expired receipt and one used before issuance", () => {
    const { signingKey, verificationKey } = keys();
    const receipt = signSecretBrokerReceipt(receiptPayload(installationExpectation), signingKey);
    expect(
      verifierAt(
        ISSUED + TTL,
        verificationKey
      )({ proof: receipt, expected: installationExpectation })
    ).toBeNull();
    expect(
      verifierAt(ISSUED - 1, verificationKey)({ proof: receipt, expected: installationExpectation })
    ).toBeNull();
  });

  it("rejects a receipt bound to a different provider, broker kind, or usage", () => {
    const { signingKey, verificationKey } = keys();
    const verify = verifierAt(ISSUED + 1000, verificationKey);
    // A receipt signed for telegram cannot be replayed as a slack expectation.
    const telegramExpectation = { ...installationExpectation, provider: "telegram" as const };
    const receipt = signSecretBrokerReceipt(receiptPayload(telegramExpectation), signingKey);
    expect(verify({ proof: receipt, expected: installationExpectation })).toBeNull();
    expect(verify({ proof: receipt, expected: telegramExpectation })).not.toBeNull();

    const onepwExpectation = {
      ...installationExpectation,
      brokerKind: "onepassword-connect" as const,
    };
    const kindReceipt = signSecretBrokerReceipt(receiptPayload(onepwExpectation), signingKey);
    expect(verify({ proof: kindReceipt, expected: installationExpectation })).toBeNull();
  });

  it("rejects a receipt whose authority binding does not match the expectation", () => {
    const { signingKey, verificationKey } = keys();
    const verify = verifierAt(ISSUED + 1000, verificationKey);
    // Sign against one team, present a different team as the expectation.
    const receipt = signSecretBrokerReceipt(receiptPayload(installationExpectation), signingKey);
    const otherTeam: CredentialHandleRegistrationExpectation = {
      ...installationExpectation,
      authorityBinding: {
        kind: "installation",
        teamId: "team_2",
        externalTenantId: "T-TENANT",
        externalAppId: "A-APP",
      },
    };
    expect(verify({ proof: receipt, expected: otherTeam })).toBeNull();
  });

  it("rejects a rotation/non-rotation mismatch", () => {
    const { signingKey, verificationKey } = keys();
    const verify = verifierAt(ISSUED + 1000, verificationKey);
    const rotationExpectation: CredentialHandleRegistrationExpectation = {
      ...installationExpectation,
      replaces: { handleId: "hnd_old", generation: 1 },
    };
    const rotationReceipt = signSecretBrokerReceipt(
      receiptPayload(rotationExpectation),
      signingKey
    );
    // A rotation receipt cannot satisfy a non-rotation expectation and vice versa.
    expect(verify({ proof: rotationReceipt, expected: installationExpectation })).toBeNull();
    expect(verify({ proof: rotationReceipt, expected: rotationExpectation })).not.toBeNull();
    const plain = signSecretBrokerReceipt(receiptPayload(installationExpectation), signingKey);
    expect(verify({ proof: plain, expected: rotationExpectation })).toBeNull();
  });

  it("rejects structurally invalid proofs without throwing", () => {
    const { verificationKey } = keys();
    const verify = verifierAt(ISSUED + 1000, verificationKey);
    for (const proof of [null, undefined, {}, { payload: {} }, "nope", 42, []]) {
      expect(verify({ proof, expected: installationExpectation })).toBeNull();
    }
  });
});
