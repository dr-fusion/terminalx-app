import { createPublicKey, type KeyObject } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import { sameDigest } from "../../../packages/secret-broker/src/protocol";
import { verifySecretBrokerReceipt } from "../../../packages/secret-broker/src/receipt-schema";
import { BROKER_VERIFICATION_KEY_FILE } from "../../../packages/secret-broker/src/broker-root";
import { secretBrokerExpectationDigest } from "./secret-broker-shared";
import type {
  CredentialHandleRegistrationExpectation,
  VerifiedCredentialHandleRegistration,
} from "./authority";

export interface CreateBrokerReceiptVerifierOptions {
  readonly verificationPublicKey: KeyObject;
  readonly clock?: () => number;
}

export type BrokerReceiptVerifier = (input: {
  proof: unknown;
  expected: Readonly<CredentialHandleRegistrationExpectation>;
}) => VerifiedCredentialHandleRegistration | null;

/**
 * A synchronous, local, network-free verifier for the injected
 * `verifyCredentialHandleRegistration` authority callback. It checks the
 * Ed25519 signature, the exact expectation binding, and the receipt validity
 * window, and fails closed (returns `null`) on any mismatch. Single-use is
 * enforced separately by the authority's unique broker-receipt-digest column.
 */
export function createBrokerReceiptVerifier(
  options: CreateBrokerReceiptVerifierOptions
): BrokerReceiptVerifier {
  const publicKey = options.verificationPublicKey;
  if (
    !(publicKey instanceof Object) ||
    publicKey.type !== "public" ||
    publicKey.asymmetricKeyType !== "ed25519"
  ) {
    throw new TypeError("A Secret Broker Ed25519 verification key is required");
  }
  const clock = options.clock ?? Date.now;

  return ({ proof, expected }) => {
    try {
      const payload = verifySecretBrokerReceipt(proof, publicKey);
      if (!payload) return null;
      const now = clock();
      if (!Number.isSafeInteger(now) || now < payload.issuedAtMs || now >= payload.expiresAtMs) {
        return null;
      }
      if (
        payload.provider !== expected.provider ||
        payload.brokerKind !== expected.brokerKind ||
        payload.usage !== expected.usage ||
        payload.hasReplacement !== (expected.replaces !== null) ||
        !sameDigest(payload.expectationDigest, secretBrokerExpectationDigest(expected))
      ) {
        return null;
      }
      return Object.freeze({
        provider: expected.provider,
        brokerKind: expected.brokerKind,
        usage: expected.usage,
        authorityBinding: expected.authorityBinding,
        replaces: expected.replaces,
        handleId: payload.handleId,
        receiptId: payload.receiptId,
      });
    } catch {
      return null;
    }
  };
}

/**
 * Read the broker's published Ed25519 verification key at composition time. No
 * network I/O and no IPC; the broker writes this file into its 0700 root on
 * first boot. Fails closed on any permission or format problem.
 */
export function readBrokerVerificationKey(
  rootDir: string,
  expectedOwnerUid?: number
): KeyObject | null {
  const path = join(rootDir, BROKER_VERIFICATION_KEY_FILE);
  let descriptor = -1;
  try {
    const link = lstatSync(path);
    if (link.isSymbolicLink()) return null;
    descriptor = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const stat = fstatSync(descriptor);
    const uid =
      expectedOwnerUid ?? (typeof process.geteuid === "function" ? process.geteuid() : stat.uid);
    if (
      !stat.isFile() ||
      stat.nlink !== 1 ||
      stat.uid !== uid ||
      (stat.mode & 0o077) !== 0 ||
      stat.size < 1 ||
      stat.size > 64 * 1024
    ) {
      return null;
    }
    const pem = readFileSync(descriptor, "utf8");
    const key = createPublicKey(pem);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") return null;
    return key;
  } catch {
    return null;
  } finally {
    if (descriptor >= 0) closeSync(descriptor);
  }
}
