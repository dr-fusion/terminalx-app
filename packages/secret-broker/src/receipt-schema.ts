import { sign, verify, type KeyObject } from "node:crypto";
import {
  boundedIdentifier,
  canonicalJson,
  digestField,
  exactRecord,
  field,
  positiveInteger,
  RECEIPT_FIELDS,
  RECEIPT_PAYLOAD_FIELDS,
  safeTimestamp,
} from "./protocol";

export const SECRET_BROKER_RECEIPT_KIND = "terminalx.secret-broker-registration-receipt" as const;
export const SECRET_BROKER_RECEIPT_SCHEMA = 1 as const;
const RECEIPT_SIGNATURE_DOMAIN = "terminalx/secret-broker-registration-receipt/v1\0";
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;

/**
 * The signed body of a registration receipt. It binds the broker identity, the
 * opaque handle/receipt/operation identifiers, and a single `expectationDigest`
 * that commits to the exact CredentialHandleRegistrationExpectation. It never
 * contains secret material — that is enforced structurally here and by the
 * closed-response guard in {@link ./protocol}.
 */
export interface SecretBrokerReceiptPayload {
  readonly schema: typeof SECRET_BROKER_RECEIPT_SCHEMA;
  readonly kind: typeof SECRET_BROKER_RECEIPT_KIND;
  readonly brokerInstanceId: string;
  readonly brokerEpoch: number;
  readonly signingKeyId: string;
  readonly operationId: string;
  readonly handleId: string;
  readonly receiptId: string;
  readonly provider: string;
  readonly brokerKind: string;
  readonly usage: string;
  readonly expectationDigest: string;
  readonly hasReplacement: boolean;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

export interface SecretBrokerReceipt {
  readonly payload: SecretBrokerReceiptPayload;
  readonly signature: string;
}

/** Validate and freeze a receipt payload. Throws on any shape violation. */
export function snapshotReceiptPayload(value: unknown): SecretBrokerReceiptPayload {
  const record = exactRecord(value, RECEIPT_PAYLOAD_FIELDS);
  const issuedAtMs = safeTimestamp(field(record, "issuedAtMs"));
  const expiresAtMs = safeTimestamp(field(record, "expiresAtMs"));
  const hasReplacement = field(record, "hasReplacement");
  if (
    field(record, "schema") !== SECRET_BROKER_RECEIPT_SCHEMA ||
    field(record, "kind") !== SECRET_BROKER_RECEIPT_KIND ||
    typeof hasReplacement !== "boolean" ||
    expiresAtMs <= issuedAtMs
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    schema: SECRET_BROKER_RECEIPT_SCHEMA,
    kind: SECRET_BROKER_RECEIPT_KIND,
    brokerInstanceId: boundedIdentifier(field(record, "brokerInstanceId")),
    brokerEpoch: positiveInteger(field(record, "brokerEpoch")),
    signingKeyId: boundedIdentifier(field(record, "signingKeyId")),
    operationId: boundedIdentifier(field(record, "operationId")),
    handleId: boundedIdentifier(field(record, "handleId")),
    receiptId: boundedIdentifier(field(record, "receiptId"), 2048),
    provider: boundedIdentifier(field(record, "provider")),
    brokerKind: boundedIdentifier(field(record, "brokerKind")),
    usage: boundedIdentifier(field(record, "usage")),
    expectationDigest: digestField(field(record, "expectationDigest")),
    hasReplacement,
    issuedAtMs,
    expiresAtMs,
  });
}

function receiptSigningInput(payload: SecretBrokerReceiptPayload): Buffer {
  return Buffer.from(`${RECEIPT_SIGNATURE_DOMAIN}${canonicalJson(payload)}`, "utf8");
}

/** Ed25519-sign a validated receipt payload with the broker signing key. */
export function signSecretBrokerReceipt(
  payload: SecretBrokerReceiptPayload,
  signingPrivateKey: KeyObject
): SecretBrokerReceipt {
  assertEd25519Key(signingPrivateKey, "private");
  const snapshot = snapshotReceiptPayload(payload);
  const signature = sign(null, receiptSigningInput(snapshot), signingPrivateKey).toString(
    "base64url"
  );
  if (!SIGNATURE.test(signature)) throw new TypeError();
  return Object.freeze({ payload: snapshot, signature });
}

/** Snapshot an untrusted wire receipt without verifying its signature. */
export function snapshotReceipt(value: unknown): SecretBrokerReceipt {
  const record = exactRecord(value, RECEIPT_FIELDS);
  const signature = field(record, "signature");
  if (typeof signature !== "string" || !SIGNATURE.test(signature)) throw new TypeError();
  return Object.freeze({
    payload: snapshotReceiptPayload(field(record, "payload")),
    signature,
  });
}

/**
 * Verify a wire receipt's Ed25519 signature against `verificationPublicKey` and
 * return the validated payload. Returns `null` on any failure so callers fail
 * closed without leaking which check failed.
 */
export function verifySecretBrokerReceipt(
  proof: unknown,
  verificationPublicKey: KeyObject
): SecretBrokerReceiptPayload | null {
  try {
    assertEd25519Key(verificationPublicKey, "public");
    const receipt = snapshotReceipt(proof);
    const valid = verify(
      null,
      receiptSigningInput(receipt.payload),
      verificationPublicKey,
      Buffer.from(receipt.signature, "base64url")
    );
    return valid ? receipt.payload : null;
  } catch {
    return null;
  }
}

function assertEd25519Key(value: unknown, type: "public" | "private"): asserts value is KeyObject {
  if (
    !(value instanceof Object) ||
    (value as KeyObject).type !== type ||
    (value as KeyObject).asymmetricKeyType !== "ed25519"
  ) {
    throw new TypeError();
  }
}
