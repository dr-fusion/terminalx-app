import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * AES-256-GCM at-rest envelope for broker-local secret material. The key never
 * leaves the broker process. Layout: 1 version byte, 12-byte IV, 16-byte auth
 * tag, then ciphertext. No plaintext is ever represented as a JS string, log
 * line, protocol frame, or error.
 */
const ENVELOPE_VERSION = 1;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + IV_BYTES + TAG_BYTES;
export const AT_REST_KEY_BYTES = KEY_BYTES;
const MAX_PLAINTEXT_BYTES = 256 * 1024;

const ASSOCIATED_DATA = Buffer.from("terminalx/secret-broker-at-rest/v1", "utf8");

export function assertAtRestKey(key: Buffer): Buffer {
  if (!Buffer.isBuffer(key) || key.byteLength !== KEY_BYTES) throw new TypeError();
  return key;
}

/** Encrypt `plaintext` and zero the caller-owned buffer on return. */
export function sealAtRest(plaintext: Buffer, key: Buffer): Buffer {
  assertAtRestKey(key);
  if (!Buffer.isBuffer(plaintext) || plaintext.byteLength > MAX_PLAINTEXT_BYTES) {
    plaintext.fill(0);
    throw new TypeError();
  }
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(ASSOCIATED_DATA);
  try {
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const envelope = Buffer.allocUnsafe(HEADER_BYTES + ciphertext.byteLength);
    envelope.writeUInt8(ENVELOPE_VERSION, 0);
    iv.copy(envelope, 1);
    tag.copy(envelope, 1 + IV_BYTES);
    ciphertext.copy(envelope, HEADER_BYTES);
    ciphertext.fill(0);
    return envelope;
  } finally {
    plaintext.fill(0);
  }
}

/**
 * Decrypt an at-rest envelope. The returned buffer is the caller's to zero.
 * Provided for completeness and tests; 8C never resolves secret material into a
 * response (that is Credential Proxy work).
 */
export function openAtRest(envelope: Buffer, key: Buffer): Buffer {
  assertAtRestKey(key);
  if (
    !Buffer.isBuffer(envelope) ||
    envelope.byteLength < HEADER_BYTES ||
    envelope.readUInt8(0) !== ENVELOPE_VERSION
  ) {
    throw new TypeError();
  }
  const iv = envelope.subarray(1, 1 + IV_BYTES);
  const tag = envelope.subarray(1 + IV_BYTES, HEADER_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(ASSOCIATED_DATA);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(envelope.subarray(HEADER_BYTES)), decipher.final()]);
}

export function sameKey(left: Buffer, right: Buffer): boolean {
  return left.byteLength === right.byteLength && timingSafeEqual(left, right);
}
