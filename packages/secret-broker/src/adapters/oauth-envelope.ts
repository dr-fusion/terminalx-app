import { assertAtRestKey, openAtRest, sealAtRest } from "../at-rest";
import { SecretBrokerProtocolError } from "../protocol";
import type { PreparedSecret, SecretManagerAdapter } from "./index";

/**
 * Stores provider OAuth material broker-locally, encrypted at rest with
 * AES-256-GCM under the broker-root keyfile. The key never leaves this process
 * and the plaintext is zeroed immediately after sealing.
 */
export function createOauthEnvelopeAdapter(atRestKey: Buffer): SecretManagerAdapter {
  assertAtRestKey(atRestKey);
  return Object.freeze({
    kind: "oauth-envelope" as const,
    async prepare(secretMaterial: Buffer): Promise<PreparedSecret> {
      if (!Buffer.isBuffer(secretMaterial) || secretMaterial.byteLength < 1) {
        if (Buffer.isBuffer(secretMaterial)) secretMaterial.fill(0);
        throw new SecretBrokerProtocolError("invalid-request");
      }
      // sealAtRest zeroes secretMaterial; the sealed envelope is opaque.
      return Object.freeze({ material: sealAtRest(secretMaterial, atRestKey) });
    },
    async destroy(material: Buffer): Promise<void> {
      // The sealed envelope is deleted with its broker row. Zero any copy we
      // are handed for defense in depth.
      if (Buffer.isBuffer(material)) material.fill(0);
    },
  });
}

/**
 * Test-only helper proving the sealed material round-trips. 8C never resolves
 * secret material into a protocol response; this exists so at-rest encryption
 * can be asserted without adding an exporting operation.
 */
export function openOauthEnvelopeForTest(sealed: Buffer, atRestKey: Buffer): Buffer {
  return openAtRest(sealed, atRestKey);
}
