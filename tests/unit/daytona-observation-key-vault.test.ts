import { generateKeyPairSync } from "node:crypto";
import { chmodSync, lstatSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createRootObservationKeyVault,
  DAYTONA_OBSERVATION_KEY_ENVELOPE_KIND,
  encodeDaytonaObservationKeyEnvelope,
} from "../../packages/daytona-supervisor/src/observation-key-vault";

const uid = process.getuid?.() ?? 0;
const NOW = 10_000;
const binding = Object.freeze({
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 1,
  sandboxId: "sandbox-1",
  sandboxGeneration: 1,
  runtimePrincipalId: "principal-1",
});

describe("Daytona root observation-key vault", () => {
  it("zeroes intake bytes, retires an exact binding, and permanently tombstones the reference", async () => {
    const root = mkdtempSync(join(tmpdir(), "terminalx-observation-vault-"));
    chmodSync(root, 0o700);
    const vault = createRootObservationKeyVault({
      vaultRoot: root,
      expectedOwnerUid: uid,
      clock: () => NOW,
    });
    const first = envelope();
    const original = Buffer.from(first);
    try {
      const descriptor = await vault.provision(first);
      expect(first.every((byte) => byte === 0)).toBe(true);
      expect(descriptor).toMatchObject({
        keyProvisioningRef: "assignment-key-1",
        issuerKeyId: "observation-key-1",
        notAfterMs: NOW + 60_000,
      });

      const entries = readdirSync(root).filter((name) => name !== ".retired");
      expect(entries).toHaveLength(1);
      const entry = join(root, entries[0]!);
      expect(lstatSync(entry).mode & 0o777).toBe(0o700);
      expect(lstatSync(join(entry, "observation-key.pk8")).mode & 0o777).toBe(0o600);

      await expect(
        vault.retire({
          keyProvisioningRef: "assignment-key-1",
          binding: { ...binding, sandboxGeneration: 2 },
        })
      ).rejects.toMatchObject({ code: "conflict" });
      expect(readdirSync(entry)).toContain("observation-key.pk8");

      await vault.retire({ keyProvisioningRef: "assignment-key-1", binding });
      expect(readdirSync(root).filter((name) => name !== ".retired")).toEqual([]);
      await expect(
        vault.retire({ keyProvisioningRef: "assignment-key-1", binding })
      ).resolves.toBeUndefined();

      const replay = Buffer.from(original);
      await expect(vault.provision(replay)).rejects.toMatchObject({ code: "conflict" });
      expect(replay.every((byte) => byte === 0)).toBe(true);
      await vault.close();
    } finally {
      original.fill(0);
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("zeroes a malformed or public-key-mismatched envelope", async () => {
    const root = mkdtempSync(join(tmpdir(), "terminalx-observation-vault-"));
    chmodSync(root, 0o700);
    const vault = createRootObservationKeyVault({
      vaultRoot: root,
      expectedOwnerUid: uid,
      clock: () => NOW,
    });
    const value = envelope();
    value[value.byteLength - 1] = value[value.byteLength - 1]! ^ 0xff;
    try {
      await expect(vault.provision(value)).rejects.toMatchObject({ code: "not-ready" });
      expect(value.every((byte) => byte === 0)).toBe(true);
      await vault.close();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

function envelope(): Buffer {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyDer = privateKey.export({ type: "pkcs8", format: "der" });
  const bytes = Buffer.isBuffer(privateKeyDer) ? privateKeyDer : Buffer.from(privateKeyDer);
  try {
    return encodeDaytonaObservationKeyEnvelope(
      {
        version: 1,
        kind: DAYTONA_OBSERVATION_KEY_ENVELOPE_KIND,
        keyProvisioningRef: "assignment-key-1",
        binding,
        issuerKeyId: "observation-key-1",
        publicKeySpkiPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
        privateKeyBytes: bytes.byteLength,
        notAfterMs: NOW + 60_000,
      },
      bytes
    );
  } finally {
    bytes.fill(0);
  }
}
