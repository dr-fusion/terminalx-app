import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { writeOwnedBuffer } from "../../packages/daytona-supervisor/src/owned-writable";
import { encodeDaytonaAssignmentBootstrapInstalledResponse } from "../../packages/daytona-supervisor/src/assignment-bootstrap-daemon";
import { canonicalRuntimeJson } from "../../src/lib/runtime/runtime-command-canonical";

describe("Daytona owned Writable output", () => {
  it("does not zero a retained chunk until the Writable callback releases it", async () => {
    let release: (() => void) | undefined;
    let observedDuringWrite: Buffer | undefined;
    const output = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        observedDuringWrite = Buffer.from(chunk);
        release = callback;
      },
    });
    const bytes = Buffer.from("sensitive-response", "utf8");
    const pending = writeOwnedBuffer(output, bytes);
    await Promise.resolve();
    expect(bytes.toString("utf8")).toBe("sensitive-response");
    expect(observedDuringWrite?.toString("utf8")).toBe("sensitive-response");
    release?.();
    await pending;
    expect(bytes.every((byte) => byte === 0)).toBe(true);
  });

  it("emits the installed descriptor as exact JSON with no leading or trailing bytes", () => {
    const publicKeySpkiPem =
      "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2gR9n1Vv6T6g9gxucZyyi2dKXr0/TYBVlC6V6dH3v8A=\n-----END PUBLIC KEY-----\n";
    const descriptor = {
      version: 1,
      kind: "terminalx.daytona-assignment-bootstrap-installed",
      envelopeDigest: "0".repeat(64),
      providerIdentityCommitment: "1".repeat(64),
      providerRevision: 1,
      planDigest: "2".repeat(64),
      assignmentPlanDigest: "2".repeat(64),
      effectEnforcerPolicyDigest: "7".repeat(64),
      effectManifestBindingDigest: "8".repeat(64),
      effectEnforcerSetDigest: "9".repeat(64),
      bindingDigest: "3".repeat(64),
      effectEnforcerKeyId: "runtime-enforcer-key-1",
      effectEnforcerPublicKeyDigest: "6".repeat(64),
      observationIssuerKeyId: "observation-key-1",
      observationPublicKeyDigest: "4".repeat(64),
      stateVerificationPublicKeySpkiPem: publicKeySpkiPem,
      stateVerificationPublicKeyDigest:
        "f156757c29b06e139f85f758a95e6819536ac887631d395782ce5797516e159b",
      supervisorArtifactDigest: "5".repeat(64),
      installedMarker: "/run/terminalx-root/assignment.installed.json",
      supervisorReady: false,
    } as const;
    const bytes = encodeDaytonaAssignmentBootstrapInstalledResponse(descriptor);
    try {
      const wire = bytes.toString("utf8");
      expect(wire).toBe(canonicalRuntimeJson(descriptor));
      expect(bytes[0]).toBe(0x7b);
      expect(bytes[bytes.byteLength - 1]).toBe(0x7d);
    } finally {
      bytes.fill(0);
    }
  });
});
