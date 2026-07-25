import { createHash, generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createDaytonaAssignmentBootstrapEnvelope,
  DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND,
  DAYTONA_SANDBOX_DEPLOYMENT_BINDING_CLAIMS_DIGEST_DOMAIN,
  DAYTONA_SANDBOX_DEPLOYMENT_BINDING_KIND,
  DAYTONA_SANDBOX_DEPLOYMENT_BINDING_SIGNATURE_DOMAIN,
  provisionDaytonaAssignmentBootstrap,
} from "../../packages/daytona-supervisor/src/assignment-bootstrap";
import {
  decodeDaytonaSupervisorBootstrapConfiguration,
  type DaytonaSupervisorBootstrapConfiguration,
} from "../../packages/daytona-supervisor/src/daemon";
import { canonicalRuntimeJson } from "../../src/lib/runtime/runtime-command-canonical";
import { createDaytonaAssignmentEffectManifest } from "../../src/lib/runtime/daytona-assignment-effect-manifest";

const PROVIDER_ID = "123e4567-e89b-42d3-a456-426614174000";
const NOW = 10_000;
const uid = process.getuid?.() ?? 0;

afterEach(() => vi.unstubAllEnvs());

describe("Daytona assignment bootstrap", () => {
  it("installs once, generates the state key in root, and revalidates an expired exact replay", () => {
    const fixture = bootstrapFixture();
    let now = NOW;
    const envelope = fixture.envelope();
    const replay = Buffer.from(envelope);
    vi.stubEnv("DAYTONA_SANDBOX_ID", PROVIDER_ID);
    vi.stubEnv("DAYTONA_SANDBOX_USER", "terminalx");
    try {
      const installed = provisionDaytonaAssignmentBootstrap(envelope, {
        ...fixture.provision,
        clock: () => now,
      });
      expect(envelope.every((byte) => byte === 0)).toBe(true);
      expect(installed).toMatchObject({
        kind: DAYTONA_ASSIGNMENT_BOOTSTRAP_INSTALLED_KIND,
        supervisorReady: false,
        installedMarker: join(fixture.runtimeRoot, "assignment.installed.json"),
        supervisorArtifactDigest: fixture.bootstrap.assignment.supervisorArtifactDigest,
      });
      expect(installed.stateVerificationPublicKeySpkiPem).toMatch(/^-----BEGIN PUBLIC KEY-----/u);
      const statePrivate = readFileSync(
        join(fixture.runtimeRoot, "assignment", "state-signing.pk8")
      );
      expect(replay.includes(statePrivate)).toBe(false);
      statePrivate.fill(0);

      now = NOW + 60_000;
      const replayed = provisionDaytonaAssignmentBootstrap(replay, {
        ...fixture.provision,
        clock: () => now,
      });
      expect(replay.every((byte) => byte === 0)).toBe(true);
      expect(replayed).toEqual(installed);
    } finally {
      fixture.close();
    }
  });

  it("rejects a different envelope and fails closed if committed key material drifts", () => {
    const fixture = bootstrapFixture();
    vi.stubEnv("DAYTONA_SANDBOX_ID", PROVIDER_ID);
    vi.stubEnv("DAYTONA_SANDBOX_USER", "terminalx");
    const first = fixture.envelope();
    const replay = Buffer.from(first);
    try {
      provisionDaytonaAssignmentBootstrap(first, fixture.provision);
      const different = Buffer.from(replay);
      different[different.byteLength - 1] = different[different.byteLength - 1]! ^ 0xff;
      expect(() => provisionDaytonaAssignmentBootstrap(different, fixture.provision)).toThrow(
        expect.objectContaining({ exitCode: 73 })
      );
      expect(different.every((byte) => byte === 0)).toBe(true);

      writeFileSync(
        join(fixture.runtimeRoot, "assignment", "observation-key.pk8"),
        Buffer.from("drift", "utf8")
      );
      chmodSync(join(fixture.runtimeRoot, "assignment", "observation-key.pk8"), 0o600);
      expect(() => provisionDaytonaAssignmentBootstrap(replay, fixture.provision)).toThrow();
      expect(replay.every((byte) => byte === 0)).toBe(true);
    } finally {
      fixture.close();
    }
  });

  it("rejects envelope-selected executable and isolation pins", () => {
    const fixture = bootstrapFixture();
    vi.stubEnv("DAYTONA_SANDBOX_ID", PROVIDER_ID);
    vi.stubEnv("DAYTONA_SANDBOX_USER", "terminalx");
    const envelope = fixture.envelope({
      ...fixture.bootstrap,
      transport: {
        ...fixture.bootstrap.transport,
        peerCredentialExecutableSha256: "f".repeat(64),
      },
    });
    try {
      expect(() => provisionDaytonaAssignmentBootstrap(envelope, fixture.provision)).toThrow(
        expect.objectContaining({ exitCode: 64 })
      );
      expect(envelope.every((byte) => byte === 0)).toBe(true);
    } finally {
      fixture.close();
    }
  });

  it("rejects noncanonical, invalid UTF-8, section-tampered, and signature-tampered headers", () => {
    const fixture = bootstrapFixture();
    vi.stubEnv("DAYTONA_SANDBOX_ID", PROVIDER_ID);
    vi.stubEnv("DAYTONA_SANDBOX_USER", "terminalx");
    try {
      const candidates = [
        rewriteEnvelopeHeader(fixture.envelope(), (header) =>
          Buffer.from(`{ ${header.toString("utf8").slice(1)}`, "utf8")
        ),
        rewriteEnvelopeHeader(fixture.envelope(), (header) => {
          const invalid = Buffer.from(header);
          invalid[1] = 0xff;
          return invalid;
        }),
        rewriteEnvelopeCanonicalHeader(fixture.envelope(), (header) => {
          header.sections[0].sha256 = "0".repeat(64);
        }),
        rewriteEnvelopeCanonicalHeader(fixture.envelope(), (header) => {
          const signature = header.authority.signature;
          header.authority.signature = `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
        }),
      ];
      for (const envelope of candidates) {
        expect(() => provisionDaytonaAssignmentBootstrap(envelope, fixture.provision)).toThrow(
          expect.objectContaining({ exitCode: 64 })
        );
        expect(envelope.every((byte) => byte === 0)).toBe(true);
      }
    } finally {
      fixture.close();
    }
  });

  it.each([
    "provider environment",
    "sandbox user environment",
    "hostname binding",
    "image-owned artifact pin",
    "bootstrap authority pin",
    "deployment signature",
    "deployment canonical bytes",
  ] as const)("rejects drift in %s", (drift) => {
    const fixture = bootstrapFixture();
    vi.stubEnv("DAYTONA_SANDBOX_ID", PROVIDER_ID);
    vi.stubEnv("DAYTONA_SANDBOX_USER", "terminalx");
    try {
      if (drift === "provider environment") {
        vi.stubEnv("DAYTONA_SANDBOX_ID", "223e4567-e89b-42d3-a456-426614174000");
      } else if (drift === "sandbox user environment") {
        vi.stubEnv("DAYTONA_SANDBOX_USER", "root");
      } else if (drift === "hostname binding") {
        writeFileSync(fixture.provision.hostnameFile, "223e4567-e89b-42d3-a456-426614174000\n", {
          mode: 0o600,
        });
      } else if (drift === "image-owned artifact pin") {
        const pins = readJsonRecord(fixture.provision.imageTrustPinFile);
        pins.supervisorArtifactDigest = "f".repeat(64);
        writePrivateJson(fixture.provision.imageTrustPinFile, pins);
      } else if (drift === "bootstrap authority pin") {
        const pin = readJsonRecord(fixture.provision.authorityPinFile);
        pin.issuerKeyId = "different-bootstrap-authority";
        writePrivateJson(fixture.provision.authorityPinFile, pin);
      } else if (drift === "deployment signature") {
        const binding = readJsonRecord(fixture.provision.deploymentBindingFile);
        const authority = binding.authority as Record<string, unknown>;
        const signature = authority.signature as string;
        authority.signature = `${signature.startsWith("A") ? "B" : "A"}${signature.slice(1)}`;
        writePrivateJson(fixture.provision.deploymentBindingFile, binding, false);
      } else {
        const bytes = readFileSync(fixture.provision.deploymentBindingFile);
        try {
          writeFileSync(
            fixture.provision.deploymentBindingFile,
            Buffer.concat([bytes, Buffer.from("\n", "utf8")]),
            { mode: 0o600 }
          );
        } finally {
          bytes.fill(0);
        }
      }
      const envelope = fixture.envelope();
      expect(() => provisionDaytonaAssignmentBootstrap(envelope, fixture.provision)).toThrow(
        expect.objectContaining({ exitCode: 64 })
      );
      expect(envelope.every((byte) => byte === 0)).toBe(true);
    } finally {
      fixture.close();
    }
  });

  it("enforces initial authority time and recovers only the exact committed marker", () => {
    const fixture = bootstrapFixture();
    vi.stubEnv("DAYTONA_SANDBOX_ID", PROVIDER_ID);
    vi.stubEnv("DAYTONA_SANDBOX_USER", "terminalx");
    try {
      const expired = fixture.envelope(fixture.bootstrap, NOW, NOW + 1_000);
      expect(() =>
        provisionDaytonaAssignmentBootstrap(expired, {
          ...fixture.provision,
          clock: () => NOW + 1_000,
        })
      ).toThrow(expect.objectContaining({ exitCode: 64 }));
      expect(expired.every((byte) => byte === 0)).toBe(true);

      const initial = fixture.envelope();
      const replay = Buffer.from(initial);
      const tamperedReplay = Buffer.from(initial);
      const installed = provisionDaytonaAssignmentBootstrap(initial, fixture.provision);
      const marker = join(fixture.runtimeRoot, "assignment.installed.json");
      unlinkSync(marker);
      expect(provisionDaytonaAssignmentBootstrap(replay, fixture.provision)).toEqual(installed);
      expect(replay.every((byte) => byte === 0)).toBe(true);

      writePrivateJson(marker, { ...installed, planDigest: "f".repeat(64) });
      expect(() => provisionDaytonaAssignmentBootstrap(tamperedReplay, fixture.provision)).toThrow(
        expect.objectContaining({ exitCode: 73 })
      );
      expect(tamperedReplay.every((byte) => byte === 0)).toBe(true);
    } finally {
      fixture.close();
    }
  });

  it("accepts only fatal-UTF8 canonical bootstrap files with one trailing LF", () => {
    const fixture = bootstrapFixture();
    try {
      const canonical = canonicalRuntimeJson(fixture.bootstrap);
      expect(
        decodeDaytonaSupervisorBootstrapConfiguration(Buffer.from(`${canonical}\n`, "utf8"))
      ).toEqual(fixture.bootstrap);
      for (const bytes of [
        Buffer.from(canonical, "utf8"),
        Buffer.from(`${canonical}\n\n`, "utf8"),
        Buffer.from(`{ ${canonical.slice(1)}\n`, "utf8"),
        Buffer.from([0x7b, 0xff, 0x7d, 0x0a]),
      ]) {
        expect(() => decodeDaytonaSupervisorBootstrapConfiguration(bytes)).toThrow(TypeError);
      }
    } finally {
      fixture.close();
    }
  });

  it.each([
    "observation<key",
    "observation&key",
    "observation\u2028key",
    `observation-${"é".repeat(20)}`,
    `k${"a".repeat(128)}`,
  ])("rejects non-contract observation issuer key id %j", (issuerKeyId) => {
    const fixture = bootstrapFixture();
    try {
      expect(() =>
        fixture.envelope({
          ...fixture.bootstrap,
          assignment: {
            ...fixture.bootstrap.assignment,
            plan: {
              ...fixture.bootstrap.assignment.plan,
              observation: {
                ...fixture.bootstrap.assignment.plan.observation,
                issuerKeyId,
              },
            },
          },
        })
      ).toThrow(expect.objectContaining({ exitCode: 64 }));
    } finally {
      fixture.close();
    }
  });
});

function bootstrapFixture() {
  const root = mkdtempSync(join(tmpdir(), "terminalx-assignment-bootstrap-"));
  chmodSync(root, 0o700);
  const runtimeRoot = join(root, "run");
  const stateRoot = join(root, "state");
  const executableRoot = join(root, "libexec");
  mkdirSync(runtimeRoot, { mode: 0o700 });
  mkdirSync(stateRoot, { mode: 0o700 });
  mkdirSync(executableRoot, { mode: 0o700 });
  const peerCredentialExecutable = join(executableRoot, "terminalx-peercred");
  const effectExecutable = join(executableRoot, "terminalx-effect-enforcer");
  const nodeExecutable = join(executableRoot, "node");
  writeFileSync(peerCredentialExecutable, "peercred-v1\n", { mode: 0o555 });
  writeFileSync(effectExecutable, "effect-v1\n", { mode: 0o555 });
  writeFileSync(nodeExecutable, "node-v1\n", { mode: 0o555 });
  chmodSync(peerCredentialExecutable, 0o555);
  chmodSync(effectExecutable, 0o555);
  chmodSync(nodeExecutable, 0o555);
  const peerSha = sha256(readFileSync(peerCredentialExecutable));
  const effectSha = sha256(readFileSync(effectExecutable));
  const nodeSha = sha256(readFileSync(nodeExecutable));

  const observation = generateKeyPairSync("ed25519");
  const effectEnforcer = generateKeyPairSync("ed25519");
  const authority = generateKeyPairSync("ed25519");
  const isolation = generateKeyPairSync("ed25519");
  const observationPrivateDer = observation.privateKey.export({ type: "pkcs8", format: "der" });
  const observationPrivateBytes = Buffer.isBuffer(observationPrivateDer)
    ? observationPrivateDer
    : Buffer.from(observationPrivateDer);
  const observationPublicPem = String(
    observation.publicKey.export({ type: "spki", format: "pem" })
  );
  const authorityPublicPem = String(authority.publicKey.export({ type: "spki", format: "pem" }));
  const isolationPublicPem = String(isolation.publicKey.export({ type: "spki", format: "pem" }));
  const effectEnforcerPrivateDer = effectEnforcer.privateKey.export({
    type: "pkcs8",
    format: "der",
  });
  const effectEnforcerPrivateBytes = Buffer.isBuffer(effectEnforcerPrivateDer)
    ? effectEnforcerPrivateDer
    : Buffer.from(effectEnforcerPrivateDer);
  const effectEnforcerPublicPem = String(
    effectEnforcer.publicKey.export({ type: "spki", format: "pem" })
  );
  const effectEnforcerPublicDigest = sha256(
    effectEnforcer.publicKey.export({ type: "spki", format: "der" })
  );
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
  const plan = Object.freeze({
    binding,
    runtimeAuthorizationGeneration: 7,
    incarnation: "a".repeat(64),
    specificationDigest: "b".repeat(64),
    effectEnforcerPolicyDigest: "c".repeat(64),
    adapterConfigurationRef: "daytona-production-v1",
    observation: Object.freeze({
      keyProvisioningRef: "observation-provisioning-1",
      issuerKeyId: "observation-key-1",
      publicKeySpkiPem: observationPublicPem,
    }),
    isolation: Object.freeze({
      isolationPolicyDigest: "c".repeat(64),
      publicAccess: false as const,
      hostMounts: false as const,
      linkedSandbox: false as const,
      rootIdentity: false as const,
      network: Object.freeze({
        mode: "blocked" as const,
        policyDigest: "d".repeat(64),
        allowedDestinations: Object.freeze([]),
      }),
      resources: Object.freeze({ cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 256 }),
    }),
    capabilities: Object.freeze({
      isolatedExecution: true as const,
      brokeredCredentials: false as const,
      proxyOnlyEgress: false as const,
      checkpoints: false,
      yoloEligible: false as const,
    }),
  });
  const effectRecord = createDaytonaAssignmentEffectManifest({
    plan,
    providerSandboxId: PROVIDER_ID,
    providerRevision: 1,
    effectEnforcerIdentity: Object.freeze({
      enforcerRef: "runtime-enforcer-1",
      enforcerKeyId: "runtime-enforcer-key-1",
      publicKeySpkiPem: effectEnforcerPublicPem,
      publicKeySpkiDigest: effectEnforcerPublicDigest,
    }),
    authorityIssuerKeyId: "effect-manifest-authority-1",
    authoritySigningPrivateKey: authority.privateKey,
    validFromMs: 1,
    expiresAtMs: NOW + 24 * 60 * 60_000,
  });
  const effectManifest = effectRecord.manifest;
  const manifestDigest = effectRecord.activation.effectEnforcerSetDigest;
  const authorityPublicKeyDigest = sha256(
    authority.publicKey.export({ type: "spki", format: "der" })
  );
  const assignmentDirectory = join(runtimeRoot, "assignment");
  const bindingDigest = sha256(
    Buffer.from(`terminalx/daytona-bootstrap-binding/v1\0${canonicalRuntimeJson(binding)}`, "utf8")
  );
  const bootstrap: DaytonaSupervisorBootstrapConfiguration = Object.freeze({
    version: 1,
    kind: "terminalx.daytona-supervisor-bootstrap",
    assignment: Object.freeze({
      plan,
      providerSandboxId: PROVIDER_ID,
      expectedRevision: 1,
      artifactDigest: "1".repeat(64),
      sandboxUser: "terminalx",
      supervisorArtifactDigest: "2".repeat(64),
      effectEnforcerSetDigest: manifestDigest,
      maxOperations: 100,
    }),
    commandAuthority: Object.freeze({
      pinnedPublicKeys: Object.freeze([
        Object.freeze({
          issuer: "team-session" as const,
          issuerKeyId: "team-session-authority-1",
          publicKeyPem: authorityPublicPem,
        }),
      ]),
      maximumAuthorityTtlMs: 60_000,
    }),
    observation: Object.freeze({
      provisioningRecordFile: join(assignmentDirectory, "observation-provisioning.json"),
      observationTtlMs: 60_000,
    }),
    transport: Object.freeze({
      socketDirectory: runtimeRoot,
      socketPath: join(runtimeRoot, "supervisor.sock"),
      peerCredentialExecutableRoot: executableRoot,
      peerCredentialExecutableFile: peerCredentialExecutable,
      peerCredentialExecutableSha256: peerSha,
      authenticationTimeoutMs: 1_000,
      requestTimeoutMs: 5_000,
      maximumFrameBytes: 1024 * 1024,
      maximumInflightRequests: 32,
    }),
    state: Object.freeze({
      stateDirectory: join(stateRoot, bindingDigest),
      stateFileName: "supervisor-state.json",
      signingPrivateKeyFile: join(assignmentDirectory, "state-signing.pk8"),
      verificationPublicKeyFile: join(assignmentDirectory, "state-verification.pem"),
      maxStateBytes: 1024 * 1024,
    }),
    terminal: Object.freeze({
      requestTimeoutMs: 5_000,
      maximumLifetimeMs: 24 * 60 * 60_000,
      maximumTerminals: 16,
      maximumTerminalsPerSandbox: 8,
      maximumPendingOutputBytes: 1024 * 1024,
      maximumOutputFrameBytes: 64 * 1024,
      maximumPendingWebSocketBytes: 1024 * 1024,
    }),
    isolation: Object.freeze({
      attestationFile: join(runtimeRoot, "live", "isolation-attestation.json"),
      issuerKeyId: "isolation-key-1",
      issuerPublicKeySpkiPem: isolationPublicPem,
      hardenedDaytonaSourceCommit: "e".repeat(40),
      expectedSandboxImageId: `sha256:${"5".repeat(64)}`,
      expectedSandboxSnapshotRef: `registry.example/terminalx@sha256:${"6".repeat(64)}`,
      expectedSandboxUser: "terminalx",
      expectedSeccompProfileDigest: "7".repeat(64),
      expectedDockerVersion: "docker-29.1.3",
      expectedContainerdVersion: "containerd-2.2.1",
      expectedProviderRevision: 1,
      expectedSupervisorUid: 0,
      expectedDaytonaDaemonUid: 1000,
      expectedAgentUid: 1000,
      maximumAttestationTtlMs: 60_000,
    }),
    effect: Object.freeze({
      executableRoot,
      executableFile: effectExecutable,
      executableSha256: effectSha,
      timeoutMs: 5_000,
      maximumInputBytes: 1024 * 1024,
      maximumOutputBytes: 1024 * 1024,
      manifest: effectManifest,
      pinnedManifestAuthorityPublicKeys: Object.freeze([
        Object.freeze({
          issuerKeyId: effectManifest.authority.issuerKeyId,
          publicKeySpkiPem: authorityPublicPem,
          publicKeySpkiDigest: authorityPublicKeyDigest,
        }),
      ]),
    }),
  });

  const hostnameFile = join(root, "hostname");
  const authorityPinFile = join(root, "bootstrap-authority-pin.json");
  const imageTrustPinFile = join(root, "sandbox-trust-pins.json");
  const deploymentBindingFile = join(root, "deployment-binding.json");
  writeFileSync(hostnameFile, "terminalx-sandbox\n", { mode: 0o600 });
  chmodSync(hostnameFile, 0o600);
  writePrivateJson(authorityPinFile, {
    version: 1,
    kind: "terminalx.daytona-bootstrap-authority-pin",
    issuerKeyId: "platform-bootstrap-1",
    publicKeySpkiPem: authorityPublicPem,
  });
  writePrivateJson(imageTrustPinFile, {
    version: 1,
    kind: "terminalx.daytona-sandbox-trust-pins",
    supervisorArtifactDigest: bootstrap.assignment.supervisorArtifactDigest,
    peerCredentialExecutableSha256: peerSha,
    effectExecutableSha256: effectSha,
    nodeExecutableSha256: nodeSha,
    isolationIssuerKeyId: bootstrap.isolation.issuerKeyId,
    isolationIssuerPublicKeySpkiPem: isolationPublicPem,
    hardenedDaytonaSourceCommit: bootstrap.isolation.hardenedDaytonaSourceCommit,
    effectManifestAuthorityIssuerKeyId: effectManifest.authority.issuerKeyId,
    effectManifestAuthorityPublicKeySpkiPem: authorityPublicPem,
    deploymentBindingIssuerKeyId: "runner-deployment-key-1",
    deploymentBindingIssuerPublicKeySpkiPem: isolationPublicPem,
  });
  const deploymentClaims = {
    version: 1,
    kind: DAYTONA_SANDBOX_DEPLOYMENT_BINDING_KIND,
    providerSandboxId: PROVIDER_ID,
    providerRevision: 1,
    sandboxArtifactDigest: bootstrap.assignment.artifactDigest,
    expectedSandboxImageId: bootstrap.isolation.expectedSandboxImageId,
    expectedSandboxSnapshotRef: bootstrap.isolation.expectedSandboxSnapshotRef,
  } as const;
  const deploymentClaimsDigest = sha256(
    Buffer.from(
      `${DAYTONA_SANDBOX_DEPLOYMENT_BINDING_CLAIMS_DIGEST_DOMAIN}${canonicalRuntimeJson(deploymentClaims)}`,
      "utf8"
    )
  );
  const deploymentStatement = {
    version: 1,
    issuer: "daytona-runner",
    issuerKeyId: "runner-deployment-key-1",
    audience: "terminalx-assignment-bootstrap",
    capability: "sandbox.deployment.bind",
    claimsDigest: deploymentClaimsDigest,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 5 * 60_000,
  } as const;
  writePrivateJson(
    deploymentBindingFile,
    {
      ...deploymentClaims,
      authority: {
        issuer: deploymentStatement.issuer,
        issuerKeyId: deploymentStatement.issuerKeyId,
        audience: deploymentStatement.audience,
        capability: deploymentStatement.capability,
        claimsDigest: deploymentStatement.claimsDigest,
        issuedAtMs: deploymentStatement.issuedAtMs,
        expiresAtMs: deploymentStatement.expiresAtMs,
        signature: signEd25519(
          null,
          Buffer.from(
            `${DAYTONA_SANDBOX_DEPLOYMENT_BINDING_SIGNATURE_DOMAIN}${canonicalRuntimeJson(deploymentStatement)}`,
            "utf8"
          ),
          isolation.privateKey
        ).toString("base64url"),
      },
    },
    false
  );

  return {
    root,
    runtimeRoot,
    bootstrap,
    provision: {
      runtimeRoot,
      stateRoot,
      authorityPinFile,
      imageTrustPinFile,
      deploymentBindingFile,
      hostnameFile,
      expectedOwnerUid: uid,
      expectedPeerCredentialExecutable: peerCredentialExecutable,
      expectedEffectExecutable: effectExecutable,
      expectedNodeExecutable: nodeExecutable,
      expectedSupervisorSocket: bootstrap.transport.socketPath,
      clock: () => NOW,
    },
    envelope: (
      configuration: DaytonaSupervisorBootstrapConfiguration = bootstrap,
      issuedAtMs = NOW,
      expiresAtMs = NOW + 1_000
    ) =>
      createDaytonaAssignmentBootstrapEnvelope({
        bootstrap: configuration,
        observationPrivateKeyPkcs8Der: observationPrivateBytes,
        effectEnforcerPrivateKeyPkcs8Der: effectEnforcerPrivateBytes,
        authorityIssuerKeyId: "platform-bootstrap-1",
        authoritySigningPrivateKey: authority.privateKey,
        issuedAtMs,
        expiresAtMs,
      }),
    close() {
      observationPrivateBytes.fill(0);
      effectEnforcerPrivateBytes.fill(0);
      rmSync(root, { recursive: true, force: true });
    },
  };
}

function writePrivateJson(path: string, value: unknown, trailingNewline = true): void {
  writeFileSync(path, `${canonicalRuntimeJson(value)}${trailingNewline ? "\n" : ""}`, {
    mode: 0o600,
  });
  chmodSync(path, 0o600);
}

function readJsonRecord(path: string): Record<string, unknown> {
  return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

interface MutableEnvelopeHeader {
  sections: [{ sha256: string }, { sha256: string }];
  authority: { signature: string };
  [key: string]: unknown;
}

function rewriteEnvelopeCanonicalHeader(
  envelope: Buffer,
  mutate: (header: MutableEnvelopeHeader) => void
): Buffer {
  const headerLength = envelope.readUInt32BE(0);
  const header = JSON.parse(
    envelope.subarray(4, 4 + headerLength).toString("utf8")
  ) as MutableEnvelopeHeader;
  mutate(header);
  return rewriteEnvelopeHeader(envelope, () => Buffer.from(canonicalRuntimeJson(header), "utf8"));
}

function rewriteEnvelopeHeader(envelope: Buffer, rewrite: (header: Buffer) => Buffer): Buffer {
  const headerLength = envelope.readUInt32BE(0);
  const originalHeader = Buffer.from(envelope.subarray(4, 4 + headerLength));
  const sections = Buffer.from(envelope.subarray(4 + headerLength));
  let rewritten: Buffer | undefined;
  try {
    rewritten = rewrite(originalHeader);
    const result = Buffer.allocUnsafe(4 + rewritten.byteLength + sections.byteLength);
    result.writeUInt32BE(rewritten.byteLength, 0);
    rewritten.copy(result, 4);
    sections.copy(result, 4 + rewritten.byteLength);
    return result;
  } finally {
    envelope.fill(0);
    originalHeader.fill(0);
    sections.fill(0);
    rewritten?.fill(0);
  }
}

function sha256(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
