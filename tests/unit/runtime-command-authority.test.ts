import { generateKeyPairSync, createHash } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, expectTypeOf, it } from "vitest";
import type { RuntimeCommand, RuntimeAuthorityVerifier as ExecutionVerifier } from "@/lib/runtime";
import {
  RuntimeCommandAuthorityError,
  createRuntimeCommandAuthorityIssuer,
  createRuntimeCommandAuthorityVerifier,
  type RuntimeCommandAuthorityVerifier,
  type RuntimeCommandClaims,
} from "@/lib/runtime/runtime-command-authority";
import {
  RUNTIME_COMMAND_CLAIMS_DIGEST_DOMAIN,
  RuntimeCommandCanonicalError,
  canonicalRuntimeCommandClaims,
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "@/lib/runtime/runtime-command-canonical";

const binding = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 2,
  sandboxId: "sandbox-1",
  sandboxGeneration: 3,
  runtimePrincipalId: "principal-1",
} as const;

const pauseClaims = {
  kind: "run.pause",
  commandId: "command-1",
  binding,
  projectCeilingRevision: "ceiling-1",
  runtimeAuthorizationGeneration: 4,
  requiredEffectEnforcerSetDigest: "b".repeat(64),
  causationId: "event-1",
  actor: { kind: "human", actorRef: "user-1" },
  issuedAtMs: 100,
  deadlineAtMs: 1_000,
  agentRunId: "run-1",
  runPolicyRevision: 1,
  fromRunStateVersion: 6,
  toRunStateVersion: 7,
  reason: "human",
} as const satisfies RuntimeCommandClaims<"run.pause">;

const quarantineClaims = {
  kind: "safety.quarantine",
  commandId: "quarantine-command-1",
  compensationId: "compensation-1",
  binding,
  observedRuntimeAuthorizationGeneration: 4,
  causationId: "lifecycle-command-1",
  actor: { kind: "system", actorRef: "platform-security" },
  issuedAtMs: 100,
  deadlineAtMs: 1_000,
  source: {
    lifecycleCommandId: "lifecycle-command-1",
    lifecycleCommandClaimsDigest: "b".repeat(64),
    lifecycleReceiptDigest: "c".repeat(64),
    lifecycleEnforcementSubjectDigest: "d".repeat(64),
    lifecycleAggregateProofDigest: "e".repeat(64),
    sourceRequiredEffectEnforcerSetDigest: "f".repeat(64),
  },
  platformSecurityPolicyRevision: "platform-security-policy:v1",
  requiredContainmentEnforcerSetDigest: "1".repeat(64),
  containment: {
    revokeTerminalWrites: true,
    stopProcessExecution: true,
    quarantineRuntime: true,
  },
  safetyFence: 8,
  advanceBeyondCurrentFences: true,
  exactBindingOnly: true,
  reasonRef: "compensation-incident:1",
} as const satisfies RuntimeCommandClaims<"safety.quarantine">;

describe("Runtime command canonical claims", () => {
  it("sorts every record, omits only top-level authority, and uses a digest domain", () => {
    const reordered = {
      reason: pauseClaims.reason,
      toRunStateVersion: pauseClaims.toRunStateVersion,
      fromRunStateVersion: pauseClaims.fromRunStateVersion,
      runPolicyRevision: pauseClaims.runPolicyRevision,
      agentRunId: pauseClaims.agentRunId,
      deadlineAtMs: pauseClaims.deadlineAtMs,
      issuedAtMs: pauseClaims.issuedAtMs,
      actor: { actorRef: "user-1", kind: "human" },
      causationId: pauseClaims.causationId,
      requiredEffectEnforcerSetDigest: pauseClaims.requiredEffectEnforcerSetDigest,
      runtimeAuthorizationGeneration: pauseClaims.runtimeAuthorizationGeneration,
      projectCeilingRevision: pauseClaims.projectCeilingRevision,
      binding: {
        runtimePrincipalId: binding.runtimePrincipalId,
        sandboxGeneration: binding.sandboxGeneration,
        sandboxId: binding.sandboxId,
        runtimeAssignmentGeneration: binding.runtimeAssignmentGeneration,
        runtimeAssignmentId: binding.runtimeAssignmentId,
        sessionId: binding.sessionId,
        projectId: binding.projectId,
        teamId: binding.teamId,
      },
      commandId: pauseClaims.commandId,
      kind: pauseClaims.kind,
    };
    const withAuthority = { ...pauseClaims, authority: { ignored: true } };

    expect(canonicalRuntimeCommandClaims(reordered)).toBe(
      canonicalRuntimeCommandClaims(pauseClaims)
    );
    expect(digestRuntimeCommandClaims(reordered)).toBe(digestRuntimeCommandClaims(pauseClaims));
    expect(digestRuntimeCommandClaims(withAuthority)).toBe(digestRuntimeCommandClaims(pauseClaims));
    const rawJsonDigest = createHash("sha256")
      .update(canonicalRuntimeCommandClaims(pauseClaims), "utf8")
      .digest("hex");
    expect(digestRuntimeCommandClaims(pauseClaims)).not.toBe(rawJsonDigest);
    expect(RUNTIME_COMMAND_CLAIMS_DIGEST_DOMAIN.endsWith("\0")).toBe(true);
  });

  it("canonically tags bytes without colliding with a caller-owned record", () => {
    expect(canonicalRuntimeJson(new Uint8Array([0, 127, 255]))).toBe(
      '{"$terminalx.runtime.bytes.v1":"AH__"}'
    );
    expect(() => canonicalRuntimeJson({ "$terminalx.runtime.bytes.v1": "AH__" })).toThrow(
      RuntimeCommandCanonicalError
    );
  });

  it("rejects lone UTF-16 surrogates in values and object keys but permits valid pairs", () => {
    for (const value of ["\ud800", "\udbff", "\udc00", "\udfff", `left\ud800right`]) {
      expect(() => canonicalRuntimeJson(value)).toThrow(RuntimeCommandCanonicalError);
      expect(() => canonicalRuntimeJson({ [value]: true })).toThrow(RuntimeCommandCanonicalError);
    }
    expect(
      canonicalRuntimeJson({ "astral-\ud83d\ude80": "\ud83d\ude80", separator: "\u2028\u2029" })
    ).toBe('{"astral-🚀":"🚀","separator":"  "}');
  });

  it("rejects cycles, accessors, non-finite numbers, negative zero, and unsupported values safely", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    let getterInvoked = false;
    const accessor = {};
    Object.defineProperty(accessor, "secret", {
      enumerable: true,
      get() {
        getterInvoked = true;
        return "private-key-material";
      },
    });

    for (const value of [cyclic, accessor, Number.NaN, Number.POSITIVE_INFINITY, -0, BigInt(1)]) {
      expect(() => canonicalRuntimeJson(value)).toThrow(RuntimeCommandCanonicalError);
    }
    expect(getterInvoked).toBe(false);
    try {
      canonicalRuntimeJson(accessor);
    } catch (error) {
      expect(String(error)).not.toContain("private-key-material");
    }
  });
});

describe("Ed25519 Runtime command authority", () => {
  let directory: string;
  let privateKeyFile: string;
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "terminalx-runtime-authority-"));
    const pair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    privateKeyPem = pair.privateKey;
    publicKeyPem = pair.publicKey;
    privateKeyFile = join(directory, "runtime-authority.pem");
    writeFileSync(privateKeyFile, privateKeyPem, { mode: 0o600 });
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  function issuer() {
    return createRuntimeCommandAuthorityIssuer({
      issuer: "team-session",
      issuerKeyId: "team-session:v1",
      trustedConfigurationRoot: directory,
      privateKeyFile,
      clock: () => 100,
      authorityTtlMs: 300,
    });
  }

  function verifier(pem = publicKeyPem): RuntimeCommandAuthorityVerifier {
    return createRuntimeCommandAuthorityVerifier({
      pinnedPublicKeys: [
        {
          issuer: "team-session",
          issuerKeyId: "team-session:v1",
          publicKeyPem: pem,
        },
      ],
    });
  }

  function signedCommand(): Extract<RuntimeCommand, { kind: "run.pause" }> {
    return { ...pauseClaims, authority: issuer().issue(pauseClaims) };
  }

  it("issues a frozen deterministic envelope and verifies every signed claim", () => {
    const first = issuer().issue(pauseClaims);
    const second = issuer().issue(pauseClaims);
    const command = { ...pauseClaims, authority: first };

    expect(Object.isFrozen(first)).toBe(true);
    expect(first).toMatchObject({
      issuer: "team-session",
      issuerKeyId: "team-session:v1",
      audience: "runtime",
      capability: "run.pause",
      issuedAtMs: 100,
      expiresAtMs: 400,
      claimsDigest: digestRuntimeCommandClaims(pauseClaims),
    });
    expect(first.signature).toBe(second.signature);
    expect(verifier()({ command, nowMs: 100 })).toBe(true);
    expect(verifier()({ command, nowMs: 399 })).toBe(true);
    expect(verifier()({ command, nowMs: 400 })).toBe(false);
    expectTypeOf(verifier()).toMatchTypeOf<ExecutionVerifier>();
  });

  it("reserves safety quarantine authority for the platform-security issuer", () => {
    expect(() => issuer().issue(quarantineClaims)).toThrow(
      expect.objectContaining({ code: "invalid_command" })
    );

    const platformPair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const platformPrivateKeyFile = join(directory, "platform-security-authority.pem");
    writeFileSync(platformPrivateKeyFile, platformPair.privateKey, { mode: 0o600 });
    const platformIssuer = createRuntimeCommandAuthorityIssuer({
      issuer: "platform-security",
      issuerKeyId: "platform-security:v1",
      trustedConfigurationRoot: directory,
      privateKeyFile: platformPrivateKeyFile,
      clock: () => 100,
      authorityTtlMs: 300,
    });
    const command = {
      ...quarantineClaims,
      authority: platformIssuer.issue(quarantineClaims),
    };
    const platformVerifier = createRuntimeCommandAuthorityVerifier({
      pinnedPublicKeys: [
        {
          issuer: "platform-security",
          issuerKeyId: "platform-security:v1",
          publicKeyPem: platformPair.publicKey,
        },
      ],
    });

    expect(command.authority.issuer).toBe("platform-security");
    expect(platformVerifier({ command, nowMs: 200 })).toBe(true);
    expect(
      platformVerifier({
        command: {
          ...command,
          source: {
            ...command.source,
            lifecycleReceiptDigest: "0".repeat(64),
          },
        },
        nowMs: 200,
      })
    ).toBe(false);
  });

  it("rejects Ed25519 key reuse across Team Session and platform-security trust domains", () => {
    expect(() =>
      createRuntimeCommandAuthorityVerifier({
        pinnedPublicKeys: [
          {
            issuer: "team-session",
            issuerKeyId: "team-session:v1",
            publicKeyPem,
          },
          {
            issuer: "platform-security",
            issuerKeyId: "platform-security:v1",
            publicKeyPem,
          },
        ],
      })
    ).toThrow(expect.objectContaining({ code: "invalid_public_key" }));
  });

  it("rejects claim, capability, audience, issuer, key-id, time, digest, and signature tampering", () => {
    const command = signedCommand();
    const authority = command.authority;
    const attempts = [
      { ...command, reason: "safety" },
      { ...command, requiredEffectEnforcerSetDigest: "c".repeat(64) },
      { ...command, authority: { ...authority, capability: "run.stop" } },
      { ...command, authority: { ...authority, audience: "other" as "runtime" } },
      {
        ...command,
        authority: { ...authority, issuer: "platform-security" },
      },
      { ...command, authority: { ...authority, issuerKeyId: "team-session:v2" } },
      { ...command, authority: { ...authority, issuedAtMs: 99 } },
      { ...command, authority: { ...authority, expiresAtMs: 900 } },
      { ...command, authority: { ...authority, claimsDigest: "0".repeat(64) } },
      {
        ...command,
        authority: {
          ...authority,
          signature: `${authority.signature.slice(0, -1)}${
            authority.signature.endsWith("A") ? "B" : "A"
          }`,
        },
      },
    ] as unknown as RuntimeCommand[];

    for (const attempt of attempts) {
      expect(verifier()({ command: attempt, nowMs: 200 })).toBe(false);
    }
  });

  it("fails closed without invoking hostile getters or exposing their values", () => {
    let invoked = false;
    const hostile = { ...signedCommand() } as Record<string, unknown>;
    Object.defineProperty(hostile, "reason", {
      enumerable: true,
      get() {
        invoked = true;
        return "secret-private-key";
      },
    });

    expect(verifier()({ command: hostile as unknown as RuntimeCommand, nowMs: 200 })).toBe(false);
    expect(invoked).toBe(false);
  });

  it("loads private keys only from an absolute, owned, non-symlink 0400/0600 file", () => {
    const relative = () =>
      createRuntimeCommandAuthorityIssuer({
        issuer: "team-session",
        issuerKeyId: "team-session:v1",
        trustedConfigurationRoot: directory,
        privateKeyFile: "relative-key.pem",
      });
    expect(relative).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));

    chmodSync(privateKeyFile, 0o644);
    expect(() =>
      createRuntimeCommandAuthorityIssuer({
        issuer: "team-session",
        issuerKeyId: "team-session:v1",
        trustedConfigurationRoot: directory,
        privateKeyFile,
      })
    ).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));

    chmodSync(privateKeyFile, 0o600);
    const link = join(directory, "runtime-authority-link.pem");
    symlinkSync(privateKeyFile, link);
    expect(() =>
      createRuntimeCommandAuthorityIssuer({
        issuer: "team-session",
        issuerKeyId: "team-session:v1",
        trustedConfigurationRoot: directory,
        privateKeyFile: link,
      })
    ).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));
  });

  it("rejects non-Ed25519 private keys and private or non-Ed25519 verifier pins", () => {
    const rsa = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const rsaFile = join(directory, "rsa-private.pem");
    writeFileSync(rsaFile, rsa.privateKey, { mode: 0o600 });
    expect(() =>
      createRuntimeCommandAuthorityIssuer({
        issuer: "team-session",
        issuerKeyId: "team-session:v1",
        trustedConfigurationRoot: directory,
        privateKeyFile: rsaFile,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_private_key" }));

    for (const publicKey of [privateKeyPem, rsa.publicKey]) {
      expect(() =>
        createRuntimeCommandAuthorityVerifier({
          pinnedPublicKeys: [
            {
              issuer: "team-session",
              issuerKeyId: "team-session:v1",
              publicKeyPem: publicKey,
            },
          ],
        })
      ).toThrow(expect.objectContaining({ code: "invalid_public_key" }));
    }
  });

  it("keeps all configuration and crypto errors free of paths and key material", () => {
    chmodSync(privateKeyFile, 0o644);
    try {
      createRuntimeCommandAuthorityIssuer({
        issuer: "team-session",
        issuerKeyId: "team-session:v1",
        trustedConfigurationRoot: directory,
        privateKeyFile,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(RuntimeCommandAuthorityError);
      const serialized = String(error);
      expect(serialized).not.toContain(privateKeyFile);
      expect(serialized).not.toContain("PRIVATE KEY");
      expect(serialized).not.toContain(privateKeyPem.slice(40, 80));
    }
  });
});
