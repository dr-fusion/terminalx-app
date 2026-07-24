import { generateKeyPairSync, sign as signEd25519 } from "node:crypto";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RuntimeBinding } from "@/lib/team-sessions/contracts";
import type {
  NonDuplicateRuntimeCompensationReceipt,
  RuntimeCompensationCommand,
  RuntimeCompensationReceipt,
} from "@/lib/runtime/contracts";
import {
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "@/lib/runtime/runtime-command-canonical";
import {
  RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN,
  RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN,
  RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN,
  RuntimeCompensationReceiptObservationError,
  createRuntimeCompensationReceiptObservationIssuer,
  createRuntimeCompensationReceiptObservationVerifier,
  digestRuntimeCompensationReceiptForObservation,
  isVerifiedRuntimeCompensationReceiptObservation,
  type RuntimeCompensationReceiptObservation,
  type RuntimeCompensationReceiptObservationCheckpoint,
} from "@/lib/runtime/runtime-compensation-receipt-observation";
import { digestNonDuplicateRuntimeCompensationReceipt } from "@/lib/runtime/runtime-compensation-execution";
import { digestAggregateEnforcementProof } from "@/lib/runtime/runtime-enforcement-proof";
import {
  TrustedConfigurationFileError,
  readTrustedConfigurationFileWithRaceHookForTest,
} from "@/lib/runtime/runtime-trusted-configuration-file";
import {
  RUNTIME_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN,
  RUNTIME_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN,
  RUNTIME_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN,
} from "@/lib/runtime/runtime-receipt-observation";

const binding = {
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 3,
  sandboxId: "sandbox-1",
  sandboxGeneration: 4,
  runtimePrincipalId: "principal-1",
} as const;

describe("signed Runtime compensation receipt observations", () => {
  let directory: string;
  let privateKeyFile: string;
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "terminalx-compensation-observation-"));
    const pair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    privateKeyPem = pair.privateKey;
    publicKeyPem = pair.publicKey;
    privateKeyFile = join(directory, "compensation-observer-private.pem");
    writeFileSync(privateKeyFile, privateKeyPem, { mode: 0o600 });
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  function issuer(clock = () => 1_000, issuerBinding: RuntimeBinding = binding) {
    return createRuntimeCompensationReceiptObservationIssuer({
      issuerKeyId: "daytona-compensation-observer:v1",
      binding: issuerBinding,
      trustedConfigurationRoot: directory,
      privateKeyFile,
      clock,
      observationTtlMs: 500,
    });
  }

  function verifier(pem = publicKeyPem, pinBinding: RuntimeBinding = binding) {
    return createRuntimeCompensationReceiptObservationVerifier({
      pinnedPublicKeys: [
        {
          issuerKeyId: "daytona-compensation-observer:v1",
          binding: pinBinding,
          publicKeyPem: pem,
        },
      ],
      maximumObservationTtlMs: 1_000,
    });
  }

  function issue(
    previous: RuntimeCompensationReceiptObservationCheckpoint | null = null,
    overrides: Partial<{
      observationId: string;
      cursor: string;
      command: RuntimeCompensationCommand;
      receipt: RuntimeCompensationReceipt;
    }> = {}
  ): RuntimeCompensationReceiptObservation {
    const command = overrides.command ?? compensationCommand();
    return issuer().issue({
      observationId: overrides.observationId ?? "compensation-observation-1",
      cursor: overrides.cursor ?? "compensation-cursor-1",
      previous,
      command,
      receipt: overrides.receipt ?? acceptedReceipt(command),
    });
  }

  it("issues and verifies an exact-bound, signed, privately branded observation", () => {
    const command = compensationCommand();
    const receipt = acceptedReceipt(command);
    const observation = issue(null, { command, receipt });
    const verified = verifier().verify({
      observation,
      command,
      expectedPrevious: null,
      nowMs: 1_200,
    });

    expect(observation).toMatchObject({
      version: 1,
      kind: "runtime.compensation-receipt-observed",
      observationId: "compensation-observation-1",
      cursor: "compensation-cursor-1",
      previous: null,
      observedAtMs: 1_000,
      command: {
        kind: "safety.quarantine",
        commandId: command.commandId,
        compensationId: command.compensationId,
        claimsDigest: command.authority.claimsDigest,
        binding,
        observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
        safetyFence: command.safetyFence,
        source: command.source,
        requiredContainmentEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
      },
      receipt,
      receiptDigest: digestRuntimeCompensationReceiptForObservation(receipt, command),
      authority: {
        issuer: "runtime",
        issuerKeyId: "daytona-compensation-observer:v1",
        audience: "terminalx-control-plane",
        capability: "runtime.compensation-receipt.observe",
        issuedAtMs: 1_000,
        expiresAtMs: 1_500,
      },
    });
    expect(verified.observationDigest).toBe(observation.authority.claimsDigest);
    expect(Object.keys(verified)).not.toContain("observationDigest");
    expect(Object.isFrozen(verified)).toBe(true);
    expect(Object.isFrozen(verified.command)).toBe(true);
    expect(Object.isFrozen(verified.command.binding)).toBe(true);
    expect(Object.isFrozen(verified.command.source)).toBe(true);
    expect(Object.isFrozen(verified.receipt)).toBe(true);
    expect(Object.isFrozen(verified.authority)).toBe(true);
    expect(isVerifiedRuntimeCompensationReceiptObservation(verified)).toBe(true);
    expect(isVerifiedRuntimeCompensationReceiptObservation(Object.freeze({ ...observation }))).toBe(
      false
    );
    expect(
      isVerifiedRuntimeCompensationReceiptObservation(
        new Proxy(
          {},
          {
            getOwnPropertyDescriptor() {
              throw new Error("hostile brand trap");
            },
          }
        )
      )
    ).toBe(false);
  });

  it("requires the exact predecessor and rejects cursor replay", () => {
    const command = compensationCommand();
    const firstObservation = issue(null, { command });
    const first = verifier().verify({
      observation: firstObservation,
      command,
      expectedPrevious: null,
      nowMs: 1_100,
    });
    const checkpoint = {
      cursor: first.cursor,
      observationDigest: first.observationDigest,
    } as const;
    const second = issue(checkpoint, {
      observationId: "compensation-observation-2",
      cursor: "compensation-cursor-2",
      command,
    });

    expect(
      verifier().verify({
        observation: second,
        command,
        expectedPrevious: checkpoint,
        nowMs: 1_100,
      }).cursor
    ).toBe("compensation-cursor-2");
    for (const expectedPrevious of [
      null,
      { ...checkpoint, cursor: "other-cursor" },
      { ...checkpoint, observationDigest: "0".repeat(64) },
    ]) {
      expect(() =>
        verifier().verify({ observation: second, command, expectedPrevious, nowMs: 1_100 })
      ).toThrow(expect.objectContaining({ code: "chain_mismatch" }));
    }
    expect(() =>
      verifier().verify({
        observation: firstObservation,
        command,
        expectedPrevious: checkpoint,
        nowMs: 1_100,
      })
    ).toThrow(expect.objectContaining({ code: "chain_mismatch" }));
    expect(() =>
      issuer().issue({
        observationId: "compensation-observation-loop",
        cursor: checkpoint.cursor,
        previous: checkpoint,
        command,
        receipt: acceptedReceipt(command),
      })
    ).toThrow(expect.objectContaining({ code: "invalid_input" }));
  });

  it("rejects every command, binding, generation, fence, source, and enforcer substitution", () => {
    const command = compensationCommand();
    const observation = issue(null, { command });
    const sourceMutations = [
      { lifecycleCommandClaimsDigest: "1".repeat(64) },
      { lifecycleReceiptDigest: "2".repeat(64) },
      { lifecycleEnforcementSubjectDigest: "3".repeat(64) },
      { lifecycleAggregateProofDigest: "4".repeat(64) },
      { sourceRequiredEffectEnforcerSetDigest: "5".repeat(64) },
    ];
    const bindingMutations: RuntimeBinding[] = [
      { ...binding, teamId: "team-other" },
      { ...binding, projectId: "project-other" },
      { ...binding, sessionId: "session-other" },
      { ...binding, runtimeAssignmentId: "assignment-other" },
      {
        ...binding,
        runtimeAssignmentGeneration: binding.runtimeAssignmentGeneration + 1,
      },
      { ...binding, sandboxId: "sandbox-other" },
      { ...binding, sandboxGeneration: binding.sandboxGeneration + 1 },
      { ...binding, runtimePrincipalId: "principal-other" },
    ];
    const mutations: RuntimeCompensationCommand[] = [
      compensationCommand({ commandId: "quarantine-command-other" }),
      compensationCommand({ compensationId: "compensation-other" }),
      ...bindingMutations.map((mutatedBinding) => compensationCommand({ binding: mutatedBinding })),
      compensationCommand({ observedRuntimeAuthorizationGeneration: 8 }),
      compensationCommand({ safetyFence: command.safetyFence + 1 }),
      compensationCommand({ requiredContainmentEnforcerSetDigest: "6".repeat(64) }),
      compensationCommand({
        source: { ...command.source, lifecycleCommandId: "lifecycle-command-other" },
        causationId: "lifecycle-command-other",
      }),
      ...sourceMutations.map((mutation) =>
        compensationCommand({ source: { ...command.source, ...mutation } })
      ),
    ];

    for (const expectedCommand of mutations) {
      expect(() =>
        verifier().verify({
          observation,
          command: expectedCommand,
          expectedPrevious: null,
          nowMs: 1_100,
        })
      ).toThrow(expect.objectContaining({ code: "command_mismatch" }));
    }
  });

  it("rejects receipt identity, binding, generation, digest, and duplicate mutations", () => {
    const command = compensationCommand();
    const receipt = acceptedReceipt(command);
    const invalidReceipts: RuntimeCompensationReceipt[] = [
      { ...receipt, compensationId: "compensation-other" },
      { ...receipt, commandId: "quarantine-command-other" },
      { ...receipt, binding: { ...binding, sandboxId: "sandbox-other" } },
      { ...receipt, observedRuntimeAuthorizationGeneration: 8 },
    ];
    for (const invalidReceipt of invalidReceipts) {
      expect(() =>
        issuer().issue({
          observationId: "invalid-receipt-observation",
          cursor: "invalid-receipt-cursor",
          previous: null,
          command,
          receipt: invalidReceipt,
        })
      ).toThrow(expect.objectContaining({ code: "invalid_receipt" }));
    }
    const enforced = enforcedReceipt(command);
    expect(
      verifier().verify({
        observation: issue(null, { command, receipt: enforced }),
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      }).receipt
    ).toEqual(enforced);
    expect(() =>
      issue(null, {
        command,
        receipt: { ...enforced, enforcedSafetyFence: command.safetyFence - 1 },
      })
    ).toThrow(expect.objectContaining({ code: "invalid_receipt" }));

    const observation = issue(null, { command, receipt });
    for (const candidate of [
      { ...observation, receipt: { ...receipt, effectRef: "substituted-effect" } },
      { ...observation, receiptDigest: "0".repeat(64) },
    ]) {
      expect(() =>
        verifier().verify({
          observation: candidate,
          command,
          expectedPrevious: null,
          nowMs: 1_100,
        })
      ).toThrow(RuntimeCompensationReceiptObservationError);
    }

    const duplicate = {
      receiptKind: "runtime.compensation",
      compensationId: command.compensationId,
      commandId: command.commandId,
      binding: command.binding,
      observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt: receipt,
      originalReceiptDigest: digestNonDuplicateRuntimeCompensationReceipt(receipt),
    } as const satisfies RuntimeCompensationReceipt;
    expect(
      verifier().verify({
        observation: issue(null, { command, receipt: duplicate }),
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      }).receipt
    ).toEqual(duplicate);
    expect(() =>
      issue(null, {
        command,
        receipt: { ...duplicate, originalReceiptDigest: "0".repeat(64) },
      })
    ).toThrow(expect.objectContaining({ code: "invalid_receipt" }));
  });

  it("rejects wrong binding pins, unknown issuers, wrong keys, and expired envelopes", () => {
    const command = compensationCommand();
    const observation = issue(null, { command });
    expect(() =>
      verifier(publicKeyPem, { ...binding, runtimeAssignmentId: "assignment-other" }).verify({
        observation,
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      })
    ).toThrow(expect.objectContaining({ code: "untrusted_issuer" }));
    expect(() =>
      issuer(() => 1_000, { ...binding, runtimeAssignmentId: "assignment-other" }).issue({
        observationId: "wrong-issuer-binding",
        cursor: "wrong-issuer-binding-cursor",
        previous: null,
        command,
        receipt: acceptedReceipt(command),
      })
    ).toThrow(expect.objectContaining({ code: "invalid_command" }));

    const unknownIssuer = {
      ...observation,
      authority: { ...observation.authority, issuerKeyId: "unknown-observer:v1" },
    };
    expect(() =>
      verifier().verify({
        observation: unknownIssuer,
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      })
    ).toThrow(expect.objectContaining({ code: "untrusted_issuer" }));

    const otherPair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    expect(() =>
      verifier(otherPair.publicKey).verify({
        observation,
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_signature" }));
    for (const nowMs of [999, observation.authority.expiresAtMs]) {
      expect(() =>
        verifier().verify({ observation, command, expectedPrevious: null, nowMs })
      ).toThrow(expect.objectContaining({ code: "expired" }));
    }
  });

  it("never invokes accessors or leaks hostile proxy failures", () => {
    const command = compensationCommand();
    let commandGetterInvoked = false;
    const hostileCommand = { ...command } as Record<string, unknown>;
    Object.defineProperty(hostileCommand, "commandId", {
      enumerable: true,
      get() {
        commandGetterInvoked = true;
        return "secret-command";
      },
    });
    expect(() =>
      issuer().issue({
        observationId: "hostile-command-observation",
        cursor: "hostile-command-cursor",
        previous: null,
        command: hostileCommand as unknown as RuntimeCompensationCommand,
        receipt: acceptedReceipt(command),
      })
    ).toThrow(expect.objectContaining({ code: "invalid_command" }));
    expect(commandGetterInvoked).toBe(false);

    let receiptGetterInvoked = false;
    const hostileReceipt = { ...acceptedReceipt(command) } as Record<string, unknown>;
    Object.defineProperty(hostileReceipt, "effectRef", {
      enumerable: true,
      get() {
        receiptGetterInvoked = true;
        return "secret-effect";
      },
    });
    expect(() =>
      issuer().issue({
        observationId: "hostile-receipt-observation",
        cursor: "hostile-receipt-cursor",
        previous: null,
        command,
        receipt: hostileReceipt as unknown as RuntimeCompensationReceipt,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_receipt" }));
    expect(receiptGetterInvoked).toBe(false);

    const observation = issue(null, { command });
    let observationGetterInvoked = false;
    const hostileObservation = { ...observation } as Record<string, unknown>;
    Object.defineProperty(hostileObservation, "receipt", {
      enumerable: true,
      get() {
        observationGetterInvoked = true;
        return "secret-provider-receipt";
      },
    });
    expect(() =>
      verifier().verify({
        observation: hostileObservation,
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_observation" }));
    expect(observationGetterInvoked).toBe(false);

    const hostileProxy = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error("secret proxy failure");
        },
      }
    );
    for (const run of [
      () => issuer().issue(hostileProxy as never),
      () =>
        verifier().verify({
          observation: hostileProxy,
          command,
          expectedPrevious: null,
          nowMs: 1_100,
        }),
    ]) {
      try {
        run();
        throw new Error("Expected hostile input rejection");
      } catch (error) {
        expect(error).toBeInstanceOf(RuntimeCompensationReceiptObservationError);
        expect(String(error)).not.toContain("secret proxy failure");
      }
    }
  });

  it("loads only strict Ed25519 private files and binding-scoped SPKI public keys", () => {
    chmodSync(privateKeyFile, 0o644);
    expect(() => issuer()).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));
    chmodSync(privateKeyFile, 0o600);

    const link = join(directory, "compensation-observer-link.pem");
    symlinkSync(privateKeyFile, link);
    expect(() =>
      createRuntimeCompensationReceiptObservationIssuer({
        issuerKeyId: "daytona-compensation-observer:v1",
        binding,
        trustedConfigurationRoot: directory,
        privateKeyFile: link,
      })
    ).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));

    const nonCanonicalPath = `${directory}/../${basename(directory)}/${basename(privateKeyFile)}`;
    expect(() =>
      createRuntimeCompensationReceiptObservationIssuer({
        issuerKeyId: "daytona-compensation-observer:v1",
        binding,
        trustedConfigurationRoot: directory,
        privateKeyFile: nonCanonicalPath,
      })
    ).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));

    const outsideRoot = `${directory}-outside`;
    mkdirSync(outsideRoot, { mode: 0o700 });
    const outsideKey = join(outsideRoot, "private.pem");
    writeFileSync(outsideKey, privateKeyPem, { mode: 0o600 });
    expect(() =>
      createRuntimeCompensationReceiptObservationIssuer({
        issuerKeyId: "daytona-compensation-observer:v1",
        binding,
        trustedConfigurationRoot: directory,
        privateKeyFile: outsideKey,
      })
    ).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));
    rmSync(outsideRoot, { recursive: true, force: true });

    const realParent = join(directory, "real-parent");
    mkdirSync(realParent, { mode: 0o700 });
    const nestedKey = join(realParent, "private.pem");
    writeFileSync(nestedKey, privateKeyPem, { mode: 0o600 });
    const linkedParent = join(directory, "linked-parent");
    symlinkSync(realParent, linkedParent);
    expect(() =>
      createRuntimeCompensationReceiptObservationIssuer({
        issuerKeyId: "daytona-compensation-observer:v1",
        binding,
        trustedConfigurationRoot: directory,
        privateKeyFile: join(linkedParent, "private.pem"),
      })
    ).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));

    chmodSync(directory, 0o770);
    expect(() => issuer()).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));
    chmodSync(directory, 0o700);

    const hardLink = join(directory, "compensation-observer-hard-link.pem");
    linkSync(privateKeyFile, hardLink);
    expect(() => issuer()).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));
    rmSync(hardLink);

    const rsa = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const rsaFile = join(directory, "rsa-private.pem");
    writeFileSync(rsaFile, rsa.privateKey, { mode: 0o600 });
    expect(() =>
      createRuntimeCompensationReceiptObservationIssuer({
        issuerKeyId: "daytona-compensation-observer:v1",
        binding,
        trustedConfigurationRoot: directory,
        privateKeyFile: rsaFile,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_private_key" }));
    for (const invalidPublicKey of [privateKeyPem, rsa.publicKey]) {
      expect(() => verifier(invalidPublicKey)).toThrow(
        expect.objectContaining({ code: "invalid_public_key" })
      );
    }
  });

  it("fails closed when a trusted file path is replaced after descriptor reading", () => {
    const replacement = join(directory, "replacement.pem");
    const original = join(directory, "original.pem");
    const displaced = join(directory, "displaced.pem");
    writeFileSync(original, privateKeyPem, { mode: 0o600 });
    writeFileSync(replacement, privateKeyPem, { mode: 0o600 });

    expect(() =>
      readTrustedConfigurationFileWithRaceHookForTest(
        {
          trustedConfigurationRoot: directory,
          filePath: original,
          minimumBytes: 1,
          maximumBytes: 64 * 1024,
        },
        () => {
          renameSync(original, displaced);
          renameSync(replacement, original);
        }
      )
    ).toThrow(TrustedConfigurationFileError);
  });

  it("cryptographically separates compensation observations from lifecycle domains", () => {
    expect(RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN).not.toBe(
      RUNTIME_RECEIPT_OBSERVATION_CLAIMS_DIGEST_DOMAIN
    );
    expect(RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN).not.toBe(
      RUNTIME_RECEIPT_OBSERVATION_RECEIPT_DIGEST_DOMAIN
    );
    expect(RUNTIME_COMPENSATION_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN).not.toBe(
      RUNTIME_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN
    );

    const command = compensationCommand();
    const observation = issue(null, { command });
    for (const lifecycleShaped of [
      { ...observation, kind: "runtime.lifecycle-receipt-observed" },
      {
        ...observation,
        authority: {
          ...observation.authority,
          capability: "runtime.lifecycle-receipt.observe",
        },
      },
    ]) {
      expect(() =>
        verifier().verify({
          observation: lifecycleShaped,
          command,
          expectedPrevious: null,
          nowMs: 1_100,
        })
      ).toThrow(expect.objectContaining({ code: "invalid_observation" }));
    }
    const statement = {
      version: 1,
      issuer: observation.authority.issuer,
      issuerKeyId: observation.authority.issuerKeyId,
      audience: observation.authority.audience,
      capability: observation.authority.capability,
      claimsDigest: observation.authority.claimsDigest,
      issuedAtMs: observation.authority.issuedAtMs,
      expiresAtMs: observation.authority.expiresAtMs,
    } as const;
    const lifecycleDomainSignature = signEd25519(
      null,
      Buffer.concat([
        Buffer.from(RUNTIME_RECEIPT_OBSERVATION_SIGNATURE_DOMAIN, "utf8"),
        Buffer.from(canonicalRuntimeJson(statement), "utf8"),
      ]),
      privateKeyPem
    ).toString("base64url");
    expect(() =>
      verifier().verify({
        observation: {
          ...observation,
          authority: { ...observation.authority, signature: lifecycleDomainSignature },
        },
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_signature" }));
  });
});

function compensationCommand(
  overrides: Partial<Omit<RuntimeCompensationCommand, "authority">> = {}
): RuntimeCompensationCommand {
  const source =
    overrides.source ??
    ({
      lifecycleCommandId: "lifecycle-command-1",
      lifecycleCommandClaimsDigest: "a".repeat(64),
      lifecycleReceiptDigest: "b".repeat(64),
      lifecycleEnforcementSubjectDigest: "c".repeat(64),
      lifecycleAggregateProofDigest: "d".repeat(64),
      sourceRequiredEffectEnforcerSetDigest: "e".repeat(64),
    } as const);
  const claims = {
    kind: "safety.quarantine" as const,
    commandId: "quarantine-command-1",
    compensationId: "compensation-1",
    binding,
    observedRuntimeAuthorizationGeneration: 7,
    source,
    platformSecurityPolicyRevision: "platform-security-policy:v1",
    requiredContainmentEnforcerSetDigest: "f".repeat(64),
    containment: {
      revokeTerminalWrites: true as const,
      stopProcessExecution: true as const,
      quarantineRuntime: true as const,
    },
    safetyFence: 12,
    exactBindingOnly: true as const,
    advanceBeyondCurrentFences: true as const,
    reasonRef: "compensation-incident:1",
    causationId: source.lifecycleCommandId,
    actor: { kind: "system" as const, actorRef: "platform-security" as const },
    issuedAtMs: 100,
    deadlineAtMs: 900,
    ...overrides,
  };
  return {
    ...claims,
    authority: {
      issuerKeyId: "platform-security:v1",
      audience: "runtime",
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: claims.issuedAtMs,
      expiresAtMs: claims.deadlineAtMs,
      signature: "A".repeat(86),
      issuer: "platform-security",
      capability: "safety.quarantine",
    },
  } as RuntimeCompensationCommand;
}

function acceptedReceipt(
  command: RuntimeCompensationCommand
): NonDuplicateRuntimeCompensationReceipt {
  return {
    receiptKind: "runtime.compensation",
    compensationId: command.compensationId,
    commandId: command.commandId,
    binding: command.binding,
    observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
    outcome: "accepted",
    effectRef: "provider-compensation-effect-1",
  };
}

function enforcedReceipt(
  command: RuntimeCompensationCommand
): Extract<NonDuplicateRuntimeCompensationReceipt, { outcome: "enforced" }> {
  const proofPayload = {
    generation: command.observedRuntimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest: command.requiredContainmentEnforcerSetDigest,
    enforcementSubjectDigest: "1".repeat(64),
    acknowledgements: [
      {
        enforcerRef: "test-containment-enforcer",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: "2".repeat(64),
      },
    ],
  };
  return {
    receiptKind: "runtime.compensation",
    compensationId: command.compensationId,
    commandId: command.commandId,
    binding: command.binding,
    observedRuntimeAuthorizationGeneration: command.observedRuntimeAuthorizationGeneration,
    outcome: "enforced",
    effectRef: "provider-compensation-effect-1",
    enforcedSafetyFence: command.safetyFence,
    containment: {
      terminalWritesRevoked: true,
      processExecutionStopped: true,
      runtimeQuarantined: true,
    },
    aggregateEnforcementProof: {
      ...proofPayload,
      aggregateProofDigest: digestAggregateEnforcementProof(proofPayload),
    },
  };
}
