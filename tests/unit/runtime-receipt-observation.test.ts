import { chmodSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RuntimeBinding } from "@/lib/team-sessions/contracts";
import type {
  NonDuplicateRuntimeReceipt,
  RuntimeLifecycleCommand,
  RuntimeReceipt,
} from "@/lib/runtime/contracts";
import { digestRuntimeCommandClaims } from "@/lib/runtime/runtime-command-canonical";
import { digestNonDuplicateRuntimeReceipt } from "@/lib/runtime/runtime-command-execution";
import {
  RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS,
  RuntimeReceiptObservationError,
  createRuntimeReceiptObservationIssuer,
  createRuntimeReceiptObservationVerifier,
  digestRuntimeLifecycleReceipt,
  isVerifiedRuntimeLifecycleReceiptObservation,
  type RuntimeLifecycleReceiptObservation,
  type RuntimeReceiptObservationCheckpoint,
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

describe("signed Runtime lifecycle receipt observations", () => {
  let directory: string;
  let privateKeyFile: string;
  let privateKeyPem: string;
  let publicKeyPem: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "terminalx-runtime-observation-"));
    const pair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    privateKeyPem = pair.privateKey;
    publicKeyPem = pair.publicKey;
    privateKeyFile = join(directory, "observer-private.pem");
    writeFileSync(privateKeyFile, privateKeyPem, { mode: 0o600 });
  });

  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  function issuer(clock = () => 1_000) {
    return createRuntimeReceiptObservationIssuer({
      issuerKeyId: "daytona-observer:v1",
      binding,
      privateKeyFile,
      clock,
      observationTtlMs: 500,
    });
  }

  function verifier(pem = publicKeyPem, pinBinding: RuntimeBinding = binding) {
    return createRuntimeReceiptObservationVerifier({
      pinnedPublicKeys: [
        {
          issuerKeyId: "daytona-observer:v1",
          binding: pinBinding,
          publicKeyPem: pem,
        },
      ],
      maximumObservationTtlMs: 1_000,
    });
  }

  function issue(
    previous: RuntimeReceiptObservationCheckpoint | null = null,
    overrides: Partial<{
      observationId: string;
      cursor: string;
      command: RuntimeLifecycleCommand;
      receipt: RuntimeReceipt;
    }> = {}
  ): RuntimeLifecycleReceiptObservation {
    const command = overrides.command ?? pauseCommand();
    return issuer().issue({
      observationId: overrides.observationId ?? "observation-1",
      cursor: overrides.cursor ?? "cursor-1",
      previous,
      command,
      receipt: overrides.receipt ?? acceptedReceipt(command),
    });
  }

  it("issues and verifies an exact-bound, signed, deeply frozen observation", () => {
    const command = pauseCommand();
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
      kind: "runtime.lifecycle-receipt-observed",
      observationId: "observation-1",
      cursor: "cursor-1",
      previous: null,
      observedAtMs: 1_000,
      command: {
        kind: "run.pause",
        commandId: command.commandId,
        claimsDigest: command.authority.claimsDigest,
        binding,
        runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
        requiredEffectEnforcerSetDigest: "d".repeat(64),
        agentRunId: command.agentRunId,
        fromRunStateVersion: command.fromRunStateVersion,
        toRunStateVersion: command.toRunStateVersion,
      },
      receipt,
      receiptDigest: digestRuntimeLifecycleReceipt(receipt, command),
      authority: {
        issuer: "runtime",
        issuerKeyId: "daytona-observer:v1",
        audience: "terminalx-control-plane",
        capability: "runtime.lifecycle-receipt.observe",
        issuedAtMs: 1_000,
        expiresAtMs: 1_500,
      },
    });
    expect(verified.observationDigest).toBe(observation.authority.claimsDigest);
    expect(Object.keys(verified)).not.toContain("observationDigest");
    expect(Object.isFrozen(verified)).toBe(true);
    expect(Object.isFrozen(verified.command)).toBe(true);
    expect(Object.isFrozen(verified.command.binding)).toBe(true);
    expect(Object.isFrozen(verified.receipt)).toBe(true);
    expect(Object.isFrozen(verified.authority)).toBe(true);
    expect(isVerifiedRuntimeLifecycleReceiptObservation(verified)).toBe(true);
    expect(isVerifiedRuntimeLifecycleReceiptObservation(Object.freeze({ ...observation }))).toBe(
      false
    );
    expect(
      isVerifiedRuntimeLifecycleReceiptObservation(
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

  it("uses the durable Unicode code-point cursor bound at max and max plus one", () => {
    const command = pauseCommand();
    const maximumCursor = "🧭".repeat(RUNTIME_RECEIPT_OBSERVATION_MAX_CURSOR_CODE_POINTS);
    const observation = issue(null, { command, cursor: maximumCursor });
    expect(
      verifier().verify({
        observation,
        command,
        expectedPrevious: null,
        nowMs: 1_100,
      }).cursor
    ).toBe(maximumCursor);

    expect(() =>
      issue(null, {
        command,
        cursor: `${maximumCursor}🧭`,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_input" }));
  });

  it("requires an exact prior cursor and observation-digest checkpoint", () => {
    const command = pauseCommand();
    const first = verifier().verify({
      observation: issue(null, { command }),
      command,
      expectedPrevious: null,
      nowMs: 1_100,
    });
    const checkpoint = {
      cursor: first.cursor,
      observationDigest: first.observationDigest,
    } as const;
    const second = issue(checkpoint, {
      observationId: "observation-2",
      cursor: "cursor-2",
      command,
    });

    expect(
      verifier().verify({
        observation: second,
        command,
        expectedPrevious: checkpoint,
        nowMs: 1_100,
      }).cursor
    ).toBe("cursor-2");
    for (const expectedPrevious of [
      null,
      { ...checkpoint, cursor: "cursor-other" },
      { ...checkpoint, observationDigest: "0".repeat(64) },
    ]) {
      expect(() =>
        verifier().verify({ observation: second, command, expectedPrevious, nowMs: 1_100 })
      ).toThrow(expect.objectContaining({ code: "chain_mismatch" }));
    }

    expect(() =>
      issuer().issue({
        observationId: "observation-loop",
        cursor: checkpoint.cursor,
        previous: checkpoint,
        command,
        receipt: acceptedReceipt(command),
      })
    ).toThrow(expect.objectContaining({ code: "invalid_input" }));
  });

  it("rejects every command identity, binding, authorization, and receipt substitution", () => {
    const command = pauseCommand();
    const observation = issue(null, { command });
    const otherCommand = pauseCommand({ commandId: "command-other" });
    const otherBindingCommand = pauseCommand({
      binding: { ...binding, sandboxGeneration: binding.sandboxGeneration + 1 },
    });
    const otherAuthorizationCommand = pauseCommand({ runtimeAuthorizationGeneration: 8 });

    for (const expectedCommand of [otherCommand, otherBindingCommand, otherAuthorizationCommand]) {
      expect(() =>
        verifier().verify({
          observation,
          command: expectedCommand,
          expectedPrevious: null,
          nowMs: 1_100,
        })
      ).toThrow(expect.objectContaining({ code: "command_mismatch" }));
    }

    const tamperedReceipt = {
      ...observation,
      receipt: { ...observation.receipt, effectRef: "effect-substituted" },
    };
    const tamperedReceiptDigest = {
      ...observation,
      receiptDigest: "0".repeat(64),
    };
    const tamperedCommandReference = {
      ...observation,
      command: { ...observation.command, claimsDigest: "0".repeat(64) },
    };
    for (const candidate of [tamperedReceipt, tamperedReceiptDigest, tamperedCommandReference]) {
      expect(() =>
        verifier().verify({
          observation: candidate,
          command,
          expectedPrevious: null,
          nowMs: 1_100,
        })
      ).toThrow(RuntimeReceiptObservationError);
    }
  });

  it("rejects cursor, time, authority, digest, and signature tampering", () => {
    const command = pauseCommand();
    const observation = issue(null, { command });
    const authority = observation.authority;
    const attempts: unknown[] = [
      { ...observation, cursor: "cursor-other" },
      { ...observation, observedAtMs: 999 },
      { ...observation, unexpected: true },
      { ...observation, authority: { ...authority, issuer: "control-plane" } },
      { ...observation, authority: { ...authority, audience: "browser" } },
      { ...observation, authority: { ...authority, capability: "runtime.event.observe" } },
      { ...observation, authority: { ...authority, issuerKeyId: "unknown:v1" } },
      { ...observation, authority: { ...authority, claimsDigest: "0".repeat(64) } },
      { ...observation, authority: { ...authority, issuedAtMs: 999 } },
      { ...observation, authority: { ...authority, expiresAtMs: 3_000 } },
      {
        ...observation,
        authority: {
          ...authority,
          signature: `${authority.signature.slice(0, -1)}${
            authority.signature.endsWith("A") ? "B" : "A"
          }`,
        },
      },
    ];

    for (const attempt of attempts) {
      expect(() =>
        verifier().verify({
          observation: attempt,
          command,
          expectedPrevious: null,
          nowMs: 1_100,
        })
      ).toThrow(RuntimeReceiptObservationError);
    }
    expect(() =>
      verifier().verify({
        observation,
        command,
        expectedPrevious: null,
        nowMs: observation.authority.expiresAtMs,
      })
    ).toThrow(expect.objectContaining({ code: "expired" }));
  });

  it("does not invoke hostile getters at issuance or verification boundaries", () => {
    const command = pauseCommand();
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
        observationId: "observation-hostile-command",
        cursor: "cursor-hostile-command",
        previous: null,
        command: hostileCommand as unknown as RuntimeLifecycleCommand,
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
        observationId: "observation-hostile-receipt",
        cursor: "cursor-hostile-receipt",
        previous: null,
        command,
        receipt: hostileReceipt as unknown as RuntimeReceipt,
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
        return "secret-private-key";
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
  });

  it("bounds untrusted fields and rejects malformed duplicate receipts", () => {
    const command = pauseCommand();
    expect(() =>
      issuer().issue({
        observationId: "observation-large-cursor",
        cursor: "x".repeat(2_049),
        previous: null,
        command,
        receipt: acceptedReceipt(command),
      })
    ).toThrow(expect.objectContaining({ code: "invalid_input" }));

    const accepted = acceptedReceipt(command);
    const malformedDuplicate = {
      commandId: command.commandId,
      binding: command.binding,
      runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt: accepted,
      originalReceiptDigest: "0".repeat(64),
    } as const satisfies RuntimeReceipt;
    expect(() =>
      issuer().issue({
        observationId: "observation-bad-duplicate",
        cursor: "cursor-bad-duplicate",
        previous: null,
        command,
        receipt: malformedDuplicate,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_receipt" }));
  });

  it("retains and authenticates the complete original result in a duplicate receipt", () => {
    const command = pauseCommand();
    const originalReceipt = acceptedReceipt(command);
    const duplicate = {
      commandId: command.commandId,
      binding: command.binding,
      runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
      outcome: "duplicate",
      originalReceipt,
      originalReceiptDigest: digestNonDuplicateRuntimeReceipt(originalReceipt),
    } as const satisfies RuntimeReceipt;
    const observation = issue(null, { command, receipt: duplicate });

    const verified = verifier().verify({
      observation,
      command,
      expectedPrevious: null,
      nowMs: 1_100,
    });
    expect(verified.receipt).toEqual(duplicate);
    expect(verified.receiptDigest).toBe(digestRuntimeLifecycleReceipt(duplicate, command));
  });

  it("scopes every pinned key to one exact Runtime binding", () => {
    const command = pauseCommand();
    const observation = issue(null, { command });
    expect(() =>
      verifier(publicKeyPem, { ...binding, runtimeAssignmentId: "assignment-other" }).verify({
        observation,
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
  });

  it("loads only strict Ed25519 private files and pinned SPKI public keys", () => {
    chmodSync(privateKeyFile, 0o644);
    expect(() => issuer()).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));
    chmodSync(privateKeyFile, 0o600);

    const link = join(directory, "observer-link.pem");
    symlinkSync(privateKeyFile, link);
    expect(() =>
      createRuntimeReceiptObservationIssuer({
        issuerKeyId: "daytona-observer:v1",
        binding,
        privateKeyFile: link,
      })
    ).toThrow(expect.objectContaining({ code: "private_key_unavailable" }));

    const rsa = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const rsaFile = join(directory, "rsa-private.pem");
    writeFileSync(rsaFile, rsa.privateKey, { mode: 0o600 });
    expect(() =>
      createRuntimeReceiptObservationIssuer({
        issuerKeyId: "daytona-observer:v1",
        binding,
        privateKeyFile: rsaFile,
      })
    ).toThrow(expect.objectContaining({ code: "invalid_private_key" }));

    for (const invalidPublicKey of [privateKeyPem, rsa.publicKey]) {
      expect(() => verifier(invalidPublicKey)).toThrow(
        expect.objectContaining({ code: "invalid_public_key" })
      );
    }
  });

  it("keeps all errors free of secret values and file paths", () => {
    chmodSync(privateKeyFile, 0o644);
    try {
      issuer();
    } catch (error) {
      expect(error).toBeInstanceOf(RuntimeReceiptObservationError);
      expect(String(error)).not.toContain(privateKeyFile);
      expect(String(error)).not.toContain("PRIVATE KEY");
      expect(String(error)).not.toContain(privateKeyPem.slice(40, 80));
    }
  });
});

function pauseCommand(
  overrides: Partial<
    Omit<Extract<RuntimeLifecycleCommand, { kind: "run.pause" }>, "authority">
  > = {}
): Extract<RuntimeLifecycleCommand, { kind: "run.pause" }> {
  const claims = {
    kind: "run.pause" as const,
    commandId: "command-1",
    binding,
    projectCeilingRevision: "ceiling-1",
    runtimeAuthorizationGeneration: 7,
    requiredEffectEnforcerSetDigest: "d".repeat(64),
    causationId: "cause-1",
    actor: { kind: "human" as const, actorRef: "user-1" },
    issuedAtMs: 100,
    deadlineAtMs: 900,
    agentRunId: "run-1",
    runPolicyRevision: 2,
    fromRunStateVersion: 8,
    toRunStateVersion: 9,
    reason: "human" as const,
    ...overrides,
  };
  return {
    ...claims,
    authority: {
      issuerKeyId: "team-session:v1",
      audience: "runtime",
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: claims.issuedAtMs,
      expiresAtMs: claims.deadlineAtMs,
      signature: "A".repeat(86),
      issuer: "team-session",
      capability: "run.pause",
    },
  };
}

function acceptedReceipt(command: RuntimeLifecycleCommand): NonDuplicateRuntimeReceipt {
  return {
    commandId: command.commandId,
    binding: command.binding,
    runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
    outcome: "accepted",
    effectRef: "effect-1",
  };
}
