import { describe, expect, it, vi } from "vitest";
import {
  createRuntimeCompensationMaterializer,
  digestRuntimeCommandClaims,
  type RuntimeCompensationAuthorityIssuer,
  type RuntimeCompensationMaterializationCandidate,
  type RuntimeCompensationMaterializationJournal,
} from "@/lib/runtime";

const candidate = {
  compensationId: "compensation-1",
  incidentDigest: "a".repeat(64),
  binding: {
    teamId: "team-1",
    projectId: "project-1",
    sessionId: "session-1",
    runtimeAssignmentId: "assignment-1",
    runtimeAssignmentGeneration: 2,
    sandboxId: "sandbox-1",
    sandboxGeneration: 3,
    runtimePrincipalId: "principal-1",
  },
  observedRuntimeAuthorizationGeneration: 4,
  safetyFence: 8,
  source: {
    lifecycleCommandId: "lifecycle-command-1",
    lifecycleCommandClaimsDigest: "b".repeat(64),
    lifecycleReceiptDigest: "c".repeat(64),
    lifecycleEnforcementSubjectDigest: "d".repeat(64),
    lifecycleAggregateProofDigest: "e".repeat(64),
    sourceRequiredEffectEnforcerSetDigest: "f".repeat(64),
  },
} as const satisfies RuntimeCompensationMaterializationCandidate;

function authorityIssuer(): RuntimeCompensationAuthorityIssuer {
  return {
    issue: vi.fn<RuntimeCompensationAuthorityIssuer["issue"]>((claims) => ({
      issuer: "platform-security" as const,
      issuerKeyId: "platform-security:v1",
      audience: "runtime" as const,
      capability: "safety.quarantine" as const,
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: claims.issuedAtMs,
      expiresAtMs: claims.deadlineAtMs,
      signature: "platform-signature",
    })),
  };
}

function journalReturning(
  incident: RuntimeCompensationMaterializationCandidate | null = candidate,
  result: "created" | "already-materialized" = "created"
): RuntimeCompensationMaterializationJournal & {
  findMaterializable: ReturnType<typeof vi.fn>;
  materialize: ReturnType<typeof vi.fn>;
} {
  return {
    findMaterializable: vi.fn(async () => incident),
    materialize: vi.fn(async () => result),
  };
}

describe("Runtime compensation materializer", () => {
  it("signs an unsigned incident outside the journal and binds the containment policy", async () => {
    const journal = journalReturning();
    const issuer = authorityIssuer();
    const materializer = createRuntimeCompensationMaterializer({
      journal,
      authorityIssuer: issuer,
      verifyAuthority: () => true,
      policySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
        }),
      },
      idGenerator: () => "quarantine-command-1",
      clock: () => 200,
      commandTtlMs: 30_000,
    });

    await expect(materializer.runOnce()).resolves.toEqual({ found: 1, created: 1 });
    expect(issuer.issue).toHaveBeenCalledOnce();
    expect(journal.materialize).toHaveBeenCalledWith(
      {
        compensationId: candidate.compensationId,
        incidentDigest: candidate.incidentDigest,
        authorityVerifiedAtMs: 200,
        materializedAtMs: 200,
        command: expect.objectContaining({
          kind: "safety.quarantine",
          commandId: "quarantine-command-1",
          compensationId: candidate.compensationId,
          binding: candidate.binding,
          observedRuntimeAuthorizationGeneration: 4,
          safetyFence: 8,
          source: candidate.source,
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
          containment: {
            revokeTerminalWrites: true,
            stopProcessExecution: true,
            quarantineRuntime: true,
          },
          exactBindingOnly: true,
          advanceBeyondCurrentFences: true,
          reasonRef: candidate.incidentDigest,
          causationId: candidate.source.lifecycleCommandId,
          actor: { kind: "system", actorRef: "platform-security" },
          issuedAtMs: 200,
          deadlineAtMs: 30_200,
          authority: expect.objectContaining({
            issuer: "platform-security",
            capability: "safety.quarantine",
          }),
        }),
      },
      { signal: expect.anything() }
    );
    const stored = journal.materialize.mock.calls[0]?.[0];
    expect(Object.isFrozen(stored.command)).toBe(true);
    expect(Object.isFrozen(stored.command.source)).toBe(true);
  });

  it("leaves the incident unsigned when the platform signer is unavailable", async () => {
    const journal = journalReturning();
    const materializer = createRuntimeCompensationMaterializer({
      journal,
      authorityIssuer: {
        issue() {
          throw new Error("HSM unavailable");
        },
      },
      verifyAuthority: () => true,
      policySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
        }),
      },
      idGenerator: () => "quarantine-command-1",
      clock: () => 200,
    });

    await expect(materializer.runOnce()).rejects.toThrow("HSM unavailable");
    expect(journal.materialize).not.toHaveBeenCalled();
  });

  it("rejects a signer that substitutes issuer, claims, or time", async () => {
    for (const authority of [
      { issuer: "team-session" },
      { claimsDigest: "0".repeat(64) },
      { expiresAtMs: 30_201 },
    ]) {
      const journal = journalReturning();
      const materializer = createRuntimeCompensationMaterializer({
        journal,
        authorityIssuer: {
          issue(claims) {
            return {
              issuer: "platform-security",
              issuerKeyId: "platform-security:v1",
              audience: "runtime",
              capability: "safety.quarantine",
              claimsDigest: digestRuntimeCommandClaims(claims),
              issuedAtMs: claims.issuedAtMs,
              expiresAtMs: claims.deadlineAtMs,
              signature: "platform-signature",
              ...authority,
            } as never;
          },
        },
        verifyAuthority: () => true,
        policySource: {
          resolve: () => ({
            platformSecurityPolicyRevision: "platform-security-policy:v1",
            requiredContainmentEnforcerSetDigest: "1".repeat(64),
          }),
        },
        idGenerator: () => "quarantine-command-1",
        clock: () => 200,
      });
      await expect(materializer.runOnce()).rejects.toThrow(
        "Invalid platform-security Runtime authority"
      );
      expect(journal.materialize).not.toHaveBeenCalled();
    }
  });

  it("never persists a command whose platform signature is not cryptographically verified", async () => {
    for (const verifyAuthority of [
      () => false,
      () => {
        throw new Error("secret key-registry detail");
      },
      (() => Promise.resolve(true)) as never,
    ]) {
      const journal = journalReturning();
      const materializer = createRuntimeCompensationMaterializer({
        journal,
        authorityIssuer: authorityIssuer(),
        verifyAuthority,
        policySource: {
          resolve: () => ({
            platformSecurityPolicyRevision: "platform-security-policy:v1",
            requiredContainmentEnforcerSetDigest: "1".repeat(64),
          }),
        },
        idGenerator: () => "quarantine-command-1",
        clock: () => 200,
      });

      await expect(materializer.runOnce()).rejects.toThrow(
        "Platform-security Runtime authority could not be verified"
      );
      expect(journal.materialize).not.toHaveBeenCalled();
    }
  });

  it("never reads or invokes a custom thenable returned by the synchronous verifier", async () => {
    const thenBody = vi.fn();
    const thenGetter = vi.fn(() => thenBody);
    const hostileVerifierResult = {} as Record<string, unknown>;
    Object.defineProperty(hostileVerifierResult, "then", {
      get: thenGetter,
    });
    const journal = journalReturning();
    const materializer = createRuntimeCompensationMaterializer({
      journal,
      authorityIssuer: authorityIssuer(),
      verifyAuthority: (() => hostileVerifierResult) as never,
      policySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
        }),
      },
      idGenerator: () => "quarantine-command-1",
      clock: () => 200,
    });

    await expect(materializer.runOnce()).rejects.toThrow(
      "Platform-security Runtime authority could not be verified"
    );
    expect(thenGetter).not.toHaveBeenCalled();
    expect(thenBody).not.toHaveBeenCalled();
    expect(journal.materialize).not.toHaveBeenCalled();
  });

  it("stops after an aborted materialization read without signing or writing", async () => {
    let release: ((value: RuntimeCompensationMaterializationCandidate) => void) | undefined;
    const journal = journalReturning();
    journal.findMaterializable.mockImplementation(
      () =>
        new Promise<RuntimeCompensationMaterializationCandidate>((resolve) => {
          release = resolve;
        })
    );
    const issuer = authorityIssuer();
    const materializer = createRuntimeCompensationMaterializer({
      journal,
      authorityIssuer: issuer,
      verifyAuthority: () => true,
      policySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
        }),
      },
      idGenerator: () => "quarantine-command-1",
      clock: () => 200,
    });
    const controller = new AbortController();

    const running = materializer.runOnce(controller.signal);
    controller.abort();
    release?.(candidate);

    await expect(running).rejects.toMatchObject({ name: "AbortError" });
    expect(issuer.issue).not.toHaveBeenCalled();
    expect(journal.materialize).not.toHaveBeenCalled();
  });

  it("shares one active materialization and handles a concurrent winner idempotently", async () => {
    let release: (() => void) | undefined;
    const journal = journalReturning(candidate, "already-materialized");
    journal.findMaterializable.mockImplementation(
      () =>
        new Promise<RuntimeCompensationMaterializationCandidate>((resolve) => {
          release = () => resolve(candidate);
        })
    );
    const materializer = createRuntimeCompensationMaterializer({
      journal,
      authorityIssuer: authorityIssuer(),
      verifyAuthority: () => true,
      policySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
        }),
      },
      idGenerator: () => "quarantine-command-loser",
      clock: () => 200,
    });

    const first = materializer.runOnce();
    const second = materializer.runOnce();
    expect(second).toBe(first);
    release?.();
    await expect(first).resolves.toEqual({ found: 1, created: 0 });
    expect(journal.findMaterializable).toHaveBeenCalledOnce();
    expect(journal.materialize).toHaveBeenCalledOnce();
  });

  it("does nothing when no verified unsigned incident is materializable", async () => {
    const journal = journalReturning(null);
    const materializer = createRuntimeCompensationMaterializer({
      journal,
      authorityIssuer: authorityIssuer(),
      verifyAuthority: () => true,
      policySource: { resolve: () => undefined },
      idGenerator: () => "unused",
      clock: () => 200,
    });

    await expect(materializer.runOnce()).resolves.toEqual({ found: 0, created: 0 });
    expect(journal.materialize).not.toHaveBeenCalled();
  });

  it("rejects hostile incident getters without invoking the signer", async () => {
    const bindingGetter = vi.fn(() => candidate.binding);
    const hostile = { ...candidate } as Record<string, unknown>;
    Object.defineProperty(hostile, "binding", { enumerable: true, get: bindingGetter });
    const journal = journalReturning(hostile as never);
    const issuer = authorityIssuer();
    const materializer = createRuntimeCompensationMaterializer({
      journal,
      authorityIssuer: issuer,
      verifyAuthority: () => true,
      policySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
        }),
      },
      idGenerator: () => "quarantine-command-1",
      clock: () => 200,
    });

    await expect(materializer.runOnce()).rejects.toThrow("Invalid compensation incident");
    expect(bindingGetter).not.toHaveBeenCalled();
    expect(issuer.issue).not.toHaveBeenCalled();
    expect(journal.materialize).not.toHaveBeenCalled();
  });

  it("rejects hostile policy and signer getters without reading them", async () => {
    const policyGetter = vi.fn(() => "platform-security-policy:v1");
    const hostilePolicy = {
      requiredContainmentEnforcerSetDigest: "1".repeat(64),
    } as Record<string, unknown>;
    Object.defineProperty(hostilePolicy, "platformSecurityPolicyRevision", {
      enumerable: true,
      get: policyGetter,
    });
    const firstJournal = journalReturning();
    const firstIssuer = authorityIssuer();
    const first = createRuntimeCompensationMaterializer({
      journal: firstJournal,
      authorityIssuer: firstIssuer,
      verifyAuthority: () => true,
      policySource: { resolve: () => hostilePolicy as never },
      idGenerator: () => "quarantine-command-1",
      clock: () => 200,
    });

    await expect(first.runOnce()).rejects.toThrow("Runtime compensation policy is unavailable");
    expect(policyGetter).not.toHaveBeenCalled();
    expect(firstIssuer.issue).not.toHaveBeenCalled();
    expect(firstJournal.materialize).not.toHaveBeenCalled();

    const signatureGetter = vi.fn(() => "platform-signature");
    const secondJournal = journalReturning();
    const second = createRuntimeCompensationMaterializer({
      journal: secondJournal,
      authorityIssuer: {
        issue(claims) {
          const authority = {
            issuer: "platform-security",
            issuerKeyId: "platform-security:v1",
            audience: "runtime",
            capability: "safety.quarantine",
            claimsDigest: digestRuntimeCommandClaims(claims),
            issuedAtMs: claims.issuedAtMs,
            expiresAtMs: claims.deadlineAtMs,
          } as Record<string, unknown>;
          Object.defineProperty(authority, "signature", {
            enumerable: true,
            get: signatureGetter,
          });
          return authority as never;
        },
      },
      verifyAuthority: () => true,
      policySource: {
        resolve: () => ({
          platformSecurityPolicyRevision: "platform-security-policy:v1",
          requiredContainmentEnforcerSetDigest: "1".repeat(64),
        }),
      },
      idGenerator: () => "quarantine-command-1",
      clock: () => 200,
    });

    await expect(second.runOnce()).rejects.toThrow("Invalid platform-security Runtime authority");
    expect(signatureGetter).not.toHaveBeenCalled();
    expect(secondJournal.materialize).not.toHaveBeenCalled();
  });
});
