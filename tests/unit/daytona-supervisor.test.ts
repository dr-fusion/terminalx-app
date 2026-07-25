import { createHash, generateKeyPairSync, sign as signEd25519, type KeyObject } from "node:crypto";
import { chmodSync, lstatSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import {
  createDaytonaEffectiveIsolationVerifier,
  DAYTONA_EFFECTIVE_ISOLATION_ATTESTATION_KIND,
  TERMINALX_DAYTONA_BASE_SOURCE_COMMIT,
  type DaytonaEffectiveIsolationClaims,
} from "../../packages/daytona-supervisor/src/effective-isolation";
import { runDaytonaSupervisorNdjson } from "../../packages/daytona-supervisor/src/ndjson-protocol";
import { createPinnedDaytonaEffectExecutor } from "../../packages/daytona-supervisor/src/pinned-effect-executor";
import { createSignedDaytonaSupervisorStateStore } from "../../packages/daytona-supervisor/src/signed-state-store";
import {
  createPinnedDaytonaSupervisor,
  DAYTONA_SUPERVISOR_ISOLATION_CLAIMS_DIGEST_DOMAIN,
  DAYTONA_SUPERVISOR_ISOLATION_SIGNATURE_DOMAIN,
  DaytonaSupervisorProtocolError,
  type DaytonaSupervisorEffectExecutionRequest,
  type DaytonaSupervisorEffectExecutor,
  type DaytonaSupervisorState,
  type DaytonaSupervisorStateStore,
} from "../../packages/daytona-supervisor/src/supervisor";
import type {
  DaytonaSupervisorCommandRequest,
  DaytonaSupervisorIsolationRequest,
} from "@/lib/runtime/daytona-hosted-control-plane";
import type { HostedRuntimeAssignmentPlan } from "@/lib/runtime/hosted-runtime-control-plane";
import type { RuntimeLifecycleCommand, RuntimeReceipt } from "@/lib/runtime/contracts";
import type { RuntimeCommandAuthorityVerifier } from "@/lib/runtime/runtime-command-authority";
import {
  canonicalRuntimeJson,
  digestRuntimeCommandClaims,
} from "@/lib/runtime/runtime-command-canonical";
import {
  commitRuntimeEffectRef,
  digestAggregateEnforcementProof,
  digestRuntimeEnforcementSubject,
} from "@/lib/runtime/runtime-enforcement-proof";

const PROVIDER_ID = "123e4567-e89b-42d3-a456-426614174000";
const SANDBOX_SNAPSHOT_REF = `registry.example.com/terminalx/sandbox@sha256:${"9".repeat(64)}`;
const NOW = 100;
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

describe("pinned Daytona supervisor", () => {
  it("writes an intent before effects and returns an idempotent signed observation", async () => {
    const store = memoryStateStore();
    const execute = vi.fn(
      async (_input: DaytonaSupervisorEffectExecutionRequest, _signal: AbortSignal) => ({
        receipt: enforcedReceipt(command()),
        attestations: [],
      })
    );
    const supervisor = supervisorFixture({ store, execute, clock: () => NOW });
    const request = commandRequest(command());

    const first = await supervisor.executeAuthenticated(request, new AbortController().signal);
    const second = await supervisor.executeAuthenticated(request, new AbortController().signal);

    expect(execute).toHaveBeenCalledTimes(1);
    expect(execute.mock.calls[0]?.[0].mode).toBe("apply");
    expect(store.commits[0]?.operations[0]).toMatchObject({
      status: "dispatching",
      operationId: request.operationId,
      commandId: request.commandId,
      commandDigest: request.commandDigest,
    });
    expect(store.current?.operations[0]).toMatchObject({
      status: "complete",
      cursor: "00000000000000000001",
    });
    expect(second).toEqual(first);
  });

  it("reconciles a signed dispatch intent after restart even after authority expiry", async () => {
    const store = memoryStateStore();
    const request = commandRequest(command());
    const first = supervisorFixture({
      store,
      execute: vi.fn(async () => {
        throw new Error("ambiguous process exit");
      }),
      clock: () => NOW,
    });
    await expect(
      first.executeAuthenticated(request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "unavailable" });
    expect(store.current?.operations[0]).toMatchObject({ status: "dispatching" });
    await first.close();

    const reconcile = vi.fn(
      async (_input: DaytonaSupervisorEffectExecutionRequest, _signal: AbortSignal) => ({
        receipt: enforcedReceipt(request.command as RuntimeLifecycleCommand),
        attestations: [],
      })
    );
    const revokedAuthority = vi.fn(() => false);
    const restarted = supervisorFixture({
      store,
      execute: reconcile,
      clock: () => 10_000,
      authorityVerifier: revokedAuthority,
    });
    const outcome = await restarted.executeAuthenticated(request, new AbortController().signal);

    expect(outcome.commandId).toBe(request.commandId);
    expect(reconcile).toHaveBeenCalledTimes(1);
    expect(reconcile.mock.calls[0]?.[0].mode).toBe("reconcile");
    expect(revokedAuthority).not.toHaveBeenCalled();
  });

  it("rejects conflicting operation reuse and provider identifiers embedded in outputs", async () => {
    const store = memoryStateStore();
    const firstCommand = command();
    const supervisor = supervisorFixture({
      store,
      execute: vi.fn(async () => ({ receipt: enforcedReceipt(firstCommand), attestations: [] })),
      clock: () => NOW,
    });
    const request = commandRequest(firstCommand);
    await supervisor.executeAuthenticated(request, new AbortController().signal);

    await expect(
      supervisor.executeAuthenticated(
        { ...request, commandId: "different-command" },
        new AbortController().signal
      )
    ).rejects.toMatchObject({ code: "conflict" });

    const leaking = supervisorFixture({
      store: memoryStateStore(),
      execute: vi.fn(async () => ({
        receipt: enforcedReceipt(firstCommand, `sandbox=${PROVIDER_ID}`),
        attestations: [],
      })),
      clock: () => NOW,
    });
    await expect(
      leaking.executeAuthenticated(request, new AbortController().signal)
    ).rejects.toMatchObject({ code: "internal" });
  });

  it("replays only observations after an exact durable checkpoint", async () => {
    const store = memoryStateStore();
    const firstCommand = command();
    const firstRequest = commandRequest(firstCommand);
    const supervisor = supervisorFixture({
      store,
      execute: vi.fn(async (input) => ({
        receipt: enforcedReceipt(input.command as RuntimeLifecycleCommand),
        attestations: [{ signedFor: input.command.commandId }],
      })),
      clock: () => NOW,
    });
    const first = await supervisor.executeAuthenticated(firstRequest, new AbortController().signal);
    const secondCommand = command({ commandId: "command-2", from: 9, to: 10 });
    await supervisor.executeAuthenticated(
      commandRequest(secondCommand, "operation-2"),
      new AbortController().signal
    );
    const firstObservation = first.observation as {
      cursor: string;
      authority: { claimsDigest: string };
    };
    await supervisor.close();
    const restarted = supervisorFixture({
      store,
      execute: vi.fn(async (input) => ({
        receipt: enforcedReceipt(input.command as RuntimeLifecycleCommand),
        attestations: [{ signedFor: input.command.commandId }],
      })),
      clock: () => NOW,
    });
    const values = await collect(
      restarted.followSigned(
        {
          providerSandboxId: PROVIDER_ID,
          expectedRevision: 1,
          checkpoint: {
            cursor: firstObservation.cursor,
            observationDigest: firstObservation.authority.claimsDigest,
          },
          trust: isolationTrust(),
        },
        new AbortController().signal
      )
    );
    expect(values).toHaveLength(1);
    expect((values[0] as { observation: { cursor: string } }).observation.cursor).toBe(
      "00000000000000000002"
    );
    expect((values[0] as { attestations: readonly unknown[] }).attestations).toHaveLength(1);
    expect((values[0] as { attestations: readonly unknown[] }).attestations[0]).toEqual({
      signedFor: "command-2",
    });
  });

  it("maps malformed public requests to stable protocol errors", async () => {
    const supervisor = supervisorFixture({
      store: memoryStateStore(),
      execute: vi.fn(async () => ({ receipt: {}, attestations: [] })),
      clock: () => NOW,
    });
    const signal = new AbortController().signal;

    await expect(supervisor.attestIsolation(null as never, signal)).rejects.toMatchObject({
      code: "invalid-request",
    });
    expect(() => supervisor.executeAuthenticated(null as never, signal)).toThrowError(
      expect.objectContaining({ code: "invalid-request" })
    );
    expect(() => supervisor.followSigned(null as never, signal)).toThrowError(
      expect.objectContaining({ code: "invalid-request" })
    );
  });
});

describe("signed Daytona supervisor state", () => {
  it("survives restart with mode 0600 and rejects a modified payload", async () => {
    const directory = mkdtempSync(join(tmpdir(), "terminalx-supervisor-state-"));
    chmodSync(directory, 0o700);
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const store = createSignedDaytonaSupervisorStateStore({
      stateDirectory: directory,
      signingPrivateKey: privateKey,
      verificationPublicKey: publicKey,
      expectedOwnerUid: process.getuid?.() ?? 0,
    });
    const state = Object.freeze({
      version: 1 as const,
      configurationDigest: "a".repeat(64),
      nextCursor: 1,
      operations: Object.freeze([]),
    });
    expect(store.load(state.configurationDigest)).toEqual(state);
    await store.commit(state);
    const restarted = createSignedDaytonaSupervisorStateStore({
      stateDirectory: directory,
      signingPrivateKey: privateKey,
      verificationPublicKey: publicKey,
      expectedOwnerUid: process.getuid?.() ?? 0,
    });
    expect(restarted.load(state.configurationDigest)).toEqual(state);
    expect(lstatSync(join(directory, "state.json")).mode & 0o777).toBe(0o600);
    await expect(
      restarted.commit({ ...state, configurationDigest: "b".repeat(64) })
    ).rejects.toMatchObject({ code: "not-ready" });
    expect(() => restarted.load("b".repeat(64))).toThrowError(
      expect.objectContaining({ code: "not-ready" })
    );

    const path = join(directory, "state.json");
    const envelope = JSON.parse(readFileSync(path, "utf8"));
    envelope.payload.nextCursor = 2;
    writeFileSync(path, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
    expect(() => restarted.load(state.configurationDigest)).toThrowError(
      expect.objectContaining({ code: "not-ready" })
    );
  });
});

describe("Daytona effective isolation verifier", () => {
  it("accepts only a pinned hardened descendant with exact process, network and policy evidence", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const plan = hostedPlan(publicKeyPem);
    const input = isolationVerificationInput(plan, privateKey);
    const verifier = createDaytonaEffectiveIsolationVerifier({
      issuerKeyId: "isolation-authority-1",
      issuerPublicKeySpkiPem: publicKeyPem,
      hardenedDaytonaSourceCommit: "a".repeat(40),
      expectedRunnerBinaryDigest: "8".repeat(64),
      expectedSandboxImageId: `sha256:${"b".repeat(64)}`,
      expectedSandboxSnapshotRef: SANDBOX_SNAPSHOT_REF,
      expectedSandboxUser: "terminalx",
      expectedSeccompProfileDigest: "d".repeat(64),
      expectedDockerVersion: "docker-29.1.3",
      expectedContainerdVersion: "containerd-2.2.1",
      expectedProviderRevision: 1,
      expectedSupervisorUid: 0,
      expectedDaytonaDaemonUid: 1000,
      expectedAgentUid: 1000,
      clock: () => 150,
    });
    expect(verifier(input)).toBe(true);

    const wrongRunnerVerifier = createDaytonaEffectiveIsolationVerifier({
      issuerKeyId: "isolation-authority-1",
      issuerPublicKeySpkiPem: publicKeyPem,
      hardenedDaytonaSourceCommit: "a".repeat(40),
      expectedRunnerBinaryDigest: "9".repeat(64),
      expectedSandboxImageId: `sha256:${"b".repeat(64)}`,
      expectedSandboxSnapshotRef: SANDBOX_SNAPSHOT_REF,
      expectedSandboxUser: "terminalx",
      expectedSeccompProfileDigest: "d".repeat(64),
      expectedDockerVersion: "docker-29.1.3",
      expectedContainerdVersion: "containerd-2.2.1",
      expectedProviderRevision: 1,
      expectedSupervisorUid: 0,
      expectedDaytonaDaemonUid: 1000,
      expectedAgentUid: 1000,
      clock: () => 150,
    });
    expect(wrongRunnerVerifier(input)).toBe(false);
    expect(
      verifier({
        ...input,
        plan: { ...plan, effectEnforcerPolicyDigest: "" },
      })
    ).toBe(false);

    const privileged = structuredClone(input.attestation) as {
      claims: { controls: { privileged: boolean } };
    };
    privileged.claims.controls.privileged = true;
    expect(verifier({ ...input, attestation: privileged })).toBe(false);
    expect(() =>
      createDaytonaEffectiveIsolationVerifier({
        issuerKeyId: "isolation-authority-1",
        issuerPublicKeySpkiPem: publicKeyPem,
        hardenedDaytonaSourceCommit: TERMINALX_DAYTONA_BASE_SOURCE_COMMIT,
        expectedRunnerBinaryDigest: "8".repeat(64),
        expectedSandboxImageId: `sha256:${"b".repeat(64)}`,
        expectedSandboxSnapshotRef: SANDBOX_SNAPSHOT_REF,
        expectedSandboxUser: "terminalx",
        expectedSeccompProfileDigest: "d".repeat(64),
        expectedDockerVersion: "docker-29.1.3",
        expectedContainerdVersion: "containerd-2.2.1",
        expectedProviderRevision: 1,
        expectedSupervisorUid: 0,
        expectedDaytonaDaemonUid: 1000,
        expectedAgentUid: 1000,
      })
    ).toThrow();
    expect(() =>
      createDaytonaEffectiveIsolationVerifier({
        issuerKeyId: "isolation-authority-1",
        issuerPublicKeySpkiPem: publicKeyPem,
        hardenedDaytonaSourceCommit: "a".repeat(40),
        expectedRunnerBinaryDigest: "8".repeat(64),
        expectedSandboxImageId: `sha256:${"b".repeat(64)}`,
        expectedSandboxSnapshotRef: SANDBOX_SNAPSHOT_REF,
        expectedSandboxUser: "terminalx",
        expectedSeccompProfileDigest: "d".repeat(64),
        expectedDockerVersion: "docker-29.1.3",
        expectedContainerdVersion: "containerd-2.2.1",
        expectedProviderRevision: 1,
        expectedSupervisorUid: 0,
        expectedDaytonaDaemonUid: 1001,
        expectedAgentUid: 1000,
      })
    ).toThrow();
  });
});

describe("Daytona supervisor process boundaries", () => {
  it("invokes only a hash-pinned executor with a minimal environment", async () => {
    const directory = mkdtempSync(join(tmpdir(), "terminalx-effect-executor-"));
    const executable = join(directory, "effect-executor");
    writeFileSync(
      executable,
      [
        "#!/usr/bin/env node",
        'let input = "";',
        'process.stdin.setEncoding("utf8");',
        'process.stdin.on("data", (chunk) => { input += chunk; });',
        'process.stdin.on("end", () => {',
        "  const request = JSON.parse(input);",
        "  process.stdout.write(JSON.stringify({ receipt: { mode: request.mode, leaked: process.env.TERMINALX_TEST_SECRET ?? null }, attestations: [] }));",
        "});",
      ].join("\n"),
      { mode: 0o700 }
    );
    chmodSync(executable, 0o700);
    const executableDigest = createHash("sha256").update(readFileSync(executable)).digest("hex");
    const executor = createPinnedDaytonaEffectExecutor({
      executableRoot: directory,
      executableFile: executable,
      executableSha256: executableDigest,
      expectedEffectEnforcerSetDigest: "5".repeat(64),
      expectedOwnerUid: process.getuid?.() ?? 0,
      timeoutMs: 2_000,
      maximumInputBytes: 4_096,
    });
    process.env.TERMINALX_TEST_SECRET = "must-not-cross";
    try {
      const result = await executor.execute(
        {
          mode: "apply",
          operationId: "operation-1",
          commandId: "command-1",
          commandDigest: "a".repeat(64),
          command: command(),
          requiredEffectEnforcerSetDigest: "5".repeat(64),
        },
        new AbortController().signal
      );
      expect(result.receipt).toEqual({ mode: "apply", leaked: null });

      await expect(
        executor.execute(
          {
            mode: "apply",
            operationId: "operation-wrong-manifest",
            commandId: "command-wrong-manifest",
            commandDigest: "a".repeat(64),
            command: command(),
            requiredEffectEnforcerSetDigest: "6".repeat(64),
          },
          new AbortController().signal
        )
      ).rejects.toMatchObject({ code: "conflict" });

      await expect(
        executor.execute(
          {
            mode: "apply",
            operationId: "x".repeat(8_000),
            commandId: "command-oversized",
            commandDigest: "a".repeat(64),
            command: command(),
            requiredEffectEnforcerSetDigest: "5".repeat(64),
          },
          new AbortController().signal
        )
      ).rejects.toMatchObject({ code: "invalid-request" });
    } finally {
      delete process.env.TERMINALX_TEST_SECRET;
    }

    writeFileSync(executable, `${readFileSync(executable, "utf8")}\n// modified`, {
      mode: 0o700,
    });
    await expect(
      Promise.resolve().then(() =>
        executor.execute(
          {
            mode: "reconcile",
            operationId: "operation-1",
            commandId: "command-1",
            commandDigest: "a".repeat(64),
            command: command(),
            requiredEffectEnforcerSetDigest: "5".repeat(64),
          },
          new AbortController().signal
        )
      )
    ).rejects.toMatchObject({ code: "not-ready" });
  });

  it("serves private NDJSON without echoing provider identifiers", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let wire = "";
    output.setEncoding("utf8");
    output.on("data", (chunk: string) => {
      wire += chunk;
    });
    const close = vi.fn(async () => undefined);
    const run = runDaytonaSupervisorNdjson({
      supervisor: {
        attestIsolation: vi.fn(async () => ({ attested: true })),
        executeAuthenticated: vi.fn(async () => {
          throw new DaytonaSupervisorProtocolError("permission-denied");
        }),
        followSigned: vi.fn(async function* () {
          yield { signed: true };
        }),
        close,
      },
      input,
      output,
      signal: new AbortController().signal,
    });
    input.end(
      `${JSON.stringify({
        version: 1,
        sequence: 1,
        method: "isolation.attest",
        params: { providerSandboxId: PROVIDER_ID },
      })}\n`
    );
    await run;
    expect(wire).toContain('"attested":true');
    expect(wire).not.toContain(PROVIDER_ID);
    expect(close).toHaveBeenCalledOnce();
  });
});

function supervisorFixture(options: {
  store: ReturnType<typeof memoryStateStore>;
  execute: DaytonaSupervisorEffectExecutor["execute"];
  clock: () => number;
  authorityVerifier?: RuntimeCommandAuthorityVerifier;
}) {
  return createPinnedDaytonaSupervisor({
    configuration: {
      binding,
      planDigest: "1".repeat(64),
      providerIdentityCommitment: sha256(`terminalx/daytona-provider-identity/v1\0${PROVIDER_ID}`),
      artifactDigest: "2".repeat(64),
      sandboxUser: "terminalx",
      supervisorArtifactDigest: "3".repeat(64),
      observationIssuerKeyId: "observation-key-1",
      observationPublicKeyDigest: "4".repeat(64),
      effectEnforcerSetDigest: "5".repeat(64),
      expectedRevision: 1,
      maxOperations: 100,
    },
    authorityVerifier:
      options.authorityVerifier ??
      (({ command: verified, nowMs }) =>
        nowMs >= verified.authority.issuedAtMs && nowMs < verified.authority.expiresAtMs),
    lifecycleObservationIssuer: {
      issue(input) {
        return {
          version: 1,
          kind: "runtime.lifecycle-receipt-observed",
          observationId: input.observationId,
          cursor: input.cursor,
          previous: input.previous,
          observedAtMs: options.clock(),
          command: {
            kind: input.command.kind,
            commandId: input.command.commandId,
            claimsDigest: input.command.authority.claimsDigest,
            binding: input.command.binding,
            runtimeAuthorizationGeneration: input.command.runtimeAuthorizationGeneration,
            requiredEffectEnforcerSetDigest: input.command.requiredEffectEnforcerSetDigest!,
            agentRunId: input.command.agentRunId,
            runPolicyRevision: input.command.runPolicyRevision,
            fromRunStateVersion: input.command.fromRunStateVersion,
            toRunStateVersion: input.command.toRunStateVersion,
          },
          receipt: input.receipt,
          receiptDigest: "7".repeat(64),
          authority: {
            issuer: "runtime",
            issuerKeyId: "observation-key-1",
            audience: "terminalx-control-plane",
            capability: "runtime.lifecycle-receipt.observe",
            claimsDigest: sha256(`observation:${input.cursor}`),
            issuedAtMs: options.clock(),
            expiresAtMs: options.clock() + 1_000,
            signature: "A".repeat(86),
          },
        };
      },
    },
    compensationObservationIssuer: {
      issue(): never {
        throw new Error("not used");
      },
    },
    isolationEvidence: {
      read: () => ({ kind: "unused-isolation-evidence" }),
      verify: () => true,
    },
    effectExecutor: { execute: options.execute },
    proofVerifiers: {
      lifecycle: () => () => true,
      compensation: () => () => true,
    },
    stateStore: options.store,
    clock: options.clock,
    observationId: (cursor) => `observation-${cursor}`,
  });
}

function memoryStateStore() {
  const state: {
    current: DaytonaSupervisorState | null;
    commits: DaytonaSupervisorState[];
  } = { current: null, commits: [] };
  const store: DaytonaSupervisorStateStore & {
    readonly current: DaytonaSupervisorState | null;
    readonly commits: DaytonaSupervisorState[];
  } = {
    load(configurationDigest) {
      state.current ??= Object.freeze({
        version: 1,
        configurationDigest,
        nextCursor: 1,
        operations: Object.freeze([]),
      });
      return state.current;
    },
    async commit(next) {
      state.current = next;
      state.commits.push(next);
    },
    get current() {
      return state.current;
    },
    commits: state.commits,
  };
  return store;
}

function command(
  overrides: { commandId?: string; from?: number; to?: number } = {}
): Extract<RuntimeLifecycleCommand, { kind: "run.pause" }> {
  const claims = {
    kind: "run.pause" as const,
    commandId: overrides.commandId ?? "command-1",
    binding,
    projectCeilingRevision: "ceiling-1",
    runtimeAuthorizationGeneration: 7,
    requiredEffectEnforcerSetDigest: "5".repeat(64),
    causationId: "cause-1",
    actor: { kind: "human" as const, actorRef: "user-1" },
    issuedAtMs: 50,
    deadlineAtMs: 500,
    agentRunId: "run-1",
    runPolicyRevision: 1,
    fromRunStateVersion: overrides.from ?? 8,
    toRunStateVersion: overrides.to ?? 9,
    reason: "human" as const,
  };
  return Object.freeze({
    ...claims,
    authority: Object.freeze({
      issuerKeyId: "team-session-authority-1",
      audience: "runtime" as const,
      claimsDigest: digestRuntimeCommandClaims(claims),
      issuedAtMs: claims.issuedAtMs,
      expiresAtMs: 300,
      signature: "A".repeat(86),
      issuer: "team-session" as const,
      capability: "run.pause" as const,
    }),
  });
}

function enforcedReceipt(
  value: RuntimeLifecycleCommand,
  effectRef = "supervisor-effect-1"
): RuntimeReceipt {
  const requiredEffectEnforcerSetDigest = value.requiredEffectEnforcerSetDigest!;
  const enforcementSubjectDigest = digestRuntimeEnforcementSubject({
    version: 1,
    commandId: value.commandId,
    commandClaimsDigest: value.authority.claimsDigest,
    binding,
    runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest,
    effectRefCommitment: commitRuntimeEffectRef(effectRef),
    enforcedFence: value.toRunStateVersion,
  });
  const proof = {
    generation: value.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest,
    enforcementSubjectDigest,
    acknowledgements: [
      {
        enforcerRef: "runtime-enforcer-1",
        enforcerKind: "runtime" as const,
        acknowledgementDigest: "e".repeat(64),
      },
    ],
  };
  return {
    commandId: value.commandId,
    binding,
    runtimeAuthorizationGeneration: value.runtimeAuthorizationGeneration,
    outcome: "enforced",
    effectRef,
    enforcedFence: value.toRunStateVersion,
    aggregateEnforcementProof: {
      ...proof,
      aggregateProofDigest: digestAggregateEnforcementProof(proof),
    },
  };
}

function commandRequest(
  value: RuntimeLifecycleCommand,
  operationId = "operation-1"
): DaytonaSupervisorCommandRequest {
  const commandDigest = sha256(`terminalx/hosted-command/v1\0${canonicalRuntimeJson(value)}`);
  return Object.freeze({
    providerSandboxId: PROVIDER_ID,
    operationId,
    commandId: value.commandId,
    commandDigest,
    command: value,
    expectedRevision: 1,
    trust: Object.freeze({
      ...isolationTrust(),
      requiredEffectEnforcerSetDigest: "5".repeat(64),
    }),
  });
}

function isolationTrust() {
  return Object.freeze({
    supervisorArtifactDigest: "3".repeat(64),
    observationIssuerKeyId: "observation-key-1",
    observationPublicKeyDigest: "4".repeat(64),
  });
}

function hostedPlan(publicKeySpkiPem: string): HostedRuntimeAssignmentPlan {
  return Object.freeze({
    binding,
    runtimeAuthorizationGeneration: 7,
    incarnation: "1".repeat(64),
    specificationDigest: "2".repeat(64),
    effectEnforcerPolicyDigest: "3".repeat(64),
    adapterConfigurationRef: "daytona-production-v1",
    observation: Object.freeze({
      keyProvisioningRef: "observation-provisioning-1",
      issuerKeyId: "observation-key-1",
      publicKeySpkiPem,
    }),
    isolation: Object.freeze({
      isolationPolicyDigest: "3".repeat(64),
      publicAccess: false,
      hostMounts: false,
      linkedSandbox: false,
      rootIdentity: false,
      network: Object.freeze({
        mode: "blocked",
        policyDigest: "4".repeat(64),
        allowedDestinations: Object.freeze([]),
      }),
      resources: Object.freeze({ cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 256 }),
    }),
    capabilities: Object.freeze({
      isolatedExecution: true,
      brokeredCredentials: false,
      proxyOnlyEgress: false,
      checkpoints: false,
      yoloEligible: false,
    }),
  });
}

function isolationVerificationInput(plan: HostedRuntimeAssignmentPlan, privateKey: KeyObject) {
  const claims: DaytonaEffectiveIsolationClaims = Object.freeze({
    version: 1,
    providerIdentityCommitment: "5".repeat(64),
    providerRevision: 1,
    planDigest: sha256(
      `terminalx/hosted-runtime-assignment-plan/v1\0${canonicalRuntimeJson(plan)}`
    ),
    artifactDigest: "6".repeat(64),
    supervisorArtifactDigest: "7".repeat(64),
    sandboxUser: "terminalx",
    observationIssuerKeyId: plan.observation.issuerKeyId,
    observationPublicKeyDigest: sha256(plan.observation.publicKeySpkiPem),
    observationKeyProvisioningRefDigest: sha256(
      `terminalx/daytona-observation-key-provisioning-ref/v1\0${plan.observation.keyProvisioningRef}`
    ),
    isolationPolicyDigest: plan.isolation.isolationPolicyDigest,
    networkPolicyDigest: plan.isolation.network.policyDigest,
    runnerBinaryDigest: "8".repeat(64),
    resources: plan.isolation.resources,
    source: Object.freeze({
      baseCommit: TERMINALX_DAYTONA_BASE_SOURCE_COMMIT,
      hardenedCommit: "a".repeat(40),
      baseAncestryVerified: true,
    }),
    hardenedImage: Object.freeze({
      terminalxHardened: true,
      sandboxImageId: `sha256:${"b".repeat(64)}`,
      sandboxSnapshotRef: SANDBOX_SNAPSHOT_REF,
      sandboxProfileLabel: "io.terminalx.sandbox.profile=v1",
      entrypoint: "/usr/local/bin/terminalx-sandbox-init",
      useSnapshotEntrypoint: true,
      daytonaDaemonBundled: true,
      initializeDaemonTelemetry: false,
      providerSandboxTokenInjected: false,
      otelEnvironmentInjected: false,
      authorizationHeaderForwardedToSandbox: false,
      xDaytonaAuthorizationHeaderForwardedToSandbox: false,
      rootSecretsExcludedFromCheckpoints: true,
    }),
    runnerEnforcement: Object.freeze({
      resourceLimitsEnabled: true,
      xfsProjectQuotaEnabled: true,
      dockerDriver: "overlay2",
      backingFilesystem: "xfs",
      builtInSeccomp: true,
      dockerVersion: "docker-29.1.3",
      containerdVersion: "containerd-2.2.1",
      interSandboxNetworking: false,
      blockAllEgressInstalledBeforeStart: true,
      dockerUserEgressDropBeforeStart: true,
      inputHostNewDrop: true,
      inputEstablishedRepliesAllowed: true,
      genericBuildsDisabled: true,
      backupsDisabled: true,
      snapshotsDisabled: true,
      resizesDisabled: true,
    }),
    runnerNetwork: Object.freeze({
      label: "io.terminalx.runner-network=v1",
      driver: "bridge",
      scope: "local",
      internal: true,
      ipv4Only: true,
      interContainerCommunication: false,
      subnet: "172.20.0.0/16",
    }),
    controls: Object.freeze({
      publicAccess: false,
      hostMounts: false,
      linkedSandbox: false,
      rootIdentity: false,
      privileged: false,
      hostNetwork: false,
      capabilitiesDropped: true,
      capDropAll: true,
      rootInitCapAdd: Object.freeze(["CHOWN", "KILL", "SETGID", "SETUID"] as const),
      agentEffectiveCapabilitiesEmpty: true,
      agentPermittedCapabilitiesEmpty: true,
      agentInheritableCapabilitiesEmpty: true,
      agentAmbientCapabilitiesEmpty: true,
      agentNoNewPrivileges: true,
      noNewPrivileges: true,
      readOnlyRootFilesystem: false,
      privateWritableOverlay: true,
      zeroExternalMounts: true,
      imageDeclaredVolumes: 0,
      pidsLimit: 256,
      seccompProfileDigest: "d".repeat(64),
    }),
    processBoundary: Object.freeze({
      supervisorUid: 0,
      daytonaDaemonUid: 1000,
      agentUid: 1000,
      observationKeyOwnerUid: 0,
      stateOwnerUid: 0,
      rootOwnedLocalCredentialChannel: true,
      agentCanReadObservationKey: false,
      agentCanReadSupervisorState: false,
      agentCanAccessCredentialChannel: false,
      agentCanSignalSupervisor: false,
      agentCanWriteSupervisorExecutable: false,
      agentCanWriteEffectExecutor: false,
    }),
    observedAtMs: 100,
    expiresAtMs: 200,
  });
  const claimsDigest = sha256(
    `${DAYTONA_SUPERVISOR_ISOLATION_CLAIMS_DIGEST_DOMAIN}${canonicalRuntimeJson(claims)}`
  );
  const authorityStatement = Object.freeze({
    version: 1,
    issuer: "runtime-isolation-enforcer",
    issuerKeyId: "isolation-authority-1",
    audience: "terminalx-control-plane",
    capability: "runtime.isolation.attest",
    claimsDigest,
    issuedAtMs: 100,
    expiresAtMs: 200,
  });
  const signature = signEd25519(
    null,
    Buffer.from(
      `${DAYTONA_SUPERVISOR_ISOLATION_SIGNATURE_DOMAIN}${canonicalRuntimeJson(authorityStatement)}`
    ),
    privateKey
  ).toString("base64url");
  const attestation = Object.freeze({
    version: 1,
    kind: DAYTONA_EFFECTIVE_ISOLATION_ATTESTATION_KIND,
    claims,
    authority: Object.freeze({
      issuer: authorityStatement.issuer,
      issuerKeyId: authorityStatement.issuerKeyId,
      audience: authorityStatement.audience,
      capability: authorityStatement.capability,
      claimsDigest: authorityStatement.claimsDigest,
      issuedAtMs: authorityStatement.issuedAtMs,
      expiresAtMs: authorityStatement.expiresAtMs,
      signature,
    }),
  });
  return Object.freeze({
    attestation,
    plan,
    providerIdentityCommitment: claims.providerIdentityCommitment,
    artifactDigest: claims.artifactDigest,
    supervisorArtifactDigest: claims.supervisorArtifactDigest,
    observationIssuerKeyId: claims.observationIssuerKeyId,
    observationPublicKeyDigest: claims.observationPublicKeyDigest,
  });
}

async function collect(iterable: AsyncIterable<unknown>): Promise<readonly unknown[]> {
  const result: unknown[] = [];
  for await (const value of iterable) result.push(value);
  return result;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

void DaytonaSupervisorProtocolError;
void (null as DaytonaSupervisorIsolationRequest | null);
