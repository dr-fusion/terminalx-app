import { describe, expect, it } from "vitest";
import type { RuntimeBinding } from "@/lib/team-sessions/contracts";
import type { RuntimeOutboxDelivery } from "@/lib/team-sessions/types";
import type { RuntimeHandle, RuntimeLifecycleCommand } from "@/lib/runtime/contracts";
import {
  createHostedRuntimeAdapterBundle,
  digestHostedRuntimeAssignmentPlan,
  type HostedRuntimeAdapterBundle,
  type HostedRuntimeCapabilityActivation,
} from "@/lib/runtime/hosted-runtime-adapter";
import type { HostedRuntimeAssignmentPlan } from "@/lib/runtime/hosted-runtime-control-plane";
import {
  InMemoryHostedAssignmentPlanSource,
  InMemoryHostedRuntimeControlPlane,
  InMemoryHostedRuntimeControlPlaneState,
} from "@/lib/runtime/in-memory-hosted-runtime-control-plane";
import { InMemoryHostedRuntimeCapabilityActivation } from "@/lib/runtime/in-memory-hosted-runtime-capability-activation";
import {
  createHostedRuntimeCapabilityActivationVerifier,
  deriveMeasuredHostedRuntimeCapabilities,
  type HostedRuntimeCapabilityActivationQuery,
} from "@/lib/runtime/runtime-capability-activation-evidence";

const NEVER_ABORT = new AbortController().signal;
const OPAQUE_KEY = new Uint8Array(32).fill(37);
const OBSERVATION_PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFf4/tX72aI7ln4nW9XH7z9xWMNJm9Q7A7jTZSlmWyNg=\n-----END PUBLIC KEY-----\n";

const binding = Object.freeze({
  teamId: "team-1",
  projectId: "project-1",
  sessionId: "session-1",
  runtimeAssignmentId: "assignment-1",
  runtimeAssignmentGeneration: 3,
  sandboxId: "sandbox-1",
  sandboxGeneration: 4,
  runtimePrincipalId: "principal-1",
}) satisfies RuntimeBinding;

const command = {
  kind: "run.pause",
  commandId: "command-1",
  binding,
  projectCeilingRevision: "ceiling-1",
  runtimeAuthorizationGeneration: 7,
  requiredEffectEnforcerSetDigest: "b".repeat(64),
  causationId: "cause-1",
  actor: { kind: "human", actorRef: "user-1" },
  issuedAtMs: 50,
  deadlineAtMs: 400,
  authority: {
    issuerKeyId: "runtime-key:v1",
    audience: "runtime",
    claimsDigest: "a".repeat(64),
    issuedAtMs: 40,
    expiresAtMs: 500,
    signature: "signed-envelope",
    issuer: "team-session",
    capability: "run.pause",
  },
  agentRunId: "run-1",
  runPolicyRevision: 2,
  fromRunStateVersion: 8,
  toRunStateVersion: 9,
  reason: "human",
} as const satisfies RuntimeLifecycleCommand;

describe("hosted Runtime measured capability activation", () => {
  it("advertises the plan's false capabilities when no activation seam is supplied", async () => {
    const harness = await setup({ withSeam: false });
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities.brokeredCredentials).toBe(false);
    expect(handle.capabilities.proxyOnlyEgress).toBe(false);
    expect(handle.capabilities.isolatedExecution).toBe(true);
    await harness.bundle.close();
  });

  it("advertises brokered + proxy-only only for valid trust-group-signed measured evidence", async () => {
    const harness = await setup({ withSeam: true });
    harness.activation.seed(harness.query);
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities).toEqual({
      isolatedExecution: true,
      brokeredCredentials: true,
      proxyOnlyEgress: true,
      checkpoints: true,
      yoloEligible: false,
    });
    await harness.bundle.close();
  });

  it("fails closed for absent evidence", async () => {
    const harness = await setup({ withSeam: true });
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities.brokeredCredentials).toBe(false);
    expect(handle.capabilities.proxyOnlyEgress).toBe(false);
    await harness.bundle.close();
  });

  it("fails closed for a tampered signature", async () => {
    const harness = await setup({ withSeam: true });
    harness.activation.seed(harness.query, { tamperSignature: true });
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities.brokeredCredentials).toBe(false);
    expect(handle.capabilities.proxyOnlyEgress).toBe(false);
    await harness.bundle.close();
  });

  it("fails closed for evidence signed by a key outside the trust group", async () => {
    const harness = await setup({ withSeam: true });
    harness.activation.seed(harness.query, { signWithForeignKey: true });
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities.brokeredCredentials).toBe(false);
    expect(handle.capabilities.proxyOnlyEgress).toBe(false);
    await harness.bundle.close();
  });

  it("fails closed for stale evidence bound to a superseded boot epoch", async () => {
    const harness = await setup({ withSeam: true });
    harness.activation.seed(harness.query, { bootEpoch: harness.query.bootEpoch + 1 });
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities.brokeredCredentials).toBe(false);
    expect(handle.capabilities.proxyOnlyEgress).toBe(false);
    await harness.bundle.close();
  });

  it("advertises proxy-only egress but not brokered credentials for a partial measurement", async () => {
    const harness = await setup({ withSeam: true });
    harness.activation.seed(harness.query, {
      measurements: {
        ambientProviderCredentialsAbsent: false,
        brokerReachOnlyViaSupervisor: true,
        egressLockdownMeasured: true,
      },
    });
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities.proxyOnlyEgress).toBe(true);
    expect(handle.capabilities.brokeredCredentials).toBe(false);
    await harness.bundle.close();
  });

  it("withholds brokered credentials when egress lockdown is unmeasured", async () => {
    const harness = await setup({ withSeam: true });
    harness.activation.seed(harness.query, {
      measurements: {
        ambientProviderCredentialsAbsent: true,
        brokerReachOnlyViaSupervisor: true,
        egressLockdownMeasured: false,
      },
    });
    const handle = await requireHandle(harness.bundle, command);
    expect(handle.capabilities.brokeredCredentials).toBe(false);
    expect(handle.capabilities.proxyOnlyEgress).toBe(false);
    await harness.bundle.close();
  });

  it("carries measured capabilities through the vault into the command path", async () => {
    const harness = await setup({ withSeam: true });
    harness.activation.seed(harness.query);
    const handle = await requireHandle(harness.bundle, command);
    const receipt = await harness.bundle.runtime.command(handle, command, NEVER_ABORT);
    expect(receipt).toMatchObject({ outcome: "accepted", commandId: command.commandId });
    await harness.bundle.close();
  });
});

describe("measured capability-activation verifier and derivation", () => {
  it("rejects expired and excessive-TTL evidence at the verifier boundary", () => {
    const activation = new InMemoryHostedRuntimeCapabilityActivation();
    const query = sampleQuery();
    const evidence = activation.seed(query, { issuedAtMs: 1_000, expiresAtMs: 1_000 + 60_000 });
    const live = createHostedRuntimeCapabilityActivationVerifier({
      trustGroupPublicKeys: [activation.trustGroupKey],
      clock: () => 1_500,
    });
    const afterExpiry = createHostedRuntimeCapabilityActivationVerifier({
      trustGroupPublicKeys: [activation.trustGroupKey],
      clock: () => 1_000 + 60_000,
    });
    expect(live(evidence)).toBe(true);
    expect(afterExpiry(evidence)).toBe(false);
    expect(() =>
      createHostedRuntimeCapabilityActivationVerifier({
        trustGroupPublicKeys: [activation.trustGroupKey],
        maxEvidenceTtlMs: 10 * 60_000,
      })
    ).toThrow();
  });

  it("derives false for a query whose assignment identity differs from the evidence", () => {
    const activation = new InMemoryHostedRuntimeCapabilityActivation();
    const query = sampleQuery();
    activation.seed(query);
    const verify = activation.createVerifier({ clock: () => 1_000 });
    const otherGeneration: HostedRuntimeCapabilityActivationQuery = {
      ...query,
      runtimeAuthorizationGeneration: query.runtimeAuthorizationGeneration + 1,
    };
    const capabilities = deriveMeasuredHostedRuntimeCapabilities(
      PLAN_CAPABILITIES,
      otherGeneration,
      activation,
      verify
    );
    expect(capabilities.brokeredCredentials).toBe(false);
    expect(capabilities.proxyOnlyEgress).toBe(false);
  });
});

const PLAN_CAPABILITIES = Object.freeze({
  isolatedExecution: true,
  brokeredCredentials: false,
  proxyOnlyEgress: false,
  checkpoints: true,
  yoloEligible: false,
}) as HostedRuntimeAssignmentPlan["capabilities"];

function sampleQuery(): HostedRuntimeCapabilityActivationQuery {
  return {
    binding,
    runtimeAuthorizationGeneration: 7,
    assignmentPlanDigest: "1".repeat(64),
    effectEnforcerPolicyDigest: "2".repeat(64),
    effectEnforcerSetDigest: "3".repeat(64),
    bootEpoch: 1,
  };
}

async function setup(options: { withSeam: boolean }): Promise<{
  bundle: HostedRuntimeAdapterBundle;
  activation: InMemoryHostedRuntimeCapabilityActivation;
  query: HostedRuntimeCapabilityActivationQuery;
}> {
  const plan = assignmentPlan();
  const delivery = ensureDelivery(plan);
  const source = new InMemoryHostedAssignmentPlanSource();
  source.registerBinding(plan);
  source.registerDelivery(delivery, plan);
  const state = new InMemoryHostedRuntimeControlPlaneState();
  const controlPlane = new InMemoryHostedRuntimeControlPlane(state);
  const activation = new InMemoryHostedRuntimeCapabilityActivation();
  const capabilityActivation: HostedRuntimeCapabilityActivation = {
    source: activation,
    verify: activation.createVerifier({ clock: () => 1_000 }),
  };
  const bundle = createHostedRuntimeAdapterBundle({
    plans: source,
    controlPlane,
    activationSink: Object.freeze({ register(): void {} }),
    opaqueHandleKey: OPAQUE_KEY,
    operationTimeoutMs: 100,
    ...(options.withSeam ? { capabilityActivation } : {}),
  });
  await bundle.assignmentRuntime.apply(delivery, NEVER_ABORT);
  const sandbox = state.list(plan)[0];
  if (!sandbox || sandbox.activation === null) throw new Error("Expected active sandbox");
  const query: HostedRuntimeCapabilityActivationQuery = {
    binding: plan.binding,
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    assignmentPlanDigest: sandbox.activation.assignmentPlanDigest,
    effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
    effectEnforcerSetDigest: sandbox.activation.effectEnforcerSetDigest,
    bootEpoch: sandbox.activation.providerRevision,
  };
  return { bundle, activation, query };
}

async function requireHandle(
  bundle: HostedRuntimeAdapterBundle,
  lifecycleCommand: RuntimeLifecycleCommand
): Promise<RuntimeHandle> {
  const handle = await bundle.lifecycleHandles.resolve(lifecycleCommand, NEVER_ABORT);
  expect(handle).not.toBeNull();
  return handle as RuntimeHandle;
}

function assignmentPlan(): HostedRuntimeAssignmentPlan {
  const digestSeed = "c";
  return Object.freeze({
    binding,
    runtimeAuthorizationGeneration: 7,
    incarnation: digestSeed.repeat(64),
    specificationDigest: shaSeed(digestSeed, 1),
    effectEnforcerPolicyDigest: shaSeed(digestSeed, 4),
    adapterConfigurationRef: `adapter-config-${digestSeed}`,
    observation: Object.freeze({
      keyProvisioningRef: `runtime-observation-key-provisioning:${digestSeed}`,
      issuerKeyId: `runtime-observation-key:${digestSeed}`,
      publicKeySpkiPem: OBSERVATION_PUBLIC_KEY,
    }),
    isolation: Object.freeze({
      isolationPolicyDigest: shaSeed(digestSeed, 2),
      publicAccess: false,
      hostMounts: false,
      linkedSandbox: false,
      rootIdentity: false,
      network: Object.freeze({
        mode: "blocked" as const,
        policyDigest: shaSeed(digestSeed, 3),
        allowedDestinations: Object.freeze([]),
      }),
      resources: Object.freeze({ cpu: 2, memoryGiB: 4, diskGiB: 20, pids: 512 }),
    }),
    capabilities: Object.freeze({
      isolatedExecution: true,
      brokeredCredentials: false,
      proxyOnlyEgress: false,
      checkpoints: true,
      yoloEligible: false,
    }),
  });
}

function ensureDelivery(
  plan: HostedRuntimeAssignmentPlan
): Extract<RuntimeOutboxDelivery, { kind: "runtime.session.ensure" }> {
  return {
    outboxId: "outbox-ensure",
    sessionId: plan.binding.sessionId,
    sessionSequence: 1,
    attempts: 1,
    leaseOwner: "hosted-runtime-worker-1",
    leaseExpiresAtMs: 2_000_000_030_000,
    dispatchMode: "apply",
    kind: "runtime.session.ensure",
    payload: {
      sessionId: plan.binding.sessionId,
      runtimeKind: "daytona",
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      binding: plan.binding,
      assignmentPlanRef: "assignment-plan:outbox-ensure",
      assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
    },
  };
}

function shaSeed(seed: string, offset: number): string {
  return String((seed.charCodeAt(0) + offset) % 16).repeat(64);
}
