import { describe, expect, it } from "vitest";
import type { RuntimeBinding } from "@/lib/team-sessions/contracts";
import type { RuntimeOutboxDelivery } from "@/lib/team-sessions/types";
import type {
  RuntimeCompensationCommand,
  RuntimeHandle,
  RuntimeLifecycleCommand,
} from "@/lib/runtime/contracts";
import type { RuntimeReceiptFollowLease } from "@/lib/runtime/runtime-receipt-follow-supervisor";
import {
  createHostedRuntimeAdapterBundle,
  digestHostedRuntimeAssignmentPlan,
  type HostedRuntimeAdapterBundle,
} from "@/lib/runtime/hosted-runtime-adapter";
import type {
  HostedAssignmentLookup,
  HostedControlPlaneCommandRequest,
  HostedControlPlaneCommandResult,
  HostedControlPlaneCreateRequest,
  HostedControlPlaneFollowRequest,
  HostedControlPlaneMutationRequest,
  HostedControlPlaneSandbox,
  HostedRuntimeAssignmentPlan,
  HostedRuntimeControlPlane,
} from "@/lib/runtime/hosted-runtime-control-plane";
import {
  InMemoryHostedAssignmentPlanSource,
  InMemoryHostedRuntimeControlPlane,
  InMemoryHostedRuntimeControlPlaneState,
} from "@/lib/runtime/in-memory-hosted-runtime-control-plane";
import { RuntimeEffectError } from "@/lib/runtime/local-tmux-runtime";

const NEVER_ABORT = new AbortController().signal;
const OPAQUE_KEY = new Uint8Array(32).fill(37);
const OBSERVATION_PUBLIC_KEY =
  "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAFf4/tX72aI7ln4nW9XH7z9xWMNJm9Q7A7jTZSlmWyNg=\n-----END PUBLIC KEY-----\n";
const OBSERVATION_PUBLIC_KEY_DIGEST =
  "ec5b0e02366725d7bc363e57aaf8709a5ac2c141cc9e9f52e958db2aeb20f883";

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

describe("hosted Runtime adapter", () => {
  it("creates exactly once and exposes one frozen provider-neutral capability bundle", async () => {
    const plan = assignmentPlan();
    const apply = ensureDelivery(plan, "apply");
    const source = sourceFor(plan, apply);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane(state));

    expect(Object.isFrozen(bundle)).toBe(true);
    expect(Object.isFrozen(bundle.assignmentRuntime)).toBe(true);
    expect(Object.isFrozen(bundle.runtime)).toBe(true);
    expect(Object.isFrozen(bundle.receiptTransport)).toBe(true);

    await bundle.assignmentRuntime.apply(apply, NEVER_ABORT);
    expect(state.countExact(plan)).toBe(1);

    const handle = await requireHandle(bundle, command);
    const providerId = state.providerIdsExact(plan)[0];
    expect(providerId).toBeDefined();
    expect(handle.opaqueHandleRef).toMatch(/^txh1_[A-Za-z0-9_-]{43}$/);
    expect(handle.opaqueHandleRef).not.toContain(providerId);

    const first = await bundle.runtime.command(handle, command, NEVER_ABORT);
    const duplicate = await bundle.runtime.command(handle, command, NEVER_ABORT);
    expect(duplicate).toEqual(first);
    expect(JSON.stringify(first)).not.toContain(providerId);
    expect(first).toMatchObject({ outcome: "accepted", commandId: command.commandId, binding });

    await bundle.close();
  });

  it("keeps apply and reconcile as distinct fail-closed dispatch paths", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "apply");
    const bundle = adapter(sourceFor(plan, delivery), new InMemoryHostedRuntimeControlPlane());

    expect(() => bundle.assignmentRuntime.reconcile(delivery, NEVER_ABORT)).toThrowError(
      expect.objectContaining({ code: "runtime_invalid_state" })
    );
    await bundle.close();
  });

  it("resolves receipt follow only for the plan's exact registered public observation key", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "apply", "outbox-follow-key");
    const source = sourceFor(plan, delivery);
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane());
    await bundle.assignmentRuntime.apply(delivery, NEVER_ABORT);
    const lease = Object.freeze({
      binding,
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      issuerKeyId: plan.observation.issuerKeyId,
      publicKeySpkiDigest: OBSERVATION_PUBLIC_KEY_DIGEST,
      checkpoint: null,
      attempt: 1,
      leaseOwner: "receipt-follow-worker-1",
      leaseVersion: 1,
      leaseExpiresAtMs: 2_000_000_030_000,
    }) satisfies RuntimeReceiptFollowLease;

    await expect(bundle.receiptFollowHandles.resolve(lease, NEVER_ABORT)).resolves.toMatchObject({
      binding,
    });
    await expect(
      bundle.receiptFollowHandles.resolve(
        { ...lease, publicKeySpkiDigest: "0".repeat(64) },
        NEVER_ABORT
      )
    ).rejects.toMatchObject({ code: "runtime_invalid_state" });
    await bundle.close();
  });

  it("blocks stale lifecycle handles and commands while preserving historical receipt follow", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "apply", "outbox-current-lifecycle");
    const source = sourceFor(plan, delivery);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const controlPlane = new CountingInMemoryHostedControlPlane(state);
    const bundle = adapter(source, controlPlane);
    await bundle.assignmentRuntime.apply(delivery, NEVER_ABORT);
    const lifecycleHandle = await requireHandle(bundle, command);

    const replacementBinding = Object.freeze({
      ...binding,
      runtimeAssignmentId: "assignment-current-replacement",
      runtimeAssignmentGeneration: 4,
      sandboxId: "sandbox-current-replacement",
      sandboxGeneration: 5,
      runtimePrincipalId: "principal-current-replacement",
    });
    source.registerBinding(assignmentPlan(replacementBinding, 8, "e"));
    controlPlane.resetCounts();

    await expect(bundle.lifecycleHandles.resolve(command, NEVER_ABORT)).resolves.toBeNull();
    await expect(
      bundle.runtime.command(lifecycleHandle, command, NEVER_ABORT)
    ).rejects.toMatchObject({ code: "runtime_invalid_state", retryable: false });
    expect(controlPlane.listExactCalls).toBe(0);
    expect(controlPlane.commandCalls).toBe(0);

    const lease = Object.freeze({
      binding,
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      issuerKeyId: plan.observation.issuerKeyId,
      publicKeySpkiDigest: OBSERVATION_PUBLIC_KEY_DIGEST,
      checkpoint: null,
      attempt: 1,
      leaseOwner: "historical-receipt-worker",
      leaseVersion: 1,
      leaseExpiresAtMs: 2_000_000_030_000,
    }) satisfies RuntimeReceiptFollowLease;
    const historicalHandle = await bundle.receiptFollowHandles.resolve(lease, NEVER_ABORT);
    expect(historicalHandle).not.toBeNull();
    state.appendObservation(plan, { cursor: "historical-cursor", outcome: "settled" });
    const iterator = bundle.receiptTransport
      .follow(historicalHandle as RuntimeHandle, null, NEVER_ABORT)
      [Symbol.asyncIterator]();
    await expect(iterator.next()).resolves.toEqual({
      done: false,
      value: { cursor: "historical-cursor", outcome: "settled" },
    });
    expect(controlPlane.listExactCalls).toBeGreaterThan(0);
    expect(controlPlane.followCalls).toBe(1);

    const containment = compensationCommand(plan);
    const containmentHandle = await bundle.compensationHandles.resolve(containment, NEVER_ABORT);
    expect(containmentHandle).not.toBeNull();
    await expect(
      bundle.runtime.command(containmentHandle as RuntimeHandle, containment, NEVER_ABORT)
    ).resolves.toMatchObject({
      receiptKind: "runtime.compensation",
      compensationId: containment.compensationId,
      outcome: "accepted",
    });
    expect(controlPlane.commandCalls).toBe(1);
    await bundle.close();
  });

  it("rejects proxy-only egress claims until a later phase supplies proof", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "apply", "outbox-unproven-proxy");
    const unprovenPlan = {
      ...plan,
      capabilities: { ...plan.capabilities, proxyOnlyEgress: true },
    } as unknown as HostedRuntimeAssignmentPlan;
    const source = new InMemoryHostedAssignmentPlanSource();
    source.registerBinding(unprovenPlan);
    source.registerDelivery(delivery, unprovenPlan);
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane());

    expect(() => bundle.assignmentRuntime.apply(delivery, NEVER_ABORT)).toThrowError(
      expect.objectContaining({ code: "runtime_invalid_state" })
    );
    await bundle.close();
  });

  it("reconciles an after-effect timeout across adapter restart without duplicating", async () => {
    const plan = assignmentPlan();
    const apply = ensureDelivery(plan, "apply", "outbox-ambiguous");
    const reconcile = ensureDelivery(plan, "reconcile", "outbox-ambiguous");
    const source = sourceFor(plan, apply, reconcile);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    state.faultNext({
      operation: "create",
      phase: "after",
      failure: "timeout",
    });
    const first = adapter(source, new InMemoryHostedRuntimeControlPlane(state), 15);

    await expect(first.assignmentRuntime.apply(apply, NEVER_ABORT)).rejects.toMatchObject({
      code: "runtime_timeout",
      retryable: true,
    });
    expect(state.countExact(plan)).toBe(1);
    const beforeRestart = await requireHandle(first, command);
    await first.close();

    const restarted = adapter(source, new InMemoryHostedRuntimeControlPlane(state));
    await restarted.assignmentRuntime.reconcile(reconcile, NEVER_ABORT);
    expect(state.countExact(plan)).toBe(1);
    const afterRestart = await requireHandle(restarted, command);
    expect(afterRestart.opaqueHandleRef).toBe(beforeRestart.opaqueHandleRef);

    await restarted.close();
  });

  it("fences and retires an ambiguously-created ensure after durable supersession", async () => {
    const oldPlan = assignmentPlan();
    const apply = ensureDelivery(oldPlan, "apply", "outbox-superseded-ensure");
    const reconcile = ensureDelivery(oldPlan, "reconcile", "outbox-superseded-ensure");
    const source = sourceFor(oldPlan, apply, reconcile);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    state.faultNext({ operation: "create", phase: "after", failure: "timeout" });
    const first = adapter(source, new InMemoryHostedRuntimeControlPlane(state), 15);

    await expect(first.assignmentRuntime.apply(apply, NEVER_ABORT)).rejects.toMatchObject({
      code: "runtime_timeout",
      retryable: true,
    });
    expect(state.list(oldPlan)).toMatchObject([{ state: "active" }]);
    await first.close();

    const replacementPlan = assignmentPlan(
      Object.freeze({
        ...binding,
        runtimeAssignmentId: "assignment-superseding",
        runtimeAssignmentGeneration: 4,
        sandboxId: "sandbox-superseding",
        sandboxGeneration: 5,
        runtimePrincipalId: "principal-superseding",
      }),
      8,
      "d"
    );
    source.registerBinding(replacementPlan);
    state.faultNext({ operation: "fence", phase: "after", failure: "timeout" });
    const second = adapter(source, new InMemoryHostedRuntimeControlPlane(state), 15);
    await expect(second.assignmentRuntime.reconcile(reconcile, NEVER_ABORT)).rejects.toMatchObject({
      code: "runtime_timeout",
      retryable: true,
    });
    expect(state.list(oldPlan)).toMatchObject([{ state: "fenced" }]);
    await second.close();

    const third = adapter(source, new InMemoryHostedRuntimeControlPlane(state));
    await expect(
      third.assignmentRuntime.reconcile(reconcile, NEVER_ABORT)
    ).resolves.toBeUndefined();
    expect(state.countExact(oldPlan)).toBe(0);
    await third.close();
  });

  it("retires superseded provisioning compute without activating or fencing it", async () => {
    const oldPlan = assignmentPlan();
    const delivery = ensureDelivery(oldPlan, "reconcile", "outbox-stale-provisioning");
    const source = sourceFor(oldPlan, delivery);
    const replacementPlan = assignmentPlan(
      Object.freeze({
        ...binding,
        runtimeAssignmentId: "assignment-after-provisioning",
        runtimeAssignmentGeneration: 4,
        sandboxId: "sandbox-after-provisioning",
        sandboxGeneration: 5,
        runtimePrincipalId: "principal-after-provisioning",
      }),
      8,
      "e"
    );
    source.registerBinding(replacementPlan);
    const controlPlane = new ProvisioningHostedControlPlane(oldPlan);
    const bundle = adapter(source, controlPlane);

    await expect(
      bundle.assignmentRuntime.reconcile(delivery, NEVER_ABORT)
    ).resolves.toBeUndefined();
    expect(controlPlane.createCalls).toBe(0);
    expect(controlPlane.fenceCalls).toBe(0);
    expect(controlPlane.retireCalls).toBe(1);
    expect(controlPlane.sandbox).toBeNull();

    await bundle.close();
  });

  it("does not expose a Runtime handle for provisioning compute", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "reconcile", "outbox-provisioning-handle");
    const controlPlane = new ProvisioningHostedControlPlane(plan);
    const bundle = adapter(sourceFor(plan, delivery), controlPlane);

    await expect(bundle.lifecycleHandles.resolve(command, NEVER_ABORT)).resolves.toBeNull();
    expect(controlPlane.createCalls).toBe(0);
    expect(controlPlane.sandbox?.state).toBe("provisioning");

    await bundle.close();
  });

  it("replays commandId plus digest after an ambiguous command response and rejects drift", async () => {
    const plan = assignmentPlan();
    const ensure = ensureDelivery(plan, "apply", "outbox-command-ambiguity");
    const source = sourceFor(plan, ensure);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const first = adapter(source, new InMemoryHostedRuntimeControlPlane(state), 15);
    await first.assignmentRuntime.apply(ensure, NEVER_ABORT);
    const handle = await requireHandle(first, command);
    state.faultNext({ operation: "command", phase: "after", failure: "timeout" });

    await expect(first.runtime.command(handle, command, NEVER_ABORT)).rejects.toMatchObject({
      code: "runtime_timeout",
      retryable: true,
    });
    await first.close();

    const restarted = adapter(source, new InMemoryHostedRuntimeControlPlane(state));
    const restartedHandle = await requireHandle(restarted, command);
    await expect(
      restarted.runtime.command(restartedHandle, command, NEVER_ABORT)
    ).resolves.toMatchObject({ outcome: "accepted", commandId: command.commandId });
    const drifted = Object.freeze({
      ...command,
      toRunStateVersion: command.toRunStateVersion + 1,
    }) satisfies RuntimeLifecycleCommand;
    await expect(
      restarted.runtime.command(restartedHandle, drifted, NEVER_ABORT)
    ).rejects.toMatchObject({ code: "runtime_conflict", retryable: false });

    await restarted.close();
  });

  it("rejects duplicate exact provider matches instead of selecting one", async () => {
    const plan = assignmentPlan();
    const apply = ensureDelivery(plan, "apply", "outbox-duplicate");
    const reconcile = ensureDelivery(plan, "reconcile", "outbox-duplicate");
    const source = sourceFor(plan, apply, reconcile);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane(state));

    await bundle.assignmentRuntime.apply(apply, NEVER_ABORT);
    state.injectDuplicate(plan);
    expect(state.countExact(plan)).toBe(2);
    await expect(bundle.assignmentRuntime.reconcile(reconcile, NEVER_ABORT)).rejects.toMatchObject({
      code: "runtime_conflict",
      retryable: false,
    });

    await bundle.close();
  });

  it("settles an already-fenced exact match after an ambiguous fence effect", async () => {
    const plan = assignmentPlan();
    const ensure = ensureDelivery(plan, "apply", "outbox-fence-ensure");
    const fenceApply = fenceDelivery(plan, "apply", "outbox-ambiguous-fence");
    const fenceReconcile = fenceDelivery(plan, "reconcile", "outbox-ambiguous-fence");
    const source = sourceFor(plan, ensure, fenceApply, fenceReconcile);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const first = adapter(source, new InMemoryHostedRuntimeControlPlane(state), 15);
    await first.assignmentRuntime.apply(ensure, NEVER_ABORT);
    const activeHandle = await requireHandle(first, command);
    state.faultNext({ operation: "fence", phase: "after", failure: "timeout" });

    await expect(first.assignmentRuntime.apply(fenceApply, NEVER_ABORT)).rejects.toMatchObject({
      code: "runtime_timeout",
      retryable: true,
    });
    expect(state.countExact(plan)).toBe(1);
    await expect(first.runtime.command(activeHandle, command, NEVER_ABORT)).rejects.toMatchObject({
      code: "runtime_invalid_state",
      retryable: false,
    });
    await first.close();

    const restarted = adapter(source, new InMemoryHostedRuntimeControlPlane(state));
    await expect(
      restarted.assignmentRuntime.reconcile(fenceReconcile, NEVER_ABORT)
    ).resolves.toBeUndefined();
    expect(state.countExact(plan)).toBe(1);
    await restarted.close();
  });

  it("fences the exact old provider plan when the Session advances to a new generation", async () => {
    const oldPlan = assignmentPlan(binding, 7, "c");
    const ensure = ensureDelivery(oldPlan, "apply", "outbox-generation-ensure");
    const fenceApply = fenceDelivery(oldPlan, "apply", "outbox-generation-fence", 8);
    const fenceReconcile = fenceDelivery(oldPlan, "reconcile", "outbox-generation-fence", 8);
    const source = sourceFor(oldPlan, ensure, fenceApply, fenceReconcile);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane(state));

    await bundle.assignmentRuntime.apply(ensure, NEVER_ABORT);
    const oldProviderId = state.providerIdsExact(oldPlan)[0];
    expect(oldProviderId).toBeDefined();
    expect(state.list(oldPlan)).toMatchObject([{ state: "active" }]);

    await bundle.assignmentRuntime.apply(fenceApply, NEVER_ABORT);
    expect(state.list(oldPlan)).toMatchObject([
      { providerSandboxId: oldProviderId, state: "fenced" },
    ]);
    const uncreatedNewPlan = assignmentPlan(binding, 8, "e");
    expect(state.countExact(uncreatedNewPlan)).toBe(0);

    await expect(
      bundle.assignmentRuntime.reconcile(fenceReconcile, NEVER_ABORT)
    ).resolves.toBeUndefined();
    expect(state.list(oldPlan)).toMatchObject([
      { providerSandboxId: oldProviderId, state: "fenced" },
    ]);
    await bundle.close();
  });

  it("retires only the exact stale assignment and preserves a replacement generation", async () => {
    const oldPlan = assignmentPlan();
    const replacementBinding = Object.freeze({
      ...binding,
      runtimeAssignmentId: "assignment-2",
      runtimeAssignmentGeneration: 4,
      sandboxId: "sandbox-2",
      sandboxGeneration: 5,
      runtimePrincipalId: "principal-2",
    });
    const replacementPlan = assignmentPlan(replacementBinding, 8, "e");
    const oldEnsure = ensureDelivery(oldPlan, "apply", "outbox-old-ensure");
    const replacementEnsure = ensureDelivery(replacementPlan, "apply", "outbox-replacement-ensure");
    const oldRetire = retireDelivery(oldPlan, "apply", "outbox-old-retire");
    const source = sourceFor(oldPlan, oldEnsure, oldRetire);
    source.registerDelivery(replacementEnsure, replacementPlan);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane(state));

    await bundle.assignmentRuntime.apply(oldEnsure, NEVER_ABORT);
    source.registerBinding(replacementPlan);
    await bundle.assignmentRuntime.apply(replacementEnsure, NEVER_ABORT);
    expect(state.countExact(oldPlan)).toBe(1);
    expect(state.countExact(replacementPlan)).toBe(1);

    await bundle.assignmentRuntime.apply(oldRetire, NEVER_ABORT);
    expect(state.countExact(oldPlan)).toBe(0);
    expect(state.countExact(replacementPlan)).toBe(1);

    await bundle.close();
  });

  it("redacts provider identifiers from handles, outcomes, observations, and raw errors", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "apply", "outbox-redaction");
    const source = sourceFor(plan, delivery);
    const state = new InMemoryHostedRuntimeControlPlaneState();
    const controlPlane = new LeakyInMemoryHostedControlPlane(state);
    const bundle = adapter(source, controlPlane);

    await bundle.assignmentRuntime.apply(delivery, NEVER_ABORT);
    const providerId = state.providerIdsExact(plan)[0] as string;
    const handle = await requireHandle(bundle, command);
    const receipt = await bundle.runtime.command(handle, command, NEVER_ABORT);
    expect(JSON.stringify({ handle, receipt })).not.toContain(providerId);

    state.appendObservation(plan, { cursor: "cursor-1", safeDetail: "settled" });
    state.appendObservation(plan, { cursor: "cursor-2", [providerId]: "unsafe-key" });
    const iterator = bundle.receiptTransport
      .follow(handle, null, NEVER_ABORT)
      [Symbol.asyncIterator]();
    await expect(iterator.next()).resolves.toEqual({
      done: false,
      value: { cursor: "cursor-1", safeDetail: "settled" },
    });
    await expect(iterator.next()).rejects.toMatchObject({
      code: "runtime_internal",
      message: "runtime_internal",
    });

    controlPlane.leakProviderId = providerId;
    let failure: unknown;
    try {
      await bundle.lifecycleHandles.resolve(command, NEVER_ABORT);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(RuntimeEffectError);
    expect(failure).toMatchObject({ code: "runtime_internal", message: "runtime_internal" });
    expect(String(failure)).not.toContain(providerId);

    await bundle.close();
  });

  it("fails closed when the exact delivery plan is unavailable", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "apply", "outbox-no-plan");
    const bundle = adapter(
      new InMemoryHostedAssignmentPlanSource(),
      new InMemoryHostedRuntimeControlPlane()
    );

    expect(() => bundle.assignmentRuntime.apply(delivery, NEVER_ABORT)).toThrowError(
      expect.objectContaining({ code: "runtime_invalid_state" })
    );
    await bundle.close();
  });

  it("rejects a durable payload whose canonical assignment-plan digest does not match", async () => {
    const plan = assignmentPlan();
    const valid = ensureDelivery(plan, "apply", "outbox-plan-digest");
    if (valid.payload.runtimeKind !== "daytona") throw new TypeError("Expected hosted delivery");
    const delivery = {
      ...valid,
      payload: { ...valid.payload, assignmentPlanDigest: "0".repeat(64) },
    } satisfies typeof valid;
    const source = sourceFor(plan, delivery);
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane());

    expect(() => bundle.assignmentRuntime.apply(delivery, NEVER_ABORT)).toThrowError(
      expect.objectContaining({ code: "runtime_invalid_state" })
    );
    await bundle.close();
  });

  it("requires an exact old-plan generation on hosted fence transitions", async () => {
    const plan = assignmentPlan();
    const valid = fenceDelivery(plan, "apply", "outbox-target-generation", 8);
    const source = sourceFor(plan);

    const missingTarget = {
      ...valid,
      payload: Object.fromEntries(
        Object.entries(valid.payload).filter(
          ([key]) => key !== "assignmentPlanRuntimeAuthorizationGeneration"
        )
      ),
    } as unknown as RuntimeOutboxDelivery;
    source.registerDelivery(missingTarget, plan);
    const missingBundle = adapter(source, new InMemoryHostedRuntimeControlPlane());
    expect(() => missingBundle.assignmentRuntime.apply(missingTarget, NEVER_ABORT)).toThrowError(
      expect.objectContaining({ code: "runtime_invalid_state" })
    );
    await missingBundle.close();

    const mismatchedTarget = {
      ...valid,
      payload: { ...valid.payload, assignmentPlanRuntimeAuthorizationGeneration: 6 },
    } satisfies typeof valid;
    source.registerDelivery(mismatchedTarget, plan);
    const mismatchedBundle = adapter(source, new InMemoryHostedRuntimeControlPlane());
    expect(() =>
      mismatchedBundle.assignmentRuntime.apply(mismatchedTarget, NEVER_ABORT)
    ).toThrowError(expect.objectContaining({ code: "runtime_invalid_state" }));
    await mismatchedBundle.close();
  });

  it("aborts outstanding availability and becomes permanently unavailable after disposal", async () => {
    const plan = assignmentPlan();
    const delivery = ensureDelivery(plan, "apply", "outbox-dispose");
    const source = sourceFor(plan, delivery);
    const bundle = adapter(source, new InMemoryHostedRuntimeControlPlane());
    const aborted = new AbortController();
    aborted.abort();

    expect(() => bundle.assignmentRuntime.apply(delivery, aborted.signal)).toThrowError(
      expect.objectContaining({ code: "runtime_timeout" })
    );
    await bundle[Symbol.asyncDispose]();
    expect(() => bundle.assignmentRuntime.apply(delivery, NEVER_ABORT)).toThrowError(
      expect.objectContaining({ code: "runtime_unavailable" })
    );
  });
});

class LeakyInMemoryHostedControlPlane extends InMemoryHostedRuntimeControlPlane {
  leakProviderId: string | null = null;

  override async listExact(
    plan: HostedRuntimeAssignmentPlan,
    signal: AbortSignal
  ): Promise<
    readonly import("@/lib/runtime/hosted-runtime-control-plane").HostedControlPlaneSandbox[]
  > {
    if (this.leakProviderId) throw new Error(`provider response mentioned ${this.leakProviderId}`);
    return super.listExact(plan, signal);
  }
}

class CountingInMemoryHostedControlPlane extends InMemoryHostedRuntimeControlPlane {
  listExactCalls = 0;
  commandCalls = 0;
  followCalls = 0;

  resetCounts(): void {
    this.listExactCalls = 0;
    this.commandCalls = 0;
    this.followCalls = 0;
  }

  override async listExact(
    ...args: Parameters<InMemoryHostedRuntimeControlPlane["listExact"]>
  ): ReturnType<InMemoryHostedRuntimeControlPlane["listExact"]> {
    this.listExactCalls += 1;
    return super.listExact(...args);
  }

  override async command(
    ...args: Parameters<InMemoryHostedRuntimeControlPlane["command"]>
  ): ReturnType<InMemoryHostedRuntimeControlPlane["command"]> {
    this.commandCalls += 1;
    return super.command(...args);
  }

  override follow(
    ...args: Parameters<InMemoryHostedRuntimeControlPlane["follow"]>
  ): ReturnType<InMemoryHostedRuntimeControlPlane["follow"]> {
    this.followCalls += 1;
    return super.follow(...args);
  }
}

class ProvisioningHostedControlPlane implements HostedRuntimeControlPlane {
  sandbox: HostedControlPlaneSandbox | null;
  createCalls = 0;
  fenceCalls = 0;
  retireCalls = 0;

  constructor(plan: HostedRuntimeAssignmentPlan) {
    this.sandbox = Object.freeze({
      providerSandboxId: "provider-provisioning-1",
      binding: plan.binding,
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      incarnation: plan.incarnation,
      specificationDigest: plan.specificationDigest,
      effectEnforcerPolicyDigest: plan.effectEnforcerPolicyDigest,
      adapterConfigurationRef: plan.adapterConfigurationRef,
      isolationPolicyDigest: plan.isolation.isolationPolicyDigest,
      state: "provisioning",
      revision: 1,
      activation: null,
    });
  }

  async listExact(): Promise<readonly HostedControlPlaneSandbox[]> {
    return this.sandbox === null ? Object.freeze([]) : Object.freeze([this.sandbox]);
  }

  async create(_request: HostedControlPlaneCreateRequest): Promise<HostedControlPlaneSandbox> {
    this.createCalls += 1;
    throw new Error("stale provisioning compute must never be activated");
  }

  async fence(_request: HostedControlPlaneMutationRequest): Promise<HostedControlPlaneSandbox> {
    this.fenceCalls += 1;
    throw new Error("unattested provisioning compute must not need a fence before deletion");
  }

  async retire(request: HostedControlPlaneMutationRequest): Promise<void> {
    this.retireCalls += 1;
    if (
      this.sandbox === null ||
      request.expected.providerSandboxId !== this.sandbox.providerSandboxId ||
      request.expected.state !== "provisioning"
    ) {
      throw new Error("unexpected provisioning retirement");
    }
    this.sandbox = null;
  }

  async command(
    _request: HostedControlPlaneCommandRequest
  ): Promise<HostedControlPlaneCommandResult> {
    throw new Error("provisioning compute is not command-ready");
  }

  follow(_request: HostedControlPlaneFollowRequest): AsyncIterable<unknown> {
    return Object.freeze({
      async *[Symbol.asyncIterator](): AsyncGenerator<unknown> {
        throw new Error("provisioning compute has no receipt stream");
      },
    });
  }

  async close(): Promise<void> {}
}

class TransitionAwareHostedPlanSource extends InMemoryHostedAssignmentPlanSource {
  override isCurrent(lookup: HostedAssignmentLookup): boolean {
    if (lookup.kind === "delivery" && lookup.delivery.kind !== "runtime.session.ensure") {
      // A destructive delivery is current as an explicitly registered desired
      // transition, even though its immutable target plan is historical.
      return this.resolve(lookup) !== null;
    }
    return super.isCurrent(lookup);
  }
}

function assignmentPlan(
  exactBinding: RuntimeBinding = binding,
  runtimeAuthorizationGeneration = 7,
  digestSeed = "c"
): HostedRuntimeAssignmentPlan {
  return Object.freeze({
    binding: exactBinding,
    runtimeAuthorizationGeneration,
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

function compensationCommand(plan: HostedRuntimeAssignmentPlan): RuntimeCompensationCommand {
  return {
    kind: "safety.quarantine",
    commandId: "historical-quarantine-command",
    compensationId: "historical-compensation",
    binding: plan.binding,
    observedRuntimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    source: {
      lifecycleCommandId: "historical-lifecycle-command",
      lifecycleCommandClaimsDigest: "1".repeat(64),
      lifecycleReceiptDigest: "2".repeat(64),
      lifecycleEnforcementSubjectDigest: "3".repeat(64),
      lifecycleAggregateProofDigest: "4".repeat(64),
      sourceRequiredEffectEnforcerSetDigest: "5".repeat(64),
    },
    platformSecurityPolicyRevision: "platform-security-policy:v1",
    requiredContainmentEnforcerSetDigest: "6".repeat(64),
    containment: {
      revokeTerminalWrites: true,
      stopProcessExecution: true,
      quarantineRuntime: true,
    },
    safetyFence: 9,
    exactBindingOnly: true,
    advanceBeyondCurrentFences: true,
    reasonRef: "historical-compensation:1",
    causationId: "historical-lifecycle-command",
    actor: { kind: "system", actorRef: "platform-security" },
    issuedAtMs: 100,
    deadlineAtMs: 1_000,
    authority: {
      issuer: "platform-security",
      issuerKeyId: "platform-security:v1",
      audience: "runtime",
      capability: "safety.quarantine",
      claimsDigest: "7".repeat(64),
      issuedAtMs: 100,
      expiresAtMs: 1_000,
      signature: "platform-signature",
    },
  };
}

function ensureDelivery(
  plan: HostedRuntimeAssignmentPlan,
  dispatchMode: RuntimeOutboxDelivery["dispatchMode"],
  outboxId = "outbox-ensure"
): Extract<RuntimeOutboxDelivery, { kind: "runtime.session.ensure" }> {
  return {
    outboxId,
    sessionId: plan.binding.sessionId,
    sessionSequence: 1,
    attempts: 1,
    leaseOwner: "hosted-runtime-worker-1",
    leaseExpiresAtMs: 2_000_000_030_000,
    dispatchMode,
    kind: "runtime.session.ensure",
    payload: {
      sessionId: plan.binding.sessionId,
      runtimeKind: "daytona",
      runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      binding: plan.binding,
      assignmentPlanRef: `assignment-plan:${outboxId}`,
      assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
    },
  };
}

function retireDelivery(
  plan: HostedRuntimeAssignmentPlan,
  dispatchMode: RuntimeOutboxDelivery["dispatchMode"],
  outboxId: string,
  runtimeAuthorizationGeneration = plan.runtimeAuthorizationGeneration + 1
): Extract<RuntimeOutboxDelivery, { kind: "runtime.session.retire" }> {
  return {
    outboxId,
    sessionId: plan.binding.sessionId,
    sessionSequence: 2,
    attempts: 1,
    leaseOwner: "hosted-runtime-worker-1",
    leaseExpiresAtMs: 2_000_000_030_000,
    dispatchMode,
    kind: "runtime.session.retire",
    payload: {
      sessionId: plan.binding.sessionId,
      runtimeKind: "daytona",
      runtimeAuthorizationGeneration,
      assignmentPlanRuntimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      reason: "emergency-stop",
      agentRunId: "run-1",
      runtimeAssignmentId: plan.binding.runtimeAssignmentId,
      runtimeAssignmentGeneration: plan.binding.runtimeAssignmentGeneration,
      sandboxId: plan.binding.sandboxId,
      sandboxGeneration: plan.binding.sandboxGeneration,
      binding: plan.binding,
      assignmentPlanRef: `assignment-plan:${outboxId}`,
      assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
    },
  };
}

function fenceDelivery(
  plan: HostedRuntimeAssignmentPlan,
  dispatchMode: RuntimeOutboxDelivery["dispatchMode"],
  outboxId: string,
  runtimeAuthorizationGeneration = plan.runtimeAuthorizationGeneration + 1
): Extract<RuntimeOutboxDelivery, { kind: "runtime.authorization.fence" }> {
  return {
    outboxId,
    sessionId: plan.binding.sessionId,
    sessionSequence: 2,
    attempts: 1,
    leaseOwner: "hosted-runtime-worker-1",
    leaseExpiresAtMs: 2_000_000_030_000,
    dispatchMode,
    kind: "runtime.authorization.fence",
    payload: {
      sessionId: plan.binding.sessionId,
      runtimeKind: "daytona",
      runtimeAuthorizationGeneration,
      assignmentPlanRuntimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
      reason: "assignee-loss",
      binding: plan.binding,
      assignmentPlanRef: `assignment-plan:${outboxId}`,
      assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(plan),
    },
  };
}

function sourceFor(
  plan: HostedRuntimeAssignmentPlan,
  ...deliveries: readonly RuntimeOutboxDelivery[]
): InMemoryHostedAssignmentPlanSource {
  const source = new TransitionAwareHostedPlanSource();
  source.registerBinding(plan);
  for (const delivery of deliveries) source.registerDelivery(delivery, plan);
  return source;
}

function adapter(
  plans: InMemoryHostedAssignmentPlanSource,
  controlPlane: HostedRuntimeControlPlane,
  operationTimeoutMs = 100
): HostedRuntimeAdapterBundle {
  return createHostedRuntimeAdapterBundle({
    plans,
    controlPlane,
    activationSink: Object.freeze({ register(): void {} }),
    opaqueHandleKey: OPAQUE_KEY,
    operationTimeoutMs,
  });
}

async function requireHandle(
  bundle: HostedRuntimeAdapterBundle,
  lifecycleCommand: RuntimeLifecycleCommand
): Promise<RuntimeHandle> {
  const handle = await bundle.lifecycleHandles.resolve(lifecycleCommand, NEVER_ABORT);
  expect(handle).not.toBeNull();
  return handle as RuntimeHandle;
}

function shaSeed(seed: string, offset: number): string {
  return String((seed.charCodeAt(0) + offset) % 16).repeat(64);
}
