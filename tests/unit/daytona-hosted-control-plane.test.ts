import { describe, expect, it, vi } from "vitest";
import type {
  RuntimeCommand,
  RuntimeLifecycleCommand,
  RuntimeReceipt,
} from "@/lib/runtime/contracts";
import {
  createDaytonaHostedRuntimeControlPlane,
  createPinnedDaytonaFetchApi,
  TERMINALX_DAYTONA_SOURCE_COMMIT,
  type DaytonaHostedControlPlaneConfiguration,
  type DaytonaSandboxApiPort,
  type DaytonaSandboxCreateBody,
  type DaytonaSandboxListRequest,
  type DaytonaSupervisorCommandOutcome,
  type PinnedDaytonaSupervisorTransport,
} from "@/lib/runtime/daytona-hosted-control-plane";
import { HostedControlPlaneError } from "@/lib/runtime/hosted-runtime-control-plane";
import type { DaytonaAssignmentBootstrapCoordinator } from "@/lib/runtime/daytona-assignment-bootstrap-saga";
import type {
  HostedControlPlaneSandbox,
  HostedRuntimeAssignmentPlan,
} from "@/lib/runtime/hosted-runtime-control-plane";
import { commitRuntimeEffectRef } from "@/lib/runtime/runtime-enforcement-proof";
import {
  digestAggregateEnforcementProof,
  digestRuntimeEnforcementSubject,
} from "@/lib/runtime/runtime-enforcement-proof";
import { digestHostedRuntimeAssignmentPlan } from "@/lib/runtime/hosted-runtime-adapter";
import { commitDaytonaProviderIdentity } from "@/lib/runtime/daytona-assignment-effect-manifest";

const EFFECT_ENFORCER_SET_DIGEST = "b".repeat(64);

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
  incarnation: "1".repeat(64),
  specificationDigest: "2".repeat(64),
  effectEnforcerPolicyDigest: "3".repeat(64),
  adapterConfigurationRef: "daytona-production-v1",
  observation: Object.freeze({
    keyProvisioningRef: "runtime-observation-provisioning:assignment-1:g7",
    issuerKeyId: "runtime-observation:assignment-1:g7",
    publicKeySpkiPem:
      "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA2gR9n1Vv6T6g9gxucZyyi2dKXr0/TYBVlC6V6dH3v8A=\n-----END PUBLIC KEY-----\n",
  }),
  isolation: Object.freeze({
    isolationPolicyDigest: "3".repeat(64),
    publicAccess: false as const,
    hostMounts: false as const,
    linkedSandbox: false as const,
    rootIdentity: false as const,
    network: Object.freeze({
      mode: "blocked" as const,
      policyDigest: "4".repeat(64),
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
}) satisfies HostedRuntimeAssignmentPlan;

const configuration = Object.freeze({
  sourceCommit: TERMINALX_DAYTONA_SOURCE_COMMIT,
  target: "eu",
  sandboxUser: "terminalx",
  artifact: Object.freeze({
    kind: "snapshot" as const,
    snapshotId: "123e4567-e89b-42d3-a456-426614174000",
    snapshotRef: `registry.example.com/terminalx/sandbox@sha256:${"5".repeat(64)}`,
    imageId: `sha256:${"8".repeat(64)}`,
    contentDigest: "5".repeat(64),
  }),
  supervisorArtifactDigest: "6".repeat(64),
  lifecycle: Object.freeze({
    autoStopIntervalMinutes: 0,
    autoArchiveIntervalMinutes: 0,
    autoDeleteIntervalMinutes: -1,
  }),
}) satisfies DaytonaHostedControlPlaneConfiguration;

describe("Daytona hosted control plane", () => {
  it("creates one private finite Sandbox and activates only after effective isolation attests", async () => {
    const fixture = controlPlaneFixture();
    const signal = new AbortController().signal;

    const sandbox = await fixture.controlPlane.create(
      { operationId: "operation-create-1", plan },
      signal
    );

    expect(sandbox).toMatchObject({ state: "active", revision: 1, binding });
    expect(fixture.api.createSandbox).toHaveBeenCalledOnce();
    const listRequest = fixture.api.listSandboxes.mock.calls[0]?.[0];
    expect(listRequest).toMatchObject({ cursor: null, limit: 100, isPublic: false });
    expect(listRequest?.labels).toEqual(
      expect.objectContaining({
        "terminalx.managed": "terminalx-hosted-runtime-v1",
        "terminalx.plan": expect.stringMatching(/^[0-9a-f]{64}$/),
        "terminalx.authorization-generation": String(plan.runtimeAuthorizationGeneration),
      })
    );
    expect(JSON.stringify(listRequest?.labels)).not.toContain(binding.sessionId);
    const body = fixture.api.createSandbox.mock.calls[0]?.[0];
    expect(body).toMatchObject({
      snapshot: configuration.artifact.snapshotId,
      user: "terminalx",
      public: false,
      target: "eu",
      cpu: 2,
      memory: 4,
      disk: 20,
      networkBlockAll: true,
      volumes: [],
      autoStopInterval: 0,
      autoArchiveInterval: 0,
      autoDeleteInterval: -1,
    });
    expect(body).not.toHaveProperty("linkedSandbox");
    expect(body).not.toHaveProperty("networkAllowList");
    expect(body?.labels["terminalx.state"]).toBe("provisioning");
    expect(fixture.supervisor.attestIsolation).toHaveBeenCalledWith(
      expect.objectContaining({
        plan,
        sandboxUser: "terminalx",
        trust: expect.objectContaining({
          supervisorArtifactDigest: configuration.supervisorArtifactDigest,
          observationIssuerKeyId: plan.observation.issuerKeyId,
        }),
      }),
      expect.any(AbortSignal)
    );
    expect(fixture.api.replaceLabels.mock.calls.at(-1)?.[1].labels["terminalx.state"]).toBe(
      "active"
    );
    expect(fixture.verifyIsolation).toHaveBeenCalledWith(
      expect.objectContaining({
        plan,
        artifactDigest: expect.stringMatching(/^[0-9a-f]{64}$/),
        providerIdentityCommitment: expect.stringMatching(/^[0-9a-f]{64}$/),
      })
    );
    expect(fixture.assignmentBootstrap.install).toHaveBeenCalledWith(
      expect.objectContaining({
        providerSandboxId: sandbox.providerSandboxId,
        plan,
        expectedRevision: 1,
        sandboxUser: "terminalx",
        supervisorArtifactDigest: configuration.supervisorArtifactDigest,
      }),
      expect.any(AbortSignal)
    );
    expect(fixture.assignmentBootstrap.install.mock.invocationCallOrder[0]).toBeLessThan(
      fixture.supervisor.attestIsolation.mock.invocationCallOrder[0]!
    );
    expect(fixture.supervisor.attestIsolation.mock.invocationCallOrder[0]).toBeLessThan(
      fixture.assignmentBootstrap.activate.mock.invocationCallOrder[0]!
    );
    expect(fixture.assignmentBootstrap.activate.mock.invocationCallOrder[0]).toBeLessThan(
      fixture.api.replaceLabels.mock.invocationCallOrder[0]!
    );
  });

  it("accepts the exact b5 label route's complete Sandbox response", async () => {
    const fixture = controlPlaneFixture();
    fixture.api.replaceLabels.mockImplementationOnce(async (providerSandboxId, body) => {
      const sandbox = fixture.provider.sandboxes.find(
        (candidate) => candidate.id === providerSandboxId
      );
      if (!sandbox) throw new Error("missing provider fixture");
      sandbox.labels = { ...body.labels };
      return structuredClone(sandbox);
    });

    await expect(
      fixture.controlPlane.create(
        { operationId: "operation-full-label-response", plan },
        new AbortController().signal
      )
    ).resolves.toMatchObject({ state: "active", revision: 1 });
  });

  it("leaves an ambiguous create in provisioning and reconciles the same Sandbox", async () => {
    const fixture = controlPlaneFixture();
    fixture.supervisor.attestIsolation.mockRejectedValueOnce(
      new HostedControlPlaneError("unavailable")
    );

    await expect(
      fixture.controlPlane.create(
        { operationId: "operation-create-ambiguous", plan },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("unavailable"));
    expect(fixture.provider.sandboxes).toHaveLength(1);
    expect(fixture.provider.sandboxes[0]?.labels["terminalx.state"]).toBe("provisioning");

    const observed = await fixture.controlPlane.listExact(plan, new AbortController().signal);
    expect(observed).toMatchObject([{ state: "provisioning", revision: 1 }]);
    expect(fixture.supervisor.attestIsolation).toHaveBeenCalledTimes(1);
    expect(fixture.api.replaceLabels).not.toHaveBeenCalled();

    const reconciled = await fixture.controlPlane.create(
      { operationId: "operation-create-ambiguous", plan },
      new AbortController().signal
    );
    expect(reconciled).toMatchObject({ state: "active", revision: 1 });
    expect(fixture.api.createSandbox).toHaveBeenCalledOnce();
    expect(fixture.assignmentBootstrap.install).toHaveBeenCalledTimes(2);
    expect(fixture.assignmentBootstrap.activate).toHaveBeenCalledOnce();
  });

  it("keeps provisioning closed when bootstrap is ambiguous and retries before attesting", async () => {
    const fixture = controlPlaneFixture();
    fixture.assignmentBootstrap.install.mockRejectedValueOnce(
      new HostedControlPlaneError("unavailable")
    );

    await expect(
      fixture.controlPlane.create(
        { operationId: "operation-bootstrap-ambiguous", plan },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("unavailable"));
    expect(fixture.provider.sandboxes).toHaveLength(1);
    expect(fixture.provider.sandboxes[0]?.labels["terminalx.state"]).toBe("provisioning");
    expect(fixture.supervisor.attestIsolation).not.toHaveBeenCalled();
    expect(fixture.assignmentBootstrap.activate).not.toHaveBeenCalled();
    expect(fixture.api.replaceLabels).not.toHaveBeenCalled();

    await expect(
      fixture.controlPlane.create(
        { operationId: "operation-bootstrap-ambiguous", plan },
        new AbortController().signal
      )
    ).resolves.toMatchObject({ state: "active", revision: 1 });
    expect(fixture.api.createSandbox).toHaveBeenCalledOnce();
    expect(fixture.assignmentBootstrap.install).toHaveBeenCalledTimes(2);
  });

  it("does not publish active labels until durable activation completes", async () => {
    const fixture = controlPlaneFixture();
    fixture.assignmentBootstrap.activate.mockRejectedValueOnce(
      new HostedControlPlaneError("unavailable")
    );

    await expect(
      fixture.controlPlane.create(
        { operationId: "operation-activation-ambiguous", plan },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("unavailable"));
    expect(fixture.provider.sandboxes[0]?.labels["terminalx.state"]).toBe("provisioning");
    expect(fixture.supervisor.attestIsolation).toHaveBeenCalledOnce();
    expect(fixture.api.replaceLabels).not.toHaveBeenCalled();

    await expect(
      fixture.controlPlane.create(
        { operationId: "operation-activation-ambiguous", plan },
        new AbortController().signal
      )
    ).resolves.toMatchObject({ state: "active" });
    expect(fixture.assignmentBootstrap.activate).toHaveBeenCalledTimes(2);
  });

  it("returns exact 0/1/many matches and fails closed on malformed provider detail", async () => {
    const empty = controlPlaneFixture();
    expect(await empty.controlPlane.listExact(plan, new AbortController().signal)).toEqual([]);

    const one = controlPlaneFixture();
    await one.controlPlane.create(
      { operationId: "operation-one", plan },
      new AbortController().signal
    );
    expect(await one.controlPlane.listExact(plan, new AbortController().signal)).toHaveLength(1);

    one.provider.sandboxes.push({
      ...structuredClone(one.provider.sandboxes[0]!),
      id: "123e4567-e89b-42d3-a456-426614174099",
    });
    expect(await one.controlPlane.listExact(plan, new AbortController().signal)).toHaveLength(2);

    one.provider.sandboxes[0]!.public = true;
    const failure = one.controlPlane.listExact(plan, new AbortController().signal);
    await expect(failure).rejects.toEqual(new HostedControlPlaneError("invalid-state"));
    await expect(failure).rejects.not.toHaveProperty("cause");
  });

  it("propagates caller cancellation to the lower Daytona transport", async () => {
    const fixture = controlPlaneFixture();
    let receivedSignal: AbortSignal | undefined;
    fixture.api.createSandbox.mockImplementationOnce(
      (_body, signal) =>
        new Promise((_resolve, reject) => {
          receivedSignal = signal;
          signal.addEventListener(
            "abort",
            () => reject(new DOMException("provider secret", "AbortError")),
            { once: true }
          );
        })
    );
    const controller = new AbortController();
    const operation = fixture.controlPlane.create(
      { operationId: "operation-abort", plan },
      controller.signal
    );
    await vi.waitFor(() => expect(receivedSignal).toBeInstanceOf(AbortSignal));
    controller.abort();
    await expect(operation).rejects.toEqual(new HostedControlPlaneError("timeout"));
    expect(receivedSignal?.aborted).toBe(true);
  });

  it("bounds and redacts provider failures", async () => {
    const fixture = controlPlaneFixture();
    fixture.api.listSandboxes.mockRejectedValueOnce(
      new Error("provider-sandbox-secret-id bearer-secret")
    );
    const operation = fixture.controlPlane.listExact(plan, new AbortController().signal);
    await expect(operation).rejects.toEqual(new HostedControlPlaneError("unavailable"));
    await expect(operation).rejects.not.toHaveProperty("cause");
    await expect(operation).rejects.not.toHaveProperty(
      "message",
      expect.stringContaining("provider-sandbox-secret-id")
    );
  });

  it("fences through pause plus an optimistic label revision and rejects stale expectations", async () => {
    const fixture = controlPlaneFixture();
    const active = await fixture.controlPlane.create(
      { operationId: "operation-fence-create", plan },
      new AbortController().signal
    );
    const stale = Object.freeze({ ...active, revision: active.revision + 1 });
    await expect(
      fixture.controlPlane.fence(
        { operationId: "operation-stale", plan, expected: stale },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("conflict"));
    expect(fixture.api.pauseSandbox).not.toHaveBeenCalled();

    const wrongProvider = Object.freeze({
      ...active,
      providerSandboxId: "provider-sandbox-does-not-exist",
    });
    await expect(
      fixture.controlPlane.fence(
        { operationId: "operation-wrong-provider", plan, expected: wrongProvider },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("conflict"));

    const fenced = await fixture.controlPlane.fence(
      { operationId: "operation-fence", plan, expected: active },
      new AbortController().signal
    );
    expect(fenced).toMatchObject({ state: "fenced", revision: 2 });
    expect(fixture.api.pauseSandbox).toHaveBeenCalledWith(
      active.providerSandboxId,
      expect.any(AbortSignal)
    );
    await expect(
      fixture.controlPlane.fence(
        { operationId: "operation-fence", plan, expected: active },
        new AbortController().signal
      )
    ).resolves.toEqual(fenced);
    expect(fixture.api.pauseSandbox).toHaveBeenCalledOnce();
  });

  it("retires only the exact expected provider identity and reconciles absence idempotently", async () => {
    const fixture = controlPlaneFixture();
    const active = await fixture.controlPlane.create(
      { operationId: "operation-retire-create", plan },
      new AbortController().signal
    );
    const stale = Object.freeze({ ...active, revision: 2 });
    await expect(
      fixture.controlPlane.retire(
        { operationId: "operation-retire-stale", plan, expected: stale },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("conflict"));
    expect(fixture.api.deleteSandbox).not.toHaveBeenCalled();

    await fixture.controlPlane.retire(
      { operationId: "operation-retire", plan, expected: active },
      new AbortController().signal
    );
    expect(fixture.provider.sandboxes).toHaveLength(0);
    expect(fixture.api.deleteSandbox.mock.invocationCallOrder[0]).toBeLessThan(
      fixture.assignmentBootstrap.retire.mock.invocationCallOrder[0]!
    );
    await expect(
      fixture.controlPlane.retire(
        { operationId: "operation-retire", plan, expected: active },
        new AbortController().signal
      )
    ).resolves.toBeUndefined();
  });

  it("independently authenticates commands and accepts only proof-backed enforced truth", async () => {
    const fixture = controlPlaneFixture();
    const active = await fixture.controlPlane.create(
      { operationId: "operation-command-create", plan },
      new AbortController().signal
    );
    const command = pauseCommand();
    const receipt = enforcedReceipt(command);
    fixture.supervisor.executeAuthenticated.mockResolvedValueOnce(commandOutcome(command, receipt));

    const result = await fixture.controlPlane.command(
      {
        operationId: "operation-command",
        plan,
        expected: active,
        commandId: command.commandId,
        commandDigest: "d".repeat(64),
        command,
      },
      new AbortController().signal
    );
    expect(result.receipt).toEqual(receipt);
    expect(fixture.effectTrust.registerManifest).toHaveBeenCalled();
    expect(fixture.effectTrust.registerAttestations).toHaveBeenCalledWith({
      effectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
      attestations: [{ signedFor: command.commandId }],
    });
    expect(fixture.verifyAuthority).toHaveBeenCalledWith({ command, nowMs: 100 });
    expect(fixture.supervisor.executeAuthenticated).toHaveBeenCalledWith(
      expect.objectContaining({
        command,
        trust: expect.objectContaining({
          requiredEffectEnforcerSetDigest: command.requiredEffectEnforcerSetDigest,
          observationIssuerKeyId: plan.observation.issuerKeyId,
        }),
      }),
      expect.any(AbortSignal)
    );

    fixture.verifyAuthority.mockReturnValueOnce(false);
    await expect(
      fixture.controlPlane.command(
        {
          operationId: "operation-command-denied",
          plan,
          expected: active,
          commandId: command.commandId,
          commandDigest: "e".repeat(64),
          command,
        },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("permission-denied"));
  });

  it("rejects accepted-only receipts, mismatched enforcer sets, and wrong observation issuers", async () => {
    const fixture = controlPlaneFixture();
    const active = await fixture.controlPlane.create(
      { operationId: "operation-command-negative-create", plan },
      new AbortController().signal
    );
    const command = pauseCommand();
    fixture.supervisor.executeAuthenticated.mockResolvedValueOnce(
      commandOutcome(command, {
        commandId: command.commandId,
        binding,
        runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
        outcome: "accepted",
        effectRef: "provider-effect",
      })
    );
    await expect(
      fixture.controlPlane.command(
        {
          operationId: "operation-accepted-only",
          plan,
          expected: active,
          commandId: command.commandId,
          commandDigest: "d".repeat(64),
          command,
        },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("invalid-state"));

    const mismatched = { ...command, requiredEffectEnforcerSetDigest: "f".repeat(64) };
    await expect(
      fixture.controlPlane.command(
        {
          operationId: "operation-enforcer-mismatch",
          plan,
          expected: active,
          commandId: mismatched.commandId,
          commandDigest: "e".repeat(64),
          command: mismatched,
        },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("permission-denied"));

    fixture.supervisor.followSigned.mockImplementationOnce(async function* () {
      yield {
        observation: signedObservation(command.commandId, "wrong-issuer"),
        attestations: [],
      };
    });
    const followed = fixture.controlPlane.follow(
      { plan, expected: active, checkpoint: null },
      new AbortController().signal
    );
    await expect(collect(followed)).rejects.toEqual(new HostedControlPlaneError("invalid-state"));
  });

  it("closes both transports, rejects later use, and does not erase provider state", async () => {
    const fixture = controlPlaneFixture();
    await fixture.controlPlane.create(
      { operationId: "operation-close-create", plan },
      new AbortController().signal
    );
    await fixture.controlPlane.close();
    await fixture.controlPlane.close();
    expect(fixture.api.close).toHaveBeenCalledOnce();
    expect(fixture.supervisor.close).toHaveBeenCalledOnce();
    expect(fixture.assignmentBootstrap.close).toHaveBeenCalledOnce();
    expect(fixture.provider.sandboxes).toHaveLength(1);
    await expect(
      fixture.controlPlane.listExact(plan, new AbortController().signal)
    ).rejects.toEqual(new HostedControlPlaneError("unavailable"));
  });

  it("rejects build-based image configuration before any provider request", () => {
    const imageConfiguration = {
      ...configuration,
      artifact: {
        kind: "image",
        imageReference: `registry.example.com/terminalx/supervisor@sha256:${"7".repeat(64)}`,
        contentDigest: "7".repeat(64),
      },
    };

    expect(() => controlPlaneFixture({ configuration: imageConfiguration as never })).toThrowError(
      new HostedControlPlaneError("invalid-state")
    );
  });

  it("rejects direct allowlist egress before provider creation", async () => {
    const allowlistPlan = structuredClone(plan) as HostedRuntimeAssignmentPlan;
    Object.assign(allowlistPlan.isolation.network, {
      mode: "allowlist",
      allowedDestinations: ["cidr:10.0.0.0/8", "domain:api.example.com"],
    });
    const fixture = controlPlaneFixture({ plan: allowlistPlan });

    await expect(
      fixture.controlPlane.create(
        { operationId: "operation-allowlist", plan: allowlistPlan },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("invalid-state"));
    expect(fixture.api.createSandbox).not.toHaveBeenCalled();
  });

  it("maps malformed private requests to the stable control-plane error surface", async () => {
    const fixture = controlPlaneFixture();
    const malformedPlan = {
      specificationDigest: "a".repeat(64),
      effectEnforcerPolicyDigest: "3".repeat(64),
      incarnation: "b".repeat(64),
    } as HostedRuntimeAssignmentPlan;

    await expect(
      fixture.controlPlane.listExact(malformedPlan, new AbortController().signal)
    ).rejects.toEqual(new HostedControlPlaneError("invalid-state"));
    await expect(
      fixture.controlPlane.command(
        {
          operationId: "operation-malformed-command",
          plan,
          expected: {} as never,
          commandId: "command-malformed",
          commandDigest: "c".repeat(64),
          command: "not-a-command" as never,
        },
        new AbortController().signal
      )
    ).rejects.toEqual(new HostedControlPlaneError("invalid-state"));
    expect(fixture.api.listSandboxes).not.toHaveBeenCalled();
    expect(fixture.supervisor.executeAuthenticated).not.toHaveBeenCalled();
  });

  it("rejects provider buildInfo even when the pinned snapshot id matches", async () => {
    const fixture = controlPlaneFixture();
    await fixture.controlPlane.create(
      { operationId: "operation-build-info", plan },
      new AbortController().signal
    );
    fixture.provider.sandboxes[0]!.buildInfo = {
      dockerfileContent: "FROM attacker.example/image:latest\n",
    };

    await expect(
      fixture.controlPlane.listExact(plan, new AbortController().signal)
    ).rejects.toEqual(new HostedControlPlaneError("invalid-state"));
  });
});

describe("pinned Daytona fetch API", () => {
  it("uses exact b5a5 routes, explicit scope, caller signal, and no ambient fallback", async () => {
    const calls: Array<{ url: URL; init: RequestInit }> = [];
    const fetchFunction = vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
      calls.push({ url: new URL(String(input)), init: init ?? {} });
      return Response.json({ items: [], nextCursor: null });
    }) as unknown as typeof fetch;
    const credential = new TextEncoder().encode("explicit-daytona-token");
    const api = createPinnedDaytonaFetchApi({
      endpoint: "https://daytona.example.test/api",
      organizationId: "organization-1",
      credential,
      fetch: fetchFunction,
    });
    const signal = new AbortController().signal;
    await api.listSandboxes(
      { labels: { "terminalx.plan": "a".repeat(64) }, cursor: null, limit: 100, isPublic: false },
      signal
    );

    expect(calls[0]?.url.pathname).toBe("/api/sandbox");
    expect(calls[0]?.url.searchParams.get("labels")).toBe(
      JSON.stringify({ "terminalx.plan": "a".repeat(64) })
    );
    expect(calls[0]?.url.searchParams.get("isPublic")).toBe("false");
    const headers = new Headers(calls[0]?.init.headers);
    expect(headers.get("authorization")).toBe("Bearer explicit-daytona-token");
    expect(headers.get("x-daytona-organization-id")).toBe("organization-1");
    expect(calls[0]?.init.signal).toBeInstanceOf(AbortSignal);
    expect(calls[0]?.init.redirect).toBe("error");

    await api.close();
    expect([...credential]).toEqual(new Array(credential.length).fill(0));
    await expect(
      api.listSandboxes({ labels: { x: "y" }, cursor: null, limit: 1, isPublic: false }, signal)
    ).rejects.toEqual(new HostedControlPlaneError("unavailable"));
  });

  it("rejects missing/default endpoints, insecure URLs, and invalid credentials", () => {
    const fetchFunction = vi.fn() as unknown as typeof fetch;
    expect(() =>
      createPinnedDaytonaFetchApi({
        endpoint: "http://daytona.example.test/api",
        organizationId: null,
        credential: new TextEncoder().encode("token"),
        fetch: fetchFunction,
      })
    ).toThrow(new HostedControlPlaneError("invalid-state"));
    expect(() =>
      createPinnedDaytonaFetchApi({
        endpoint: undefined as never,
        organizationId: null,
        credential: new TextEncoder().encode("token"),
        fetch: fetchFunction,
      })
    ).toThrow(new HostedControlPlaneError("invalid-state"));
    expect(() =>
      createPinnedDaytonaFetchApi({
        endpoint: "https://daytona.example.test/api",
        organizationId: null,
        credential: new TextEncoder().encode("Bearer ambient-token"),
        fetch: fetchFunction,
      })
    ).toThrow(new HostedControlPlaneError("invalid-state"));
    expect(fetchFunction).not.toHaveBeenCalled();
  });

  it("maps every mutating operation to the exact b5 sandbox route", async () => {
    const calls: Array<{ url: URL; init: RequestInit }> = [];
    const fetchFunction = vi.fn(async (input: URL | RequestInfo, init?: RequestInit) => {
      calls.push({ url: new URL(String(input)), init: init ?? {} });
      return Response.json({ labels: { "terminalx.state": "active" } });
    }) as unknown as typeof fetch;
    const api = createPinnedDaytonaFetchApi({
      endpoint: "https://daytona.example.test/api/",
      organizationId: null,
      credential: new TextEncoder().encode("explicit-api-key"),
      fetch: fetchFunction,
    });
    const signal = new AbortController().signal;
    const body = {
      name: "tx-sandbox",
      snapshot: "123e4567-e89b-42d3-a456-426614174000",
      user: "daytona",
      env: {},
      labels: { "terminalx.state": "provisioning" },
      public: false as const,
      target: "eu",
      cpu: 2,
      memory: 4,
      disk: 20,
      autoStopInterval: 0,
      autoArchiveInterval: 0,
      autoDeleteInterval: -1,
      volumes: [] as const,
      networkBlockAll: true,
    };

    await api.createSandbox(body, signal);
    await api.getSandbox("sandbox/id", signal);
    await api.pauseSandbox("sandbox/id", signal);
    await api.replaceLabels("sandbox/id", { labels: { "terminalx.state": "active" } }, signal);
    await api.deleteSandbox("sandbox/id", signal);

    expect(calls.map(({ url, init }) => [init.method, url.pathname])).toEqual([
      ["POST", "/api/sandbox"],
      ["GET", "/api/sandbox/sandbox%2Fid"],
      ["POST", "/api/sandbox/sandbox%2Fid/pause"],
      ["PUT", "/api/sandbox/sandbox%2Fid/labels"],
      ["DELETE", "/api/sandbox/sandbox%2Fid"],
    ]);
    expect(JSON.parse(String(calls[0]?.init.body))).toEqual(body);
    expect(JSON.parse(String(calls[3]?.init.body))).toEqual({
      labels: { "terminalx.state": "active" },
    });
    for (const call of calls) {
      expect(new Headers(call.init.headers).get("x-daytona-organization-id")).toBeNull();
      expect(call.init.signal).toBeInstanceOf(AbortSignal);
    }
    await api.close();
  });
});

function controlPlaneFixture(overrides?: {
  readonly plan?: HostedRuntimeAssignmentPlan;
  readonly configuration?: DaytonaHostedControlPlaneConfiguration;
}) {
  const selectedPlan = overrides?.plan ?? plan;
  const selectedConfiguration = overrides?.configuration ?? configuration;
  const provider = { sandboxes: [] as ProviderSandbox[] };
  const api = stubApi(provider, selectedConfiguration);
  const supervisor = stubSupervisor();
  const assignmentBootstrap = stubAssignmentBootstrap();
  const verifyIsolation = vi.fn(async () => true);
  const verifyAuthority = vi.fn(() => true);
  const effectTrust = {
    registerManifest: vi.fn(() => undefined),
    registerAttestations: vi.fn(() => undefined),
  };
  const controlPlane = createDaytonaHostedRuntimeControlPlane({
    configuration: selectedConfiguration,
    api,
    supervisor,
    assignmentBootstrap,
    effectTrust,
    verifyIsolationAttestation: verifyIsolation,
    verifyCommandAuthority: verifyAuthority,
    verifyLifecycleEnforcementProof: vi.fn(async () => true),
    verifyCompensationEnforcementProof: vi.fn(async () => true),
    clock: () => 100,
  });
  return {
    controlPlane,
    api,
    supervisor,
    assignmentBootstrap,
    verifyIsolation,
    verifyAuthority,
    effectTrust,
    provider,
    selectedPlan,
  };
}

interface ProviderSandbox {
  id: string;
  labels: Record<string, string>;
  state: string;
  desiredState: string;
  snapshot?: string;
  buildInfo?: { dockerfileContent: string; contextHashes?: string[] };
  user: string;
  public: boolean;
  networkBlockAll: boolean;
  networkAllowList?: string;
  domainAllowList?: string;
  target: string;
  cpu: number;
  memory: number;
  disk: number;
  volumes: unknown[];
  linkedSandboxId?: string;
}

function stubApi(
  provider: { sandboxes: ProviderSandbox[] },
  selectedConfiguration: DaytonaHostedControlPlaneConfiguration
) {
  const listSandboxes = vi.fn(
    async (_request: DaytonaSandboxListRequest, _signal: AbortSignal) => ({
      items: provider.sandboxes.map((sandbox) => ({ id: sandbox.id })),
      nextCursor: null,
    })
  );
  const createSandbox = vi.fn(async (body: DaytonaSandboxCreateBody, _signal: AbortSignal) => {
    const sandbox: ProviderSandbox = {
      id: `123e4567-e89b-42d3-a456-${String(provider.sandboxes.length + 1).padStart(12, "0")}`,
      labels: { ...body.labels },
      state: "started",
      desiredState: "started",
      snapshot: body.snapshot,
      user: body.user,
      public: body.public,
      networkBlockAll: body.networkBlockAll,
      ...(body.networkAllowList === undefined ? {} : { networkAllowList: body.networkAllowList }),
      ...(body.domainAllowList === undefined ? {} : { domainAllowList: body.domainAllowList }),
      target: body.target,
      cpu: body.cpu,
      memory: body.memory,
      disk: body.disk,
      volumes: [],
    };
    provider.sandboxes.push(sandbox);
    return structuredClone(sandbox);
  });
  const getSandbox = vi.fn(async (id: string, _signal: AbortSignal) => {
    const sandbox = provider.sandboxes.find((candidate) => candidate.id === id);
    if (!sandbox) throw new HostedControlPlaneError("conflict");
    return structuredClone(sandbox);
  });
  const pauseSandbox = vi.fn(async (id: string, _signal: AbortSignal) => {
    const sandbox = provider.sandboxes.find((candidate) => candidate.id === id);
    if (!sandbox) throw new Error("provider not found");
    sandbox.state = "paused";
    sandbox.desiredState = "paused";
    return structuredClone(sandbox);
  });
  const replaceLabels = vi.fn(
    async (id: string, body: { readonly labels: Readonly<Record<string, string>> }) => {
      const sandbox = provider.sandboxes.find((candidate) => candidate.id === id);
      if (!sandbox) throw new Error("provider not found");
      sandbox.labels = { ...body.labels };
      return { labels: structuredClone(sandbox.labels) };
    }
  );
  const deleteSandbox = vi.fn(async (id: string, _signal: AbortSignal) => {
    const index = provider.sandboxes.findIndex((candidate) => candidate.id === id);
    if (index >= 0) provider.sandboxes.splice(index, 1);
    return undefined;
  });
  const close = vi.fn(async () => undefined);
  void selectedConfiguration;
  return {
    listSandboxes,
    createSandbox,
    getSandbox,
    pauseSandbox,
    replaceLabels,
    deleteSandbox,
    close,
  } satisfies DaytonaSandboxApiPort;
}

function stubSupervisor() {
  const attestIsolation = vi.fn(async () => ({ kind: "signed-isolation-attestation" }));
  const executeAuthenticated = vi.fn<PinnedDaytonaSupervisorTransport["executeAuthenticated"]>(
    async () => {
      throw new Error("No command outcome configured");
    }
  );
  const followSigned = vi.fn<PinnedDaytonaSupervisorTransport["followSigned"]>(async function* () {
    return;
  });
  const close = vi.fn(async () => undefined);
  return { attestIsolation, executeAuthenticated, followSigned, close };
}

function stubAssignmentBootstrap(): DaytonaAssignmentBootstrapCoordinator & {
  readonly install: ReturnType<typeof vi.fn>;
  readonly activate: ReturnType<typeof vi.fn>;
  readonly retire: ReturnType<typeof vi.fn>;
  readonly close: ReturnType<typeof vi.fn>;
} {
  const install = vi.fn(async () => Object.freeze({ kind: "assignment.installed" }));
  const activate = vi.fn(async () => undefined);
  const resolveActivation = vi.fn(
    (request: Parameters<DaytonaAssignmentBootstrapCoordinator["resolveActivation"]>[0]) =>
      Object.freeze({
        version: 1 as const,
        kind: "hosted-runtime.activation" as const,
        binding: request.plan.binding,
        runtimeAuthorizationGeneration: request.plan.runtimeAuthorizationGeneration,
        assignmentPlanDigest: digestHostedRuntimeAssignmentPlan(request.plan),
        effectEnforcerPolicyDigest: request.plan.effectEnforcerPolicyDigest,
        providerIdentityCommitment: commitDaytonaProviderIdentity(request.providerSandboxId),
        providerRevision: request.expectedRevision,
        effectManifestBindingDigest: "a".repeat(64),
        effectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
      })
  );
  const resolveEffectManifest = vi.fn(() => ({ manifest: {}, activation: {} }));
  const retire = vi.fn(async () => undefined);
  const close = vi.fn(async () => undefined);
  return {
    install,
    activate,
    resolveActivation,
    resolveEffectManifest,
    retire,
    close,
  } as unknown as DaytonaAssignmentBootstrapCoordinator & {
    readonly install: ReturnType<typeof vi.fn>;
    readonly activate: ReturnType<typeof vi.fn>;
    readonly retire: ReturnType<typeof vi.fn>;
    readonly close: ReturnType<typeof vi.fn>;
  };
}

function pauseCommand(): Extract<RuntimeLifecycleCommand, { kind: "run.pause" }> {
  return {
    kind: "run.pause",
    commandId: "command-pause-1",
    binding,
    projectCeilingRevision: "ceiling-1",
    runtimeAuthorizationGeneration: plan.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest: EFFECT_ENFORCER_SET_DIGEST,
    causationId: "cause-1",
    actor: { kind: "human", actorRef: "user-1" },
    issuedAtMs: 50,
    deadlineAtMs: 400,
    authority: {
      issuerKeyId: "team-session-authority-1",
      audience: "runtime",
      claimsDigest: "a".repeat(64),
      issuedAtMs: 50,
      expiresAtMs: 300,
      signature: "signed-runtime-command",
      issuer: "team-session",
      capability: "run.pause",
    },
    agentRunId: "run-1",
    runPolicyRevision: 1,
    fromRunStateVersion: 8,
    toRunStateVersion: 9,
    reason: "human",
  };
}

function enforcedReceipt(command: Extract<RuntimeLifecycleCommand, { kind: "run.pause" }>) {
  const effectRef = "supervisor-effect-1";
  const requiredEffectEnforcerSetDigest = command.requiredEffectEnforcerSetDigest!;
  const enforcementSubjectDigest = digestRuntimeEnforcementSubject({
    version: 1,
    commandId: command.commandId,
    commandClaimsDigest: command.authority.claimsDigest,
    binding,
    runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
    requiredEffectEnforcerSetDigest,
    effectRefCommitment: commitRuntimeEffectRef(effectRef),
    enforcedFence: command.toRunStateVersion,
  });
  const proof = {
    generation: command.runtimeAuthorizationGeneration,
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
    commandId: command.commandId,
    binding,
    runtimeAuthorizationGeneration: command.runtimeAuthorizationGeneration,
    outcome: "enforced" as const,
    effectRef,
    enforcedFence: command.toRunStateVersion,
    aggregateEnforcementProof: {
      ...proof,
      aggregateProofDigest: digestAggregateEnforcementProof(proof),
    },
  } satisfies RuntimeReceipt;
}

function commandOutcome(
  command: RuntimeCommand,
  receipt: RuntimeReceipt
): DaytonaSupervisorCommandOutcome {
  return {
    commandId: command.commandId,
    commandDigest: "d".repeat(64),
    receipt,
    observation: signedObservation(command.commandId, plan.observation.issuerKeyId),
    attestations: [{ signedFor: command.commandId }],
  };
}

function signedObservation(commandId: string, issuerKeyId: string) {
  return {
    kind: "runtime.lifecycle-receipt-observed",
    command: { commandId },
    authority: {
      issuer: "runtime",
      issuerKeyId,
      signature: "A".repeat(86),
    },
  };
}

async function collect(iterable: AsyncIterable<unknown>): Promise<readonly unknown[]> {
  const values: unknown[] = [];
  for await (const value of iterable) values.push(value);
  return values;
}

void (null as HostedControlPlaneSandbox | null);
