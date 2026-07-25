import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { describe, expect, it } from "vitest";
import type { DaytonaAssignmentBootstrapInstallRequest } from "../../src/lib/runtime/daytona-assignment-bootstrap-saga";
import {
  createDaytonaAssignmentKeyRegistry,
  type DaytonaAssignmentKeyRegistry,
} from "../../src/lib/runtime/daytona-assignment-key-registry";
import type { HostedRuntimeAssignmentPlan } from "../../src/lib/runtime/hosted-runtime-control-plane";
import type { HostedRuntimeObservationProvisioningRequest } from "../../src/lib/team-sessions/module";

const PROVIDER_ID = "123e4567-e89b-42d3-a456-426614174000";

describe("Daytona assignment key registry", () => {
  it("deterministically derives distinct assignment-scoped observation and effect keys", () => {
    const { registry, source } = registryFixture();
    expect(source.every((byte) => byte === 0)).toBe(true);
    const context = provisioningRequest();

    const firstRegistration = registry.provisionObservation(context);
    const replayRegistration = registry.provisionObservation(context);
    expect(replayRegistration).toEqual(firstRegistration);

    const nextRegistration = registry.provisionObservation({
      ...context,
      runtimeAuthorizationGeneration: context.runtimeAuthorizationGeneration + 1,
    });
    expect(nextRegistration.keyProvisioningRef).not.toBe(firstRegistration.keyProvisioningRef);
    expect(nextRegistration.issuerKeyId).not.toBe(firstRegistration.issuerKeyId);
    expect(nextRegistration.publicKeySpkiPem).not.toBe(firstRegistration.publicKeySpkiPem);

    const plan = hostedPlan(context, firstRegistration);
    const request = installRequest(plan);
    const firstKeys = registry.resolvePrivateKeys(request);
    const replayKeys = registry.resolvePrivateKeys(request);
    try {
      expect(replayKeys.observationPrivateKeyPkcs8Der).not.toBe(
        firstKeys.observationPrivateKeyPkcs8Der
      );
      expect(replayKeys.effectEnforcerPrivateKeyPkcs8Der).not.toBe(
        firstKeys.effectEnforcerPrivateKeyPkcs8Der
      );
      expect(replayKeys).toEqual(firstKeys);
      expect(firstKeys.observationPrivateKeyPkcs8Der).not.toEqual(
        firstKeys.effectEnforcerPrivateKeyPkcs8Der
      );
      expect(publicPem(firstKeys.observationPrivateKeyPkcs8Der)).toBe(
        firstRegistration.publicKeySpkiPem
      );

      const effect = registry.effectEnforcerIdentity(plan);
      expect(publicPem(firstKeys.effectEnforcerPrivateKeyPkcs8Der)).toBe(effect.publicKeySpkiPem);
      expect(publicDigest(firstKeys.effectEnforcerPrivateKeyPkcs8Der)).toBe(
        effect.publicKeySpkiDigest
      );
      expect(effect.enforcerRef).toContain(":master-2026-07:");
      expect(effect.enforcerKeyId).toContain(":master-2026-07:");
      expect(registry.effectEnforcerIdentity(plan)).toEqual(effect);
    } finally {
      firstKeys.observationPrivateKeyPkcs8Der.fill(0);
      firstKeys.effectEnforcerPrivateKeyPkcs8Der.fill(0);
      replayKeys.observationPrivateKeyPkcs8Der.fill(0);
      replayKeys.effectEnforcerPrivateKeyPkcs8Der.fill(0);
      registry.close();
    }
  });

  it("rejects a plan whose persisted public observation identity was not derived for its context", () => {
    const { registry } = registryFixture();
    const context = provisioningRequest();
    const registration = registry.provisionObservation(context);
    const plan = hostedPlan(context, {
      ...registration,
      issuerKeyId: `${registration.issuerKeyId}-tampered`,
    });

    expect(() => registry.resolvePrivateKeys(installRequest(plan))).toThrowError(
      expect.objectContaining({ code: "conflict" })
    );
    expect(() => registry.effectEnforcerIdentity(plan)).toThrowError(
      expect.objectContaining({ code: "conflict" })
    );

    const validPlan = hostedPlan(context, registration);
    const keys = registry.resolvePrivateKeys(installRequest(validPlan));
    keys.observationPrivateKeyPkcs8Der.fill(0);
    keys.effectEnforcerPrivateKeyPkcs8Der.fill(0);
    registry.close();
  });

  it("zeros caller key material on valid and rejected construction and fails closed after close", () => {
    const rejectedSource = Buffer.alloc(32, 0xa5);
    expect(() =>
      createDaytonaAssignmentKeyRegistry({
        masterKeyId: "invalid:key-id",
        masterKey: rejectedSource,
      })
    ).toThrowError(expect.objectContaining({ code: "invalid-state" }));
    expect(rejectedSource.every((byte) => byte === 0)).toBe(true);

    const { registry, source } = registryFixture();
    const context = provisioningRequest();
    const registration = registry.provisionObservation(context);
    const plan = hostedPlan(context, registration);
    expect(source.every((byte) => byte === 0)).toBe(true);
    registry.close();
    registry.close();

    for (const operation of [
      () => registry.provisionObservation(context),
      () => registry.effectEnforcerIdentity(plan),
      () => registry.resolvePrivateKeys(installRequest(plan)),
    ]) {
      expect(operation).toThrowError(expect.objectContaining({ code: "unavailable" }));
    }
  });

  it("rejects accessors, proxies, extra fields, and malformed assignment contexts", () => {
    const { registry } = registryFixture();
    const context = provisioningRequest();
    const accessor = Object.defineProperty({}, "binding", {
      enumerable: true,
      get() {
        throw new Error("must not execute");
      },
    });
    Object.assign(accessor, {
      runtimeAuthorizationGeneration: 7,
      incarnation: "a".repeat(64),
      adapterConfigurationRef: "daytona-production-v1",
    });

    for (const input of [
      { ...context, extra: true },
      { ...context, runtimeAuthorizationGeneration: 0 },
      { ...context, incarnation: "not-a-digest" },
      new Proxy(context, {}),
      accessor,
    ]) {
      expect(() =>
        registry.provisionObservation(input as HostedRuntimeObservationProvisioningRequest)
      ).toThrowError(expect.objectContaining({ code: "invalid-state" }));
    }
    registry.close();
  });
});

function registryFixture(): { registry: DaytonaAssignmentKeyRegistry; source: Buffer } {
  const source = Buffer.from(Array.from({ length: 32 }, (_value, index) => index + 1));
  const registry = createDaytonaAssignmentKeyRegistry({
    masterKeyId: "master-2026-07",
    masterKey: source,
  });
  return { registry, source };
}

function provisioningRequest(): HostedRuntimeObservationProvisioningRequest {
  return Object.freeze({
    binding: Object.freeze({
      teamId: "team-1",
      projectId: "project-1",
      sessionId: "session-1",
      runtimeAssignmentId: "assignment-1",
      runtimeAssignmentGeneration: 1,
      sandboxId: "sandbox-1",
      sandboxGeneration: 1,
      runtimePrincipalId: "principal-1",
    }),
    runtimeAuthorizationGeneration: 7,
    incarnation: "a".repeat(64),
    adapterConfigurationRef: "daytona-production-v1",
  });
}

function hostedPlan(
  context: HostedRuntimeObservationProvisioningRequest,
  observation: HostedRuntimeAssignmentPlan["observation"]
): HostedRuntimeAssignmentPlan {
  return Object.freeze({
    ...context,
    specificationDigest: "b".repeat(64),
    effectEnforcerPolicyDigest: "c".repeat(64),
    observation: Object.freeze(observation),
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
}

function installRequest(
  plan: HostedRuntimeAssignmentPlan
): DaytonaAssignmentBootstrapInstallRequest {
  return Object.freeze({
    providerSandboxId: PROVIDER_ID,
    plan,
    expectedRevision: 1,
    artifactDigest: "1".repeat(64),
    sandboxUser: "terminalx",
    supervisorArtifactDigest: "2".repeat(64),
  });
}

function publicPem(privateKeyPkcs8Der: Buffer): string {
  return String(
    createPublicKey(
      createPrivateKey({ key: privateKeyPkcs8Der, format: "der", type: "pkcs8" })
    ).export({ format: "pem", type: "spki" })
  );
}

function publicDigest(privateKeyPkcs8Der: Buffer): string {
  const publicDer = createPublicKey(
    createPrivateKey({ key: privateKeyPkcs8Der, format: "der", type: "pkcs8" })
  ).export({ format: "der", type: "spki" });
  return createHash("sha256").update(publicDer).digest("hex");
}
