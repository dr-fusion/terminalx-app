import {
  createHash,
  createPrivateKey,
  createPublicKey,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import type { DaytonaSupervisorBootstrapConfiguration } from "../packages/daytona-supervisor/src/daemon";
import { createDaytonaEffectiveIsolationVerifier } from "../packages/daytona-supervisor/src/effective-isolation";
import {
  DAYTONA_FORK_REPOSITORY,
  DAYTONA_PRODUCTION_FORK_COMMIT,
  createDaytonaAssignmentBootstrapTransport,
  createDaytonaAssignmentEffectManifest,
  createDaytonaAssignmentKeyRegistry,
  createDaytonaSupervisorRelayTransport,
  createDurableDaytonaAssignmentBootstrapCoordinator,
  createRuntimeEffectEnforcerTrustRouter,
  startDaytonaHostedMultiplayerService,
  type CreateDaytonaHostedMultiplayerServiceOptions,
  type DaytonaAssignmentBootstrapCoordinator,
  type DaytonaAssignmentBootstrapInstallRequest,
  type DaytonaAssignmentBootstrapTransport,
  type DaytonaAssignmentKeyRegistry,
  type DaytonaHostedMultiplayerService,
} from "../src/lib/runtime";
import type { RuntimeCommand } from "../src/lib/runtime/contracts";
import {
  createRuntimeCommandAuthorityIssuer,
  createRuntimeCommandAuthorityVerifier,
  type RuntimeCommandAuthorityIssuer,
} from "../src/lib/runtime/runtime-command-authority";
import { canonicalRuntimeJson } from "../src/lib/runtime/runtime-command-canonical";
import type { RuntimeCompensationMaterializationCandidate } from "../src/lib/runtime/runtime-compensation-materializer";
import type { RuntimeEffectEnforcerTrustRouter } from "../src/lib/runtime/runtime-effect-enforcer-trust-router";
import type { RuntimeSupervisorComponent } from "../src/lib/runtime/runtime-supervisor-composition";
import { markMultiplayerTransportAvailable } from "../src/lib/team-sessions/feature";
import type { RuntimeAuthorizationSnapshotQuery } from "../src/lib/team-sessions/module";
import { createHostedMultiplayerIngress } from "./hosted-multiplayer-ingress";
import {
  ProductionHostedRuntimeConfigurationError,
  type EnabledProductionHostedRuntimeConfiguration,
  type ProductionHostedRuntimePinnedIdentity,
} from "./production-hosted-runtime";
import {
  parseProductionDaytonaSettings,
  type ProductionDaytonaSettings,
} from "./production-daytona-settings";

const RUNTIME_ROOT = "/run/terminalx-root" as const;
const ASSIGNMENT_ROOT = `${RUNTIME_ROOT}/assignment` as const;
const SUPERVISOR_SOCKET = `${RUNTIME_ROOT}/supervisor.sock` as const;
const SUPERVISOR_STATE_ROOT = "/var/lib/terminalx-supervisor" as const;
const PEER_CREDENTIAL_EXECUTABLE = "/usr/local/libexec/terminalx/terminalx-peercred" as const;
const EFFECT_EXECUTABLE = "/usr/local/libexec/terminalx/terminalx-effect-enforcer" as const;
const HOSTED_PLAN_BINDING_DIGEST_DOMAIN = "terminalx/daytona-bootstrap-binding/v1\0" as const;
const SHA256 = /^[0-9a-f]{64}$/;
const ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const RELEASE_VERIFICATION_FIELDS = [
  "algorithm",
  "issuerKeyId",
  "claimsDigest",
  "canonicalPayload",
  "signature",
] as const;

interface ProductionCompositionOwners {
  keyRegistry?: DaytonaAssignmentKeyRegistry;
  bootstrapTransport?: DaytonaAssignmentBootstrapTransport;
  assignmentBootstrap?: DaytonaAssignmentBootstrapCoordinator;
  relay?: ReturnType<typeof createDaytonaSupervisorRelayTransport>;
  effectTrust?: RuntimeEffectEnforcerTrustRouter;
  ingress?: ReturnType<typeof createHostedMultiplayerIngress>;
}

/**
 * Concrete one-shot production graph. All protected settings are validated
 * before a private capability is constructed, and every partial owner is
 * closed in reverse dependency order on failure.
 */
export async function composeProductionDaytonaHostedRuntime(
  configuration: EnabledProductionHostedRuntimeConfiguration
): Promise<DaytonaHostedMultiplayerService> {
  const settings = parseProductionDaytonaSettings(configuration.publicConfiguration);
  const identities = configuration.publicConfiguration.identities;
  const clock = Date.now;
  const owners: ProductionCompositionOwners = {};
  let serviceStarted = false;

  try {
    const bootstrapAuthorityPrivateKey = privateKey(
      configuration.privateMaterial.bootstrapAuthorityPrivateKeyPkcs8
    );
    const effectManifestAuthorityPrivateKey = privateKey(
      configuration.privateMaterial.platformCompensationAuthorityPrivateKeyPkcs8
    );
    const effectManifestAuthorityPins = Object.freeze([
      Object.freeze({
        issuerKeyId: identities.platformCompensationAuthority.keyId,
        publicKeySpkiPem: identities.platformCompensationAuthority.publicKeySpkiPem,
        publicKeySpkiDigest: identities.platformCompensationAuthority.publicKeySpkiSha256,
      }),
    ]);

    owners.effectTrust = createRuntimeEffectEnforcerTrustRouter({
      pinnedManifestAuthorityPublicKeys: effectManifestAuthorityPins,
    });
    owners.keyRegistry = createDaytonaAssignmentKeyRegistry({
      masterKeyId: settings.bootstrap.assignmentMasterKeyId,
      masterKey: configuration.privateMaterial.assignmentMasterKey,
    });

    const bootstrapCredential = new Uint8Array(configuration.privateMaterial.runnerCredential);
    try {
      owners.bootstrapTransport = createDaytonaAssignmentBootstrapTransport({
        runnerOrigin: settings.runner.origin,
        runnerCaPem: settings.runner.caPem,
        runnerTlsSpkiSha256: settings.runner.tlsSpkiSha256,
        runnerCredential: bootstrapCredential,
        connectTimeoutMs: settings.runner.connectTimeoutMs,
        requestTimeoutMs: settings.runner.requestTimeoutMs,
      });
    } finally {
      bootstrapCredential.fill(0);
    }

    const relayCredential = new Uint8Array(configuration.privateMaterial.runnerCredential);
    try {
      owners.relay = createDaytonaSupervisorRelayTransport({
        runnerOrigin: settings.runner.origin,
        runnerCaPem: settings.runner.caPem,
        runnerTlsSpkiSha256: settings.runner.tlsSpkiSha256,
        runnerCredential: relayCredential,
        connectTimeoutMs: settings.runner.connectTimeoutMs,
        requestTimeoutMs: settings.runner.requestTimeoutMs,
        terminalLifetimeMs: settings.runner.terminalLifetimeMs,
        maximumPendingTerminalOutputBytes: settings.runner.maximumPendingTerminalOutputBytes,
        maximumFrameBytes: settings.runner.maximumFrameBytes,
      });
    } finally {
      relayCredential.fill(0);
    }

    owners.assignmentBootstrap = createAssignmentBootstrap({
      settings,
      identities,
      keyRegistry: owners.keyRegistry,
      transport: owners.bootstrapTransport,
      bootstrapAuthorityPrivateKey,
      effectManifestAuthorityPrivateKey,
      clock,
    });

    const teamAuthorityIssuer = createRuntimeCommandAuthorityIssuer({
      issuer: "team-session",
      issuerKeyId: identities.teamCommandAuthority.keyId,
      trustedConfigurationRoot: configuration.trustedConfigurationRoot,
      privateKeyFile: configuration.privateFiles.teamCommandAuthorityPrivateKey,
      clock,
      authorityTtlMs: settings.kernel.runtimeLifecycleCommandTtlMs,
    });
    const platformAuthorityIssuer = createRuntimeCommandAuthorityIssuer({
      issuer: "platform-security",
      issuerKeyId: identities.platformCompensationAuthority.keyId,
      trustedConfigurationRoot: configuration.trustedConfigurationRoot,
      privateKeyFile: configuration.privateFiles.platformCompensationAuthorityPrivateKey,
      clock,
      authorityTtlMs: settings.kernel.runtimeLifecycleCommandTtlMs,
    });
    const commandAuthorityVerifier = createRuntimeCommandAuthorityVerifier({
      pinnedPublicKeys: Object.freeze([
        runtimeAuthorityPin("team-session", identities.teamCommandAuthority),
        runtimeAuthorityPin("platform-security", identities.platformCompensationAuthority),
      ]),
      maximumAuthorityTtlMs: settings.supervisor.commandAuthorityMaximumTtlMs,
    });
    const verifyCommandAuthority = (input: {
      readonly command: RuntimeCommand;
      readonly nowMs: number;
    }): boolean => commandAuthorityVerifier(input);

    const verifyIsolationAttestation = createDaytonaEffectiveIsolationVerifier({
      issuerKeyId: settings.supervisor.isolation.issuerKeyId,
      issuerPublicKeySpkiPem: settings.supervisor.isolation.issuerPublicKeySpkiPem,
      hardenedDaytonaSourceCommit: settings.supervisor.isolation.hardenedDaytonaSourceCommit,
      expectedRunnerBinaryDigest: settings.provider.configuration.runnerBinaryDigest,
      expectedSandboxImageId: settings.provider.configuration.artifact.imageId,
      expectedSandboxSnapshotRef: settings.provider.configuration.artifact.snapshotRef,
      expectedSandboxUser: "terminalx",
      expectedSeccompProfileDigest: settings.supervisor.isolation.expectedSeccompProfileDigest,
      expectedDockerVersion: settings.supervisor.isolation.expectedDockerVersion,
      expectedContainerdVersion: settings.supervisor.isolation.expectedContainerdVersion,
      expectedProviderRevision: settings.supervisor.isolation.expectedProviderRevision,
      expectedSupervisorUid: settings.supervisor.isolation.expectedSupervisorUid,
      expectedDaytonaDaemonUid: settings.supervisor.isolation.expectedDaytonaDaemonUid,
      expectedAgentUid: settings.supervisor.isolation.expectedAgentUid,
      maximumAttestationTtlMs: settings.supervisor.isolation.maximumAttestationTtlMs,
      clock,
    });

    owners.ingress = createHostedMultiplayerIngress({
      credentialCheckIntervalMs: settings.ingress.credentialCheckIntervalMs,
      eventPollIntervalMs: settings.ingress.eventPollIntervalMs,
      monitorPollIntervalMs: settings.ingress.monitorPollIntervalMs,
      reportInternalError: reportHostedIngressError,
    });

    const service = await startDaytonaHostedMultiplayerService({
      deployment: {
        sourceEnvironment: {
          TERMINALX_DAYTONA_FORK_REPOSITORY: DAYTONA_FORK_REPOSITORY,
          TERMINALX_DAYTONA_PRODUCTION_FORK_COMMIT: DAYTONA_PRODUCTION_FORK_COMMIT,
        },
        manifest: settings.deployment.manifest,
        signatureVerifier: releaseSignatureVerifier(settings.deployment.releaseAuthority),
        measuredArtifacts: settings.deployment.measuredArtifacts,
      },
      runtimeProfile: settings.runtimeProfile,
      kernel: {
        filename: settings.kernel.filename,
        hostedRuntimeObservationProvisioner: owners.keyRegistry.provisionObservation,
        runtimeCommandAuthorityIssuer: teamAuthorityIssuer,
        runtimeAuthorizationSnapshotSource: authorizationSnapshotSource(settings),
        runtimeEnforcementProofVerifier: owners.effectTrust.verifyRuntimeEnforcementProof,
        runtimeLifecycleCommandTtlMs: settings.kernel.runtimeLifecycleCommandTtlMs,
        runtimeCompensationAuthorityIssuer: compensationAuthorityIssuer(platformAuthorityIssuer),
        runtimeCompensationAuthorityVerifier: ({ command, nowMs }) =>
          commandAuthorityVerifier({ command, nowMs }),
        runtimeCompensationPolicySource: compensationPolicySource(settings),
        runtimeCompensationEnforcementProofVerifier:
          owners.effectTrust.verifyRuntimeCompensationEnforcementProof,
      },
      provider: {
        endpoint: settings.provider.endpoint,
        organizationId: settings.provider.organizationId,
        credential: configuration.privateMaterial.daytonaApiCredential,
        fetch: requiredFetch(),
        configuration: settings.provider.configuration,
        supervisor: owners.relay,
        assignmentBootstrap: owners.assignmentBootstrap,
        terminal: owners.relay,
        verifyIsolationAttestation,
        verifyCommandAuthority,
      },
      trust: {
        effectTrust: owners.effectTrust,
        verifyLifecycleAuthority: ({ command, nowMs }) =>
          commandAuthorityVerifier({ command, nowMs }),
        verifyLifecycleEnforcementProof: owners.effectTrust.verifyRuntimeEnforcementProof,
        verifyCompensationAuthority: ({ command, nowMs }) =>
          commandAuthorityVerifier({ command, nowMs }),
        verifyCompensationEnforcementProof:
          owners.effectTrust.verifyRuntimeCompensationEnforcementProof,
      },
      adapter: {
        opaqueHandleKey: configuration.privateMaterial.opaqueHandleKey,
        operationTimeoutMs: settings.adapter.operationTimeoutMs,
      },
      supervisor: {
        workerIdPrefix: settings.supervisor.workerIdPrefix,
        clock,
        onOperationalError: reportHostedOperationalError,
      },
      ingress: owners.ingress,
      availability: Object.freeze({
        publish: markMultiplayerTransportAvailable,
      }),
    });
    serviceStarted = true;
    return service;
  } catch (error) {
    if (error instanceof ProductionHostedRuntimeConfigurationError) throw error;
    throw new ProductionHostedRuntimeConfigurationError("composition-unavailable");
  } finally {
    if (!serviceStarted) await closePartialComposition(owners);
  }
}

function createAssignmentBootstrap(options: {
  readonly settings: ProductionDaytonaSettings;
  readonly identities: EnabledProductionHostedRuntimeConfiguration["publicConfiguration"]["identities"];
  readonly keyRegistry: DaytonaAssignmentKeyRegistry;
  readonly transport: DaytonaAssignmentBootstrapTransport;
  readonly bootstrapAuthorityPrivateKey: KeyObject;
  readonly effectManifestAuthorityPrivateKey: KeyObject;
  readonly clock: () => number;
}): DaytonaAssignmentBootstrapCoordinator {
  const { settings, identities, keyRegistry, transport, clock } = options;
  return createDurableDaytonaAssignmentBootstrapCoordinator({
    pendingRoot: settings.bootstrap.pendingRoot,
    expectedOwnerUid: settings.bootstrap.expectedOwnerUid,
    authorityIssuerKeyId: identities.bootstrapAuthority.keyId,
    authoritySigningPrivateKey: options.bootstrapAuthorityPrivateKey,
    authorityTtlMs: settings.bootstrap.authorityTtlMs,
    buildEffectManifest: (request) => {
      const validFromMs = sampledClock(clock);
      return createDaytonaAssignmentEffectManifest({
        plan: request.plan,
        providerSandboxId: request.providerSandboxId,
        providerRevision: request.expectedRevision,
        effectEnforcerIdentity: keyRegistry.effectEnforcerIdentity(request.plan),
        authorityIssuerKeyId: identities.platformCompensationAuthority.keyId,
        authoritySigningPrivateKey: options.effectManifestAuthorityPrivateKey,
        validFromMs,
        expiresAtMs: safeAdd(validFromMs, settings.bootstrap.effectManifestTtlMs),
      });
    },
    buildBootstrapConfiguration: (request, manifest) =>
      bootstrapConfiguration(request, manifest, settings, identities),
    resolvePrivateKeys: keyRegistry.resolvePrivateKeys,
    closePrivateKeys: keyRegistry.close,
    transport,
    clock,
  });
}

function bootstrapConfiguration(
  request: DaytonaAssignmentBootstrapInstallRequest,
  manifest: unknown,
  settings: ProductionDaytonaSettings,
  identities: EnabledProductionHostedRuntimeConfiguration["publicConfiguration"]["identities"]
): DaytonaSupervisorBootstrapConfiguration {
  const bindingDigest = createHash("sha256")
    .update(HOSTED_PLAN_BINDING_DIGEST_DOMAIN, "utf8")
    .update(canonicalRuntimeJson(request.plan.binding), "utf8")
    .digest("hex");
  return Object.freeze({
    version: 1,
    kind: "terminalx.daytona-supervisor-bootstrap",
    assignment: Object.freeze({
      plan: request.plan,
      providerSandboxId: request.providerSandboxId,
      expectedRevision: request.expectedRevision,
      artifactDigest: request.artifactDigest,
      sandboxUser: request.sandboxUser,
      supervisorArtifactDigest: request.supervisorArtifactDigest,
      effectEnforcerSetDigest: manifestClaimsDigest(manifest),
      maxOperations: settings.supervisor.maxOperations,
    }),
    commandAuthority: Object.freeze({
      pinnedPublicKeys: Object.freeze([
        runtimeAuthorityPin("team-session", identities.teamCommandAuthority),
        runtimeAuthorityPin("platform-security", identities.platformCompensationAuthority),
      ]),
      maximumAuthorityTtlMs: settings.supervisor.commandAuthorityMaximumTtlMs,
    }),
    observation: Object.freeze({
      provisioningRecordFile: `${ASSIGNMENT_ROOT}/observation-provisioning.json`,
      observationTtlMs: settings.supervisor.observationTtlMs,
    }),
    transport: Object.freeze({
      socketDirectory: RUNTIME_ROOT,
      socketPath: SUPERVISOR_SOCKET,
      peerCredentialExecutableRoot: "/usr/local/libexec/terminalx",
      peerCredentialExecutableFile: PEER_CREDENTIAL_EXECUTABLE,
      peerCredentialExecutableSha256: settings.supervisor.transport.peerCredentialExecutableSha256,
      authenticationTimeoutMs: settings.supervisor.transport.authenticationTimeoutMs,
      requestTimeoutMs: settings.supervisor.transport.requestTimeoutMs,
      maximumFrameBytes: settings.supervisor.transport.maximumFrameBytes,
      maximumInflightRequests: settings.supervisor.transport.maximumInflightRequests,
    }),
    state: Object.freeze({
      stateDirectory: `${SUPERVISOR_STATE_ROOT}/${bindingDigest}`,
      stateFileName: "supervisor-state.json",
      signingPrivateKeyFile: `${ASSIGNMENT_ROOT}/state-signing.pk8`,
      verificationPublicKeyFile: `${ASSIGNMENT_ROOT}/state-verification.pem`,
      maxStateBytes: settings.supervisor.state.maxStateBytes,
    }),
    terminal: settings.supervisor.terminal,
    isolation: Object.freeze({
      attestationFile: `${RUNTIME_ROOT}/live/isolation-attestation.json`,
      ...settings.supervisor.isolation,
      expectedRunnerBinaryDigest: request.runnerBinaryDigest,
      expectedSandboxImageId: settings.provider.configuration.artifact.imageId,
      expectedSandboxSnapshotRef: settings.provider.configuration.artifact.snapshotRef,
      expectedSandboxUser: "terminalx" as const,
    }),
    effect: Object.freeze({
      executableRoot: "/usr/local/libexec/terminalx",
      executableFile: EFFECT_EXECUTABLE,
      executableSha256: settings.supervisor.effect.executableSha256,
      timeoutMs: settings.supervisor.effect.timeoutMs,
      maximumInputBytes: settings.supervisor.effect.maximumInputBytes,
      maximumOutputBytes: settings.supervisor.effect.maximumOutputBytes,
      manifest,
      pinnedManifestAuthorityPublicKeys: Object.freeze([
        Object.freeze({
          issuerKeyId: identities.platformCompensationAuthority.keyId,
          publicKeySpkiPem: identities.platformCompensationAuthority.publicKeySpkiPem,
          publicKeySpkiDigest: identities.platformCompensationAuthority.publicKeySpkiSha256,
        }),
      ]),
    }),
  });
}

function runtimeAuthorityPin(
  issuer: "team-session" | "platform-security",
  identity: ProductionHostedRuntimePinnedIdentity
) {
  return Object.freeze({
    issuer,
    issuerKeyId: identity.keyId,
    publicKeyPem: identity.publicKeySpkiPem,
  });
}

function authorizationSnapshotSource(settings: ProductionDaytonaSettings) {
  return Object.freeze({
    resolve(query: RuntimeAuthorizationSnapshotQuery) {
      if (
        !Number.isSafeInteger(query.runtimeAuthorizationGeneration) ||
        query.runtimeAuthorizationGeneration < 1
      ) {
        return undefined;
      }
      return Object.freeze({
        generation: query.runtimeAuthorizationGeneration,
        ...settings.kernel.authorization,
      });
    },
  });
}

function compensationAuthorityIssuer(issuer: RuntimeCommandAuthorityIssuer) {
  return Object.freeze({
    issue(
      claims: Parameters<
        CreateDaytonaHostedMultiplayerServiceOptions["kernel"]["runtimeCompensationAuthorityIssuer"]["issue"]
      >[0]
    ) {
      return issuer.issue(claims);
    },
  });
}

function compensationPolicySource(settings: ProductionDaytonaSettings) {
  return Object.freeze({
    resolve(incident: RuntimeCompensationMaterializationCandidate) {
      const digest = incident.source.sourceRequiredEffectEnforcerSetDigest;
      if (!SHA256.test(digest)) return undefined;
      return Object.freeze({
        platformSecurityPolicyRevision: settings.kernel.platformSecurityPolicyRevision,
        requiredContainmentEnforcerSetDigest: digest,
      });
    },
  });
}

function releaseSignatureVerifier(authority: {
  readonly keyId: string;
  readonly publicKeySpkiPem: string;
}) {
  const publicKey = createPublicKey(authority.publicKeySpkiPem);
  return (unsafeVerification: unknown): boolean => {
    try {
      const verification = exactRecord(unsafeVerification, RELEASE_VERIFICATION_FIELDS);
      const algorithm = field(verification, "algorithm");
      const issuerKeyId = field(verification, "issuerKeyId");
      const claimsDigest = field(verification, "claimsDigest");
      const canonicalPayload = field(verification, "canonicalPayload");
      const signature = field(verification, "signature");
      if (
        algorithm !== "ed25519" ||
        issuerKeyId !== authority.keyId ||
        typeof claimsDigest !== "string" ||
        !SHA256.test(claimsDigest) ||
        typeof canonicalPayload !== "string" ||
        Buffer.byteLength(canonicalPayload, "utf8") > 16 * 1024 ||
        typeof signature !== "string" ||
        !ED25519_SIGNATURE.test(signature)
      ) {
        return false;
      }
      const signatureBytes = Buffer.from(signature, "base64url");
      try {
        return (
          signatureBytes.byteLength === 64 &&
          verifyEd25519(null, Buffer.from(canonicalPayload, "utf8"), publicKey, signatureBytes)
        );
      } finally {
        signatureBytes.fill(0);
      }
    } catch {
      return false;
    }
  };
}

function manifestClaimsDigest(value: unknown): string {
  const record = exactRecord(value, [
    "version",
    "kind",
    "manifestId",
    "assignmentPlanDigest",
    "effectEnforcerPolicyDigest",
    "providerIdentityCommitment",
    "providerRevision",
    "effectManifestBindingDigest",
    "validFromMs",
    "expiresAtMs",
    "enforcers",
    "authority",
  ]);
  const authority = exactRecord(field(record, "authority"), [
    "issuer",
    "issuerKeyId",
    "audience",
    "capability",
    "claimsDigest",
    "issuedAtMs",
    "expiresAtMs",
    "signature",
  ]);
  const digest = field(authority, "claimsDigest");
  if (typeof digest !== "string" || !SHA256.test(digest)) invalidComposition();
  return digest;
}

function privateKey(bytes: Uint8Array): KeyObject {
  const copy = Buffer.from(bytes);
  try {
    const key = createPrivateKey(copy);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") invalidComposition();
    return key;
  } catch (error) {
    if (error instanceof ProductionHostedRuntimeConfigurationError) throw error;
    invalidComposition();
  } finally {
    copy.fill(0);
  }
}

function requiredFetch(): typeof fetch {
  const candidate = globalThis.fetch;
  if (typeof candidate !== "function") invalidComposition();
  return candidate.bind(globalThis);
}

function sampledClock(clock: () => number): number {
  const value = clock();
  if (!Number.isSafeInteger(value) || value < 0) invalidComposition();
  return value;
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result) || result <= left) invalidComposition();
  return result;
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    invalidComposition();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    invalidComposition();
  }
  for (const name of fields) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalidComposition();
  return descriptor.value;
}

function reportHostedIngressError(errorName: string): void {
  if (/^[A-Za-z][A-Za-z0-9_.-]{0,127}$/u.test(errorName)) {
    console.error(`[hosted-runtime] ingress failure: ${errorName}`);
  } else {
    console.error("[hosted-runtime] ingress failure");
  }
}

function reportHostedOperationalError(component: RuntimeSupervisorComponent): void {
  console.error(`[hosted-runtime] supervisor component failed: ${component}`);
}

async function closePartialComposition(owners: ProductionCompositionOwners): Promise<void> {
  const actions: Array<() => void | Promise<void>> = [];
  if (owners.ingress) actions.push(() => owners.ingress!.close());
  if (owners.relay) actions.push(() => owners.relay!.close());
  if (owners.assignmentBootstrap) actions.push(() => owners.assignmentBootstrap!.close());
  else {
    if (owners.bootstrapTransport) actions.push(() => owners.bootstrapTransport!.close());
    if (owners.keyRegistry) actions.push(() => owners.keyRegistry!.close());
  }
  if (owners.effectTrust) actions.push(() => owners.effectTrust!.close());
  for (const action of actions) {
    try {
      await action();
    } catch {
      // The original safe composition error remains authoritative.
    }
  }
}

function invalidComposition(): never {
  throw new ProductionHostedRuntimeConfigurationError("composition-unavailable");
}
