#!/usr/local/bin/node

import { createHash, createPrivateKey, createPublicKey, timingSafeEqual } from "node:crypto";
import { TextDecoder, types as nodeTypes } from "node:util";
import { verifyDaytonaAssignmentEffectManifestBinding } from "../../../src/lib/runtime/daytona-assignment-effect-manifest";
import {
  HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN,
  type HostedRuntimeAssignmentPlan,
} from "../../../src/lib/runtime/hosted-runtime-control-plane";
import { createRuntimeCommandAuthorityVerifier } from "../../../src/lib/runtime/runtime-command-authority";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import { readTrustedConfigurationFile } from "../../../src/lib/runtime/runtime-trusted-configuration-file";
import {
  createFileBackedDaytonaIsolationEvidenceSource,
  type CreateFileBackedDaytonaIsolationEvidenceSourceOptions,
} from "./effective-isolation";
import { createDaytonaSupervisorProofVerifierFactory } from "./effect-proof-verifiers";
import { createDaytonaDaemonPtyDriver } from "./daytona-daemon-pty-driver";
import { createPinnedLinuxPeerCredentialVerifier } from "./linux-peer-credentials";
import { createRootFileObservationCredentialResolver } from "./observation-credential-resolver";
import { createPinnedDaytonaEffectExecutor } from "./pinned-effect-executor";
import { createDaytonaSupervisorPtyRegistry } from "./pty-registry";
import { createSignedDaytonaSupervisorStateStore } from "./signed-state-store";
import { createPinnedDaytonaSupervisor, type DaytonaSupervisorConfiguration } from "./supervisor";
import { createDaytonaSupervisorUnixSocketServer } from "./unix-socket-transport";

const CONFIGURATION_KIND = "terminalx.daytona-supervisor-bootstrap" as const;
const PROVIDER_IDENTITY_DIGEST_DOMAIN = "terminalx/daytona-provider-identity/v1\0";
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const MAX_BOOTSTRAP_BYTES = 2 * 1024 * 1024;
const MAX_KEY_BYTES = 64 * 1024;

export interface DaytonaSupervisorBootstrapConfiguration {
  readonly version: 1;
  readonly kind: typeof CONFIGURATION_KIND;
  readonly assignment: {
    readonly plan: HostedRuntimeAssignmentPlan;
    readonly providerSandboxId: string;
    readonly expectedRevision: number;
    readonly artifactDigest: string;
    readonly sandboxUser: string;
    readonly supervisorArtifactDigest: string;
    readonly effectEnforcerSetDigest: string;
    readonly maxOperations: number;
  };
  readonly commandAuthority: {
    readonly pinnedPublicKeys: Parameters<
      typeof createRuntimeCommandAuthorityVerifier
    >[0]["pinnedPublicKeys"];
    readonly maximumAuthorityTtlMs: number;
  };
  readonly observation: {
    readonly provisioningRecordFile: string;
    readonly observationTtlMs: number;
  };
  readonly transport: {
    readonly socketDirectory: string;
    readonly socketPath: string;
    readonly peerCredentialExecutableRoot: string;
    readonly peerCredentialExecutableFile: string;
    readonly peerCredentialExecutableSha256: string;
    readonly authenticationTimeoutMs: number;
    readonly requestTimeoutMs: number;
    readonly maximumFrameBytes: number;
    readonly maximumInflightRequests: number;
  };
  readonly state: {
    readonly stateDirectory: string;
    readonly stateFileName: string;
    readonly signingPrivateKeyFile: string;
    readonly verificationPublicKeyFile: string;
    readonly maxStateBytes: number;
  };
  readonly terminal: {
    readonly requestTimeoutMs: number;
    readonly maximumLifetimeMs: number;
    readonly maximumTerminals: number;
    readonly maximumTerminalsPerSandbox: number;
    readonly maximumPendingOutputBytes: number;
    readonly maximumOutputFrameBytes: number;
    readonly maximumPendingWebSocketBytes: number;
  };
  readonly isolation: Omit<
    CreateFileBackedDaytonaIsolationEvidenceSourceOptions,
    "trustedConfigurationRoot" | "clock"
  >;
  readonly effect: {
    readonly executableRoot: string;
    readonly executableFile: string;
    readonly executableSha256: string;
    readonly timeoutMs: number;
    readonly maximumInputBytes: number;
    readonly maximumOutputBytes: number;
    readonly manifest: unknown;
    readonly pinnedManifestAuthorityPublicKeys: Parameters<
      typeof createDaytonaSupervisorProofVerifierFactory
    >[0]["pinnedManifestAuthorityPublicKeys"];
  };
}

async function main(): Promise<void> {
  if (
    typeof process.geteuid !== "function" ||
    process.geteuid() !== 0 ||
    process.argv.length !== 4
  ) {
    throw new TypeError();
  }
  const trustedConfigurationRoot = requiredArgument(process.argv[2]);
  const configurationFile = requiredArgument(process.argv[3]);
  const bytes = readTrustedConfigurationFile({
    trustedConfigurationRoot,
    filePath: configurationFile,
    minimumBytes: 2,
    maximumBytes: MAX_BOOTSTRAP_BYTES,
  });
  let configuration: DaytonaSupervisorBootstrapConfiguration;
  try {
    configuration = decodeDaytonaSupervisorBootstrapConfiguration(bytes);
  } finally {
    bytes.fill(0);
  }

  const controller = new AbortController();
  const abort = (): void => controller.abort();
  process.once("SIGINT", abort);
  process.once("SIGTERM", abort);

  const observationResolver = createRootFileObservationCredentialResolver({
    trustedConfigurationRoot,
    provisioningRecordFile: configuration.observation.provisioningRecordFile,
    observationTtlMs: configuration.observation.observationTtlMs,
  });
  const observationLease = await observationResolver.resolve(
    Object.freeze({
      keyProvisioningRef: configuration.assignment.plan.observation.keyProvisioningRef,
      binding: configuration.assignment.plan.binding,
      issuerKeyId: configuration.assignment.plan.observation.issuerKeyId,
      publicKeySpkiPem: configuration.assignment.plan.observation.publicKeySpkiPem,
    }),
    controller.signal
  );

  try {
    const statePrivateKey = readPrivateKey(
      trustedConfigurationRoot,
      configuration.state.signingPrivateKeyFile
    );
    const statePublicKey = readPublicKey(
      trustedConfigurationRoot,
      configuration.state.verificationPublicKeyFile
    );
    const assignment = configuration.assignment;
    const planDigest = sha256(
      `${HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN}${canonicalRuntimeJson(assignment.plan)}`
    );
    const providerIdentityCommitment = sha256(
      `${PROVIDER_IDENTITY_DIGEST_DOMAIN}${assignment.providerSandboxId}`
    );
    // Generic authority verification is deliberately performed before the
    // provider/plan semantic binding. Both gates must pass before constructing
    // an executor or opening the root supervisor socket.
    const proofVerifiers = createDaytonaSupervisorProofVerifierFactory({
      manifest: configuration.effect.manifest,
      pinnedManifestAuthorityPublicKeys: configuration.effect.pinnedManifestAuthorityPublicKeys,
    });
    const effectRecord = verifyDaytonaAssignmentEffectManifestBinding({
      manifest: configuration.effect.manifest,
      plan: assignment.plan,
      providerSandboxId: assignment.providerSandboxId,
      providerRevision: assignment.expectedRevision,
      nowMs: Date.now(),
    });
    if (
      !sameDigest(
        effectRecord.activation.effectEnforcerSetDigest,
        assignment.effectEnforcerSetDigest
      ) ||
      !sameDigest(
        effectRecord.activation.effectEnforcerPolicyDigest,
        assignment.plan.effectEnforcerPolicyDigest
      )
    ) {
      throw new TypeError();
    }
    const supervisorConfiguration: DaytonaSupervisorConfiguration = Object.freeze({
      binding: assignment.plan.binding,
      planDigest,
      providerIdentityCommitment,
      artifactDigest: assignment.artifactDigest,
      sandboxUser: assignment.sandboxUser,
      supervisorArtifactDigest: assignment.supervisorArtifactDigest,
      observationIssuerKeyId: assignment.plan.observation.issuerKeyId,
      observationPublicKeyDigest: sha256(assignment.plan.observation.publicKeySpkiPem),
      effectEnforcerSetDigest: assignment.effectEnforcerSetDigest,
      expectedRevision: assignment.expectedRevision,
      maxOperations: assignment.maxOperations,
    });
    const isolationEvidence = createFileBackedDaytonaIsolationEvidenceSource({
      ...configuration.isolation,
      trustedConfigurationRoot,
    });
    const supervisor = createPinnedDaytonaSupervisor({
      configuration: supervisorConfiguration,
      authorityVerifier: createRuntimeCommandAuthorityVerifier({
        pinnedPublicKeys: configuration.commandAuthority.pinnedPublicKeys,
        maximumAuthorityTtlMs: configuration.commandAuthority.maximumAuthorityTtlMs,
      }),
      lifecycleObservationIssuer: observationLease.lifecycleObservationIssuer,
      compensationObservationIssuer: observationLease.compensationObservationIssuer,
      isolationEvidence,
      effectExecutor: createPinnedDaytonaEffectExecutor({
        executableRoot: configuration.effect.executableRoot,
        executableFile: configuration.effect.executableFile,
        executableSha256: configuration.effect.executableSha256,
        expectedEffectEnforcerSetDigest: assignment.effectEnforcerSetDigest,
        expectedOwnerUid: 0,
        timeoutMs: configuration.effect.timeoutMs,
        maximumInputBytes: configuration.effect.maximumInputBytes,
        maximumOutputBytes: configuration.effect.maximumOutputBytes,
      }),
      proofVerifiers,
      stateStore: createSignedDaytonaSupervisorStateStore({
        stateDirectory: configuration.state.stateDirectory,
        stateFileName: configuration.state.stateFileName,
        signingPrivateKey: statePrivateKey,
        verificationPublicKey: statePublicKey,
        expectedOwnerUid: 0,
        maxStateBytes: configuration.state.maxStateBytes,
      }),
      clock: Date.now,
      observationId: (cursor) =>
        `daytona-observation:${sha256(canonicalRuntimeJson(assignment.plan.binding))}:${cursor}`,
    });
    const isolationRequest = Object.freeze({
      providerSandboxId: assignment.providerSandboxId,
      plan: assignment.plan,
      artifactDigest: assignment.artifactDigest,
      sandboxUser: assignment.sandboxUser,
      trust: Object.freeze({
        supervisorArtifactDigest: assignment.supervisorArtifactDigest,
        observationIssuerKeyId: assignment.plan.observation.issuerKeyId,
        observationPublicKeyDigest: sha256(assignment.plan.observation.publicKeySpkiPem),
      }),
    });
    const terminal = createDaytonaSupervisorPtyRegistry({
      providerSandboxId: assignment.providerSandboxId,
      expectedProviderRevision: assignment.expectedRevision,
      binding: assignment.plan.binding,
      planDigest,
      requireCurrentIsolation: () => {
        try {
          const evidence = isolationEvidence.read();
          return (
            isolationEvidence.verify({
              evidence,
              request: isolationRequest,
              providerIdentityCommitment,
            }) === true
          );
        } catch {
          return false;
        }
      },
      driver: createDaytonaDaemonPtyDriver({
        requestTimeoutMs: configuration.terminal.requestTimeoutMs,
        maximumPendingWebSocketBytes: configuration.terminal.maximumPendingWebSocketBytes,
      }),
      maximumTerminals: configuration.terminal.maximumTerminals,
      maximumTerminalsPerSandbox: configuration.terminal.maximumTerminalsPerSandbox,
      maximumPendingOutputBytes: configuration.terminal.maximumPendingOutputBytes,
      maximumOutputFrameBytes: configuration.terminal.maximumOutputFrameBytes,
    });
    const socketServer = createDaytonaSupervisorUnixSocketServer({
      supervisor,
      terminal,
      socketDirectory: configuration.transport.socketDirectory,
      socketPath: configuration.transport.socketPath,
      expectedOwnerUid: 0,
      expectedPeerUid: 0,
      expectedPeerGid: 0,
      verifyPeerCredentials: createPinnedLinuxPeerCredentialVerifier({
        executableRoot: configuration.transport.peerCredentialExecutableRoot,
        executableFile: configuration.transport.peerCredentialExecutableFile,
        executableSha256: configuration.transport.peerCredentialExecutableSha256,
        expectedOwnerUid: 0,
        timeoutMs: configuration.transport.authenticationTimeoutMs,
      }),
      authenticationTimeoutMs: configuration.transport.authenticationTimeoutMs,
      requestTimeoutMs: configuration.transport.requestTimeoutMs,
      terminalRequestTimeoutMs: configuration.terminal.maximumLifetimeMs,
      maximumFrameBytes: configuration.transport.maximumFrameBytes,
      maximumInflightRequests: configuration.transport.maximumInflightRequests,
    });
    await socketServer.listen();
    if (controller.signal.aborted) await socketServer.close();
    else
      controller.signal.addEventListener("abort", () => void socketServer.close(), { once: true });
    await socketServer.wait();
  } finally {
    controller.abort();
    process.removeListener("SIGINT", abort);
    process.removeListener("SIGTERM", abort);
    await observationLease.close().catch(() => undefined);
  }
}

/** Strict on-disk bootstrap format: canonical JSON followed by one LF. */
export function decodeDaytonaSupervisorBootstrapConfiguration(
  bytes: Uint8Array
): DaytonaSupervisorBootstrapConfiguration {
  if (!(bytes instanceof Uint8Array) || nodeTypes.isProxy(bytes) || bytes.byteLength < 3) {
    throw new TypeError();
  }
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!text.endsWith("\n")) throw new TypeError();
  const json = text.slice(0, -1);
  const configuration = snapshotDaytonaSupervisorBootstrapConfiguration(JSON.parse(json));
  if (canonicalRuntimeJson(configuration) !== json) throw new TypeError();
  return configuration;
}

export function snapshotDaytonaSupervisorBootstrapConfiguration(
  value: unknown
): DaytonaSupervisorBootstrapConfiguration {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, [
    "version",
    "kind",
    "assignment",
    "commandAuthority",
    "observation",
    "transport",
    "state",
    "terminal",
    "isolation",
    "effect",
  ]);
  if (field(record, "version") !== 1 || field(record, "kind") !== CONFIGURATION_KIND) {
    throw new TypeError();
  }
  const configuration = Object.freeze({
    version: 1,
    kind: CONFIGURATION_KIND,
    assignment: snapshotAssignment(field(record, "assignment")),
    commandAuthority: snapshotCommandAuthority(field(record, "commandAuthority")),
    observation: snapshotObservation(field(record, "observation")),
    transport: snapshotTransport(field(record, "transport")),
    state: snapshotState(field(record, "state")),
    terminal: snapshotTerminal(field(record, "terminal")),
    isolation: snapshotIsolation(field(record, "isolation")),
    effect: snapshotEffect(field(record, "effect")),
  });
  if (
    configuration.assignment.sandboxUser !== "terminalx" ||
    configuration.isolation.expectedSandboxUser !== "terminalx" ||
    configuration.isolation.expectedProviderRevision !==
      configuration.assignment.expectedRevision ||
    configuration.isolation.expectedSupervisorUid !== 0 ||
    configuration.isolation.expectedDaytonaDaemonUid === 0 ||
    configuration.isolation.expectedAgentUid === 0 ||
    configuration.assignment.plan.isolation.network.mode !== "blocked" ||
    configuration.assignment.plan.isolation.network.allowedDestinations.length !== 0 ||
    configuration.assignment.plan.capabilities.checkpoints !== false
  ) {
    throw new TypeError();
  }
  return configuration;
}

function snapshotAssignment(value: unknown): DaytonaSupervisorBootstrapConfiguration["assignment"] {
  const record = exactRecord(value, [
    "plan",
    "providerSandboxId",
    "expectedRevision",
    "artifactDigest",
    "sandboxUser",
    "supervisorArtifactDigest",
    "effectEnforcerSetDigest",
    "maxOperations",
  ]);
  const plan = snapshotRuntimeSupervisorPortableData(
    field(record, "plan")
  ) as HostedRuntimeAssignmentPlan;
  canonicalRuntimeJson(plan);
  safeReference(plan.observation.keyProvisioningRef);
  safeReference(plan.observation.issuerKeyId);
  if (typeof plan.observation.publicKeySpkiPem !== "string") throw new TypeError();
  return Object.freeze({
    plan,
    providerSandboxId: safeReference(field(record, "providerSandboxId")),
    expectedRevision: positiveInteger(field(record, "expectedRevision")),
    artifactDigest: digest(field(record, "artifactDigest")),
    sandboxUser: safeReference(field(record, "sandboxUser")),
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    effectEnforcerSetDigest: digest(field(record, "effectEnforcerSetDigest")),
    maxOperations: positiveInteger(field(record, "maxOperations")),
  });
}

function snapshotCommandAuthority(
  value: unknown
): DaytonaSupervisorBootstrapConfiguration["commandAuthority"] {
  const record = exactRecord(value, ["pinnedPublicKeys", "maximumAuthorityTtlMs"]);
  const pinnedPublicKeys = field(record, "pinnedPublicKeys");
  if (!Array.isArray(pinnedPublicKeys)) throw new TypeError();
  return Object.freeze({
    pinnedPublicKeys: snapshotRuntimeSupervisorPortableData(
      pinnedPublicKeys
    ) as DaytonaSupervisorBootstrapConfiguration["commandAuthority"]["pinnedPublicKeys"],
    maximumAuthorityTtlMs: positiveInteger(field(record, "maximumAuthorityTtlMs")),
  });
}

function snapshotObservation(
  value: unknown
): DaytonaSupervisorBootstrapConfiguration["observation"] {
  const record = exactRecord(value, ["provisioningRecordFile", "observationTtlMs"]);
  return Object.freeze({
    provisioningRecordFile: safeReference(field(record, "provisioningRecordFile")),
    observationTtlMs: positiveInteger(field(record, "observationTtlMs")),
  });
}

function snapshotTransport(value: unknown): DaytonaSupervisorBootstrapConfiguration["transport"] {
  const record = exactRecord(value, [
    "socketDirectory",
    "socketPath",
    "peerCredentialExecutableRoot",
    "peerCredentialExecutableFile",
    "peerCredentialExecutableSha256",
    "authenticationTimeoutMs",
    "requestTimeoutMs",
    "maximumFrameBytes",
    "maximumInflightRequests",
  ]);
  return Object.freeze({
    socketDirectory: absolutePath(field(record, "socketDirectory")),
    socketPath: absolutePath(field(record, "socketPath")),
    peerCredentialExecutableRoot: absolutePath(field(record, "peerCredentialExecutableRoot")),
    peerCredentialExecutableFile: absolutePath(field(record, "peerCredentialExecutableFile")),
    peerCredentialExecutableSha256: digest(field(record, "peerCredentialExecutableSha256")),
    authenticationTimeoutMs: positiveInteger(field(record, "authenticationTimeoutMs")),
    requestTimeoutMs: positiveInteger(field(record, "requestTimeoutMs")),
    maximumFrameBytes: positiveInteger(field(record, "maximumFrameBytes")),
    maximumInflightRequests: positiveInteger(field(record, "maximumInflightRequests")),
  });
}

function snapshotState(value: unknown): DaytonaSupervisorBootstrapConfiguration["state"] {
  const record = exactRecord(value, [
    "stateDirectory",
    "stateFileName",
    "signingPrivateKeyFile",
    "verificationPublicKeyFile",
    "maxStateBytes",
  ]);
  return Object.freeze({
    stateDirectory: safeReference(field(record, "stateDirectory")),
    stateFileName: safeReference(field(record, "stateFileName")),
    signingPrivateKeyFile: safeReference(field(record, "signingPrivateKeyFile")),
    verificationPublicKeyFile: safeReference(field(record, "verificationPublicKeyFile")),
    maxStateBytes: positiveInteger(field(record, "maxStateBytes")),
  });
}

function snapshotTerminal(value: unknown): DaytonaSupervisorBootstrapConfiguration["terminal"] {
  const record = exactRecord(value, [
    "requestTimeoutMs",
    "maximumLifetimeMs",
    "maximumTerminals",
    "maximumTerminalsPerSandbox",
    "maximumPendingOutputBytes",
    "maximumOutputFrameBytes",
    "maximumPendingWebSocketBytes",
  ]);
  const maximumTerminals = positiveInteger(field(record, "maximumTerminals"));
  const maximumTerminalsPerSandbox = positiveInteger(field(record, "maximumTerminalsPerSandbox"));
  if (maximumTerminals > 256 || maximumTerminalsPerSandbox > maximumTerminals) {
    throw new TypeError();
  }
  const maximumOutputFrameBytes = positiveInteger(field(record, "maximumOutputFrameBytes"));
  const maximumPendingOutputBytes = positiveInteger(field(record, "maximumPendingOutputBytes"));
  if (
    maximumOutputFrameBytes < 1024 ||
    maximumOutputFrameBytes > 64 * 1024 ||
    maximumPendingOutputBytes < maximumOutputFrameBytes ||
    maximumPendingOutputBytes > 16 * 1024 * 1024
  ) {
    throw new TypeError();
  }
  const requestTimeoutMs = positiveInteger(field(record, "requestTimeoutMs"));
  const maximumLifetimeMs = positiveInteger(field(record, "maximumLifetimeMs"));
  const maximumPendingWebSocketBytes = positiveInteger(
    field(record, "maximumPendingWebSocketBytes")
  );
  if (
    requestTimeoutMs < 100 ||
    requestTimeoutMs > 60_000 ||
    maximumLifetimeMs < 60_000 ||
    maximumLifetimeMs > 7 * 24 * 60 * 60_000 ||
    maximumPendingWebSocketBytes < 64 * 1024 ||
    maximumPendingWebSocketBytes > 1024 * 1024
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    requestTimeoutMs,
    maximumLifetimeMs,
    maximumTerminals,
    maximumTerminalsPerSandbox,
    maximumPendingOutputBytes,
    maximumOutputFrameBytes,
    maximumPendingWebSocketBytes,
  });
}

function snapshotIsolation(value: unknown): DaytonaSupervisorBootstrapConfiguration["isolation"] {
  const record = exactRecord(value, [
    "attestationFile",
    "issuerKeyId",
    "issuerPublicKeySpkiPem",
    "hardenedDaytonaSourceCommit",
    "expectedSandboxImageId",
    "expectedSandboxSnapshotRef",
    "expectedSandboxUser",
    "expectedSeccompProfileDigest",
    "expectedDockerVersion",
    "expectedContainerdVersion",
    "expectedProviderRevision",
    "expectedSupervisorUid",
    "expectedDaytonaDaemonUid",
    "expectedAgentUid",
    "maximumAttestationTtlMs",
  ]);
  return Object.freeze({
    attestationFile: safeReference(field(record, "attestationFile")),
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    issuerPublicKeySpkiPem: canonicalPublicKeyPem(field(record, "issuerPublicKeySpkiPem")),
    hardenedDaytonaSourceCommit: safeReference(field(record, "hardenedDaytonaSourceCommit")),
    expectedSandboxImageId: safeReference(field(record, "expectedSandboxImageId")),
    expectedSandboxSnapshotRef: safeReference(field(record, "expectedSandboxSnapshotRef")),
    expectedSandboxUser: terminalxUser(field(record, "expectedSandboxUser")),
    expectedSeccompProfileDigest: digest(field(record, "expectedSeccompProfileDigest")),
    expectedDockerVersion: safeReference(field(record, "expectedDockerVersion")),
    expectedContainerdVersion: safeReference(field(record, "expectedContainerdVersion")),
    expectedProviderRevision: positiveInteger(field(record, "expectedProviderRevision")),
    expectedSupervisorUid: nonNegativeInteger(field(record, "expectedSupervisorUid")),
    expectedDaytonaDaemonUid: nonNegativeInteger(field(record, "expectedDaytonaDaemonUid")),
    expectedAgentUid: nonNegativeInteger(field(record, "expectedAgentUid")),
    maximumAttestationTtlMs: positiveInteger(field(record, "maximumAttestationTtlMs")),
  });
}

function snapshotEffect(value: unknown): DaytonaSupervisorBootstrapConfiguration["effect"] {
  const record = exactRecord(value, [
    "executableRoot",
    "executableFile",
    "executableSha256",
    "timeoutMs",
    "maximumInputBytes",
    "maximumOutputBytes",
    "manifest",
    "pinnedManifestAuthorityPublicKeys",
  ]);
  const pins = field(record, "pinnedManifestAuthorityPublicKeys");
  if (!Array.isArray(pins)) throw new TypeError();
  return Object.freeze({
    executableRoot: safeReference(field(record, "executableRoot")),
    executableFile: safeReference(field(record, "executableFile")),
    executableSha256: digest(field(record, "executableSha256")),
    timeoutMs: positiveInteger(field(record, "timeoutMs")),
    maximumInputBytes: positiveInteger(field(record, "maximumInputBytes")),
    maximumOutputBytes: positiveInteger(field(record, "maximumOutputBytes")),
    manifest: field(record, "manifest"),
    pinnedManifestAuthorityPublicKeys: snapshotRuntimeSupervisorPortableData(
      pins
    ) as DaytonaSupervisorBootstrapConfiguration["effect"]["pinnedManifestAuthorityPublicKeys"],
  });
}

function readPrivateKey(trustedConfigurationRoot: string, privateKeyFile: string) {
  const bytes = readTrustedConfigurationFile({
    trustedConfigurationRoot,
    filePath: privateKeyFile,
    minimumBytes: 1,
    maximumBytes: MAX_KEY_BYTES,
  });
  try {
    const key = createPrivateKey(bytes);
    if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
    return key;
  } finally {
    bytes.fill(0);
  }
}

function readPublicKey(trustedConfigurationRoot: string, publicKeyFile: string) {
  const bytes = readTrustedConfigurationFile({
    trustedConfigurationRoot,
    filePath: publicKeyFile,
    minimumBytes: 1,
    maximumBytes: MAX_KEY_BYTES,
  });
  try {
    const key = createPublicKey(bytes);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
    return key;
  } finally {
    bytes.fill(0);
  }
}

function exactRecord(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== names.length ||
    keys.some((key) => typeof key !== "string" || !names.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of names) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throw new TypeError();
  return value;
}

function requiredArgument(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new TypeError();
  return value;
}

function absolutePath(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.includes("\0")) {
    throw new TypeError();
  }
  return value;
}

function terminalxUser(value: unknown): "terminalx" {
  if (value !== "terminalx") throw new TypeError();
  return "terminalx";
}

function canonicalPublicKeyPem(value: unknown): string {
  if (typeof value !== "string") throw new TypeError();
  const key = createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
  const canonical = key.export({ type: "spki", format: "pem" });
  if (typeof canonical !== "string" || canonical !== value) throw new TypeError();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new TypeError();
  return value as number;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}

if (require.main === module) {
  main().catch(() => {
    process.stderr.write("TerminalX Daytona supervisor failed closed\n");
    process.exitCode = 78;
  });
}
