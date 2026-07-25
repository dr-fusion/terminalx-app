import { createPublicKey } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { types as nodeTypes } from "node:util";
import { DAYTONA_PRODUCTION_FORK_COMMIT } from "../src/lib/runtime/daytona-source";
import type { DaytonaHostedControlPlaneConfiguration } from "../src/lib/runtime/daytona-hosted-control-plane";
import type {
  CreateDaytonaHostedMultiplayerServiceOptions,
  MeasuredDaytonaDeploymentArtifacts,
} from "../src/lib/runtime/hosted-multiplayer-service";
import { canonicalRuntimeJson } from "../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../src/lib/runtime/runtime-supervisor-snapshot";
import {
  ProductionHostedRuntimeConfigurationError,
  type ProductionHostedRuntimePublicConfiguration,
} from "./production-hosted-runtime";

const SETTINGS_FIELDS = [
  "deployment",
  "runtimeProfile",
  "kernel",
  "provider",
  "runner",
  "bootstrap",
  "supervisor",
  "adapter",
  "ingress",
] as const;
const DEPLOYMENT_FIELDS = ["manifest", "releaseAuthority", "measuredArtifacts"] as const;
const RELEASE_AUTHORITY_FIELDS = ["keyId", "publicKeySpkiPem"] as const;
const MEASURED_ARTIFACT_FIELDS = [
  "sdkSha256",
  "supervisorSha256",
  "runtimeArtifactManifestDigest",
  "runnerBinaryDigest",
  "daemonBinaryDigest",
  "sbomSha256",
  "provenanceSha256",
  "sandboxSha256",
  "isolationProfileSha256",
] as const;
const KERNEL_FIELDS = [
  "filename",
  "authorization",
  "runtimeLifecycleCommandTtlMs",
  "platformSecurityPolicyRevision",
] as const;
const AUTHORIZATION_FIELDS = [
  "networkPolicyRef",
  "networkPolicyDigest",
  "credentialPolicyRef",
  "credentialPolicyDigest",
  "effectEnforcerPolicyDigest",
] as const;
const PROVIDER_FIELDS = ["endpoint", "organizationId", "configuration"] as const;
const PROVIDER_CONFIGURATION_FIELDS = [
  "sourceCommit",
  "target",
  "sandboxUser",
  "artifact",
  "supervisorArtifactDigest",
  "runnerBinaryDigest",
  "lifecycle",
] as const;
const PROVIDER_ARTIFACT_FIELDS = [
  "kind",
  "snapshotId",
  "snapshotRef",
  "imageId",
  "contentDigest",
] as const;
const PROVIDER_LIFECYCLE_FIELDS = [
  "autoStopIntervalMinutes",
  "autoArchiveIntervalMinutes",
  "autoDeleteIntervalMinutes",
] as const;
const RUNNER_FIELDS = [
  "origin",
  "caPem",
  "tlsSpkiSha256",
  "connectTimeoutMs",
  "requestTimeoutMs",
  "terminalLifetimeMs",
  "maximumPendingTerminalOutputBytes",
  "maximumFrameBytes",
] as const;
const BOOTSTRAP_FIELDS = [
  "pendingRoot",
  "expectedOwnerUid",
  "assignmentMasterKeyId",
  "authorityTtlMs",
  "effectManifestTtlMs",
] as const;
const SUPERVISOR_FIELDS = [
  "commandAuthorityMaximumTtlMs",
  "maxOperations",
  "observationTtlMs",
  "transport",
  "state",
  "terminal",
  "isolation",
  "effect",
  "workerIdPrefix",
] as const;
const SUPERVISOR_TRANSPORT_FIELDS = [
  "peerCredentialExecutableSha256",
  "authenticationTimeoutMs",
  "requestTimeoutMs",
  "maximumFrameBytes",
  "maximumInflightRequests",
] as const;
const SUPERVISOR_STATE_FIELDS = ["maxStateBytes"] as const;
const SUPERVISOR_TERMINAL_FIELDS = [
  "requestTimeoutMs",
  "maximumLifetimeMs",
  "maximumTerminals",
  "maximumTerminalsPerSandbox",
  "maximumPendingOutputBytes",
  "maximumOutputFrameBytes",
  "maximumPendingWebSocketBytes",
] as const;
const SUPERVISOR_ISOLATION_FIELDS = [
  "issuerKeyId",
  "issuerPublicKeySpkiPem",
  "hardenedDaytonaSourceCommit",
  "expectedSeccompProfileDigest",
  "expectedDockerVersion",
  "expectedContainerdVersion",
  "expectedProviderRevision",
  "expectedSupervisorUid",
  "expectedDaytonaDaemonUid",
  "expectedAgentUid",
  "maximumAttestationTtlMs",
] as const;
const SUPERVISOR_EFFECT_FIELDS = [
  "executableSha256",
  "timeoutMs",
  "maximumInputBytes",
  "maximumOutputBytes",
] as const;
const ADAPTER_FIELDS = ["operationTimeoutMs"] as const;
const INGRESS_FIELDS = [
  "credentialCheckIntervalMs",
  "eventPollIntervalMs",
  "monitorPollIntervalMs",
] as const;
const RUNTIME_PROFILE_FIELDS = [
  "kind",
  "source",
  "harnessRef",
  "projectCeiling",
  "checkpointPolicyRef",
  "adapterConfigurationRef",
  "isolation",
  "capabilities",
] as const;
const RUNTIME_SOURCE_FIELDS = ["sourceRevision", "expectedCommitSha", "setupRef"] as const;
const PROJECT_CEILING_FIELDS = [
  "revision",
  "digest",
  "allowedModes",
  "yoloEnabled",
  "finiteResourceProfile",
  "maximumRunLimits",
  "scopedExternalRulesDigest",
  "isolationPolicyDigest",
  "networkPolicyDigest",
  "credentialPolicyDigest",
] as const;
const RESOURCE_PROFILE_FIELDS = ["cpu", "memoryGiB", "diskGiB"] as const;
const RUN_LIMIT_FIELDS = [
  "wallClock",
  "modelTokens",
  "modelSpend",
  "outboundBytes",
  "actionCounts",
] as const;
const ACTION_COUNT_FIELDS = ["local", "scoped-external", "protected", "forbidden"] as const;
const ISOLATION_FIELDS = [
  "isolationPolicyDigest",
  "publicAccess",
  "hostMounts",
  "linkedSandbox",
  "rootIdentity",
  "network",
  "resources",
] as const;
const NETWORK_FIELDS = ["mode", "policyDigest", "allowedDestinations"] as const;
const ISOLATION_RESOURCE_FIELDS = ["cpu", "memoryGiB", "diskGiB", "pids"] as const;
const CAPABILITY_FIELDS = [
  "isolatedExecution",
  "brokeredCredentials",
  "proxyOnlyEgress",
  "checkpoints",
  "yoloEligible",
] as const;

const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,127}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 10 * 60_000;
const MAX_TERMINAL_LIFETIME_MS = 7 * 24 * 60 * 60_000;
const MAX_EFFECT_MANIFEST_TTL_MS = 365 * 24 * 60 * 60_000;

export interface ProductionDaytonaSettings {
  readonly deployment: {
    readonly manifest: unknown;
    readonly releaseAuthority: { readonly keyId: string; readonly publicKeySpkiPem: string };
    readonly measuredArtifacts: MeasuredDaytonaDeploymentArtifacts;
  };
  readonly runtimeProfile: CreateDaytonaHostedMultiplayerServiceOptions["runtimeProfile"];
  readonly kernel: {
    readonly filename: string;
    readonly authorization: {
      readonly networkPolicyRef: string;
      readonly networkPolicyDigest: string;
      readonly credentialPolicyRef: string;
      readonly credentialPolicyDigest: string;
      readonly effectEnforcerPolicyDigest: string;
    };
    readonly runtimeLifecycleCommandTtlMs: number;
    readonly platformSecurityPolicyRevision: string;
  };
  readonly provider: {
    readonly endpoint: string;
    readonly organizationId: string | null;
    readonly configuration: DaytonaHostedControlPlaneConfiguration;
  };
  readonly runner: {
    readonly origin: string;
    readonly caPem: string;
    readonly tlsSpkiSha256: string;
    readonly connectTimeoutMs: number;
    readonly requestTimeoutMs: number;
    readonly terminalLifetimeMs: number;
    readonly maximumPendingTerminalOutputBytes: number;
    readonly maximumFrameBytes: number;
  };
  readonly bootstrap: {
    readonly pendingRoot: string;
    readonly expectedOwnerUid: number;
    readonly assignmentMasterKeyId: string;
    readonly authorityTtlMs: number;
    readonly effectManifestTtlMs: number;
  };
  readonly supervisor: {
    readonly commandAuthorityMaximumTtlMs: number;
    readonly maxOperations: number;
    readonly observationTtlMs: number;
    readonly transport: {
      readonly peerCredentialExecutableSha256: string;
      readonly authenticationTimeoutMs: number;
      readonly requestTimeoutMs: number;
      readonly maximumFrameBytes: number;
      readonly maximumInflightRequests: number;
    };
    readonly state: { readonly maxStateBytes: number };
    readonly terminal: {
      readonly requestTimeoutMs: number;
      readonly maximumLifetimeMs: number;
      readonly maximumTerminals: number;
      readonly maximumTerminalsPerSandbox: number;
      readonly maximumPendingOutputBytes: number;
      readonly maximumOutputFrameBytes: number;
      readonly maximumPendingWebSocketBytes: number;
    };
    readonly isolation: {
      readonly issuerKeyId: string;
      readonly issuerPublicKeySpkiPem: string;
      readonly hardenedDaytonaSourceCommit: string;
      readonly expectedSeccompProfileDigest: string;
      readonly expectedDockerVersion: string;
      readonly expectedContainerdVersion: string;
      readonly expectedProviderRevision: number;
      readonly expectedSupervisorUid: number;
      readonly expectedDaytonaDaemonUid: number;
      readonly expectedAgentUid: number;
      readonly maximumAttestationTtlMs: number;
    };
    readonly effect: {
      readonly executableSha256: string;
      readonly timeoutMs: number;
      readonly maximumInputBytes: number;
      readonly maximumOutputBytes: number;
    };
    readonly workerIdPrefix: string;
  };
  readonly adapter: { readonly operationTimeoutMs: number };
  readonly ingress: {
    readonly credentialCheckIntervalMs: number;
    readonly eventPollIntervalMs: number;
    readonly monitorPollIntervalMs: number;
  };
}

/** Exact-validate the complete protected public settings graph before secrets are composed. */
export function parseProductionDaytonaSettings(
  configuration: ProductionHostedRuntimePublicConfiguration
): ProductionDaytonaSettings {
  try {
    const settings = exact(
      snapshotRuntimeSupervisorPortableData(configuration.settings),
      SETTINGS_FIELDS
    );
    canonicalRuntimeJson(settings);

    const deployment = exact(field(settings, "deployment"), DEPLOYMENT_FIELDS);
    const releaseAuthority = exact(field(deployment, "releaseAuthority"), RELEASE_AUTHORITY_FIELDS);
    const measured = exact(field(deployment, "measuredArtifacts"), MEASURED_ARTIFACT_FIELDS);
    const measuredArtifacts = Object.freeze(
      Object.fromEntries(
        MEASURED_ARTIFACT_FIELDS.map((name) => [name, digest(field(measured, name))])
      )
    ) as unknown as MeasuredDaytonaDeploymentArtifacts;

    const runtimeProfile = snapshotRuntimeProfile(field(settings, "runtimeProfile"));
    const kernel = exact(field(settings, "kernel"), KERNEL_FIELDS);
    const authorization = exact(field(kernel, "authorization"), AUTHORIZATION_FIELDS);
    const provider = exact(field(settings, "provider"), PROVIDER_FIELDS);
    const providerConfiguration = snapshotProviderConfiguration(field(provider, "configuration"));
    const runner = exact(field(settings, "runner"), RUNNER_FIELDS);
    const bootstrap = exact(field(settings, "bootstrap"), BOOTSTRAP_FIELDS);
    const supervisor = exact(field(settings, "supervisor"), SUPERVISOR_FIELDS);
    const supervisorTransport = exact(field(supervisor, "transport"), SUPERVISOR_TRANSPORT_FIELDS);
    const supervisorState = exact(field(supervisor, "state"), SUPERVISOR_STATE_FIELDS);
    const supervisorTerminal = exact(field(supervisor, "terminal"), SUPERVISOR_TERMINAL_FIELDS);
    const supervisorIsolation = exact(field(supervisor, "isolation"), SUPERVISOR_ISOLATION_FIELDS);
    const supervisorEffect = exact(field(supervisor, "effect"), SUPERVISOR_EFFECT_FIELDS);
    const adapter = exact(field(settings, "adapter"), ADAPTER_FIELDS);
    const ingress = exact(field(settings, "ingress"), INGRESS_FIELDS);

    const endpoint = exactHttpsOriginOrApiBase(field(provider, "endpoint"));
    const organizationIdValue = field(provider, "organizationId");
    const organizationId = organizationIdValue === null ? null : safeReference(organizationIdValue);
    const runnerOrigin = exactHttpsOrigin(field(runner, "origin"));
    const caPem = boundedString(field(runner, "caPem"), 1, 1024 * 1024);
    if (
      !caPem.startsWith("-----BEGIN CERTIFICATE-----\n") ||
      !caPem.endsWith("-----END CERTIFICATE-----\n")
    ) {
      invalid();
    }

    const isolationPublicKey = canonicalEd25519PublicKey(
      field(supervisorIsolation, "issuerPublicKeySpkiPem")
    );
    const expectedSupervisorUid = integer(
      field(supervisorIsolation, "expectedSupervisorUid"),
      0,
      0
    );
    const expectedDaytonaDaemonUid = integer(
      field(supervisorIsolation, "expectedDaytonaDaemonUid"),
      1,
      0x7fffffff
    );
    const expectedAgentUid = integer(field(supervisorIsolation, "expectedAgentUid"), 1, 0x7fffffff);
    if (expectedDaytonaDaemonUid !== expectedAgentUid) invalid();
    const expectedOwnerUid = integer(field(bootstrap, "expectedOwnerUid"), 0, 0x7fffffff);
    if (typeof process.geteuid === "function" && expectedOwnerUid !== process.geteuid()) invalid();

    if (
      runtimeProfile.isolation.network.policyDigest !==
        digest(field(authorization, "networkPolicyDigest")) ||
      runtimeProfile.projectCeiling.networkPolicyDigest !==
        digest(field(authorization, "networkPolicyDigest")) ||
      runtimeProfile.projectCeiling.credentialPolicyDigest !==
        digest(field(authorization, "credentialPolicyDigest")) ||
      providerConfiguration.supervisorArtifactDigest !== measuredArtifacts.supervisorSha256 ||
      providerConfiguration.runnerBinaryDigest !== measuredArtifacts.runnerBinaryDigest ||
      providerConfiguration.artifact.contentDigest !== measuredArtifacts.sandboxSha256 ||
      runtimeProfile.isolation.isolationPolicyDigest !== measuredArtifacts.isolationProfileSha256 ||
      providerConfiguration.artifact.snapshotRef !==
        (deploymentManifestSnapshotRef(field(deployment, "manifest")) ??
          providerConfiguration.artifact.snapshotRef)
    ) {
      invalid();
    }

    return Object.freeze({
      deployment: Object.freeze({
        manifest: field(deployment, "manifest"),
        releaseAuthority: Object.freeze({
          keyId: keyId(field(releaseAuthority, "keyId")),
          publicKeySpkiPem: canonicalEd25519PublicKey(field(releaseAuthority, "publicKeySpkiPem")),
        }),
        measuredArtifacts,
      }),
      runtimeProfile,
      kernel: Object.freeze({
        filename: absolutePath(field(kernel, "filename")),
        authorization: Object.freeze({
          networkPolicyRef: safeReference(field(authorization, "networkPolicyRef")),
          networkPolicyDigest: digest(field(authorization, "networkPolicyDigest")),
          credentialPolicyRef: safeReference(field(authorization, "credentialPolicyRef")),
          credentialPolicyDigest: digest(field(authorization, "credentialPolicyDigest")),
          effectEnforcerPolicyDigest: digest(field(authorization, "effectEnforcerPolicyDigest")),
        }),
        runtimeLifecycleCommandTtlMs: integer(
          field(kernel, "runtimeLifecycleCommandTtlMs"),
          1,
          300_000
        ),
        platformSecurityPolicyRevision: safeReference(
          field(kernel, "platformSecurityPolicyRevision")
        ),
      }),
      provider: Object.freeze({ endpoint, organizationId, configuration: providerConfiguration }),
      runner: Object.freeze({
        origin: runnerOrigin,
        caPem,
        tlsSpkiSha256: digest(field(runner, "tlsSpkiSha256")),
        connectTimeoutMs: timeout(field(runner, "connectTimeoutMs")),
        requestTimeoutMs: timeout(field(runner, "requestTimeoutMs")),
        terminalLifetimeMs: integer(
          field(runner, "terminalLifetimeMs"),
          MIN_TIMEOUT_MS,
          MAX_TERMINAL_LIFETIME_MS
        ),
        maximumPendingTerminalOutputBytes: integer(
          field(runner, "maximumPendingTerminalOutputBytes"),
          1,
          16 * 1024 * 1024
        ),
        maximumFrameBytes: integer(field(runner, "maximumFrameBytes"), 1024, 16 * 1024 * 1024),
      }),
      bootstrap: Object.freeze({
        pendingRoot: absolutePath(field(bootstrap, "pendingRoot")),
        expectedOwnerUid,
        assignmentMasterKeyId: boundedToken(
          field(bootstrap, "assignmentMasterKeyId"),
          /^[A-Za-z0-9][A-Za-z0-9._~-]{0,63}$/
        ),
        authorityTtlMs: integer(field(bootstrap, "authorityTtlMs"), 1, 300_000),
        effectManifestTtlMs: integer(
          field(bootstrap, "effectManifestTtlMs"),
          60_000,
          MAX_EFFECT_MANIFEST_TTL_MS
        ),
      }),
      supervisor: Object.freeze({
        commandAuthorityMaximumTtlMs: integer(
          field(supervisor, "commandAuthorityMaximumTtlMs"),
          1,
          300_000
        ),
        maxOperations: integer(field(supervisor, "maxOperations"), 1, 1_000_000),
        observationTtlMs: integer(field(supervisor, "observationTtlMs"), 1, 300_000),
        transport: Object.freeze({
          peerCredentialExecutableSha256: digest(
            field(supervisorTransport, "peerCredentialExecutableSha256")
          ),
          authenticationTimeoutMs: timeout(field(supervisorTransport, "authenticationTimeoutMs")),
          requestTimeoutMs: timeout(field(supervisorTransport, "requestTimeoutMs")),
          maximumFrameBytes: integer(
            field(supervisorTransport, "maximumFrameBytes"),
            1024,
            16 * 1024 * 1024
          ),
          maximumInflightRequests: integer(
            field(supervisorTransport, "maximumInflightRequests"),
            1,
            1024
          ),
        }),
        state: Object.freeze({
          maxStateBytes: integer(field(supervisorState, "maxStateBytes"), 1024, 64 * 1024 * 1024),
        }),
        terminal: Object.freeze({
          requestTimeoutMs: timeout(field(supervisorTerminal, "requestTimeoutMs")),
          maximumLifetimeMs: integer(
            field(supervisorTerminal, "maximumLifetimeMs"),
            MIN_TIMEOUT_MS,
            MAX_TERMINAL_LIFETIME_MS
          ),
          maximumTerminals: integer(field(supervisorTerminal, "maximumTerminals"), 1, 1024),
          maximumTerminalsPerSandbox: integer(
            field(supervisorTerminal, "maximumTerminalsPerSandbox"),
            1,
            1024
          ),
          maximumPendingOutputBytes: integer(
            field(supervisorTerminal, "maximumPendingOutputBytes"),
            1,
            16 * 1024 * 1024
          ),
          maximumOutputFrameBytes: integer(
            field(supervisorTerminal, "maximumOutputFrameBytes"),
            1,
            1024 * 1024
          ),
          maximumPendingWebSocketBytes: integer(
            field(supervisorTerminal, "maximumPendingWebSocketBytes"),
            1,
            16 * 1024 * 1024
          ),
        }),
        isolation: Object.freeze({
          issuerKeyId: keyId(field(supervisorIsolation, "issuerKeyId")),
          issuerPublicKeySpkiPem: isolationPublicKey,
          hardenedDaytonaSourceCommit: productionDaytonaCommit(
            field(supervisorIsolation, "hardenedDaytonaSourceCommit")
          ),
          expectedSeccompProfileDigest: digest(
            field(supervisorIsolation, "expectedSeccompProfileDigest")
          ),
          expectedDockerVersion: safeReference(field(supervisorIsolation, "expectedDockerVersion")),
          expectedContainerdVersion: safeReference(
            field(supervisorIsolation, "expectedContainerdVersion")
          ),
          expectedProviderRevision: integer(
            field(supervisorIsolation, "expectedProviderRevision"),
            1,
            1
          ),
          expectedSupervisorUid,
          expectedDaytonaDaemonUid,
          expectedAgentUid,
          maximumAttestationTtlMs: integer(
            field(supervisorIsolation, "maximumAttestationTtlMs"),
            1,
            300_000
          ),
        }),
        effect: Object.freeze({
          executableSha256: digest(field(supervisorEffect, "executableSha256")),
          timeoutMs: timeout(field(supervisorEffect, "timeoutMs")),
          maximumInputBytes: integer(
            field(supervisorEffect, "maximumInputBytes"),
            1024,
            16 * 1024 * 1024
          ),
          maximumOutputBytes: integer(
            field(supervisorEffect, "maximumOutputBytes"),
            1024,
            16 * 1024 * 1024
          ),
        }),
        workerIdPrefix: boundedToken(
          field(supervisor, "workerIdPrefix"),
          /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,95}$/
        ),
      }),
      adapter: Object.freeze({
        operationTimeoutMs: timeout(field(adapter, "operationTimeoutMs")),
      }),
      ingress: Object.freeze({
        credentialCheckIntervalMs: timeout(field(ingress, "credentialCheckIntervalMs")),
        eventPollIntervalMs: timeout(field(ingress, "eventPollIntervalMs")),
        monitorPollIntervalMs: timeout(field(ingress, "monitorPollIntervalMs")),
      }),
    });
  } catch (error) {
    if (error instanceof ProductionHostedRuntimeConfigurationError) throw error;
    invalid();
  }
}

function snapshotRuntimeProfile(
  value: unknown
): CreateDaytonaHostedMultiplayerServiceOptions["runtimeProfile"] {
  const profile = exact(value, RUNTIME_PROFILE_FIELDS);
  if (field(profile, "kind") !== "daytona") invalid();
  exact(field(profile, "source"), RUNTIME_SOURCE_FIELDS);
  const ceiling = exact(field(profile, "projectCeiling"), PROJECT_CEILING_FIELDS);
  exact(field(ceiling, "finiteResourceProfile"), RESOURCE_PROFILE_FIELDS);
  const limits = exact(field(ceiling, "maximumRunLimits"), RUN_LIMIT_FIELDS);
  exact(field(limits, "actionCounts"), ACTION_COUNT_FIELDS);
  const isolation = exact(field(profile, "isolation"), ISOLATION_FIELDS);
  exact(field(isolation, "network"), NETWORK_FIELDS);
  exact(field(isolation, "resources"), ISOLATION_RESOURCE_FIELDS);
  exact(field(profile, "capabilities"), CAPABILITY_FIELDS);
  return Object.freeze(
    profile
  ) as unknown as CreateDaytonaHostedMultiplayerServiceOptions["runtimeProfile"];
}

function snapshotProviderConfiguration(value: unknown): DaytonaHostedControlPlaneConfiguration {
  const configuration = exact(value, PROVIDER_CONFIGURATION_FIELDS);
  if (field(configuration, "sourceCommit") !== DAYTONA_PRODUCTION_FORK_COMMIT) invalid();
  exact(field(configuration, "artifact"), PROVIDER_ARTIFACT_FIELDS);
  exact(field(configuration, "lifecycle"), PROVIDER_LIFECYCLE_FIELDS);
  return Object.freeze(configuration) as unknown as DaytonaHostedControlPlaneConfiguration;
}

function productionDaytonaCommit(value: unknown): typeof DAYTONA_PRODUCTION_FORK_COMMIT {
  const commit = boundedToken(value, GIT_COMMIT);
  if (commit !== DAYTONA_PRODUCTION_FORK_COMMIT) invalid();
  return DAYTONA_PRODUCTION_FORK_COMMIT;
}

function deploymentManifestSnapshotRef(value: unknown): string | null {
  try {
    const record = value as Record<string, unknown>;
    const artifact = record.sandboxArtifact as Record<string, unknown>;
    return artifact.kind === "daytona-snapshot" && typeof artifact.snapshotRef === "string"
      ? artifact.snapshotRef
      : null;
  } catch {
    return null;
  }
}

function exact(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    invalid();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    invalid();
  }
  for (const name of fields) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
  return descriptor.value;
}

function canonicalEd25519PublicKey(value: unknown): string {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > 4096) invalid();
  try {
    const key = createPublicKey(value);
    if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") invalid();
    const canonical = key.export({ type: "spki", format: "pem" }).toString();
    if (canonical !== value) invalid();
    return canonical;
  } catch (error) {
    if (error instanceof ProductionHostedRuntimeConfigurationError) throw error;
    invalid();
  }
}

function exactHttpsOrigin(value: unknown): string {
  const source = boundedString(value, 1, 2048);
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    invalid();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.origin !== source.replace(/\/$/u, "")
  ) {
    invalid();
  }
  return url.origin;
}

function exactHttpsOriginOrApiBase(value: unknown): string {
  const source = boundedString(value, 1, 2048);
  let url: URL;
  try {
    url = new URL(source);
  } catch {
    invalid();
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname.includes("//") ||
    source.endsWith("/")
  ) {
    invalid();
  }
  return source;
}

function absolutePath(value: unknown): string {
  const source = boundedString(value, 1, 4096);
  if (!isAbsolute(source) || resolve(source) !== source || source.includes("\0")) invalid();
  return source;
}

function boundedString(value: unknown, minimum: number, maximum: number): string {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") < minimum ||
    Buffer.byteLength(value, "utf8") > maximum ||
    value.includes("\0")
  ) {
    invalid();
  }
  return value;
}

function boundedToken(value: unknown, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) invalid();
  return value;
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value) || value !== value.trim()) invalid();
  return value;
}

function keyId(value: unknown): string {
  if (typeof value !== "string" || !KEY_ID.test(value)) invalid();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) invalid();
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    invalid();
  }
  return value as number;
}

function timeout(value: unknown): number {
  return integer(value, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS);
}

function invalid(): never {
  throw new ProductionHostedRuntimeConfigurationError("invalid-configuration");
}
