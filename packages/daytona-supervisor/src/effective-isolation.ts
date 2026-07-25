import {
  createHash,
  createPublicKey,
  timingSafeEqual,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { types as nodeTypes } from "node:util";
import type { DaytonaSupervisorIsolationRequest } from "../../../src/lib/runtime/daytona-hosted-control-plane";
import {
  HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN,
  type HostedRuntimeAssignmentPlan,
} from "../../../src/lib/runtime/hosted-runtime-control-plane";
import { canonicalRuntimeJson } from "../../../src/lib/runtime/runtime-command-canonical";
import { snapshotRuntimeSupervisorPortableData } from "../../../src/lib/runtime/runtime-supervisor-snapshot";
import { readTrustedConfigurationFile } from "../../../src/lib/runtime/runtime-trusted-configuration-file";
import {
  DAYTONA_SUPERVISOR_ISOLATION_CLAIMS_DIGEST_DOMAIN,
  DAYTONA_SUPERVISOR_ISOLATION_SIGNATURE_DOMAIN,
  type DaytonaSupervisorIsolationEvidenceSource,
} from "./supervisor";

export const DAYTONA_UPSTREAM_BASE_COMMIT = "b5a5d9e78d76c8bcf351f2049620250e0f34eea4" as const;
export const TERMINALX_DAYTONA_BASE_SOURCE_COMMIT = DAYTONA_UPSTREAM_BASE_COMMIT;
export const DAYTONA_EFFECTIVE_ISOLATION_ATTESTATION_KIND =
  "terminalx.daytona-effective-isolation" as const;

const OBSERVATION_PROVISIONING_REF_DIGEST_DOMAIN =
  "terminalx/daytona-observation-key-provisioning-ref/v1\0";
const ISOLATION_ISSUER = "runtime-isolation-enforcer" as const;
const ISOLATION_AUDIENCE = "terminalx-control-plane" as const;
const ISOLATION_CAPABILITY = "runtime.isolation.attest" as const;
const SHA256 = /^[0-9a-f]{64}$/;
const GIT_COMMIT = /^[0-9a-f]{40}$/;
const SANDBOX_IMAGE_ID = /^sha256:[0-9a-f]{64}$/;
const SANDBOX_SNAPSHOT_REF = /^[a-z0-9][a-z0-9._:/-]{0,446}@sha256:[0-9a-f]{64}$/;
const SAFE_REFERENCE = /^[^\u0000-\u001f\u007f]{1,300}$/u;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const MAX_EVIDENCE_BYTES = 256 * 1024;
const MAX_PUBLIC_KEY_BYTES = 16 * 1024;
const MAX_ATTESTATION_TTL_MS = 5 * 60_000;

export interface DaytonaEffectiveIsolationClaims {
  readonly version: 1;
  readonly providerIdentityCommitment: string;
  readonly providerRevision: number;
  readonly planDigest: string;
  readonly artifactDigest: string;
  readonly supervisorArtifactDigest: string;
  readonly sandboxUser: string;
  readonly observationIssuerKeyId: string;
  readonly observationPublicKeyDigest: string;
  readonly observationKeyProvisioningRefDigest: string;
  readonly isolationPolicyDigest: string;
  readonly networkPolicyDigest: string;
  readonly resources: {
    readonly cpu: number;
    readonly memoryGiB: number;
    readonly diskGiB: number;
    readonly pids: number;
  };
  readonly source: {
    readonly baseCommit: typeof TERMINALX_DAYTONA_BASE_SOURCE_COMMIT;
    readonly hardenedCommit: string;
    readonly baseAncestryVerified: true;
  };
  readonly hardenedImage: {
    readonly terminalxHardened: true;
    readonly sandboxImageId: string;
    readonly sandboxSnapshotRef: string;
    readonly sandboxProfileLabel: "io.terminalx.sandbox.profile=v1";
    readonly entrypoint: "/usr/local/bin/terminalx-sandbox-init";
    readonly useSnapshotEntrypoint: true;
    readonly daytonaDaemonBundled: true;
    readonly initializeDaemonTelemetry: false;
    readonly providerSandboxTokenInjected: false;
    readonly otelEnvironmentInjected: false;
    readonly authorizationHeaderForwardedToSandbox: false;
    readonly xDaytonaAuthorizationHeaderForwardedToSandbox: false;
    readonly rootSecretsExcludedFromCheckpoints: true;
  };
  readonly runnerEnforcement: {
    readonly resourceLimitsEnabled: true;
    readonly xfsProjectQuotaEnabled: true;
    readonly dockerDriver: "overlay2";
    readonly backingFilesystem: "xfs";
    readonly builtInSeccomp: true;
    readonly dockerVersion: string;
    readonly containerdVersion: string;
    readonly interSandboxNetworking: false;
    readonly blockAllEgressInstalledBeforeStart: true;
    readonly dockerUserEgressDropBeforeStart: true;
    readonly inputHostNewDrop: true;
    readonly inputEstablishedRepliesAllowed: true;
    readonly genericBuildsDisabled: true;
    readonly backupsDisabled: true;
    readonly snapshotsDisabled: true;
    readonly resizesDisabled: true;
  };
  readonly runnerNetwork: {
    readonly label: "io.terminalx.runner-network=v1";
    readonly driver: "bridge";
    readonly scope: "local";
    readonly internal: true;
    readonly ipv4Only: true;
    readonly interContainerCommunication: false;
    readonly subnet: "172.20.0.0/16";
  };
  readonly controls: {
    readonly publicAccess: false;
    readonly hostMounts: false;
    readonly linkedSandbox: false;
    readonly rootIdentity: false;
    readonly privileged: false;
    readonly hostNetwork: false;
    readonly capabilitiesDropped: true;
    readonly capDropAll: true;
    readonly rootInitCapAdd: readonly ["CHOWN", "KILL", "SETGID", "SETUID"];
    readonly agentEffectiveCapabilitiesEmpty: true;
    readonly agentPermittedCapabilitiesEmpty: true;
    readonly agentInheritableCapabilitiesEmpty: true;
    readonly agentAmbientCapabilitiesEmpty: true;
    readonly agentNoNewPrivileges: true;
    readonly noNewPrivileges: true;
    readonly readOnlyRootFilesystem: false;
    readonly privateWritableOverlay: true;
    readonly zeroExternalMounts: true;
    readonly imageDeclaredVolumes: 0;
    readonly pidsLimit: number;
    readonly seccompProfileDigest: string;
  };
  readonly processBoundary: {
    readonly supervisorUid: number;
    readonly daytonaDaemonUid: number;
    readonly agentUid: number;
    readonly observationKeyOwnerUid: number;
    readonly stateOwnerUid: number;
    readonly rootOwnedLocalCredentialChannel: true;
    readonly agentCanReadObservationKey: false;
    readonly agentCanReadSupervisorState: false;
    readonly agentCanAccessCredentialChannel: false;
    readonly agentCanSignalSupervisor: false;
    readonly agentCanWriteSupervisorExecutable: false;
    readonly agentCanWriteEffectExecutor: false;
  };
  readonly observedAtMs: number;
  readonly expiresAtMs: number;
}

export interface DaytonaEffectiveIsolationAttestation {
  readonly version: 1;
  readonly kind: typeof DAYTONA_EFFECTIVE_ISOLATION_ATTESTATION_KIND;
  readonly claims: DaytonaEffectiveIsolationClaims;
  readonly authority: {
    readonly issuer: typeof ISOLATION_ISSUER;
    readonly issuerKeyId: string;
    readonly audience: typeof ISOLATION_AUDIENCE;
    readonly capability: typeof ISOLATION_CAPABILITY;
    readonly claimsDigest: string;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
    readonly signature: string;
  };
}

export interface DaytonaEffectiveIsolationVerificationInput {
  readonly attestation: unknown;
  readonly plan: HostedRuntimeAssignmentPlan;
  readonly providerIdentityCommitment: string;
  readonly artifactDigest: string;
  readonly supervisorArtifactDigest: string;
  readonly observationIssuerKeyId: string;
  readonly observationPublicKeyDigest: string;
}

export interface CreateDaytonaEffectiveIsolationVerifierOptions {
  readonly issuerKeyId: string;
  readonly issuerPublicKeySpkiPem: string;
  /** A reviewed hardened descendant; the immutable b5 base itself is rejected. */
  readonly hardenedDaytonaSourceCommit: string;
  readonly expectedSandboxImageId: string;
  readonly expectedSandboxSnapshotRef: string;
  readonly expectedSandboxUser: "terminalx";
  readonly expectedSeccompProfileDigest: string;
  readonly expectedDockerVersion: string;
  readonly expectedContainerdVersion: string;
  readonly expectedProviderRevision: number;
  readonly expectedSupervisorUid: number;
  readonly expectedDaytonaDaemonUid: number;
  readonly expectedAgentUid: number;
  readonly clock?: () => number;
  readonly maximumAttestationTtlMs?: number;
}

export type DaytonaEffectiveIsolationVerifier = (
  input: DaytonaEffectiveIsolationVerificationInput
) => boolean;

export interface CreateFileBackedDaytonaIsolationEvidenceSourceOptions extends CreateDaytonaEffectiveIsolationVerifierOptions {
  readonly trustedConfigurationRoot: string;
  readonly attestationFile: string;
}

/**
 * Verify evidence signed by a separate root/platform isolation enforcer. The
 * immutable b5 commit can only be an ancestry anchor, never the effective
 * isolated implementation.
 */
export function createDaytonaEffectiveIsolationVerifier(
  unsafeOptions: CreateDaytonaEffectiveIsolationVerifierOptions
): DaytonaEffectiveIsolationVerifier {
  const options = captureVerifierOptions(unsafeOptions);
  return Object.freeze((unsafeInput: DaytonaEffectiveIsolationVerificationInput): boolean => {
    try {
      const input = captureVerificationInput(unsafeInput);
      const attestation = snapshotAttestation(input.attestation);
      const claims = attestation.claims;
      const plan = input.plan;
      const now = sampleClock(options.clock);
      if (
        now < claims.observedAtMs ||
        now >= claims.expiresAtMs ||
        claims.expiresAtMs - claims.observedAtMs > options.maximumAttestationTtlMs ||
        attestation.authority.issuedAtMs !== claims.observedAtMs ||
        attestation.authority.expiresAtMs !== claims.expiresAtMs ||
        attestation.authority.issuerKeyId !== options.issuerKeyId
      ) {
        return false;
      }
      if (
        claims.hardenedImage.terminalxHardened !== true ||
        claims.hardenedImage.sandboxImageId !== options.expectedSandboxImageId ||
        claims.hardenedImage.sandboxSnapshotRef !== options.expectedSandboxSnapshotRef ||
        claims.hardenedImage.sandboxProfileLabel !== "io.terminalx.sandbox.profile=v1" ||
        claims.hardenedImage.entrypoint !== "/usr/local/bin/terminalx-sandbox-init" ||
        claims.hardenedImage.useSnapshotEntrypoint !== true ||
        claims.hardenedImage.daytonaDaemonBundled !== true ||
        claims.hardenedImage.initializeDaemonTelemetry !== false ||
        claims.hardenedImage.providerSandboxTokenInjected !== false ||
        claims.hardenedImage.otelEnvironmentInjected !== false ||
        claims.hardenedImage.authorizationHeaderForwardedToSandbox !== false ||
        claims.hardenedImage.xDaytonaAuthorizationHeaderForwardedToSandbox !== false ||
        claims.hardenedImage.rootSecretsExcludedFromCheckpoints !== true ||
        claims.runnerEnforcement.resourceLimitsEnabled !== true ||
        claims.runnerEnforcement.xfsProjectQuotaEnabled !== true ||
        claims.runnerEnforcement.dockerDriver !== "overlay2" ||
        claims.runnerEnforcement.backingFilesystem !== "xfs" ||
        claims.runnerEnforcement.builtInSeccomp !== true ||
        claims.runnerEnforcement.dockerVersion !== options.expectedDockerVersion ||
        claims.runnerEnforcement.containerdVersion !== options.expectedContainerdVersion ||
        claims.runnerEnforcement.interSandboxNetworking !== false ||
        claims.runnerEnforcement.blockAllEgressInstalledBeforeStart !== true ||
        claims.runnerEnforcement.dockerUserEgressDropBeforeStart !== true ||
        claims.runnerEnforcement.inputHostNewDrop !== true ||
        claims.runnerEnforcement.inputEstablishedRepliesAllowed !== true ||
        claims.runnerEnforcement.genericBuildsDisabled !== true ||
        claims.runnerEnforcement.backupsDisabled !== true ||
        claims.runnerEnforcement.snapshotsDisabled !== true ||
        claims.runnerEnforcement.resizesDisabled !== true ||
        plan.isolation.network.mode !== "blocked" ||
        plan.isolation.network.allowedDestinations.length !== 0 ||
        plan.capabilities.checkpoints !== false
      ) {
        return false;
      }
      if (
        claims.runnerNetwork.label !== "io.terminalx.runner-network=v1" ||
        claims.runnerNetwork.driver !== "bridge" ||
        claims.runnerNetwork.scope !== "local" ||
        claims.runnerNetwork.internal !== true ||
        claims.runnerNetwork.ipv4Only !== true ||
        claims.runnerNetwork.interContainerCommunication !== false ||
        claims.runnerNetwork.subnet !== "172.20.0.0/16"
      ) {
        return false;
      }
      if (!verifyAuthority(attestation, options.issuerPublicKey)) return false;

      if (
        !sameDigest(claims.providerIdentityCommitment, input.providerIdentityCommitment) ||
        claims.providerRevision !== options.expectedProviderRevision ||
        !sameDigest(claims.planDigest, planDigest(plan)) ||
        !sameDigest(claims.artifactDigest, input.artifactDigest) ||
        !sameDigest(claims.supervisorArtifactDigest, input.supervisorArtifactDigest) ||
        claims.sandboxUser !== options.expectedSandboxUser ||
        claims.observationIssuerKeyId !== input.observationIssuerKeyId ||
        claims.observationIssuerKeyId !== plan.observation.issuerKeyId ||
        !sameDigest(claims.observationPublicKeyDigest, input.observationPublicKeyDigest) ||
        !sameDigest(claims.observationPublicKeyDigest, sha256(plan.observation.publicKeySpkiPem)) ||
        !sameDigest(
          claims.observationKeyProvisioningRefDigest,
          sha256(
            `${OBSERVATION_PROVISIONING_REF_DIGEST_DOMAIN}${plan.observation.keyProvisioningRef}`
          )
        ) ||
        !sameDigest(claims.isolationPolicyDigest, plan.isolation.isolationPolicyDigest) ||
        !sameDigest(claims.networkPolicyDigest, plan.isolation.network.policyDigest) ||
        canonicalRuntimeJson(claims.resources) !== canonicalRuntimeJson(plan.isolation.resources)
      ) {
        return false;
      }
      if (
        claims.source.baseCommit !== TERMINALX_DAYTONA_BASE_SOURCE_COMMIT ||
        claims.source.hardenedCommit !== options.hardenedDaytonaSourceCommit ||
        claims.source.hardenedCommit === TERMINALX_DAYTONA_BASE_SOURCE_COMMIT ||
        claims.source.baseAncestryVerified !== true
      ) {
        return false;
      }
      const controls = claims.controls;
      if (
        controls.publicAccess !== plan.isolation.publicAccess ||
        controls.hostMounts !== plan.isolation.hostMounts ||
        controls.linkedSandbox !== plan.isolation.linkedSandbox ||
        controls.rootIdentity !== plan.isolation.rootIdentity ||
        controls.privileged !== false ||
        controls.hostNetwork !== false ||
        controls.capabilitiesDropped !== true ||
        controls.capDropAll !== true ||
        canonicalRuntimeJson(controls.rootInitCapAdd) !==
          canonicalRuntimeJson(["CHOWN", "KILL", "SETGID", "SETUID"]) ||
        controls.agentEffectiveCapabilitiesEmpty !== true ||
        controls.agentPermittedCapabilitiesEmpty !== true ||
        controls.agentInheritableCapabilitiesEmpty !== true ||
        controls.agentAmbientCapabilitiesEmpty !== true ||
        controls.agentNoNewPrivileges !== true ||
        controls.noNewPrivileges !== true ||
        controls.readOnlyRootFilesystem !== false ||
        controls.privateWritableOverlay !== true ||
        controls.zeroExternalMounts !== true ||
        controls.imageDeclaredVolumes !== 0 ||
        controls.pidsLimit !== plan.isolation.resources.pids ||
        !sameDigest(controls.seccompProfileDigest, options.expectedSeccompProfileDigest)
      ) {
        return false;
      }
      const boundary = claims.processBoundary;
      return (
        boundary.supervisorUid === options.expectedSupervisorUid &&
        boundary.daytonaDaemonUid === options.expectedDaytonaDaemonUid &&
        boundary.agentUid === options.expectedAgentUid &&
        boundary.supervisorUid === 0 &&
        boundary.daytonaDaemonUid !== boundary.supervisorUid &&
        boundary.agentUid !== boundary.supervisorUid &&
        boundary.daytonaDaemonUid === boundary.agentUid &&
        boundary.observationKeyOwnerUid === boundary.supervisorUid &&
        boundary.stateOwnerUid === boundary.supervisorUid &&
        boundary.rootOwnedLocalCredentialChannel === true &&
        boundary.agentCanReadObservationKey === false &&
        boundary.agentCanReadSupervisorState === false &&
        boundary.agentCanAccessCredentialChannel === false &&
        boundary.agentCanSignalSupervisor === false &&
        boundary.agentCanWriteSupervisorExecutable === false &&
        boundary.agentCanWriteEffectExecutor === false
      );
    } catch {
      return false;
    }
  });
}

/** Read fresh signed evidence for every readiness probe; stale cached evidence is never reused. */
export function createFileBackedDaytonaIsolationEvidenceSource(
  unsafeOptions: CreateFileBackedDaytonaIsolationEvidenceSourceOptions
): DaytonaSupervisorIsolationEvidenceSource {
  const verifier = createDaytonaEffectiveIsolationVerifier(unsafeOptions);
  const trustedConfigurationRoot = unsafeOptions.trustedConfigurationRoot;
  const attestationFile = unsafeOptions.attestationFile;
  return Object.freeze({
    read(): unknown {
      const bytes = readTrustedConfigurationFile({
        trustedConfigurationRoot,
        filePath: attestationFile,
        minimumBytes: 2,
        maximumBytes: MAX_EVIDENCE_BYTES,
      });
      try {
        return snapshotRuntimeSupervisorPortableData(JSON.parse(bytes.toString("utf8")));
      } finally {
        bytes.fill(0);
      }
    },
    verify(input: {
      readonly evidence: unknown;
      readonly request: DaytonaSupervisorIsolationRequest;
      readonly providerIdentityCommitment: string;
    }): boolean {
      try {
        return (
          snapshotAttestation(input.evidence).claims.sandboxUser === input.request.sandboxUser &&
          verifier(
            Object.freeze({
              attestation: input.evidence,
              plan: input.request.plan,
              providerIdentityCommitment: input.providerIdentityCommitment,
              artifactDigest: input.request.artifactDigest,
              supervisorArtifactDigest: input.request.trust.supervisorArtifactDigest,
              observationIssuerKeyId: input.request.trust.observationIssuerKeyId,
              observationPublicKeyDigest: input.request.trust.observationPublicKeyDigest,
            })
          )
        );
      } catch {
        return false;
      }
    },
  });
}

function captureVerifierOptions(value: CreateDaytonaEffectiveIsolationVerifierOptions): Readonly<{
  issuerKeyId: string;
  issuerPublicKey: KeyObject;
  hardenedDaytonaSourceCommit: string;
  expectedSandboxImageId: string;
  expectedSandboxSnapshotRef: string;
  expectedSandboxUser: "terminalx";
  expectedSeccompProfileDigest: string;
  expectedDockerVersion: string;
  expectedContainerdVersion: string;
  expectedProviderRevision: number;
  expectedSupervisorUid: number;
  expectedDaytonaDaemonUid: number;
  expectedAgentUid: number;
  clock: () => number;
  maximumAttestationTtlMs: number;
}> {
  if (typeof value !== "object" || value === null || nodeTypes.isProxy(value))
    throw new TypeError();
  const hardenedCommit = gitCommit(value.hardenedDaytonaSourceCommit);
  if (hardenedCommit === TERMINALX_DAYTONA_BASE_SOURCE_COMMIT) throw new TypeError();
  const publicKey = parsePublicKey(value.issuerPublicKeySpkiPem);
  if (value.expectedSandboxUser !== "terminalx") throw new TypeError();
  const expectedSupervisorUid = nonNegativeInteger(value.expectedSupervisorUid);
  const expectedDaytonaDaemonUid = nonNegativeInteger(value.expectedDaytonaDaemonUid);
  const expectedAgentUid = nonNegativeInteger(value.expectedAgentUid);
  if (
    expectedSupervisorUid !== 0 ||
    expectedDaytonaDaemonUid === 0 ||
    expectedDaytonaDaemonUid !== expectedAgentUid
  ) {
    throw new TypeError();
  }
  const maximumAttestationTtlMs = boundedPositiveInteger(
    value.maximumAttestationTtlMs ?? MAX_ATTESTATION_TTL_MS,
    MAX_ATTESTATION_TTL_MS
  );
  return Object.freeze({
    issuerKeyId: safeReference(value.issuerKeyId),
    issuerPublicKey: publicKey,
    hardenedDaytonaSourceCommit: hardenedCommit,
    expectedSandboxImageId: sandboxImageId(value.expectedSandboxImageId),
    expectedSandboxSnapshotRef: sandboxSnapshotRef(value.expectedSandboxSnapshotRef),
    expectedSandboxUser: "terminalx",
    expectedSeccompProfileDigest: digest(value.expectedSeccompProfileDigest),
    expectedDockerVersion: safeReference(value.expectedDockerVersion),
    expectedContainerdVersion: safeReference(value.expectedContainerdVersion),
    expectedProviderRevision: positiveInteger(value.expectedProviderRevision),
    expectedSupervisorUid,
    expectedDaytonaDaemonUid,
    expectedAgentUid,
    clock: captureClock(value.clock ?? Date.now),
    maximumAttestationTtlMs,
  });
}

function captureVerificationInput(
  value: DaytonaEffectiveIsolationVerificationInput
): DaytonaEffectiveIsolationVerificationInput {
  const record = exactRecord(value, [
    "attestation",
    "plan",
    "providerIdentityCommitment",
    "artifactDigest",
    "supervisorArtifactDigest",
    "observationIssuerKeyId",
    "observationPublicKeyDigest",
  ]);
  const plan = snapshotRuntimeSupervisorPortableData(
    field(record, "plan")
  ) as HostedRuntimeAssignmentPlan;
  canonicalRuntimeJson(plan);
  safeReference(plan.observation.keyProvisioningRef);
  safeReference(plan.observation.issuerKeyId);
  if (typeof plan.observation.publicKeySpkiPem !== "string") throw new TypeError();
  return Object.freeze({
    attestation: field(record, "attestation"),
    plan,
    providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
    artifactDigest: digest(field(record, "artifactDigest")),
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    observationIssuerKeyId: safeReference(field(record, "observationIssuerKeyId")),
    observationPublicKeyDigest: digest(field(record, "observationPublicKeyDigest")),
  });
}

function snapshotAttestation(value: unknown): DaytonaEffectiveIsolationAttestation {
  const snapshot = snapshotRuntimeSupervisorPortableData(value);
  const record = exactRecord(snapshot, ["version", "kind", "claims", "authority"]);
  if (
    field(record, "version") !== 1 ||
    field(record, "kind") !== DAYTONA_EFFECTIVE_ISOLATION_ATTESTATION_KIND
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    version: 1,
    kind: DAYTONA_EFFECTIVE_ISOLATION_ATTESTATION_KIND,
    claims: snapshotClaims(field(record, "claims")),
    authority: snapshotAuthority(field(record, "authority")),
  });
}

function snapshotClaims(value: unknown): DaytonaEffectiveIsolationClaims {
  const record = exactRecord(value, [
    "version",
    "providerIdentityCommitment",
    "providerRevision",
    "planDigest",
    "artifactDigest",
    "supervisorArtifactDigest",
    "sandboxUser",
    "observationIssuerKeyId",
    "observationPublicKeyDigest",
    "observationKeyProvisioningRefDigest",
    "isolationPolicyDigest",
    "networkPolicyDigest",
    "resources",
    "source",
    "hardenedImage",
    "runnerEnforcement",
    "runnerNetwork",
    "controls",
    "processBoundary",
    "observedAtMs",
    "expiresAtMs",
  ]);
  if (field(record, "version") !== 1) throw new TypeError();
  const observedAtMs = nonNegativeInteger(field(record, "observedAtMs"));
  const expiresAtMs = positiveInteger(field(record, "expiresAtMs"));
  if (expiresAtMs <= observedAtMs) throw new TypeError();
  return Object.freeze({
    version: 1,
    providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
    providerRevision: positiveInteger(field(record, "providerRevision")),
    planDigest: digest(field(record, "planDigest")),
    artifactDigest: digest(field(record, "artifactDigest")),
    supervisorArtifactDigest: digest(field(record, "supervisorArtifactDigest")),
    sandboxUser: safeReference(field(record, "sandboxUser")),
    observationIssuerKeyId: safeReference(field(record, "observationIssuerKeyId")),
    observationPublicKeyDigest: digest(field(record, "observationPublicKeyDigest")),
    observationKeyProvisioningRefDigest: digest(
      field(record, "observationKeyProvisioningRefDigest")
    ),
    isolationPolicyDigest: digest(field(record, "isolationPolicyDigest")),
    networkPolicyDigest: digest(field(record, "networkPolicyDigest")),
    resources: snapshotResources(field(record, "resources")),
    source: snapshotSource(field(record, "source")),
    hardenedImage: snapshotHardenedImage(field(record, "hardenedImage")),
    runnerEnforcement: snapshotRunnerEnforcement(field(record, "runnerEnforcement")),
    runnerNetwork: snapshotRunnerNetwork(field(record, "runnerNetwork")),
    controls: snapshotControls(field(record, "controls")),
    processBoundary: snapshotProcessBoundary(field(record, "processBoundary")),
    observedAtMs,
    expiresAtMs,
  });
}

function snapshotHardenedImage(value: unknown): DaytonaEffectiveIsolationClaims["hardenedImage"] {
  const record = exactRecord(value, [
    "terminalxHardened",
    "sandboxImageId",
    "sandboxSnapshotRef",
    "sandboxProfileLabel",
    "entrypoint",
    "useSnapshotEntrypoint",
    "daytonaDaemonBundled",
    "initializeDaemonTelemetry",
    "providerSandboxTokenInjected",
    "otelEnvironmentInjected",
    "authorizationHeaderForwardedToSandbox",
    "xDaytonaAuthorizationHeaderForwardedToSandbox",
    "rootSecretsExcludedFromCheckpoints",
  ]);
  if (
    field(record, "terminalxHardened") !== true ||
    field(record, "sandboxProfileLabel") !== "io.terminalx.sandbox.profile=v1" ||
    field(record, "entrypoint") !== "/usr/local/bin/terminalx-sandbox-init" ||
    field(record, "useSnapshotEntrypoint") !== true ||
    field(record, "daytonaDaemonBundled") !== true ||
    field(record, "initializeDaemonTelemetry") !== false ||
    field(record, "providerSandboxTokenInjected") !== false ||
    field(record, "otelEnvironmentInjected") !== false ||
    field(record, "authorizationHeaderForwardedToSandbox") !== false ||
    field(record, "xDaytonaAuthorizationHeaderForwardedToSandbox") !== false ||
    field(record, "rootSecretsExcludedFromCheckpoints") !== true
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    terminalxHardened: true,
    sandboxImageId: sandboxImageId(field(record, "sandboxImageId")),
    sandboxSnapshotRef: sandboxSnapshotRef(field(record, "sandboxSnapshotRef")),
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
  });
}

function snapshotRunnerEnforcement(
  value: unknown
): DaytonaEffectiveIsolationClaims["runnerEnforcement"] {
  const record = exactRecord(value, [
    "resourceLimitsEnabled",
    "xfsProjectQuotaEnabled",
    "dockerDriver",
    "backingFilesystem",
    "builtInSeccomp",
    "dockerVersion",
    "containerdVersion",
    "interSandboxNetworking",
    "blockAllEgressInstalledBeforeStart",
    "dockerUserEgressDropBeforeStart",
    "inputHostNewDrop",
    "inputEstablishedRepliesAllowed",
    "genericBuildsDisabled",
    "backupsDisabled",
    "snapshotsDisabled",
    "resizesDisabled",
  ]);
  for (const name of [
    "resourceLimitsEnabled",
    "xfsProjectQuotaEnabled",
    "builtInSeccomp",
    "blockAllEgressInstalledBeforeStart",
    "dockerUserEgressDropBeforeStart",
    "inputHostNewDrop",
    "inputEstablishedRepliesAllowed",
    "genericBuildsDisabled",
    "backupsDisabled",
    "snapshotsDisabled",
    "resizesDisabled",
  ]) {
    if (field(record, name) !== true) throw new TypeError();
  }
  if (
    field(record, "interSandboxNetworking") !== false ||
    field(record, "dockerDriver") !== "overlay2" ||
    field(record, "backingFilesystem") !== "xfs"
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    resourceLimitsEnabled: true,
    xfsProjectQuotaEnabled: true,
    dockerDriver: "overlay2",
    backingFilesystem: "xfs",
    builtInSeccomp: true,
    dockerVersion: safeReference(field(record, "dockerVersion")),
    containerdVersion: safeReference(field(record, "containerdVersion")),
    interSandboxNetworking: false,
    blockAllEgressInstalledBeforeStart: true,
    dockerUserEgressDropBeforeStart: true,
    inputHostNewDrop: true,
    inputEstablishedRepliesAllowed: true,
    genericBuildsDisabled: true,
    backupsDisabled: true,
    snapshotsDisabled: true,
    resizesDisabled: true,
  });
}

function snapshotRunnerNetwork(value: unknown): DaytonaEffectiveIsolationClaims["runnerNetwork"] {
  const record = exactRecord(value, [
    "label",
    "driver",
    "scope",
    "internal",
    "ipv4Only",
    "interContainerCommunication",
    "subnet",
  ]);
  if (
    field(record, "label") !== "io.terminalx.runner-network=v1" ||
    field(record, "driver") !== "bridge" ||
    field(record, "scope") !== "local" ||
    field(record, "internal") !== true ||
    field(record, "ipv4Only") !== true ||
    field(record, "interContainerCommunication") !== false ||
    field(record, "subnet") !== "172.20.0.0/16"
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    label: "io.terminalx.runner-network=v1",
    driver: "bridge",
    scope: "local",
    internal: true,
    ipv4Only: true,
    interContainerCommunication: false,
    subnet: "172.20.0.0/16",
  });
}

function snapshotResources(value: unknown): DaytonaEffectiveIsolationClaims["resources"] {
  const record = exactRecord(value, ["cpu", "memoryGiB", "diskGiB", "pids"]);
  return Object.freeze({
    cpu: boundedPositiveInteger(field(record, "cpu"), 1024),
    memoryGiB: boundedPositiveInteger(field(record, "memoryGiB"), 1024 * 1024),
    diskGiB: boundedPositiveInteger(field(record, "diskGiB"), 1024 * 1024),
    pids: boundedPositiveInteger(field(record, "pids"), 1_000_000),
  });
}

function snapshotSource(value: unknown): DaytonaEffectiveIsolationClaims["source"] {
  const record = exactRecord(value, ["baseCommit", "hardenedCommit", "baseAncestryVerified"]);
  if (
    field(record, "baseCommit") !== TERMINALX_DAYTONA_BASE_SOURCE_COMMIT ||
    field(record, "baseAncestryVerified") !== true
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    baseCommit: TERMINALX_DAYTONA_BASE_SOURCE_COMMIT,
    hardenedCommit: gitCommit(field(record, "hardenedCommit")),
    baseAncestryVerified: true,
  });
}

function snapshotControls(value: unknown): DaytonaEffectiveIsolationClaims["controls"] {
  const record = exactRecord(value, [
    "publicAccess",
    "hostMounts",
    "linkedSandbox",
    "rootIdentity",
    "privileged",
    "hostNetwork",
    "capabilitiesDropped",
    "capDropAll",
    "rootInitCapAdd",
    "agentEffectiveCapabilitiesEmpty",
    "agentPermittedCapabilitiesEmpty",
    "agentInheritableCapabilitiesEmpty",
    "agentAmbientCapabilitiesEmpty",
    "agentNoNewPrivileges",
    "noNewPrivileges",
    "readOnlyRootFilesystem",
    "privateWritableOverlay",
    "zeroExternalMounts",
    "imageDeclaredVolumes",
    "pidsLimit",
    "seccompProfileDigest",
  ]);
  for (const name of [
    "publicAccess",
    "hostMounts",
    "linkedSandbox",
    "rootIdentity",
    "privileged",
    "hostNetwork",
  ]) {
    if (field(record, name) !== false) throw new TypeError();
  }
  for (const name of [
    "capabilitiesDropped",
    "capDropAll",
    "noNewPrivileges",
    "agentEffectiveCapabilitiesEmpty",
    "agentPermittedCapabilitiesEmpty",
    "agentInheritableCapabilitiesEmpty",
    "agentAmbientCapabilitiesEmpty",
    "agentNoNewPrivileges",
    "privateWritableOverlay",
    "zeroExternalMounts",
  ]) {
    if (field(record, name) !== true) throw new TypeError();
  }
  if (
    field(record, "readOnlyRootFilesystem") !== false ||
    field(record, "imageDeclaredVolumes") !== 0
  ) {
    throw new TypeError();
  }
  const rootInitCapAdd = field(record, "rootInitCapAdd");
  if (
    !Array.isArray(rootInitCapAdd) ||
    canonicalRuntimeJson(rootInitCapAdd) !==
      canonicalRuntimeJson(["CHOWN", "KILL", "SETGID", "SETUID"])
  ) {
    throw new TypeError();
  }
  return Object.freeze({
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
    pidsLimit: boundedPositiveInteger(field(record, "pidsLimit"), 1_000_000),
    seccompProfileDigest: digest(field(record, "seccompProfileDigest")),
  });
}

function snapshotProcessBoundary(
  value: unknown
): DaytonaEffectiveIsolationClaims["processBoundary"] {
  const record = exactRecord(value, [
    "supervisorUid",
    "daytonaDaemonUid",
    "agentUid",
    "observationKeyOwnerUid",
    "stateOwnerUid",
    "rootOwnedLocalCredentialChannel",
    "agentCanReadObservationKey",
    "agentCanReadSupervisorState",
    "agentCanAccessCredentialChannel",
    "agentCanSignalSupervisor",
    "agentCanWriteSupervisorExecutable",
    "agentCanWriteEffectExecutor",
  ]);
  if (field(record, "rootOwnedLocalCredentialChannel") !== true) throw new TypeError();
  for (const name of [
    "agentCanReadObservationKey",
    "agentCanReadSupervisorState",
    "agentCanAccessCredentialChannel",
    "agentCanSignalSupervisor",
    "agentCanWriteSupervisorExecutable",
    "agentCanWriteEffectExecutor",
  ]) {
    if (field(record, name) !== false) throw new TypeError();
  }
  return Object.freeze({
    supervisorUid: nonNegativeInteger(field(record, "supervisorUid")),
    daytonaDaemonUid: nonNegativeInteger(field(record, "daytonaDaemonUid")),
    agentUid: nonNegativeInteger(field(record, "agentUid")),
    observationKeyOwnerUid: nonNegativeInteger(field(record, "observationKeyOwnerUid")),
    stateOwnerUid: nonNegativeInteger(field(record, "stateOwnerUid")),
    rootOwnedLocalCredentialChannel: true,
    agentCanReadObservationKey: false,
    agentCanReadSupervisorState: false,
    agentCanAccessCredentialChannel: false,
    agentCanSignalSupervisor: false,
    agentCanWriteSupervisorExecutable: false,
    agentCanWriteEffectExecutor: false,
  });
}

function snapshotAuthority(value: unknown): DaytonaEffectiveIsolationAttestation["authority"] {
  const record = exactRecord(value, [
    "issuer",
    "issuerKeyId",
    "audience",
    "capability",
    "claimsDigest",
    "issuedAtMs",
    "expiresAtMs",
    "signature",
  ]);
  const signature = field(record, "signature");
  if (
    field(record, "issuer") !== ISOLATION_ISSUER ||
    field(record, "audience") !== ISOLATION_AUDIENCE ||
    field(record, "capability") !== ISOLATION_CAPABILITY ||
    typeof signature !== "string" ||
    !SIGNATURE.test(signature)
  ) {
    throw new TypeError();
  }
  return Object.freeze({
    issuer: ISOLATION_ISSUER,
    issuerKeyId: safeReference(field(record, "issuerKeyId")),
    audience: ISOLATION_AUDIENCE,
    capability: ISOLATION_CAPABILITY,
    claimsDigest: digest(field(record, "claimsDigest")),
    issuedAtMs: nonNegativeInteger(field(record, "issuedAtMs")),
    expiresAtMs: positiveInteger(field(record, "expiresAtMs")),
    signature,
  });
}

function verifyAuthority(
  attestation: DaytonaEffectiveIsolationAttestation,
  key: KeyObject
): boolean {
  const claimsJson = canonicalRuntimeJson(attestation.claims);
  const claimsDigest = sha256(`${DAYTONA_SUPERVISOR_ISOLATION_CLAIMS_DIGEST_DOMAIN}${claimsJson}`);
  if (!sameDigest(attestation.authority.claimsDigest, claimsDigest)) return false;
  const statement = Object.freeze({
    version: 1,
    issuer: attestation.authority.issuer,
    issuerKeyId: attestation.authority.issuerKeyId,
    audience: attestation.authority.audience,
    capability: attestation.authority.capability,
    claimsDigest: attestation.authority.claimsDigest,
    issuedAtMs: attestation.authority.issuedAtMs,
    expiresAtMs: attestation.authority.expiresAtMs,
  });
  return verifyEd25519(
    null,
    Buffer.from(
      `${DAYTONA_SUPERVISOR_ISOLATION_SIGNATURE_DOMAIN}${canonicalRuntimeJson(statement)}`,
      "utf8"
    ),
    key,
    Buffer.from(attestation.authority.signature, "base64url")
  );
}

function planDigest(plan: HostedRuntimeAssignmentPlan): string {
  return sha256(`${HOSTED_RUNTIME_ASSIGNMENT_PLAN_DIGEST_DOMAIN}${canonicalRuntimeJson(plan)}`);
}

function parsePublicKey(value: unknown): KeyObject {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") > MAX_PUBLIC_KEY_BYTES ||
    !value.startsWith("-----BEGIN PUBLIC KEY-----\n") ||
    !value.endsWith("-----END PUBLIC KEY-----\n")
  ) {
    throw new TypeError();
  }
  const key = createPublicKey(value);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") throw new TypeError();
  return key;
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

function captureClock(value: unknown): () => number {
  if (typeof value !== "function" || nodeTypes.isProxy(value)) throw new TypeError();
  return value as () => number;
}

function sampleClock(clock: () => number): number {
  const value = clock();
  return nonNegativeInteger(value);
}

function safeReference(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REFERENCE.test(value)) throw new TypeError();
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function gitCommit(value: unknown): string {
  if (typeof value !== "string" || !GIT_COMMIT.test(value)) throw new TypeError();
  return value;
}

function sandboxImageId(value: unknown): string {
  if (typeof value !== "string" || !SANDBOX_IMAGE_ID.test(value)) throw new TypeError();
  return value;
}

function sandboxSnapshotRef(value: unknown): string {
  if (
    typeof value !== "string" ||
    !SANDBOX_SNAPSHOT_REF.test(value) ||
    value.includes("://") ||
    value.includes("//")
  ) {
    throw new TypeError();
  }
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

function boundedPositiveInteger(value: unknown, maximum: number): number {
  const integer = positiveInteger(value);
  if (integer > maximum) throw new TypeError();
  return integer;
}

function sameDigest(left: string, right: string): boolean {
  return (
    SHA256.test(left) &&
    SHA256.test(right) &&
    timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"))
  );
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
