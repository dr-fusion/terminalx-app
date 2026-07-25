import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createDaytonaEffectiveIsolationVerifier } from "../../packages/daytona-supervisor/src/effective-isolation";
import type { HostedRuntimeAssignmentPlan } from "@/lib/runtime/hosted-runtime-control-plane";
import { canonicalRuntimeJson } from "@/lib/runtime/runtime-command-canonical";

// Emitted by the hardened Go runner's deterministic
// TestTerminalXEffectiveIsolationEvidenceIsCanonicalFreshAndVerifiable fixture.
// The runner pins the SHA-256 of the complete evidence below, so this test is a
// cross-language contract check rather than a second TypeScript-only signer.
const GO_RUNNER_PLAN_JSON = String.raw`{"adapterConfigurationRef":"daytona-production-v1","binding":{"projectId":"project-1","runtimeAssignmentGeneration":1,"runtimeAssignmentId":"assignment-1","runtimePrincipalId":"principal-1","sandboxGeneration":1,"sandboxId":"sandbox-1","sessionId":"session-1","teamId":"team-1"},"capabilities":{"brokeredCredentials":false,"checkpoints":false,"isolatedExecution":true,"proxyOnlyEgress":false,"yoloEligible":false},"incarnation":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","isolation":{"hostMounts":false,"isolationPolicyDigest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","linkedSandbox":false,"network":{"allowedDestinations":[],"mode":"blocked","policyDigest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},"publicAccess":false,"resources":{"cpu":2,"diskGiB":20,"memoryGiB":4,"pids":256},"rootIdentity":false},"observation":{"issuerKeyId":"observation-key-1","keyProvisioningRef":"observation-provisioning-1","publicKeySpkiPem":"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAIVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=\n-----END PUBLIC KEY-----\n"},"runtimeAuthorizationGeneration":7,"specificationDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`;

const GO_RUNNER_EVIDENCE_JSON = String.raw`{"authority":{"audience":"terminalx-control-plane","capability":"runtime.isolation.attest","claimsDigest":"bbc0842dffcf0560565520cad49391da6c06eccd72cf62988a995dae39b1978b","expiresAtMs":1800000060000,"issuedAtMs":1800000000000,"issuer":"runtime-isolation-enforcer","issuerKeyId":"isolation-key-1","signature":"SmJNRkV7-nR4ZhuqAR_NH4Z0v_UHqBCcFenMgktnxS6BR6zKLG6VY8ym2_5GmlvdRKHqJNdn60wyH_gJpkLPCQ"},"claims":{"artifactDigest":"1111111111111111111111111111111111111111111111111111111111111111","controls":{"agentAmbientCapabilitiesEmpty":true,"agentEffectiveCapabilitiesEmpty":true,"agentInheritableCapabilitiesEmpty":true,"agentNoNewPrivileges":true,"agentPermittedCapabilitiesEmpty":true,"capDropAll":true,"capabilitiesDropped":true,"hostMounts":false,"hostNetwork":false,"imageDeclaredVolumes":0,"linkedSandbox":false,"noNewPrivileges":true,"pidsLimit":256,"privateWritableOverlay":true,"privileged":false,"publicAccess":false,"readOnlyRootFilesystem":false,"rootIdentity":false,"rootInitCapAdd":["CHOWN","KILL","SETGID","SETUID"],"seccompProfileDigest":"7777777777777777777777777777777777777777777777777777777777777777","zeroExternalMounts":true},"expiresAtMs":1800000060000,"hardenedImage":{"authorizationHeaderForwardedToSandbox":false,"daytonaDaemonBundled":true,"entrypoint":"/usr/local/bin/terminalx-sandbox-init","initializeDaemonTelemetry":false,"otelEnvironmentInjected":false,"providerSandboxTokenInjected":false,"rootSecretsExcludedFromCheckpoints":true,"sandboxImageId":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","sandboxProfileLabel":"io.terminalx.sandbox.profile=v1","sandboxSnapshotRef":"registry.example/terminalx/sandbox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","terminalxHardened":true,"useSnapshotEntrypoint":true,"xDaytonaAuthorizationHeaderForwardedToSandbox":false},"isolationPolicyDigest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","networkPolicyDigest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","observationIssuerKeyId":"observation-key-1","observationKeyProvisioningRefDigest":"eceb84f17b31ac15fe7104b9c1d383cb7020062d6cb1bd391edac69b4aafd760","observationPublicKeyDigest":"13f4e1ff7075a3533c2a9338e89f69f06b5385f604353e75adc4ec64951bd88c","observedAtMs":1800000000000,"planDigest":"bd73b1b1e44d2258a2c06ba92e8c6e93daf9e5d93bf64f0c64d73aec1ba4b859","processBoundary":{"agentCanAccessCredentialChannel":false,"agentCanReadObservationKey":false,"agentCanReadSupervisorState":false,"agentCanSignalSupervisor":false,"agentCanWriteEffectExecutor":false,"agentCanWriteSupervisorExecutable":false,"agentUid":10001,"daytonaDaemonUid":10001,"observationKeyOwnerUid":0,"rootOwnedLocalCredentialChannel":true,"stateOwnerUid":0,"supervisorUid":0},"providerIdentityCommitment":"19c21b79c5f246b9eaf659c1cdb96d1f02637a8daaa4c23ed423a897e1d24468","providerRevision":7,"resources":{"cpu":2,"diskGiB":20,"memoryGiB":4,"pids":256},"runnerEnforcement":{"backingFilesystem":"xfs","backupsDisabled":true,"blockAllEgressInstalledBeforeStart":true,"builtInSeccomp":true,"containerdVersion":"2.2.1","dockerDriver":"overlay2","dockerUserEgressDropBeforeStart":true,"dockerVersion":"29.1.3","genericBuildsDisabled":true,"inputEstablishedRepliesAllowed":true,"inputHostNewDrop":true,"interSandboxNetworking":false,"resizesDisabled":true,"resourceLimitsEnabled":true,"snapshotsDisabled":true,"xfsProjectQuotaEnabled":true},"runnerNetwork":{"driver":"bridge","interContainerCommunication":false,"internal":true,"ipv4Only":true,"label":"io.terminalx.runner-network=v1","scope":"local","subnet":"172.20.0.0/16"},"sandboxUser":"terminalx","source":{"baseAncestryVerified":true,"baseCommit":"b5a5d9e78d76c8bcf351f2049620250e0f34eea4","hardenedCommit":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"},"supervisorArtifactDigest":"2222222222222222222222222222222222222222222222222222222222222222","version":1},"kind":"terminalx.daytona-effective-isolation","version":1}`;

// Keep the prior literal visible beside the exact schema/signature delta that the
// hardened fork introduced for assignment-scoped effect-policy binding.
const CURRENT_GO_RUNNER_PLAN_JSON = GO_RUNNER_PLAN_JSON.replace(
  `,"incarnation":`,
  `,"effectEnforcerPolicyDigest":"","incarnation":`
);
const CURRENT_GO_RUNNER_EVIDENCE_JSON = GO_RUNNER_EVIDENCE_JSON.replace(
  "bbc0842dffcf0560565520cad49391da6c06eccd72cf62988a995dae39b1978b",
  "eea4dd7126d1179f3533c4cc0295cadba78f914503662f98e6c5d54a833d9b4e"
)
  .replace(
    "SmJNRkV7-nR4ZhuqAR_NH4Z0v_UHqBCcFenMgktnxS6BR6zKLG6VY8ym2_5GmlvdRKHqJNdn60wyH_gJpkLPCQ",
    "FpbyZDWD9oTT0fysI5d0naf85sdRV3aJvIvZqiIkSPbLp_htX_MkRjb-ei8NEP5sU4Ug0VHy68hOj2jtRh2RCQ"
  )
  .replace(
    "bd73b1b1e44d2258a2c06ba92e8c6e93daf9e5d93bf64f0c64d73aec1ba4b859",
    "cb3124860e695ed3b7257071dad7ea10033ef27620cbb215666774d28a2ea88b"
  );

const GO_RUNNER_ISOLATION_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=
-----END PUBLIC KEY-----
`;

describe("Daytona effective-isolation Go/TypeScript contract", () => {
  it("accepts the exact canonical evidence signed and serialized by the hardened Go runner", () => {
    const plan = JSON.parse(CURRENT_GO_RUNNER_PLAN_JSON) as HostedRuntimeAssignmentPlan;
    const attestation = JSON.parse(CURRENT_GO_RUNNER_EVIDENCE_JSON) as {
      claims: {
        artifactDigest: string;
        observationIssuerKeyId: string;
        observationPublicKeyDigest: string;
        providerIdentityCommitment: string;
        supervisorArtifactDigest: string;
      };
    };

    expect(canonicalRuntimeJson(plan)).toBe(CURRENT_GO_RUNNER_PLAN_JSON);
    expect(canonicalRuntimeJson(attestation)).toBe(CURRENT_GO_RUNNER_EVIDENCE_JSON);
    expect(createHash("sha256").update(CURRENT_GO_RUNNER_EVIDENCE_JSON).digest("hex")).toBe(
      "3d038d564ea9a9d9dcadecbf0ebb88a38ee4fec47cad5722073bab79828eda47"
    );

    const verify = createDaytonaEffectiveIsolationVerifier({
      issuerKeyId: "isolation-key-1",
      issuerPublicKeySpkiPem: GO_RUNNER_ISOLATION_PUBLIC_KEY,
      hardenedDaytonaSourceCommit: "e".repeat(40),
      expectedSandboxImageId: `sha256:${"a".repeat(64)}`,
      expectedSandboxSnapshotRef: `registry.example/terminalx/sandbox@sha256:${"b".repeat(64)}`,
      expectedSandboxUser: "terminalx",
      expectedSeccompProfileDigest: "7".repeat(64),
      expectedDockerVersion: "29.1.3",
      expectedContainerdVersion: "2.2.1",
      expectedProviderRevision: 7,
      expectedSupervisorUid: 0,
      expectedDaytonaDaemonUid: 10001,
      expectedAgentUid: 10001,
      clock: () => 1_800_000_000_001,
      maximumAttestationTtlMs: 60_000,
    });

    expect(
      verify({
        attestation,
        plan,
        providerIdentityCommitment: attestation.claims.providerIdentityCommitment,
        artifactDigest: attestation.claims.artifactDigest,
        supervisorArtifactDigest: attestation.claims.supervisorArtifactDigest,
        observationIssuerKeyId: attestation.claims.observationIssuerKeyId,
        observationPublicKeyDigest: attestation.claims.observationPublicKeyDigest,
      })
    ).toBe(true);
  });
});
