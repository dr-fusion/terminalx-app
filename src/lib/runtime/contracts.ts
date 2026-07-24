import type {
  ActionClass,
  ActionGrant,
  ActionManifest,
  AgentRunPolicySnapshot,
  GoalSet,
  ResourceEffect,
  RunLimits,
  RuntimeBinding,
  ScopedExternalRule,
} from "../team-sessions/contracts";

export type RuntimeCursor = string;

export interface ResourceProfile {
  readonly cpu: number;
  readonly memoryGiB: number;
  readonly diskGiB: number;
  readonly gpu?: number;
}

export interface ProjectRuntimeCeiling {
  readonly revision: string;
  readonly digest: string;
  readonly allowedModes: ReadonlyArray<"supervised" | "autonomous" | "yolo">;
  readonly yoloEnabled: boolean;
  readonly finiteResourceProfile: ResourceProfile;
  readonly maximumRunLimits: RunLimits;
  readonly scopedExternalRulesDigest: string;
  readonly isolationPolicyDigest: string;
  readonly networkPolicyDigest: string;
  readonly credentialPolicyDigest: string;
}

export interface RuntimeAuthorizationSnapshot {
  readonly generation: number;
  readonly networkPolicyRef: string;
  readonly networkPolicyDigest: string;
  readonly credentialPolicyRef: string;
  readonly credentialPolicyDigest: string;
  readonly effectEnforcerSetDigest: string;
}

export interface RuntimeSpec {
  readonly binding: RuntimeBinding;
  readonly source: {
    readonly sourceRevision: string;
    readonly expectedCommitSha: string;
    readonly setupRef: string;
  };
  readonly harnessRef: string;
  readonly projectCeiling: ProjectRuntimeCeiling;
  readonly authorization: RuntimeAuthorizationSnapshot;
  readonly checkpointPolicyRef: string;
  readonly adapterConfigurationRef: string;
}

export interface RuntimeHandle {
  readonly binding: RuntimeBinding;
  readonly opaqueHandleRef: string;
  readonly capabilities: {
    readonly isolatedExecution: boolean;
    readonly brokeredCredentials: boolean;
    readonly proxyOnlyEgress: boolean;
    readonly checkpoints: boolean;
    readonly yoloEligible: boolean;
  };
}

export type RuntimeCapability =
  | "run.start"
  | "run.revise"
  | "goal-set.apply"
  | "run.pause"
  | "run.resume"
  | "run.stop"
  | "run.emergency-stop"
  | "agent.directive"
  | "terminal.input"
  | "terminal.resize"
  | "process.interrupt"
  | "action.resolve"
  | "fence.advance"
  | "checkpoint.create"
  | "safety.quarantine"
  | "runtime.retire";

interface RuntimeAuthorityEnvelopeBase {
  readonly issuerKeyId: string;
  readonly audience: "runtime";
  readonly claimsDigest: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signature: string;
}

export type PlatformSecurityRuntimeCapability = "run.emergency-stop" | "safety.quarantine";

export type TeamSessionRuntimeAuthorityEnvelope<
  Capability extends RuntimeCapability = RuntimeCapability,
> = RuntimeAuthorityEnvelopeBase & {
  readonly issuer: "team-session";
  readonly capability: Capability;
};

export type PlatformSecurityRuntimeAuthorityEnvelope<
  Capability extends PlatformSecurityRuntimeCapability = PlatformSecurityRuntimeCapability,
> = RuntimeAuthorityEnvelopeBase & {
  readonly issuer: "platform-security";
  readonly capability: Capability;
};

/**
 * Authority is parameterized by the one capability it grants. The conditional
 * branch keeps platform-security authority closed to emergency/quarantine
 * commands while preserving a convenient union when no capability is supplied.
 */
export type RuntimeAuthorityEnvelope<Capability extends RuntimeCapability = RuntimeCapability> =
  Capability extends RuntimeCapability
    ?
        | TeamSessionRuntimeAuthorityEnvelope<Capability>
        | (Capability extends PlatformSecurityRuntimeCapability
            ? PlatformSecurityRuntimeAuthorityEnvelope<Capability>
            : never)
    : never;

/** Destructive Runtime retirement is a distinct Team Session authority. */
export type RuntimeRetireAuthorityEnvelope = TeamSessionRuntimeAuthorityEnvelope<"runtime.retire">;

interface RuntimeCommandBase<Capability extends RuntimeCapability> {
  readonly commandId: string;
  readonly binding: RuntimeBinding;
  readonly projectCeilingRevision: string;
  readonly runtimeAuthorizationGeneration: number;
  readonly causationId: string;
  readonly actor: { readonly kind: "human" | "system"; readonly actorRef: string };
  readonly issuedAtMs: number;
  readonly deadlineAtMs: number;
  readonly authority: RuntimeAuthorityEnvelope<Capability>;
}

interface EmergencyRuntimeCommandBase<
  Capability extends PlatformSecurityRuntimeCapability,
> extends Omit<RuntimeCommandBase<Capability>, "runtimeAuthorizationGeneration"> {
  readonly observedRuntimeAuthorizationGeneration: number;
}

export type FenceAdvance =
  | { readonly kind: "control"; readonly fromEpoch: number; readonly toEpoch: number }
  | {
      readonly kind: "steering";
      readonly fromRevision: number;
      readonly toRevision: number;
      readonly cancelledDirectiveIds: ReadonlyArray<string>;
    }
  | {
      readonly kind: "runtime-authorization";
      readonly fromGeneration: number;
      readonly to: RuntimeAuthorizationSnapshot;
      readonly transition: "tighten" | "widen";
      readonly revokedGrantIds: ReadonlyArray<string>;
      readonly reason:
        | "grant"
        | "credential"
        | "principal"
        | "policy"
        | "assignee-loss"
        | "emergency";
    };

export type CheckpointReason =
  | "baseline"
  | "pre_risk"
  | "pre_policy_widening"
  | "milestone"
  | "periodic"
  | "pause"
  | "crash_recovery"
  | "limit"
  | "manual";

export type RuntimeCommand =
  | (RuntimeCommandBase<"run.start"> & {
      readonly kind: "run.start";
      readonly agentRunId: string;
      readonly runPolicyRevision: number;
      readonly fromRunStateVersion: number;
      readonly toRunStateVersion: number;
      readonly policy: AgentRunPolicySnapshot;
      readonly yoloAuthorization?: {
        readonly manifest: ActionManifest;
        readonly grant: ActionGrant;
      };
    })
  | (RuntimeCommandBase<"run.revise"> & {
      readonly kind: "run.revise";
      readonly currentRevision: number;
      readonly nextPolicy: AgentRunPolicySnapshot;
      readonly nextProjectCeiling: ProjectRuntimeCeiling;
      readonly transition: "tighten" | "widen";
      readonly wideningAuthorization?: {
        readonly manifest: ActionManifest;
        readonly grant: ActionGrant;
      };
    })
  | (RuntimeCommandBase<"goal-set.apply"> & {
      readonly kind: "goal-set.apply";
      readonly agentRunId: string;
      readonly runPolicyRevision: number;
      readonly fromGoalSetRevision: number;
      readonly nextGoalSet: GoalSet;
      readonly attributedDirectiveIds: ReadonlyArray<string>;
    })
  | (RuntimeCommandBase<"run.pause"> & {
      readonly kind: "run.pause";
      readonly agentRunId: string;
      readonly runPolicyRevision: number;
      readonly fromRunStateVersion: number;
      readonly toRunStateVersion: number;
      readonly reason: "human" | "attention_timeout" | "limit" | "safety";
    })
  | (RuntimeCommandBase<"run.resume"> & {
      readonly kind: "run.resume";
      readonly agentRunId: string;
      readonly runPolicyRevision: number;
      readonly fromRunStateVersion: number;
      readonly toRunStateVersion: number;
      readonly accountableAssigneePresent: true;
    })
  | (RuntimeCommandBase<"run.stop"> & {
      readonly kind: "run.stop";
      readonly agentRunId: string;
      readonly runPolicyRevision: number;
      readonly fromRunStateVersion: number;
      readonly toRunStateVersion: number;
      readonly reason: "human" | "final_review_closed" | "superseded";
    })
  | (EmergencyRuntimeCommandBase<"run.emergency-stop"> & {
      readonly kind: "run.emergency-stop";
      readonly observedAgentRun?: {
        readonly agentRunId: string;
        readonly runPolicyRevision: number;
      };
      readonly observedControlEpoch: number;
      readonly observedSteeringPolicyRevision: number;
      readonly reasonRef: string;
      readonly advanceBeyondCurrentFences: true;
      readonly revokeAllRunGrants: true;
    })
  | (RuntimeCommandBase<"agent.directive"> & {
      readonly kind: "agent.directive";
      readonly agentRunId: string;
      readonly policyRevision: number;
      readonly directiveId: string;
      readonly canonicalOrder: number;
      readonly steeringPolicyRevision: number;
      readonly sanitizedContentRef: string;
      readonly contentDigest: string;
      readonly explicitlyNamedExternalRules: ReadonlyArray<ScopedExternalRule>;
    })
  | (RuntimeCommandBase<"terminal.input"> & {
      readonly kind: "terminal.input";
      readonly controllerEpoch: number;
      readonly bytes: Uint8Array;
    })
  | (RuntimeCommandBase<"terminal.resize"> & {
      readonly kind: "terminal.resize";
      readonly controllerEpoch: number;
      readonly columns: number;
      readonly rows: number;
    })
  | (RuntimeCommandBase<"process.interrupt"> & {
      readonly kind: "process.interrupt";
      readonly controllerEpoch: number;
      readonly signal: "interrupt";
    })
  | (RuntimeCommandBase<"action.resolve"> & {
      readonly kind: "action.resolve";
      readonly resolution:
        | {
            readonly outcome: "authorized";
            readonly proposalId: string;
            readonly manifest: ActionManifest;
            readonly grant: ActionGrant;
          }
        | {
            readonly outcome: "denied" | "superseded";
            readonly proposalId: string;
            readonly manifestDigest: string;
            readonly approvalRequestId: string;
            readonly approvalRequestVersion: number;
          };
    })
  | (RuntimeCommandBase<"fence.advance"> & {
      readonly kind: "fence.advance";
      readonly fence: FenceAdvance;
    })
  | (RuntimeCommandBase<"checkpoint.create"> & {
      readonly kind: "checkpoint.create";
      readonly agentRunId?: string;
      readonly reason: CheckpointReason;
    })
  | (RuntimeCommandBase<"safety.quarantine"> & {
      readonly kind: "safety.quarantine";
      readonly reasonRef: string;
    });

export type RuntimeLifecycleCommand = Extract<
  RuntimeCommand,
  { readonly kind: "run.start" | "run.pause" | "run.resume" | "run.stop" }
>;

/** Existing-Run transitions currently supported by the fail-closed execution Module. */
export type RuntimePostStartLifecycleCommand = Extract<
  RuntimeLifecycleCommand,
  { readonly kind: "run.pause" | "run.resume" | "run.stop" }
>;

export interface AggregateEnforcementProof {
  readonly generation: number;
  readonly requiredEffectEnforcerSetDigest: string;
  readonly acknowledgements: ReadonlyArray<{
    readonly enforcerRef: string;
    readonly enforcerKind:
      | "runtime"
      | "credential-proxy"
      | "source-control"
      | "deployment"
      | "signer"
      | "other-effect-enforcer";
    readonly acknowledgementDigest: string;
  }>;
  /**
   * Internal canonical integrity digest. A consumer must still bind
   * `requiredEffectEnforcerSetDigest` to its trusted authorization snapshot
   * before treating the proof as an authoritative cross-enforcer attestation.
   */
  readonly aggregateProofDigest: string;
}

interface RuntimeReceiptBase {
  readonly commandId: string;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
}

/** A complete first-processing result, retained verbatim by duplicate receipts. */
export type NonDuplicateRuntimeReceipt = RuntimeReceiptBase &
  (
    | { readonly outcome: "accepted"; readonly effectRef: string }
    | {
        readonly outcome: "enforced";
        readonly effectRef: string;
        readonly enforcedFence: number;
        readonly aggregateEnforcementProof?: AggregateEnforcementProof;
      }
    | {
        readonly outcome: "rejected";
        readonly code:
          | "invalid_authority"
          | "expired"
          | "stale_binding"
          | "stale_fence"
          | "conflicting_duplicate"
          | "policy_exceeds_ceiling"
          | "policy_revision_conflict"
          | "second_active_run"
          | "awaiting_assignee"
          | "invalid_manifest"
          | "invalid_grant"
          | "grant_consumed"
          | "action_already_resolved"
          | "forbidden"
          | "not_ready";
        readonly safeDetail: string;
      }
    | {
        readonly outcome: "quarantined";
        readonly reason:
          | "authorization_ack_failed"
          | "effect_enforcer_set_mismatch"
          | "isolation_failure"
          | "kill_failure";
        readonly effectRef: string;
      }
  );

export type RuntimeReceipt =
  | NonDuplicateRuntimeReceipt
  | (RuntimeReceiptBase & {
      readonly outcome: "duplicate";
      readonly originalReceipt: NonDuplicateRuntimeReceipt;
      /** Lowercase SHA-256 of the strict canonical JSON form of `originalReceipt`. */
      readonly originalReceiptDigest: string;
    });

export interface UsageSnapshot {
  readonly usage: ResourceEffect;
  readonly ledgerRevision: number;
  readonly ledgerDigest: string;
}

export interface ArtifactChunkRef {
  readonly artifactRef: string;
  readonly offset: number;
  readonly length: number;
  readonly digest: string;
  readonly mediaType: string;
}

export interface GrantUsageLedgerSnapshot {
  readonly grantId: string;
  readonly ledgerRevision: number;
  readonly reserved: ResourceEffect;
  readonly consumed: ResourceEffect;
  readonly remaining: ResourceEffect;
  readonly digest: string;
}

export interface CheckpointDescriptor {
  readonly checkpointRef: string;
  readonly checkpointDigest: string;
  readonly sourceBinding: RuntimeBinding;
  readonly encryptionDomainRef: string;
  readonly classification: "session-sensitive";
  readonly brokeredCredentialValuesIncluded: false;
  readonly signature: string;
}

interface RuntimeEventBase {
  readonly eventId: string;
  readonly cursor: RuntimeCursor;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly agentRun?: { readonly agentRunId: string; readonly runPolicyRevision: number };
  readonly actor?: { readonly kind: "human" | "agent" | "system"; readonly actorRef: string };
  readonly causationId?: string;
  readonly observedAtMs: number;
}

export type RuntimeEvent = RuntimeEventBase &
  (
    | {
        readonly kind: "runtime.ready";
        readonly payload: {
          readonly capabilities: RuntimeHandle["capabilities"];
          readonly runtimeAuthorizationGeneration: number;
          readonly policyDigests: ReadonlyArray<string>;
          readonly requiredEffectEnforcerSetDigest: string;
        };
      }
    | {
        readonly kind: "runtime.heartbeat";
        readonly payload: { readonly health: "healthy" | "degraded"; readonly expiresAtMs: number };
      }
    | {
        readonly kind: "runtime.quarantined";
        readonly payload: {
          readonly reason: string;
          readonly lastEnforcedAuthorizationGeneration: number;
        };
      }
    | {
        readonly kind: "runtime.retired";
        readonly payload: {
          readonly disposition: "release_compute_preserve_state" | "destroy_sandbox_state";
          readonly cleanupProofDigest: string;
        };
      }
    | { readonly kind: "terminal.output"; readonly payload: ArtifactChunkRef }
    | {
        readonly kind: "run.started" | "run.policy-applied";
        readonly payload: {
          readonly agentRunId: string;
          readonly revision: number;
          readonly policyDigest: string;
        };
      }
    | {
        readonly kind:
          | "run.pausing"
          | "run.paused"
          | "run.resumed"
          | "run.awaiting-final-review"
          | "run.agent-work-finished"
          | "run.failed";
        readonly payload: {
          readonly agentRunId: string;
          readonly revision: number;
          readonly safeReason?: string;
        };
      }
    | {
        readonly kind: "run.stopped";
        readonly payload: {
          readonly agentRunId: string;
          readonly revision: number;
          readonly checkpointRef?: string;
          readonly expiredGrantIds: ReadonlyArray<string>;
          readonly safeReason?: string;
        };
      }
    | {
        readonly kind: "run.emergency-stopped";
        readonly payload: {
          readonly agentRunId?: string;
          readonly advancedControlEpoch: number;
          readonly advancedSteeringPolicyRevision: number;
          readonly advancedRuntimeAuthorizationGeneration: number;
          readonly revokedAllRunGrants: true;
          readonly aggregateEnforcementProof: AggregateEnforcementProof;
        };
      }
    | {
        readonly kind: "goal-set.applied";
        readonly payload: {
          readonly agentRunId: string;
          readonly runPolicyRevision: number;
          readonly goalSet: GoalSet;
        };
      }
    | {
        readonly kind: "goal.progress" | "goal.provisionally-achieved";
        readonly payload: {
          readonly agentRunId: string;
          readonly goalId: string;
          readonly evidenceRefs: ReadonlyArray<string>;
        };
      }
    | {
        readonly kind: "action.proposed";
        readonly payload: {
          readonly proposalId: string;
          readonly classification: "scoped-external" | "protected";
          readonly manifest: ActionManifest;
        };
      }
    | {
        readonly kind: "action.denied";
        readonly payload: {
          readonly classification: "forbidden";
          readonly actionClass: ActionClass;
          readonly reason: string;
        };
      }
    | {
        readonly kind:
          | "action.started"
          | "action.completed"
          | "action.failed"
          | "action.outcome-uncertain";
        readonly payload: {
          readonly manifestDigest: string;
          readonly canonicalEffectInputDigest: string;
          readonly effectIdempotencyKey: string;
          readonly grantId?: string;
          readonly safeOutcomeRef?: string;
        };
      }
    | { readonly kind: "grant.usage-updated"; readonly payload: GrantUsageLedgerSnapshot }
    | {
        readonly kind: "grant-review.required";
        readonly payload: {
          readonly previousRuntimeAuthorizationGeneration: number;
          readonly currentRuntimeAuthorizationGeneration: number;
          readonly staleGrantIds: ReadonlyArray<string>;
          readonly intentionallyRevokedGrantIds: ReadonlyArray<string>;
        };
      }
    | {
        readonly kind: "attention.needed";
        readonly payload: {
          readonly reason: string;
          readonly exactManifest?: ActionManifest;
          readonly proposedActionRef?: string;
          readonly risk: string;
          readonly eligibleCapability: RuntimeCapability;
          readonly suggestedDeadlineAtMs?: number;
          readonly independentAuthorizedWorkMayContinue: boolean;
        };
      }
    | {
        readonly kind: "usage.observed" | "usage.warning" | "usage.limit-reached";
        readonly payload: {
          readonly agentRunId: string;
          readonly usage: UsageSnapshot;
          readonly threshold?: 0.75 | 0.9 | 1;
        };
      }
    | {
        readonly kind: "authorization.acknowledged";
        readonly payload: {
          readonly generation: number;
          readonly networkDigest: string;
          readonly credentialDigest: string;
          readonly aggregateEnforcementProof: AggregateEnforcementProof;
        };
      }
    | {
        readonly kind: "authorization.failed";
        readonly payload: { readonly requestedGeneration: number; readonly safeReason: string };
      }
    | {
        readonly kind: "credential.connection-closed";
        readonly payload: {
          readonly credentialRef: string;
          readonly reason: "revoked" | "expired" | "emergency";
        };
      }
    | {
        readonly kind: "artifact.created";
        readonly payload: {
          readonly artifactRef: string;
          readonly digest: string;
          readonly mediaType: string;
        };
      }
    | {
        readonly kind: "checkpoint.created" | "checkpoint.restored";
        readonly payload: {
          readonly checkpoint: CheckpointDescriptor;
          readonly reason: CheckpointReason;
          readonly executionBaselineDigest: string;
          readonly externalEffectsReversed: false;
        };
      }
    | {
        readonly kind: "process.exited";
        readonly payload: {
          readonly processRef: string;
          readonly exitCode?: number;
          readonly signal?: string;
        };
      }
    | {
        readonly kind: "runtime.failed";
        readonly payload: {
          readonly code: string;
          readonly recoverable: boolean;
          readonly safeDetail: string;
        };
      }
  );

export interface RuntimeRetireRequest {
  readonly retirementId: string;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly reason: "archive" | "replacement" | "retention_expired" | "project_destroyed";
  readonly disposition:
    | { readonly kind: "release_compute_preserve_state"; readonly decisionRef: string }
    | {
        readonly kind: "destroy_sandbox_state";
        readonly destructionAuthorizationRef: string;
        readonly expectedSandboxGeneration: number;
      };
  readonly authority: RuntimeRetireAuthorityEnvelope;
  readonly deadlineAtMs: number;
}

/** Deep Runtime Interface. Provider-native identifiers and credentials stay behind this Seam. */
export interface Runtime {
  ensure(spec: RuntimeSpec): Promise<RuntimeHandle>;
  command(handle: RuntimeHandle, command: RuntimeCommand): Promise<RuntimeReceipt>;
  follow(handle: RuntimeHandle, cursor?: RuntimeCursor): AsyncIterable<RuntimeEvent>;
  retire(handle: RuntimeHandle, request: RuntimeRetireRequest): Promise<void>;
}
