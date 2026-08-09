import type { ActorContext, CommandIdempotency } from "../types";
import type { ActionClass, Duration, Money, RuntimeBinding } from "./shared";

export type AgentRunMode = "supervised" | "autonomous" | "yolo";

export type AgentRunLifecycle =
  | "starting"
  | "active"
  | "pausing"
  | "paused"
  | "agent-work-finished"
  | "completed"
  | "failed"
  | "stopped"
  | "emergency-stopped";

export type CompletionPolicy =
  | { readonly kind: "stop-after-directed-work" }
  | { readonly kind: "continue-until-all-goals-achieved" };

/** A missing user cap is always explicit; null, omission, zero, and Infinity are not sentinels. */
export type RunLimit<T> =
  | { readonly kind: "unconfigured" }
  | { readonly kind: "capped"; readonly value: T };

export interface RunLimits {
  readonly wallClock: RunLimit<Duration>;
  readonly modelTokens: RunLimit<number>;
  readonly modelSpend: RunLimit<Money>;
  readonly outboundBytes: RunLimit<number>;
  readonly actionCounts: Readonly<Record<ActionClass, RunLimit<number>>>;
}

export interface GoalDefinition {
  readonly goalId: string;
  readonly position: number;
  readonly title: string;
  readonly acceptanceCriteria: ReadonlyArray<string>;
  readonly dependencyGoalIds: ReadonlyArray<string>;
}

export type GoalStatus =
  | "pending"
  | "in-progress"
  | "blocked"
  | "provisionally-achieved"
  | "validated";

export interface GoalItem extends GoalDefinition {
  readonly version: number;
  readonly status: GoalStatus;
}

export interface GoalSet {
  readonly goalSetId: string;
  readonly agentRunId: string;
  readonly revision: number;
  readonly previousRevision?: number;
  readonly digest: string;
  readonly goals: ReadonlyArray<GoalItem>;
}

/** Evidence is always an opaque artifact reference, never copied provider output or a secret. */
export interface GoalEvidence {
  readonly evidenceId: string;
  readonly agentRunId: string;
  readonly goalSetRevision: number;
  readonly goalId: string;
  readonly goalVersion: number;
  readonly evidenceRef: string;
  readonly evidenceDigest: string;
  readonly status: "proposed" | "validated" | "more-work-requested";
  readonly createdAtMs: number;
  readonly reviewedAtMs?: number;
}

export interface ScopedExternalRule {
  readonly actionClass: ActionClass;
  readonly provider: string;
  readonly operation: string;
  readonly targetPattern: string;
  readonly credentialRef?: string;
}

export interface RunPolicyDraft {
  readonly mode: AgentRunMode;
  readonly completionPolicy: CompletionPolicy;
  readonly scopedExternalPolicyRef: string;
  readonly limits: RunLimits;
}

export interface YoloConfirmation {
  readonly challengeId: string;
  readonly challengeVersion: number;
  readonly policyDigest: string;
  readonly warningDigest: string;
  readonly sessionNameRevision: number;
  readonly typedSessionName: string;
  readonly projectCeilingRevision: string;
  readonly sourceRevision: string;
  readonly sandboxId: string;
  readonly sandboxGeneration: number;
  readonly sandboxProfileDigest: string;
  readonly runtimeAssignmentGeneration: number;
  readonly runtimeAuthorizationGeneration: number;
  readonly credentialPolicyDigest: string;
  readonly networkPolicyDigest: string;
  readonly limitsDigest: string;
}

export interface RunPolicyCommit {
  readonly policy: RunPolicyDraft;
  readonly policyDigest: string;
  readonly expectedProjectCeilingRevision: string;
  readonly expectedRuntimeAssignmentGeneration: number;
  readonly expectedSandboxGeneration: number;
  readonly expectedRuntimeAuthorizationGeneration: number;
  readonly previewId?: string;
  readonly yoloConfirmation?: YoloConfirmation;
  readonly wideningActionGrantId?: string;
}

/** Complete immutable snapshot supplied to Runtime for a particular policy revision. */
export interface RunPolicyRevision extends RunPolicyDraft {
  readonly agentRunId: string;
  readonly revision: number;
  readonly previousRevision?: number;
  /** Digest of the complete exact-bound immutable snapshot. */
  readonly digest: string;
  /** Stable digest of the semantic policy body, used to recognize an exact rebind. */
  readonly policyBodyDigest: string;
  readonly initialGoalSet: GoalSet;
  readonly scopedExternalRules: ReadonlyArray<ScopedExternalRule>;
  readonly projectCeilingRevision: string;
  readonly projectCeilingDigest: string;
  readonly binding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  /** Immutable trusted authorization-epoch commitment, never supplied by Runtime. */
  readonly requiredEffectEnforcerSetDigest: string;
  readonly yoloConfirmationRef?: string;
  readonly createdAtMs: number;
}

/** Alias retained for the Runtime architecture terminology. */
export type AgentRunPolicySnapshot = RunPolicyRevision;

export interface AgentRun {
  readonly agentRunId: string;
  readonly teamId: string;
  readonly projectId: string;
  readonly sessionId: string;
  readonly lifecycle: AgentRunLifecycle;
  readonly stateVersion: number;
  readonly currentRunPolicyRevision: number;
  readonly currentGoalSetRevision: number;
  readonly runtimeBinding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly finalReviewVersion: number;
  readonly createdByUserId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly terminalAtMs?: number;
}

export interface DirectiveAttributionInput {
  readonly format: "plain-text";
  readonly body: string;
}

export type AgentRunCommandPayload =
  | {
      readonly type: "run.start";
      readonly sessionId: string;
      readonly expectedSessionRevision: number;
      readonly initialGoals: ReadonlyArray<GoalDefinition>;
      readonly commit: RunPolicyCommit;
      readonly initialYoloActionGrantId?: string;
    }
  | {
      readonly type: "run.policy.revise";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly expectedRunPolicyRevision: number;
      readonly commit: RunPolicyCommit;
    }
  | {
      readonly type: "run.pause";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly expectedRunStateVersion: number;
      readonly reason?: string;
    }
  | {
      readonly type: "run.resume";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly expectedRunStateVersion: number;
      readonly expectedRunPolicyRevision: number;
      readonly expectedRuntimeAuthorizationGeneration: number;
    }
  | {
      readonly type: "run.stop";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly expectedRunStateVersion: number;
      readonly reason?: string;
    }
  | {
      readonly type: "run.emergency-stop";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly runtimeBinding: Pick<
        RuntimeBinding,
        "runtimeAssignmentId" | "runtimeAssignmentGeneration" | "sandboxId" | "sandboxGeneration"
      >;
      readonly observedSubordinateFences: {
        readonly runStateVersion?: number;
        readonly steeringRevision?: number;
        readonly controlFencingEpoch?: number;
        readonly runtimeAuthorizationGeneration?: number;
      };
      readonly revokeAllRunGrants: true;
      readonly reason: string;
    }
  | {
      readonly type: "goal.add";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly expectedGoalSetRevision: number;
      readonly goal: GoalDefinition;
      readonly directive: DirectiveAttributionInput;
    }
  | {
      readonly type: "goal.criteria.strengthen";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly goalId: string;
      readonly expectedGoalSetRevision: number;
      readonly addedCriteria: ReadonlyArray<string>;
      readonly directive: DirectiveAttributionInput;
    }
  | {
      readonly type: "goal.dependency.add";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly goalId: string;
      readonly expectedGoalSetRevision: number;
      readonly dependencyGoalId: string;
      readonly directive: DirectiveAttributionInput;
    }
  | {
      readonly type: "goal.reorder";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly goalId: string;
      readonly beforeGoalId?: string;
      readonly expectedGoalSetRevision: number;
      readonly directive: DirectiveAttributionInput;
    }
  | {
      readonly type: "goal.evidence.review";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly goalId: string;
      readonly expectedGoalVersion: number;
      readonly disposition: "validate" | "request-more-work";
      readonly directive?: DirectiveAttributionInput;
    }
  | {
      readonly type: "run.final-review.resolve";
      readonly sessionId: string;
      readonly agentRunId: string;
      readonly expectedFinalReviewVersion: number;
      readonly resolution:
        | { readonly kind: "accept-outcome" }
        | { readonly kind: "continue-work"; readonly directive: DirectiveAttributionInput };
    };

/** Phase 4 command envelope. It joins SessionCommand when its handlers and HTTP allowlist land. */
export type AgentRunSessionCommand = AgentRunCommandPayload & {
  readonly schemaVersion: 1;
  readonly actor: ActorContext;
  readonly idempotency: CommandIdempotency;
  readonly occurredAtMs?: number;
};

export interface SessionRunStateQuery {
  readonly schemaVersion: 1;
  readonly actor: ActorContext;
  readonly type: "session.run-state";
  readonly sessionId: string;
}

export interface SessionRunStateView {
  readonly agentRunId: string;
  readonly lifecycle: AgentRunLifecycle;
  readonly stateVersion: number;
  readonly pendingLifecycleOperation: {
    readonly kind: "start" | "pause" | "resume" | "stop";
    readonly status: "queued" | "awaiting-runtime" | "compensating";
    readonly requestedAtMs: number;
  } | null;
  readonly attention: {
    readonly openRequestIds: ReadonlyArray<string>;
    readonly blockingRequestIds: ReadonlyArray<string>;
    readonly independentAuthorizedWorkMayContinue: boolean;
  };
  readonly limitStatus:
    | "accounting-unavailable"
    | "within-configured-limits"
    | "warning-75-percent"
    | "approaching-90-percent"
    | "configured-limit-reached";
  readonly sandboxState:
    | "provisioning"
    | "ready"
    | "checkpointing"
    | "recovering"
    | "quarantined"
    | "retired"
    | "failed";
  readonly finalReviewState: "not-ready" | "open" | "accepted";
  readonly mode: AgentRunMode;
  readonly runPolicyRevision: number;
  readonly goalSetRevision: number;
  readonly finalReviewVersion: number;
  readonly limits: RunLimits;
  /** True only when the current immutable policy names the current exact Runtime fence. */
  readonly policyRuntimeBindingCurrent: boolean;
  readonly runtimeAssignmentGeneration: number;
  readonly sandboxGeneration: number;
  readonly runtimeAuthorizationGeneration: number;
  readonly completionPolicy: CompletionPolicy["kind"];
  readonly goals: ReadonlyArray<GoalItem & { readonly evidence: ReadonlyArray<GoalEvidence> }>;
}
