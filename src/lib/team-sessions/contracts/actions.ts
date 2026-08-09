import type { ActorContext, CommandIdempotency } from "../types";
import type { DirectiveAttributionInput } from "./agent-runs";
import type { ActionClass, ResourceEffect, RuntimeBinding } from "./shared";

export type ApprovableActionClass = "scoped-external" | "protected";

export interface ActionSchemaRef {
  readonly schemaId: string;
  readonly schemaVersion: number;
  readonly schemaDigest: string;
  readonly canonicalizationProfile: "terminalx-canonical-effect-v1";
  readonly unknownFields: "reject";
}

export interface ActionManifest {
  readonly version: 1;
  readonly manifestId: string;
  readonly digest: string;
  readonly actionClass: ActionClass;
  readonly provider: string;
  readonly operation: string;
  readonly exactTarget: string;
  readonly actionSchema: ActionSchemaRef;
  readonly canonicalEffectInputDigest: string;
  readonly effectIdempotencyKey: string;
  readonly commitSha?: string;
  readonly artifactDigest?: string;
  readonly credentialRef?: string;
  readonly expectedEffect: ResourceEffect;
  readonly expiresAtMs: number;
}

export type ApprovalRequestStatus = "open" | "approved" | "denied" | "expired" | "superseded";

export type EligibleRunGrantUse =
  | "session_branch_push"
  | "draft_pull_request_update"
  | "ephemeral_preview_update"
  | "same_credential_nonproduction_target";

export interface RunActionPattern {
  readonly actionClass: "scoped-external";
  readonly provider: string;
  readonly operation: string;
  readonly targetPattern: string;
  readonly credentialRef?: string;
  readonly eligibleUse: EligibleRunGrantUse;
  readonly digest: string;
}

interface ApprovalRequestBase {
  readonly approvalRequestId: string;
  readonly version: number;
  readonly requestDigest: string;
  readonly teamId: string;
  readonly projectId: string;
  readonly sessionId: string;
  readonly agentRunId: string;
  readonly runPolicyRevision: number;
  readonly runtimeBinding: RuntimeBinding;
  readonly runtimeAuthorizationGeneration: number;
  readonly status: ApprovalRequestStatus;
  readonly expiresAtMs: number;
  readonly createdAtMs: number;
  readonly resolvedAtMs?: number;
  readonly resolvedByActorRef?: string;
}

export type ApprovalRequest = ApprovalRequestBase &
  (
    | {
        readonly actionClass: ApprovableActionClass;
        readonly subject: {
          readonly kind: "manifest";
          readonly manifestId: string;
          readonly manifestDigest: string;
        };
      }
    | {
        readonly actionClass: "scoped-external";
        readonly subject: { readonly kind: "run-pattern"; readonly pattern: RunActionPattern };
      }
  );

export interface ActionGrantBudget {
  readonly perEffectLimit: ResourceEffect;
  readonly cumulativeLimit: ResourceEffect;
}

export type ActionGrantStatus =
  | "issued"
  | "enforcement-pending"
  | "active"
  | "consumed"
  | "expired"
  | "revoked"
  | "invalidated"
  | "enforcement-failed";

export type GrantReviewReason =
  | "policy-revision"
  | "runtime-assignment"
  | "sandbox-generation"
  | "runtime-authorization"
  | "credential"
  | "explicit-revocation"
  | "recovery";

export type GrantReviewStatus = "open" | "resolved" | "superseded";

/** Canonical, versioned review opened whenever old grants cannot carry forward implicitly. */
export interface GrantReview {
  readonly grantReviewId: string;
  readonly version: number;
  readonly previousVersion?: number;
  readonly sessionId: string;
  readonly agentRunId: string;
  readonly reason: GrantReviewReason;
  readonly safeDefault: "revoke-all";
  readonly status: GrantReviewStatus;
  readonly staleGrantIds: ReadonlyArray<string>;
  readonly intentionallyRevokedGrantIds: ReadonlyArray<string>;
  readonly reissuableCandidateGrantIds: ReadonlyArray<string>;
  readonly target: {
    readonly runPolicyRevision: number;
    readonly runtimeBinding: RuntimeBinding;
    readonly runtimeAuthorizationGeneration: number;
  };
  readonly resolution?:
    | { readonly kind: "revoke-all" }
    | {
        readonly kind: "reissue-selected";
        readonly selectedCandidateGrantIds: ReadonlyArray<string>;
      };
  readonly createdAtMs: number;
  readonly resolvedAtMs?: number;
  readonly resolvedByActorRef?: string;
}

interface ActionGrantBase {
  readonly grantId: string;
  readonly teamId: string;
  readonly projectId: string;
  readonly sessionId: string;
  readonly agentRunId: string;
  readonly runPolicyRevision: number;
  readonly runtimeAssignmentId: string;
  readonly runtimeAssignmentGeneration: number;
  readonly sandboxId: string;
  readonly sandboxGeneration: number;
  readonly runtimePrincipalId: string;
  readonly runtimeAuthorizationGeneration: number;
  readonly approvalRequestId: string;
  readonly approvalRequestVersion: number;
  readonly provider: string;
  readonly operation: string;
  readonly target: string;
  readonly credentialRef?: string;
  readonly budget: ActionGrantBudget;
  readonly usageLedgerRef: string;
  readonly issuerActorRef: string;
  readonly issuerApprovalAuthorityRevision: string;
  readonly expiresAtMs: number;
  readonly signature: string;
  readonly createdAtMs: number;
}

type OnceActionGrantScope = {
  readonly kind: "once";
  readonly manifestDigest: string;
  readonly effectIdempotencyKey: string;
};

export type ActionGrant = ActionGrantBase &
  (
    | { readonly actionClass: "protected"; readonly scope: OnceActionGrantScope }
    | {
        readonly actionClass: "scoped-external";
        readonly scope: OnceActionGrantScope | ({ readonly kind: "run" } & RunActionPattern);
      }
  );

export type AttentionRequestStatus = "open" | "resolved" | "superseded" | "timed-out";

export interface AttentionRequest {
  readonly attentionRequestId: string;
  readonly version: number;
  readonly teamId: string;
  readonly projectId: string;
  readonly sessionId: string;
  readonly agentRunId: string;
  readonly runPolicyRevision: number;
  readonly reason: string;
  readonly exactProposal:
    | {
        readonly kind: "action-manifest";
        readonly manifestId: string;
        readonly manifestDigest: string;
      }
    | {
        readonly kind: "structured-decision";
        readonly decisionRef: string;
        readonly decisionDigest: string;
      };
  readonly risk: string;
  readonly eligibleResponderCapabilities: ReadonlyArray<string>;
  readonly validResolutions: ReadonlyArray<
    "deny-proposed-action" | "supersede-with-directive" | "answer"
  >;
  readonly deadlineAtMs: number;
  readonly status: AttentionRequestStatus;
  readonly linkedApprovalRequest?: {
    readonly approvalRequestId: string;
    readonly approvalRequestVersion: number;
    readonly actionClass: ApprovableActionClass;
    readonly denialRequiresMatchingApprovalAuthority: true;
  };
  readonly independentAuthorizedWorkMayContinue: boolean;
  readonly createdAtMs: number;
  readonly resolvedAtMs?: number;
}

export type ActionControlCommandPayload =
  | {
      readonly type: "approval.resolve";
      readonly sessionId: string;
      readonly approvalRequestId: string;
      readonly expectedRequestVersion: number;
      readonly requestDigest: string;
      readonly displayedPolicyDigest: string;
      readonly runPolicyRevision: number;
      readonly runtimeAssignmentGeneration: number;
      readonly sandboxGeneration: number;
      readonly runtimeAuthorizationGeneration: number;
      readonly resolution:
        | { readonly kind: "approve-once"; readonly manifestDigest: string }
        | { readonly kind: "approve-for-run"; readonly actionPatternDigest: string }
        | { readonly kind: "deny" };
    }
  | {
      readonly type: "grant.revoke";
      readonly sessionId: string;
      readonly actionGrantId: string;
      readonly expectedGrantVersion: number;
    }
  | {
      readonly type: "grant.review.resolve";
      readonly sessionId: string;
      readonly grantReviewId: string;
      readonly expectedReviewVersion: number;
      readonly resolution:
        | { readonly kind: "revoke-all" }
        | {
            readonly kind: "reissue-selected";
            readonly candidateGrantIds: ReadonlyArray<string>;
            readonly targetRunPolicyRevision: number;
            readonly targetRuntimeAssignmentGeneration: number;
            readonly targetRuntimeAuthorizationGeneration: number;
          };
    }
  | {
      readonly type: "attention.resolve";
      readonly sessionId: string;
      readonly attentionRequestId: string;
      readonly expectedRequestVersion: number;
      readonly resolution:
        | { readonly kind: "deny-proposed-action" }
        | {
            readonly kind: "supersede-with-directive";
            readonly directive: DirectiveAttributionInput;
            readonly expectedDirectiveQueueRevision: number;
          }
        | {
            readonly kind: "answer";
            readonly optionId: string;
            readonly structuredAnswerRef: string;
            readonly structuredAnswerDigest: string;
          };
    };

/** Phase 4 command envelope. It joins SessionCommand when its handlers and HTTP allowlist land. */
export type ActionControlSessionCommand = ActionControlCommandPayload & {
  readonly schemaVersion: 1;
  readonly actor: ActorContext;
  readonly idempotency: CommandIdempotency;
  readonly occurredAtMs?: number;
};
