import type { RunLimit, RunLimits, SessionRunStateView } from "./contracts";
import type {
  PublicSessionAgentRunView,
  PublicSessionGoalEvidenceSummary,
  PublicSessionRunCapabilities,
  PublicSessionRunLimitsSummary,
  PublicSessionRunStartAvailability,
  PublicSessionRunStartReason,
  PublicSessionRunStateView,
  SessionDetailView,
} from "./types";

const MAX_GOALS = 100;
const MAX_CRITERIA_PER_GOAL = 32;
const MAX_DEPENDENCIES_PER_GOAL = 99;
const MAX_EVIDENCE_PER_GOAL = 100;

const MUTABLE_RUN_LIFECYCLES = new Set(["active", "pausing", "paused", "agent-work-finished"]);

/**
 * Convert the internal actor-scoped Run query into the deliberately smaller
 * browser contract. Keep this projection explicit: spreading an internal Run,
 * policy, evidence, approval, grant, or Runtime object here is forbidden.
 */
export function projectPublicSessionRunState(
  session: SessionDetailView,
  run: SessionRunStateView | null
): PublicSessionRunStateView {
  const responsibilities = new Set(session.viewer.responsibilities);
  const manager = responsibilities.has("assignee") || responsibilities.has("supervisor");
  const mutableRun = run !== null && MUTABLE_RUN_LIFECYCLES.has(run.lifecycle);
  const start = projectStartAvailability(session, manager, mutableRun);
  // These are browser actions, not abstract authority hints. Keep every action
  // false until its HTTP command surface and exact-bound Runtime enforcement
  // land together. The kernel predicates remain the source for that future
  // release, but exposing them early would advertise SQLite-only transitions.
  const capabilities: PublicSessionRunCapabilities = {
    startRun: false,
    reviseRunPolicy: false,
    pauseRun: false,
    resumeRun: false,
    stopRun: false,
    emergencyStopRun: false,
    editGoals: false,
    reviewGoalEvidence: false,
    resolveFinalReview: false,
    viewActionCenter: false,
    resolveAttention: false,
    resolveApprovals: false,
    revokeRunGrants: false,
    resolveGrantReviews: false,
  };

  return {
    sessionId: boundedIdentifier(session.sessionId, "Session id"),
    asOfSequence: nonNegativeInteger(session.latestSequence, "Session sequence"),
    runStateRevision: positiveInteger(session.viewer.basis.runStateRevision, "Run state revision"),
    capabilities,
    start,
    currentRun: run === null ? null : projectCurrentRun(run),
    // The shapes are intentionally defined now, but empty until request-level
    // authority and every safe display field can be materialized atomically.
    attentionRequests: [],
    approvalRequests: [],
    activeGrants: [],
    grantReviews: [],
  };
}

function projectStartAvailability(
  session: SessionDetailView,
  manager: boolean,
  mutableRun: boolean
): PublicSessionRunStartAvailability {
  let reason: PublicSessionRunStartReason = "available";
  if (!manager) reason = "not-session-manager";
  else if (session.status !== "active") reason = "session-not-active";
  else if (session.runtime.authorizationState !== "enforced") reason = "runtime-not-ready";
  else if (mutableRun) reason = "mutable-run-exists";
  else reason = "run-mutations-unavailable";
  return { available: false, reason };
}

function projectCurrentRun(run: SessionRunStateView): PublicSessionAgentRunView {
  const goals = boundedArray(run.goals, MAX_GOALS, "Run goals").map((goal) => {
    const evidence = boundedArray(goal.evidence, Number.MAX_SAFE_INTEGER, "Goal evidence").filter(
      (entry) =>
        entry.agentRunId === run.agentRunId &&
        entry.goalSetRevision === run.goalSetRevision &&
        entry.goalId === goal.goalId &&
        entry.goalVersion === goal.version
    );
    return {
      goalId: boundedIdentifier(goal.goalId, "Goal id"),
      position: positiveInteger(goal.position, "Goal position"),
      title: boundedText(goal.title, 1_000, "Goal title"),
      acceptanceCriteria: boundedArray(
        goal.acceptanceCriteria,
        MAX_CRITERIA_PER_GOAL,
        "Goal acceptance criteria"
      ).map((criterion) => boundedText(criterion, 1_000, "Goal acceptance criterion")),
      dependencyGoalIds: boundedArray(
        goal.dependencyGoalIds,
        MAX_DEPENDENCIES_PER_GOAL,
        "Goal dependencies"
      ).map((goalId) => boundedIdentifier(goalId, "Goal dependency id")),
      version: positiveInteger(goal.version, "Goal version"),
      status: enumValue(
        goal.status,
        ["pending", "in-progress", "blocked", "provisionally-achieved", "validated"] as const,
        "Goal status"
      ),
      evidenceTotalCount: nonNegativeInteger(evidence.length, "Goal evidence count"),
      evidence: evidence.slice(0, MAX_EVIDENCE_PER_GOAL).map(projectEvidenceSummary),
    };
  });
  const mode = enumValue(run.mode, ["supervised", "autonomous", "yolo"] as const, "Run mode");
  const completionPolicy = enumValue(
    run.completionPolicy,
    ["stop-after-directed-work", "continue-until-all-goals-achieved"] as const,
    "Completion policy"
  );

  return {
    agentRunId: boundedIdentifier(run.agentRunId, "Agent Run id"),
    lifecycle: enumValue(
      run.lifecycle,
      [
        "active",
        "pausing",
        "paused",
        "agent-work-finished",
        "completed",
        "failed",
        "stopped",
        "emergency-stopped",
      ] as const,
      "Run lifecycle"
    ),
    stateVersion: positiveInteger(run.stateVersion, "Run state version"),
    mode,
    completionPolicy,
    runPolicyRevision: positiveInteger(run.runPolicyRevision, "Run policy revision"),
    goalSetRevision: positiveInteger(run.goalSetRevision, "Goal Set revision"),
    finalReviewVersion: positiveInteger(run.finalReviewVersion, "Final review version"),
    requiresPolicyRebind: !booleanValue(
      run.policyRuntimeBindingCurrent,
      "Run policy binding state"
    ),
    finalReviewState: enumValue(
      run.finalReviewState,
      ["not-ready", "open", "accepted"] as const,
      "Final review state"
    ),
    sandboxState: enumValue(
      run.sandboxState,
      [
        "provisioning",
        "ready",
        "checkpointing",
        "recovering",
        "quarantined",
        "retired",
        "failed",
      ] as const,
      "Sandbox state"
    ),
    limitStatus: enumValue(
      run.limitStatus,
      [
        "accounting-unavailable",
        "within-configured-limits",
        "warning-75-percent",
        "approaching-90-percent",
        "configured-limit-reached",
      ] as const,
      "Run limit status"
    ),
    attentionSummary: {
      openCount: boundedArray(
        run.attention.openRequestIds,
        Number.MAX_SAFE_INTEGER,
        "Open attention requests"
      ).length,
      blockingCount: boundedArray(
        run.attention.blockingRequestIds,
        Number.MAX_SAFE_INTEGER,
        "Blocking attention requests"
      ).length,
      independentAuthorizedWorkMayContinue: booleanValue(
        run.attention.independentAuthorizedWorkMayContinue,
        "Independent work flag"
      ),
    },
    policySummary: {
      mode,
      completionPolicy,
      limits: projectLimits(run.limits),
    },
    goals,
  };
}

function projectEvidenceSummary(
  evidence: SessionRunStateView["goals"][number]["evidence"][number]
): PublicSessionGoalEvidenceSummary {
  return {
    evidenceId: boundedIdentifier(evidence.evidenceId, "Goal evidence id"),
    status: enumValue(
      evidence.status,
      ["proposed", "validated", "more-work-requested"] as const,
      "Goal evidence status"
    ),
    createdAtMs: nonNegativeInteger(evidence.createdAtMs, "Goal evidence creation time"),
    ...(evidence.reviewedAtMs === undefined
      ? {}
      : {
          reviewedAtMs: nonNegativeInteger(evidence.reviewedAtMs, "Goal evidence review time"),
        }),
  };
}

function projectLimits(limits: RunLimits): PublicSessionRunLimitsSummary {
  return {
    wallClock: projectLimit(limits.wallClock, (value) => ({
      milliseconds: nonNegativeInteger(value.milliseconds, "Wall clock limit"),
    })),
    modelTokens: projectLimit(limits.modelTokens, (value) =>
      nonNegativeInteger(value, "Model token limit")
    ),
    modelSpend: projectLimit(limits.modelSpend, (value) => ({
      currency: currency(value.currency),
      minorUnits: nonNegativeInteger(value.minorUnits, "Model spend limit"),
    })),
    outboundBytes: projectLimit(limits.outboundBytes, (value) =>
      nonNegativeInteger(value, "Outbound byte limit")
    ),
    actionCounts: {
      local: projectLimit(limits.actionCounts.local, (value) =>
        nonNegativeInteger(value, "Local action limit")
      ),
      "scoped-external": projectLimit(limits.actionCounts["scoped-external"], (value) =>
        nonNegativeInteger(value, "Scoped external action limit")
      ),
      protected: projectLimit(limits.actionCounts.protected, (value) =>
        nonNegativeInteger(value, "Protected action limit")
      ),
      forbidden: projectLimit(limits.actionCounts.forbidden, (value) =>
        nonNegativeInteger(value, "Forbidden action limit")
      ),
    },
  };
}

function projectLimit<Input, Output>(
  limit: RunLimit<Input>,
  projectValue: (value: Input) => Output
): PublicSessionRunLimit<Output> {
  if (limit.kind === "unconfigured") return { kind: "unconfigured" };
  if (limit.kind !== "capped") throw invalidInternalState("Run limit");
  return { kind: "capped", value: projectValue(limit.value) };
}

type PublicSessionRunLimit<T> = { kind: "unconfigured" } | { kind: "capped"; value: T };

function boundedArray<T>(
  value: ReadonlyArray<T>,
  maximum: number,
  label: string
): ReadonlyArray<T> {
  if (!Array.isArray(value) || value.length > maximum) throw invalidInternalState(label);
  return value;
}

function boundedIdentifier(value: string, label: string): string {
  return boundedText(value, 300, label);
}

function boundedText(value: string, maximum: number, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximum ||
    /[\u0000-\u0008\u000b-\u001f\u007f]/.test(value)
  ) {
    throw invalidInternalState(label);
  }
  return value;
}

function currency(value: string): string {
  if (!/^[A-Z]{3}$/.test(value)) throw invalidInternalState("Currency");
  return value;
}

function booleanValue(value: boolean, label: string): boolean {
  if (typeof value !== "boolean") throw invalidInternalState(label);
  return value;
}

function nonNegativeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) throw invalidInternalState(label);
  return value;
}

function positiveInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw invalidInternalState(label);
  return value;
}

function enumValue<const Values extends readonly string[]>(
  value: string,
  allowed: Values,
  label: string
): Values[number] {
  if (!(allowed as readonly string[]).includes(value)) throw invalidInternalState(label);
  return value as Values[number];
}

function invalidInternalState(label: string): Error {
  // Do not interpolate the malformed value: it might have come from a provider
  // payload or corrupted secret-shaped record.
  return new Error(`Invalid internal ${label}`);
}
