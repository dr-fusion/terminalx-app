import { createHash } from "node:crypto";
import type {
  GoalDefinition,
  RunLimit,
  RunLimits,
  RunPolicyCommit,
  RunPolicyDraft,
} from "./contracts";

const ACTION_CLASSES = ["local", "scoped-external", "protected", "forbidden"] as const;
const SAFE_REF = /^[A-Za-z0-9][A-Za-z0-9._~:/-]{0,299}$/;

export class RunPolicyValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RunPolicyValidationError";
  }
}

export interface RunPolicyValidationContext {
  readonly sessionName: string;
  readonly yoloEligible: boolean;
  readonly projectCeilingRevision: string;
  readonly runtimeAssignmentGeneration: number;
  readonly sandboxId: string;
  readonly sandboxGeneration: number;
  readonly runtimeAuthorizationGeneration: number;
}

export function digestRunPolicyDraft(policy: RunPolicyDraft): string {
  validateRunPolicyDraft(policy);
  return sha256(canonicalJson(policy));
}

export function assertValidRunPolicyCommit(
  commit: RunPolicyCommit,
  context: RunPolicyValidationContext
): void {
  exactKeys(
    commit,
    [
      "policy",
      "policyDigest",
      "expectedProjectCeilingRevision",
      "expectedRuntimeAssignmentGeneration",
      "expectedSandboxGeneration",
      "expectedRuntimeAuthorizationGeneration",
    ],
    "Run policy commit",
    ["previewId", "yoloConfirmation", "wideningActionGrantId"]
  );
  validateRunPolicyDraft(commit.policy);
  if (!/^[0-9a-f]{64}$/.test(commit.policyDigest)) invalid("Run policy digest is invalid");
  if (digestRunPolicyDraft(commit.policy) !== commit.policyDigest) {
    invalid("Run policy digest does not match the displayed policy");
  }
  if (commit.expectedProjectCeilingRevision !== context.projectCeilingRevision) {
    invalid("Project Runtime ceiling changed");
  }
  if (commit.expectedRuntimeAssignmentGeneration !== context.runtimeAssignmentGeneration) {
    invalid("Runtime Assignment changed");
  }
  if (commit.expectedSandboxGeneration !== context.sandboxGeneration) {
    invalid("Sandbox generation changed");
  }
  if (commit.expectedRuntimeAuthorizationGeneration !== context.runtimeAuthorizationGeneration) {
    invalid("Runtime Authorization changed");
  }
  optionalRef(commit.previewId, "Run policy preview id");
  optionalRef(commit.wideningActionGrantId, "Widening Action Grant id");

  if (commit.policy.mode !== "yolo") {
    if (commit.yoloConfirmation !== undefined) {
      invalid("YOLO confirmation is valid only for YOLO mode");
    }
    return;
  }
  if (!context.yoloEligible) invalid("This Runtime is not eligible for YOLO mode");
  const confirmation = commit.yoloConfirmation;
  if (!confirmation) invalid("YOLO mode requires a fresh typed confirmation");
  exactKeys(
    confirmation,
    [
      "challengeId",
      "challengeVersion",
      "policyDigest",
      "warningDigest",
      "sessionNameRevision",
      "typedSessionName",
      "projectCeilingRevision",
      "sourceRevision",
      "sandboxId",
      "sandboxGeneration",
      "sandboxProfileDigest",
      "runtimeAssignmentGeneration",
      "runtimeAuthorizationGeneration",
      "credentialPolicyDigest",
      "networkPolicyDigest",
      "limitsDigest",
    ],
    "YOLO confirmation"
  );
  requiredRef(confirmation.challengeId, "YOLO challenge id");
  positiveInteger(confirmation.challengeVersion, "YOLO challenge version");
  positiveInteger(confirmation.sessionNameRevision, "Session name revision");
  if (confirmation.policyDigest !== commit.policyDigest) invalid("YOLO policy changed");
  if (confirmation.typedSessionName !== context.sessionName) invalid("Typed Session name is stale");
  if (confirmation.projectCeilingRevision !== context.projectCeilingRevision) {
    invalid("YOLO Project ceiling changed");
  }
  if (confirmation.sandboxId !== context.sandboxId) invalid("YOLO Sandbox changed");
  if (confirmation.sandboxGeneration !== context.sandboxGeneration) {
    invalid("YOLO Sandbox generation changed");
  }
  if (confirmation.runtimeAssignmentGeneration !== context.runtimeAssignmentGeneration) {
    invalid("YOLO Runtime Assignment changed");
  }
  if (confirmation.runtimeAuthorizationGeneration !== context.runtimeAuthorizationGeneration) {
    invalid("YOLO Runtime Authorization changed");
  }
  for (const [value, label] of [
    [confirmation.policyDigest, "YOLO policy digest"],
    [confirmation.warningDigest, "YOLO warning digest"],
    [confirmation.sandboxProfileDigest, "Sandbox profile digest"],
    [confirmation.credentialPolicyDigest, "Credential policy digest"],
    [confirmation.networkPolicyDigest, "Network policy digest"],
    [confirmation.limitsDigest, "Run limits digest"],
  ] as const) {
    if (!/^[0-9a-f]{64}$/.test(value)) invalid(`${label} is invalid`);
  }
  requiredRef(confirmation.sourceRevision, "Source revision");
}

export function validateInitialGoals(goals: ReadonlyArray<GoalDefinition>): void {
  if (!Array.isArray(goals) || goals.length < 1 || goals.length > 100) {
    invalid("A Run requires between 1 and 100 goals");
  }
  const ids = new Set<string>();
  for (const [index, goal] of goals.entries()) {
    exactKeys(
      goal,
      ["goalId", "position", "title", "acceptanceCriteria", "dependencyGoalIds"],
      "Goal"
    );
    requiredRef(goal.goalId, "Goal id");
    if (ids.has(goal.goalId)) invalid("Goal ids must be unique");
    ids.add(goal.goalId);
    if (goal.position !== index + 1) invalid("Goal positions must be contiguous and ordered");
    requiredText(goal.title, "Goal title", 1_000);
    if (
      !Array.isArray(goal.acceptanceCriteria) ||
      goal.acceptanceCriteria.length < 1 ||
      goal.acceptanceCriteria.length > 32
    ) {
      invalid("Each Goal requires between 1 and 32 acceptance criteria");
    }
    for (const criterion of goal.acceptanceCriteria) {
      requiredText(criterion, "Goal acceptance criterion", 1_000);
    }
    if (!Array.isArray(goal.dependencyGoalIds) || goal.dependencyGoalIds.length > 99) {
      invalid("Goal dependencies are invalid");
    }
    if (new Set(goal.dependencyGoalIds).size !== goal.dependencyGoalIds.length) {
      invalid("Goal dependencies must be unique");
    }
  }
  for (const goal of goals) {
    for (const dependency of goal.dependencyGoalIds) {
      if (!ids.has(dependency) || dependency === goal.goalId) {
        invalid("Goal dependency is missing or self-referential");
      }
    }
  }
  assertAcyclicGoals(goals);
}

export function isRunPolicyWidening(current: RunPolicyDraft, next: RunPolicyDraft): boolean {
  validateRunPolicyDraft(current);
  validateRunPolicyDraft(next);
  const modeRank = { supervised: 0, autonomous: 1, yolo: 2 } as const;
  if (modeRank[next.mode] > modeRank[current.mode]) return true;
  if (
    current.completionPolicy.kind === "stop-after-directed-work" &&
    next.completionPolicy.kind === "continue-until-all-goals-achieved"
  ) {
    return true;
  }
  if (current.scopedExternalPolicyRef !== next.scopedExternalPolicyRef) return true;
  return limitsWiden(current.limits, next.limits);
}

function validateRunPolicyDraft(policy: RunPolicyDraft): void {
  exactKeys(
    policy,
    ["mode", "completionPolicy", "scopedExternalPolicyRef", "limits"],
    "Run policy"
  );
  if (policy.mode !== "supervised" && policy.mode !== "autonomous" && policy.mode !== "yolo") {
    invalid("Run mode is invalid");
  }
  exactKeys(policy.completionPolicy, ["kind"], "Completion policy");
  if (
    policy.completionPolicy.kind !== "stop-after-directed-work" &&
    policy.completionPolicy.kind !== "continue-until-all-goals-achieved"
  ) {
    invalid("Completion policy is invalid");
  }
  if (
    policy.mode === "supervised" &&
    policy.completionPolicy.kind === "continue-until-all-goals-achieved"
  ) {
    invalid("Supervised mode cannot continue until all goals are achieved");
  }
  requiredRef(policy.scopedExternalPolicyRef, "Scoped external policy reference");
  validateLimits(policy.limits);
}

function validateLimits(limits: RunLimits): void {
  exactKeys(
    limits,
    ["wallClock", "modelTokens", "modelSpend", "outboundBytes", "actionCounts"],
    "Run limits"
  );
  validateLimit(limits.wallClock, "Wall clock", (value) => {
    exactKeys(value, ["milliseconds"], "Wall clock duration");
    nonNegativeInteger(value.milliseconds, "Wall clock milliseconds");
  });
  validateLimit(limits.modelTokens, "Model token", (value) =>
    nonNegativeInteger(value, "Model token limit")
  );
  validateLimit(limits.modelSpend, "Model spend", validateMoney);
  validateLimit(limits.outboundBytes, "Outbound byte", (value) =>
    nonNegativeInteger(value, "Outbound byte limit")
  );
  exactKeys(limits.actionCounts, ACTION_CLASSES, "Action count limits");
  for (const actionClass of ACTION_CLASSES) {
    validateLimit(limits.actionCounts[actionClass], `${actionClass} action`, (value) =>
      nonNegativeInteger(value, `${actionClass} action limit`)
    );
  }
}

function validateLimit<T>(
  limit: RunLimit<T>,
  label: string,
  validateValue: (value: T) => void
): void {
  if (!limit || typeof limit !== "object" || Array.isArray(limit))
    invalid(`${label} cap is invalid`);
  if (limit.kind === "unconfigured") {
    exactKeys(limit, ["kind"], `${label} cap`);
    return;
  }
  if (limit.kind !== "capped") invalid(`${label} cap must be explicit`);
  exactKeys(limit, ["kind", "value"], `${label} cap`);
  validateValue(limit.value);
}

function validateMoney(value: { currency: string; minorUnits: number }): void {
  exactKeys(value, ["currency", "minorUnits"], "Money limit");
  if (!/^[A-Z]{3}$/.test(value.currency)) invalid("Money currency is invalid");
  nonNegativeInteger(value.minorUnits, "Money minor units");
}

function limitsWiden(current: RunLimits, next: RunLimits): boolean {
  return (
    limitWidens(current.wallClock, next.wallClock, (value) => value.milliseconds) ||
    limitWidens(current.modelTokens, next.modelTokens, (value) => value) ||
    moneyLimitWidens(current.modelSpend, next.modelSpend) ||
    limitWidens(current.outboundBytes, next.outboundBytes, (value) => value) ||
    ACTION_CLASSES.some((actionClass) =>
      limitWidens(
        current.actionCounts[actionClass],
        next.actionCounts[actionClass],
        (value) => value
      )
    )
  );
}

function limitWidens<T>(
  current: RunLimit<T>,
  next: RunLimit<T>,
  numericValue: (value: T) => number
): boolean {
  if (current.kind === "capped" && next.kind === "unconfigured") return true;
  return (
    current.kind === "capped" &&
    next.kind === "capped" &&
    numericValue(next.value) > numericValue(current.value)
  );
}

function moneyLimitWidens(
  current: RunLimits["modelSpend"],
  next: RunLimits["modelSpend"]
): boolean {
  if (current.kind === "capped" && next.kind === "unconfigured") return true;
  if (current.kind !== "capped" || next.kind !== "capped") return false;
  return (
    current.value.currency !== next.value.currency ||
    next.value.minorUnits > current.value.minorUnits
  );
}

function assertAcyclicGoals(goals: ReadonlyArray<GoalDefinition>): void {
  const byId = new Map(goals.map((goal) => [goal.goalId, goal]));
  const visiting = new Set<string>();
  const visited = new Set<string>();
  const visit = (goalId: string): void => {
    if (visiting.has(goalId)) invalid("Goal dependencies contain a cycle");
    if (visited.has(goalId)) return;
    visiting.add(goalId);
    for (const dependency of byId.get(goalId)?.dependencyGoalIds ?? []) visit(dependency);
    visiting.delete(goalId);
    visited.add(goalId);
  };
  for (const goal of goals) visit(goal.goalId);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid("Run policy contains a non-integer number");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value !== "object") invalid("Run policy contains an unsupported value");
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

function exactKeys(
  value: unknown,
  required: readonly string[],
  label: string,
  optional: readonly string[] = []
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalid(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(`${label} must be a plain object`);
  }
  const symbolKeys = Object.getOwnPropertySymbols(value);
  if (symbolKeys.some((key) => Object.prototype.propertyIsEnumerable.call(value, key))) {
    invalid(`${label} contains an unknown field`);
  }
  const keys = Object.keys(value).sort();
  const allowed = new Set([...required, ...optional]);
  if (keys.some((key) => !allowed.has(key))) {
    invalid(`${label} contains an unknown field`);
  }
  const missing = required.find((key) => !Object.hasOwn(value, key));
  if (missing) invalid(`${label} is missing ${missing}`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor)) {
      invalid(`${label} cannot contain accessors`);
    }
  }
}

function requiredText(value: unknown, label: string, maximum: number): asserts value is string {
  if (
    typeof value !== "string" ||
    value.trim() !== value ||
    value.length < 1 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    invalid(`${label} is invalid`);
  }
}

function requiredRef(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !SAFE_REF.test(value)) invalid(`${label} is invalid`);
}

function optionalRef(value: unknown, label: string): void {
  if (value !== undefined) requiredRef(value, label);
}

function positiveInteger(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) invalid(`${label} is invalid`);
}

function nonNegativeInteger(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) invalid(`${label} is invalid`);
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function invalid(message: string): never {
  throw new RunPolicyValidationError(message);
}
