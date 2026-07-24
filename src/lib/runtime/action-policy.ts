import { createHash } from "node:crypto";

export const ACTION_MANIFEST_VERSION = 1 as const;
export const ACTION_MANIFEST_CANONICALIZATION_PROFILE = "terminalx-canonical-effect-v1" as const;

export type ActionClass = "local" | "scoped-external" | "protected" | "forbidden";

export interface ActionSchemaDescriptor {
  readonly schemaId: string;
  readonly schemaVersion: number;
  readonly schemaDigest: string;
  readonly canonicalizationProfile: typeof ACTION_MANIFEST_CANONICALIZATION_PROFILE;
  readonly unknownFields: "reject";
}

/**
 * Structural v1 manifest contract used by the pure policy module. `digest` is
 * excluded from its own canonical bytes, so the same functions accept a
 * not-yet-signed manifest as well as its persisted envelope.
 */
export interface ActionManifest {
  readonly version: typeof ACTION_MANIFEST_VERSION;
  readonly manifestId: string;
  readonly digest?: string;
  readonly actionClass: ActionClass;
  readonly provider: string;
  readonly operation: string;
  readonly exactTarget: unknown;
  readonly actionSchema: ActionSchemaDescriptor;
  readonly canonicalEffectInputDigest: string;
  readonly effectIdempotencyKey: string;
  readonly commitSha?: string;
  readonly artifactDigest?: string;
  readonly credentialRef?: string;
  readonly expectedEffect: unknown;
  readonly expiresAtMs: number;
}

export type ExecutionBoundary = "sandbox" | "host" | "control-plane";
export type ActionEffectScope = "local" | "external";
export type TargetProtection = "unprotected" | "protected" | "production";
export type SecretHandling = "none" | "reference" | "reveal";

/** Runtime facts must be produced by a trusted adapter, not by an agent. */
export interface ActionClassificationInput {
  readonly sessionId: string;
  readonly targetSessionId: string;
  readonly executionBoundary: ExecutionBoundary;
  readonly effectScope: ActionEffectScope;
  readonly targetProtection: TargetProtection;
  readonly secretHandling: SecretHandling;
  readonly killSwitch: "preserve" | "disable";
  readonly audit: "preserve" | "disable";
  readonly operation: string;
}

export type BoundedRunGrantUse =
  | "session_branch_push"
  | "draft_pull_request_update"
  | "ephemeral_preview_update"
  | "same_credential_nonproduction_target";

export interface SessionBranchTarget {
  readonly kind: "session-branch";
  readonly repositoryId: string;
  readonly branch: string;
  readonly owningSessionId: string;
}

export interface DraftPullRequestTarget {
  readonly kind: "draft-pull-request";
  readonly repositoryId: string;
  readonly pullRequestId: string;
  readonly sourceSessionId: string;
  readonly draft: true;
}

export interface EphemeralPreviewTarget {
  readonly kind: "ephemeral-preview";
  readonly projectId: string;
  readonly previewName: string;
  readonly owningSessionId: string;
  readonly ephemeral: true;
  readonly production: false;
}

export interface NonProductionExternalTarget {
  readonly kind: "nonproduction-target";
  readonly targetId: string;
  readonly environment: string;
  readonly production: false;
}

export type BoundedRunTarget =
  | SessionBranchTarget
  | DraftPullRequestTarget
  | EphemeralPreviewTarget
  | NonProductionExternalTarget;

export interface V1RunGrantScope {
  readonly kind: "run";
  /** Protected actions are one-shot only and never valid under a run scope. */
  readonly actionClass: "scoped-external";
  readonly provider: string;
  readonly operation: string;
  readonly targetPattern: BoundedRunTarget;
  readonly credentialRef?: string;
  readonly eligibleUse: BoundedRunGrantUse;
}

/** The surrounding grant contract owns authority, expiry, signature and budget. */
export interface V1RunGrant {
  readonly version: 1;
  readonly sessionId: string;
  readonly runId: string;
  readonly scope: V1RunGrantScope;
}

export interface RuntimeActionCandidate {
  readonly sessionId: string;
  readonly runId: string;
  readonly actionClass: ActionClass;
  readonly provider: string;
  readonly operation: string;
  readonly exactTarget: BoundedRunTarget;
  readonly credentialRef?: string;
  readonly policy: ActionClassificationInput;
}

export type ActionPolicyErrorCode =
  | "invalid-manifest"
  | "invalid-classification"
  | "classification-downgrade";

export class ActionPolicyError extends Error {
  constructor(
    readonly code: ActionPolicyErrorCode,
    message: string
  ) {
    super(message);
    this.name = "ActionPolicyError";
  }
}

const ACTION_CLASS_RANK: Readonly<Record<ActionClass, number>> = Object.freeze({
  local: 0,
  "scoped-external": 1,
  protected: 2,
  forbidden: 3,
});

const FORBIDDEN_OPERATIONS = new Set([
  "host.execute",
  "control-plane.mutate",
  "session.cross",
  "secret.reveal",
  "runtime.kill-switch.disable",
  "audit.disable",
]);

const MAX_CANONICAL_DEPTH = 16;
const MAX_CANONICAL_NODES = 4_096;
const MAX_CANONICAL_COLLECTION_ENTRIES = 1_024;
const MAX_CANONICAL_STRING_BYTES = 16 * 1_024;
const MAX_CANONICAL_MANIFEST_BYTES = 256 * 1_024;

const MANIFEST_FIELDS = new Set([
  "version",
  "manifestId",
  "digest",
  "actionClass",
  "provider",
  "operation",
  "exactTarget",
  "actionSchema",
  "canonicalEffectInputDigest",
  "effectIdempotencyKey",
  "commitSha",
  "artifactDigest",
  "credentialRef",
  "expectedEffect",
  "expiresAtMs",
]);
const ACTION_SCHEMA_FIELDS = new Set([
  "schemaId",
  "schemaVersion",
  "schemaDigest",
  "canonicalizationProfile",
  "unknownFields",
]);
const CLASSIFICATION_FIELDS = new Set([
  "sessionId",
  "targetSessionId",
  "executionBoundary",
  "effectScope",
  "targetProtection",
  "secretHandling",
  "killSwitch",
  "audit",
  "operation",
]);
const RUN_GRANT_FIELDS = new Set(["version", "sessionId", "runId", "scope"]);
const RUN_GRANT_SCOPE_FIELDS = new Set([
  "kind",
  "actionClass",
  "provider",
  "operation",
  "targetPattern",
  "credentialRef",
  "eligibleUse",
]);
const RUNTIME_ACTION_FIELDS = new Set([
  "sessionId",
  "runId",
  "actionClass",
  "provider",
  "operation",
  "exactTarget",
  "credentialRef",
  "policy",
]);
const SESSION_BRANCH_TARGET_FIELDS = new Set(["kind", "repositoryId", "branch", "owningSessionId"]);
const DRAFT_PULL_REQUEST_TARGET_FIELDS = new Set([
  "kind",
  "repositoryId",
  "pullRequestId",
  "sourceSessionId",
  "draft",
]);
const EPHEMERAL_PREVIEW_TARGET_FIELDS = new Set([
  "kind",
  "projectId",
  "previewName",
  "owningSessionId",
  "ephemeral",
  "production",
]);
const NONPRODUCTION_TARGET_FIELDS = new Set(["kind", "targetId", "environment", "production"]);

/** Return the exact UTF-8 JSON string whose SHA-256 is the manifest digest. */
export function canonicalizeActionManifest(manifest: ActionManifest): string {
  try {
    assertManifest(manifest);
    const payload = {
      version: manifest.version,
      manifestId: manifest.manifestId,
      actionClass: manifest.actionClass,
      provider: manifest.provider,
      operation: manifest.operation,
      exactTarget: manifest.exactTarget,
      actionSchema: manifest.actionSchema,
      canonicalEffectInputDigest: manifest.canonicalEffectInputDigest,
      effectIdempotencyKey: manifest.effectIdempotencyKey,
      ...(manifest.commitSha === undefined ? {} : { commitSha: manifest.commitSha }),
      ...(manifest.artifactDigest === undefined ? {} : { artifactDigest: manifest.artifactDigest }),
      ...(manifest.credentialRef === undefined ? {} : { credentialRef: manifest.credentialRef }),
      expectedEffect: manifest.expectedEffect,
      expiresAtMs: manifest.expiresAtMs,
    };
    return canonicalJson(payload);
  } catch {
    return invalidManifest();
  }
}

export function digestActionManifest(manifest: ActionManifest): string {
  return createHash("sha256").update(canonicalizeActionManifest(manifest), "utf8").digest("hex");
}

export function verifyActionManifestDigest(manifest: ActionManifest): boolean {
  try {
    const suppliedDigest = isPlainRecord(manifest) ? ownDataField(manifest, "digest") : undefined;
    return typeof suppliedDigest === "string" && suppliedDigest === digestActionManifest(manifest);
  } catch {
    return false;
  }
}

/**
 * Classify trusted runtime facts. Invalid or unrecognized runtime metadata is
 * forbidden rather than throwing into a potentially fail-open caller.
 */
export function classifyAction(input: ActionClassificationInput): ActionClass {
  try {
    if (!validClassificationInput(input)) return "forbidden";
    if (
      input.executionBoundary !== "sandbox" ||
      input.targetSessionId !== input.sessionId ||
      input.secretHandling === "reveal" ||
      input.killSwitch === "disable" ||
      input.audit === "disable" ||
      FORBIDDEN_OPERATIONS.has(input.operation)
    ) {
      return "forbidden";
    }
    if (input.targetProtection === "protected" || input.targetProtection === "production") {
      return "protected";
    }
    if (input.effectScope === "external" || input.secretHandling === "reference") {
      return "scoped-external";
    }
    return "local";
  } catch {
    return "forbidden";
  }
}

/** Runtime inspection may preserve or raise the manifest class, never lower it. */
export function applyRuntimeReclassification(
  manifestClass: ActionClass,
  runtimeClass: ActionClass
): ActionClass {
  if (!isActionClass(manifestClass) || !isActionClass(runtimeClass)) {
    throw new ActionPolicyError("invalid-classification", "Action classification is invalid");
  }
  if (ACTION_CLASS_RANK[runtimeClass] < ACTION_CLASS_RANK[manifestClass]) {
    throw new ActionPolicyError(
      "classification-downgrade",
      "Runtime classification cannot weaken the manifest classification"
    );
  }
  return runtimeClass;
}

/**
 * Match only the four bounded v1 run patterns. This does not validate grant
 * signatures, authority, expiry or remaining budget; those belong to the
 * surrounding ActionGrant seam.
 */
export function matchesV1RunGrant(grant: V1RunGrant, action: RuntimeActionCandidate): boolean {
  try {
    if (!validRunGrantEnvelope(grant, action)) return false;

    const requiredClass = classifyAction(action.policy);
    if (
      requiredClass !== "scoped-external" ||
      action.actionClass !== "scoped-external" ||
      grant.scope.actionClass !== "scoped-external"
    ) {
      return false;
    }

    if (
      action.sessionId !== grant.sessionId ||
      action.runId !== grant.runId ||
      action.policy.sessionId !== action.sessionId ||
      action.policy.operation !== action.operation ||
      action.provider !== grant.scope.provider ||
      action.operation !== grant.scope.operation ||
      (action.credentialRef ?? null) !== (grant.scope.credentialRef ?? null)
    ) {
      return false;
    }

    const pattern = grant.scope.targetPattern;
    const target = action.exactTarget;
    switch (grant.scope.eligibleUse) {
      case "session_branch_push":
        return (
          pattern.kind === "session-branch" &&
          target.kind === "session-branch" &&
          pattern.owningSessionId === grant.sessionId &&
          target.owningSessionId === grant.sessionId &&
          target.repositoryId === pattern.repositoryId &&
          target.branch === pattern.branch
        );
      case "draft_pull_request_update":
        return (
          pattern.kind === "draft-pull-request" &&
          target.kind === "draft-pull-request" &&
          pattern.draft === true &&
          target.draft === true &&
          pattern.sourceSessionId === grant.sessionId &&
          target.sourceSessionId === grant.sessionId &&
          target.repositoryId === pattern.repositoryId &&
          target.pullRequestId === pattern.pullRequestId
        );
      case "ephemeral_preview_update":
        return (
          pattern.kind === "ephemeral-preview" &&
          target.kind === "ephemeral-preview" &&
          pattern.ephemeral === true &&
          target.ephemeral === true &&
          pattern.production === false &&
          target.production === false &&
          pattern.owningSessionId === grant.sessionId &&
          target.owningSessionId === grant.sessionId &&
          target.projectId === pattern.projectId &&
          target.previewName === pattern.previewName
        );
      case "same_credential_nonproduction_target":
        return (
          typeof grant.scope.credentialRef === "string" &&
          pattern.kind === "nonproduction-target" &&
          target.kind === "nonproduction-target" &&
          pattern.production === false &&
          target.production === false &&
          target.targetId === pattern.targetId &&
          target.environment === pattern.environment
        );
    }
  } catch {
    return false;
  }
}

function assertManifest(manifest: ActionManifest): void {
  if (!isPlainRecord(manifest) || !hasOnlyDataFields(manifest, MANIFEST_FIELDS)) invalidManifest();
  if (
    manifest.version !== ACTION_MANIFEST_VERSION ||
    !validText(manifest.manifestId, 512) ||
    !isActionClass(manifest.actionClass) ||
    !validText(manifest.provider, 200) ||
    !validText(manifest.operation, 300) ||
    !validText(manifest.effectIdempotencyKey, 512) ||
    !isSha256(manifest.canonicalEffectInputDigest) ||
    !Number.isSafeInteger(manifest.expiresAtMs) ||
    manifest.expiresAtMs < 1 ||
    (manifest.digest !== undefined && !isSha256(manifest.digest)) ||
    (manifest.commitSha !== undefined && !/^[a-fA-F0-9]{7,64}$/.test(manifest.commitSha)) ||
    (manifest.artifactDigest !== undefined && !isSha256(manifest.artifactDigest)) ||
    (manifest.credentialRef !== undefined && !validText(manifest.credentialRef, 1_024))
  ) {
    invalidManifest();
  }

  const schema = manifest.actionSchema;
  if (
    !isPlainRecord(schema) ||
    !hasOnlyDataFields(schema, ACTION_SCHEMA_FIELDS) ||
    !validText(schema.schemaId, 300) ||
    !Number.isSafeInteger(schema.schemaVersion) ||
    schema.schemaVersion < 1 ||
    !isSha256(schema.schemaDigest) ||
    schema.canonicalizationProfile !== ACTION_MANIFEST_CANONICALIZATION_PROFILE ||
    schema.unknownFields !== "reject"
  ) {
    invalidManifest();
  }
}

function validClassificationInput(input: ActionClassificationInput): boolean {
  return (
    isPlainRecord(input) &&
    hasOnlyDataFields(input, CLASSIFICATION_FIELDS) &&
    validText(input.sessionId, 512) &&
    validText(input.targetSessionId, 512) &&
    (input.executionBoundary === "sandbox" ||
      input.executionBoundary === "host" ||
      input.executionBoundary === "control-plane") &&
    (input.effectScope === "local" || input.effectScope === "external") &&
    (input.targetProtection === "unprotected" ||
      input.targetProtection === "protected" ||
      input.targetProtection === "production") &&
    (input.secretHandling === "none" ||
      input.secretHandling === "reference" ||
      input.secretHandling === "reveal") &&
    (input.killSwitch === "preserve" || input.killSwitch === "disable") &&
    (input.audit === "preserve" || input.audit === "disable") &&
    validText(input.operation, 300)
  );
}

function validRunGrantEnvelope(grant: V1RunGrant, action: RuntimeActionCandidate): boolean {
  return (
    isPlainRecord(grant) &&
    hasOnlyDataFields(grant, RUN_GRANT_FIELDS) &&
    grant.version === 1 &&
    validText(grant.sessionId, 512) &&
    validText(grant.runId, 512) &&
    isPlainRecord(grant.scope) &&
    hasOnlyDataFields(grant.scope, RUN_GRANT_SCOPE_FIELDS) &&
    grant.scope.kind === "run" &&
    grant.scope.actionClass === "scoped-external" &&
    validText(grant.scope.provider, 200) &&
    validText(grant.scope.operation, 300) &&
    (grant.scope.credentialRef === undefined || validText(grant.scope.credentialRef, 1_024)) &&
    isBoundedRunGrantUse(grant.scope.eligibleUse) &&
    isPlainRecord(grant.scope.targetPattern) &&
    isPlainRecord(action) &&
    hasOnlyDataFields(action, RUNTIME_ACTION_FIELDS) &&
    validText(action.sessionId, 512) &&
    validText(action.runId, 512) &&
    action.actionClass === "scoped-external" &&
    validText(action.provider, 200) &&
    validText(action.operation, 300) &&
    (action.credentialRef === undefined || validText(action.credentialRef, 1_024)) &&
    isPlainRecord(action.exactTarget) &&
    isPlainRecord(action.policy) &&
    validBoundedTarget(grant.scope.targetPattern) &&
    validBoundedTarget(action.exactTarget)
  );
}

function validBoundedTarget(value: unknown): value is BoundedRunTarget {
  if (!isPlainRecord(value)) return false;
  const kind = ownDataField(value, "kind");
  if (!hasOnlyDataFields(value, targetFields(kind))) return false;
  switch (kind) {
    case "session-branch": {
      const target = value as unknown as SessionBranchTarget;
      return (
        validText(target.repositoryId, 512) &&
        validText(target.branch, 512) &&
        validText(target.owningSessionId, 512)
      );
    }
    case "draft-pull-request": {
      const target = value as unknown as DraftPullRequestTarget;
      return (
        validText(target.repositoryId, 512) &&
        validText(target.pullRequestId, 512) &&
        validText(target.sourceSessionId, 512) &&
        target.draft === true
      );
    }
    case "ephemeral-preview": {
      const target = value as unknown as EphemeralPreviewTarget;
      return (
        validText(target.projectId, 512) &&
        validText(target.previewName, 512) &&
        validText(target.owningSessionId, 512) &&
        target.ephemeral === true &&
        target.production === false
      );
    }
    case "nonproduction-target": {
      const target = value as unknown as NonProductionExternalTarget;
      return (
        validText(target.targetId, 512) &&
        validText(target.environment, 200) &&
        target.production === false
      );
    }
    default:
      return false;
  }
}

function targetFields(kind: unknown): ReadonlySet<string> {
  switch (kind) {
    case "session-branch":
      return SESSION_BRANCH_TARGET_FIELDS;
    case "draft-pull-request":
      return DRAFT_PULL_REQUEST_TARGET_FIELDS;
    case "ephemeral-preview":
      return EPHEMERAL_PREVIEW_TARGET_FIELDS;
    case "nonproduction-target":
      return NONPRODUCTION_TARGET_FIELDS;
    default:
      return new Set();
  }
}

function isBoundedRunGrantUse(value: unknown): value is BoundedRunGrantUse {
  return (
    value === "session_branch_push" ||
    value === "draft_pull_request_update" ||
    value === "ephemeral_preview_update" ||
    value === "same_credential_nonproduction_target"
  );
}

interface CanonicalJsonState {
  readonly ancestors: Set<object>;
  remainingNodes: number;
  remainingBytes: number;
}

function canonicalJson(
  value: unknown,
  state: CanonicalJsonState = {
    ancestors: new Set<object>(),
    remainingNodes: MAX_CANONICAL_NODES,
    remainingBytes: MAX_CANONICAL_MANIFEST_BYTES,
  },
  depth = 0
): string {
  if (depth > MAX_CANONICAL_DEPTH || state.remainingNodes-- < 1) {
    throw new TypeError("Canonical JSON exceeds its complexity limit");
  }
  if (value === null) return canonicalToken("null", state);
  if (typeof value === "string") {
    if (Buffer.byteLength(value, "utf8") > MAX_CANONICAL_STRING_BYTES) {
      throw new TypeError("Canonical JSON string exceeds its limit");
    }
    return canonicalToken(JSON.stringify(value), state);
  }
  if (typeof value === "boolean") return canonicalToken(JSON.stringify(value), state);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON number is invalid");
    return canonicalToken(JSON.stringify(value), state);
  }
  if (Array.isArray(value)) {
    if (
      value.length > MAX_CANONICAL_COLLECTION_ENTRIES ||
      state.ancestors.has(value) ||
      !validCanonicalArray(value)
    ) {
      throw new TypeError("Canonical JSON array is invalid");
    }
    state.ancestors.add(value);
    consumeCanonicalBytes(state, 2 + Math.max(0, value.length - 1));
    const serialized = `[${value
      .map((entry) => canonicalJson(entry, state, depth + 1))
      .join(",")}]`;
    state.ancestors.delete(value);
    return serialized;
  }
  if (!isPlainRecord(value)) throw new TypeError("Canonical JSON value is invalid");
  if (state.ancestors.has(value)) throw new TypeError("Canonical JSON cannot contain cycles");
  const entries = canonicalObjectEntries(value);
  if (entries.length > MAX_CANONICAL_COLLECTION_ENTRIES) {
    throw new TypeError("Canonical JSON object exceeds its collection limit");
  }
  state.ancestors.add(value);
  consumeCanonicalBytes(state, 2 + Math.max(0, entries.length - 1));
  const pairs = entries.map(([key, entry]) => {
    if (Buffer.byteLength(key, "utf8") > MAX_CANONICAL_STRING_BYTES) {
      throw new TypeError("Canonical JSON key exceeds its string limit");
    }
    const serializedKey = JSON.stringify(key);
    consumeCanonicalBytes(state, Buffer.byteLength(serializedKey, "utf8") + 1);
    return `${serializedKey}:${canonicalJson(entry, state, depth + 1)}`;
  });
  state.ancestors.delete(value);
  return `{${pairs.join(",")}}`;
}

function canonicalToken(token: string, state: CanonicalJsonState): string {
  consumeCanonicalBytes(state, Buffer.byteLength(token, "utf8"));
  return token;
}

function consumeCanonicalBytes(state: CanonicalJsonState, bytes: number): void {
  state.remainingBytes -= bytes;
  if (state.remainingBytes < 0) {
    throw new TypeError("Canonical JSON exceeds its byte limit");
  }
}

function validCanonicalArray(value: readonly unknown[]): boolean {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes("length")) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) return false;
  }
  return true;
}

function canonicalObjectEntries(value: Record<string, unknown>): Array<[string, unknown]> {
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_CANONICAL_COLLECTION_ENTRIES) {
    throw new TypeError("Canonical JSON object exceeds its collection limit");
  }
  const entries: Array<[string, unknown]> = [];
  for (const key of keys) {
    if (typeof key !== "string") throw new TypeError("Canonical JSON key is invalid");
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
      throw new TypeError("Canonical JSON property is invalid");
    }
    if (descriptor.value === undefined) {
      throw new TypeError("Canonical JSON cannot contain undefined");
    }
    entries.push([key, descriptor.value]);
  }
  return entries.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
}

function ownDataField(value: Record<string, unknown>, field: string): unknown {
  try {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    return descriptor && descriptor.enumerable && "value" in descriptor
      ? descriptor.value
      : undefined;
  } catch {
    return undefined;
  }
}

function hasOnlyDataFields(value: Record<string, unknown>, fields: ReadonlySet<string>): boolean {
  try {
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string" || !fields.has(key)) return false;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function isActionClass(value: unknown): value is ActionClass {
  return (
    value === "local" ||
    value === "scoped-external" ||
    value === "protected" ||
    value === "forbidden"
  );
}

function validText(value: unknown, maximumLength: number): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= maximumLength &&
    value.trim() === value &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function invalidManifest(): never {
  throw new ActionPolicyError("invalid-manifest", "Action manifest is invalid");
}
