import type { RuntimeBinding } from "../team-sessions/contracts";
import type {
  PlatformSecurityRuntimeAuthorityEnvelope,
  RuntimeCompensationCommand,
} from "./contracts";
import { digestRuntimeCommandClaims } from "./runtime-command-canonical";
import { suppressNativePromiseRejection } from "./runtime-native-promise";

const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;
const DEFAULT_COMMAND_TTL_MS = 30_000;
const MAX_COMMAND_TTL_MS = 5 * 60_000;
const CANDIDATE_FIELDS = [
  "compensationId",
  "incidentDigest",
  "binding",
  "observedRuntimeAuthorizationGeneration",
  "safetyFence",
  "source",
] as const;
const BINDING_FIELDS = [
  "teamId",
  "projectId",
  "sessionId",
  "runtimeAssignmentId",
  "runtimeAssignmentGeneration",
  "sandboxId",
  "sandboxGeneration",
  "runtimePrincipalId",
] as const;
const SOURCE_FIELDS = [
  "lifecycleCommandId",
  "lifecycleCommandClaimsDigest",
  "lifecycleReceiptDigest",
  "lifecycleEnforcementSubjectDigest",
  "lifecycleAggregateProofDigest",
  "sourceRequiredEffectEnforcerSetDigest",
] as const;
const POLICY_FIELDS = [
  "platformSecurityPolicyRevision",
  "requiredContainmentEnforcerSetDigest",
] as const;
const AUTHORITY_FIELDS = [
  "issuer",
  "issuerKeyId",
  "audience",
  "capability",
  "claimsDigest",
  "issuedAtMs",
  "expiresAtMs",
  "signature",
] as const;

export type RuntimeCompensationCommandClaims = Omit<RuntimeCompensationCommand, "authority">;

/** Narrow signer seam: it cannot issue ordinary Team Session Runtime commands. */
export interface RuntimeCompensationAuthorityIssuer {
  issue(
    claims: RuntimeCompensationCommandClaims
  ): PlatformSecurityRuntimeAuthorityEnvelope<"safety.quarantine">;
}

/** Immutable, proof-backed incident projected without any current tenant state. */
export interface RuntimeCompensationMaterializationCandidate {
  readonly compensationId: string;
  readonly incidentDigest: string;
  readonly binding: RuntimeBinding;
  readonly observedRuntimeAuthorizationGeneration: number;
  /** Atomically allocated global lower bound for this exact Runtime binding. */
  readonly safetyFence: number;
  readonly source: RuntimeCompensationCommand["source"];
}

export interface RuntimeCompensationMaterializationClaimOptions {
  readonly nowMs: number;
  /** Cancellation is authoritative before returning materialization candidates. */
  readonly signal: AbortSignal;
}

export interface RuntimeCompensationMaterializationWriteOptions {
  /** The journal must not begin a durable write after this signal is aborted. */
  readonly signal: AbortSignal;
}

export interface RuntimeCompensationMaterializationInput {
  readonly compensationId: string;
  readonly incidentDigest: string;
  readonly command: RuntimeCompensationCommand;
  readonly authorityVerifiedAtMs: number;
  readonly materializedAtMs: number;
}

export type RuntimeCompensationMaterializationResult = "created" | "already-materialized";

/**
 * Reads an unsigned incident and conditionally stores a signed command. The
 * signer is deliberately outside the journal transaction; concurrent signed
 * candidates race safely at the unique persistence boundary.
 */
export interface RuntimeCompensationMaterializationJournal {
  findMaterializable(
    options: RuntimeCompensationMaterializationClaimOptions
  ): Promise<RuntimeCompensationMaterializationCandidate | null>;
  materialize(
    input: RuntimeCompensationMaterializationInput,
    options: RuntimeCompensationMaterializationWriteOptions
  ): Promise<RuntimeCompensationMaterializationResult>;
}

export interface RuntimeCompensationPolicySnapshot {
  readonly platformSecurityPolicyRevision: string;
  readonly requiredContainmentEnforcerSetDigest: string;
}

/** Synchronous local policy source; provider/Runtime payloads must never implement it. */
export interface RuntimeCompensationPolicySource {
  resolve(
    incident: RuntimeCompensationMaterializationCandidate
  ): RuntimeCompensationPolicySnapshot | undefined;
}

/** Synchronous pinned-key verification required before a signed command is durable. */
export type RuntimeCompensationCommandAuthorityVerifier = (input: {
  readonly command: RuntimeCompensationCommand;
  readonly nowMs: number;
}) => boolean;

export interface RuntimeCompensationMaterializerOptions {
  readonly journal: RuntimeCompensationMaterializationJournal;
  readonly authorityIssuer: RuntimeCompensationAuthorityIssuer;
  readonly verifyAuthority: RuntimeCompensationCommandAuthorityVerifier;
  readonly policySource: RuntimeCompensationPolicySource;
  readonly idGenerator: () => string;
  readonly clock?: () => number;
  readonly commandTtlMs?: number;
}

export interface RuntimeCompensationMaterializerRunResult {
  readonly found: number;
  readonly created: number;
}

/** Materialize at most one signed command per call. */
export class RuntimeCompensationMaterializer {
  private readonly journal: RuntimeCompensationMaterializationJournal;
  private readonly authorityIssuer: RuntimeCompensationAuthorityIssuer;
  private readonly policySource: RuntimeCompensationPolicySource;
  private readonly verifyAuthority: RuntimeCompensationCommandAuthorityVerifier;
  private readonly idGenerator: () => string;
  private readonly clock: () => number;
  private readonly commandTtlMs: number;
  private activeRun: Promise<RuntimeCompensationMaterializerRunResult> | null = null;

  constructor(options: RuntimeCompensationMaterializerOptions) {
    if (
      typeof options?.journal?.findMaterializable !== "function" ||
      typeof options?.journal?.materialize !== "function" ||
      typeof options?.authorityIssuer?.issue !== "function" ||
      typeof options?.verifyAuthority !== "function" ||
      typeof options?.policySource?.resolve !== "function" ||
      typeof options?.idGenerator !== "function"
    ) {
      throw new TypeError("Invalid Runtime compensation materializer dependency");
    }
    this.journal = options.journal;
    this.authorityIssuer = options.authorityIssuer;
    this.verifyAuthority = options.verifyAuthority;
    this.policySource = options.policySource;
    this.idGenerator = options.idGenerator;
    this.clock = options.clock ?? Date.now;
    if (typeof this.clock !== "function") throw new TypeError("Invalid Runtime clock");
    this.commandTtlMs = boundedInteger(
      options.commandTtlMs ?? DEFAULT_COMMAND_TTL_MS,
      1,
      MAX_COMMAND_TTL_MS
    );
  }

  /** Concurrent callers share the same signing attempt. */
  runOnce(
    signal: AbortSignal = new AbortController().signal
  ): Promise<RuntimeCompensationMaterializerRunResult> {
    if (this.activeRun) return this.activeRun;
    const run = this.materializeOne(signal).finally(() => {
      if (this.activeRun === run) this.activeRun = null;
    });
    this.activeRun = run;
    return run;
  }

  private async materializeOne(
    signal: AbortSignal
  ): Promise<RuntimeCompensationMaterializerRunResult> {
    assertNotAborted(signal);
    const observedAtMs = sampleClock(this.clock);
    const unsafeCandidate = await this.journal.findMaterializable({ nowMs: observedAtMs, signal });
    assertNotAborted(signal);
    if (unsafeCandidate === null) return { found: 0, created: 0 };
    const candidate = snapshotCandidate(unsafeCandidate);
    assertNotAborted(signal);
    const policy = snapshotPolicy(this.policySource.resolve(candidate));
    assertNotAborted(signal);
    const issuedAtMs = sampleClock(this.clock, observedAtMs);
    const deadlineAtMs = safeAdd(issuedAtMs, this.commandTtlMs);
    const commandId = safeRef(this.idGenerator());
    const claims = deepFreeze({
      kind: "safety.quarantine" as const,
      commandId,
      compensationId: candidate.compensationId,
      binding: candidate.binding,
      observedRuntimeAuthorizationGeneration: candidate.observedRuntimeAuthorizationGeneration,
      source: candidate.source,
      platformSecurityPolicyRevision: policy.platformSecurityPolicyRevision,
      requiredContainmentEnforcerSetDigest: policy.requiredContainmentEnforcerSetDigest,
      containment: {
        revokeTerminalWrites: true as const,
        stopProcessExecution: true as const,
        quarantineRuntime: true as const,
      },
      safetyFence: candidate.safetyFence,
      exactBindingOnly: true as const,
      advanceBeyondCurrentFences: true as const,
      reasonRef: candidate.incidentDigest,
      causationId: candidate.source.lifecycleCommandId,
      actor: { kind: "system" as const, actorRef: "platform-security" as const },
      issuedAtMs,
      deadlineAtMs,
    }) satisfies RuntimeCompensationCommandClaims;

    assertNotAborted(signal);
    const authority = snapshotAuthority(this.authorityIssuer.issue(claims), claims);
    assertNotAborted(signal);
    const command = deepFreeze({ ...claims, authority }) satisfies RuntimeCompensationCommand;
    const authorityVerifiedAtMs = sampleClock(this.clock, issuedAtMs);
    if (authorityVerifiedAtMs >= deadlineAtMs) {
      throw new TypeError("Platform-security Runtime authority could not be verified");
    }
    let verified: unknown;
    try {
      verified = this.verifyAuthority({ command, nowMs: authorityVerifiedAtMs });
    } catch {
      throw new TypeError("Platform-security Runtime authority could not be verified");
    }
    if (verified !== true) {
      suppressNativePromiseRejection(verified);
      throw new TypeError("Platform-security Runtime authority could not be verified");
    }
    assertNotAborted(signal);
    const materializedAtMs = sampleClock(this.clock, authorityVerifiedAtMs);
    const result = await this.journal.materialize(
      {
        compensationId: candidate.compensationId,
        incidentDigest: candidate.incidentDigest,
        command,
        authorityVerifiedAtMs,
        materializedAtMs,
      },
      { signal }
    );
    assertNotAborted(signal);
    if (result !== "created" && result !== "already-materialized") {
      throw new TypeError("Invalid Runtime compensation materialization result");
    }
    return { found: 1, created: result === "created" ? 1 : 0 };
  }
}

function assertNotAborted(signal: AbortSignal): void {
  if (signal?.aborted === true) {
    throw new DOMException("Runtime compensation materialization aborted", "AbortError");
  }
}

export function createRuntimeCompensationMaterializer(
  options: RuntimeCompensationMaterializerOptions
): RuntimeCompensationMaterializer {
  return new RuntimeCompensationMaterializer(options);
}

function snapshotCandidate(
  value: RuntimeCompensationMaterializationCandidate
): RuntimeCompensationMaterializationCandidate {
  const candidate = exactDataRecord(value, CANDIDATE_FIELDS, "Invalid compensation incident");
  const binding = snapshotBinding(dataField(candidate, "binding", "Invalid compensation incident"));
  const source = exactDataRecord(
    dataField(candidate, "source", "Invalid compensation incident"),
    SOURCE_FIELDS,
    "Invalid compensation incident"
  );
  const snapshot = {
    compensationId: safeRef(
      dataField(candidate, "compensationId", "Invalid compensation incident")
    ),
    incidentDigest: sha256(dataField(candidate, "incidentDigest", "Invalid compensation incident")),
    binding,
    observedRuntimeAuthorizationGeneration: positiveInteger(
      dataField(
        candidate,
        "observedRuntimeAuthorizationGeneration",
        "Invalid compensation incident"
      )
    ),
    safetyFence: positiveInteger(
      dataField(candidate, "safetyFence", "Invalid compensation incident")
    ),
    source: {
      lifecycleCommandId: safeRef(
        dataField(source, "lifecycleCommandId", "Invalid compensation incident")
      ),
      lifecycleCommandClaimsDigest: sha256(
        dataField(source, "lifecycleCommandClaimsDigest", "Invalid compensation incident")
      ),
      lifecycleReceiptDigest: sha256(
        dataField(source, "lifecycleReceiptDigest", "Invalid compensation incident")
      ),
      lifecycleEnforcementSubjectDigest: sha256(
        dataField(source, "lifecycleEnforcementSubjectDigest", "Invalid compensation incident")
      ),
      lifecycleAggregateProofDigest: sha256(
        dataField(source, "lifecycleAggregateProofDigest", "Invalid compensation incident")
      ),
      sourceRequiredEffectEnforcerSetDigest: sha256(
        dataField(source, "sourceRequiredEffectEnforcerSetDigest", "Invalid compensation incident")
      ),
    },
  };
  return deepFreeze(snapshot);
}

function snapshotPolicy(value: RuntimeCompensationPolicySnapshot | undefined) {
  const policy = exactDataRecord(
    value,
    POLICY_FIELDS,
    "Runtime compensation policy is unavailable"
  );
  return Object.freeze({
    platformSecurityPolicyRevision: safeRef(
      dataField(
        policy,
        "platformSecurityPolicyRevision",
        "Runtime compensation policy is unavailable"
      )
    ),
    requiredContainmentEnforcerSetDigest: sha256(
      dataField(
        policy,
        "requiredContainmentEnforcerSetDigest",
        "Runtime compensation policy is unavailable"
      )
    ),
  });
}

function snapshotAuthority(
  value: PlatformSecurityRuntimeAuthorityEnvelope<"safety.quarantine">,
  claims: RuntimeCompensationCommandClaims
): PlatformSecurityRuntimeAuthorityEnvelope<"safety.quarantine"> {
  const authority = exactDataRecord(
    value,
    AUTHORITY_FIELDS,
    "Invalid platform-security Runtime authority"
  );
  const issuer = dataField(authority, "issuer", "Invalid platform-security Runtime authority");
  const issuerKeyId = dataField(
    authority,
    "issuerKeyId",
    "Invalid platform-security Runtime authority"
  );
  const audience = dataField(authority, "audience", "Invalid platform-security Runtime authority");
  const capability = dataField(
    authority,
    "capability",
    "Invalid platform-security Runtime authority"
  );
  const claimsDigest = dataField(
    authority,
    "claimsDigest",
    "Invalid platform-security Runtime authority"
  );
  const issuedAtMs = dataField(
    authority,
    "issuedAtMs",
    "Invalid platform-security Runtime authority"
  );
  const expiresAtMs = dataField(
    authority,
    "expiresAtMs",
    "Invalid platform-security Runtime authority"
  );
  const signature = dataField(
    authority,
    "signature",
    "Invalid platform-security Runtime authority"
  );
  if (
    issuer !== "platform-security" ||
    capability !== "safety.quarantine" ||
    audience !== "runtime" ||
    claimsDigest !== digestRuntimeCommandClaims(claims) ||
    issuedAtMs !== claims.issuedAtMs ||
    !Number.isSafeInteger(expiresAtMs) ||
    (expiresAtMs as number) <= claims.issuedAtMs ||
    (expiresAtMs as number) > claims.deadlineAtMs ||
    typeof issuerKeyId !== "string" ||
    !SAFE_REF.test(issuerKeyId) ||
    typeof signature !== "string" ||
    signature.length < 1 ||
    signature.length > 4_000 ||
    signature.trim() !== signature ||
    /[\u0000-\u001f\u007f]/.test(signature)
  ) {
    throw new TypeError("Invalid platform-security Runtime authority");
  }
  return Object.freeze({
    issuer: "platform-security",
    issuerKeyId,
    audience: "runtime",
    capability: "safety.quarantine",
    claimsDigest: claimsDigest as string,
    issuedAtMs: claims.issuedAtMs,
    expiresAtMs: expiresAtMs as number,
    signature,
  });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const binding = exactDataRecord(value, BINDING_FIELDS, "Invalid Runtime binding");
  return Object.freeze({
    teamId: safeRef(dataField(binding, "teamId", "Invalid Runtime binding")),
    projectId: safeRef(dataField(binding, "projectId", "Invalid Runtime binding")),
    sessionId: safeRef(dataField(binding, "sessionId", "Invalid Runtime binding")),
    runtimeAssignmentId: safeRef(
      dataField(binding, "runtimeAssignmentId", "Invalid Runtime binding")
    ),
    runtimeAssignmentGeneration: positiveInteger(
      dataField(binding, "runtimeAssignmentGeneration", "Invalid Runtime binding")
    ),
    sandboxId: safeRef(dataField(binding, "sandboxId", "Invalid Runtime binding")),
    sandboxGeneration: positiveInteger(
      dataField(binding, "sandboxGeneration", "Invalid Runtime binding")
    ),
    runtimePrincipalId: safeRef(
      dataField(binding, "runtimePrincipalId", "Invalid Runtime binding")
    ),
  });
}

function exactDataRecord(
  value: unknown,
  fields: readonly string[],
  message: string
): Record<string, unknown> {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError(message);
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError(message);
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== fields.length ||
      keys.some((key) => typeof key !== "string" || !fields.includes(key))
    ) {
      throw new TypeError(message);
    }
    for (const field of fields) dataField(value, field, message);
    return value as Record<string, unknown>;
  } catch (error) {
    if (error instanceof TypeError && error.message === message) throw error;
    throw new TypeError(message);
  }
}

function dataField(value: object, field: string, message: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, field);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    throw new TypeError(message);
  }
  return descriptor.value;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function safeRef(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REF.test(value)) {
    throw new TypeError("Invalid Runtime compensation reference");
  }
  return value;
}

function sha256(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError("Invalid Runtime compensation digest");
  }
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TypeError("Invalid Runtime compensation generation");
  }
  return value as number;
}

function boundedInteger(value: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError("Invalid Runtime compensation materializer bound");
  }
  return value;
}

function sampleClock(clock: () => number, minimum = 0): number {
  let nowMs: number;
  try {
    nowMs = clock();
  } catch {
    throw new TypeError("Invalid Runtime clock");
  }
  if (!Number.isSafeInteger(nowMs) || nowMs < minimum) {
    throw new TypeError("Invalid Runtime clock");
  }
  return nowMs;
}

function safeAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw new TypeError("Invalid Runtime compensation time");
  return result;
}
