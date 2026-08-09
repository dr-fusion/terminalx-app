import { createHash } from "node:crypto";
import type { RuntimeBinding } from "../team-sessions/contracts";
import { canonicalRuntimeJson } from "./runtime-command-canonical";
import {
  snapshotPersistedRuntimeEffectRefCommitment,
  type RuntimeEffectRefCommitment,
} from "./runtime-enforcement-proof";

export const RUNTIME_COMPENSATION_INCIDENT_DIGEST_DOMAIN =
  "terminalx/runtime-compensation-incident/v1\0" as const;

const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_REF = /^[^\u0000-\u001f\u007f]{1,300}$/;
const INCIDENT_FIELDS = [
  "version",
  "compensationId",
  "sourceCommandId",
  "sourceReceiptId",
  "trustState",
  "binding",
  "observedRuntimeAuthorizationGeneration",
  "lifecycleCommandClaimsDigest",
  "lifecycleReceiptDigest",
  "sourceEnforcedFence",
  "safetyFence",
  "sourceRequiredEffectEnforcerSetDigest",
  "lifecycleEnforcementSubjectDigest",
  "lifecycleAggregateProofDigest",
  "sourceEffectRefCommitment",
  "createdAtMs",
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

interface RuntimeCompensationIncidentBase {
  readonly version: 1;
  readonly compensationId: string;
  readonly sourceCommandId: string;
  readonly sourceReceiptId: string;
  readonly binding: RuntimeBinding;
  readonly observedRuntimeAuthorizationGeneration: number;
  readonly lifecycleCommandClaimsDigest: string;
  readonly lifecycleReceiptDigest: string;
  readonly sourceEnforcedFence: number;
  readonly safetyFence: number;
  readonly createdAtMs: number;
}

export type RuntimeCompensationIncident =
  | (RuntimeCompensationIncidentBase & {
      readonly trustState: "verified";
      readonly sourceRequiredEffectEnforcerSetDigest: string;
      readonly lifecycleEnforcementSubjectDigest: string;
      readonly lifecycleAggregateProofDigest: string;
      readonly sourceEffectRefCommitment: RuntimeEffectRefCommitment;
    })
  | (RuntimeCompensationIncidentBase & {
      readonly trustState: "legacy-untrusted";
      readonly sourceRequiredEffectEnforcerSetDigest: null;
      readonly lifecycleEnforcementSubjectDigest: null;
      readonly lifecycleAggregateProofDigest: null;
      readonly sourceEffectRefCommitment: null;
    });

export class RuntimeCompensationIncidentError extends TypeError {
  readonly code = "invalid_incident" as const;

  constructor() {
    super("Runtime compensation incident is invalid");
    this.name = "RuntimeCompensationIncidentError";
  }
}

/**
 * Validate, detach, and deeply freeze one durable compensation incident.
 *
 * The proof group is all-or-nothing: live incidents retain complete verified
 * source evidence, while migrated untrusted incidents cannot acquire partial
 * trust by populating only some proof fields.
 */
export function snapshotRuntimeCompensationIncident(value: unknown): RuntimeCompensationIncident {
  try {
    const incident = exactDataRecord(value, INCIDENT_FIELDS);
    const version = dataField(incident, "version");
    const trustState = dataField(incident, "trustState");
    if (version !== 1 || (trustState !== "verified" && trustState !== "legacy-untrusted")) {
      invalid();
    }

    const sourceEnforcedFence = positiveInteger(dataField(incident, "sourceEnforcedFence"));
    const safetyFence = positiveInteger(dataField(incident, "safetyFence"));
    if (safetyFence <= sourceEnforcedFence) invalid();

    const base = {
      version: 1 as const,
      compensationId: safeRef(dataField(incident, "compensationId")),
      sourceCommandId: safeRef(dataField(incident, "sourceCommandId")),
      sourceReceiptId: safeRef(dataField(incident, "sourceReceiptId")),
      binding: snapshotBinding(dataField(incident, "binding")),
      observedRuntimeAuthorizationGeneration: positiveInteger(
        dataField(incident, "observedRuntimeAuthorizationGeneration")
      ),
      lifecycleCommandClaimsDigest: sha256(dataField(incident, "lifecycleCommandClaimsDigest")),
      lifecycleReceiptDigest: sha256(dataField(incident, "lifecycleReceiptDigest")),
      sourceEnforcedFence,
      safetyFence,
      createdAtMs: nonNegativeInteger(dataField(incident, "createdAtMs")),
    };

    const sourceRequiredEffectEnforcerSetDigest = dataField(
      incident,
      "sourceRequiredEffectEnforcerSetDigest"
    );
    const lifecycleEnforcementSubjectDigest = dataField(
      incident,
      "lifecycleEnforcementSubjectDigest"
    );
    const lifecycleAggregateProofDigest = dataField(incident, "lifecycleAggregateProofDigest");
    const sourceEffectRefCommitment = dataField(incident, "sourceEffectRefCommitment");

    if (trustState === "verified") {
      return Object.freeze({
        ...base,
        trustState,
        sourceRequiredEffectEnforcerSetDigest: sha256(sourceRequiredEffectEnforcerSetDigest),
        lifecycleEnforcementSubjectDigest: sha256(lifecycleEnforcementSubjectDigest),
        lifecycleAggregateProofDigest: sha256(lifecycleAggregateProofDigest),
        sourceEffectRefCommitment: persistedEffectRefCommitment(sourceEffectRefCommitment),
      });
    }
    if (
      sourceRequiredEffectEnforcerSetDigest !== null ||
      lifecycleEnforcementSubjectDigest !== null ||
      lifecycleAggregateProofDigest !== null ||
      sourceEffectRefCommitment !== null
    ) {
      invalid();
    }
    return Object.freeze({
      ...base,
      trustState,
      sourceRequiredEffectEnforcerSetDigest: null,
      lifecycleEnforcementSubjectDigest: null,
      lifecycleAggregateProofDigest: null,
      sourceEffectRefCommitment: null,
    });
  } catch (error) {
    if (error instanceof RuntimeCompensationIncidentError) throw error;
    invalid();
  }
}

/** Lowercase SHA-256 over the exact canonical incident snapshot. */
export function digestRuntimeCompensationIncident(value: unknown): string {
  try {
    const snapshot = snapshotRuntimeCompensationIncident(value);
    return createHash("sha256")
      .update(RUNTIME_COMPENSATION_INCIDENT_DIGEST_DOMAIN, "utf8")
      .update(canonicalRuntimeJson(snapshot), "utf8")
      .digest("hex");
  } catch (error) {
    if (error instanceof RuntimeCompensationIncidentError) throw error;
    invalid();
  }
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const binding = exactDataRecord(value, BINDING_FIELDS);
  return Object.freeze({
    teamId: safeRef(dataField(binding, "teamId")),
    projectId: safeRef(dataField(binding, "projectId")),
    sessionId: safeRef(dataField(binding, "sessionId")),
    runtimeAssignmentId: safeRef(dataField(binding, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(dataField(binding, "runtimeAssignmentGeneration")),
    sandboxId: safeRef(dataField(binding, "sandboxId")),
    sandboxGeneration: positiveInteger(dataField(binding, "sandboxGeneration")),
    runtimePrincipalId: safeRef(dataField(binding, "runtimePrincipalId")),
  });
}

function exactDataRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) invalid();
  let prototype: object | null;
  let keys: PropertyKey[];
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch {
    invalid();
  }
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    invalid();
  }
  return value as Record<string, unknown>;
}

function dataField(record: Record<string, unknown>, name: string): unknown {
  let descriptor: PropertyDescriptor | undefined;
  try {
    descriptor = Object.getOwnPropertyDescriptor(record, name);
  } catch {
    invalid();
  }
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
  return descriptor.value;
}

function safeRef(value: unknown): string {
  if (typeof value !== "string" || !SAFE_REF.test(value)) invalid();
  return value;
}

function sha256(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) invalid();
  return value;
}

function persistedEffectRefCommitment(value: unknown): RuntimeEffectRefCommitment {
  try {
    return snapshotPersistedRuntimeEffectRefCommitment(value);
  } catch {
    invalid();
  }
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) invalid();
  return value as number;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) invalid();
  return value as number;
}

function invalid(): never {
  throw new RuntimeCompensationIncidentError();
}
