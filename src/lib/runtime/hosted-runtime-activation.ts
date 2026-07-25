import { types as nodeTypes } from "node:util";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { HostedRuntimeActivation } from "./hosted-runtime-control-plane";
import { snapshotRuntimeSupervisorPortableData } from "./runtime-supervisor-snapshot";

const SHA256 = /^[0-9a-f]{64}$/;
const ACTIVATION_FIELDS = [
  "version",
  "kind",
  "binding",
  "runtimeAuthorizationGeneration",
  "assignmentPlanDigest",
  "effectEnforcerPolicyDigest",
  "providerIdentityCommitment",
  "providerRevision",
  "effectManifestBindingDigest",
  "effectEnforcerSetDigest",
] as const;

/** Strict provider-neutral snapshot for the durable hosted activation seam. */
export function snapshotHostedRuntimeActivation(value: unknown): HostedRuntimeActivation {
  const record = exactRecord(snapshotRuntimeSupervisorPortableData(value), ACTIVATION_FIELDS);
  if (field(record, "version") !== 1 || field(record, "kind") !== "hosted-runtime.activation") {
    throw new TypeError();
  }
  return Object.freeze({
    version: 1,
    kind: "hosted-runtime.activation",
    binding: snapshotBinding(field(record, "binding")),
    runtimeAuthorizationGeneration: positiveInteger(
      field(record, "runtimeAuthorizationGeneration")
    ),
    assignmentPlanDigest: digest(field(record, "assignmentPlanDigest")),
    effectEnforcerPolicyDigest: digest(field(record, "effectEnforcerPolicyDigest")),
    providerIdentityCommitment: digest(field(record, "providerIdentityCommitment")),
    providerRevision: positiveInteger(field(record, "providerRevision")),
    effectManifestBindingDigest: digest(field(record, "effectManifestBindingDigest")),
    effectEnforcerSetDigest: digest(field(record, "effectEnforcerSetDigest")),
  });
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const record = exactRecord(value, [
    "teamId",
    "projectId",
    "sessionId",
    "runtimeAssignmentId",
    "runtimeAssignmentGeneration",
    "sandboxId",
    "sandboxGeneration",
    "runtimePrincipalId",
  ]);
  return Object.freeze({
    teamId: safeReference(field(record, "teamId")),
    projectId: safeReference(field(record, "projectId")),
    sessionId: safeReference(field(record, "sessionId")),
    runtimeAssignmentId: safeReference(field(record, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(record, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(record, "sandboxId")),
    sandboxGeneration: positiveInteger(field(record, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(record, "runtimePrincipalId")),
  });
}

function exactRecord(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)
  ) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    throw new TypeError();
  }
  for (const name of fields) field(value as Record<string, unknown>, name);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, name);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > 300 ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    throw new TypeError();
  }
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new TypeError();
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}
