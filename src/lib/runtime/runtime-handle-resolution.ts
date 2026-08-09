import { types as utilTypes } from "node:util";
import type { RuntimeBinding } from "../team-sessions/contracts";
import type { RuntimeHandle } from "./contracts";

const MAX_PROTOTYPE_DEPTH = 32;
const MAX_REFERENCE_LENGTH = 300;

export type CapturedRuntimeHandleResolver<Input> = (
  input: Input,
  signal: AbortSignal
) => Promise<RuntimeHandle | null>;

/** Capture an adapter lookup capability without invoking an accessor. */
export function captureRuntimeHandleResolver<Input>(
  resolver: unknown
): CapturedRuntimeHandleResolver<Input> {
  if (
    (typeof resolver !== "object" && typeof resolver !== "function") ||
    resolver === null ||
    utilTypes.isProxy(resolver)
  ) {
    throw new TypeError("Invalid Runtime handle resolver");
  }
  try {
    const visited = new Set<object>();
    let current: object | null = resolver;
    for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
      if (visited.has(current) || utilTypes.isProxy(current)) {
        throw new TypeError("Invalid Runtime handle resolver");
      }
      visited.add(current);
      const descriptor = Object.getOwnPropertyDescriptor(current, "resolve");
      if (descriptor !== undefined) {
        if (!("value" in descriptor) || typeof descriptor.value !== "function") {
          throw new TypeError("Invalid Runtime handle resolver");
        }
        const resolve = descriptor.value;
        return Object.freeze((input: Input, signal: AbortSignal) => {
          const result = Reflect.apply(resolve, resolver, [input, signal]) as unknown;
          return result as Promise<RuntimeHandle | null>;
        });
      }
      current = Object.getPrototypeOf(current) as object | null;
    }
  } catch {
    throw new TypeError("Invalid Runtime handle resolver");
  }
  throw new TypeError("Invalid Runtime handle resolver");
}

/** Detach and exact-bind one adapter-owned handle before any dispatch interlock. */
export function snapshotExactRuntimeHandle(
  value: unknown,
  expectedBinding: RuntimeBinding
): RuntimeHandle | null {
  if (value === null) return null;
  try {
    const handle = exactRecord(value, ["binding", "opaqueHandleRef", "capabilities"]);
    const binding = snapshotBinding(field(handle, "binding"));
    if (!sameBinding(binding, expectedBinding)) return null;
    const unsafeCapabilities = exactRecord(field(handle, "capabilities"), [
      "isolatedExecution",
      "brokeredCredentials",
      "proxyOnlyEgress",
      "checkpoints",
      "yoloEligible",
    ]);
    const capabilities = Object.freeze({
      isolatedExecution: booleanValue(field(unsafeCapabilities, "isolatedExecution")),
      brokeredCredentials: booleanValue(field(unsafeCapabilities, "brokeredCredentials")),
      proxyOnlyEgress: booleanValue(field(unsafeCapabilities, "proxyOnlyEgress")),
      checkpoints: booleanValue(field(unsafeCapabilities, "checkpoints")),
      yoloEligible: booleanValue(field(unsafeCapabilities, "yoloEligible")),
    });
    return Object.freeze({
      binding,
      opaqueHandleRef: safeReference(field(handle, "opaqueHandleRef")),
      capabilities,
    });
  } catch {
    return null;
  }
}

function snapshotBinding(value: unknown): RuntimeBinding {
  const binding = exactRecord(value, [
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
    teamId: safeReference(field(binding, "teamId")),
    projectId: safeReference(field(binding, "projectId")),
    sessionId: safeReference(field(binding, "sessionId")),
    runtimeAssignmentId: safeReference(field(binding, "runtimeAssignmentId")),
    runtimeAssignmentGeneration: positiveInteger(field(binding, "runtimeAssignmentGeneration")),
    sandboxId: safeReference(field(binding, "sandboxId")),
    sandboxGeneration: positiveInteger(field(binding, "sandboxGeneration")),
    runtimePrincipalId: safeReference(field(binding, "runtimePrincipalId")),
  });
}

function exactRecord(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    utilTypes.isProxy(value)
  ) {
    throw new TypeError();
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new TypeError();
  }
  for (const key of expected) field(value as Record<string, unknown>, key);
  return value as Record<string, unknown>;
}

function field(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function safeReference(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > MAX_REFERENCE_LENGTH ||
    value.trim() !== value ||
    /[\0\r\n\t]/.test(value)
  ) {
    throw new TypeError();
  }
  return value;
}

function positiveInteger(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TypeError();
  return value as number;
}

function booleanValue(value: unknown): boolean {
  if (typeof value !== "boolean") throw new TypeError();
  return value;
}

function sameBinding(left: RuntimeBinding, right: RuntimeBinding): boolean {
  return (
    left.teamId === right.teamId &&
    left.projectId === right.projectId &&
    left.sessionId === right.sessionId &&
    left.runtimeAssignmentId === right.runtimeAssignmentId &&
    left.runtimeAssignmentGeneration === right.runtimeAssignmentGeneration &&
    left.sandboxId === right.sandboxId &&
    left.sandboxGeneration === right.sandboxGeneration &&
    left.runtimePrincipalId === right.runtimePrincipalId
  );
}
