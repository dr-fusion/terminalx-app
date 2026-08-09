import { types as nodeTypes } from "node:util";

const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_NODES = 20_000;
const MAX_SNAPSHOT_FIELDS = 1_000;
const MAX_SNAPSHOT_STRING_BYTES = 1_000_000;

interface PortableSnapshotState {
  readonly ancestors: Set<object>;
  remainingNodes: number;
  remainingStringBytes: number;
}

/** Clone untrusted journal data without invoking accessors, proxies, or custom prototypes. */
export function snapshotRuntimeSupervisorPortableData(value: unknown): unknown {
  const state: PortableSnapshotState = {
    ancestors: new Set<object>(),
    remainingNodes: MAX_SNAPSHOT_NODES,
    remainingStringBytes: MAX_SNAPSHOT_STRING_BYTES,
  };
  return clonePortableData(value, state, 0);
}

export function exactRuntimeSupervisorDataRecord(
  value: unknown,
  fields: readonly string[]
): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError();
  }
  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== fields.length ||
    keys.some((key) => typeof key !== "string" || !fields.includes(key))
  ) {
    throw new TypeError();
  }
  for (const field of fields) runtimeSupervisorDataField(value as Record<string, unknown>, field);
  return value as Record<string, unknown>;
}

export function runtimeSupervisorDataField(
  record: Record<string, unknown>,
  field: string
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    throw new TypeError();
  }
  return descriptor.value;
}

/** Pick a past overlap candidate so structural validation does not reject an expired command. */
export function runtimeSupervisorCommandValidationInstant(
  command: Record<string, unknown>,
  fallback: number
): number {
  try {
    const commandIssuedAtMs = runtimeSupervisorDataField(command, "issuedAtMs");
    const authority = runtimeSupervisorDataField(command, "authority");
    if (
      !Number.isSafeInteger(commandIssuedAtMs) ||
      (commandIssuedAtMs as number) < 0 ||
      typeof authority !== "object" ||
      authority === null ||
      Array.isArray(authority)
    ) {
      return fallback;
    }
    const authorityIssuedAtMs = runtimeSupervisorDataField(
      authority as Record<string, unknown>,
      "issuedAtMs"
    );
    if (!Number.isSafeInteger(authorityIssuedAtMs) || (authorityIssuedAtMs as number) < 0) {
      return fallback;
    }
    return Math.max(commandIssuedAtMs as number, authorityIssuedAtMs as number);
  } catch {
    return fallback;
  }
}

function clonePortableData(value: unknown, state: PortableSnapshotState, depth: number): unknown {
  if (depth > MAX_SNAPSHOT_DEPTH || state.remainingNodes-- < 1) throw new TypeError();
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") {
    state.remainingStringBytes -= Buffer.byteLength(value, "utf8");
    if (state.remainingStringBytes < 0) throw new TypeError();
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new TypeError();
    return value;
  }
  if (typeof value !== "object" || nodeTypes.isProxy(value)) throw new TypeError();
  if (state.ancestors.has(value)) throw new TypeError();
  state.ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const keys = Reflect.ownKeys(value);
      const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
      if (!lengthDescriptor || !("value" in lengthDescriptor)) throw new TypeError();
      const length = lengthDescriptor.value;
      if (
        !Number.isSafeInteger(length) ||
        length < 0 ||
        keys.length !== length + 1 ||
        !keys.includes("length")
      ) {
        throw new TypeError();
      }
      const clone: unknown[] = [];
      for (let index = 0; index < length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
          throw new TypeError();
        }
        clone.push(clonePortableData(descriptor.value, state, depth + 1));
      }
      return Object.freeze(clone);
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) throw new TypeError();
    const keys = Reflect.ownKeys(value);
    if (keys.length > MAX_SNAPSHOT_FIELDS) throw new TypeError();
    const clone = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
      if (typeof key !== "string") throw new TypeError();
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        !descriptor ||
        !descriptor.enumerable ||
        !("value" in descriptor) ||
        descriptor.value === undefined
      ) {
        throw new TypeError();
      }
      Object.defineProperty(clone, key, {
        value: clonePortableData(descriptor.value, state, depth + 1),
        enumerable: true,
        writable: false,
        configurable: false,
      });
    }
    return Object.freeze(clone);
  } finally {
    state.ancestors.delete(value);
  }
}
