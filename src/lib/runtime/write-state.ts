import type { RuntimeWriteStateUpdate } from "./local-tmux-runtime";

export interface RuntimeWriteFence {
  sessionId: string;
  runtimeAuthorizationGeneration: number;
}

export interface CreateRuntimeWriteStateRegistryOptions {
  /**
   * Production transports set this to true and remain closed until one full
   * durable snapshot has been installed. Development callers retain the
   * historical kernel-authorized default.
   */
  requireBootstrap?: boolean;
}

/**
 * Process-local mirror of Runtime fence progress.
 *
 * The kernel remains authoritative. A missing entry is therefore allowed and
 * must still pass the kernel transaction. Entries only add a fast, monotonic
 * rejection for PTYs captured before a Runtime fence or retirement.
 */
export class RuntimeWriteStateRegistry {
  private states = new Map<string, RuntimeWriteStateUpdate>();
  private bootstrapped: boolean;
  private snapshotInstalled = false;

  constructor(options: CreateRuntimeWriteStateRegistryOptions = {}) {
    let requireBootstrap: unknown;
    try {
      if (
        typeof options !== "object" ||
        options === null ||
        Array.isArray(options) ||
        Object.getPrototypeOf(options) !== Object.prototype
      ) {
        throw new TypeError();
      }
      const keys = Reflect.ownKeys(options);
      if (keys.length > 1 || keys.some((key) => key !== "requireBootstrap")) {
        throw new TypeError();
      }
      const descriptor = Object.getOwnPropertyDescriptor(options, "requireBootstrap");
      if (descriptor !== undefined) {
        if (!descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
        requireBootstrap = descriptor.value;
      }
    } catch {
      throw new TypeError("Invalid Runtime write-state registry options");
    }
    if (requireBootstrap !== undefined && typeof requireBootstrap !== "boolean") {
      throw new TypeError("Invalid Runtime write-state registry options");
    }
    this.bootstrapped = requireBootstrap !== true;
  }

  get isBootstrapped(): boolean {
    return this.bootstrapped;
  }

  get hasDurableSnapshot(): boolean {
    return this.snapshotInstalled;
  }

  /**
   * Atomically install one complete durable restart snapshot. Updates that
   * raced while the snapshot was being read are merged monotonically and can
   * never be rolled back by older persisted state.
   */
  bootstrap(updates: readonly RuntimeWriteStateUpdate[]): void {
    if (this.snapshotInstalled) {
      throw new TypeError("Invalid Runtime write-state bootstrap");
    }
    const snapshot = new Map<string, RuntimeWriteStateUpdate>();
    for (const update of snapshotUpdates(updates)) {
      if (snapshot.has(update.sessionId)) {
        throw new TypeError("Invalid Runtime write-state bootstrap");
      }
      snapshot.set(update.sessionId, update);
    }
    for (const update of this.states.values()) mergeMonotonic(snapshot, update);
    this.states = snapshot;
    this.snapshotInstalled = true;
    this.bootstrapped = true;
  }

  update(update: RuntimeWriteStateUpdate): void {
    const snapshot = snapshotUpdate(update);
    mergeMonotonic(this.states, snapshot);
  }

  isWriteAllowed(input: RuntimeWriteFence): boolean {
    const fence = snapshotFence(input);
    if (!this.bootstrapped) return false;
    const state = this.states.get(fence.sessionId);
    if (!state) return true;
    if (fence.runtimeAuthorizationGeneration < state.runtimeAuthorizationGeneration) return false;
    if (
      state.state === "retired" &&
      fence.runtimeAuthorizationGeneration <= state.runtimeAuthorizationGeneration
    ) {
      return false;
    }
    return true;
  }
}

export function createRuntimeWriteStateRegistry(
  options: CreateRuntimeWriteStateRegistryOptions = {}
): RuntimeWriteStateRegistry {
  return new RuntimeWriteStateRegistry(options);
}

function validateFenceValues(input: RuntimeWriteFence): void {
  if (
    typeof input.sessionId !== "string" ||
    input.sessionId.length < 1 ||
    input.sessionId.length > 256 ||
    input.sessionId.trim() !== input.sessionId ||
    /[\0\r\n\t]/.test(input.sessionId) ||
    !Number.isSafeInteger(input.runtimeAuthorizationGeneration) ||
    input.runtimeAuthorizationGeneration < 1
  ) {
    throw new TypeError("Invalid Runtime write fence");
  }
}

function validateUpdate(update: RuntimeWriteStateUpdate): void {
  validateFenceValues(update);
  if (update.state !== "active" && update.state !== "fenced" && update.state !== "retired") {
    throw new TypeError("Invalid Runtime write state");
  }
}

function snapshotFence(input: RuntimeWriteFence): RuntimeWriteFence {
  try {
    if (
      typeof input !== "object" ||
      input === null ||
      Array.isArray(input) ||
      Object.getPrototypeOf(input) !== Object.prototype
    ) {
      throw new TypeError();
    }
    const fields = ["sessionId", "runtimeAuthorizationGeneration"] as const;
    const keys = Reflect.ownKeys(input);
    if (keys.length !== fields.length || keys.some((key) => !fields.includes(key as never))) {
      throw new TypeError();
    }
    const sessionId = dataField(input, "sessionId");
    const runtimeAuthorizationGeneration = dataField(input, "runtimeAuthorizationGeneration");
    const snapshot = { sessionId, runtimeAuthorizationGeneration } as RuntimeWriteFence;
    validateFenceValues(snapshot);
    return Object.freeze(snapshot);
  } catch {
    throw new TypeError("Invalid Runtime write fence");
  }
}

function dataField(value: object, key: PropertyKey): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) throw new TypeError();
  return descriptor.value;
}

function snapshotUpdate(update: RuntimeWriteStateUpdate): RuntimeWriteStateUpdate {
  let snapshot: RuntimeWriteStateUpdate;
  try {
    if (
      typeof update !== "object" ||
      update === null ||
      Array.isArray(update) ||
      Object.getPrototypeOf(update) !== Object.prototype
    ) {
      throw new TypeError();
    }
    const fields = ["sessionId", "runtimeAuthorizationGeneration", "state"] as const;
    const keys = Reflect.ownKeys(update);
    if (keys.length !== fields.length || keys.some((key) => !fields.includes(key as never))) {
      throw new TypeError("Invalid Runtime write state");
    }
    const values = Object.fromEntries(
      fields.map((field) => {
        const descriptor = Object.getOwnPropertyDescriptor(update, field);
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
          throw new TypeError();
        }
        return [field, descriptor.value];
      })
    ) as unknown as RuntimeWriteStateUpdate;
    snapshot = values;
  } catch {
    throw new TypeError("Invalid Runtime write state");
  }
  validateUpdate(snapshot);
  return Object.freeze(snapshot);
}

function snapshotUpdates(updates: readonly RuntimeWriteStateUpdate[]): RuntimeWriteStateUpdate[] {
  try {
    if (!Array.isArray(updates) || Object.getPrototypeOf(updates) !== Array.prototype) {
      throw new TypeError();
    }
    const length = Object.getOwnPropertyDescriptor(updates, "length");
    if (
      !length ||
      length.enumerable ||
      !("value" in length) ||
      !Number.isSafeInteger(length.value) ||
      length.value < 0 ||
      length.value > 100_000
    ) {
      throw new TypeError();
    }
    const keys = Reflect.ownKeys(updates);
    if (
      keys.length !== length.value + 1 ||
      !keys.includes("length") ||
      keys.some(
        (key) =>
          key !== "length" &&
          (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= length.value)
      )
    ) {
      throw new TypeError();
    }
    const result: RuntimeWriteStateUpdate[] = [];
    for (let index = 0; index < length.value; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(updates, String(index));
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new TypeError();
      }
      result.push(snapshotUpdate(descriptor.value as RuntimeWriteStateUpdate));
    }
    return result;
  } catch {
    throw new TypeError("Invalid Runtime write-state bootstrap");
  }
}

function mergeMonotonic(
  target: Map<string, RuntimeWriteStateUpdate>,
  update: RuntimeWriteStateUpdate
): void {
  const current = target.get(update.sessionId);
  if (current) {
    if (update.runtimeAuthorizationGeneration < current.runtimeAuthorizationGeneration) return;
    if (
      update.runtimeAuthorizationGeneration === current.runtimeAuthorizationGeneration &&
      stateRank(update.state) < stateRank(current.state)
    ) {
      return;
    }
  }
  target.set(update.sessionId, update);
}

function stateRank(state: RuntimeWriteStateUpdate["state"]): number {
  switch (state) {
    case "active":
      return 0;
    case "fenced":
      return 1;
    case "retired":
      return 2;
  }
}
