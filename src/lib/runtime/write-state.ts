import type { RuntimeWriteStateUpdate } from "./local-tmux-runtime";

export interface RuntimeWriteFence {
  sessionId: string;
  runtimeAuthorizationGeneration: number;
}

/**
 * Process-local mirror of Runtime fence progress.
 *
 * The kernel remains authoritative. A missing entry is therefore allowed and
 * must still pass the kernel transaction. Entries only add a fast, monotonic
 * rejection for PTYs captured before a Runtime fence or retirement.
 */
export class RuntimeWriteStateRegistry {
  private readonly states = new Map<string, RuntimeWriteStateUpdate>();

  update(update: RuntimeWriteStateUpdate): void {
    validateUpdate(update);
    const current = this.states.get(update.sessionId);
    if (current) {
      if (update.runtimeAuthorizationGeneration < current.runtimeAuthorizationGeneration) return;
      if (
        update.runtimeAuthorizationGeneration === current.runtimeAuthorizationGeneration &&
        stateRank(update.state) < stateRank(current.state)
      ) {
        return;
      }
    }
    this.states.set(update.sessionId, Object.freeze({ ...update }));
  }

  isWriteAllowed(input: RuntimeWriteFence): boolean {
    validateFence(input);
    const state = this.states.get(input.sessionId);
    if (!state) return true;
    if (input.runtimeAuthorizationGeneration < state.runtimeAuthorizationGeneration) return false;
    if (
      state.state === "retired" &&
      input.runtimeAuthorizationGeneration <= state.runtimeAuthorizationGeneration
    ) {
      return false;
    }
    return true;
  }
}

export function createRuntimeWriteStateRegistry(): RuntimeWriteStateRegistry {
  return new RuntimeWriteStateRegistry();
}

function validateFence(input: RuntimeWriteFence): void {
  if (
    !input.sessionId ||
    input.sessionId.length > 256 ||
    /[\0\r\n\t]/.test(input.sessionId) ||
    !Number.isSafeInteger(input.runtimeAuthorizationGeneration) ||
    input.runtimeAuthorizationGeneration < 1
  ) {
    throw new TypeError("Invalid Runtime write fence");
  }
}

function validateUpdate(update: RuntimeWriteStateUpdate): void {
  validateFence(update);
  if (update.state !== "active" && update.state !== "fenced" && update.state !== "retired") {
    throw new TypeError("Invalid Runtime write state");
  }
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
