import { createTeamSessionKernel, type TeamSessionKernel } from "./module";
import type { TeamSessions } from "./types";

const serviceRegistry = globalThis as typeof globalThis & {
  __terminalxTeamSessionKernel?: TeamSessionKernel;
  __terminalxTeamSessionKernelClose?: {
    readonly kernel: TeamSessionKernel;
    readonly close: () => void;
  };
  __terminalxTeamSessionKernelPhase?: "constructing" | "closing";
};

const KERNEL_KEY = "__terminalxTeamSessionKernel" as const;
const CLOSE_KEY = "__terminalxTeamSessionKernelClose" as const;
const PHASE_KEY = "__terminalxTeamSessionKernelPhase" as const;
const MAX_PROTOTYPE_DEPTH = 32;

/**
 * Return the process-wide Team Session kernel.
 *
 * Next.js may evaluate a route module more than once during development. The
 * global registry avoids opening competing SQLite handles when modules are
 * reloaded while still keeping construction lazy for commands that do not use
 * the Team Session API.
 */
export function getTeamSessions(): TeamSessions {
  return kernelTeamSessions(getTeamSessionKernel());
}

/**
 * Return the process-wide private worker kernel. Server composition uses this
 * seam to bootstrap write fences from the same SQLite handle before exposing
 * canonical terminal transports.
 */
export function getTeamSessionKernel(): TeamSessionKernel {
  const phase = readPhase();
  if (phase !== undefined) {
    throw new TypeError("Team Session kernel lifecycle is in progress");
  }
  const current = readKernel();
  if (current) {
    ensureCloseCapability(current);
    return current;
  }

  writeRegistryValue(PHASE_KEY, "constructing");
  let created: TeamSessionKernel | undefined;
  let closeCreated: (() => void) | undefined;
  try {
    created = createTeamSessionKernel();
    closeCreated = captureKernelClose(created);
    // Construction is synchronous and guarded. A second installation here
    // means another module generation ignored the shared lifecycle fence.
    if (readKernel() !== undefined) {
      throw new TypeError("Team Session kernel singleton conflicts");
    }
    writeRegistryValue(KERNEL_KEY, created);
    writeRegistryValue(CLOSE_KEY, Object.freeze({ kernel: created, close: closeCreated }));
    return created;
  } catch {
    if (readKernel() === created) deleteRegistryValue(KERNEL_KEY);
    const closeCapability = readCloseCapabilityOrUndefined();
    if (closeCapability?.kernel === created) deleteRegistryValue(CLOSE_KEY);
    try {
      closeCreated?.();
    } catch {
      // Preserve the stable construction failure after best-effort cleanup.
    }
    throw new TypeError("Team Session kernel could not be constructed");
  } finally {
    deleteRegistryValue(PHASE_KEY);
  }
}

/**
 * Close and forget the process-wide kernel during an orderly server stop.
 * When an owner is supplied, a stale HMR service cannot close its replacement.
 */
export function closeTeamSessions(expectedKernel?: TeamSessionKernel): void {
  const phase = readPhase();
  if (phase === "closing") return;
  if (phase === "constructing") {
    throw new TypeError("Team Session kernel lifecycle is in progress");
  }
  const kernel = readKernel();
  if (!kernel) return;
  if (expectedKernel !== undefined && expectedKernel !== kernel) return;
  const close = ensureCloseCapability(kernel);

  writeRegistryValue(PHASE_KEY, "closing");
  deleteRegistryValue(KERNEL_KEY);
  deleteRegistryValue(CLOSE_KEY);
  try {
    close();
  } catch {
    throw new TypeError("Team Session kernel could not be closed");
  } finally {
    deleteRegistryValue(PHASE_KEY);
  }
}

function readKernel(): TeamSessionKernel | undefined {
  const value = readRegistryValue(KERNEL_KEY);
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  kernelTeamSessions(value as TeamSessionKernel);
  return value as TeamSessionKernel;
}

function kernelTeamSessions(kernel: TeamSessionKernel): TeamSessions {
  const descriptor = Object.getOwnPropertyDescriptor(kernel, "teamSessions");
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  const teamSessions = descriptor.value;
  if (typeof teamSessions !== "object" || teamSessions === null) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  return teamSessions as TeamSessions;
}

function ensureCloseCapability(kernel: TeamSessionKernel): () => void {
  const existing = readCloseCapabilityOrUndefined();
  if (existing?.kernel === kernel) return existing.close;
  // An older HMR generation may have closed/replaced the public kernel without
  // knowing about this pinned capability slot. Rebind only to the currently
  // registered identity; owner-scoped close still prevents stale shutdown.
  const close = captureKernelClose(kernel);
  writeRegistryValue(CLOSE_KEY, Object.freeze({ kernel, close }));
  return close;
}

function readCloseCapabilityOrUndefined():
  | { readonly kernel: TeamSessionKernel; readonly close: () => void }
  | undefined {
  const value = readRegistryValue(CLOSE_KEY);
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  const kernelDescriptor = Object.getOwnPropertyDescriptor(value, "kernel");
  const closeDescriptor = Object.getOwnPropertyDescriptor(value, "close");
  if (
    !kernelDescriptor ||
    !kernelDescriptor.enumerable ||
    !("value" in kernelDescriptor) ||
    !closeDescriptor ||
    !closeDescriptor.enumerable ||
    !("value" in closeDescriptor) ||
    typeof closeDescriptor.value !== "function"
  ) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  return value as { readonly kernel: TeamSessionKernel; readonly close: () => void };
}

function captureKernelClose(kernel: TeamSessionKernel): () => void {
  const teamSessions = kernelTeamSessions(kernel);
  const receiver = teamSessions as object;
  const visited = new Set<object>();
  let current: object | null = receiver;
  for (let depth = 0; current !== null && depth < MAX_PROTOTYPE_DEPTH; depth += 1) {
    if (visited.has(current)) break;
    visited.add(current);
    const descriptor = Object.getOwnPropertyDescriptor(current, "close");
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") break;
      const close = descriptor.value as (...args: unknown[]) => unknown;
      return Object.freeze(() => {
        Reflect.apply(close, receiver, []);
      });
    }
    current = Object.getPrototypeOf(current) as object | null;
  }
  throw new TypeError("Invalid Team Session kernel registry");
}

function readPhase(): "constructing" | "closing" | undefined {
  const value = readRegistryValue(PHASE_KEY);
  if (value === undefined || value === "constructing" || value === "closing") return value;
  throw new TypeError("Invalid Team Session kernel registry");
}

function readRegistryValue(key: typeof KERNEL_KEY | typeof CLOSE_KEY | typeof PHASE_KEY): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(serviceRegistry, key);
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor)) throw new TypeError("Invalid Team Session kernel registry");
  return descriptor.value;
}

function writeRegistryValue(
  key: typeof KERNEL_KEY | typeof CLOSE_KEY | typeof PHASE_KEY,
  value: unknown
): void {
  Object.defineProperty(serviceRegistry, key, {
    configurable: true,
    enumerable: false,
    value,
    writable: true,
  });
}

function deleteRegistryValue(key: typeof KERNEL_KEY | typeof CLOSE_KEY | typeof PHASE_KEY): void {
  if (!Reflect.deleteProperty(serviceRegistry, key)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
}
