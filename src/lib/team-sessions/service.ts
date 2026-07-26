import { createTeamSessionKernel, type TeamSessionKernel } from "./module";
import type { AttentionInboxStore } from "../attention/store";
import type { TeamSessions } from "./types";
import { types as nodeTypes } from "node:util";
import type { DaytonaHostedMultiplayerService } from "../runtime/hosted-multiplayer-service";

export type HostedMultiplayerServiceFactory = () => Promise<DaytonaHostedMultiplayerService>;

const serviceRegistry = globalThis as typeof globalThis & {
  __terminalxTeamSessionKernel?: TeamSessionKernel;
  __terminalxTeamSessionKernelClose?: {
    readonly kernel: TeamSessionKernel;
    readonly close: () => void;
  };
  __terminalxTeamSessionKernelInstallation?: {
    readonly kernel: TeamSessionKernel;
    readonly owner: object;
  };
  __terminalxTeamSessionKernelPhase?: "constructing" | "installing" | "disposing" | "closing";
  __terminalxHostedMultiplayerServiceFactory?: {
    readonly factory: HostedMultiplayerServiceFactory;
  };
};

const KERNEL_KEY = "__terminalxTeamSessionKernel" as const;
const CLOSE_KEY = "__terminalxTeamSessionKernelClose" as const;
const INSTALLATION_KEY = "__terminalxTeamSessionKernelInstallation" as const;
const PHASE_KEY = "__terminalxTeamSessionKernelPhase" as const;
const HOSTED_FACTORY_KEY = "__terminalxHostedMultiplayerServiceFactory" as const;
const MAX_PROTOTYPE_DEPTH = 32;

/**
 * Install the explicit, one-call production composition. Registration never
 * constructs a Team Session kernel and an owner-scoped disposer cannot remove
 * a replacement installed by a later module generation.
 */
export function installHostedMultiplayerServiceFactory(
  factory: HostedMultiplayerServiceFactory
): () => void {
  if (typeof factory !== "function" || nodeTypes.isProxy(factory)) {
    throw new TypeError("Hosted multiplayer factory is invalid");
  }
  const current = readHostedFactoryCapability();
  if (current !== undefined) {
    if (current.factory !== factory) throw new TypeError("Hosted multiplayer factory conflicts");
    return Object.freeze(() => {
      if (readHostedFactoryCapability()?.factory === factory) {
        deleteRegistryValue(HOSTED_FACTORY_KEY);
      }
    });
  }
  const capability = Object.freeze({ factory });
  writeRegistryValue(HOSTED_FACTORY_KEY, capability);
  return Object.freeze(() => {
    if (readHostedFactoryCapability() === capability) deleteRegistryValue(HOSTED_FACTORY_KEY);
  });
}

/** Null means production multiplayer remains unavailable; there is no local fallback here. */
export function getHostedMultiplayerServiceFactory(): HostedMultiplayerServiceFactory | null {
  return readHostedFactoryCapability()?.factory ?? null;
}

/**
 * Publish a deployment-owned kernel to every Next.js route module in this
 * process. The returned disposer only unregisters this exact installation;
 * the deployment remains solely responsible for closing its SQLite owner.
 */
export function installTeamSessionKernel(kernel: TeamSessionKernel): () => void {
  if (readPhase() !== undefined) {
    throw new TypeError("Team Session kernel lifecycle is in progress");
  }
  const close = captureKernelClose(kernel);
  if (
    readKernel() !== undefined ||
    readCloseCapabilityOrUndefined() !== undefined ||
    readInstallationOrUndefined() !== undefined
  ) {
    throw new TypeError("Team Session kernel installation conflicts");
  }

  const owner = Object.freeze(Object.create(null) as object);
  const installation = Object.freeze({ kernel, owner });
  writeRegistryValue(PHASE_KEY, "installing");
  try {
    // Keep the installation descriptor last. Readers either observe no kernel
    // while the lifecycle phase is present or the complete frozen capability.
    writeRegistryValue(KERNEL_KEY, kernel);
    writeRegistryValue(CLOSE_KEY, Object.freeze({ kernel, close }));
    writeRegistryValue(INSTALLATION_KEY, installation);
  } catch {
    if (readRegistryValue(KERNEL_KEY) === kernel) deleteRegistryValue(KERNEL_KEY);
    const closeCapability = readCloseCapabilityOrUndefined();
    if (closeCapability?.kernel === kernel) deleteRegistryValue(CLOSE_KEY);
    if (readRegistryValue(INSTALLATION_KEY) === installation) {
      deleteRegistryValue(INSTALLATION_KEY);
    }
    throw new TypeError("Team Session kernel could not be installed");
  } finally {
    deleteRegistryValue(PHASE_KEY);
  }

  let disposed = false;
  return Object.freeze(() => {
    if (disposed) return;
    const current = readInstallationOrUndefined();
    if (current !== installation) {
      disposed = true;
      return;
    }
    if (readPhase() !== undefined) {
      throw new TypeError("Team Session kernel lifecycle is in progress");
    }
    if (readKernel() !== kernel || readCloseCapabilityOrUndefined()?.kernel !== kernel) {
      throw new TypeError("Invalid Team Session kernel registry");
    }

    writeRegistryValue(PHASE_KEY, "disposing");
    try {
      deleteRegistryValue(INSTALLATION_KEY);
      deleteRegistryValue(KERNEL_KEY);
      deleteRegistryValue(CLOSE_KEY);
      disposed = true;
    } finally {
      deleteRegistryValue(PHASE_KEY);
    }
  });
}

/** Read the registered kernel without ever constructing a LocalTmux fallback. */
export function getRegisteredTeamSessionKernel(): TeamSessionKernel | null {
  if (readPhase() !== undefined) {
    throw new TypeError("Team Session kernel lifecycle is in progress");
  }
  const kernel = readKernel();
  const close = readCloseCapabilityOrUndefined();
  const installation = readInstallationOrUndefined();
  if (kernel === undefined) {
    if (close !== undefined || installation !== undefined) {
      throw new TypeError("Invalid Team Session kernel registry");
    }
    return null;
  }
  if (close?.kernel !== kernel || (installation !== undefined && installation.kernel !== kernel)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  return kernel;
}

/** HTTP routes use this non-constructing seam so production can fail closed. */
export function getRegisteredTeamSessions(): TeamSessions | null {
  const kernel = getRegisteredTeamSessionKernel();
  return kernel === null ? null : kernelTeamSessions(kernel);
}

/**
 * Non-constructing seam for the Phase 11A attention-inbox HTTP routes. Returns
 * null when no kernel is installed so production fails closed exactly like the
 * Team Session routes.
 */
export function getRegisteredAttentionInbox(): AttentionInboxStore | null {
  const kernel = getRegisteredTeamSessionKernel();
  return kernel === null ? null : kernelAttentionInbox(kernel);
}

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
    if (readInstallationOrUndefined() !== undefined) {
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
  if (readInstallationOrUndefined()?.kernel === kernel) {
    throw new TypeError("Installed Team Session kernel is externally owned");
  }
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

function kernelAttentionInbox(kernel: TeamSessionKernel): AttentionInboxStore {
  const descriptor = Object.getOwnPropertyDescriptor(kernel, "attentionInbox");
  if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  const attentionInbox = descriptor.value;
  if (typeof attentionInbox !== "object" || attentionInbox === null) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  return attentionInbox as AttentionInboxStore;
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

function readInstallationOrUndefined():
  | { readonly kernel: TeamSessionKernel; readonly owner: object }
  | undefined {
  const value = readRegistryValue(INSTALLATION_KEY);
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  const keys = Reflect.ownKeys(value);
  const kernelDescriptor = Object.getOwnPropertyDescriptor(value, "kernel");
  const ownerDescriptor = Object.getOwnPropertyDescriptor(value, "owner");
  if (
    keys.length !== 2 ||
    !kernelDescriptor ||
    !kernelDescriptor.enumerable ||
    !("value" in kernelDescriptor) ||
    !ownerDescriptor ||
    !ownerDescriptor.enumerable ||
    !("value" in ownerDescriptor) ||
    typeof ownerDescriptor.value !== "object" ||
    ownerDescriptor.value === null
  ) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
  return value as { readonly kernel: TeamSessionKernel; readonly owner: object };
}

function readPhase(): "constructing" | "installing" | "disposing" | "closing" | undefined {
  const value = readRegistryValue(PHASE_KEY);
  if (
    value === undefined ||
    value === "constructing" ||
    value === "installing" ||
    value === "disposing" ||
    value === "closing"
  ) {
    return value;
  }
  throw new TypeError("Invalid Team Session kernel registry");
}

function readHostedFactoryCapability():
  | { readonly factory: HostedMultiplayerServiceFactory }
  | undefined {
  const value = readRegistryValue(HOSTED_FACTORY_KEY);
  if (value === undefined) return undefined;
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    nodeTypes.isProxy(value)
  ) {
    throw new TypeError("Invalid hosted multiplayer factory registry");
  }
  const keys = Reflect.ownKeys(value);
  const descriptor = Object.getOwnPropertyDescriptor(value, "factory");
  if (
    keys.length !== 1 ||
    !descriptor ||
    !descriptor.enumerable ||
    !("value" in descriptor) ||
    typeof descriptor.value !== "function" ||
    nodeTypes.isProxy(descriptor.value)
  ) {
    throw new TypeError("Invalid hosted multiplayer factory registry");
  }
  return value as { readonly factory: HostedMultiplayerServiceFactory };
}

type RegistryKey =
  | typeof KERNEL_KEY
  | typeof CLOSE_KEY
  | typeof INSTALLATION_KEY
  | typeof PHASE_KEY
  | typeof HOSTED_FACTORY_KEY;

function readRegistryValue(key: RegistryKey): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(serviceRegistry, key);
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor)) throw new TypeError("Invalid Team Session kernel registry");
  return descriptor.value;
}

function writeRegistryValue(key: RegistryKey, value: unknown): void {
  Object.defineProperty(serviceRegistry, key, {
    configurable: true,
    enumerable: false,
    value,
    writable: true,
  });
}

function deleteRegistryValue(key: RegistryKey): void {
  if (!Reflect.deleteProperty(serviceRegistry, key)) {
    throw new TypeError("Invalid Team Session kernel registry");
  }
}
