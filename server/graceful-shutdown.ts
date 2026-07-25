import { types as nodeTypes } from "node:util";

export type ServerShutdownStage =
  | "http-drain"
  | "multiplayer"
  | "telegram"
  | "watcher"
  | "legacy-websockets"
  | "process-resources";

export interface OrderedServerShutdownOptions {
  /** Synchronously stops accepting new HTTP connections and returns its drain. */
  readonly beginHttpDrain: () => Promise<void>;
  /** Owns admission withdrawal, ingress, workers, provider adapters, then SQLite. */
  readonly closeMultiplayer: () => Promise<void>;
  readonly stopTelegram: () => Promise<void>;
  readonly closeWatcher: () => Promise<void>;
  readonly closeLegacyWebSockets: () => Promise<void>;
  readonly destroyProcessResources: () => void;
  readonly reportFailure?: (stage: ServerShutdownStage) => void;
}

export class ServerShutdownError extends Error {
  constructor(readonly code: "cleanup-failed" | "deadline-exceeded") {
    super("TerminalX server shutdown did not complete cleanly");
    this.name = "ServerShutdownError";
  }
}

/**
 * Stop new HTTP admission first, then await the deployment-owned multiplayer
 * cleanup in its own safe order before closing ancillary process resources.
 * Every later stage is still attempted after a failure, and no dependency
 * error value is rethrown or interpolated.
 */
export async function runOrderedServerShutdown(
  options: OrderedServerShutdownOptions
): Promise<void> {
  let clean = true;
  let drain: Promise<void>;
  try {
    drain = options.beginHttpDrain();
    if (!nodeTypes.isPromise(drain)) throw new TypeError();
    // The ordered close steps may take longer than an already-failed drain;
    // attach rejection handling immediately and still inspect it at the end.
    void drain.catch(() => undefined);
  } catch {
    report(options, "http-drain");
    clean = false;
    drain = Promise.resolve();
  }

  clean = (await settle(options.closeMultiplayer, options, "multiplayer")) && clean;
  clean = (await settle(options.stopTelegram, options, "telegram")) && clean;
  clean = (await settle(options.closeWatcher, options, "watcher")) && clean;
  clean = (await settle(options.closeLegacyWebSockets, options, "legacy-websockets")) && clean;
  clean = (await settle(() => drain, options, "http-drain")) && clean;
  clean = settleSynchronous(options.destroyProcessResources, options) && clean;

  if (!clean) throw new ServerShutdownError("cleanup-failed");
}

/** Enforce the process deadline calculated from the selected Runtime owner. */
export async function runServerShutdownWithin(
  options: OrderedServerShutdownOptions,
  deadlineMs: number
): Promise<void> {
  if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 100 || deadlineMs > 2_000_000_000) {
    throw new TypeError("Server shutdown deadline is invalid");
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new ServerShutdownError("deadline-exceeded")), deadlineMs);
  });
  try {
    await Promise.race([runOrderedServerShutdown(options), deadline]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function settle(
  operation: () => Promise<void>,
  options: OrderedServerShutdownOptions,
  stage: ServerShutdownStage
): Promise<boolean> {
  try {
    const result = operation();
    if (!nodeTypes.isPromise(result)) throw new TypeError();
    if ((await result) !== undefined) throw new TypeError();
    return true;
  } catch {
    report(options, stage);
    return false;
  }
}

function settleSynchronous(operation: () => void, options: OrderedServerShutdownOptions): boolean {
  try {
    if (operation() !== undefined) throw new TypeError();
    return true;
  } catch {
    report(options, "process-resources");
    return false;
  }
}

function report(options: OrderedServerShutdownOptions, stage: ServerShutdownStage): void {
  try {
    options.reportFailure?.(stage);
  } catch {
    // Telemetry cannot alter cleanup ordering or the eventual non-zero result.
  }
}
