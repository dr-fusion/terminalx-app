import { types as utilTypes } from "node:util";
import type { Runtime, RuntimeCommand, RuntimeCommandReceipt, RuntimeHandle } from "./contracts";

const MAX_RUNTIME_PROTOTYPE_DEPTH = 32;

/**
 * A Runtime command capability captured from a data property. Keeping this
 * helper below the public Runtime interface lets execution modules reject
 * accessor-backed adapters without ever invoking provider-controlled getters.
 */
export type RuntimeCommandDataFunction = (
  handle: RuntimeHandle,
  command: RuntimeCommand,
  signal: AbortSignal
) => Promise<RuntimeCommandReceipt>;

/**
 * Capture `Runtime.command` without ordinary property access. The first
 * descriptor in the prototype chain shadows every later one, so an accessor
 * is rejected instead of skipped. The captured function also prevents later method
 * replacement from changing the dispatch capability after composition.
 */
export function captureRuntimeCommandDataFunction(runtime: Runtime): RuntimeCommandDataFunction {
  if (
    (typeof runtime !== "object" && typeof runtime !== "function") ||
    runtime === null ||
    utilTypes.isProxy(runtime)
  ) {
    throw new TypeError("Invalid Runtime command dispatch");
  }

  try {
    const visited = new Set<object>();
    let target: object | null = runtime;
    for (let depth = 0; target !== null && depth < MAX_RUNTIME_PROTOTYPE_DEPTH; depth += 1) {
      if (visited.has(target) || utilTypes.isProxy(target)) {
        throw new TypeError("Invalid Runtime command dispatch");
      }
      visited.add(target);

      const descriptor = Object.getOwnPropertyDescriptor(target, "command");
      if (descriptor !== undefined) {
        if (!("value" in descriptor) || typeof descriptor.value !== "function") {
          throw new TypeError("Invalid Runtime command dispatch");
        }
        const command = descriptor.value;
        return Object.freeze(
          (handle: RuntimeHandle, runtimeCommand: RuntimeCommand, signal: AbortSignal) =>
            Reflect.apply(command, runtime, [
              handle,
              runtimeCommand,
              signal,
            ]) as Promise<RuntimeCommandReceipt>
        );
      }
      target = Object.getPrototypeOf(target) as object | null;
    }
  } catch {
    throw new TypeError("Invalid Runtime command dispatch");
  }

  throw new TypeError("Invalid Runtime command dispatch");
}
