/**
 * The canonical multiplayer transport is opt-in while it uses the trusted-host
 * LocalTmux development adapter. Keep the parser strict so a typo cannot turn
 * the security boundary on or off unexpectedly.
 */
export function isMultiplayerTransportEnabled(
  value: string | undefined = process.env.TERMINALX_MULTIPLAYER_ENABLED
): boolean {
  if (value === undefined || value === "") return false;
  if (value === "true") return true;
  if (value === "false") return false;
  throw new Error("TERMINALX_MULTIPLAYER_ENABLED must be true or false");
}

const transportRegistry = globalThis as typeof globalThis & {
  __terminalxMultiplayerTransportStatus?: MultiplayerTransportStatus;
};

export type MultiplayerRuntimeStatus =
  | {
      readonly kind: "local-tmux";
      readonly isolation: "trusted-shared-host";
      readonly yoloEligible: false;
    }
  | {
      readonly kind: "daytona";
      readonly isolation: "isolated-hosted";
      readonly yoloEligible: false;
    };

export interface MultiplayerTransportStatus {
  readonly enabled: boolean;
  readonly runtime: MultiplayerRuntimeStatus | null;
}

/**
 * Publish actual custom-server ownership together with its selected Runtime.
 * Availability can never become true without a truthful deployment profile.
 */
export function markMultiplayerTransportAvailable(
  available: boolean,
  runtime: MultiplayerRuntimeStatus | null = null
): void {
  if (typeof available !== "boolean") {
    throw new TypeError("Multiplayer transport status is invalid");
  }
  const snapshot = runtime === null ? null : snapshotRuntime(runtime);
  if (available && snapshot === null) {
    throw new TypeError("Available multiplayer transport requires a Runtime profile");
  }
  Object.defineProperty(transportRegistry, "__terminalxMultiplayerTransportStatus", {
    configurable: true,
    enumerable: false,
    value: Object.freeze({ enabled: available, runtime: snapshot }),
    writable: true,
  });
}

/** Next-only development must stay false even if the environment flag is set. */
export function isMultiplayerTransportAvailable(): boolean {
  return getMultiplayerTransportStatus().enabled;
}

export function getMultiplayerTransportStatus(): MultiplayerTransportStatus {
  const descriptor = Object.getOwnPropertyDescriptor(
    transportRegistry,
    "__terminalxMultiplayerTransportStatus"
  );
  if (descriptor === undefined) return Object.freeze({ enabled: false, runtime: null });
  if (!("value" in descriptor)) throw new TypeError("Multiplayer transport status is invalid");
  const value = descriptor.value as unknown;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Multiplayer transport status is invalid");
  }
  const keys = Reflect.ownKeys(value);
  const enabledDescriptor = Object.getOwnPropertyDescriptor(value, "enabled");
  const runtimeDescriptor = Object.getOwnPropertyDescriptor(value, "runtime");
  if (
    keys.length !== 2 ||
    !enabledDescriptor ||
    !enabledDescriptor.enumerable ||
    !("value" in enabledDescriptor) ||
    typeof enabledDescriptor.value !== "boolean" ||
    !runtimeDescriptor ||
    !runtimeDescriptor.enumerable ||
    !("value" in runtimeDescriptor)
  ) {
    throw new TypeError("Multiplayer transport status is invalid");
  }
  const runtime =
    runtimeDescriptor.value === null
      ? null
      : snapshotRuntime(runtimeDescriptor.value as MultiplayerRuntimeStatus);
  if (enabledDescriptor.value && runtime === null) {
    throw new TypeError("Multiplayer transport status is invalid");
  }
  return Object.freeze({ enabled: enabledDescriptor.value, runtime });
}

function snapshotRuntime(runtime: MultiplayerRuntimeStatus): MultiplayerRuntimeStatus {
  if (typeof runtime !== "object" || runtime === null || Array.isArray(runtime)) {
    throw new TypeError("Multiplayer Runtime profile is invalid");
  }
  const keys = Reflect.ownKeys(runtime);
  if (keys.length !== 3 || !hasExactDataValue(runtime, "yoloEligible", false)) {
    throw new TypeError("Multiplayer Runtime profile is invalid");
  }
  if (
    hasExactDataValue(runtime, "kind", "local-tmux") &&
    hasExactDataValue(runtime, "isolation", "trusted-shared-host")
  ) {
    return Object.freeze({
      kind: "local-tmux",
      isolation: "trusted-shared-host",
      yoloEligible: false,
    });
  }
  if (
    hasExactDataValue(runtime, "kind", "daytona") &&
    hasExactDataValue(runtime, "isolation", "isolated-hosted")
  ) {
    return Object.freeze({
      kind: "daytona",
      isolation: "isolated-hosted",
      yoloEligible: false,
    });
  }
  throw new TypeError("Multiplayer Runtime profile is invalid");
}

function hasExactDataValue(object: object, key: string, expected: unknown): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(object, key);
  return (
    descriptor !== undefined &&
    descriptor.enumerable === true &&
    "value" in descriptor &&
    descriptor.value === expected
  );
}
