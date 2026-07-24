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
  __terminalxMultiplayerTransportAvailable?: boolean;
};

/** Mark that the custom WebSocket server actually owns the canonical routes. */
export function markMultiplayerTransportAvailable(available: boolean): void {
  transportRegistry.__terminalxMultiplayerTransportAvailable = available;
}

/** Next-only development must stay false even if the environment flag is set. */
export function isMultiplayerTransportAvailable(): boolean {
  return transportRegistry.__terminalxMultiplayerTransportAvailable === true;
}
