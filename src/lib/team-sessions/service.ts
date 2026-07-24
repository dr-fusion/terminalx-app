import { createTeamSessions } from "./module";
import type { TeamSessions } from "./types";

const serviceRegistry = globalThis as typeof globalThis & {
  __terminalxTeamSessionsService?: TeamSessions;
};

/**
 * Return the process-wide Team Session kernel.
 *
 * Next.js may evaluate a route module more than once during development. The
 * global registry avoids opening competing SQLite handles when modules are
 * reloaded while still keeping construction lazy for commands that do not use
 * the Team Session API.
 */
export function getTeamSessions(): TeamSessions {
  serviceRegistry.__terminalxTeamSessionsService ??= createTeamSessions();
  return serviceRegistry.__terminalxTeamSessionsService;
}

/** Close and forget the process-wide kernel during an orderly server stop. */
export function closeTeamSessions(): void {
  const service = serviceRegistry.__terminalxTeamSessionsService;
  if (!service) return;
  delete serviceRegistry.__terminalxTeamSessionsService;
  service.close();
}
