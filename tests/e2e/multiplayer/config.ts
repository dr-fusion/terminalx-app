import * as path from "node:path";

/**
 * Shared configuration for the hermetic local-auth multi-user Playwright suite.
 *
 * A high, fixed port well clear of production (3456) and preview (3101), and of
 * the auth-none e2e server (3200). Imported by both playwright.config.ts and the
 * specs so the same-origin `Origin` header the command bus requires is derived
 * from a single source of truth.
 */
export const LOCAL_AUTH_PORT = 45813;
export const LOCAL_AUTH_BASE_URL = `http://localhost:${LOCAL_AUTH_PORT}`;

/** Isolated data + workspace roots for the local-auth server (never production). */
export const LOCAL_AUTH_SANDBOX_DIR = path.resolve(
  __dirname,
  "..",
  "..",
  "..",
  ".test-sandbox",
  "local-auth"
);
export const LOCAL_AUTH_DB_PATH = path.join(LOCAL_AUTH_SANDBOX_DIR, "team-sessions.sqlite");
export const LOCAL_AUTH_TERMINUS_ROOT = path.join(LOCAL_AUTH_SANDBOX_DIR, "repo");

/**
 * Saved authenticated storage states, produced once by auth.setup.ts and reused
 * by every multiplayer project. This keeps total logins to two for the whole
 * suite (login is rate-limited to 5/user/60s), so the matrix never self-throttles.
 */
export const AUTH_STATE_DIR = path.join(LOCAL_AUTH_SANDBOX_DIR, ".auth");
export const ALICE_STATE = path.join(AUTH_STATE_DIR, "alice.json");
export const BOB_STATE = path.join(AUTH_STATE_DIR, "bob.json");
