/**
 * Hermetic local-auth test server for the Phase 12 multi-user Playwright suite.
 *
 * Playwright launches this as its second `webServer`. It seeds two canonical
 * users (alice = admin, bob = member) into a FRESH, isolated SQLite database and
 * then boots the real TerminalX custom server in the SAME process — so the seed
 * always completes and releases its database handle before the server opens it,
 * with no cross-process SQLite lock race and no dependency on Playwright's
 * globalSetup/webServer ordering.
 *
 * There is no env var that seeds a list of local users, and `POST /api/users`
 * needs identity headers a middleware would inject (that middleware is not wired
 * in this checkout), so direct `createUser` is the only reliable bootstrap. The
 * Team Session, command, and attention routes authenticate straight from the
 * `terminalx-session` cookie, so no middleware is required for the flows we test.
 *
 * Every value here is a throwaway test fixture — never a production secret.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

async function main(): Promise<void> {
  const dbPath = process.env.TERMINALX_TEAM_SESSION_DB_PATH;
  if (!dbPath) {
    throw new Error("TERMINALX_TEAM_SESSION_DB_PATH must be set for the local-auth test server");
  }

  // Fresh database on every cold boot so the seed is deterministic.
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  for (const suffix of ["", "-wal", "-shm", "-journal"]) {
    fs.rmSync(`${dbPath}${suffix}`, { force: true });
  }

  // Ensure the file-browser root exists and is a git repo (some surfaces probe it).
  const root = process.env.TERMINUS_ROOT;
  if (root) {
    fs.mkdirSync(root, { recursive: true });
    if (!fs.existsSync(path.join(root, ".git"))) {
      try {
        execFileSync("git", ["-C", root, "init", "-b", "main"], { stdio: "ignore" });
        execFileSync("git", ["-C", root, "config", "user.email", "e2e@example.test"], {
          stdio: "ignore",
        });
        execFileSync("git", ["-C", root, "config", "user.name", "TerminalX E2E"], {
          stdio: "ignore",
        });
      } catch {
        /* git optional — the multiplayer flows do not require a repo */
      }
    }
  }

  const users = await import("../../../src/lib/users");
  await users.createUser("alice", "alice-password-123", "admin");
  await users.createUser("bob", "bob-password-123", "user");

  const identity = await import("../../../src/lib/identity-service");
  identity.closeCanonicalIdentityAuthorityService();

  // Boot the real server (starts listening on PORT as a top-level side effect).
  await import("../../../server/index");
}

main().catch((error) => {
  console.error("[local-auth-serve] failed to start:", error);
  process.exit(1);
});
