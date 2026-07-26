import { defineConfig, devices } from "@playwright/test";
import * as path from "path";
import {
  LOCAL_AUTH_PORT,
  LOCAL_AUTH_BASE_URL,
  LOCAL_AUTH_DB_PATH,
  LOCAL_AUTH_TERMINUS_ROOT,
} from "./tests/e2e/multiplayer/config";

/**
 * Playwright config for TerminalX e2e tests.
 *
 * TWO hermetic test servers run side by side:
 *
 *  1. Legacy single-user server (auth-none) on :3200 for the original tests/e2e
 *     specs. TERMINALX_AUTH_MODE=none (login bypassed), TERMINUS_ROOT pointed at
 *     the sandbox sample-repo so worktree / symlink flows exercise a real repo.
 *     Port 3200 is used because 3100 is occupied by another server in this env.
 *
 *  2. Phase 12 multi-user local-auth server on :45813 (tests/e2e/multiplayer/**).
 *     Real login with two seeded users (alice = admin, bob = member). The port is
 *     high and clear of production (3456), preview (3101), and the auth-none
 *     server (3200). See tests/e2e/multiplayer/local-auth-serve.ts.
 */

const SANDBOX_REPO = path.resolve(__dirname, ".test-sandbox/sample-repo");

const PORT = 3200;
const BASE_URL = `http://localhost:${PORT}`;

// A ≥32-char throwaway JWT secret for the local-auth test server (never a
// production secret; only ever used against the hermetic sandbox database).
const LOCAL_AUTH_JWT_SECRET = "e2e-local-jwt-secret-at-least-32-characters-long";

export default defineConfig({
  testDir: "tests/e2e",
  outputDir: "test-results",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [["list"], ["html", { outputFolder: "playwright-report", open: "never" }]],
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },
  projects: [
    {
      // Legacy single-user (auth-none) suite.
      name: "chromium",
      testIgnore: "multiplayer/**",
      use: { ...devices["Desktop Chrome"], baseURL: BASE_URL },
    },
    {
      // One-time login → saved storage state, reused by every mp project.
      name: "mp-setup",
      testMatch: "multiplayer/auth.setup.ts",
      use: { ...devices["Desktop Chrome"], baseURL: LOCAL_AUTH_BASE_URL },
    },
    {
      // Phase 12 multi-user local-auth suite — desktop Chromium.
      name: "mp-chromium",
      testMatch: "multiplayer/**/*.spec.ts",
      dependencies: ["mp-setup"],
      use: { ...devices["Desktop Chrome"], baseURL: LOCAL_AUTH_BASE_URL },
    },
    {
      // Phase 12 multi-user local-auth suite — WebKit.
      name: "mp-webkit",
      testMatch: "multiplayer/**/*.spec.ts",
      dependencies: ["mp-setup"],
      use: { ...devices["Desktop Safari"], baseURL: LOCAL_AUTH_BASE_URL },
    },
    {
      // Phase 12 multi-user local-auth suite — mobile viewport.
      name: "mp-mobile",
      testMatch: "multiplayer/**/*.spec.ts",
      dependencies: ["mp-setup"],
      use: { ...devices["Pixel 5"], baseURL: LOCAL_AUTH_BASE_URL },
    },
  ],
  webServer: [
    {
      command: "npm run dev",
      url: BASE_URL,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        PORT: String(PORT),
        TERMINALX_AUTH_MODE: "none",
        // Opt-in escape hatch so the no-auth test server is allowed to boot.
        // Production startup still forbids `none` unless this is explicitly set.
        TERMINALX_ALLOW_AUTH_NONE: "true",
        TERMINUS_ROOT: SANDBOX_REPO,
        // Master key for the GitHub token vault (a base64-encoded 32-byte key) so
        // the e2e server can encrypt PATs at rest without a real production secret.
        TERMINALX_GITHUB_TOKEN_MASTER_KEY: "5hA7+v5UNOOW0BeCMmltY7i1Rwh52Jdx7KKt8HcvtTY=",
        // Point the server-side GitHub REST client at the in-process test mock
        // (src/app/api/test-github-mock) so the connect flow's `GET /user` hop
        // resolves offline. The mock only responds while auth-none is enabled.
        GITHUB_API_BASE_URL: `${BASE_URL}/api/test-github-mock`,
      },
    },
    {
      // Seeds two users then boots the real server in the same process.
      command: "npx tsx tests/e2e/multiplayer/local-auth-serve.ts",
      url: `${LOCAL_AUTH_BASE_URL}/login`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: "pipe",
      stderr: "pipe",
      env: {
        // Development mode composes the LocalTmux multiplayer transport (a trusted
        // dev adapter) so the Team Session command bus is available; production
        // mode intentionally serves no multiplayer transport without hosted Daytona.
        NODE_ENV: "development",
        PORT: String(LOCAL_AUTH_PORT),
        TERMINALX_AUTH_MODE: "local",
        TERMINALX_JWT_SECRET: LOCAL_AUTH_JWT_SECRET,
        TERMINALX_TEAM_SESSION_DB_PATH: LOCAL_AUTH_DB_PATH,
        TERMINALX_MULTIPLAYER_ENABLED: "true",
        // Safety net for first-boot startup validation; unused once users are seeded.
        TERMINALX_ADMIN_USERNAME: "alice",
        TERMINALX_ADMIN_PASSWORD: "alice-password-123",
        TERMINUS_ROOT: LOCAL_AUTH_TERMINUS_ROOT,
      },
    },
  ],
});
