import { test as setup, expect } from "@playwright/test";
import * as fs from "node:fs";
import { USERS, whoami } from "./helpers";
import { ALICE_STATE, BOB_STATE, AUTH_STATE_DIR } from "./config";

/**
 * One-time authentication for the multiplayer suite. Logs in each seeded user
 * exactly once and saves their authenticated storage state, which every
 * multiplayer project reuses (login is rate-limited to 5/user/60s, so the full
 * Chromium+WebKit+mobile matrix must not re-login per test).
 */

setup.beforeAll(() => {
  fs.mkdirSync(AUTH_STATE_DIR, { recursive: true });
});

setup("authenticate alice (admin)", async ({ browser }) => {
  const context = await browser.newContext();
  const res = await context.request.post("/api/auth/login", {
    data: { username: USERS.alice.username, password: USERS.alice.password },
  });
  expect(res.ok(), "alice login should succeed").toBeTruthy();
  const aliceId = await whoami(context.request);
  expect(aliceId).toBeTruthy();
  await context.storageState({ path: ALICE_STATE });
  await context.close();
});

setup("authenticate bob (member)", async ({ browser }) => {
  const context = await browser.newContext();
  const res = await context.request.post("/api/auth/login", {
    data: { username: USERS.bob.username, password: USERS.bob.password },
  });
  expect(res.ok(), "bob login should succeed").toBeTruthy();
  const bobId = await whoami(context.request);
  expect(bobId).toBeTruthy();
  await context.storageState({ path: BOB_STATE });
  await context.close();
});
