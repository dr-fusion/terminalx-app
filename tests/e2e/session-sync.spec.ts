import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

function sessionName(label: string): string {
  return `e2e-sync-${label}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e4).toString(36)}`;
}

async function createSession(request: APIRequestContext, name: string): Promise<void> {
  const response = await request.post("/api/sessions", {
    data: { name, kind: "bash", cwd: "." },
  });
  expect(response.ok(), await response.text()).toBe(true);
}

async function deleteSession(request: APIRequestContext, name: string): Promise<void> {
  await request.delete(`/api/sessions/${encodeURIComponent(name)}`).catch(() => undefined);
}

async function sessionExists(request: APIRequestContext, name: string): Promise<boolean> {
  const response = await request.get("/api/sessions");
  if (!response.ok()) return false;
  const data = await response.json();
  const sessions: Array<{ name: string }> = data.sessions ?? data;
  return sessions.some((session) => session.name === name);
}

function sidebarSession(page: Page, name: string) {
  return page.locator(`[data-testid="standalone-session-row"][data-session="${name}"]`);
}

function workspaceTab(page: Page, name: string) {
  return page.locator(`[data-testid="workspace-tab"][data-session="${name}"]`);
}

test("a session created from the dashboard appears in the persistent sidebar", async ({
  page,
  request,
}) => {
  const name = sessionName("created");
  let sessionListReads = 0;
  page.on("response", (response) => {
    if (response.request().method() === "GET" && response.url().endsWith("/api/sessions")) {
      sessionListReads += 1;
    }
  });

  try {
    await page.goto("/dashboard");

    // Wait until the shared initial snapshot is settled. The buggy baseline
    // issues multiple reads; the fixed store intentionally deduplicates them.
    await expect.poll(() => sessionListReads).toBeGreaterThanOrEqual(1);
    await expect(sidebarSession(page, name)).toHaveCount(0);

    await page
      .getByRole("button", { name: /new session/i })
      .first()
      .click();
    await page.getByPlaceholder("my-project").fill(name);
    await page.getByRole("button", { name: /create/i }).click();

    await expect(page).toHaveURL(new RegExp(`/workspace/${encodeURIComponent(name)}$`));
    await expect.poll(() => sessionExists(request, name)).toBe(true);
    await expect(workspaceTab(page, name)).toBeVisible();

    // Must update through the client transition; a reload would hide the bug.
    await expect(sidebarSession(page, name)).toBeVisible({ timeout: 2_000 });
  } finally {
    await deleteSession(request, name);
  }
});

test("a successful create stays synchronized when immediate revalidation fails", async ({
  page,
  request,
}) => {
  const name = sessionName("created-offline");
  let rejectSessionReads = false;

  await page.route("**/api/sessions", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname !== "/api/sessions") {
      await route.continue();
      return;
    }
    if (route.request().method() === "GET" && rejectSessionReads) {
      await route.fulfill({
        status: 503,
        contentType: "application/json",
        body: JSON.stringify({ error: "temporary list failure" }),
      });
      return;
    }
    if (route.request().method() === "POST") {
      const response = await route.fetch();
      rejectSessionReads = response.ok();
      await route.fulfill({ response });
      return;
    }
    await route.continue();
  });

  try {
    await page.goto("/dashboard");
    await page
      .getByRole("button", { name: /new session/i })
      .first()
      .click();
    await page.getByPlaceholder("my-project").fill(name);
    await page.getByRole("button", { name: /^create/i }).click();

    await expect.poll(() => sessionExists(request, name)).toBe(true);
    await expect(page).toHaveURL(new RegExp(`/workspace/${encodeURIComponent(name)}$`));
    await expect(sidebarSession(page, name)).toBeVisible();
    await expect(workspaceTab(page, name)).toBeVisible();
  } finally {
    await deleteSession(request, name);
  }
});

test("deleting a session removes its sidebar row and open tab without a reload", async ({
  page,
  request,
}) => {
  const deleted = sessionName("deleted");
  const survivor = sessionName("survivor");
  await createSession(request, deleted);
  await createSession(request, survivor);

  try {
    await page.goto(`/workspace/${encodeURIComponent(deleted)}`);
    await expect(sidebarSession(page, deleted)).toBeVisible();
    await expect(sidebarSession(page, survivor)).toBeVisible();

    await sidebarSession(page, survivor).click();
    await expect(page).toHaveURL(new RegExp(`/workspace/${encodeURIComponent(survivor)}$`));
    await expect(workspaceTab(page, deleted)).toBeVisible();
    await expect(workspaceTab(page, survivor)).toBeVisible();

    // Delete through the same dashboard control a user operates. The shared
    // AppShell stays mounted across this client-side navigation.
    await page.getByRole("link", { name: "open dashboard" }).click();
    await expect(page).toHaveURL(/\/dashboard$/);
    await page.getByRole("button", { name: `kill session ${deleted}` }).click();
    await expect.poll(() => sessionExists(request, deleted)).toBe(false);

    await expect.soft(sidebarSession(page, deleted)).toHaveCount(0, { timeout: 2_000 });
    await sidebarSession(page, survivor).click();
    await expect(page).toHaveURL(new RegExp(`/workspace/${encodeURIComponent(survivor)}$`));
    await expect.soft(workspaceTab(page, deleted)).toHaveCount(0, { timeout: 2_000 });
    await expect(workspaceTab(page, survivor)).toBeVisible();
  } finally {
    await deleteSession(request, deleted);
    await deleteSession(request, survivor);
  }
});

test("a persisted tab for a session that no longer exists is pruned on load", async ({
  page,
  request,
}) => {
  const live = sessionName("live");
  const ghost = sessionName("ghost");
  await createSession(request, live);
  await page.addInitScript(
    ({ storageKey, staleTabs }) => {
      window.localStorage.setItem(storageKey, JSON.stringify(staleTabs));
    },
    { storageKey: "terminalx:open-tabs", staleTabs: [ghost] }
  );

  try {
    await page.goto(`/workspace/${encodeURIComponent(live)}`);
    await expect.poll(() => sessionExists(request, ghost)).toBe(false);
    await expect(workspaceTab(page, live)).toBeVisible();
    await expect(workspaceTab(page, ghost)).toHaveCount(0, { timeout: 2_000 });
  } finally {
    await deleteSession(request, live);
  }
});
