import { expect, test } from "@playwright/test";
import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

const SANDBOX_REPO = path.resolve(__dirname, "..", "..", ".test-sandbox", "sample-repo");

test.beforeAll(() => {
  if (fs.existsSync(path.join(SANDBOX_REPO, ".git"))) return;
  fs.mkdirSync(SANDBOX_REPO, { recursive: true });
  execFileSync("git", ["init", "-b", "main", SANDBOX_REPO]);
  execFileSync("git", ["-C", SANDBOX_REPO, "config", "user.email", "terminalx@example.test"]);
  execFileSync("git", ["-C", SANDBOX_REPO, "config", "user.name", "TerminalX Test"]);
  fs.writeFileSync(path.join(SANDBOX_REPO, "README.md"), "TerminalX test repository\n");
  execFileSync("git", ["-C", SANDBOX_REPO, "add", "README.md"]);
  execFileSync("git", ["-C", SANDBOX_REPO, "commit", "-m", "initial"]);
});

test("a main refresh failure stays in the dialog and does not open a session", async ({ page }) => {
  const refreshError =
    "Failed to refresh main before creating Git worktree: fatal: unable to access origin";

  await page.route("**/api/sessions", async (route) => {
    if (route.request().method() !== "POST") {
      await route.continue();
      return;
    }
    await route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({ error: refreshError }),
    });
  });

  await page.goto("/dashboard");
  await page
    .getByRole("button", { name: /new session/i })
    .first()
    .click();
  await page.getByPlaceholder("my-project").fill("refresh-must-succeed");
  await page.getByLabel(/create Git worktree/i).check();
  await page.getByPlaceholder(/feature\//i).fill("feature/refresh-must-succeed");
  await page.getByRole("button", { name: /^create/i }).click();

  await expect(page.getByTestId("session-create-error")).toHaveText(refreshError);
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByPlaceholder("my-project")).toBeVisible();
});
